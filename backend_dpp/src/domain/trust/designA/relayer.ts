import client from "prom-client";
import type { Prisma, PrismaClient } from "@prisma/client";
import { logger } from "../../../observability/logger.js";
import { registry } from "../../../observability/metrics.js";
import type { ChainGateway } from "./chainGateway.js";
import { deserializeCall } from "./outbox.js";
import {
  asAddress,
  asUint,
  ChainCallRevertedError,
  ChainMisconfiguredError,
  ChainUnavailableError,
  InvalidChainArgumentError,
  RelayerMayNotAuthorizeError,
  signedCallSummary,
  type Address,
  type SignedCall,
  type TxStatus,
} from "./chainTypes.js";

/**
 * ─── AnchorTx relayer — the DRAIN half of the chain outbox ────────────────────
 * `outbox.ts` fills the queue; this file empties it. Separate files because they
 * have opposite trust properties (filling records what an actor authorized;
 * draining spends the platform's gas), but this one imports `deserializeCall`
 * from there so the wire format has exactly ONE definition — a writer and reader
 * with independent copies is how a signed payload eventually stops decoding.
 */

/** `AnchorTx.status`. `confirmed` and `failed` are terminal. */
type AnchorTxStatus = "pending" | "sent" | "confirmed" | "failed";

// ── Tuning ───────────────────────────────────────────────────────────────────

/** Matches the email outbox's cadence. Amoy blocks are ~2 s, so this is polling, not latency. */
const POLL_MS = 15_000;

/**
 * Submits are deliberately a smaller batch than polls: each submit is a real
 * transaction (a broadcast, gas, and a serial slot in the nonce lane), while a
 * poll is one `eth_getTransactionReceipt`. Draining 50 submits in a tick would
 * just push the tail of the batch into the next tick's territory anyway.
 */
const SUBMIT_BATCH = 10;
const POLL_BATCH = 50;

/**
 * How many times a payload may be given a real chance before the row is written
 * off. Only failures that the CHAIN answered count against this (see
 * `classify`) — an unreachable RPC is refunded, so an outage can never exhaust
 * a legitimate anchor.
 */
const MAX_ATTEMPTS = 10;

/**
 * 15 s, 30 s, 1 m, 2 m, 4 m, 8 m, then 15 m — about an hour of grace before
 * `MAX_ATTEMPTS` bites. Same `base * 2^(n-1)` shape as the email outbox, with a
 * shorter base because a chain answer is cheaper to re-ask for than an SMTP
 * handshake.
 */
const backoffMs = (attempt: number) => Math.min(15_000 * 2 ** (attempt - 1), 15 * 60_000);

/**
 * Availability failures get the same curve with a much lower ceiling. An RPC
 * outage resolves on its own and we want the queue moving again within a minute
 * of it doing so; backing off to 15 minutes would turn a 30-second blip into a
 * quarter-hour of stalled anchors for no benefit. A reverting call, by contrast,
 * deserves the long ceiling — it is asking the chain the same question again.
 */
const OUTAGE_MAX_BACKOFF_MS = 60_000;

/**
 * Consecutive `unknown` observations before a `sent` row is pushed back to
 * `pending` for re-forwarding. `chainTypes.ts` names `unknown` as a fourth state
 * precisely so this worker can act on it: the node has never heard of the hash,
 * so the transaction was dropped from the mempool, replaced, or never actually
 * broadcast.
 */
const UNKNOWN_REQUEUE_AFTER = 3;

/** Postgres `text` has no limit, but an unbounded error string in a queue row does. */
const MAX_ERROR_CHARS = 500;

// ── Metrics ──────────────────────────────────────────────────────────────────

/**
 * Mirrors `outbox_pending` from `src/observability/metrics.ts` — same
 * `prom-client` Gauge on the same shared `registry`, so it is scraped at
 * /metrics with no extra wiring.
 */
const anchorTxPending = new client.Gauge({
  name: "anchor_tx_pending",
  help: "Design A chain writes not yet in a terminal state (pending = unsubmitted, sent = awaiting confirmation)",
  labelNames: ["status"] as const,
  registers: [registry],
});

/**
 * Consecutive `unknown` observations per row, for `UNKNOWN_REQUEUE_AFTER`.
 */
const unknownStreak = new Map<string, number>();

// ── Reading a row back ───────────────────────────────────────────────────────

/**
 * The stored payload as the `SignedCall` the actor signed.
 */
function toSignedCall(kind: string, payload: Prisma.JsonValue): SignedCall {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new InvalidChainArgumentError("AnchorTx.payload must be a JSON object");
  }
  const p = payload as Record<string, unknown>;
  if (p.kind !== kind) {
    // Key deliberately NOT named `payload`: `logger.error({ err })` serialises
    // `ChainGatewayError.detail` wholesale, and a key called `payload` in a log
    // line reads as "the signed payload was logged" to anyone auditing later.
    throw new InvalidChainArgumentError("AnchorTx.kind and payload.kind disagree", { kindColumn: kind, kindInPayload: String(p.kind) });
  }
  if (p.nonce === undefined || p.nonce === null) {
    throw new InvalidChainArgumentError("AnchorTx payload has no nonce — it is a signed field and must not be defaulted");
  }
  if (kind === "anchor" && (p.version === undefined || p.version === null)) {
    throw new InvalidChainArgumentError("anchor payload has no version — it is a signed field and must not be defaulted");
  }
  if (kind === "setIssuers" && (!Array.isArray(p.issuers) || p.issuers.length === 0)) {
    // The array is inside the digest and the contract reverts `EmptyIssuerSet`,
    // so a row without it can only ever fail. Refusing to decode costs nothing;
    // submitting it costs gas to be told the same thing.
    throw new InvalidChainArgumentError("setIssuers payload has no issuers — it is a signed field and must not be defaulted");
  }
  return deserializeCall(p);
}

/**
 * The signer hint, or `undefined`.
 */
function signerHint(payload: Prisma.JsonValue): Address | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const raw = (payload as Record<string, unknown>).signer;
  try {
    return raw === undefined ? undefined : asAddress(raw, "signer");
  } catch {
    return undefined;
  }
}

// ── Failure classification ───────────────────────────────────────────────────

/**
 * What to do with a failed submission.
 */
type Disposition =
  | { outcome: "permanent"; reason: string }
  | { outcome: "retry"; burnsBudget: boolean; reason: string; alert: boolean };

/**
 * Transient vs permanent, decided from the error taxonomy in `chainTypes.ts`
 * rather than from string matching.
 */
function classify(err: unknown): Disposition {
  if (err instanceof ChainUnavailableError) {
    return { outcome: "retry", burnsBudget: false, reason: `chain unavailable: ${err.message}`, alert: false };
  }
  if (err instanceof ChainMisconfiguredError) {
    return { outcome: "retry", burnsBudget: false, reason: `chain misconfigured: ${err.message}`, alert: true };
  }
  if (err instanceof RelayerMayNotAuthorizeError) {
    return {
      outcome: "permanent",
      reason: "refused: the payload's recovered signer is the relayer — the relayer pays gas and holds no authority",
    };
  }
  if (err instanceof InvalidChainArgumentError) {
    return { outcome: "permanent", reason: `invalid argument: ${err.message}` };
  }
  if (err instanceof ChainCallRevertedError) {
    if (err.reason === "InvalidNonce") {
      const nonces = nonceComparison(err.detail);
      if (!nonces || nonces.provided > nonces.expected) {
        const detail = nonces ? ` (expected ${nonces.expected}, provided ${nonces.provided})` : "";
        return {
          outcome: "retry",
          burnsBudget: true,
          reason: `InvalidNonce: this signer's earlier payload has not landed yet${detail}`,
          alert: false,
        };
      }
      return {
        outcome: "permanent",
        reason:
          `InvalidNonce: nonce ${nonces.provided} was already consumed on-chain (contract expects ${nonces.expected}) — ` +
          "this payload was already applied, or superseded by another payload from the same signer. Replaying it can only revert.",
      };
    }
    return { outcome: "permanent", reason: `reverted: ${err.reason ?? err.message}` };
  }
  // Not from the chain layer at all — a bug here, a Prisma blip, an
  // `AbortError`. Retry, but charge it: an unclassified error that repeats ten
  // times is not going to resolve itself, and a row stuck forever is worse than
  // a row an operator can see in `failed`.
  return { outcome: "retry", burnsBudget: true, reason: describeError(err), alert: false };
}

/**
 * Pull `(expected, provided)` out of an `InvalidNonce` revert.
 */
function nonceComparison(detail: Record<string, unknown>): { expected: bigint; provided: bigint } | null {
  const args = Array.isArray(detail.args) ? (detail.args as unknown[]) : null;
  const rawExpected = detail.expected ?? args?.[1];
  const rawProvided = detail.provided ?? args?.[2];
  if (rawExpected === undefined || rawProvided === undefined) return null;
  try {
    return { expected: asUint(rawExpected, "expected"), provided: asUint(rawProvided, "provided") };
  } catch {
    return null;
  }
}

/**
 * Never includes a URL (RPC endpoints carry API keys in their path or
 * subdomain), never a payload, never a signature. Same helper the gateway keeps
 * private, for the same reason.
 */
function describeError(err: unknown): string {
  const text = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  return text.slice(0, MAX_ERROR_CHARS);
}

// ── The drain ────────────────────────────────────────────────────────────────

/**
 * One drain pass: poll first, then submit.
 */
export async function drainAnchorTxs(prisma: PrismaClient, gateway: ChainGateway): Promise<void> {
  await pollSent(prisma, gateway);
  await submitPending(prisma, gateway);
  await updateGauge(prisma);
}

/**
 * Job 2, run first: ask the chain where each in-flight transaction got to.
 */
async function pollSent(prisma: PrismaClient, gateway: ChainGateway): Promise<void> {
  const inFlight = await prisma.anchorTx.findMany({
    where: { status: "sent", nextTryAt: { lte: new Date() } },
    orderBy: { createdAt: "asc" },
    take: POLL_BATCH,
  });

  for (const row of inFlight) {
    if (!row.txHash) {
      // Unreachable through this worker (the transition to `sent` writes both in
      // one update), so if it happens something else wrote the row. It cannot be
      // polled and must not be silently re-submitted.
      await markFailed(prisma, row.id, "row is 'sent' with no txHash — cannot be polled");
      logger.error({ id: row.id, kind: row.kind }, "designA relayer: 'sent' row has no txHash");
      continue;
    }

    let status: TxStatus;
    try {
      status = await gateway.txStatus(row.txHash);
    } catch (err) {
      const disposition = classify(err);
      if (disposition.outcome === "permanent") {
        // In practice only a malformed hash reaches here.
        await markFailed(prisma, row.id, `cannot poll: ${disposition.reason}`);
        logger.error({ id: row.id, txHash: row.txHash, err }, "designA relayer: transaction is unpollable");
        continue;
      }
      await prisma.anchorTx.update({
        where: { id: row.id },
        data: {
          nextTryAt: new Date(Date.now() + Math.min(backoffMs(row.attempts + 1), OUTAGE_MAX_BACKOFF_MS)),
          lastError: disposition.reason.slice(0, MAX_ERROR_CHARS),
        },
      });
      logger.warn({ id: row.id, txHash: row.txHash, err }, "designA relayer: could not read transaction status");
      continue;
    }

    switch (status.status) {
      case "confirmed":
        unknownStreak.delete(row.id);
        await prisma.anchorTx.update({
          where: { id: row.id },
          data: {
            status: "confirmed" satisfies AnchorTxStatus,
            blockNumber: status.blockNumber ?? null,
            confirmedAt: new Date(),
            lastError: null,
          },
        });
        logger.info(
          { id: row.id, kind: row.kind, productId: row.productId, txHash: row.txHash, blockNumber: status.blockNumber },
          "designA relayer: chain write confirmed",
        );
        break;

      case "failed":
        unknownStreak.delete(row.id);
        // Mined and reverted. It passed gas estimation at submit time, so the
        // state it depended on changed underneath it (almost always: the signer's
        // nonce was consumed by another transaction). Terminal — and this worker
        // structurally cannot repair it, because repairing it means signing a new
        // payload and only the actor can do that. `confirmedAt` stays null;
        // `blockNumber` records that it was mined.
        await prisma.anchorTx.update({
          where: { id: row.id },
          data: {
            status: "failed" satisfies AnchorTxStatus,
            blockNumber: status.blockNumber ?? null,
            lastError: "transaction was mined but reverted — the actor must sign a replacement payload",
          },
        });
        logger.error(
          { id: row.id, kind: row.kind, productId: row.productId, txHash: row.txHash, blockNumber: status.blockNumber },
          "designA relayer: chain write reverted on-chain",
        );
        break;

      case "pending":
        // Queued and healthy. Leave `nextTryAt` alone → polled again next tick.
        unknownStreak.delete(row.id);
        break;

      case "unknown": {
        // The node has never heard of this hash: dropped from the mempool,
        // fee-replaced, or never broadcast. Folding this into `pending` polls a
        // lost transaction forever; folding it into `failed` asserts something we
        // did not observe. Re-forward instead, after a grace period — safe
        // because if it DID land after all, the resubmission meets a consumed
        // nonce and is classified as already-applied, never as a double-anchor.
        const streak = (unknownStreak.get(row.id) ?? 0) + 1;
        if (streak < UNKNOWN_REQUEUE_AFTER) {
          unknownStreak.set(row.id, streak);
          break;
        }
        unknownStreak.delete(row.id);
        await prisma.anchorTx.update({
          where: { id: row.id },
          data: {
            status: "pending" satisfies AnchorTxStatus,
            txHash: null,
            nextTryAt: new Date(),
            lastError: `no node has seen ${row.txHash} after ${streak} checks — re-forwarding the signed payload`,
          },
        });
        logger.warn({ id: row.id, kind: row.kind, txHash: row.txHash }, "designA relayer: transaction vanished, re-forwarding");
        break;
      }
    }
  }
}

/**
 * Job 1, run second: forward due `pending` payloads.
 */
async function submitPending(prisma: PrismaClient, gateway: ChainGateway): Promise<void> {
  const busy = await busyLanes(prisma);

  const due = await prisma.anchorTx.findMany({
    where: { status: "pending", nextTryAt: { lte: new Date() } },
    orderBy: { createdAt: "asc" },
    take: SUBMIT_BATCH,
  });

  for (const row of due) {
    let call: SignedCall;
    try {
      call = toSignedCall(row.kind, row.payload);
    } catch (err) {
      // A payload that does not decode today will not decode in fifteen minutes.
      await markFailed(prisma, row.id, `undecodable payload: ${describeError(err)}`);
      logger.error({ id: row.id, kind: row.kind, err }, "designA relayer: payload does not decode");
      continue;
    }

    // Nonce lane. The contract's per-signer nonce is strict equality, so a
    // signer's payload N+1 cannot be estimated until N has been MINED — not
    // merely broadcast. Holding the row costs one tick; submitting it costs a
    // guaranteed `InvalidNonce` revert and an attempt.
    const signer = signerHint(row.payload);
    if (signer && busy.signers.has(signer)) continue;
    if (busy.products.has(call.productId)) continue;

    // Optimistic claim, exactly as the email outbox does it: bump `attempts` and
    // push `nextTryAt` BEFORE the call, so a crash mid-submit leaves a row that
    // retries later rather than one that is re-forwarded immediately by the next
    // tick. Guarded on `(status, attempts)` so it is a no-op if anything else
    // touched the row. The attempt is REFUNDED below when the failure turns out
    // to be the chain being unreachable rather than the payload being wrong.
    const claimed = await prisma.anchorTx.updateMany({
      where: { id: row.id, status: "pending", attempts: row.attempts },
      data: { attempts: row.attempts + 1, nextTryAt: new Date(Date.now() + backoffMs(row.attempts + 1)) },
    });
    if (claimed.count !== 1) continue;

    // Claim the lane before the await, and keep it claimed even if the submit
    // fails: an error during broadcast does not prove the transaction is absent
    // from the network, and a second payload sent on that assumption is how a
    // nonce gets double-spent.
    if (signer) busy.signers.add(signer);
    busy.products.add(call.productId);

    try {
      const { txHash, signer: recovered } = await gateway.submitSignedCall(call);
      await prisma.anchorTx.update({
        where: { id: row.id },
        data: {
          status: "sent" satisfies AnchorTxStatus,
          txHash,
          // `nextTryAt` now means "next poll", so reset it: a row on its fourth
          // attempt would otherwise not be polled for two minutes.
          nextTryAt: new Date(),
          lastError: null,
        },
      });
      if (signer && recovered !== signer) {
        // Not recoverable — the transaction is already broadcast and cannot be
        // recalled — but it means the stored payload is not what the enqueuer
        // believed it was signing. The chain will do the right thing regardless
        // (authority follows the RECOVERED signer), so this is a tripwire, not a
        // control.
        logger.error(
          { id: row.id, ...signedCallSummary(call), expected: signer, recovered, txHash },
          "designA relayer: payload recovered to a different signer than the queue row claimed",
        );
      }
      logger.info(
        { id: row.id, ...signedCallSummary(call), txHash, signer: recovered },
        "designA relayer: forwarded pre-signed call",
      );
    } catch (err) {
      await handleSubmitFailure(prisma, row.id, row.attempts + 1, call, err);
    }
  }
}

/**
 * Which nonce lanes already have a payload in flight.
 */
async function busyLanes(prisma: PrismaClient): Promise<{ signers: Set<Address>; products: Set<string> }> {
  const sent = await prisma.anchorTx.findMany({
    where: { status: "sent" },
    select: { payload: true, productId: true },
    take: POLL_BATCH * 4,
  });
  const signers = new Set<Address>();
  const products = new Set<string>();
  for (const row of sent) {
    const signer = signerHint(row.payload);
    if (signer) signers.add(signer);
    if (row.productId) products.add(row.productId);
  }
  return { signers, products };
}

/** Apply a `Disposition` to a row whose submission threw. */
async function handleSubmitFailure(
  prisma: PrismaClient,
  id: string,
  attempts: number,
  call: SignedCall,
  err: unknown,
): Promise<void> {
  const disposition = classify(err);
  // `signedCallSummary` is the only shape of this call that ever reaches a log:
  // kind, productId, nonce — never the signature. Note that `logger.ts`'s pino
  // `redact` list covers `token`/`password` and NOT `signature`, so redaction
  // here is by CONSTRUCTION (no log object in this file can carry one) rather
  // than by the filter catching it afterwards.
  const context = { id, ...signedCallSummary(call), attempts };

  if (disposition.outcome === "permanent") {
    await markFailed(prisma, id, disposition.reason);
    logger.error({ ...context, reason: disposition.reason }, "designA relayer: chain refused the payload — not retrying");
    return;
  }

  if (!disposition.burnsBudget) {
    // Refund. The chain never gave this payload an answer, so it has not used up
    // a chance. `attempts` therefore means "times the chain answered and the
    // answer was not success" — an outage can push `nextTryAt` forever without
    // ever getting the row closer to being written off.
    await prisma.anchorTx.update({
      where: { id },
      data: {
        attempts: attempts - 1,
        nextTryAt: new Date(Date.now() + Math.min(backoffMs(attempts), OUTAGE_MAX_BACKOFF_MS)),
        lastError: disposition.reason.slice(0, MAX_ERROR_CHARS),
      },
    });
    const line = "designA relayer: could not reach the chain — holding the payload, not retrying against the budget";
    if (disposition.alert) logger.error({ ...context, err }, line);
    else logger.warn({ ...context, err }, line);
    return;
  }

  if (attempts >= MAX_ATTEMPTS) {
    await markFailed(prisma, id, `giving up after ${MAX_ATTEMPTS} attempts: ${disposition.reason}`);
    logger.error({ ...context, reason: disposition.reason }, "designA relayer: giving up after max attempts");
    return;
  }
  // `nextTryAt` was already pushed by the claim; only the reason needs recording.
  await prisma.anchorTx.update({
    where: { id },
    data: { lastError: disposition.reason.slice(0, MAX_ERROR_CHARS) },
  });
  logger.warn({ ...context, err }, "designA relayer: submission failed, will retry");
}

/** Terminal failure. `updateMany` so a row deleted underneath us is not an exception. */
async function markFailed(prisma: PrismaClient, id: string, reason: string): Promise<void> {
  unknownStreak.delete(id);
  await prisma.anchorTx
    .updateMany({
      where: { id },
      data: { status: "failed" satisfies AnchorTxStatus, lastError: reason.slice(0, MAX_ERROR_CHARS) },
    })
    .catch((err: unknown) => logger.error({ id, err }, "designA relayer: could not mark row failed"));
}

/** One `GROUP BY`, both series. Absent statuses are set to 0 so a drained queue reads as 0, not as a stale value. */
async function updateGauge(prisma: PrismaClient): Promise<void> {
  const counts = await prisma.anchorTx.groupBy({
    by: ["status"],
    where: { status: { in: ["pending", "sent"] } },
    _count: true,
  });
  const by = new Map(counts.map((c) => [c.status, c._count]));
  anchorTxPending.set({ status: "pending" }, by.get("pending") ?? 0);
  anchorTxPending.set({ status: "sent" }, by.get("sent") ?? 0);
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

/**
 * Start the relayer. Returns a `stop()` for graceful shutdown.
 */
export function startAnchorRelayer(prisma: PrismaClient, gateway: ChainGateway): () => void {
  let draining = false;
  const tick = async () => {
    if (draining) return; // never overlap passes
    draining = true;
    try {
      await drainAnchorTxs(prisma, gateway);
    } catch (err) {
      logger.error({ err }, "designA relayer: drain pass failed");
    } finally {
      draining = false;
    }
  };
  void tick(); // pick up anything left over from a previous run immediately
  const timer = setInterval(() => void tick(), POLL_MS);
  return () => clearInterval(timer);
}
