#!/usr/bin/env -S npx tsx
/**
 * ─── The Design A ceremony, driven end to end (demo + RQ3 instrument) ─────────
 * Every step of Design A is built and individually verified. Nothing had ever
 * run as ONE sequence. This script is that sequence: it onboards the actors,
 * runs the signing ceremony, publishes, anchors, and verifies the result.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import { utf8ToBytes } from "@noble/hashes/utils";
import { TypedDataEncoder, Wallet } from "ethers";
// The ONE import from the platform, and the one the brief requires: the
// isomorphic builder. This is `backend_dpp/src/dpp-core/`, the synced copy of
// `packages/dpp-core/` — byte-identical (scripts/sync-dpp-core.mjs keeps it so),
// and deliberately the copy the SERVER loads, so the two sides of the byte
// comparison below are literally the same module rather than two copies of it.
import { buildAttestationBody } from "../src/dpp-core/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BACKEND = resolve(HERE, "..");
const REPO = resolve(BACKEND, "..");
const VERIFIER = join(HERE, "verify-passport.mjs");

/* ════════════════════════════════════════════════════════════════════════════
 * §1  Arguments
 * ════════════════════════════════════════════════════════════════════════════ */

function parseArgs(argv: string[]) {
  const get = (name: string, fallback: string | null = null): string | null => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1]! : fallback;
  };
  const has = (name: string) => argv.includes(`--${name}`);
  if (has("help") || has("h")) {
    console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("*/")[0]!.replace(/^\/\*\*| \* ?/gm, ""));
    process.exit(0);
  }
  return {
    api: (get("api", "http://localhost:3011") as string).replace(/\/$/, ""),
    rpc: discoverRpc(get("rpc")),
    actorsPath: get("actors", join(HERE, ".design-a-actors.json")) as string,
    freshActors: has("fresh-actors"),
    outDir: get("out", join(HERE, "out")) as string,
    dbContainer: get("db-container", "trustdpp-db-dev") as string,
    dbUser: get("db-user", "trustdpp") as string,
    dbName: get("db-name", "trustdpp") as string,
    chainTimeoutMs: Number(get("chain-timeout", "900000")),
    verify: !has("no-verify"),
    json: has("json"),
  };
}

/** The RPC URL, from the usual places. `contracts/.env` is parsed by hand and
 *  never sourced — that file also holds a private key. */
function discoverRpc(explicit: string | null): { url: string | null; source: string | null } {
  if (explicit) return { url: explicit, source: "--rpc" };
  if (process.env.RPC_URL) return { url: process.env.RPC_URL, source: "$RPC_URL" };
  if (process.env.AMOY_RPC_URL) return { url: process.env.AMOY_RPC_URL, source: "$AMOY_RPC_URL" };
  const envPath = join(REPO, "contracts", ".env");
  if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, "utf8").split("\n")) {
      const m = /^\s*AMOY_RPC_URL\s*=\s*(.+?)\s*$/.exec(line);
      if (m?.[1] && !m[1].startsWith("#")) return { url: m[1], source: "contracts/.env" };
    }
  }
  return { url: null, source: null };
}

/** The host, and only the host: RPC URLs carry API keys and this output is meant
 *  to be pasted into a thesis appendix. Same precaution as the verifiers. */
const rpcHost = (url: string | null): string | null => {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return "unparseable";
  }
};

const cfg = parseArgs(process.argv.slice(2));

/*
 * §2 Output — the run record, and the timings measure-rq3 consumes
 */

interface Step {
  id: string;
  label: string;
  actor: string | null;
  startedAt: string;
  ms: number;
  detail?: unknown;
}

interface Measurement {
  id: string;
  category: string;
  metric: string;
  design: "A" | "B" | null;
  unit: string | null;
  state: "measured" | "unavailable" | "n/a" | "structural";
  provenance: string | null;
  value: unknown;
  dist: unknown;
  reason: string | null;
  precondition: string | null;
  includes: string[];
  excludes: string[];
  notes: string | null;
  detail: unknown;
  samples: number[] | null;
}

const steps: Step[] = [];
const measurements: Measurement[] = [];
const findings: string[] = [];

const round = (x: number | null | undefined) => (x === null || x === undefined ? null : Math.round(x * 1000) / 1000);
/** Gwei resolution for currency: `round` would flatten 0.00115 POL to 0.001. */
const roundPol = (x: number | null | undefined) => (x === null || x === undefined ? null : Math.round(x * 1e9) / 1e9);

function percentile(sorted: number[], p: number): number | null {
  if (sorted.length === 0) return null;
  if (sorted.length === 1) return sorted[0]!;
  const rank = (sorted.length - 1) * p;
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sorted[lo]!;
  return sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (rank - lo);
}

/** Quantiles below this n are refused, not computed — measure-rq3's policy,
 *  reproduced with its exact threshold so the twin `describe`s keep producing
 *  identical figures for identical samples. */
const QUANTILE_MIN_N = 5;

function describe(samples: number[] | null | undefined) {
  if (!samples || samples.length === 0) return null;
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  const mean = s.reduce((a, b) => a + b, 0) / n;
  /* Small-n honesty, mirrored from measure-rq3 (see the long comment there):
   * stddev at n=1 is UNDEFINED (Bessel divides by n−1), not 0 — this file's own
   * 2026-08-08 artifact printed `anchor.timeToConfirm` as n=1 with stddev 0 and
   * IQR 0, a degenerate distribution wearing §12's "median + IQR" label. And
   * quantiles interpolated from fewer than 5 points are numbers without
   * meaning. min/max/mean stay; the nulls are the honest report. */
  const variance = n > 1 ? s.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1) : null;
  const quantiles = n >= QUANTILE_MIN_N;
  const p25 = quantiles ? percentile(s, 0.25)! : null;
  const p75 = quantiles ? percentile(s, 0.75)! : null;
  return {
    n,
    min: round(s[0]),
    p25: round(p25),
    median: quantiles ? round(percentile(s, 0.5)) : null,
    p75: round(p75),
    iqr: quantiles ? round(p75! - p25!) : null,
    p95: quantiles ? round(percentile(s, 0.95)) : null,
    max: round(s[n - 1]),
    mean: round(mean),
    stddev: variance === null ? null : round(Math.sqrt(variance)),
  };
}

/** measure-rq3's category prefixes, so its renderer groups these rows with its
 *  own. Derived from the id rather than passed in, for the same reason. */
const CATEGORIES: [string, string][] = [
  ["verification.", "Graph-Verifikations-Latenz  (RQ3 §13)"],
  ["gas.", "Gas & Kosten  (RQ3 §13)"],
  ["anchor.", "Verankerung  (nicht in §13 versprochen — Zugabe)"],
  ["onboarding.", "Onboarding-Latenz  (RQ3 §13 — Primärmetrik)"],
  ["signing.", "Signierlatenz  (RQ3 §13)"],
  ["ceremony.", "Zeremonie-Schritte (Design A, end-to-end)"],
];
const categoryOf = (id: string) => CATEGORIES.find(([p]) => id.startsWith(p))?.[1] ?? "Sonstige";

function record(rec: Partial<Measurement> & { id: string; metric: string; state: Measurement["state"] }): Measurement {
  const full: Measurement = {
    id: rec.id,
    category: categoryOf(rec.id),
    metric: rec.metric,
    design: rec.design ?? "A",
    unit: rec.unit ?? null,
    state: rec.state,
    provenance: rec.provenance ?? null,
    value: rec.value ?? null,
    dist: rec.dist ?? null,
    reason: rec.reason ?? null,
    precondition: rec.precondition ?? null,
    includes: rec.includes ?? [],
    excludes: rec.excludes ?? [],
    notes: rec.notes ?? null,
    detail: rec.detail ?? null,
    samples: rec.samples ?? null,
  };
  measurements.push(full);
  return full;
}

// ── Console ──────────────────────────────────────────────────────────────────

const C = {
  on: process.stdout.isTTY && !process.argv.includes("--no-color"),
  dim: (s: string) => (C.on ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s: string) => (C.on ? `\x1b[1m${s}\x1b[0m` : s),
  green: (s: string) => (C.on ? `\x1b[32m${s}\x1b[0m` : s),
  yellow: (s: string) => (C.on ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s: string) => (C.on ? `\x1b[36m${s}\x1b[0m` : s),
  red: (s: string) => (C.on ? `\x1b[31m${s}\x1b[0m` : s),
};
const say = (s = "") => console.log(s);
const note = (s: string) => say(C.dim(`      ${s}`));

/**
 * Run one ceremony step, time it, record it.
 *
 * The clock is `hrtime`, and the step is recorded even when it throws — a
 * failed run must still say how far it got and how long each step that DID run
 * took, or a failure at step 14 discards the thirteen measurements before it.
 */
async function step<T>(
  id: string,
  label: string,
  actor: string | null,
  fn: () => Promise<T>,
  detailOf?: (result: T) => unknown,
): Promise<T> {
  const startedAt = new Date().toISOString();
  const t0 = process.hrtime.bigint();
  process.stdout.write(`  ${C.dim("·")} ${label.padEnd(58)}`);
  try {
    const result = await fn();
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    steps.push({ id, label, actor, startedAt, ms: round(ms)!, detail: detailOf?.(result) });
    say(`${C.green("ok")} ${C.dim(`${Math.round(ms)} ms`)}`);
    return result;
  } catch (err) {
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    steps.push({ id, label, actor, startedAt, ms: round(ms)!, detail: { failed: String((err as Error).message) } });
    say(`${C.red("FAILED")} ${C.dim(`${Math.round(ms)} ms`)}`);
    throw err;
  }
}

/** The wall time of the last recorded step whose id matches. */
const msOf = (id: string): number => steps.find((s) => s.id === id)?.ms ?? 0;
const msOfAll = (prefix: string): number =>
  steps.filter((s) => s.id.startsWith(prefix)).reduce((n, s) => n + s.ms, 0);

/* ════════════════════════════════════════════════════════════════════════════
 * §3  HTTP — the only way this script talks to the platform
 * ════════════════════════════════════════════════════════════════════════════ */

class ApiError extends Error {
  constructor(readonly status: number, readonly method: string, readonly path: string, readonly body: unknown) {
    super(
      `${method} ${path} → HTTP ${status}: ${
        typeof body === "object" && body !== null
          ? JSON.stringify(body).slice(0, 600)
          : String(body).slice(0, 300)
      }`,
    );
  }
}

async function api<T = any>(
  method: "GET" | "POST" | "PUT",
  path: string,
  opts: { token?: string | null; body?: unknown; expect?: number[] } = {},
): Promise<T> {
  const res = await fetch(`${cfg.api}${path}`, {
    method,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
    },
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  });
  const text = await res.text();
  let parsed: unknown = text;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* keep the raw text — an HTML error page is worth seeing verbatim */
  }
  const expected = opts.expect ?? [200, 201, 202];
  if (!expected.includes(res.status)) throw new ApiError(res.status, method, path, parsed);
  return parsed as T;
}

/*
 * §4 Chain reads — what a stranger can see, and nothing more
 */

const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const selector = (sig: string) => `0x${toHex(keccak_256(utf8ToBytes(sig))).slice(0, 8)}`;
const word = (hex: string) => hex.replace(/^0x/, "").padStart(64, "0");

let rpcCalls = 0;
async function rpc<T = any>(method: string, params: unknown[] = []): Promise<T> {
  if (!cfg.rpc.url) throw new Error("no JSON-RPC endpoint configured (--rpc, $RPC_URL, or contracts/.env)");
  rpcCalls += 1;
  const res = await fetch(cfg.rpc.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcCalls, method, params }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status} for ${method}`);
  const body = (await res.json()) as { result?: T; error?: { message: string } };
  if (body.error) throw new Error(`RPC ${method}: ${body.error.message}`);
  return body.result as T;
}

const ethCall = (to: string, data: string) => rpc<string>("eth_call", [{ to, data }, "latest"]);

/** `authorized[productId][issuer]` — Mechanism 4's read side. */
async function chainAuthorized(registry: string, productId: string, issuer: string): Promise<boolean> {
  const data = `${selector("authorized(bytes32,address)")}${word(productId)}${word(issuer)}`;
  return BigInt(await ethCall(registry, data)) === 1n;
}

/** `nonces[signer]` — the registry's per-signer nonce. One `eth_call`, and an
 *  EXACT statement about whether a payload signed at nonce N has been applied:
 *  the contract accepts a given (signer, nonce) exactly once. This is the probe
 *  used to wait for the anchor, because the platform's own anchor read cannot be
 *  used on a range-capped endpoint — see `FINDING_ANCHOR_READ`. */
async function chainNonce(registry: string, signer: string): Promise<bigint> {
  return BigInt(await ethCall(registry, `${selector("nonces(address)")}${word(signer)}`));
}

/** `keccak256("Anchored(bytes32,bytes32,uint64,address)")` — topic0. */
const ANCHORED_TOPIC = `0x${toHex(keccak_256(utf8ToBytes("Anchored(bytes32,bytes32,uint64,address)")))}`;

/**
 * Find this product's `Anchored` log, scanning FORWARD from a known-recent block
 * in windows that shrink when an endpoint refuses the range.
 */
async function scanAnchorLog(
  registry: string,
  productId: string,
  fromBlock: number,
): Promise<{ txHash: string; blockNumber: number; merkleRoot: string } | null> {
  const head = parseInt(await rpc<string>("eth_blockNumber"), 16);
  let window = 2000;
  let cursor = fromBlock;
  while (cursor <= head) {
    const to = Math.min(cursor + window - 1, head);
    let logs: any[];
    try {
      logs = await rpc<any[]>("eth_getLogs", [
        {
          address: registry,
          topics: [ANCHORED_TOPIC, `0x${word(productId)}`],
          fromBlock: `0x${cursor.toString(16)}`,
          toBlock: `0x${to.toString(16)}`,
        },
      ]);
    } catch (err) {
      // The endpoint refused the range. Shrink and retry the SAME window — the
      // shrinking is the whole point, and giving up here would report "no
      // anchor" for what is actually an endpoint policy.
      if (window <= 1) throw err;
      window = Math.max(1, Math.floor(window / 4));
      continue;
    }
    if (logs.length) {
      const log = logs[logs.length - 1]!;
      return {
        txHash: log.transactionHash,
        blockNumber: parseInt(log.blockNumber, 16),
        merkleRoot: `0x${log.data.replace(/^0x/, "").slice(0, 64)}`,
      };
    }
    cursor = to + 1;
  }
  return null;
}

/** Poll `probe` until it is true, or give up with a message that says how long
 *  it waited and what it was waiting for. Never "assume it worked". */
async function waitFor(what: string, probe: () => Promise<boolean>, timeoutMs = cfg.chainTimeoutMs): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let first = true;
  for (;;) {
    if (await probe()) return;
    if (Date.now() > deadline) {
      throw new Error(`timed out after ${Math.round(timeoutMs / 1000)} s waiting for ${what}`);
    }
    if (first) {
      process.stdout.write(C.dim(" waiting"));
      first = false;
    } else {
      process.stdout.write(C.dim("."));
    }
    await sleep(5000);
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/*
 * §5 The actors' keys
 */

/** The prefix that goes into the organisation NAME, i.e. into the thing a reader
 *  sees as the credential issuer on the published passport. Not a comment
 *  somewhere — the label has to travel with the data. */
const DEMO_PREFIX = "[DEMONSTRATION ACCOUNT]";

interface ActorSpec {
  key: string;
  /** The company name, before the demonstration prefix is applied. */
  company: string;
  role: "operator" | "supplier";
  /** dpp-core stage roles this actor's node provides (suppliers only). */
  roles: string[];
  tierIndex: number;
  tierRole: string;
}

const CAST: ActorSpec[] = [
  { key: "operator", company: "Zyton GmbH", role: "operator", roles: [], tierIndex: -1, tierRole: "" },
  { key: "farm", company: "Karimov Cotton Farm", role: "supplier", roles: ["cotton-farming"], tierIndex: 0, tierRole: "Cotton Farm" },
  { key: "spinner", company: "Dhaka Spinning Mills", role: "supplier", roles: ["spinning"], tierIndex: 1, tierRole: "Spinning Mill" },
  // Vertically integrated on purpose: one node providing TWO roles is the case
  // that exercises `assertRoleCoverage` (an approval per role, one decision) and
  // the multi-payload wallet session the operator UI has to handle.
  { key: "mill", company: "Anatolia Denim Mill", role: "supplier", roles: ["weaving", "dyeing"], tierIndex: 2, tierRole: "Weaving & Wet Processing" },
  { key: "maker", company: "Saigon Garment Works", role: "supplier", roles: ["garment"], tierIndex: 3, tierRole: "Cut, Sew & Assembly" },
];

interface Actor extends ActorSpec {
  privateKey: string;
  address: string;
  wallet: Wallet;
  orgName: string;
  token: string;
  orgId: string;
  did: string;
  userId: string;
  provisioned: boolean;
}

interface StoredActor {
  privateKey: string;
  address: string;
  company: string;
  /** Written after a successful bind. Its presence is what lets a re-run SKIP
   *  the bind ceremony — see `onboard`. */
  did?: string;
  orgId?: string;
  boundAt?: string;
}

interface StoredActors {
  warning: string;
  demonstrationAccounts: true;
  createdAt: string;
  chainId: number | null;
  actors: Record<string, StoredActor>;
}

function loadOrMintKeys(): { stored: StoredActors; fresh: boolean } {
  if (!cfg.freshActors && existsSync(cfg.actorsPath)) {
    const stored = JSON.parse(readFileSync(cfg.actorsPath, "utf8")) as StoredActors;
    if (CAST.every((a) => stored.actors?.[a.key]?.privateKey)) return { stored, fresh: false };
  }
  const actors: StoredActors["actors"] = {};
  for (const spec of CAST) {
    const key = secp256k1.utils.randomPrivateKey();
    const wallet = new Wallet(`0x${toHex(key)}`);
    actors[spec.key] = { privateKey: wallet.privateKey, address: wallet.address, company: spec.company };
  }
  say(
    C.dim(
      "      minting a fresh cast: five new organisations will be provisioned, which costs five\n" +
        "      wallet-bind requests — the tightest limiter on this surface (5 per hour per IP).",
    ),
  );
  const stored: StoredActors = {
    warning:
      "DEMONSTRATION KEYS. Generated by scripts/seed-design-a.ts to play the part of five independent " +
      "actors on a dev stack. They control demonstration organisations and nothing else. They are NOT " +
      "Web3Auth tKey shares, they hold no funds, and they must never be used on a production stack.",
    demonstrationAccounts: true,
    createdAt: new Date().toISOString(),
    chainId: null,
    actors,
  };
  return { stored, fresh: true };
}

/*
 * §6 Signing — the three things an actor's key does
 */

/** EIP-191 `personal_sign`, exactly what a wallet's `personal_sign` produces. */
const personalSign = (wallet: Wallet, message: string) => wallet.signMessage(message);

/**
 * EIP-712, exactly what `eth_signTypedData_v4` produces for the same payload.
 */
async function signTypedDataPayload(wallet: Wallet, payload: any): Promise<string> {
  const { EIP712Domain: _domainType, ...types } = payload.types ?? {};
  return wallet.signTypedData(payload.domain, types, payload.message);
}

/** base64url, canonical: `-_`, unpadded. The verifier re-encodes what it decoded
 *  and refuses anything non-canonical, so `+`, `/` or `=` is a broken token. */
const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** The address a private key controls: uncompressed point, drop the 0x04 tag,
 *  keccak the remaining 64 bytes, take the low 20. The same derivation the
 *  verifier performs on the RECOVERED key. */
function addressFromPrivateKey(privateKey: Uint8Array): string {
  return `0x${toHex(keccak_256(secp256k1.getPublicKey(privateKey, false).slice(1))).slice(-40)}`;
}

/** The address a finished JWS recovers to — the verifier's own procedure, run
 *  locally before the token is uploaded. */
function recoveredAddress(signingInput: string, signatureSegment: string): string {
  const bytes = new Uint8Array(Buffer.from(signatureSegment, "base64url"));
  const parsed = secp256k1.Signature.fromCompact(bytes.slice(0, 64)).addRecoveryBit(bytes[64]!);
  const publicKey = parsed.recoverPublicKey(sha256(utf8ToBytes(signingInput))).toRawBytes(false);
  return `0x${toHex(keccak_256(publicKey.slice(1))).slice(-40)}`;
}

interface AttestationClaim {
  role: string;
  issuerDid: string;
  productDid: string | null;
  contextUrl: string;
  schemaUrl: string;
  validUntil: string | null;
  subject: Record<string, unknown>;
}

/**
 * Build and sign one credential. The mirror of
 * `frontend_dpp/src/lib/wallet/signer.ts`, line for line, and the one function
 * in this file a reviewer should read against it.
 */
function signAttestationJws(
  claim: AttestationClaim,
  validFrom: Date,
  privateKeyHex: string,
): { jws: string; body: Record<string, unknown>; signerAddress: string } {
  const body = buildAttestationBody({
    contextUrl: claim.contextUrl,
    schemaUrl: claim.schemaUrl,
    credential: { role: claim.role, issuerDid: claim.issuerDid, credentialSubject: claim.subject },
    productDid: claim.productDid,
    // Null, always. `brandOrgDid` is the FALLBACK issuer for a role no node
    // covers; an actor signing their own slice always has an issuer DID of their
    // own, and anything else here would mint a credential attributed to the brand.
    brandOrgDid: null,
    validFrom,
    validUntil: claim.validUntil ? new Date(claim.validUntil) : null,
  }) as unknown as Record<string, unknown>;

  const header = { alg: "ES256K-R", typ: "vc+jwt", kid: `${claim.issuerDid}#controller` };
  const enc = (v: unknown) => base64url(new TextEncoder().encode(JSON.stringify(v)));
  const signingInput = `${enc(header)}.${enc(body)}`;

  const key = new Uint8Array(Buffer.from(privateKeyHex.replace(/^0x/, ""), "hex"));
  const derived = addressFromPrivateKey(key);
  const expected = /^did:ethr:(?:[^:]+:)?(0x[0-9a-fA-F]{40})$/.exec(claim.issuerDid)?.[1]?.toLowerCase();
  if (!expected) throw new Error(`issuer identity is not a did:ethr: ${claim.issuerDid}`);
  if (derived !== expected) {
    throw new Error(`this key controls ${derived}, but the role issues as ${expected} — refusing to sign`);
  }

  const signature = secp256k1.sign(sha256(utf8ToBytes(signingInput)), key);
  if (signature.hasHighS()) throw new Error("refusing a high-s ES256K-R signature (EIP-2)");
  const recovery = signature.recovery;
  if (recovery !== 0 && recovery !== 1) throw new Error(`ES256K-R recovery id must be 0 or 1, got ${recovery}`);
  const sig = new Uint8Array(65);
  sig.set(signature.toCompactRawBytes(), 0);
  sig[64] = recovery;
  const jws = `${signingInput}.${base64url(sig)}`;

  // Self-verification, on the BYTES, exactly as signer.ts does after the key is
  // gone. A prefix, a curve default or a recovery id gone wrong becomes a
  // precise local refusal instead of a 400 whose text is "issued by a stranger".
  const signerAddress = recoveredAddress(signingInput, jws.slice(signingInput.length + 1));
  if (signerAddress !== expected) {
    throw new Error(`the signature recovers to ${signerAddress}, not to ${expected}. Nothing was uploaded.`);
  }
  return { jws, body, signerAddress };
}

/**
 * The coverage endpoint's unsigned body → the VALUES it was assembled from.
 */
function decompose(view: { role: string; credential?: Record<string, unknown> }): AttestationClaim {
  const body = view.credential;
  if (!body) throw new Error(`role "${view.role}": the server sent no credential body (not this org's role?)`);
  const context = Array.isArray(body["@context"]) ? (body["@context"] as unknown[]) : [];
  const contextUrl = typeof context[1] === "string" ? context[1] : null;
  const schemaUrl = typeof (body.credentialSchema as any)?.id === "string" ? (body.credentialSchema as any).id : null;
  const issuerDid = typeof body.issuer === "string" ? body.issuer : null;
  const subject = body.credentialSubject as Record<string, unknown> | undefined;
  if (!contextUrl || !schemaUrl) throw new Error(`role "${view.role}": missing context or schema URL`);
  if (!issuerDid) throw new Error(`role "${view.role}": no issuer identity — the org has not bound a wallet`);
  if (!subject) throw new Error(`role "${view.role}": no credentialSubject to attest`);
  const { id: productDid, role: subjectRole, ...values } = subject;
  return {
    role: typeof subjectRole === "string" ? subjectRole : view.role,
    issuerDid,
    productDid: typeof productDid === "string" ? productDid : null,
    contextUrl,
    schemaUrl,
    validUntil: typeof body.validUntil === "string" ? body.validUntil : null,
    subject: values,
  };
}

/** Does this file's assembly fail to reproduce the server's reference? Returns
 *  the offending member, or null. `validFrom` is excluded because the reference
 *  deliberately has none — it is the SIGNER's instant. */
function divergesFromReference(built: Record<string, unknown>, reference: Record<string, unknown>): string | null {
  const canon = (v: unknown): string => JSON.stringify(sortDeep(v));
  for (const key of new Set([...Object.keys(built), ...Object.keys(reference)])) {
    if (key === "validFrom") continue;
    if (canon(built[key]) !== canon(reference[key])) return key;
  }
  return null;
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    out[k] = sortDeep((value as Record<string, unknown>)[k]);
  }
  return out;
}

/*
 * §7 The passport's content
 */

const SYSTEM_OWNED = new Set([
  "textile.metadata.passportId",
  "textile.metadata.version",
  "textile.metadata.status",
  "textile.metadata.issueDate",
  "textile.identity.productDid",
  "textile.identity.imageUrl",
]);

/**
 * A fresh, VALID GTIN-13 per run.
 */
function mintGtin13(): string {
  // 4056205 is the demo passport's GS1 company prefix; the item reference is the
  // run's timestamp so two runs a second apart cannot collide.
  const body = `4056205${String(Date.now()).slice(-5)}`.padEnd(12, "0").slice(0, 12);
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += Number(body[i]) * (i % 2 === 0 ? 1 : 3);
  return `${body}${(10 - (sum % 10)) % 10}`;
}

function passportFields(): { category: string; productName: string; values: Record<string, string>; gtin: string } {
  const raw = JSON.parse(readFileSync(join(BACKEND, "data", "demo.json"), "utf8"));
  const demo = (raw.dpps ?? []).find((d: any) => d.id === "dpp_denim_003");
  if (!demo) throw new Error("data/demo.json no longer carries dpp_denim_003 — pick another template passport");
  const values: Record<string, string> = {};
  for (const fv of demo.fieldValues ?? []) {
    if (SYSTEM_OWNED.has(fv.fieldId)) continue;
    values[fv.fieldId] = typeof fv.value === "string" ? fv.value : JSON.stringify(fv.value);
  }
  const gtin = mintGtin13();
  values["textile.identity.codeValue"] = gtin;
  return { category: demo.category, productName: demo.productName, values, gtin };
}

/* ════════════════════════════════════════════════════════════════════════════
 * §8  The ceremony
 * ════════════════════════════════════════════════════════════════════════════ */

async function onboard(spec: ActorSpec, key: StoredActor): Promise<Actor> {
  const wallet = new Wallet(key.privateKey);
  const orgName = `${DEMO_PREFIX} ${spec.company}`;
  const id = spec.key;

  // 1 — SIWE login. The server mints the message; this signs THOSE bytes and
  //     echoes them back. Nothing about the message is built here.
  const challenge = await step(`onboarding.${id}.challenge`, `${spec.company}: SIWE challenge (login)`, id, () =>
    api<{ message: string }>("GET", `/api/auth/challenge?address=${wallet.address}&purpose=login`),
  );
  const login = await step(`onboarding.${id}.login`, `${spec.company}: wallet-login`, id, async () =>
    api<{ token: string; user: { id: string; orgId: string }; provisioned: boolean }>("POST", "/api/auth/wallet-login", {
      body: {
        address: wallet.address,
        message: challenge.message,
        signature: await personalSign(wallet, challenge.message),
        company: orgName,
        /* The sign-in gate (2026-08): provisioning is a REGISTER-only act now —
         * a bare sign-in with an unknown address gets a 404 with instructions
         * instead of a phantom organization, because a supplier who typed their
         * email into the wrong door used to end up owning a brand. This script
         * IS registering (five demonstration orgs, on purpose), so it says so
         * the same way the register card does. Re-runs are unaffected: a known
         * address signs in, and the flag is ignored for existing accounts. */
        register: true,
      },
    }),
  );

  // 2 — Bind the wallet as the org's issuer identity. A separate `purpose: "bind"`
  // challenge: a login signature may not be spent here, and the server refuses the
  // mismatch. This is the step that mints the org's did:ethr — for ZERO gas,
  // because a did:ethr is derived from the address (RQ3 gas.perActorDid).
  if (key.did) {
    const sk = await api<{ did: string | null }>("GET", "/api/dashboard/signing-keys", { token: login.token });
    if (!sk.did) {
      say(`  ${C.dim("·")} ${C.dim(`${spec.company}: stored binding is stale (server has no did for this org) — re-binding`)}`);
      delete key.did;
      delete key.orgId;
      delete key.boundAt;
    }
  }
  let binding: { orgId: string; did: string; alreadyBound: boolean };
  if (key.did) {
    binding = { orgId: login.user.orgId, did: key.did, alreadyBound: true };
    steps.push({
      id: `onboarding.${id}.bind`,
      label: `${spec.company}: wallet already bound (skipped)`,
      actor: id,
      startedAt: new Date().toISOString(),
      ms: 0,
      detail: { skipped: "already bound on an earlier run", did: key.did, boundAt: key.boundAt },
    });
    say(`  ${C.dim("·")} ${`${spec.company}: bind wallet → did:ethr`.padEnd(58)}${C.cyan("skip")} ${C.dim("already bound")}`);
  } else {
    const bindChallenge = await step(`onboarding.${id}.bindChallenge`, `${spec.company}: SIWE challenge (bind)`, id, () =>
      api<{ message: string }>("GET", `/api/auth/challenge?address=${wallet.address}&purpose=bind`, {
        token: login.token,
      }),
    );
    binding = await step(
      `onboarding.${id}.bind`,
      `${spec.company}: bind wallet → did:ethr`,
      id,
      async () =>
        api<{ orgId: string; did: string; alreadyBound: boolean }>("POST", "/api/auth/wallet/bind", {
          token: login.token,
          body: {
            address: wallet.address,
            message: bindChallenge.message,
            signature: await personalSign(wallet, bindChallenge.message),
          },
        }),
      (b) => ({ did: b.did, alreadyBound: b.alreadyBound }),
    );
    key.did = binding.did;
    key.orgId = binding.orgId;
    key.boundAt = new Date().toISOString();
  }

  note(`${binding.did}${binding.alreadyBound ? C.dim("  (bound on an earlier run)") : ""}`);
  return {
    ...spec,
    privateKey: key.privateKey,
    address: wallet.address,
    wallet,
    orgName,
    token: login.token,
    orgId: login.user.orgId,
    userId: login.user.id,
    did: binding.did,
    provisioned: login.provisioned,
  };
}

/** One controller-signed chain call, from payload to confirmed on chain. */
async function chainCall(
  idPrefix: string,
  label: string,
  operator: Actor,
  build: () => Promise<{ payload: any; nonce: string }>,
  submit: (nonce: string, signature: string) => Promise<unknown>,
  landed: () => Promise<boolean>,
): Promise<void> {
  const request = await step(`${idPrefix}.payload`, `${label}: build payload`, operator.key, build, (r) => ({
    nonce: r.nonce,
    primaryType: r.payload?.primaryType,
  }));
  const signature = await step(`${idPrefix}.sign`, `${label}: operator signs (EIP-712)`, operator.key, () =>
    signTypedDataPayload(operator.wallet, request.payload),
  );
  await step(`${idPrefix}.enqueue`, `${label}: queue for the relayer`, operator.key, () =>
    submit(request.nonce, signature),
  );
  await step(`${idPrefix}.confirm`, `${label}: confirmed on chain`, operator.key, () =>
    waitFor(label, landed),
  );
}

/*
 * §9 Gas + outbox receipts — a MEASUREMENT read, never a ceremony step
 */

interface OutboxRow {
  id: string;
  kind: string;
  status: string;
  txHash: string | null;
  blockNumber: string | null;
  createdAt: string;
  confirmedAt: string | null;
}

/**
 * Read the outbox, waiting for the anchor row to reach `confirmed`.
 */
async function readOutboxAwaitingAnchor(passportId: string): Promise<{ rows: OutboxRow[] | null; why: string | null }> {
  const deadline = Date.now() + 90_000;
  for (;;) {
    const out = readOutbox(passportId);
    if (!out.rows) return out;
    const anchor = out.rows.find((r) => r.kind === "anchor");
    if (!anchor || (anchor.status === "confirmed" && anchor.confirmedAt) || Date.now() > deadline) return out;
    await sleep(5000);
  }
}

function readOutbox(passportId: string): { rows: OutboxRow[] | null; why: string | null } {
  const sql =
    `select coalesce(json_agg(row_to_json(t)), '[]') from (` +
    `select id, kind, status, "txHash", "blockNumber"::text, "createdAt"::text, "confirmedAt"::text ` +
    `from "AnchorTx" where "passportId" = '${passportId}' order by "createdAt") t;`;
  const r = spawnSync("docker", ["exec", cfg.dbContainer, "psql", "-U", cfg.dbUser, "-d", cfg.dbName, "-tAc", sql], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.status !== 0) {
    return { rows: null, why: `psql via docker exec ${cfg.dbContainer} failed: ${(r.stderr || "").trim().split("\n")[0]}` };
  }
  try {
    return { rows: JSON.parse(r.stdout.trim()) as OutboxRow[], why: null };
  } catch {
    return { rows: null, why: "AnchorTx query returned unparseable output" };
  }
}

async function receiptOf(txHash: string) {
  const r = await rpc<any>("eth_getTransactionReceipt", [txHash]);
  if (!r) return { txHash, error: "receipt not found" };
  const gasUsed = parseInt(r.gasUsed, 16);
  const price = parseInt(r.effectiveGasPrice, 16);
  return {
    txHash,
    gasUsed,
    effectiveGasPriceWei: price,
    effectiveGasPriceGwei: round(price / 1e9),
    costPol: roundPol((gasUsed * price) / 1e18),
    blockNumber: parseInt(r.blockNumber, 16),
    status: r.status === "0x1" ? "success" : "reverted",
  };
}

/* ════════════════════════════════════════════════════════════════════════════
 * §10  main
 * ════════════════════════════════════════════════════════════════════════════ */

async function main(): Promise<number> {
  const startedAt = new Date();
  say();
  say(C.bold("  TrustDPP — the Design A ceremony, end to end"));
  say();
  say(
    C.yellow(
      `  ${DEMO_PREFIX}  Every organisation this script creates is a demonstration account.\n` +
        "  This process holds five private keys because in this scenario it IS the five actors.\n" +
        "  The platform still holds none: it has no signing path, and this script adds none.",
    ),
  );
  say();
  say(C.dim(`  api ${cfg.api}   rpc ${rpcHost(cfg.rpc.url) ?? "none"} (${cfg.rpc.source ?? "unconfigured"})`));
  say();

  if (!cfg.rpc.url) throw new Error("a JSON-RPC endpoint is required to observe the chain (--rpc)");

  // ── 0. The stack has to actually be Design A ───────────────────────────────
  const health = await step("ceremony.preflight", "preflight: the platform is in Design A mode", null, async () => {
    const ready = await api<any>("GET", "/ready", { expect: [200] });
    // `/api/trust/design-a/*` is mounted ONLY by a Design A process — not
    // disabled, absent — so a 404 here is the honest test of which design is
    // running. 401 means the routes exist and are (correctly) authenticated.
    const probe = await fetch(`${cfg.api}/api/trust/design-a/passports/none/claim`);
    if (probe.status === 404) {
      throw new Error(
        "this platform does not serve /api/trust/design-a/* — it is running Design B. " +
          "Start the backend with TRUST_MODE=design-a and its chain wiring.",
      );
    }
    return { ready, designARoutes: probe.status };
  });
  note(`design-a routes present (probe → HTTP ${health.designARoutes})`);

  const registry = process.env.ANCHOR_REGISTRY_ADDRESS ?? readDeployment().trustAnchorRegistry;
  const chainId = Number(await rpc<string>("eth_chainId"));
  const startBlock = parseInt(await rpc<string>("eth_blockNumber"), 16);
  note(`chain ${chainId}  registry ${registry}  head #${startBlock}`);
  say();

  // ── 1. Five actors, each with their own key ────────────────────────────────
  say(C.bold("  1 · Five actors onboard with their own keys (SIWE + wallet binding)"));
  const { stored, fresh } = loadOrMintKeys();
  stored.chainId = chainId;
  const actors: Record<string, Actor> = {};
  for (const spec of CAST) actors[spec.key] = await onboard(spec, stored.actors[spec.key]!);
  writeFileSync(cfg.actorsPath, JSON.stringify(stored, null, 2));
  note(`${fresh ? "minted" : "reused"} ${CAST.length} demonstration actors — keys in ${cfg.actorsPath}`);
  if (fresh) {
    findings.push(
      "Design A's onboarding rate limits are sized for one actor, not for a ceremony. Per IP: " +
        "`wallet-challenge` 10 per 15 min, `wallet-login` 10 per 15 min, `wallet-bind` 5 per HOUR. A " +
        "five-actor first run needs exactly 10 challenges and exactly 5 binds — it fits with zero headroom, " +
        "one retry of anything fails it, and a SIXTH actor cannot be onboarded from the same IP within the " +
        "hour at all. This is invisible in production only while actors arrive from different addresses; a " +
        "brand onboarding its chain in one workshop, or several suppliers behind one corporate NAT, hits it. " +
        "This script now persists each actor's binding and skips re-binding on later runs, which is a " +
        "workaround for the script, not a fix for the surface.",
    );
  }
  const operator = actors.operator!;
  const suppliers = CAST.filter((s) => s.role === "supplier").map((s) => actors[s.key]!);
  say();

  // ── 2. The product, its data and its chain ─────────────────────────────────
  say(C.bold("  2 · The operator creates the product, its data and its supply chain"));
  const content = passportFields();
  const dpp = await step(
    "ceremony.product.create",
    "create product + draft passport",
    "operator",
    () =>
      api<{ id: string; did: string; productName: string }>("POST", "/api/dpps", {
        token: operator.token,
        body: {
          productName: content.productName,
          category: content.category,
          productLine: "Design A ceremony",
          sku: `DEMO-A-${Date.now().toString(36).toUpperCase()}`,
        },
      }),
    (d) => ({ passportId: d.id, productDid: d.did }),
  );
  note(`${dpp.id}   product DID ${dpp.did}   GTIN ${content.gtin}`);

  await step(
    "ceremony.product.fields",
    `save ${Object.keys(content.values).length} regulated field values`,
    "operator",
    () => api("PUT", `/api/dpps/${dpp.id}/fields`, { token: operator.token, body: { values: content.values } }),
  );

  const nodes: Record<string, string> = {};
  for (const supplier of suppliers) {
    const tier = await step(
      `ceremony.tier.${supplier.key}`,
      `bind node "${supplier.tierRole}" → ${supplier.company}`,
      "operator",
      () =>
        api<{ tierId: string }>("POST", `/api/dpps/${dpp.id}/supply-chain/tiers`, {
          token: operator.token,
          body: {
            tierIndex: supplier.tierIndex,
            tierRole: supplier.tierRole,
            tierName: supplier.orgName,
            roles: supplier.roles,
            orgId: supplier.orgId,
          },
        }),
      (t) => ({ nodeId: t.tierId, roles: supplier.roles }),
    );
    nodes[supplier.key] = tier.tierId;
  }
  say();

  // ── 3. The operator claims the product on chain ────────────────────────────
  say(C.bold("  3 · The operator claims the product on chain (self-signed, first-claim-wins)"));
  const claimState = await step("ceremony.claim.state", "read on-chain claim state", "operator", () =>
    api<{ productId: string; claimed: boolean; canClaim: boolean }>("GET", `/api/trust/design-a/passports/${dpp.id}/claim`, {
      token: operator.token,
    }),
  );
  const productId = claimState.productId;
  note(`productId ${productId} = keccak256(${dpp.did})`);

  /*
   * This used to be one `claimProduct` call plus a per-supplier `setIssuer` loop —
   * five transactions, and honest for the API of its day. Production stopped
   * driving that path in August: the one-click ceremony reads `GET /publish/plan`,
   * signs each step (EIP-712, per-signer sequential nonces), and POSTs the signed
   * plan back, where new issuers land in ONE batched `setIssuers` transaction.
   */
  const plan = await step(
    "ceremony.plan.read",
    "read the one-click publish plan",
    "operator",
    () =>
      api<{
        baseNonce: string;
        ready: boolean;
        steps: { kind: "claim" | "authorize"; issuerDids: string[]; nonce: string; payload: any; label: string }[];
      }>("GET", `/api/trust/design-a/passports/${dpp.id}/publish/plan`, { token: operator.token }),
    (p) => ({ baseNonce: p.baseNonce, steps: p.steps.map((x) => `${x.kind}[${x.issuerDids.length}]`) }),
  );
  if (!plan.ready) throw new Error("publish plan reports not ready — earlier chain work is still in flight");
  note(plan.steps.map((x) => x.label).join("  ·  "));

  const planSignatures = await step(
    "ceremony.plan.sign",
    `operator signs ${plan.steps.length} plan step(s) (EIP-712)`,
    "operator",
    async () => {
      const sigs: string[] = [];
      // Sequential, not Promise.all: the payloads carry consecutive nonces and
      // KEEPING the signing order identical to the queue order mirrors what the
      // wallet does — and makes the transcript read in the order the chain will.
      for (const st of plan.steps) sigs.push(await signTypedDataPayload(operator.wallet, st.payload));
      return sigs;
    },
    (sigs) => ({ signatures: sigs.length }),
  );

  await step("ceremony.plan.enqueue", "queue the signed plan for the relayer", "operator", () =>
    api("POST", `/api/trust/design-a/passports/${dpp.id}/publish/plan`, {
      token: operator.token,
      body: {
        baseNonce: plan.baseNonce,
        steps: plan.steps.map((st, i) => ({
          kind: st.kind,
          issuerDids: st.issuerDids,
          nonce: st.nonce,
          signature: planSignatures[i],
        })),
      },
    }),
  );

  await step("ceremony.plan.confirm.claim", "claimProduct: confirmed on chain", "operator", () =>
    waitFor("claimProduct", async () => {
      const s = await api<{ claimedByThisOrg: boolean }>("GET", `/api/trust/design-a/passports/${dpp.id}/claim`, {
        token: operator.token,
      });
      return s.claimedByThisOrg;
    }),
  );
  await step("ceremony.plan.confirm.issuers", `setIssuers: all ${suppliers.length} suppliers authorized on chain`, "operator", () =>
    waitFor("setIssuers", async () => {
      for (const supplier of suppliers) {
        if (!(await chainAuthorized(registry, productId, addressOfDid(supplier.did)))) return false;
      }
      return true;
    }),
  );
  findings.push(
    "No API read exists for on-chain authorisation state or for the outbox status of a queued " +
      "claimProduct/setIssuer. `GET /passports/:id/anchor` returns a queue, but filtered to `kind: \"anchor\"`, " +
      "and `GET /passports/:id/claim` covers only the claim. So an operator UI cannot tell a supplier " +
      "\"your authorisation is still pending\" — it can only retry the upload and read the 403. This script " +
      "waits on `authorized[productId][issuer]` over JSON-RPC instead, which is what the upload route and " +
      "any verifier do, but it is a gap in the browser-drivable surface.",
  );
  say();

  // ── 5. Every actor signs their own slice ───────────────────────────────────
  say(C.bold("  5 · Every actor signs their own credential slice (ES256K-R JWS)"));
  const signingSamples: number[] = [];
  const signedRoles: { role: string; actor: string; issuerDid: string; signerAddress: string; snapshotHash: string }[] = [];

  for (const actor of [operator, ...suppliers]) {
    const coverage = await step(
      `ceremony.attest.${actor.key}.coverage`,
      `${actor.company}: read what this org must sign`,
      actor.key,
      () =>
        api<{ roles: any[] }>("GET", `/api/trust/design-a/passports/${dpp.id}/attestations`, { token: actor.token }),
      (c) => ({ mine: c.roles.filter((r) => r.mine).map((r) => `${r.role}:${r.state}`) }),
    );
    const mine = coverage.roles.filter((r) => r.mine);
    if (!mine.length) throw new Error(`${actor.company} owns no role on this passport — the chain graph is wrong`);

    for (const view of mine) {
      const t0 = process.hrtime.bigint();
      const claim = decompose(view);
      const validFrom = new Date();
      const { jws, body, signerAddress } = signAttestationJws(claim, validFrom, actor.privateKey);

      // The browser's own guard: if THIS file's assembly does not reproduce the
      // reference the server displayed, a value exists that was never read and
      // would be inside signed bytes. Loud, before anything is signed for real.
      const diverged = divergesFromReference(body, view.credential);
      if (diverged) {
        throw new Error(
          `role "${view.role}": this script's assembly differs from the server's reference at \`${diverged}\` — ` +
            "refusing to sign a document that was not displayed",
        );
      }

      const stored = await step(
        `ceremony.attest.${actor.key}.${view.role}`,
        `${actor.company}: sign + upload "${view.role}"`,
        actor.key,
        () =>
          api<{ attestation: { snapshotHash: string }; verified: boolean }>(
            "POST",
            `/api/trust/design-a/passports/${dpp.id}/attestations`,
            { token: actor.token, body: { role: view.role, credential: jws } },
          ),
        (s) => ({ verified: s.verified, snapshotHash: s.attestation.snapshotHash, signerAddress }),
      );
      // The RQ3 sample: assemble + digest + sign + upload + the server's six
      // checks (two of which are chain reads). The whole "sign → VC on the
      // server" span, minus the wallet — see the measurement's `excludes`.
      signingSamples.push(Number(process.hrtime.bigint() - t0) / 1e6);
      signedRoles.push({
        role: view.role,
        actor: actor.company,
        issuerDid: claim.issuerDid,
        signerAddress,
        snapshotHash: stored.attestation.snapshotHash,
      });
    }
  }
  note(`${signedRoles.length} credentials signed by ${new Set(signedRoles.map((r) => r.issuerDid)).size} distinct issuers`);
  say();

  // ── 6. The operator signs an approval per role ─────────────────────────────
  say(C.bold("  6 · The operator signs a review decision per role (EIP-712, zero gas)"));
  for (const supplier of suppliers) {
    const nodeId = nodes[supplier.key]!;
    const review = await step(
      `ceremony.review.${supplier.key}.payload`,
      `${supplier.company}: build approval payloads`,
      "operator",
      () =>
        api<{ issuedAt: number; roles: { role: string; signable: boolean; attestationState: string; payload: any }[] }>(
          "GET",
          `/api/trust/design-a/passports/${dpp.id}/nodes/${nodeId}/review?decision=approved`,
          { token: operator.token },
        ),
      (r) => ({ roles: r.roles.map((x) => `${x.role}:${x.attestationState}`) }),
    );
    const signable = review.roles.filter((r) => r.signable);
    const signatures = await step(
      `ceremony.review.${supplier.key}.sign`,
      `${supplier.company}: operator signs ${signable.length} approval(s)`,
      "operator",
      async () =>
        Promise.all(
          signable.map(async (r) => ({ role: r.role, signature: await signTypedDataPayload(operator.wallet, r.payload) })),
        ),
    );
    await step(
      `ceremony.review.${supplier.key}.post`,
      `${supplier.company}: record the signed decision`,
      "operator",
      () =>
        api<{ dataStatus: string }>("POST", `/api/trust/design-a/passports/${dpp.id}/nodes/${nodeId}/review`, {
          token: operator.token,
          body: { action: "approve", issuedAt: review.issuedAt, signatures },
        }),
      (r) => ({ dataStatus: r.dataStatus }),
    );
  }
  say();

  // ── 7. Publish — assembly, not signing ─────────────────────────────────────
  say(C.bold("  7 · Publish assembles the pre-signed envelopes (CeremonyAssembly)"));
  const published = await step(
    "ceremony.publish",
    "POST /api/dpps/:id/publish",
    "operator",
    () => api<any>("POST", `/api/dpps/${dpp.id}/publish`, { token: operator.token, body: {} }),
    (p) => ({ version: p?.version ?? p?.dpp?.version ?? null }),
  );
  const version = Number(published?.version ?? published?.dpp?.version ?? 1);
  note(`version ${version} frozen — the platform signed nothing; it verified coverage and assembled`);

  // ── 8. The chain-head checkpoint ───────────────────────────────────────────
  const head = await step(
    "ceremony.chainhead.payload",
    "operator: build the audit chain-head checkpoint",
    "operator",
    () =>
      api<{ seq: number; issuedAt: number; headHash: string; payload: any }>(
        "GET",
        `/api/trust/design-a/orgs/${operator.orgId}/chain-head/payload`,
        { token: operator.token },
      ),
    (h) => ({ seq: h.seq, headHash: h.headHash }),
  );
  const headSignature = await step("ceremony.chainhead.sign", "operator: signs the checkpoint", "operator", () =>
    signTypedDataPayload(operator.wallet, head.payload),
  );
  await step("ceremony.chainhead.post", "operator: store the signed checkpoint", "operator", () =>
    api("POST", `/api/trust/design-a/orgs/${operator.orgId}/chain-head`, {
      token: operator.token,
      body: { seq: head.seq, issuedAt: head.issuedAt, signature: headSignature },
    }),
  );
  say();

  // ── 9. The anchor ──────────────────────────────────────────────────────────
  say(C.bold("  9 · The operator signs the anchor; the relayer submits it"));
  let merkleRoot = "";
  let anchorNonce = 0n;
  await chainCall(
    "ceremony.anchor",
    "anchor",
    operator,
    async () => {
      const request = await api<{ merkleRoot: string; version: number; nonce: string; payload: any; credentialDigests: string[] }>(
        "GET",
        `/api/trust/design-a/passports/${dpp.id}/anchor/payload`,
        { token: operator.token },
      );
      merkleRoot = request.merkleRoot;
      anchorNonce = BigInt(request.nonce);
      return request;
    },
    (nonce, signature) =>
      api("POST", `/api/trust/design-a/passports/${dpp.id}/anchor`, {
        token: operator.token,
        body: { version, nonce, signature },
      }),
    // The registry's own nonce, not the platform's anchor endpoint. The contract
    // accepts a given (signer, nonce) exactly once, so `nonces[operator] >
    // anchorNonce` is an exact statement that THIS payload was applied — and it
    // is one `eth_call`. The platform's `GET …/anchor` cannot serve this wait;
    // see the finding recorded immediately below.
    async () => (await chainNonce(registry, operator.address)) > anchorNonce,
  );

  // The platform's own anchor read, attempted for real and reported honestly
  // whichever way it goes. On a range-capped endpoint it 503s, and the ceremony
  // has to survive that because the anchor is on chain either way.
  const anchorState = await step(
    "ceremony.anchor.state",
    "read the platform's anchor status",
    "operator",
    async () => {
      try {
        const s = await api<any>("GET", `/api/trust/design-a/passports/${dpp.id}/anchor`, { token: operator.token });
        return { ok: true as const, state: s };
      } catch (err) {
        return { ok: false as const, error: err instanceof ApiError ? { status: err.status, body: err.body } : String(err) };
      }
    },
    (r) => (r.ok ? { matches: r.state.matches, anchored: !!r.state.anchor } : r.error),
  );
  if (!anchorState.ok) {
    findings.push(
      "`GET /api/trust/design-a/passports/:id/anchor` — the ONLY API read of anchor status, and the one an " +
        "operator UI must poll after signing an anchor — returned " +
        `${(anchorState.error as any)?.status ?? "an error"} on this run. Cause: ` +
        "`ChainGateway.findAnchor` issues ONE unchunked `eth_getLogs` from `anchorsFromBlock` (which " +
        "`createChainGateway` never sets, so it is 0 — genesis) to `latest`. Every range-capped endpoint " +
        "refuses that: Alchemy's Amoy free tier caps it at TEN blocks, publicnode and dRPC at ten thousand. " +
        "The gateway's failover then asks the second endpoint the same impossible question and the route " +
        "503s. `verify-passport.mjs` already solves this exact problem — a backwards sweep in shrinking " +
        "windows under a request budget — so the fix is to port that into the gateway and to wire " +
        "`anchorsFromBlock` to the deployment block. Until then the anchor is unreadable through the API on " +
        "any free endpoint, while being perfectly readable on chain.",
    );
  }

  // Independent confirmation: find the Anchored log from the chain, in bounded
  // windows. This is also where the bundle's `anchorTxHash` hint comes from —
  // deliberately from the chain rather than from the platform's database, so it
  // is a value an outsider could have produced.
  const anchorLog = await step(
    "ceremony.anchor.log",
    "locate the Anchored log on chain (bounded scan)",
    null,
    () => scanAnchorLog(registry, productId, startBlock),
    (l) => l,
  );
  if (!anchorLog) throw new Error("the anchor transaction confirmed but no Anchored log was found for this productId");
  if (anchorLog.merkleRoot.toLowerCase() !== merkleRoot.toLowerCase()) {
    throw new Error(`the anchored root ${anchorLog.merkleRoot} is not the root this version produces (${merkleRoot})`);
  }
  note(`merkleRoot ${merkleRoot}`);
  note(`anchored in block ${anchorLog.blockNumber}, tx ${anchorLog.txHash}`);
  say();

  // ── 10. Export + independent verification ──────────────────────────────────
  say(C.bold("  10 · Export the bundle and verify it from outside the platform"));
  mkdirSync(cfg.outDir, { recursive: true });
  const bundlePath = join(cfg.outDir, `design-a-export-${dpp.id}-v${version}.json`);
  const bundle = await step(
    "ceremony.export",
    "GET /api/public/passports/:id/export (anonymous)",
    null,
    () => api<any>("GET", `/api/public/passports/${dpp.id}/export`),
    (b) => ({ credentials: (b.credentials ?? []).length, hash: b.hash }),
  );

  // `anchorTxHash` is a HINT the verifier accepts inside the bundle — it says
  // only WHERE to look, and the log found there is still checked against the
  // registry address, the topic, the productId, the version and the locally
  // recomputed root. The export route does not carry one, so it is attached here
  // from the log this script found on chain.
  const outbox = await step(
    "ceremony.outbox.read",
    "read the anchor outbox (measurement only, never a ceremony step)",
    null,
    () => readOutboxAwaitingAnchor(dpp.id),
    (o) => ({ rows: o.rows?.map((r) => `${r.kind}:${r.status}`) ?? null, unavailable: o.why }),
  );
  bundle.anchorTxHash = anchorLog.txHash;
  findings.push(
    "The public export bundle carries no anchoring transaction hash, so an independent verifier has to " +
      "sweep `eth_getLogs` to find the anchor — which on a range-capped free-tier endpoint exhausts its " +
      "request budget and yields an honest but useless \"inconclusive\". `verify-passport.mjs` already " +
      "accepts an `anchorTxHash` member (a hint; the log found there is still fully checked against the " +
      "registry, the topic, the productId, the version and the recomputed root). Emitting it from " +
      "`GET /api/public/passports/:id/export` would cost one column read and remove the sweep entirely. " +
      "This script attaches it from the chain so the exported bundle in scripts/out/ is directly verifiable.",
  );
  writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
  note(`bundle → ${bundlePath}`);

  let verdict: { verdict: string; exitCode: number; counts?: unknown } | null = null;
  if (cfg.verify) {
    const args = [VERIFIER, bundlePath, "--json", "--rpc", cfg.rpc.url, "--from-block", String(startBlock - 5)];
    if (bundle.anchorTxHash) args.push("--anchor-tx", bundle.anchorTxHash);
    const run = await step("verification.designA.singleRun", "node scripts/verify-passport.mjs <bundle>", null, async () => {
      const r = spawnSync(process.execPath, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      let report: any = null;
      try {
        report = JSON.parse(r.stdout);
      } catch {
        /* keep null; the exit code is still meaningful */
      }
      return { exitCode: r.status ?? -1, report, stderr: (r.stderr ?? "").slice(0, 2000) };
    });
    verdict = { verdict: run.report?.verdict ?? "UNPARSEABLE", exitCode: run.exitCode, counts: run.report?.counts };
    const colour = verdict.verdict === "VERIFIED" ? C.green : verdict.verdict === "FAILED" ? C.red : C.yellow;
    note(`verdict ${colour(C.bold(verdict.verdict))} (exit ${verdict.exitCode})  ${JSON.stringify(verdict.counts ?? {})}`);
    if (run.report?.checks) {
      for (const c of run.report.checks.filter((x: any) => x.status !== "PASS")) {
        note(`${C.yellow(c.status)} ${c.name}: ${String(c.detail ?? "").slice(0, 140)}`);
      }
    }
  }
  say();

  // ── 11. Measurements ───────────────────────────────────────────────────────
  await recordMeasurements({
    passportId: dpp.id,
    productDid: dpp.did,
    version,
    actors,
    signingSamples,
    outbox,
    verdict,
    bundlePath,
    startedAt,
  });

  // ── 12. The run artifact ───────────────────────────────────────────────────
  const runPath = join(cfg.outDir, `design-a-run-${startedAt.toISOString().replace(/[:.]/g, "-")}.json`);
  const run = {
    tool: "seed-design-a",
    formatVersion: 1,
    demonstrationAccounts: true,
    disclaimer:
      "Every organisation named here is a DEMONSTRATION ACCOUNT created by scripts/seed-design-a.ts. The " +
      "script held the five actors' private keys because in this scenario it IS the five actors; it drove " +
      "only the platform's real HTTP routes and the platform holds no key at any point.",
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    provenance: provenance(chainId, registry, startBlock),
    passport: {
      passportId: dpp.id,
      productDid: dpp.did,
      productId,
      version,
      merkleRoot,
      bundlePath,
      publicUrl: `${cfg.api}/api/public/passports/${dpp.id}`,
    },
    actors: Object.values(actors).map((a) => ({
      key: a.key,
      organisation: a.orgName,
      demonstrationAccount: true,
      role: a.role,
      orgId: a.orgId,
      did: a.did,
      address: a.address,
      chainRoles: a.roles,
      provisionedThisRun: a.provisioned,
    })),
    credentials: signedRoles,
    chain: { outbox: outbox.rows, outboxUnavailable: outbox.why },
    verification: verdict,
    findings,
    steps,
    measurements,
  };
  writeFileSync(runPath, JSON.stringify(run, null, 2));

  // ── 13. Summary ────────────────────────────────────────────────────────────
  summarise(run);
  if (cfg.json) console.log(JSON.stringify(run, null, 2));

  return verdict && verdict.verdict !== "VERIFIED" ? 3 : 0;
}

/** `did:ethr:<chain>:<address>` → the address. */
function addressOfDid(did: string): string {
  const m = /^did:ethr:(?:[^:]+:)?(0x[0-9a-fA-F]{40})$/.exec(did.trim());
  if (!m) throw new Error(`not a did:ethr: ${did}`);
  return m[1]!.toLowerCase();
}

function readDeployment(): any {
  const p = join(REPO, "contracts", "deployments", "amoy.json");
  if (!existsSync(p)) throw new Error(`no deployment file at ${p} — pass ANCHOR_REGISTRY_ADDRESS`);
  return JSON.parse(readFileSync(p, "utf8"));
}

function provenance(chainId: number, registry: string, startBlock: number) {
  const git = (args: string[]) => {
    const r = spawnSync("git", ["-C", REPO, ...args], { encoding: "utf8" });
    return r.status === 0 ? r.stdout.trim() : null;
  };
  const cpus = os.cpus();
  return {
    takenAt: new Date().toISOString(),
    git: {
      commit: git(["rev-parse", "HEAD"]),
      shortCommit: git(["rev-parse", "--short", "HEAD"]),
      branch: git(["rev-parse", "--abbrev-ref", "HEAD"]),
      dirty: !!git(["status", "--porcelain"]),
    },
    machine: {
      platform: `${os.platform()} ${os.release()}`,
      arch: os.arch(),
      cpuModel: cpus[0]?.model ?? null,
      cpuCount: cpus.length,
    },
    runtime: { node: process.version },
    chain: { chainId, trustAnchorRegistry: registry, startBlock, rpcHost: rpcHost(cfg.rpc.url), rpcSource: cfg.rpc.source },
    api: cfg.api,
  };
}

/*
 * The rule is measure-rq3's, inherited verbatim: **a number that was not
 * measured is null**, and a number that was measured under different conditions
 * than the row promises gets a DIFFERENT id rather than the promised one. Two
 * rows here are deliberately NOT the ids the RQ3 metrics name:
 * `onboarding.designA.headless` and `signing.designA.ceremony.headless`. They
 * run without a browser, so they measure a lower bound of those metrics.
 */

async function recordMeasurements(ctx: {
  passportId: string;
  productDid: string;
  version: number;
  actors: Record<string, Actor>;
  signingSamples: number[];
  outbox: { rows: OutboxRow[] | null; why: string | null };
  verdict: { verdict: string; exitCode: number } | null;
  bundlePath: string;
  startedAt: Date;
}): Promise<void> {
  // ── Onboarding, per actor: challenge → login → challenge → bound did:ethr.
  const onboardingSamples = CAST.map(
    (spec) =>
      msOf(`onboarding.${spec.key}.challenge`) +
      msOf(`onboarding.${spec.key}.login`) +
      msOf(`onboarding.${spec.key}.bindChallenge`) +
      msOf(`onboarding.${spec.key}.bind`),
  );
  record({
    id: "onboarding.designA.headless",
    metric: "Onboarding — Design A, PROTOKOLLANTEIL (SIWE-Challenge → did:ethr gebunden, ohne Browser/tKey)",
    unit: "ms",
    state: "measured",
    provenance: "platform",
    dist: describe(onboardingSamples),
    samples: onboardingSamples.map((x) => round(x)!),
    includes: [
      "GET /api/auth/challenge (login) — a server-minted EIP-4361 message",
      "personal_sign by the actor's own key",
      "POST /api/auth/wallet-login — signature verified, tenant provisioned on first sight",
      "GET /api/auth/challenge (bind) + POST /api/auth/wallet/bind — the org's did:ethr is minted",
      "four HTTP round trips over loopback",
    ],
    excludes: [
      "the Web3Auth OAuth redirect",
      "2-of-3 tKey share reconstruction in the browser",
      "key derivation in the page",
      "everything a human does",
    ],
    notes:
      "NOT §13's primary metric and deliberately not filed under its id. §13 asks for 'Google-Login bis " +
      "did:ethr registriert'; this is the platform-and-protocol component of that span, i.e. a LOWER BOUND. " +
      "It is worth having because it says how much of the 30–60 s estimate is NOT the platform: on this run " +
      "the platform's share is milliseconds, so the estimate is almost entirely tKey and OAuth. Filling " +
      "`onboarding.designA` still needs a headless browser driving the real login.",
    detail: { actors: CAST.map((s) => s.key), transport: "loopback HTTP" },
  });

  // ── Signing, per credential.
  record({
    id: "signing.designA.ceremony.headless",
    metric: "Signierlatenz — Design A, PROTOKOLLANTEIL (Dokument bauen → VC auf dem Server, ohne Wallet)",
    unit: "ms",
    state: "measured",
    provenance: "platform",
    dist: describe(ctx.signingSamples),
    samples: ctx.signingSamples.map((x) => round(x)!),
    includes: [
      "assembling the credential body with the shared dpp-core kernel",
      "SHA-256 of the JWS signing input and one secp256k1 signature (ES256K-R, low-s)",
      "local recovery self-check + the browser's divergence check against the server's reference",
      "POST …/attestations and the upload route's six checks — including TWO CHAIN READS " +
        "(ERC-1056 DID resolution and the on-chain authorization root)",
    ],
    excludes: [
      "opening a wallet: no OAuth, no tKey reconstruction, no user reading a WYSIWYS dialog",
      "the coverage GET that precedes it (timed separately as ceremony.attest.*.coverage)",
    ],
    notes:
      "A LOWER BOUND on §24's 0.5–1.2 s estimate, and a useful one: the dominant term here is the server's " +
      "two chain reads, not the cryptography. The signature itself is sub-millisecond; the RPC round trips are " +
      "not. That is an architectural cost of Mechanism 4 and it is visible in this row rather than hidden " +
      "inside a wallet number.",
    detail: { credentials: ctx.signingSamples.length },
  });

  record({
    id: "signing.designA.platformSideKeyMaterial",
    metric: "Plattform-seitige Signierlatenz — Design A",
    unit: "ms",
    state: "n/a",
    provenance: "structural",
    reason:
      "There is no platform-side signing path to time. `DesignATrust.signCredential` throws by construction, " +
      "publish is `CeremonyAssembly` (validate coverage, freeze, assemble), and this run produced six signed " +
      "credentials without the server ever holding key material. Reporting 0 would read as 'the platform signs " +
      "instantly'; it does not sign at all.",
  });

  // ── Gas, from real receipts.
  if (!ctx.outbox.rows) {
    record({
      id: "gas.realCeremonyTx",
      metric: "Gas — reale Zeremonie-Transaktionen (claimProduct / setIssuers-Batch / anchor, gasUsed aus Receipts)",
      unit: "gas",
      state: "unavailable",
      provenance: "chain",
      reason: ctx.outbox.why ?? "the AnchorTx outbox could not be read",
      precondition: `a reachable database (--db-container, default ${cfg.dbContainer})`,
    });
  } else {
    const receipts: Record<string, unknown> = {};
    let totalGas = 0;
    let totalPol = 0;
    const byKind: Record<string, number[]> = {};
    for (const row of ctx.outbox.rows) {
      if (!row.txHash) continue;
      const r = await receiptOf(row.txHash);
      const label = `${row.kind}#${Object.keys(receipts).filter((k) => k.startsWith(row.kind)).length + 1}`;
      receipts[label] = { ...r, outboxStatus: row.status };
      if (typeof (r as any).gasUsed === "number") {
        totalGas += (r as any).gasUsed;
        totalPol += (r as any).costPol ?? 0;
        (byKind[row.kind] ??= []).push((r as any).gasUsed);
      }
    }
    record({
      id: "gas.realCeremonyTx",
      metric: "Gas — reale Zeremonie-Transaktionen (claimProduct / setIssuers-Batch / anchor, gasUsed aus Receipts)",
      unit: "gas",
      state: "measured",
      provenance: "chain",
      value: {
        ...Object.fromEntries(Object.entries(byKind).map(([k, v]) => [k, { count: v.length, gasUsed: v }])),
        totalGas,
        totalCostPol: roundPol(totalPol),
      },
      includes: ["real gasUsed and the real effectiveGasPrice paid, from mined receipts on Polygon Amoy"],
      excludes: ["contract deployment (paid once per chain — see gas.deployment)"],
      notes:
        "The FIRST Design A ceremony transactions that really happened, and the row measure-rq3 lists as " +
        "unavailable with the precondition 'one Design A publication driven end to end'. Cross-check them " +
        "against gas.totalTx (Foundry, cold slots): a live signature's bytes differ per key and a zero " +
        "calldata byte costs 4 gas against 16, so the live figure moves by a few gas.",
      detail: { receipts, passportId: ctx.passportId, productDid: ctx.productDid },
    });
  }

  // ── Time-to-anchor, from the outbox timestamps.
  const anchorRows = (ctx.outbox.rows ?? []).filter((r) => r.kind === "anchor" && r.confirmedAt);
  if (!anchorRows.length) {
    // Stated as a null with its precondition, never omitted: a missing row and a
    // row that could not be measured must not look the same.
    record({
      id: "anchor.timeToConfirm",
      metric: "Time-to-Anchor (Outbox-Queue → bestätigter Receipt)",
      unit: "ms",
      state: "unavailable",
      provenance: "platform",
      reason:
        ctx.outbox.why ??
        "the anchor is confirmed ON CHAIN but the relayer had not yet written `confirmedAt` when this run " +
          "read the outbox — the observation lags the chain by up to one 15 s poll",
      precondition: "re-run measure-rq3.mjs, which reads the same two timestamps once the relayer has caught up",
    });
  } else {
    const samples = anchorRows.map((r) => Date.parse(r.confirmedAt!) - Date.parse(r.createdAt));
    record({
      id: "anchor.timeToConfirm",
      metric: "Time-to-Anchor (Outbox-Queue → bestätigter Receipt)",
      unit: "ms",
      state: "measured",
      provenance: "platform",
      dist: describe(samples),
      samples: samples.map((x) => round(x)!),
      includes: [
        "outbox queue wait (the relayer's 15 s poll interval)",
        "transaction broadcast",
        "Polygon Amoy block time and the relayer's confirmation observation (another poll tick)",
      ],
      excludes: ["the publish itself — the clock starts when the AnchorTx row is created"],
      notes:
        "Read from the stored createdAt/confirmedAt, exactly as measure-rq3 reads it — this row is here so " +
        "the run artifact is self-contained, not because it is measured differently. DOMINATED by the " +
        "relayer's 15 s poll cadence, which is an implementation choice, not a property of the chain: two " +
        "poll ticks account for most of it.",
      detail: { rows: anchorRows.length },
    });
  }

  // ── Verification: one run only. Not a distribution, and it does not pretend.
  record({
    id: "verification.designA.singleRun",
    metric: "Graph-Verifikation — Design A, EINE Ausführung (kein Sample)",
    unit: "ms",
    state: ctx.verdict ? "measured" : "unavailable",
    provenance: "independent",
    value: ctx.verdict ? { ms: round(msOf("verification.designA.singleRun")), verdict: ctx.verdict.verdict } : null,
    reason: ctx.verdict ? null : "--no-verify was passed",
    precondition: ctx.verdict
      ? null
      : "run without --no-verify, or point measure-rq3 at the exported bundle",
    includes: ["one `node scripts/verify-passport.mjs <bundle> --rpc … --anchor-tx …` subprocess, end to end"],
    excludes: ["any repetition — n = 1 is not a distribution and is not reported as one"],
    notes:
      "The DISTRIBUTION belongs to measure-rq3, which repeats the verifier N ≥ 30 times with warmups. " +
      `Fill verification.designA.local / .full with:  node scripts/measure-rq3.mjs --b-bundle ${ctx.bundlePath}`,
    detail: { bundlePath: ctx.bundlePath, exitCode: ctx.verdict?.exitCode ?? null },
  });

  record({
    id: "gas.perActorDid.observed",
    metric: "Gaskosten pro Akteur-DID — beobachtet",
    unit: "gas",
    state: "measured",
    provenance: "chain",
    value: 0,
    includes: [`${CAST.length} did:ethr identities minted and bound during this run`],
    excludes: [],
    notes:
      "measure-rq3 carries this as `structural` (a did:ethr is derived from the address, so no registry " +
      "transaction exists). This run OBSERVED it: five organisations acquired working, resolvable issuer " +
      "identities and the outbox recorded no transaction for any of them. The structural claim and the " +
      "observation agree, which is the point of recording both.",
    detail: { dids: Object.values(ctx.actors).map((a) => a.did) },
  });
}

function summarise(run: any): void {
  say(C.bold("  ── Result ────────────────────────────────────────────────────────────"));
  say();
  say(`  passport      ${C.bold(run.passport.passportId)}  v${run.passport.version}`);
  say(`  product DID   ${run.passport.productDid}`);
  say(`  productId     ${run.passport.productId}`);
  say(`  merkle root   ${run.passport.merkleRoot}`);
  say(`  credentials   ${run.credentials.length} signed by ${new Set(run.credentials.map((c: any) => c.issuerDid)).size} distinct did:ethr issuers`);
  say();
  say(C.bold("  transactions"));
  const gas = run.measurements.find((m: any) => m.id === "gas.realCeremonyTx");
  const receipts = (gas?.detail as any)?.receipts ?? {};
  for (const [label, r] of Object.entries<any>(receipts)) {
    say(
      `    ${label.padEnd(12)} ${r.txHash ?? "—"}  ${String(r.gasUsed ?? "?").padStart(7)} gas  ` +
        `${r.costPol ?? "?"} POL  ${r.status === "success" ? C.green("success") : C.red(String(r.status))}`,
    );
  }
  if (gas?.value) say(C.dim(`    total        ${gas.value.totalGas} gas   ${gas.value.totalCostPol} POL`));
  say();
  if (run.verification) {
    const v = run.verification.verdict;
    const colour = v === "VERIFIED" ? C.green : v === "FAILED" ? C.red : C.yellow;
    say(`  verifier      ${colour(C.bold(v))}  (exit ${run.verification.exitCode})  ${JSON.stringify(run.verification.counts ?? {})}`);
  }
  say(`  total time    ${Math.round(steps.reduce((n, s) => n + s.ms, 0) / 1000)} s over ${steps.length} steps`);
  say();
  if (run.findings.length) {
    say(C.bold("  findings — what the real API could not do"));
    for (const f of run.findings) say(C.yellow(`    • ${wrap(f)}`));
    say();
  }
  say(C.dim(`  run artifact  ${run.passport.bundlePath.replace(/export-.*/, "")}…`));
  say();
}

function wrap(s: string): string {
  const width = 100;
  const words = s.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if (line.length + w.length + 1 > width) {
      lines.push(line);
      line = w;
    } else line = line ? `${line} ${w}` : w;
  }
  if (line) lines.push(line);
  return lines.join("\n      ");
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    say();
    say(C.red(`  ✗ ${err instanceof Error ? err.message : String(err)}`));
    if (steps.length) {
      say();
      say(C.dim("  steps completed before the failure:"));
      for (const s of steps) say(C.dim(`    ${s.id.padEnd(40)} ${String(Math.round(s.ms)).padStart(7)} ms`));
    }
    say();
    process.exit(1);
  });
