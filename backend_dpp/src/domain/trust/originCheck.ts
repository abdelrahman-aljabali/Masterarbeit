import { config } from "../../config.js";
import { logger } from "../../observability/logger.js";
// V3, deliberately: the self-check must probe the context CURRENTLY frozen into
// new signed bytes, not a predecessor that happens to still be served. (v2 kept
// resolving when /vocab was unreachable — a green check guarding the wrong door.)
import { CONTEXT_URL_V3 } from "./trustUrls.js";
import { DPP_CONTEXT_V3 } from "./vcContext.js";
import { didWebHost } from "./did.js";

/**
 * ─── CREDENTIAL_ORIGIN reachability self-check ────────────────────────────────
 * Every identifier frozen into a signed credential — `@context`, the schema id,
 * the status-list URL, the credential's own `id`, and (since the DID host moved
 * here) the issuer DID — lives under CREDENTIAL_ORIGIN. Verification INSIDE this
 * process never notices if that domain is misrouted, because the document loader
 * resolves those URLs from bundled copies and the database.
 */

export interface OriginCheckResult {
  checked: boolean;
  ok: boolean;
  origin: string;
  contextUrl: string;
  didWebHost: string;
  detail: string;
}

let lastResult: OriginCheckResult = {
  checked: false,
  ok: true,
  origin: config.credentialOrigin,
  contextUrl: CONTEXT_URL_V3,
  didWebHost: didWebHost(),
  detail: "not run",
};

/** The most recent self-check verdict (surfaced on /ready). */
export function credentialOriginStatus(): OriginCheckResult {
  return lastResult;
}

export async function checkCredentialOrigin(
  opts: { force?: boolean; timeoutMs?: number } = {},
): Promise<OriginCheckResult> {
  const base: Omit<OriginCheckResult, "ok" | "detail" | "checked"> = {
    origin: config.credentialOrigin,
    contextUrl: CONTEXT_URL_V3,
    didWebHost: didWebHost(),
  };

  if (!config.isProduction && !opts.force) {
    lastResult = { ...base, checked: false, ok: true, detail: "skipped outside production" };
    return lastResult;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 5_000);
  try {
    const res = await fetch(CONTEXT_URL_V3, {
      signal: controller.signal,
      headers: { Accept: "application/ld+json, application/json" },
    });
    if (!res.ok) {
      lastResult = { ...base, checked: true, ok: false, detail: `HTTP ${res.status} fetching the pinned @context URL` };
    } else {
      const body = (await res.json()) as Record<string, unknown>;
      // Compare the served context to the bytes we SIGN against. Anything else
      // means a different deployment (or a parked domain) owns these URLs.
      const ours = JSON.stringify(DPP_CONTEXT_V3);
      lastResult =
        JSON.stringify(body) === ours
          ? { ...base, checked: true, ok: true, detail: "pinned identifiers resolve to this deployment" }
          : {
              ...base,
              checked: true,
              ok: false,
              detail: "the pinned @context URL resolves, but serves DIFFERENT bytes than this instance signs against",
            };
    }
  } catch (err) {
    lastResult = {
      ...base,
      checked: true,
      ok: false,
      detail: `could not fetch the pinned @context URL: ${(err as Error).message}`,
    };
  } finally {
    clearTimeout(timer);
  }

  if (lastResult.ok) {
    logger.info({ origin: base.origin, didWebHost: base.didWebHost }, "credential origin self-check passed");
  } else {
    logger.error(
      { origin: base.origin, contextUrl: base.contextUrl, didWebHost: base.didWebHost, detail: lastResult.detail },
      "CREDENTIAL_ORIGIN self-check FAILED — credentials signed here advertise identifiers that third parties cannot resolve. " +
        "Every URL in signed bytes (and every issuer DID) points at this origin; it must route to this deployment permanently.",
    );
  }
  return lastResult;
}

// ── Self-healing watch ────────────────────────────────────────────────────────

const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 10 * 60_000;

export function startCredentialOriginWatch(): void {
  let attempt = 0;
  const run = async (): Promise<void> => {
    let result: OriginCheckResult;
    try {
      result = await checkCredentialOrigin();
    } catch {
      result = { ...lastResult, ok: false };
    }
    if (!result.checked || result.ok) return; // passed, or skipped outside production
    attempt += 1;
    const delay = Math.min(RETRY_BASE_MS * 2 ** (attempt - 1), RETRY_MAX_MS);
    logger.warn({ attempt, nextRetryMs: delay }, "credential origin self-check failed — will retry");
    // unref: a pending retry must never hold the process open through shutdown.
    setTimeout(() => void run(), delay).unref();
  };
  void run();
}
