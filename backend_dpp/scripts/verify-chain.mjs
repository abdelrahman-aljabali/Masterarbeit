#!/usr/bin/env node
/**
 * ─── Standalone audit-chain verifier (thesis artifact) ────────────────────────
 * Independently verifies a TrustDPP organization's tamper-evident audit chain
 * using NOTHING but Node's built-in crypto + fetch — no TrustDPP code, no npm
 * dependencies. This is the point of the design: the check must not trust the
 * platform it is checking.
 */
import crypto from "node:crypto";

const args = process.argv.slice(2);
const exportIdx = args.indexOf("--export");
const exportFile = exportIdx >= 0 ? args[exportIdx + 1] : null;
const [baseUrl, orgId] = args.filter((a, i) => a !== "--export" && args[i - 1] !== "--export");
if (!baseUrl || !orgId) {
  console.error("usage: [TOKEN=<token>] node verify-chain.mjs <baseUrl> <orgId> [--export <file>]");
  process.exit(2);
}
const TOKEN = process.env.TOKEN || "";

// ── canonical serialization (mirror of the platform's stableStringify) ────────
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const canonicalHash = (v) => sha256(stableStringify(v));

// ── multibase base58btc → raw Ed25519 public key ──────────────────────────────
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Decode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`invalid base58 char ${c}`);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of s) { if (c === "1") bytes.unshift(0); else break; }
  return Buffer.from(bytes);
}
function ed25519KeyFromMultibase(multibase) {
  if (!multibase.startsWith("z")) throw new Error("expected base58btc multibase (z…)");
  const decoded = base58Decode(multibase.slice(1));
  // multicodec ed25519-pub prefix 0xed 0x01
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error("not an ed25519-pub multikey");
  const raw = decoded.subarray(2);
  // wrap raw key in SPKI DER so node crypto can consume it
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

// ── fetch the export + head ───────────────────────────────────────────────────
async function getJson(path, auth = false) {
  const headers = auth && TOKEN ? { authorization: `Bearer ${TOKEN}` } : {};
  const res = await fetch(`${baseUrl}${path}`, { headers });
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}${res.status === 401 ? " (set TOKEN=<org access token> for the authenticated export)" : ""}`);
  return res.json();
}

const events = [];
if (exportFile) {
  // Auditor path: verify an export the org handed you against the platform's
  // public signed head — no platform auth needed to read the events.
  const { readFileSync } = await import("node:fs");
  const doc = JSON.parse(readFileSync(exportFile, "utf8"));
  events.push(...(doc.events ?? doc));
  console.log(`loaded ${events.length} events from ${exportFile}`);
} else {
  // Org path: pull your own chain from the authenticated dashboard export.
  let fromSeq = 1;
  for (;;) {
    const page = await getJson(`/api/dashboard/audit-export?fromSeq=${fromSeq}&limit=1000`, true);
    events.push(...page.events);
    if (!page.nextFromSeq) break;
    fromSeq = page.nextFromSeq;
  }
  console.log(`fetched ${events.length} chained events for ${orgId}`);
}

// ── 1. recompute every link ───────────────────────────────────────────────────
let prevHash = null;
let ok = true;
for (const e of events) {
  const expected = canonicalHash({
    content: {
      at: e.at,
      action: e.action,
      actorUserId: e.actorUserId,
      orgId: e.orgId,
      targetType: e.targetType,
      targetId: e.targetId,
      details: e.details ?? null,
      seq: e.seq,
    },
    prevHash,
  });
  if (e.prevHash !== prevHash) {
    console.error(`✗ seq ${e.seq}: prevHash mismatch (chain broken or reordered)`);
    ok = false; break;
  }
  if (e.hash !== expected) {
    console.error(`✗ seq ${e.seq}: hash mismatch — content was altered after the fact`);
    console.error(`  stored:     ${e.hash}`);
    console.error(`  recomputed: ${expected}`);
    ok = false; break;
  }
  prevHash = e.hash;
}
if (ok) console.log(`✓ all ${events.length} hashes recompute — no event was altered, removed or reordered`);

// ── 2. verify the signed chain head ───────────────────────────────────────────
const head = await getJson(`/api/public/orgs/${orgId}/chain-head`);
const digest = canonicalHash({ orgId: head.orgId, seq: head.seq, headHash: head.headHash, at: head.at });
if (digest !== head.signedDigest) {
  console.error("✗ chain-head digest does not recompute from its own fields");
  ok = false;
} else {
  const key = ed25519KeyFromMultibase(head.publicKeyMultibase);
  const sigOk = crypto.verify(null, Buffer.from(head.signedDigest, "utf8"), key, Buffer.from(head.signedHead, "base64url"));
  console.log(sigOk
    ? `✓ platform signature over the chain head verifies (${head.verificationMethod})`
    : "✗ platform signature over the chain head does NOT verify");
  ok = ok && sigOk;
}

// ── 3. head must match the export's tip ───────────────────────────────────────
const tip = events[events.length - 1];
if (tip && head.seq >= tip.seq && (head.seq !== tip.seq || head.headHash === tip.hash)) {
  console.log(`✓ signed head (seq ${head.seq}) is consistent with the export tip (seq ${tip.seq})`);
} else if (tip) {
  console.error(`✗ signed head (seq ${head.seq}, ${head.headHash}) contradicts the export tip (seq ${tip.seq}, ${tip.hash})`);
  ok = false;
}

console.log(ok ? "\nCHAIN VERIFIED" : "\nCHAIN VERIFICATION FAILED");
process.exit(ok ? 0 : 1);
