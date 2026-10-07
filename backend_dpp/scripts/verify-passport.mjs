#!/usr/bin/env node
/**
 * ─── Independent passport verifier (thesis artifact) ──────────────────────────
 * Verifies a published TrustDPP passport export **from outside the platform**,
 * using nothing but an export file, an EVM JSON-RPC endpoint, and Node's
 * standard library. This is the tool that produces both columns of the thesis's
 * headline comparison:
 */

import { readFileSync } from "node:fs";
import crypto from "node:crypto";

/*
 * §1 keccak-256, implemented from FIPS-202's permutation
 */

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** ρ offsets, laid out for a flat state indexed `x + 5y`. */
const KECCAK_ROT = [
   0n,  1n, 62n, 28n, 27n,
  36n, 44n,  6n, 55n, 20n,
   3n, 10n, 43n, 25n, 39n,
  41n, 45n, 15n, 21n,  8n,
  18n,  2n, 61n, 56n, 14n,
];

const U64 = (1n << 64n) - 1n;
const rotl64 = (x, n) => (n === 0n ? x : ((x << n) | (x >> (64n - n))) & U64);

/** Keccak-f[1600], in place. θ, ρ+π, χ, ι — 24 rounds. */
function keccakF(A) {
  const C = new Array(5);
  const B = new Array(25);
  for (let round = 0; round < 24; round++) {
    // θ
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) {
      const D = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
      for (let y = 0; y < 25; y += 5) A[x + y] ^= D;
    }
    // ρ + π, in one pass: B[y, (2x+3y) mod 5] = rot(A[x, y], r[x, y])
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], KECCAK_ROT[x + 5 * y]);
      }
    }
    // χ — the only non-linear step. `~` on a BigInt is negative, hence the mask.
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        A[x + y] = B[x + y] ^ ((~B[((x + 1) % 5) + y] & U64) & B[((x + 2) % 5) + y]);
      }
    }
    // ι
    A[0] ^= KECCAK_RC[round];
  }
}

/** keccak256 over raw bytes → 32 bytes. Rate 1088 bits, pad `0x01 … 0x80`. */
function keccak256Bytes(input) {
  const RATE = 136;
  const state = new BigUint64Array(25);
  const absorb = (buf) => {
    const dv = new DataView(buf.buffer, buf.byteOffset, RATE);
    for (let i = 0; i < RATE / 8; i++) state[i] ^= dv.getBigUint64(i * 8, true);
    keccakF(state);
  };

  let off = 0;
  while (input.length - off >= RATE) {
    absorb(input.subarray(off, off + RATE));
    off += RATE;
  }
  // pad10*1 with Keccak's 0x01 domain byte (NOT SHA3's 0x06). The remainder is
  // strictly < RATE, so the `0x01` never lands outside the block; when it lands
  // on the last byte the two markers merge into 0x81, which is correct.
  const tail = new Uint8Array(RATE);
  tail.set(input.subarray(off));
  tail[input.length - off] = 0x01;
  tail[RATE - 1] |= 0x80;
  absorb(tail);

  const out = new Uint8Array(32);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) dv.setBigUint64(i * 8, state[i], true);
  return out;
}

const keccak256 = (bytes) => "0x" + bytesToHex(keccak256Bytes(bytes));
const keccak256Utf8 = (text) => keccak256(utf8(text));

/*
 * §2 secp256k1 public-key recovery
 */

const SECP256K1 = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

const mod = (a, m) => ((a % m) + m) % m;

/** Modular inverse by the extended Euclidean algorithm. Throws on 0 — that is a
 *  malformed signature, never a legitimate input. */
function modInv(a, m) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  if (old_r === 0n) throw new Error("modular inverse of zero");
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

/** A point is `null` (infinity) or `{ x, y }` in affine coordinates. */
function ecAdd(P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  const { p } = SECP256K1;
  if (P.x === Q.x) {
    if (mod(P.y + Q.y, p) === 0n) return null; // P = −Q
    const lam = mod(3n * P.x * P.x * modInv(2n * P.y, p), p); // a = 0 for secp256k1
    const x = mod(lam * lam - 2n * P.x, p);
    return { x, y: mod(lam * (P.x - x) - P.y, p) };
  }
  const lam = mod((Q.y - P.y) * modInv(mod(Q.x - P.x, p), p), p);
  const x = mod(lam * lam - P.x - Q.x, p);
  return { x, y: mod(lam * (P.x - x) - P.y, p) };
}

function ecMul(k, P) {
  let R = null;
  let A = P;
  let e = mod(k, SECP256K1.n);
  while (e > 0n) {
    if (e & 1n) R = ecAdd(R, A);
    A = ecAdd(A, A);
    e >>= 1n;
  }
  return R;
}

/**
 * Recover the Ethereum address behind a 65-byte `r ‖ s ‖ v` signature over
 * `digest32`.
 */
function recoverAddress(digest32, signature65) {
  if (signature65.length !== 65) {
    throw new Error(`ES256K-R signature must be 65 bytes (r‖s‖v), got ${signature65.length}`);
  }
  const v = signature65[64];
  if (v !== 0 && v !== 1) {
    throw new Error(
      `ES256K-R recovery id must be 0 or 1, got ${v}` +
        (v === 27 || v === 28 ? " — that is the eth_sign/EIP-191 convention, not JOSE's" : ""),
    );
  }
  const { p, n, b, Gx, Gy } = SECP256K1;
  const r = bytesToBigInt(signature65.subarray(0, 32));
  const s = bytesToBigInt(signature65.subarray(32, 64));
  if (r <= 0n || r >= n) throw new Error("signature r is out of range");
  if (s <= 0n || s >= n) throw new Error("signature s is out of range");
  if (s > n / 2n) throw new Error("signature has high s — malleable encoding refused (EIP-2)");

  // Decompress R from x = r. p ≡ 3 (mod 4), so the square root is a single
  // exponentiation; if it does not square back, r was never an x coordinate.
  const ySq = mod(r * r * r + b, p);
  let y = modPow(ySq, (p + 1n) / 4n, p);
  if (mod(y * y, p) !== ySq) throw new Error("signature r is not the x coordinate of a curve point");
  if ((y & 1n) !== BigInt(v)) y = mod(-y, p);
  const R = { x: r, y };

  // Q = r⁻¹ · (s·R − z·G)
  const z = mod(bytesToBigInt(digest32), n);
  const Q = ecMul(modInv(r, n), ecAdd(ecMul(s, R), ecMul(mod(-z, n), { x: Gx, y: Gy })));
  if (!Q) throw new Error("signature does not recover to any public key");

  // Address = low 20 bytes of keccak256(X ‖ Y) — the uncompressed key without
  // its 0x04 prefix. This derivation is exactly why `blockchainAccountId` is
  // checkable at all.
  const pub = new Uint8Array(64);
  pub.set(bigIntTo32(Q.x), 0);
  pub.set(bigIntTo32(Q.y), 32);
  const address = "0x" + bytesToHex(keccak256Bytes(pub)).slice(-40);
  if (address === ZERO_ADDRESS) throw new Error("signature recovers to the zero address");
  return address;
}

function modPow(base, exp, m) {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/* ════════════════════════════════════════════════════════════════════════════
 * §3  Encoding — hex, base64url, base58, canonical JSON, ABI
 * ════════════════════════════════════════════════════════════════════════════ */

const ZERO_ADDRESS = "0x" + "0".repeat(40);
const ZERO_BYTES32 = "0x" + "0".repeat(64);

const utf8 = (s) => new TextEncoder().encode(s);
const bytesToHex = (b) => Buffer.from(b).toString("hex");
const bytesToBigInt = (b) => (b.length === 0 ? 0n : BigInt("0x" + bytesToHex(b)));

function bigIntTo32(v) {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function hexToBytes(hex, label = "hex") {
  const body = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(body) || body.length % 2 !== 0) {
    throw new Error(`${label}: not an even-length hex string`);
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** `0x` + 64 lowercase hex. Every bytes32 comparison in this file is a string
 *  comparison over this one spelling, so nothing reaches a comparison without
 *  passing through here. */
function toBytes32(value, label = "bytes32") {
  const body = String(value).replace(/^0[xX]/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(body)) throw new Error(`${label}: expected 32 bytes of hex, got "${value}"`);
  return "0x" + body;
}

function toAddress(value, label = "address") {
  const body = String(value).replace(/^0[xX]/, "").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(body)) throw new Error(`${label}: expected a 20-byte address, got "${value}"`);
  return "0x" + body;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * base64url → bytes, STRICTLY.
 */
function decodeBase64Url(segment, label) {
  if (typeof segment !== "string" || !BASE64URL.test(segment)) throw new Error(`${label}: not base64url`);
  if (segment.length % 4 === 1) throw new Error(`${label}: truncated base64url`);
  const buf = Buffer.from(segment, "base64url");
  if (buf.toString("base64url") !== segment) throw new Error(`${label}: non-canonical base64url`);
  return new Uint8Array(buf);
}

/** base64url → UTF-8 → JSON object. `fatal` decoding so invalid UTF-8 is an
 *  error rather than a run of U+FFFD; anything that is not a JSON OBJECT is
 *  refused, because a JWS whose payload is a number is not a credential. */
function decodeJsonSegment(segment, label) {
  const bytes = decodeBase64Url(segment, label);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label}: not valid UTF-8`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label}: not valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${label}: not a JSON object`);
  return parsed;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** base58btc → bytes. Only used to *report* which Ed25519 key a Design B DID
 *  document offers — the signature itself is not verified (see the header). */
function base58Decode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`invalid base58 character "${c}"`);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c === "1") bytes.unshift(0);
    else break;
  }
  return Uint8Array.from(bytes);
}

/**
 * Deterministic JSON: object keys sorted recursively, arrays in order.
 */
function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    if (s === undefined) throw new TypeError(`stableStringify: unserializable ${typeof value}`);
    return s;
  }
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

const sha256Hex = (s) => crypto.createHash("sha256").update(s).digest("hex");

// ── ABI, by hand ─────────────────────────────────────────────────────────────
// Four static types, all one word wide. A general ABI coder would be a hundred
// lines of machinery for calls that are `bytes32` and `address` in, one word out.

const selector = (signature) => keccak256Utf8(signature).slice(0, 10);
const topicOf = (eventSignature) => keccak256Utf8(eventSignature);
const wordBytes32 = (v) => toBytes32(v).slice(2);
const wordAddress = (v) => "0".repeat(24) + toAddress(v).slice(2);
const wordAt = (data, i) => "0x" + data.replace(/^0x/, "").slice(i * 64, (i + 1) * 64);
const decodeAddress = (word) => "0x" + word.replace(/^0x/, "").slice(24).toLowerCase();
const decodeBool = (word) => BigInt(word) === 1n;
const decodeUint = (word) => BigInt(word);

/*
 * §4 Contract surface
 */

const SIG = {
  productController: "productController(bytes32)",
  authorized: "authorized(bytes32,address)",
  nonces: "nonces(address)",
  owners: "owners(address)",
  changed: "changed(address)",
};

const EVENT = {
  // event Anchored(bytes32 indexed productId, bytes32 merkleRoot, uint64 version, address indexed by)
  Anchored: "Anchored(bytes32,bytes32,uint64,address)",
  IssuerAuthorized: "IssuerAuthorized(bytes32,address,bool)",
  ProductClaimed: "ProductClaimed(bytes32,address,address)",
  DIDOwnerChanged: "DIDOwnerChanged(address,address,uint256)",
  DIDDelegateChanged: "DIDDelegateChanged(address,bytes32,address,uint256,uint256)",
  DIDAttributeChanged: "DIDAttributeChanged(address,bytes32,bytes,uint256,uint256)",
};

/**
 * Defaults from `contracts/deployments/amoy.json`. Overridable — see the header.
 */
const DEFAULTS = {
  chainId: 80002,
  chainName: "amoy",
  registry: "0x03dd7e09263a24e5e6aBACA533EeE9d992b85479",
  didRegistry: "0x8c7F06eDe1C36FDc7d36AAb77D2Ac5bfB0aABb65",
  fromBlock: 44629028, // the registry's deployment block — nothing can precede it
  logWindow: 2000,
  // A bound on how much a single anchor lookup may cost. Reached only when an
  // endpoint caps ranges hard AND there is no anchor to find; the result is then
  // an honest "inconclusive", never a fabricated "absent".
  maxLogRequests: 200,
};

/* ════════════════════════════════════════════════════════════════════════════
 * §5  JSON-RPC
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * A chain read that could not be performed and a chain read that answered "no"
 * are different facts and must never collapse into each other. Everything in
 * this section either returns a decoded answer or throws `ChainUnreachable`; the
 * report layer renders a throw as SKIP (unknown) and a decoded `false` as FAIL
 * (the chain said no).
 */
class ChainUnreachable extends Error {}

/**
 * Endpoints fail in two ways that look alike in a message string and must be
 * handled oppositely:
 */
const RANGE_ERROR = /block range|range should|up to a \d+ block|query returned more than|too many results|exceeds? .{0,20}block|logs matched/i;
const RATE_ERROR = /rate limit|compute unit|throughput|capacity|too many requests|429|slow down|exceeded.*(second|quota)/i;

class Rpc {
  constructor(url, { timeoutMs = 15000 } = {}) {
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.id = 0;
    this.calls = 0;
  }

  /** One call, with bounded backoff on rate limits only. A rate limit is the
   *  endpoint asking for patience; every other failure is answered immediately,
   *  because retrying an outage just delays an honest SKIP. */
  async call(method, params, { retries = 4 } = {}) {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.callOnce(method, params);
      } catch (err) {
        if (attempt >= retries || !RATE_ERROR.test(String(err.message || ""))) throw err;
        await new Promise((r) => setTimeout(r, 250 * 2 ** attempt));
      }
    }
  }

  async callOnce(method, params) {
    this.calls++;
    let body;
    let status = 0;
    try {
      const res = await fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      status = res.status;
      // The body is read even on a non-2xx, deliberately. Endpoints that cap
      // `eth_getLogs` ranges answer HTTP 400 with the real reason (and often the
      // range they WOULD accept) in a JSON-RPC error object; throwing on
      // `res.status` alone discards exactly the information the range-shrinking
      // in `scanLogs` needs, and turns a recoverable limit into a dead end.
      body = await res.json().catch(() => null);
      if (!body && !res.ok) throw new ChainUnreachable(`${method}: HTTP ${status}`);
    } catch (err) {
      // The URL is never echoed into an error: RPC URLs carry API keys, and this
      // report is meant to be pasted into a thesis appendix.
      if (err instanceof ChainUnreachable) throw err;
      throw new ChainUnreachable(`${method}: ${err.message}`);
    }
    if (body?.error) {
      const e = new ChainUnreachable(`${method}: ${body.error.message ?? JSON.stringify(body.error)}`);
      e.rpcError = body.error;
      throw e;
    }
    if (status >= 400) throw new ChainUnreachable(`${method}: HTTP ${status}`);
    return body.result;
  }

  async ethCall(to, data) {
    return this.call("eth_call", [{ to, data }, "latest"]);
  }

  async blockNumber() {
    return Number(BigInt(await this.call("eth_blockNumber", [])));
  }

  async chainId() {
    return Number(BigInt(await this.call("eth_chainId", [])));
  }

  /**
   * `eth_getLogs` over a range, NEWEST BLOCK FIRST, in windows that shrink when an
   * endpoint refuses them.
   */
  async scanLogs({ address, topics, fromBlock, toBlock, window, maxRequests = 200, stopWhen = null }) {
    const out = [];
    let win = Math.max(1, window);
    let hi = toBlock;
    let requests = 0;
    let capped = false;
    while (hi >= fromBlock) {
      if (requests >= maxRequests) {
        return { logs: out, complete: false, scannedFrom: hi + 1, scannedTo: toBlock, requests, window: win, capped };
      }
      const lo = Math.max(fromBlock, hi - win + 1);
      let logs;
      try {
        requests++;
        logs = await this.call("eth_getLogs", [
          { address, topics, fromBlock: "0x" + lo.toString(16), toBlock: "0x" + hi.toString(16) },
        ]);
      } catch (err) {
        // Distinguish "this range is too wide for you" from "I cannot answer".
        // Only the former is retried narrower; anything else is a real outage
        // and must propagate, because guessing here would fabricate coverage.
        // (Rate limits never reach here — `call` has already waited them out.)
        if (RANGE_ERROR.test(String(err.message || "")) && win > 1) {
          win = Math.max(1, Math.floor(win / 4));
          capped = true;
          continue;
        }
        throw err;
      }
      out.push(...logs);
      if (stopWhen && stopWhen(out)) {
        return { logs: out, complete: true, scannedFrom: lo, scannedTo: toBlock, requests, window: win, capped };
      }
      hi = lo - 1;
    }
    return { logs: out, complete: true, scannedFrom: fromBlock, scannedTo: toBlock, requests, window: win, capped };
  }
}

/* ════════════════════════════════════════════════════════════════════════════
 * §6  DID resolution
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * `did:ethr:<network>:<address>` — address form only.
 */
function parseDidEthr(did, chain) {
  if (typeof did !== "string") return null;
  const m = /^did:ethr:(?:([^:]+):)?(0x[0-9a-fA-F]{40})$/.exec(did.trim());
  if (!m) return null;
  const network = m[1];
  const address = toAddress(m[2]);
  const matches =
    network === undefined
      ? chain.chainId === 1
      : network.toLowerCase() === chain.chainName.toLowerCase() ||
        network === String(chain.chainId) ||
        /^0x[0-9a-f]+$/i.test(network) && BigInt(network) === BigInt(chain.chainId);
  return { did: did.trim(), address, network: network ?? "mainnet(implicit)", onThisChain: matches };
}

/**
 * `did:web:example.com:foo:bar` → `https://example.com/foo/bar/did.json`.
 * A bare `did:web:example.com` → `https://example.com/.well-known/did.json`.
 * Percent-decoding per the method spec, which is how a port survives (`%3A`).
 */
function didWebUrl(did) {
  const rest = did.slice("did:web:".length);
  if (!rest) return null;
  const parts = rest.split(":").map(decodeURIComponent);
  const host = parts.shift();
  if (!host) return null;
  return parts.length === 0
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${parts.join("/")}/did.json`;
}

/**
 * Build the DID document ERC-1056 implies for an identity, from the two reads
 * that determine it.
 */
async function resolveDidEthrDocument(rpc, chain, identity) {
  const owner = decodeAddress(await rpc.ethCall(chain.didRegistry, selector(SIG.owners) + wordAddress(identity)));
  const changed = decodeUint(await rpc.ethCall(chain.didRegistry, selector(SIG.changed) + wordAddress(identity)));

  let controller;
  let provenance;
  if (changed === 0n) {
    controller = identity;
    provenance = "address-derived default document (no ERC-1056 event has ever touched this identity)";
  } else if (owner !== ZERO_ADDRESS) {
    controller = owner;
    provenance = `owners[] = ${owner}, last changed at block ${changed}`;
  } else {
    controller = await walkOwnerChangeLog(rpc, chain, identity, Number(changed));
    provenance = `recovered from the DIDOwnerChanged log (owners[] is zero with history at block ${changed})`;
  }

  const deactivated = controller === ZERO_ADDRESS;
  return {
    id: `did:ethr:0x${chain.chainId.toString(16)}:${identity}`,
    controller,
    deactivated,
    provenance,
    // The document ERC-1056 implies. Rendered rather than fetched, because there
    // is nothing to fetch: the registry publishes state, and the document is a
    // pure function of it — which is exactly why this resolves with the platform
    // switched off.
    verificationMethod: deactivated
      ? []
      : [
          {
            id: `did:ethr:0x${chain.chainId.toString(16)}:${identity}#controller`,
            type: "EcdsaSecp256k1RecoveryMethod2020",
            blockchainAccountId: `eip155:${chain.chainId}:${controller}`,
          },
        ],
  };
}

/**
 * Walk `previousChange` backwards until a `DIDOwnerChanged` appears.
 */
async function walkOwnerChangeLog(rpc, chain, identity, changedAt, maxHops = 64) {
  const identityTopic = "0x" + wordAddress(identity);
  let block = changedAt;
  for (let hop = 0; hop < maxHops; hop++) {
    const logs = await rpc.call("eth_getLogs", [
      {
        address: chain.didRegistry,
        // topic0 unconstrained: all three ERC-1056 events carry `identity` as
        // topic1, and we need whichever of them is newest.
        topics: [null, identityTopic],
        fromBlock: "0x" + block.toString(16),
        toBlock: "0x" + block.toString(16),
      },
    ]);
    let ownerAtBlock = null;
    let previous = 0;
    const ownerTopic = topicOf(EVENT.DIDOwnerChanged);
    for (const log of logs) {
      // `previousChange` is the LAST word of every ERC-1056 event's data. Only
      // the first event in a block carries the true predecessor: the contract
      // emits `changed[identity]` and then overwrites it with `block.number`, so
      // later events in the same block point at themselves. Take the smallest
      // value strictly below this block.
      const words = log.data.replace(/^0x/, "");
      const prev = Number(BigInt("0x" + words.slice(-64)));
      if (prev > 0 && prev < block && (previous === 0 || prev < previous)) previous = prev;
      // DIDOwnerChanged(address indexed identity, address owner, uint256 previousChange)
      if (log.topics[0] === ownerTopic) ownerAtBlock = decodeAddress(wordAt(log.data, 0));
    }
    if (ownerAtBlock !== null) return ownerAtBlock;
    if (previous === 0) return identity; // start of history — the owner never changed
    block = previous;
  }
  throw new ChainUnreachable(
    `did:ethr change log for ${identity} is longer than ${maxHops} hops — refusing to guess the current owner`,
  );
}

/** Every address a document permits to ASSERT, from the recovery-method entries
 *  bound to this chain. A deactivated DID yields none, which is what
 *  deactivation has to mean. */
function assertionAddresses(doc, chainId) {
  const out = [];
  for (const vm of doc?.verificationMethod ?? []) {
    if (vm?.type !== "EcdsaSecp256k1RecoveryMethod2020") continue;
    const parts = String(vm.blockchainAccountId ?? "").split(":");
    if (parts.length !== 3 || parts[0].toLowerCase() !== "eip155") continue;
    if (Number(parts[1]) !== chainId) continue; // same address, other chain = other owner
    try {
      const a = toAddress(parts[2]);
      if (a !== ZERO_ADDRESS && !out.includes(a)) out.push(a);
    } catch {
      /* not an address — ignore the entry rather than the document */
    }
  }
  return out;
}

/*
 * §7 Merkle — the anchoring convention
 */

const hashLeaf = (digest) => keccak256(concatBytes(Uint8Array.of(0x00), hexToBytes(toBytes32(digest))));

function hashNode(a, b) {
  const [lo, hi] = toBytes32(a) <= toBytes32(b) ? [toBytes32(a), toBytes32(b)] : [toBytes32(b), toBytes32(a)];
  return keccak256(concatBytes(Uint8Array.of(0x01), hexToBytes(lo), hexToBytes(hi)));
}

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function merkleRoot(digests) {
  if (digests.length === 0) throw new Error("merkle: cannot build a tree over zero digests");
  let level = digests.map(hashLeaf);
  while (level.length > 1) {
    const next = [];
    let i = 0;
    for (; i + 1 < level.length; i += 2) next.push(hashNode(level[i], level[i + 1]));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

/** The digest tag that keeps the snapshot leaf's pre-image disjoint from a
 *  credential's. Every leaf carries the same 0x00 tag, so the tree cannot tell
 *  them apart; the pre-images can, and do. */
const VERSION_SNAPSHOT_DIGEST_KIND = "trustdpp/version-snapshot/v1";

/**
 * The digest of ONE stored credential, over its EXACT stored bytes.
 */
function credentialDigest(stored) {
  if (typeof stored === "string") return keccak256Utf8(stored);
  if (!stored || typeof stored !== "object") throw new TypeError(`credentialDigest: got ${typeof stored}`);
  const env = parseEnvelope(stored);
  return env ? keccak256Utf8(env.token) : keccak256Utf8(stableStringify(stored));
}

function versionMerkleTree({ snapshot, credentials, version }) {
  const credentialDigests = credentials.map(credentialDigest);
  const snapshotDigest = keccak256Utf8(
    stableStringify({
      kind: VERSION_SNAPSHOT_DIGEST_KIND,
      version,
      credentialDigests: credentialDigests.map((d) => toBytes32(d)),
      snapshot,
    }),
  );
  const digests = [...credentialDigests, snapshotDigest];
  return { root: merkleRoot(digests), credentialDigests, snapshotDigest, digests };
}

/* ════════════════════════════════════════════════════════════════════════════
 * §8  Credential parsing and ES256K-R verification
 * ════════════════════════════════════════════════════════════════════════════ */

const ENVELOPED_TYPE = "EnvelopedVerifiableCredential";
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ES256K_R = "ES256K-R";
const ACCEPTED_TYP = new Set(["vc+jwt", "application/vc+jwt", "jwt"]);

/**
 * Pull the compact JWS out of a VCDM 2.0 enveloped credential, or `null`.
 */
function parseEnvelope(value) {
  if (!value || typeof value !== "object") return null;
  const type = value.type;
  const isEnveloped = type === ENVELOPED_TYPE || (Array.isArray(type) && type.length === 1 && type[0] === ENVELOPED_TYPE);
  if (!isEnveloped) return null;
  const id = value.id;
  if (typeof id !== "string" || !id.startsWith("data:")) return null;
  const comma = id.indexOf(",");
  if (comma < 0) return null;
  const [mediaType, ...params] = id.slice(5, comma).split(";");
  if (params.some((p) => p.trim().toLowerCase() === "base64")) return null;
  const token = id.slice(comma + 1);
  if (mediaType.trim().toLowerCase() !== "application/vc+jwt") return null;
  if (!COMPACT_JWS.test(token)) return null;
  return { mediaType: "application/vc+jwt", token };
}

/**
 * Verify one compact JWS as an ES256K-R credential.
 */
function verifyEs256kR(token) {
  const segments = token.split(".");
  if (segments.length !== 3) return { ok: false, error: `compact JWS must have 3 segments, got ${segments.length}` };
  const [encHeader, encPayload, encSignature] = segments;

  let header;
  let claims;
  try {
    header = decodeJsonSegment(encHeader, "protected header");
    claims = decodeJsonSegment(encPayload, "payload");
  } catch (err) {
    return { ok: false, error: err.message };
  }

  // An allow-list of exactly one `alg`. RFC 7515's unsecured JWS (`alg: "none"`)
  // is syntactically a JWS with an empty signature, and a verifier that
  // dispatches on `alg` without an allow-list accepts it.
  if (header.alg !== ES256K_R) {
    return {
      ok: false,
      header,
      claims,
      error:
        String(header.alg).toLowerCase() === "none"
          ? "refused `alg: none` — an unsecured JWS is not a credential"
          : `unsupported alg "${truncate(String(header.alg))}" — this verifier accepts ${ES256K_R} only`,
    };
  }
  // RFC 7515 §4.1.11: `crit` names extensions the verifier MUST understand. We
  // implement none, so any `crit` at all is an instruction we cannot honour —
  // and ignoring it is exactly what the header forbids.
  if ("crit" in header) {
    return { ok: false, header, claims, error: "protected header carries `crit` — no JWS extensions are implemented" };
  }
  // Present-but-wrong `typ` is refused; absent is tolerated (VC-JOSE-COSE only
  // RECOMMENDS it). The refusal blocks cross-protocol replay: the actor's key
  // also signs login and ceremony artefacts, and a token minted `typ:"dpop+jwt"`
  // must not become servable as a credential just because its signature is real.
  if (header.typ !== undefined && !ACCEPTED_TYP.has(String(header.typ).trim().toLowerCase())) {
    return { ok: false, header, claims, error: `unexpected \`typ\` "${truncate(String(header.typ))}" — expected vc+jwt` };
  }

  let signerAddress;
  try {
    const signature = decodeBase64Url(encSignature, "signature");
    const digest = crypto.createHash("sha256").update(`${encHeader}.${encPayload}`, "ascii").digest();
    signerAddress = recoverAddress(new Uint8Array(digest), signature);
  } catch (err) {
    return { ok: false, header, claims, error: err.message };
  }

  // Is the signed payload a Verifiable Credential AT ALL? Not pedantry: the
  // actor's key is a general-purpose secp256k1 key that also signs wallet-login
  // challenges. Without this, any ES256K-R JWS that key ever produced would
  // verify as a credential issued by that actor — the signature is genuine and
  // the issuer binding holds, and only `type` tells a credential from a login
  // token.
  const types = typeof claims.type === "string" ? [claims.type] : Array.isArray(claims.type) ? claims.type : [];
  if (!types.includes("VerifiableCredential")) {
    return { ok: false, header, claims, signerAddress, error: '`type` does not include "VerifiableCredential" — signed, but not a credential' };
  }
  if (!("@context" in claims)) return { ok: false, header, claims, signerAddress, error: "payload has no `@context`" };

  return { ok: true, error: null, header, claims, signerAddress };
}

/** `issuer` is a DID string or an object with an `id` (VCDM 2.0 allows both). */
function readIssuer(claims) {
  const issuer = claims?.issuer;
  if (typeof issuer === "string") return issuer;
  if (issuer && typeof issuer === "object" && typeof issuer.id === "string") return issuer.id;
  return null;
}

function readRole(claims) {
  const subject = Array.isArray(claims?.credentialSubject) ? claims.credentialSubject[0] : claims?.credentialSubject;
  return subject && typeof subject === "object" && typeof subject.role === "string" ? subject.role : null;
}

const truncate = (s, max = 100) => (s.length <= max ? s : s.slice(0, max) + "…");

/*
 * §9 Bundle parsing
 */

function parseBundle(raw, overrides) {
  const doc = raw?.passportVersion ?? raw?.bundle ?? raw?.payload ?? raw;
  if (!doc || typeof doc !== "object") throw new Error("bundle is not a JSON object");

  const credentials = doc.credentials;
  if (!Array.isArray(credentials)) throw new Error("bundle has no `credentials` array");

  const version = overrides.version ?? (Number.isInteger(doc.version) ? doc.version : null);
  const snapshot = doc.snapshot && typeof doc.snapshot === "object" ? doc.snapshot : null;
  const versionHash = typeof doc.hash === "string" ? doc.hash : typeof doc.versionHash === "string" ? doc.versionHash : null;

  const productDid =
    overrides.productDid ??
    (typeof doc.productDid === "string" ? doc.productDid : null) ??
    (typeof snapshot?.product?.did === "string" ? snapshot.product.did : null) ??
    (typeof doc.did === "string" ? doc.did : null);

  // An optional pointer to the anchoring transaction. A HINT — see the fast path
  // in `verifyAnchor` for why accepting it costs nothing in trust.
  const anchorTx =
    overrides.anchorTx ??
    (typeof doc.anchorTxHash === "string" ? doc.anchorTxHash : null) ??
    (typeof doc.anchor?.txHash === "string" ? doc.anchor.txHash : null);

  return {
    shape: doc.snapshot ? "passport-version row" : "public passport projection",
    passportId: doc.passportId ?? doc.id ?? null,
    version,
    snapshot,
    credentials,
    versionHash,
    productDid,
    anchorTx: anchorTx ? String(anchorTx).toLowerCase() : null,
  };
}

/* ════════════════════════════════════════════════════════════════════════════
 * §10  The report
 *
 * Three statuses, and no way for one to be mistaken for another. `SKIP` is not a
 * soft pass: it means this verifier did not establish the fact, and the overall
 * verdict downgrades to INCOMPLETE (exit 3) accordingly.
 * ════════════════════════════════════════════════════════════════════════════ */

const PASS = "PASS";
const FAIL = "FAIL";
const SKIP = "SKIP";

class Report {
  constructor() {
    this.checks = [];
  }
  add(scope, name, status, detail) {
    this.checks.push({ scope, name, status, detail: detail ?? null });
    return status;
  }
  pass(scope, name, detail) {
    return this.add(scope, name, PASS, detail);
  }
  fail(scope, name, detail) {
    return this.add(scope, name, FAIL, detail);
  }
  skip(scope, name, detail) {
    return this.add(scope, name, SKIP, detail);
  }
  counts() {
    const c = { pass: 0, fail: 0, skip: 0 };
    for (const k of this.checks) c[k.status.toLowerCase()]++;
    return c;
  }
  verdict() {
    const c = this.counts();
    if (c.fail > 0) return { verdict: "FAILED", exitCode: 1 };
    if (c.skip > 0) return { verdict: "INCOMPLETE", exitCode: 3 };
    return { verdict: "VERIFIED", exitCode: 0 };
  }
}

/*
 * §11 Self-test — run before anything else, every time
 */

const VECTORS = {
  // FIPS-202 / Ethereum's keccak256.
  keccakEmpty: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  keccakAbc: "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
  // sha256("trustdpp/verify-passport self-test vector v1"), signed by private key 1.
  es256kDigest: "0x767212d10a8cd235516a07cdc8faf3c8da7419044149459ec5effee0cc2802b0",
  es256kSig:
    "0x7d0021981ddb1eb89f5343a04f1aee7e50afa6417196bb7e586c3fc4d9ae1c4c" +
    "27092f0866d722ecac2606d8c1313670f3fe687bc393e06dcf03915b2642dcb1" +
    "00",
  es256kAddress: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
  es256kMessage: "trustdpp/verify-passport self-test vector v1",
  // Merkle, from the convention: a one-element tree's root IS its leaf.
  merkleOne: "0x" + "11".repeat(32),
};

function selfTest() {
  const failures = [];
  const check = (name, actual, expected) => {
    if (actual !== expected) failures.push(`${name}: got ${actual}, expected ${expected}`);
  };

  check("keccak256(\"\")", keccak256Utf8(""), VECTORS.keccakEmpty);
  check("keccak256(\"abc\")", keccak256Utf8("abc"), VECTORS.keccakAbc);

  // The digest must come out of Node's SHA-256 over the same string the vector
  // names — this also pins that the signing input is hashed with SHA-256 and
  // nothing else.
  const digest = crypto.createHash("sha256").update(VECTORS.es256kMessage, "ascii").digest();
  check("sha256(self-test message)", "0x" + digest.toString("hex"), VECTORS.es256kDigest);
  try {
    const recovered = recoverAddress(new Uint8Array(digest), hexToBytes(VECTORS.es256kSig));
    check("ES256K-R recovery", recovered, VECTORS.es256kAddress);
  } catch (err) {
    failures.push(`ES256K-R recovery threw: ${err.message}`);
  }

  // High-s must be REFUSED, not normalised. Flip s to n − s and re-test.
  try {
    const sig = hexToBytes(VECTORS.es256kSig);
    const s = bytesToBigInt(sig.subarray(32, 64));
    sig.set(bigIntTo32(SECP256K1.n - s), 32);
    recoverAddress(new Uint8Array(digest), sig);
    failures.push("ES256K-R accepted a high-s signature (EIP-2 malleability guard is not working)");
  } catch (err) {
    if (!/high s/.test(err.message)) failures.push(`high-s rejection gave the wrong reason: ${err.message}`);
  }

  check("merkle one-leaf root", merkleRoot([VECTORS.merkleOne]), hashLeaf(VECTORS.merkleOne));
  // node(a,b) is order-independent — the property that lets proofs omit direction bits.
  const a = "0x" + "aa".repeat(32);
  const b = "0x" + "bb".repeat(32);
  check("merkle node ordering", hashNode(a, b), hashNode(b, a));

  return failures;
}

/* ════════════════════════════════════════════════════════════════════════════
 * §12  Verification passes
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * Everything that is a property of the exported BYTES. No network, ever, so this
 * runs identically with the platform down, the chain down, or on a laptop in a
 * Faraday cage — which is the point.
 */
function verifyOffline(bundle, report) {
  // ── the platform's own digest ──
  // Recomputing it catches a truncated or corrupted export. It proves nothing
  // AGAINST the platform: the platform chose the bytes and computed the digest,
  // so it can move both. Stated plainly here because the difference between this
  // and the anchor is the substance of the A/B comparison.
  if (bundle.versionHash === null) {
    report.skip("bundle", "version-hash", "the bundle carries no `hash`/`versionHash` to check against");
  } else if (bundle.snapshot === null || bundle.version === null) {
    report.skip(
      "bundle",
      "version-hash",
      "needs the frozen `snapshot` and `version`; this bundle is a flattened public projection",
    );
  } else {
    const recomputed = sha256Hex(
      stableStringify({ snapshot: bundle.snapshot, credentials: bundle.credentials, version: bundle.version }),
    );
    if (recomputed === bundle.versionHash) {
      report.pass("bundle", "version-hash", `sha256 ${recomputed.slice(0, 16)}… recomputes (platform-defined digest)`);
    } else {
      report.fail("bundle", "version-hash", `stored ${bundle.versionHash.slice(0, 16)}… but the bytes hash to ${recomputed.slice(0, 16)}…`);
    }
  }

  // ── the Merkle root ──
  let tree = null;
  if (bundle.snapshot === null || bundle.version === null) {
    report.skip(
      "bundle",
      "merkle-root",
      "the root is built over the frozen snapshot, which this bundle does not carry — export the PassportVersion row",
    );
  } else {
    try {
      tree = versionMerkleTree({ snapshot: bundle.snapshot, credentials: bundle.credentials, version: bundle.version });
      report.pass("bundle", "merkle-root", `${tree.root} over ${bundle.credentials.length} credential digest(s) + the snapshot digest`);
    } catch (err) {
      report.fail("bundle", "merkle-root", err.message);
    }
  }
  return tree;
}

/** Per-credential offline work: what representation it is, and (for Design A)
 *  whether the signature over its bytes recovers to the issuer it names. */
function inspectCredential(stored, index, chain, report) {
  const scope = `credential[${index}]`;
  // `body` is the credential itself, whichever representation carried it: the
  // JWS claims for Design A, the object as stored for Design B. Checks that read
  // the CONTENT (subject binding, validity window) work off this and so do not
  // have to care which design produced it.
  const out = { index, design: null, issuerDid: null, signerAddress: null, role: null, id: null, claims: null, body: null };

  const env = parseEnvelope(stored);
  if (env) {
    out.design = "design-a";
    report.pass(scope, "parse", `EnvelopedVerifiableCredential, ${env.mediaType}, ${env.token.length} bytes of compact JWS`);

    const v = verifyEs256kR(env.token);
    out.claims = v.claims ?? null;
    out.body = v.claims ?? null;
    out.issuerDid = readIssuer(v.claims ?? {});
    out.role = readRole(v.claims ?? {});
    out.id = typeof v.claims?.id === "string" ? v.claims.id : null;
    out.signerAddress = v.signerAddress ?? null;

    if (!v.ok) {
      report.fail(scope, "signature", v.error);
      return out;
    }

    // The JOIN. Everything above proved SOMEBODY signed these exact bytes; this
    // proves it was the principal the bytes name as issuer. A `did:ethr` for
    // another chain is not this run's to verify — same address, different owner.
    const parsed = parseDidEthr(out.issuerDid, chain);
    if (!parsed) {
      report.fail(scope, "signature", `signature recovers to ${v.signerAddress}, but the issuer "${truncate(String(out.issuerDid))}" is not a did:ethr address`);
    } else if (!parsed.onThisChain) {
      report.fail(scope, "signature", `issuer DID is on network "${parsed.network}", not chain ${chain.chainId} (${chain.chainName})`);
    } else if (parsed.address !== v.signerAddress) {
      report.fail(scope, "signature", `signature recovers to ${v.signerAddress}, but the issuer DID names ${parsed.address}`);
    } else {
      report.pass(scope, "signature", `ES256K-R recovers to ${v.signerAddress}, which is what the issuer DID names`);
    }
    return out;
  }

  // ── Design B / embedded proof ──
  if (!stored || typeof stored !== "object") {
    report.fail(scope, "parse", `not a credential object (${typeof stored})`);
    out.parseFailed = true;
    return out;
  }
  out.design = "design-b";
  out.body = stored;
  out.issuerDid = readIssuer(stored);
  out.role = readRole(stored);
  out.id = typeof stored.id === "string" ? stored.id : null;

  const proofs = Array.isArray(stored.proof) ? stored.proof : stored.proof ? [stored.proof] : [];
  const proof = proofs[0] ?? null;
  if (!proof) {
    // Honestly unsigned is a real state in this platform (an issuer with no key)
    // and must be reported as such, never as a failed signature.
    report.fail(scope, "parse", "embedded-proof credential with NO `proof` — honestly unsigned, so there is nothing to verify");
    out.parseFailed = true;
    return out;
  }
  out.cryptosuite = proof.cryptosuite ?? proof.type ?? null;
  out.verificationMethod = typeof proof.verificationMethod === "string" ? proof.verificationMethod : null;
  report.pass(scope, "parse", `embedded proof, ${proof.type ?? "?"} / ${proof.cryptosuite ?? "?"}, purpose ${proof.proofPurpose ?? "?"}`);
  return out;
}

/**
 * The chain- and network-dependent half, per credential.
 */
async function verifyIssuer(cred, ctx, report) {
  const scope = `credential[${cred.index}]`;
  const { chain, rpc, offline, chainOffline } = ctx;

  if (!cred.issuerDid) {
    report.fail(scope, "issuer-did", "the credential names no issuer");
    report.skip(scope, "issuer-resolution", "no issuer DID to resolve");
    return;
  }

  // ── did:ethr — resolvable from the chain, with the platform switched off ──
  if (cred.issuerDid.startsWith("did:ethr:")) {
    const parsed = parseDidEthr(cred.issuerDid, chain);
    if (!parsed) {
      report.fail(scope, "issuer-did", `"${truncate(cred.issuerDid)}" is not an address-form did:ethr`);
      report.skip(scope, "issuer-resolution", "unparseable issuer DID");
      return;
    }
    if (!parsed.onThisChain) {
      report.fail(scope, "issuer-did", `did:ethr on network "${parsed.network}", but this run is bound to chain ${chain.chainId} (${chain.chainName})`);
      report.skip(scope, "issuer-resolution", "issuer is on another chain");
      return;
    }
    report.pass(scope, "issuer-did", `did:ethr address form, chain ${chain.chainId} → ${parsed.address}`);
    cred.issuerAddress = parsed.address;

    if (chainOffline) {
      const why = offline ? "--offline: the ERC-1056 registry was not read" : "the chain is not usable from this run (no endpoint, unreachable, or wrong chain id)";
      report.skip(scope, "issuer-resolution", why);
      report.skip(scope, "issuer-key-current", why);
      return;
    }

    let doc;
    try {
      doc = await resolveDidEthrDocument(rpc, chain, parsed.address);
    } catch (err) {
      // Unreachable ≠ "no such issuer". A SKIP, loudly, so an outage can never
      // be mistaken for a verdict.
      report.skip(scope, "issuer-resolution", `ERC-1056 registry could not be read: ${err.message}`);
      report.skip(scope, "issuer-key-current", "the DID document could not be resolved");
      return;
    }
    if (doc.deactivated) {
      report.fail(scope, "issuer-resolution", "the DID is DEACTIVATED on chain (owner set to 0x0) — it authorizes nothing");
    } else {
      report.pass(scope, "issuer-resolution", `resolved from ERC-1056 @ ${chain.didRegistry} — ${doc.provenance}`);
    }

    // Rotation awareness. `didMatchesAddress` is a fact about the DID STRING and
    // never changes; this is a fact about CURRENT chain state. They come apart
    // exactly after `changeOwner`, and a verifier that checks only the string
    // keeps honouring a rotated-away — possibly stolen — key forever.
    if (cred.signerAddress) {
      const allowed = assertionAddresses(doc, chain.chainId);
      if (allowed.includes(cred.signerAddress)) {
        report.pass(scope, "issuer-key-current", `the resolved document still authorizes ${cred.signerAddress} to assert`);
      } else {
        report.fail(
          scope,
          "issuer-key-current",
          // State the FACT, not a guessed cause. The old text said "the key was
          // rotated away or revoked", which names the ordinary reason — but this
          // check also fires on a forgery, where the recovered address was never
          // authorized in the first place, and a reader of that transcript was
          // told to look for a rotation that never happened. Which case it is
          // depends on whether `signature` passed, so point there instead.
          `the resolved document does not authorize ${cred.signerAddress} (it authorizes ${allowed.join(", ") || "nothing"}) — ` +
            `either that key was rotated away or revoked, or it was never the issuer's at all; ` +
            `the \`signature\` row above distinguishes the two`,
        );
      }
    } else {
      report.skip(scope, "issuer-key-current", "no signer address was recovered, so there is nothing to check against the document");
    }
    return;
  }

  // ── did:web — served by the platform, which is exactly the point ──
  if (cred.issuerDid.startsWith("did:web:")) {
    const url = didWebUrl(cred.issuerDid);
    if (!url) {
      report.fail(scope, "issuer-did", `"${truncate(cred.issuerDid)}" is not a resolvable did:web`);
      report.skip(scope, "issuer-resolution", "unparseable issuer DID");
      return;
    }
    report.pass(scope, "issuer-did", `did:web → ${url}`);

    if (offline) {
      report.skip(scope, "issuer-resolution", `--offline: ${url} was not fetched`);
      report.skip(scope, "issuer-key-current", "the DID document was not fetched");
      return;
    }

    let doc;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { accept: "application/did+json, application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      doc = await res.json();
    } catch (err) {
      // THE FINDING, not a crash. Under Design B the issuer's key is published
      // by the very platform whose claims are being audited, so when that
      // platform is unavailable — outage, insolvency, or a deliberate refusal —
      // every credential it ever issued becomes unverifiable. Nothing about the
      // credential changed; the key simply cannot be obtained.
      report.fail(
        scope,
        "issuer-resolution",
        `did:web resolution FAILED (${err.message}) — the DID document at ${url} is served by the platform under audit, ` +
          `so with it unavailable the issuer's public key cannot be obtained and NO signature over this credential can be checked`,
      );
      report.skip(scope, "issuer-key-current", "the DID document could not be fetched");
      return;
    }

    const methods = Array.isArray(doc?.verificationMethod) ? doc.verificationMethod : [];
    const named = cred.verificationMethod ? methods.find((m) => m?.id === cred.verificationMethod) : null;
    if (cred.verificationMethod && !named) {
      report.fail(scope, "issuer-resolution", `the document at ${url} contains no verification method "${truncate(cred.verificationMethod)}"`);
      return;
    }
    let keyNote = "";
    if (named?.publicKeyMultibase) {
      try {
        const decoded = base58Decode(String(named.publicKeyMultibase).slice(1));
        // multicodec ed25519-pub is 0xed 0x01
        keyNote = decoded[0] === 0xed && decoded[1] === 0x01 ? ", ed25519-pub key present" : ", non-Ed25519 multikey present";
      } catch {
        keyNote = ", publicKeyMultibase is not decodable base58btc";
      }
    }
    report.pass(scope, "issuer-resolution", `did:web document fetched from ${url}${keyNote}`);
    report.skip(
      scope,
      "issuer-key-current",
      "did:web publishes no revocation or rotation history — the document only says what the platform says TODAY",
    );
    return;
  }

  report.fail(scope, "issuer-did", `unsupported DID method in "${truncate(cred.issuerDid)}" — this verifier resolves did:ethr and did:web`);
  report.skip(scope, "issuer-resolution", "unsupported DID method");
}

/**
 * The signature check for a Design B credential.
 */
function reportDesignBSignature(cred, report) {
  const scope = `credential[${cred.index}]`;
  report.skip(
    scope,
    "signature",
    `${cred.cryptosuite ?? "embedded proof"} NOT verified — it signs the URDNA2015 canonicalization of the JSON-LD, ` +
      `which needs a JSON-LD processor plus the @context documents (themselves served by the platform). ` +
      `This verifier does not implement it and will not guess.`,
  );
}

/**
 * Does this credential actually say it is about THIS product?
 */
function verifySubjectBinding(cred, ctx, report) {
  const scope = `credential[${cred.index}]`;
  // A credential that did not parse has no content to judge. Report that as a
  // SKIP rather than staying silent (an absent row reads as "fine") and rather
  // than failing — "names no subject" is true of a malformed blob but points the
  // reader at the wrong finding; `parse` already carries the real one.
  if (cred.parseFailed || !cred.body) {
    report.skip(scope, "subject-binding", "the credential did not parse, so there is no subject to compare");
    return;
  }

  if (!ctx.productDid) {
    report.skip(scope, "subject-binding", "no product DID in the bundle, so there is nothing to bind this credential to");
    return;
  }
  const subject = cred.body.credentialSubject;
  const subjectId = typeof subject?.id === "string" ? subject.id : null;
  if (!subjectId) {
    report.fail(
      scope,
      "subject-binding",
      "the credential names NO subject, so nothing inside the signed bytes ties it to this product — " +
        "it would verify identically inside any other passport",
    );
    return;
  }
  if (subjectId !== ctx.productDid) {
    report.fail(
      scope,
      "subject-binding",
      `the credential is about "${truncate(subjectId)}", but this bundle is passport "${truncate(ctx.productDid)}" — ` +
        `a genuine credential for a DIFFERENT product`,
    );
    return;
  }
  report.pass(scope, "subject-binding", `credentialSubject.id == the bundle's productDid (${truncate(subjectId)})`);
}

/**
 * Was the credential valid at the instant we are judging it?
 */
function verifyValidity(cred, ctx, report) {
  const scope = `credential[${cred.index}]`;
  if (cred.parseFailed || !cred.body) {
    report.skip(scope, "validity", "the credential did not parse, so there is no validity window to read");
    return;
  }

  const parseInstant = (v, field) => {
    if (v === undefined || v === null) return { absent: true };
    if (typeof v !== "string") return { error: `${field} is ${typeof v}, not an XML-schema date-time string` };
    const ms = Date.parse(v);
    return Number.isNaN(ms) ? { error: `${field} "${truncate(v)}" is not a parsable date-time` } : { ms };
  };

  const from = parseInstant(cred.body.validFrom, "validFrom");
  const until = parseInstant(cred.body.validUntil, "validUntil");
  const bad = from.error ?? until.error;
  if (bad) {
    report.fail(scope, "validity", bad);
    return;
  }
  if (from.absent && until.absent) {
    report.skip(scope, "validity", "the credential asserts no validity window (both fields are optional in VCDM 2.0), so there is nothing to check");
    return;
  }

  const at = ctx.asOf;
  const when = `${new Date(at).toISOString()}${ctx.asOfExplicit ? " (--as-of)" : ""}`;
  if (!from.absent && at < from.ms) {
    report.fail(scope, "validity", `not yet valid: validFrom is ${new Date(from.ms).toISOString()}, judged at ${when}`);
    return;
  }
  if (!until.absent && at > until.ms) {
    report.fail(scope, "validity", `EXPIRED: validUntil was ${new Date(until.ms).toISOString()}, judged at ${when}`);
    return;
  }
  const window = `${from.absent ? "(no start)" : new Date(from.ms).toISOString()} → ${until.absent ? "(no end)" : new Date(until.ms).toISOString()}`;
  report.pass(scope, "validity", `in force at ${when}; window ${window}`);
}

/** On-chain authorization for one issuer over one product. */
async function verifyAuthorization(cred, ctx, report) {
  const scope = `credential[${cred.index}]`;
  const { chain, rpc, offline, chainOffline, productId } = ctx;

  if (cred.design !== "design-a") {
    report.skip(
      scope,
      "authorization",
      "Design B has no on-chain authorization root — who may issue for this product is a statement inside the platform's own database",
    );
    return;
  }
  if (!productId) {
    report.skip(scope, "authorization", "no product DID in the bundle, so there is no productId to look up");
    return;
  }
  if (!cred.issuerAddress) {
    // `issuer-did` already carries the reason; this row exists so that every
    // credential has an `authorization` line and a reader never has to notice an
    // ABSENT check — an omitted row reads as "fine" far too easily.
    report.skip(scope, "authorization", "the issuer DID could not be resolved to an address on this chain");
    return;
  }
  if (chainOffline) {
    report.skip(scope, "authorization", offline ? "--offline: the authorization root was not read" : "the chain is not usable from this run (no endpoint, unreachable, or wrong chain id)");
    return;
  }

  try {
    const explicit = decodeBool(
      await rpc.ethCall(chain.registry, selector(SIG.authorized) + wordBytes32(productId) + wordAddress(cred.issuerAddress)),
    );
    if (explicit) {
      report.pass(scope, "authorization", `authorized[${productId.slice(0, 10)}…][${cred.issuerAddress}] == true`);
      return;
    }
    // The controller rule. NOTE that this is verifier-side POLICY, not contract
    // state: `TrustAnchorRegistry` never writes `authorized[p][controller]`, and
    // `setIssuer` is the only thing that writes that mapping. The rule is
    // reproducible by anyone from public chain state (`productController` +
    // `authorized`), which is the test any policy in a verifier has to pass, and
    // it mirrors the platform's own `authRoot.isIssuerAuthorized`. It is
    // reported with its provenance so a reader can disagree with it.
    const controller = decodeAddress(
      await rpc.ethCall(chain.registry, selector(SIG.productController) + wordBytes32(productId)),
    );
    if (controller !== ZERO_ADDRESS && controller === cred.issuerAddress) {
      report.pass(
        scope,
        "authorization",
        `via the CONTROLLER rule: ${cred.issuerAddress} is productController — there is no explicit authorized[] entry ` +
          `(verifier policy, reproducible from public chain state; mirrors authRoot.isIssuerAuthorized)`,
      );
    } else {
      report.fail(
        scope,
        "authorization",
        `the chain says NO: authorized[][${cred.issuerAddress}] is false and the product's controller is ${controller === ZERO_ADDRESS ? "unset (product unclaimed)" : controller}`,
      );
    }
  } catch (err) {
    report.skip(scope, "authorization", `the authorization root could not be read: ${err.message}`);
  }
}

/**
 * The product's controller against the one the verifier EXPECTS.
 *
 * The controller rule and every SetIssuer derive from whoever claimed the product
 * first. A platform that runs the relayer could claim a product with a key of its
 * own before the operator does, admit keys it minted, and anchor — and every other
 * check would pass. Only an expectation from OUTSIDE the platform (the operator's
 * address from the operator itself, a register, a contract) closes that, so it is an
 * input, like --product-id. Judged at the anchor under --authorization-at anchor or
 * block:<n>, otherwise at the latest state.
 */
async function verifyController(ctx, report) {
  const expected = ctx.expectController;
  if (!expected) return;
  const { chain, rpc, offline, chainOffline, productId } = ctx;
  if (!productId) { report.skip("bundle", "controller", "no productId, so there is no controller to compare"); return; }
  if (chainOffline) {
    report.skip("bundle", "controller", offline ? "--offline: the controller was not read" : "the chain is not usable from this run");
    return;
  }
  try {
    let controller, at;
    if (ctx.authorizationAt === "latest" || (ctx.authorizationAt === "anchor" && !ctx.anchorFound)) {
      controller = decodeAddress(await rpc.ethCall(chain.registry, selector(SIG.productController) + wordBytes32(productId)));
      at = "the latest state";
    } else {
      const cut = ctx.authorizationAt === "anchor"
        ? { block: ctx.anchorFound.block, logIndex: ctx.anchorFound.logIndex, label: `the anchoring transaction (block ${ctx.anchorFound.block})` }
        : { block: ctx.authorizationAt.block, logIndex: Number.POSITIVE_INFINITY, label: `the end of block ${ctx.authorizationAt.block}` };
      const before = (l) => { const b = Number(BigInt(l.blockNumber)), i = Number(BigInt(l.logIndex ?? "0x0")); return b < cut.block || (b === cut.block && i < cut.logIndex); };
      const scan = await rpc.scanLogs({ address: chain.registry, topics: [topicOf(EVENT.ProductClaimed), productId],
        fromBlock: ctx.fromBlock, toBlock: cut.block, window: ctx.logWindow, maxRequests: ctx.maxLogRequests, stopWhen: (logs) => logs.some(before) });
      const last = scan.logs.filter(before).sort((x, y) => Number(BigInt(x.blockNumber)) - Number(BigInt(y.blockNumber)) || Number(BigInt(x.logIndex)) - Number(BigInt(y.logIndex))).pop();
      controller = last ? decodeAddress(last.topics[2]) : ZERO_ADDRESS;
      at = cut.label;
    }
    if (controller === expected) report.pass("bundle", "controller", `productController at ${at} is the expected ${expected}`);
    else report.fail("bundle", "controller", `productController at ${at} is ${controller === ZERO_ADDRESS ? "unset" : controller}, not the expected ${expected} — someone else controls this product`);
  } catch (err) {
    report.skip("bundle", "controller", `the controller could not be read: ${err.message}`);
  }
}

/**
 * Authorization AS IT STOOD at a point in time, from the public event log only.
 *
 * `authorized[p][i]` is current state, so a supplier revoked or dissolved AFTER a
 * version was anchored makes that honest, historical version fail under the
 * default mode. `--authorization-at anchor` judges each issuer at the anchoring
 * transaction instead — the state the operator's signed root committed to — by
 * replaying `IssuerAuthorized` and `ProductClaimed` up to (and excluding) the
 * anchor log. No archive node is needed: events are ordinary logs.
 * `--authorization-at block:<n>` judges at the end of block n (for audits and for
 * reproducing what the default mode said at that time).
 */
async function verifyAuthorizationAt(cred, ctx, report) {
  const scope = `credential[${cred.index}]`;
  const { chain, rpc, offline, chainOffline, productId } = ctx;
  if (cred.design !== "design-a") {
    report.skip(scope, "authorization", "Design B has no on-chain authorization root — who may issue for this product is a statement inside the platform's own database");
    return;
  }
  if (!productId) { report.skip(scope, "authorization", "no product DID in the bundle, so there is no productId to look up"); return; }
  if (!cred.issuerAddress) { report.skip(scope, "authorization", "the issuer DID could not be resolved to an address on this chain"); return; }
  if (chainOffline) {
    report.skip(scope, "authorization", offline ? "--offline: the authorization root was not read" : "the chain is not usable from this run (no endpoint, unreachable, or wrong chain id)");
    return;
  }
  let cutoff;
  if (ctx.authorizationAt === "anchor") {
    if (!ctx.anchorFound) {
      report.skip(scope, "authorization", "--authorization-at anchor: no anchor for this version was found, so there is no point in time to judge authorization at");
      return;
    }
    cutoff = { block: ctx.anchorFound.block, logIndex: ctx.anchorFound.logIndex, label: `the anchoring transaction (block ${ctx.anchorFound.block})` };
  } else {
    cutoff = { block: ctx.authorizationAt.block, logIndex: Number.POSITIVE_INFINITY, label: `the end of block ${ctx.authorizationAt.block}` };
  }
  const before = (l) => {
    const b = Number(BigInt(l.blockNumber)), i = Number(BigInt(l.logIndex ?? "0x0"));
    return b < cutoff.block || (b === cutoff.block && i < cutoff.logIndex);
  };
  const newest = (logs) => logs.filter(before).sort((x, y) =>
    Number(BigInt(x.blockNumber)) - Number(BigInt(y.blockNumber)) || Number(BigInt(x.logIndex)) - Number(BigInt(y.logIndex))).pop();
  const scan = (topics) => rpc.scanLogs({
    address: chain.registry, topics, fromBlock: ctx.fromBlock, toBlock: cutoff.block,
    window: ctx.logWindow, maxRequests: ctx.maxLogRequests,
    // Newest-first: the first window holding a qualifying log holds the latest one.
    stopWhen: (logs) => logs.some(before),
  });
  try {
    const auth = await scan([topicOf(EVENT.IssuerAuthorized), productId, "0x" + wordAddress(cred.issuerAddress)]);
    const last = newest(auth.logs);
    if (last && decodeBool(wordAt(last.data, 0))) {
      report.pass(scope, "authorization", `authorized at ${cutoff.label}: IssuerAuthorized(…, ${cred.issuerAddress}, true) in block ${Number(BigInt(last.blockNumber))}`);
      return;
    }
    if (!last && !auth.complete) {
      report.skip(scope, "authorization", `INCONCLUSIVE — the IssuerAuthorized log scan did not cover blocks ${ctx.fromBlock}..${cutoff.block}`);
      return;
    }
    const claims = await scan([topicOf(EVENT.ProductClaimed), productId]);
    const claim = newest(claims.logs);
    const controller = claim ? decodeAddress(claim.topics[2]) : ZERO_ADDRESS;
    if (controller !== ZERO_ADDRESS && controller === cred.issuerAddress) {
      report.pass(scope, "authorization", `via the CONTROLLER rule at ${cutoff.label}: ${cred.issuerAddress} was productController (verifier policy, reproducible from public chain state)`);
    } else if (!claim && !claims.complete) {
      report.skip(scope, "authorization", `INCONCLUSIVE — the ProductClaimed log scan did not cover blocks ${ctx.fromBlock}..${cutoff.block}`);
    } else {
      report.fail(scope, "authorization", `at ${cutoff.label} the chain said NO: ${last ? "the latest IssuerAuthorized for this issuer set false" : "no IssuerAuthorized(true) for this issuer"} and the controller was ${controller === ZERO_ADDRESS ? "unset" : controller}`);
    }
  } catch (err) {
    report.skip(scope, "authorization", `the authorization log could not be read: ${err.message}`);
  }
}

/**
 * The anchor: find the `Anchored` log for (productId, version) and compare its
 * root with the one recomputed from the exported bytes.
 */
async function verifyAnchor(ctx, tree, report) {
  const { chain, rpc, offline, chainOffline, productId, version } = ctx;

  if (!productId) {
    report.skip("bundle", "anchor", "no product DID in the bundle, so there is no productId to search the log for");
    return;
  }
  if (version === null) {
    report.skip("bundle", "anchor", "the bundle names no version, and an anchor is per (productId, version)");
    return;
  }
  if (!tree) {
    report.skip("bundle", "anchor", "the Merkle root could not be recomputed, so there is nothing to compare an anchor with");
    return;
  }
  if (chainOffline) {
    report.skip("bundle", "anchor", offline ? "--offline: the anchor log was not read" : "the chain is not usable from this run (no endpoint, unreachable, or wrong chain id)");
    return;
  }

  // Anchored(bytes32 indexed productId, bytes32 merkleRoot, uint64 version, address indexed by)
  //   topics: [sig, productId, by]   data: [merkleRoot, version]
  const decode = (log) => ({
    merkleRoot: toBytes32(wordAt(log.data, 0)),
    version: Number(decodeUint(wordAt(log.data, 1))),
    by: decodeAddress(log.topics[2]),
    block: Number(BigInt(log.blockNumber)),
    logIndex: Number(BigInt(log.logIndex ?? "0x0")),
    txHash: log.transactionHash,
  });

  // ── Fast path: the bundle (or --anchor-tx) names the anchoring transaction ──
  if (ctx.anchorTx) {
    let receipt = null;
    try {
      receipt = await rpc.call("eth_getTransactionReceipt", [ctx.anchorTx]);
    } catch {
      receipt = null;
    }
    if (receipt) {
      const matching = (receipt.logs ?? [])
        .filter(
          (log) =>
            toAddress(log.address) === chain.registry &&
            log.topics?.[0] === topicOf(EVENT.Anchored) &&
            toBytes32(log.topics[1]) === productId,
        )
        .map(decode)
        .filter((a) => a.version === version);
      if (matching.length === 0) {
        report.fail(
          "bundle",
          "anchor",
          `anchor tx ${ctx.anchorTx} contains no Anchored(productId=${productId.slice(0, 10)}…, version=${version}) log from ${chain.registry}`,
        );
        return;
      }
      ctx.anchorFound = matching[matching.length - 1];
      compareAnchor(ctx.anchorFound, matching.length, tree, report, `named by the bundle`);
      return;
    }
    // A missing receipt is not evidence of absence: endpoints that prune old
    // receipts answer null for transactions that exist. The hint is only a hint,
    // so the full log scan below decides on its own.
    ctx.anchorHintMissing = true;
  }

  let scan;
  try {
    const toBlock = ctx.toBlock ?? (await rpc.blockNumber());
    scan = await rpc.scanLogs({
      address: chain.registry,
      // Only `productId` is indexed alongside topic0; `version` lives in the
      // data, so it is filtered client-side.
      topics: [topicOf(EVENT.Anchored), productId],
      fromBlock: ctx.fromBlock,
      toBlock,
      window: ctx.logWindow,
      maxRequests: ctx.maxLogRequests,
      // Backwards scan: the first window that contains a matching anchor holds
      // the newest one, so there is nothing older worth looking for.
      stopWhen: (logs) => logs.some((l) => decode(l).version === version),
    });
  } catch (err) {
    report.skip("bundle", "anchor", `the anchor log could not be read: ${err.message}`);
    return;
  }

  const anchors = scan.logs.map(decode).filter((a) => a.version === version);

  if (anchors.length === 0) {
    if (!scan.complete) {
      // Coverage, not absence. Saying FAIL here would be the exact sin this tool
      // exists to avoid: reporting "never anchored" when the truth is "I did not
      // look at those blocks".
      report.skip(
        "bundle",
        "anchor",
        `INCONCLUSIVE — the endpoint capped eth_getLogs at ${scan.window} block(s) and the ${scan.requests}-request budget ` +
          `covered only blocks ${scan.scannedFrom}..${scan.scannedTo} of ${ctx.fromBlock}..${scan.scannedTo}. ` +
          `No anchor was found in what was scanned, but absence is NOT established. ` +
          `Narrow with --from-block/--to-block, raise --max-log-requests, or use an endpoint without a range cap.`,
      );
      return;
    }
    report.fail(
      "bundle",
      "anchor",
      `no Anchored(productId=${productId.slice(0, 10)}…, version=${version}) log in blocks ${scan.scannedFrom}..${scan.scannedTo} at ${chain.registry} — ` +
        `this version was never anchored, so nothing outside the platform attests to these bytes` +
        // For a Design B passport this is not an operational failure, it is the
        // design: B has no anchoring step at all. Naming that keeps the ✗ from
        // being read as "something went wrong" when it means "there is nothing
        // here to go right".
        (ctx.design === "design-b"
          ? ". Note this is Design B, which has NO on-chain anchor by construction: its tamper-evidence is the platform's own audit chain, which only the platform can vouch for"
          : ""),
    );
    return;
  }

  // The contract enforces no monotonicity on `version` (anchors are events, not
  // storage), so a version CAN legitimately be re-anchored. The newest log wins,
  // and an earlier one that disagrees is reported rather than hidden.
  anchors.sort((a, b) => a.block - b.block || a.logIndex - b.logIndex);
  ctx.anchorFound = anchors[anchors.length - 1];
  compareAnchor(ctx.anchorFound, anchors.length, tree, report,
    ctx.anchorHintMissing ? `found by log scan; the hinted receipt was not available from this endpoint` : `found by log scan`);
}

/** The comparison itself, shared by the receipt fast path and the log scan so
 *  the two can never disagree about what a match is. */
function compareAnchor(anchor, count, tree, report, how) {
  const detail =
    `block ${anchor.block}, tx ${anchor.txHash}, signed by ${anchor.by} (${how})` +
    (count > 1 ? ` — ${count} anchors for this version; newest used` : "");
  if (anchor.merkleRoot === toBytes32(tree.root)) {
    report.pass("bundle", "anchor", `on-chain root MATCHES the root recomputed from these bytes — ${detail}`);
  } else {
    report.fail(
      "bundle",
      "anchor",
      `MISMATCH: the chain committed to ${anchor.merkleRoot} but these bytes produce ${tree.root} — ` +
        `the served bytes are NOT the bytes that were anchored (${detail})`,
    );
  }
}

/* ════════════════════════════════════════════════════════════════════════════
 * §13  CLI
 * ════════════════════════════════════════════════════════════════════════════ */

function parseArgs(argv) {
  const opts = {
    bundle: null,
    inspect: null,
    rpc: process.env.RPC_URL || process.env.AMOY_RPC_URL || null,
    chainId: DEFAULTS.chainId,
    chainName: DEFAULTS.chainName,
    registry: DEFAULTS.registry,
    didRegistry: DEFAULTS.didRegistry,
    fromBlock: DEFAULTS.fromBlock,
    toBlock: null,
    logWindow: DEFAULTS.logWindow,
    maxLogRequests: DEFAULTS.maxLogRequests,
    productDid: null,
    asOf: null,
    // The chain stores only keccak256(productDid) — that is the contract's
    // no-PII-on-chain property. A verifier may therefore legitimately hold the
    // productId without ever having seen the DID, so it is an accepted input.
    productId: null,
    /** Where the anchoring transaction is. A hint only — see `verifyAnchor`. */
    anchorTx: null,
    authorizationAt: "latest",
    expectController: null,
    version: null,
    offline: false,
    json: false,
    color: process.stdout.isTTY === true,
    selfTestOnly: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case "--rpc": opts.rpc = next(); break;
      case "--chain-id": opts.chainId = Number(next()); break;
      case "--chain-name": opts.chainName = next(); break;
      case "--registry": opts.registry = next(); break;
      case "--did-registry": opts.didRegistry = next(); break;
      case "--from-block": opts.fromBlock = Number(next()); break;
      case "--to-block": opts.toBlock = Number(next()); break;
      case "--log-window": opts.logWindow = Number(next()); break;
      case "--max-log-requests": opts.maxLogRequests = Number(next()); break;
      case "--as-of": {
        const raw = next();
        const ms = Date.parse(raw);
        if (Number.isNaN(ms)) throw new Error(`--as-of "${raw}" is not a parsable date-time`);
        opts.asOf = ms;
        break;
      }
      case "--product-did": opts.productDid = next(); break;
      case "--product-id": opts.productId = next(); break;
      case "--anchor-tx": opts.anchorTx = next(); break;
      case "--expect-controller": opts.expectController = next(); break;
      case "--authorization-at": {
        const raw = next();
        if (raw === "latest" || raw === "anchor") opts.authorizationAt = raw;
        else if (/^block:\d+$/.test(raw)) opts.authorizationAt = { block: Number(raw.slice(6)) };
        else throw new Error(`--authorization-at "${raw}": use latest, anchor or block:<n>`);
        break;
      }
      case "--version": opts.version = Number(next()); break;
      case "--inspect": opts.inspect = next(); break;
      case "--offline": opts.offline = true; break;
      case "--json": opts.json = true; opts.color = false; break;
      case "--color": opts.color = true; break;
      case "--no-color": opts.color = false; break;
      case "--self-test": opts.selfTestOnly = true; break;
      case "-h":
      case "--help": opts.help = true; break;
      default:
        if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
        if (opts.bundle) throw new Error("more than one bundle file given");
        opts.bundle = a;
    }
  }
  return opts;
}

const USAGE = `usage: node scripts/verify-passport.mjs <bundle.json> [options]
       node scripts/verify-passport.mjs --inspect <0x…productId | did:…> [options]
       node scripts/verify-passport.mjs --self-test

  --rpc <url>            JSON-RPC endpoint (or $RPC_URL). Never printed.
  --chain-id <n>         expected chain id                     (default ${DEFAULTS.chainId})
  --chain-name <s>       chain name a did:ethr may spell       (default ${DEFAULTS.chainName})
  --registry <addr>      TrustAnchorRegistry                   (default ${DEFAULTS.registry})
  --did-registry <addr>  ERC-1056 registry                     (default ${DEFAULTS.didRegistry})
  --from-block <n>       anchor log scan start                 (default ${DEFAULTS.fromBlock})
  --to-block <n>         anchor log scan end                   (default latest)
  --log-window <n>       eth_getLogs chunk size                (default ${DEFAULTS.logWindow})
  --max-log-requests <n> budget for one anchor scan            (default ${DEFAULTS.maxLogRequests})
  --product-did <did>    override the bundle's product DID
  --as-of <date-time>    judge validFrom/validUntil at this instant, not now
                         (keeps an archived report reproducible after expiry)
  --product-id <0x…>     the keccak256(productDid) the chain stores, directly
  --anchor-tx <0x…>      the anchoring transaction (a hint; still fully checked)
  --authorization-at <m> judge issuer authorization at: latest (default, current
                         state) | anchor (as committed by the version's anchor) |
                         block:<n> (end of block n), from the public event log
  --expect-controller <a> the operator address that SHOULD control the product,
                         taken from outside the platform; adds a controller check
  --version <n>          override the bundle's passport version
  --offline              never touch the network
  --json                 machine-readable report
  --no-color             plain ASCII
  --self-test            run crypto vectors and exit

exit codes: 0 VERIFIED · 1 FAILED · 2 usage/IO/self-test · 3 INCOMPLETE (a check was skipped)`;

// ── Rendering ────────────────────────────────────────────────────────────────

const COLORS = { PASS: "\x1b[32m", FAIL: "\x1b[31m", SKIP: "\x1b[33m", dim: "\x1b[2m", bold: "\x1b[1m", off: "\x1b[0m" };
// PASS/FAIL/SKIP must be distinguishable WITHOUT colour — a thesis appendix is
// printed in black and white, and a reader must never have to infer a skip.
const MARK = { PASS: "[ ✓ PASS ]", FAIL: "[ ✗ FAIL ]", SKIP: "[ – SKIP ]" };

function render(report, meta, opts) {
  const c = (s, code) => (opts.color ? code + s + COLORS.off : s);
  const lines = [];
  lines.push(c("TrustDPP — independent passport verifier", COLORS.bold));
  lines.push(`  bundle    ${meta.bundlePath ?? "(none)"}`);
  lines.push(`  shape     ${meta.shape ?? "-"}`);
  lines.push(`  design    ${meta.design}`);
  lines.push(`  product   ${meta.productDid ?? "(none in bundle)"}${meta.productId ? `  → productId ${meta.productId}` : ""}`);
  lines.push(`  version   ${meta.version ?? "-"}   credentials: ${meta.credentialCount}`);
  lines.push(
    `  chain     ${meta.offline ? "(offline — no network was used)" : `chain ${meta.chainId}, registry ${meta.registry}, ERC-1056 ${meta.didRegistry}, ${meta.rpcCalls} RPC calls`}`,
  );
  lines.push("");

  let scope = null;
  for (const check of report.checks) {
    if (check.scope !== scope) {
      scope = check.scope;
      const label = meta.scopeLabels[scope] ?? scope;
      lines.push(c(label, COLORS.bold));
    }
    const mark = opts.color ? COLORS[check.status] + MARK[check.status] + COLORS.off : MARK[check.status];
    lines.push(`  ${mark}  ${check.name.padEnd(18)} ${wrap(check.detail ?? "", 20)}`);
  }

  const counts = report.counts();
  const { verdict } = report.verdict();
  lines.push("");
  lines.push(`  ${counts.pass} passed · ${counts.fail} failed · ${counts.skip} skipped`);
  const verdictColor = verdict === "VERIFIED" ? COLORS.PASS : verdict === "FAILED" ? COLORS.FAIL : COLORS.SKIP;
  lines.push(c(`  ${verdict}`, verdictColor + COLORS.bold));
  if (counts.skip > 0) {
    lines.push(
      c("  A skipped check is NOT a passed check — this verifier did not establish those facts.", COLORS.dim),
    );
  }
  return lines.join("\n");
}

/** Soft-wrap a detail line under the status column so long reasons stay readable. */
function wrap(text, indent, width = 100) {
  if (!text) return "";
  const pad = " ".repeat(indent + 12);
  const words = text.split(" ");
  const out = [];
  let line = "";
  for (const w of words) {
    if (line.length + w.length + 1 > width) {
      out.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) out.push(line);
  return out.join("\n" + pad);
}

/*
 * §14 --inspect: what does the chain say about this product?
 */

async function inspect(target, chain, rpc, opts) {
  const productId = target.startsWith("did:") ? keccak256Utf8(target) : toBytes32(target, "productId");
  const out = { target, productId, chainId: null, registry: chain.registry };
  out.chainId = await rpc.chainId();
  const controller = decodeAddress(await rpc.ethCall(chain.registry, selector(SIG.productController) + wordBytes32(productId)));
  out.productController = controller;
  out.nonce = String(decodeUint(await rpc.ethCall(chain.registry, selector(SIG.nonces) + wordAddress(controller))));
  out.selectors = Object.fromEntries(Object.entries(SIG).map(([k, s]) => [k, selector(s)]));
  out.eventTopics = Object.fromEntries(Object.entries(EVENT).map(([k, s]) => [k, topicOf(s)]));

  const toBlock = opts.toBlock ?? (await rpc.blockNumber());
  const scan = await rpc.scanLogs({
    address: chain.registry,
    topics: [null, productId],
    fromBlock: opts.fromBlock,
    toBlock,
    window: opts.logWindow,
    maxRequests: opts.maxLogRequests,
  });
  out.requestedBlocks = `${opts.fromBlock}..${toBlock}`;
  out.scannedBlocks = `${scan.scannedFrom}..${scan.scannedTo}`;
  out.scanComplete = scan.complete;
  out.rpcRequests = scan.requests;
  out.endpointRangeCap = scan.capped ? scan.window : null;
  out.logs = scan.logs.map((log) => {
    const base = { block: Number(BigInt(log.blockNumber)), tx: log.transactionHash };
    if (log.topics[0] === topicOf(EVENT.Anchored)) {
      return { ...base, event: "Anchored", merkleRoot: toBytes32(wordAt(log.data, 0)), version: String(decodeUint(wordAt(log.data, 1))), by: decodeAddress(log.topics[2]) };
    }
    if (log.topics[0] === topicOf(EVENT.ProductClaimed)) {
      return { ...base, event: "ProductClaimed", controller: decodeAddress(log.topics[2]), previous: decodeAddress(log.topics[3]) };
    }
    if (log.topics[0] === topicOf(EVENT.IssuerAuthorized)) {
      return { ...base, event: "IssuerAuthorized", issuer: decodeAddress(log.topics[2]), allowed: decodeBool(wordAt(log.data, 0)) };
    }
    return { ...base, event: `unknown(${log.topics[0]})` };
  });
  return out;
}

/* ════════════════════════════════════════════════════════════════════════════
 * §15  main
 * ════════════════════════════════════════════════════════════════════════════ */

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`${err.message}\n\n${USAGE}`);
    process.exit(2);
  }
  if (opts.help) {
    console.log(USAGE);
    process.exit(0);
  }

  // Always, before anything else. See §11.
  const selfTestFailures = selfTest();
  if (selfTestFailures.length > 0) {
    console.error("CRYPTO SELF-TEST FAILED — this build cannot be trusted to verify anything:");
    for (const f of selfTestFailures) console.error(`  ✗ ${f}`);
    process.exit(2);
  }
  if (opts.selfTestOnly) {
    console.log("crypto self-test: PASS (keccak256 ×2, sha256, ES256K-R recovery, EIP-2 high-s refusal, merkle ×2)");
    process.exit(0);
  }

  const chain = {
    chainId: opts.chainId,
    chainName: opts.chainName,
    registry: toAddress(opts.registry, "--registry"),
    didRegistry: toAddress(opts.didRegistry, "--did-registry"),
  };
  const rpc = opts.offline || !opts.rpc ? null : new Rpc(opts.rpc);

  // ── --inspect ──
  if (opts.inspect) {
    if (!rpc) {
      console.error("--inspect needs an RPC endpoint (--rpc or $RPC_URL) and cannot run --offline");
      process.exit(2);
    }
    const result = await inspect(opts.inspect, chain, rpc, opts);
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  }

  if (!opts.bundle) {
    console.error(USAGE);
    process.exit(2);
  }

  let bundle;
  try {
    bundle = parseBundle(JSON.parse(readFileSync(opts.bundle, "utf8")), opts);
  } catch (err) {
    console.error(`cannot read bundle: ${err.message}`);
    process.exit(2);
  }

  const report = new Report();

  // The chain identity is checked BEFORE anything is read from it. Verifying
  // against the wrong chain would produce answers that look authoritative and are
  // about somebody else's contracts. ⚠ TWO INDEPENDENT TRANSPORTS, TWO INDEPENDENT
  // FLAGS.
  let chainUsable = true;
  if (rpc) {
    try {
      const actual = await rpc.chainId();
      if (actual !== chain.chainId) {
        report.fail("chain", "chain-id", `the RPC endpoint serves chain ${actual}, but this run expects ${chain.chainId} — refusing to read it`);
        // Every CHAIN-dependent check below becomes a SKIP, not a guess.
        chainUsable = false;
      } else {
        report.pass("chain", "chain-id", `the endpoint serves chain ${actual} (${chain.chainName})`);
      }
    } catch (err) {
      report.skip("chain", "chain-id", `the endpoint could not be reached: ${err.message}`);
      chainUsable = false;
    }
  } else {
    report.skip("chain", "chain-id", opts.offline ? "--offline: no chain was consulted" : "no --rpc endpoint given");
  }

  // An explicit --product-id wins over the DID, and when both are given they are
  // checked against each other: a mismatch means the bundle and the chain lookup
  // are about two different products, which is a finding, not a preference.
  let productId = bundle.productDid ? keccak256Utf8(bundle.productDid) : null;
  if (opts.productId) {
    const given = toBytes32(opts.productId, "--product-id");
    if (productId && productId !== given) {
      report.fail("bundle", "product-id", `--product-id ${given} is not keccak256("${bundle.productDid}") = ${productId}`);
    } else if (productId) {
      report.pass("bundle", "product-id", `--product-id matches keccak256(productDid)`);
    }
    productId = given;
  }
  const ctx = {
    chain,
    rpc: chainUsable ? rpc : null,
    /** `--offline` only. Gates every network transport, HTTPS included. */
    offline: opts.offline,
    /** Gates chain reads specifically: --offline, no endpoint, or an endpoint
     *  that could not be reached or serves the wrong chain. */
    chainOffline: opts.offline || !rpc || !chainUsable,
    productId,
    productDid: bundle.productDid,
    /** The instant `validFrom`/`validUntil` are judged against. */
    asOf: opts.asOf ?? Date.now(),
    asOfExplicit: opts.asOf !== null,
    version: bundle.version,
    fromBlock: opts.fromBlock,
    toBlock: opts.toBlock,
    logWindow: opts.logWindow,
    maxLogRequests: opts.maxLogRequests,
    anchorTx: bundle.anchorTx,
    /** "latest" (default: current state), "anchor", or { block } — see verifyAuthorizationAt. */
    authorizationAt: opts.authorizationAt,
    anchorFound: null,
    expectController: opts.expectController ? toAddress(opts.expectController, "--expect-controller") : null,
  };

  const tree = verifyOffline(bundle, report);

  const creds = [];
  for (let i = 0; i < bundle.credentials.length; i++) {
    const cred = inspectCredential(bundle.credentials[i], i, chain, report);
    if (cred.design === "design-b") reportDesignBSignature(cred, report);
    verifySubjectBinding(cred, ctx, report);
    verifyValidity(cred, ctx, report);
    await verifyIssuer(cred, ctx, report);
    if (ctx.authorizationAt === "latest") await verifyAuthorization(cred, ctx, report);
    creds.push(cred);
  }

  // Determined BEFORE the anchor check, which phrases its finding differently
  // for a design that has no anchoring step at all.
  const designs = new Set(creds.map((c) => c.design).filter(Boolean));
  const design =
    designs.size === 0 ? "unknown" : designs.size > 1 ? `mixed (${[...designs].join(", ")})` : [...designs][0];
  ctx.design = design;

  await verifyAnchor(ctx, tree, report);
  // Point-in-time authorization needs the anchor first, so it runs after it.
  if (ctx.authorizationAt !== "latest") {
    for (const c of creds) await verifyAuthorizationAt(c, ctx, report);
  }
  await verifyController(ctx, report);

  const scopeLabels = { chain: "chain", bundle: "bundle" };
  for (const c of creds) {
    scopeLabels[`credential[${c.index}]`] =
      `credential[${c.index}]  ${c.role ? `role=${c.role}  ` : ""}${c.issuerDid ? `issuer=${c.issuerDid}` : "(no issuer)"}`;
  }

  const meta = {
    bundlePath: opts.bundle,
    shape: bundle.shape,
    design,
    productDid: bundle.productDid,
    productId,
    version: bundle.version,
    credentialCount: bundle.credentials.length,
    chainId: chain.chainId,
    registry: chain.registry,
    didRegistry: chain.didRegistry,
    offline: ctx.chainOffline,
    rpcCalls: rpc ? rpc.calls : 0,
    scopeLabels,
  };

  const { verdict, exitCode } = report.verdict();
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          tool: "verify-passport",
          formatVersion: 1,
          bundle: opts.bundle,
          shape: bundle.shape,
          design,
          product: { did: bundle.productDid, productId },
          passportVersion: bundle.version,
          merkleRoot: tree?.root ?? null,
          credentialDigests: tree?.credentialDigests ?? null,
          snapshotDigest: tree?.snapshotDigest ?? null,
          // The RPC URL is deliberately absent: it carries an API key and this
          // report is meant to be publishable.
          chain: { chainId: chain.chainId, registry: chain.registry, didRegistry: chain.didRegistry, rpcCalls: meta.rpcCalls, offline: ctx.chainOffline },
          credentials: creds.map((c) => ({ index: c.index, design: c.design, id: c.id, role: c.role, issuer: c.issuerDid, signerAddress: c.signerAddress ?? null, cryptosuite: c.cryptosuite ?? (c.design === "design-a" ? "ES256K-R" : null) })),
          checks: report.checks,
          counts: report.counts(),
          verdict,
          exitCode,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(render(report, meta, opts));
  }
  process.exit(exitCode);
}

main().catch((err) => {
  console.error(`verify-passport: ${err.stack ?? err.message}`);
  process.exit(2);
});
