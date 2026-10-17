#!/usr/bin/env node
/**
 * ─── Adversarial harness for `verify-passport.mjs` (thesis artifact) ──────────
 * `verify-passport.mjs` says of itself: *"the entire value of this tool is that
 * a reader can trust its ✗."* Until this file existed, nothing in the repository
 * had ever made it produce one. Every run was against bytes the platform itself
 * had just written, and a verifier that has only ever agreed is
 * indistinguishable from a verifier that always agrees.
 */

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERIFIER = join(HERE, "verify-passport.mjs");
const ACTORS_FILE = join(HERE, ".design-a-actors.json");

/* ═══════════════════════════════════════════════════════════════════════════
 * Bytes, JWS, and the platform's own digest
 * ═══════════════════════════════════════════════════════════════════════════ */

const b64uEncode = (buf) => Buffer.from(buf).toString("base64url");
const b64uDecode = (s) => Buffer.from(s, "base64url");
const sha256 = (s) => crypto.createHash("sha256").update(s).digest();

/** The verifier's canonical serializer, re-implemented — this script is playing
 *  the platform's part, so it must be able to recompute the platform's digest. */
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
    .join(",")}}`;
}

const versionHash = (bundle) =>
  sha256(stableStringify({ snapshot: bundle.snapshot, credentials: bundle.credentials, version: bundle.version })).toString("hex");

const DATA_URI = "data:application/vc+jwt,";
const tokenOf = (cred) => String(cred.id).slice(cred.id.indexOf(",") + 1);
const wrapToken = (cred, token) => ({ ...cred, id: DATA_URI + token });

function splitToken(token) {
  const [h, p, s] = token.split(".");
  return { encHeader: h, encPayload: p, encSignature: s, header: JSON.parse(b64uDecode(h)), payload: JSON.parse(b64uDecode(p)) };
}

const addressOf = (priv) => `0x${Buffer.from(keccak_256(secp256k1.getPublicKey(priv, false).slice(1))).toString("hex").slice(-40)}`;

/** ES256K-R over `${b64u(header)}.${b64u(payload)}`, exactly as the browser
 *  signer and `seed-design-a.ts` produce it: r‖s‖recovery, 65 bytes, low-s. */
function signJws(header, payload, privateKeyHex) {
  const key = Buffer.from(privateKeyHex.replace(/^0x/, ""), "hex");
  const encHeader = b64uEncode(Buffer.from(JSON.stringify(header), "utf8"));
  const encPayload = b64uEncode(Buffer.from(JSON.stringify(payload), "utf8"));
  const sig = secp256k1.sign(sha256(`${encHeader}.${encPayload}`), key);
  const raw = new Uint8Array(65);
  raw.set(sig.toCompactRawBytes(), 0);
  raw[64] = sig.recovery;
  return `${encHeader}.${encPayload}.${b64uEncode(raw)}`;
}

/*
 * The catalogue
 */

const clone = (x) => JSON.parse(JSON.stringify(x));

/** Credential indices in the demonstration bundle, by role, resolved at run time. */
function indexByIssuer(bundle, address) {
  return bundle.credentials.findIndex((c) => splitToken(tokenOf(c)).payload.issuer?.toLowerCase().endsWith(address.toLowerCase()));
}

function buildCatalogue(ctx) {
  const { actors } = ctx;
  const farm = actors?.farm ?? null;
  const list = [];

  const add = (m) => list.push(m);

  /* ── A. Byte-level corruption, attacker does not cover their tracks ────── */

  add({
    id: "payload-byte-flip",
    title: "One byte flipped inside a credential's JWS payload",
    promise: "§13 RQ2 „Manipulationserkennung: VC-Inhalt modifizieren → Hash-Mismatch\"; §16 Manipulationserkennung",
    change: (b) => {
      const i = ctx.farmIndex;
      const t = splitToken(tokenOf(b.credentials[i]));
      // Flip one character of the base64url payload — a single-byte corruption
      // of the signed bytes, nothing else touched.
      const chars = t.encPayload.split("");
      const at = Math.floor(chars.length / 2);
      chars[at] = chars[at] === "A" ? "B" : "A";
      b.credentials[i] = wrapToken(b.credentials[i], `${t.encHeader}.${chars.join("")}.${t.encSignature}`);
      return `credential[${i}] payload char ${at} '${t.encPayload[at]}' → '${chars[at]}'`;
    },
    rehash: false,
    expect: {
      offline: ["bundle.version-hash", `credential[${ctx.farmIndex}].signature`],
      // `issuer-key-current` fails too, and correctly: the address the forged
      // bytes recover to is not one the DID document authorizes. Its printed
      // reason names rotation, which is the ordinary cause but not this one.
      online: ["bundle.version-hash", `credential[${ctx.farmIndex}].signature`, `credential[${ctx.farmIndex}].issuer-key-current`, "bundle.anchor"],
    },
  });

  add({
    id: "credential-reorder",
    title: "Two credentials swapped in the array",
    promise: "§16 Manipulationserkennung — the snapshot digest is order-carrying",
    change: (b) => {
      const [a, c] = [1, 2];
      [b.credentials[a], b.credentials[c]] = [b.credentials[c], b.credentials[a]];
      return `credentials[${a}] ↔ credentials[${c}]; no bytes altered, only their order`;
    },
    rehash: false,
    expect: { offline: ["bundle.version-hash"], online: ["bundle.version-hash", "bundle.anchor"] },
  });

  add({
    id: "credential-reorder-rehashed",
    title: "Two credentials swapped, and the platform recomputes its own digest",
    promise: "§15 „ein passender version-hash beweist nichts gegen die Plattform\"",
    change: (b) => {
      const [a, c] = [1, 2];
      [b.credentials[a], b.credentials[c]] = [b.credentials[c], b.credentials[a]];
      return `credentials[${a}] ↔ credentials[${c}], then \`hash\` recomputed by the mutator`;
    },
    rehash: true,
    expect: { offline: [], online: ["bundle.anchor"] },
    pass: ["bundle.version-hash", "bundle.merkle-root"],
  });

  add({
    id: "credential-delete",
    title: "One credential removed from the bundle",
    promise: "§13 RQ2 Manipulationserkennung; §16 Hash-Integritätsprüfung",
    change: (b) => {
      const gone = splitToken(tokenOf(b.credentials[4])).payload;
      b.credentials.splice(4, 1);
      return `credential[4] (role=${gone.credentialSubject?.role}, issuer=${gone.issuer}) deleted; 6 → 5 credentials`;
    },
    rehash: false,
    expect: { offline: ["bundle.version-hash"], online: ["bundle.version-hash", "bundle.anchor"] },
  });

  add({
    id: "credential-delete-rehashed",
    title: "One credential removed, and the platform recomputes its own digest",
    promise: "§15/§16 — the only surviving evidence is the on-chain anchor",
    change: (b) => {
      const gone = splitToken(tokenOf(b.credentials[4])).payload;
      b.credentials.splice(4, 1);
      return `credential[4] (role=${gone.credentialSubject?.role}) deleted, then \`hash\` recomputed`;
    },
    rehash: true,
    expect: { offline: [], online: ["bundle.anchor"] },
    pass: ["bundle.version-hash", "bundle.merkle-root"],
  });

  add({
    id: "snapshot-attribution-swap-rehashed",
    title: "The snapshot credits a different company for a claim; credentials untouched",
    promise: "§7.4 WYSIWYS — the human-readable attribution and the cryptographic one are different surfaces",
    change: (b) => {
      const t0 = b.snapshot.tiers[0];
      const t2 = b.snapshot.tiers[2];
      const wasName = t0.tierName;
      const wasDid = t0.issuerDid;
      t0.tierName = t2.tierName;
      t0.issuerDid = t2.issuerDid;
      return `snapshot.tiers[0] re-credited from "${wasName}" (${wasDid}) to "${t2.tierName}" (${t2.issuerDid}); every credential left byte-identical, then \`hash\` recomputed`;
    },
    rehash: true,
    expect: { offline: [], online: ["bundle.anchor"] },
    pass: ["bundle.version-hash", "bundle.merkle-root"],
  });

  /* ── B. Forgery and issuer binding ──────────────────────────────────────── */

  add({
    id: "platform-signs-as-supplier",
    title: "The platform mints a key and signs a supplier's credential in that supplier's name",
    promise: "§13 RQ1 „Fälschungsversuch: Plattform versucht als Lieferant zu signieren → Verifikation muss fehlschlagen\"",
    change: (b) => {
      const i = ctx.farmIndex;
      const { header, payload } = splitToken(tokenOf(b.credentials[i]));
      const forged = clone(payload);
      forged.credentialSubject.origin = { country: "IT — Italy" };
      // The platform can mint keys freely. What it cannot do is hold the
      // supplier's. So it signs with its own and leaves `issuer` claiming to be
      // the supplier — the only forgery available to it.
      b.credentials[i] = wrapToken(b.credentials[i], signJws(header, forged, ctx.platformKey));
      return `credential[${i}] re-signed by a freshly minted platform key ${ctx.platformAddress}, origin changed PT → IT, \`issuer\` left as ${payload.issuer}`;
    },
    rehash: true,
    expect: {
      offline: [`credential[${ctx.farmIndex}].signature`],
      online: [`credential[${ctx.farmIndex}].signature`, `credential[${ctx.farmIndex}].issuer-key-current`, "bundle.anchor"],
    },
    pass: ["bundle.version-hash"],
  });

  add({
    id: "issuer-did-swap-rehashed",
    title: "The `issuer` DID is swapped to another real supplier, without re-signing",
    promise: "§13 RQ1 — issuer binding; §14 „Nicht-autorisierter Dritter\"",
    change: (b) => {
      const i = ctx.farmIndex;
      const t = splitToken(tokenOf(b.credentials[i]));
      const other = b.snapshot.tiers[2].issuerDid;
      const payload = clone(t.payload);
      const was = payload.issuer;
      payload.issuer = other;
      const encPayload = b64uEncode(Buffer.from(JSON.stringify(payload), "utf8"));
      // Signature bytes carried over verbatim: the attacker cannot re-sign.
      b.credentials[i] = wrapToken(b.credentials[i], `${t.encHeader}.${encPayload}.${t.encSignature}`);
      return `credential[${i}] \`issuer\` ${was} → ${other}, signature bytes untouched, then \`hash\` recomputed`;
    },
    rehash: true,
    expect: {
      offline: [`credential[${ctx.farmIndex}].signature`],
      online: [`credential[${ctx.farmIndex}].signature`, `credential[${ctx.farmIndex}].issuer-key-current`, "bundle.anchor"],
    },
    pass: ["bundle.version-hash"],
  });

  add({
    id: "unauthorized-issuer-rehashed",
    title: "A credential validly signed by a key the chain never authorized for this product",
    promise: "§13 RQ1 „Nicht-autorisierter Akteur stellt VC für GTIN X aus → Autorisierungsprüfung muss fehlschlagen (Mech. 4)\"",
    change: (b) => {
      const i = ctx.farmIndex;
      const t = splitToken(tokenOf(b.credentials[i]));
      const did = `did:ethr:0x13882:${ctx.rogueAddress}`;
      const payload = clone(t.payload);
      payload.issuer = did;
      payload.credentialSubject.origin = { country: "IT — Italy" };
      const header = { ...t.header, kid: `${did}#controller` };
      b.credentials[i] = wrapToken(b.credentials[i], signJws(header, payload, ctx.rogueKey));
      return `credential[${i}] replaced by a self-consistent credential from ${did} — a key that exists, resolves, and was never setIssuer'd for this product`;
    },
    rehash: true,
    expect: { offline: [], online: [`credential[${ctx.farmIndex}].authorization`, "bundle.anchor"] },
    pass: [
      "bundle.version-hash",
      `credential[${ctx.farmIndex}].signature`,
      `credential[${ctx.farmIndex}].issuer-did`,
      `credential[${ctx.farmIndex}].issuer-resolution`,
      `credential[${ctx.farmIndex}].issuer-key-current`,
    ],
  });

  add({
    id: "alg-none-rehashed",
    title: "JWS algorithm downgraded to `none`, signature bytes left in place",
    promise: "§14 „Bösartige Plattform\" — the classic JWS `alg` downgrade",
    change: (b) => {
      const i = ctx.farmIndex;
      const t = splitToken(tokenOf(b.credentials[i]));
      const header = { ...t.header, alg: "none" };
      const encHeader = b64uEncode(Buffer.from(JSON.stringify(header), "utf8"));
      // The signature segment is KEPT so the token is still a well-formed
      // compact JWS. That is what forces the `alg` allow-list to be the thing
      // that refuses it, rather than the envelope parser.
      b.credentials[i] = wrapToken(b.credentials[i], `${encHeader}.${t.encPayload}.${t.encSignature}`);
      return `credential[${i}] header alg ES256K-R → none, signature segment kept so the token still parses`;
    },
    rehash: true,
    expect: {
      offline: [`credential[${ctx.farmIndex}].signature`],
      online: [`credential[${ctx.farmIndex}].signature`, "bundle.anchor"],
    },
    pass: ["bundle.version-hash"],
  });

  add({
    id: "alg-none-empty-signature-rehashed",
    title: "RFC 7515 unsecured JWS in its canonical form — `alg: none`, empty signature segment",
    promise: "§14 — the same downgrade, refused one layer earlier",
    change: (b) => {
      const i = ctx.farmIndex;
      const t = splitToken(tokenOf(b.credentials[i]));
      const header = { ...t.header, alg: "none" };
      const encHeader = b64uEncode(Buffer.from(JSON.stringify(header), "utf8"));
      b.credentials[i] = wrapToken(b.credentials[i], `${encHeader}.${t.encPayload}.`);
      return `credential[${i}] header alg ES256K-R → none, signature segment emptied (RFC 7515 §6)`;
    },
    rehash: true,
    // Refused, but NOT by the `alg` guard: an empty third segment is not a
    // compact JWS, so the envelope parser declines it first and the credential
    // falls through to the embedded-proof branch, which finds no `proof`. The
    // refusal is correct and loud; where it lands is worth a reader knowing.
    expect: {
      offline: [`credential[${ctx.farmIndex}].parse`, `credential[${ctx.farmIndex}].issuer-did`],
      online: [`credential[${ctx.farmIndex}].parse`, `credential[${ctx.farmIndex}].issuer-did`, "bundle.anchor"],
    },
    pass: ["bundle.version-hash"],
  });

  if (farm) {
    add({
      id: "typ-cross-protocol-rehashed",
      title: "A genuine supplier signature, minted under a different `typ` and served as a credential",
      promise: "Threat model (Sec. 4.3) — cross-protocol replay of the actor's general-purpose secp256k1 key",
      change: (b) => {
        const i = ctx.farmIndex;
        const t = splitToken(tokenOf(b.credentials[i]));
        const header = { ...t.header, typ: "dpop+jwt" };
        b.credentials[i] = wrapToken(b.credentials[i], signJws(header, t.payload, farm.privateKey));
        return `credential[${i}] re-signed by the REAL supplier key ${farm.address} with typ "dpop+jwt" — the signature is genuine`;
      },
      rehash: true,
      expect: {
        offline: [`credential[${ctx.farmIndex}].signature`],
        online: [`credential[${ctx.farmIndex}].signature`, "bundle.anchor"],
      },
      pass: ["bundle.version-hash"],
    });

    add({
      id: "login-token-replay-rehashed",
      title: "A genuine supplier signature over something that is not a credential, served as one",
      promise: "§14 — the actor's key also signs wallet-login challenges",
      change: (b) => {
        const i = ctx.farmIndex;
        const t = splitToken(tokenOf(b.credentials[i]));
        const payload = clone(t.payload);
        payload.type = ["SiweSession"];
        b.credentials[i] = wrapToken(b.credentials[i], signJws(t.header, payload, farm.privateKey));
        return `credential[${i}] re-signed by the REAL supplier key with type ["SiweSession"] — genuinely signed, not a credential`;
      },
      rehash: true,
      expect: {
        offline: [`credential[${ctx.farmIndex}].signature`],
        online: [`credential[${ctx.farmIndex}].signature`, "bundle.anchor"],
      },
      pass: ["bundle.version-hash"],
    });
  }

  add({
    id: "high-s-malleability-rehashed",
    title: "The same signature re-encoded with a high `s` (EIP-2 malleability)",
    promise: "§14 — a mathematically valid signature in a non-canonical encoding",
    change: (b) => {
      const i = ctx.farmIndex;
      const t = splitToken(tokenOf(b.credentials[i]));
      const raw = b64uDecode(t.encSignature);
      const N = secp256k1.CURVE.n;
      const s = BigInt(`0x${Buffer.from(raw.subarray(32, 64)).toString("hex")}`);
      const flipped = Buffer.alloc(65);
      raw.copy(flipped);
      Buffer.from((N - s).toString(16).padStart(64, "0"), "hex").copy(flipped, 32);
      flipped[64] = raw[64] === 0 ? 1 : 0;
      b.credentials[i] = wrapToken(b.credentials[i], `${t.encHeader}.${t.encPayload}.${b64uEncode(flipped)}`);
      return `credential[${i}] signature s → n−s with the recovery bit flipped; recovers to the same address, non-canonical under EIP-2`;
    },
    rehash: true,
    expect: {
      offline: [`credential[${ctx.farmIndex}].signature`],
      online: [`credential[${ctx.farmIndex}].signature`, "bundle.anchor"],
    },
    pass: ["bundle.version-hash"],
  });

  /* ── C. Probes: semantically wrong, but signed by a genuinely AUTHORIZED
   *      actor with its real key. Nothing here is a corruption — every byte is
   *      one an entitled party could have produced. These are where a verifier
   *      is most likely to be silent, and silence here is the finding. ────── */

  if (farm) {
    add({
      id: "cross-product-transplant-rehashed",
      title: "An authorized supplier's credential naming a DIFFERENT product",
      promise: "probe — is the credential subject bound to the passport's product?",
      change: (b) => {
        const i = ctx.farmIndex;
        const t = splitToken(tokenOf(b.credentials[i]));
        const payload = clone(t.payload);
        const was = payload.credentialSubject.id;
        payload.credentialSubject.id = ctx.otherProductDid;
        b.credentials[i] = wrapToken(b.credentials[i], signJws(t.header, payload, farm.privateKey));
        return `credential[${i}].credentialSubject.id ${was} → ${ctx.otherProductDid}, re-signed by the REAL, AUTHORIZED supplier key`;
      },
      rehash: true,
      /* PROBE, RESOLVED. As written (2026-08-06 era) this expected the offline
       * pass to report NOTHING — the probe text asked whether the verifier
       * binds a credential's subject to the passport's product, and the honest
       * answer then was no. The 2026-08-24 run against the V2 bundle DIVERGED:
       * the verifier now fails `subject-binding` offline. The gap the probe
       * hunted is closed, and the expectation below records the hardened
       * behaviour — the divergence itself is the before/after evidence. */
      expect: {
        offline: [`credential[${ctx.farmIndex}].subject-binding`],
        online: [`credential[${ctx.farmIndex}].subject-binding`, "bundle.anchor"],
      },
    });

    add({
      id: "expired-credential-rehashed",
      title: "An authorized supplier's credential whose validity window closed in 2020",
      promise: "probe — §10 „Validitätsintervalle — 'war gültig' vs. 'ist gültig'\"",
      change: (b) => {
        const i = ctx.farmIndex;
        const t = splitToken(tokenOf(b.credentials[i]));
        const payload = clone(t.payload);
        const was = `${payload.validFrom} … ${payload.validUntil}`;
        payload.validFrom = "2019-01-01T00:00:00.000Z";
        payload.validUntil = "2020-01-01T00:00:00.000Z";
        b.credentials[i] = wrapToken(b.credentials[i], signJws(t.header, payload, farm.privateKey));
        return `credential[${i}] validity ${was} → 2019-01-01 … 2020-01-01 (long expired), re-signed by the REAL, AUTHORIZED supplier key`;
      },
      rehash: true,
      /* PROBE, RESOLVED — same story as subject-binding above: the 2026-08-06
       * catalogue asked whether validFrom/validUntil are evaluated at all; the
       * 2026-08-25 run showed the verifier now fails `validity` offline. */
      expect: {
        offline: [`credential[${ctx.farmIndex}].validity`],
        online: [`credential[${ctx.farmIndex}].validity`, "bundle.anchor"],
      },
    });
  }

  /*
   * `snapshot.previousVersionHash` (the version hash chain, 2026-08) and the
   * export's `anchorTxHash` (the verifier's fast-path hint) both postdate the
   * 2026-08-06 evidence run — so until these mutations, neither had ever been
   * attacked. Evidence for "the new fields are tamper-evident (or deliberately
   * untrusted)" did not exist; these three produce it.
   */

  add({
    id: "hash-chain-forge",
    title: "The snapshot claims a fabricated version history (previousVersionHash forged)",
    promise: "§16 — the version hash chain is INSIDE the snapshot, so history claims are covered bytes",
    change: (b) => {
      const was = b.snapshot.previousVersionHash ?? null;
      b.snapshot.previousVersionHash = "f".repeat(64);
      return `snapshot.previousVersionHash ${was === null ? "null (a v1 has no ancestor)" : was} → f…f — the version now claims to supersede a version that never existed`;
    },
    rehash: false,
    expect: { offline: ["bundle.version-hash"], online: ["bundle.version-hash", "bundle.anchor"] },
  });

  add({
    id: "hash-chain-forge-rehashed",
    title: "The same fabricated history, and the platform recomputes its own digest",
    promise: "§15/§16 — a matching version-hash proves nothing against the platform; the chain outranks the chain-of-hashes",
    change: (b) => {
      b.snapshot.previousVersionHash = "f".repeat(64);
      return "snapshot.previousVersionHash null → f…f, then `hash` recomputed by the mutator";
    },
    rehash: true,
    expect: { offline: [], online: ["bundle.anchor"] },
    pass: ["bundle.version-hash", "bundle.merkle-root"],
  });

  add({
    id: "anchor-hint-redirect",
    title: "The bundle's anchorTxHash repointed at a REAL anchor — of a different product",
    promise: "probe — the hint \"costs nothing in trust\" (verify-passport.mjs, verifyAnchor fast path)",
    change: (b) => {
      const was = b.anchorTxHash ?? null;
      b.anchorTxHash = ctx.otherAnchorTx;
      return `anchorTxHash ${was} → ${ctx.otherAnchorTx} — a transaction that genuinely exists and genuinely anchors, but a different productId`;
    },
    // Nothing to rehash, and that is the finding: the hint lives OUTSIDE every
    // signed and hashed surface, which is only safe if the verifier re-derives
    // everything from the receipt — productId, version, registry, topic, root.
    rehash: false,
    expect: { offline: [], online: ["bundle.anchor"] },
    pass: ["bundle.version-hash", "bundle.merkle-root"],
    probe:
      "If the online pass reports no anchor failure, the verifier trusted the hint instead of re-deriving — " +
      "a hostile export could then point every forged bundle at any real anchor it likes.",
  });

  return list;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Running the verifier
 * ═══════════════════════════════════════════════════════════════════════════ */

function runVerifier(bundlePath, { rpc, anchorTx, offline, json }) {
  const args = [VERIFIER, bundlePath];
  if (offline) args.push("--offline");
  else if (rpc) args.push("--rpc", rpc);
  if (anchorTx && !offline) args.push("--anchor-tx", anchorTx);
  if (json) args.push("--json");
  const r = spawnSync(process.execPath, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env: { ...process.env, RPC_URL: offline ? "" : rpc ?? "" } });
  return { exitCode: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function pass(bundlePath, opts) {
  const human = runVerifier(bundlePath, { ...opts, json: false });
  const structured = runVerifier(bundlePath, { ...opts, json: true });
  let parsed = null;
  try {
    parsed = JSON.parse(structured.stdout);
  } catch {
    /* left null — the human transcript is still archived */
  }
  const checks = parsed?.checks ?? [];
  return {
    exitCode: human.exitCode,
    verdict: parsed?.verdict ?? null,
    counts: parsed?.counts ?? null,
    failed: checks.filter((c) => c.status === "FAIL").map((c) => ({ check: `${c.scope}.${c.name}`, detail: c.detail })),
    passedNames: checks.filter((c) => c.status === "PASS").map((c) => `${c.scope}.${c.name}`),
    transcript: human.stdout + (human.stderr ? `\n[stderr]\n${human.stderr}` : ""),
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CLI
 * ═══════════════════════════════════════════════════════════════════════════ */

function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(
      "node scripts/tamper-passport.mjs <bundle.json> --rpc <url> [--anchor-tx 0x…]\n" +
        "                                 [--out-dir <dir>] [--only id,id] [--offline-only]\n",
    );
    process.exit(argv.length === 0 ? 2 : 0);
  }

  let bundlePath = null;
  let rpc = process.env.RPC_URL || process.env.AMOY_RPC_URL || null;
  let anchorTx = null;
  let outDir = join(HERE, "out", "tamper");
  let only = null;
  let offlineOnly = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--rpc") rpc = argv[++i];
    else if (a === "--anchor-tx") anchorTx = argv[++i];
    else if (a === "--out-dir") outDir = resolve(argv[++i]);
    else if (a === "--only") only = new Set(argv[++i].split(","));
    else if (a === "--offline-only") offlineOnly = true;
    else if (!a.startsWith("--")) bundlePath = resolve(a);
    else {
      process.stderr.write(`unknown option ${a}\n`);
      process.exit(2);
    }
  }
  if (!bundlePath || !existsSync(bundlePath)) {
    process.stderr.write("a readable bundle path is required\n");
    process.exit(2);
  }
  mkdirSync(outDir, { recursive: true });

  const original = JSON.parse(readFileSync(bundlePath, "utf8"));
  const actors = existsSync(ACTORS_FILE) ? JSON.parse(readFileSync(ACTORS_FILE, "utf8")).actors : null;
  if (!actors) {
    process.stderr.write(
      "! .design-a-actors.json is absent — the four mutations that need a REAL, AUTHORIZED\n" +
        "  supplier key (cross-protocol replay, login-token replay, cross-product transplant,\n" +
        "  expired credential) are omitted.\n\n",
    );
  }

  // Two keys this script mints for itself: one plays the platform forging a
  // supplier's credential, one plays a third party that is on chain but was
  // never authorized for this product. Neither has ever held authority.
  const platformKey = Buffer.from(secp256k1.utils.randomPrivateKey()).toString("hex");
  const rogueKey = Buffer.from(secp256k1.utils.randomPrivateKey()).toString("hex");

  const ctx = {
    actors,
    platformKey,
    platformAddress: addressOf(Buffer.from(platformKey, "hex")),
    rogueKey,
    rogueAddress: addressOf(Buffer.from(rogueKey, "hex")),
    farmIndex: actors ? indexByIssuer(original, actors.farm.address) : 1,
    otherProductDid: "did:web:trustdpp.co:prod_730b0c113be89275",
    // A GENUINE Anchored transaction — of a DIFFERENT product (the 2026-08-24
    // per-issuer comparison run, dpp_60faf481d57ca83d). The anchor-hint
    // mutation needs a hint that is real on chain and wrong for this bundle:
    // a garbage hash would test "does the tx exist", this tests the part that
    // matters — a real log whose productId is not ours must still be refused.
    otherAnchorTx: "0x85581b9e1b27bbf01ffe81a94812a5ea1ce4b013ba057cb60095b76019e981e1",
  };
  if (ctx.farmIndex < 0) ctx.farmIndex = 1;

  const catalogue = buildCatalogue(ctx).filter((m) => !only || only.has(m.id));

  const started = new Date().toISOString();
  const gitCommit = spawnSync("git", ["-C", HERE, "rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();

  const results = [];
  const transcripts = [];

  // Run 0 — the untouched export. Without it every ✗ below is unanchored: a
  // reader has to see the SAME tool say ✓ over the SAME bytes first.
  const baselineOffline = pass(bundlePath, { rpc, anchorTx, offline: true });
  const baselineOnline = offlineOnly ? null : pass(bundlePath, { rpc, anchorTx, offline: false });
  transcripts.push(section("BASELINE — the untouched export, verbatim", { offline: baselineOffline, online: baselineOnline }));

  for (const m of catalogue) {
    const mutated = clone(original);
    const change = m.change(mutated);
    if (m.rehash) mutated.hash = versionHash(mutated);
    const path = join(outDir, `mutated-${m.id}.json`);
    writeFileSync(path, JSON.stringify(mutated, null, 2));

    const off = pass(path, { rpc, anchorTx, offline: true });
    const on = offlineOnly ? null : pass(path, { rpc, anchorTx, offline: false });

    const verdicts = {};
    for (const [phase, r, want] of [
      ["offline", off, m.expect.offline],
      ["online", on, m.expect.online],
    ]) {
      if (!r) continue;
      const got = new Set(r.failed.map((f) => f.check));
      const missing = want.filter((w) => !got.has(w));
      const extra = [...got].filter((g) => !want.includes(g));
      verdicts[phase] = {
        expectedFailures: want,
        observedFailures: [...got],
        missing,
        unexpected: extra,
        ok: missing.length === 0 && extra.length === 0,
      };
    }
    // Contrast assertions: checks that must STILL pass. Evaluated against the
    // online pass when there is one — several of them (issuer-resolution,
    // authorization) are chain checks that SKIP under `--offline`, and a SKIP is
    // not a pass.
    const contrastPhase = on ? "online" : "offline";
    const contrast = (m.pass ?? []).map((name) => ({
      check: name,
      phase: contrastPhase,
      stillPasses: (on ?? off).passedNames.includes(name),
    }));

    results.push({
      id: m.id,
      title: m.title,
      promise: m.promise,
      probe: m.probe ?? null,
      rehashed: Boolean(m.rehash),
      change,
      bundle: path,
      offline: { exitCode: off.exitCode, verdict: off.verdict, counts: off.counts, failed: off.failed },
      online: on ? { exitCode: on.exitCode, verdict: on.verdict, counts: on.counts, failed: on.failed } : null,
      verdicts,
      contrast,
      asCatalogued: Object.values(verdicts).every((v) => v.ok) && contrast.every((c) => c.stillPasses),
    });
    transcripts.push(section(`MUTATION ${m.id} — ${m.title}`, { offline: off, online: on }, { change, promise: m.promise }));
  }

  const report = {
    tool: "tamper-passport.mjs",
    formatVersion: 1,
    startedAt: started,
    finishedAt: new Date().toISOString(),
    gitCommit,
    node: process.version,
    source: { bundle: bundlePath, passportId: original.passportId, version: original.version, productDid: original.productDid, versionHash: original.hash },
    chain: { chainId: 80002, anchorTx },
    keysMintedForThisRun: { platform: ctx.platformAddress, unauthorizedThirdParty: ctx.rogueAddress },
    baseline: {
      offline: { exitCode: baselineOffline.exitCode, verdict: baselineOffline.verdict, counts: baselineOffline.counts },
      online: baselineOnline ? { exitCode: baselineOnline.exitCode, verdict: baselineOnline.verdict, counts: baselineOnline.counts } : null,
    },
    mutations: results,
  };
  writeFileSync(join(outDir, "tamper-report.json"), JSON.stringify(report, null, 2));
  writeFileSync(join(outDir, "tamper-transcript.txt"), transcripts.join("\n"));

  // ── the table ──
  const w = (s, n) => String(s).padEnd(n).slice(0, n);
  process.stdout.write(`\n  ${w("mutation", 38)}${w("offline", 26)}${w("online", 34)}status\n`);
  process.stdout.write(`  ${"─".repeat(104)}\n`);
  for (const r of results) {
    const offCell = `${r.offline.exitCode} ${r.offline.failed.length ? r.offline.failed.map((f) => short(f.check)).join(",") : "— not caught"}`;
    const onCell = r.online ? `${r.online.exitCode} ${r.online.failed.length ? r.online.failed.map((f) => short(f.check)).join(",") : "— NOT CAUGHT"}` : "(skipped)";
    process.stdout.write(`  ${w(r.id, 38)}${w(offCell, 26)}${w(onCell, 34)}${r.asCatalogued ? "as catalogued" : "DIVERGES"}\n`);
  }
  const diverged = results.filter((r) => !r.asCatalogued);
  const uncaught = results.filter((r) => r.online && r.online.failed.length === 0);
  process.stdout.write(`\n  ${results.length} mutations · ${diverged.length} diverging · ${uncaught.length} not caught at all\n`);
  process.stdout.write(`  report      ${join(outDir, "tamper-report.json")}\n  transcript  ${join(outDir, "tamper-transcript.txt")}\n\n`);
  process.exit(diverged.length === 0 ? 0 : 1);
}

const short = (check) => check.replace(/^credential\[(\d+)\]\./, "c$1.").replace(/^bundle\./, "");

function section(title, runs, extra = {}) {
  const bar = "═".repeat(78);
  let s = `\n${bar}\n${title}\n${bar}\n`;
  if (extra.promise) s += `promise : ${extra.promise}\n`;
  if (extra.change) s += `changed : ${extra.change}\n`;
  for (const [phase, r] of Object.entries(runs)) {
    if (!r) continue;
    s += `\n─── ${phase} pass — verify-passport.mjs, verbatim (exit ${r.exitCode}) ${"─".repeat(20)}\n\n${r.transcript}\n`;
  }
  return s;
}

main();
