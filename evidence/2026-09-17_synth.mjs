// Synthetic scaling bundles: n issuers, one ES256K-R credential each, fresh keys, real snapshot,
// version hash recomputed the way the platform computes it. Signing convention copied from
// backend_dpp/scripts/tamper-passport.mjs (r||s||recovery, low-s, SHA-256 over the signing input).
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const [,, realPath, nStr, outPath] = process.argv; const n = Number(nStr);
const real = JSON.parse(readFileSync(realPath, "utf8"));
const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256 = (s) => createHash("sha256").update(s).digest();
const stable = (v) => v === null || typeof v !== "object" ? JSON.stringify(v) : Array.isArray(v) ? `[${v.map(stable).join(",")}]` : `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${stable(v[k])}`).join(",")}}`;
const addressOf = (priv) => `0x${Buffer.from(keccak_256(secp256k1.getPublicKey(priv, false).slice(1))).toString("hex").slice(-40)}`;
const sign = (header, payload, priv) => { const h = b64u(Buffer.from(JSON.stringify(header))), p = b64u(Buffer.from(JSON.stringify(payload))); const sig = secp256k1.sign(sha256(`${h}.${p}`), priv); const raw = new Uint8Array(65); raw.set(sig.toCompactRawBytes(), 0); raw[64] = sig.recovery; return `${h}.${p}.${b64u(raw)}`; };
const dec = (s) => JSON.parse(Buffer.from(s, "base64url").toString());
const templates = real.credentials.map(c => { const t = String(c.id).slice(c.id.indexOf(",") + 1).split("."); return { header: dec(t[0]), payload: dec(t[1]), wrapper: { ...c } }; });
const creds = [];
for (let i = 0; i < n; i++) {
  const t = templates[i % templates.length]; const priv = secp256k1.utils.randomPrivateKey(); const did = `did:ethr:0x13882:${addressOf(priv)}`;
  const payload = JSON.parse(JSON.stringify(t.payload)); payload.issuer = did;
  const header = { ...t.header, kid: `${did}#controller` };
  creds.push({ ...t.wrapper, id: `data:application/vc+jwt,${sign(header, payload, priv)}` });
}
const bundle = { ...real, credentials: creds }; delete bundle.anchorTxHash;
bundle.hash = sha256(stable({ snapshot: bundle.snapshot, credentials: bundle.credentials, version: bundle.version })).toString("hex");
bundle.synthetic = { note: "SYNTHETIC scaling bundle: fresh keys, one credential per issuer, not anchored, issuers not authorized on chain; measures the verifier's cost curve only", issuers: n, credentials: n, generatedAt: new Date().toISOString() };
writeFileSync(outPath, JSON.stringify(bundle));
console.log(`wrote ${outPath}: ${n} issuers / ${n} credentials, ${Buffer.byteLength(JSON.stringify(bundle))} bytes`);
