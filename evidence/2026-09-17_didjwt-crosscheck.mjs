// Third-party acceptance check: does DIF did-jwt (unmodified, from npm) accept the
// ES256K-R credentials in a Design A export, and reject a tampered one?
import { verifyJWS } from "did-jwt";
import { readFileSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
const bundlePath = process.argv[2];
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const tokenOf = (c) => String(c.id).slice(c.id.indexOf(",") + 1);
const b64 = (s) => JSON.parse(Buffer.from(s, "base64url").toString());
const vmFor = (issuer) => {
  const addr = issuer.split(":").pop();
  const chain = issuer.split(":")[2];
  return { id: `${issuer}#controller`, type: "EcdsaSecp256k1RecoveryMethod2020", controller: issuer,
           blockchainAccountId: `eip155:${parseInt(chain,16)}:${addr}` };
};
const out = { tool: "did-jwt cross-check", library: { name: "did-jwt", version: JSON.parse(readFileSync("node_modules/did-jwt/package.json")).version, source: "npm registry, unmodified" },
  takenAt: new Date().toISOString(), node: process.version, bundle: { path: bundlePath.split("/").pop(), passportId: bundle.passportId, version: bundle.version, credentials: bundle.credentials.length },
  results: [] };
for (const [i, c] of bundle.credentials.entries()) {
  const jws = tokenOf(c); const [h, p] = jws.split("."); const header = b64(h), payload = b64(p);
  const vm = vmFor(payload.issuer);
  let accepted, err = null;
  try { const r = verifyJWS(jws, [vm]); accepted = r && r.id === vm.id; } catch (e) { accepted = false; err = e.message; }
  // negative control: flip one byte of the payload, keep the signature
  const tampered = h + "." + Buffer.from(JSON.stringify({ ...payload, issuer: payload.issuer.replace(/.$/, (ch) => ch === "0" ? "1" : "0") })).toString("base64url") + "." + jws.split(".")[2];
  let rejected; try { verifyJWS(tampered, [vm]); rejected = false; } catch { rejected = true; }
  out.results.push({ index: i, alg: header.alg, typ: header.typ, issuer: payload.issuer, acceptedByDidJwt: accepted, error: err, tamperedPayloadRejected: rejected });
}
out.summary = { accepted: out.results.filter(r => r.acceptedByDidJwt).length, of: out.results.length, tamperedRejected: out.results.filter(r => r.tamperedPayloadRejected).length };
writeFileSync("2026-09-17_designA-didjwt-crosscheck.json", JSON.stringify(out, null, 2));
console.log(JSON.stringify(out.summary), out.results.map(r => `${r.alg}:${r.acceptedByDidJwt}/${r.tamperedPayloadRejected}${r.error ? " ERR " + r.error : ""}`).join("  "));
