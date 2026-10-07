// Is a plain ES256K (64-byte, no recovery byte) JWS self-certifying against an address-form did:ethr?
import { createJWS, verifyJWS, ES256KSigner } from "did-jwt";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { readFileSync } from "node:fs";
const hex = (u) => Buffer.from(u).toString("hex");
const results = [];
for (let i = 0; i < 20; i++) {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, false);
  const addr = "0x" + hex(keccak_256(pub.slice(1))).slice(-40);
  const did = `did:ethr:0x13882:${addr}`;
  // only what an address-form did:ethr document offers: no public key, just the account
  const vm = { id: `${did}#controller`, type: "EcdsaSecp256k1RecoveryMethod2020", controller: did, blockchainAccountId: `eip155:80002:${addr}` };
  const jws = await createJWS({ iss: did, n: i }, ES256KSigner(priv, false), { alg: "ES256K", typ: "vc+jwt" });
  const header = JSON.parse(Buffer.from(jws.split(".")[0], "base64url"));
  const sigLen = Buffer.from(jws.split(".")[2], "base64url").length;
  let ok = false, err = null; try { ok = !!(await verifyJWS(jws, [vm])); } catch (e) { err = e.message; }
  // tampered payload must fail
  const parts = jws.split("."); const bad = [parts[0], Buffer.from(JSON.stringify({ iss: did, n: i + 1 })).toString("base64url"), parts[2]].join(".");
  let badOk = false; try { badOk = !!(await verifyJWS(bad, [vm])); } catch { badOk = false; }
  // wrong address must fail
  const other = { ...vm, blockchainAccountId: `eip155:80002:0x${"1".repeat(40)}` };
  let wrongOk = false; try { wrongOk = !!(await verifyJWS(jws, [other])); } catch { wrongOk = false; }
  results.push({ alg: header.alg, sigBytes: sigLen, acceptedAgainstAddressOnly: ok, tamperedAccepted: badOk, wrongAddressAccepted: wrongOk, err });
}
const summary = { didJwt: JSON.parse(readFileSync("node_modules/did-jwt/package.json")).version, node: process.version, runs: results.length,
  allAccepted: results.every(r => r.acceptedAgainstAddressOnly), anyTamperedAccepted: results.some(r => r.tamperedAccepted), anyWrongAddressAccepted: results.some(r => r.wrongAddressAccepted), sample: results[0] };
console.log(JSON.stringify(summary, null, 2));
