Re-check 2026-10-06. Live registry: https://api-vera.susi.spherity.io/credential-registry/ (8 credentials, file 2026-10-06_spherity-live-credentials.json).
EECC POST https://ssi.eecc.de/api/verifier/ with the ConsumerInformation credential -> verified:false, 'Maximum deep iterations exceeded (3).' at rdf-canonize RDFC10.hashNDegreeQuads.
Local check (jsonld + rdf-canonize from backend_dpp/node_modules, Ed25519 via node:crypto): ConsumerInformation fails at maxDeepIterations=3, verifies (sigValid=true) with no limit; all other credentials verify at 3.
Corrects the 27 July explanation (term-scoped type redefinition), which was wrong: ProductInformation also redefines type and passes.
