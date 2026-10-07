import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // Was "off". Together with noUnusedLocals:false in tsconfig, NOTHING in the
      // toolchain flagged unused code — which is how three whole components
      // (653 lines) sat unreferenced in the tree undetected. `args: "none"`
      // keeps deliberately-unused callback params legal.
      "@typescript-eslint/no-unused-vars": ["error", { args: "none", varsIgnorePattern: "^_" }],
      // Style-tier: several `any`s sit against genuinely untyped libs (react-globe.gl,
      // recharts tooltips). Warned, not blocking; the catch(e:any) subset is fixed in P3-6.
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
  // ── The wallet wall (R6) — the client-side half of the trust wall ─────────
  //
  // Design A moves key handling INTO the browser: Web3Auth login, tKey share
  // reconstruction, and ES256K-R signing all happen client-side. Two rules keep
  // that from leaking across the app, and both are build errors:
  //
  //  1. No wallet/EVM/JOSE library may be imported outside src/lib/wallet/.
  //     Non-custodial key handling has to be auditable by reading ONE directory
  //     — if it is scattered, "the platform never sees the key" stops being
  //     checkable by inspection.
  //
  //  2. src/lib/wallet/ may only be reached by DYNAMIC `import()`. This rule
  //     bans the STATIC form specifically: ESLint's no-restricted-imports sees
  //     import declarations but not `import()` expressions, so forbidding the
  //     path here permits exactly the lazy form and forbids the eager one.
  //     The Web3Auth SDK is heavy — it lands in a ~1.29 MB lazy chunk, against
  //     an entry chunk of ~309 KB and a 512 KB CI budget. A static import would
  //     move that 1.29 MB into the entry, breaching CI and putting wallet code on
  //     the consumer passport page, the highest-traffic lowest-trust surface,
  //     which has no business carrying it.
  //
  // `allowTypeImports` keeps `import type { WalletSession }` legal: types are
  // erased at build time, so they cost no bytes and leak no code.
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/lib/wallet/**"],
    // Declared explicitly: flat-config plugin namespaces do not leak between
    // config objects, and this block extends nothing. Without it the rule name
    // below is simply unknown and the wall silently does nothing.
    plugins: { "@typescript-eslint": tseslint.plugin },
    rules: {
      "@typescript-eslint/no-restricted-imports": ["error", {
        patterns: [{
          group: [
            "ethers", "ethers/*", "@ethersproject/*",
            "@web3auth/*", "@tkey/*", "@toruslabs/*",
            "jose", "did-jwt", "did-jwt-vc", "did-resolver", "ethr-did-resolver", "ethr-did",
            "web3", "viem",
            // Added with the ES256K-R signer. `@noble/curves` is what actually
            // touches the private key (`personal_sign` cannot produce ES256K-R —
            // it prefixes EIP-191 — so the digest is signed with the key
            // itself), and `@noble/hashes` is the SHA-256/keccak beside it.
            // Without this line the wall enforces "no SDK outside the wallet
            // directory" while leaving the CURVE free to be imported anywhere,
            // which is the half that matters for "one directory to audit".
            // WebCrypto (`crypto.subtle`) is a browser global, not an import,
            // and stays available to the rest of the app.
            "@noble/*",
          ],
          message: "Wallet wall: EVM/JOSE/Web3Auth libraries belong in src/lib/wallet/ only, reached via dynamic import(). Importing one here puts key-handling code in the entry bundle and scatters the non-custody surface.",
          allowTypeImports: true,
        }, {
          group: ["**/lib/wallet", "**/lib/wallet/*", "**/lib/wallet/*/**"],
          message: "Wallet wall: load src/lib/wallet/ with a dynamic `await import(...)`, never a static import — a static one pulls the Web3Auth SDK into the entry chunk (512 KB CI budget). `import type` is allowed.",
          allowTypeImports: true,
        }],
      }],
    },
  },
);
