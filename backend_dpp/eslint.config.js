import tseslint from "typescript-eslint";

/**
 * Every library that talks to a blockchain or produces JOSE/JWS credentials.
 * Design A confines ALL of them to `domain/trust/designA/` — `ethers` in
 * particular must have exactly ONE importer (`designA/chainGateway.ts`), because
 * the gateway is what makes the whole provider testable against a fake and what
 * keeps a future chain swap from touching business logic.
 *
 * NOT listed: `did-context`, which is a static JSON-LD context package shared by
 * both designs and carries no chain or signing code.
 */
const CHAIN_LIBS = [
  "ethers", "ethers/*",
  "@web3auth/*", "@tkey/*", "@toruslabs/*",
  "jose", "did-jwt", "did-jwt-vc", "did-resolver", "ethr-did-resolver", "ethr-did",
  "web3", "viem", "@ethersproject/*",
  // The CURVE and the hashes that sign and recover. Omitting these was the hole:
  // the wall stopped `ethers` while leaving the primitive that actually touches
  // a private key importable from anywhere, which is the half that matters for
  // "non-custody is auditable by reading one directory".
  "@noble/*",
];

/**
 * The three files outside `designA/` that may legitimately import `@noble/*`.
 *
 * They are an EXPLICIT, REVIEWABLE exception rather than an absence of a rule —
 * which is the whole point. A seam does not rot by decision; it rots by the next
 * file that "just needs one thing" and nothing objecting.
 *
 *  • `integrity/keccak.ts` — a pure algorithm on the same
 *    shelf as `integrity/hash.ts` (sha256). They exist only because Design A
 *    needs them today, but they compute over bytes and know nothing about
 *    chains, keys or designs. Deleting Design A would leave them harmless.
 *  • `services/identity.ts` — SIWE/EIP-4361 login: recovers an address from a
 *    signature. It is Design A's front door and arguably belongs inside
 *    `designA/`, but the auth router cannot import there (the trust wall would
 *    block it), and AUTHENTICATION is not the trust seam's job. Listing it here
 *    keeps the compromise visible instead of silent.
 *
 * These files still get the full trust wall — see the block that re-applies it.
 */
const NOBLE_ALLOWED = [
  "src/domain/integrity/keccak.ts",
  "src/services/identity.ts",
];

/** Shared so the wall and its one exception cannot drift apart. */
const TRUST_WALL_GROUP = ["**/trust/*", "**/trust/*/**", "!**/trust/index.js", "!**/trust/types.js"];

const TRUST_WALL_MESSAGE =
  "Trust wall: import from domain/trust/index.js only (or trust/types.js for the " +
  "seam's vocabulary). Design internals (sign, did, statusList, designA/*, …) must " +
  "stay swappable — route new needs through the TrustProvider interface.";

const CHAIN_LIB_MESSAGE =
  "Chain containment: EVM and JOSE libraries live ONLY in domain/trust/designA/ " +
  "(ethers exclusively in designA/chainGateway.ts). Reaching for one here would " +
  "smear chain code past the gateway and make Design A undeletable — go through " +
  "the ChainGateway interface, or the TrustProvider seam.";

/**
 * Focused, type-aware lint. Not the full recommended set (which would drown the
 * codebase in unrelated style findings) — just the promise-misuse rules that catch
 * the P0-2 bug class: a raw `async` function passed where Express expects a
 * void-returning handler (Express 4 swallows the rejection → unhandledRejection →
 * the process exits). Every async route handler must go through `asyncHandler`.
 */
export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "src/dpp-core/**"] },
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "@typescript-eslint": tseslint.plugin },
    rules: {
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
  // ── The trust wall (see ARCHITECTURE.md — "The trust wall") ──────────────
  // Nothing outside domain/trust/ may import trust INTERNALS — the only legal
  // doorway is domain/trust/index.js. This is what keeps Design A and Design B
  // swappable and individually deletable: a bypass is a BUILD ERROR, not a
  // code-review hope. (Test files are exempt: they may pin internals.)
  //
  // ⚠ The two `no-restricted-imports` blocks below are scoped to DISJOINT file
  // sets on purpose. In ESLint flat config a later block that sets the SAME rule
  // name for an overlapping file REPLACES the earlier one — so if both matched
  // e.g. src/routes/public.ts, the second would silently switch the trust wall
  // OFF while still looking like it added protection. Keep them disjoint.
  {
    files: ["src/**/*.ts"],
    ignores: ["src/domain/trust/**", "src/**/*.test.ts", ...NOBLE_ALLOWED],
    rules: {
      "no-restricted-imports": ["error", {
        patterns: [{
          // `**/trust/*` alone does NOT match `**/trust/designA/index.js` —
          // a glob `*` never crosses a `/`. Without the second pattern, adding
          // the designA/ subfolder would have opened a hole straight through
          // the wall on its first day.
          group: TRUST_WALL_GROUP,
          message: TRUST_WALL_MESSAGE,
        }, {
          group: CHAIN_LIBS,
          message: CHAIN_LIB_MESSAGE,
        }],
      }],
    },
  },
  // ── The `@noble` exception, and ONLY that exception ─────────────────────────
  // These three files keep the full trust wall; they lose exactly one thing, the
  // chain-library restriction. A separate block is required rather than adding
  // them to the `ignores` above, because doing that would have dropped the trust
  // wall for them too — silently, and in the three files most likely to reach
  // for a trust internal. Disjoint file sets, so neither block replaces the other.
  {
    files: NOBLE_ALLOWED,
    ignores: ["src/**/*.test.ts"],
    rules: {
      "no-restricted-imports": ["error", {
        patterns: [{ group: TRUST_WALL_GROUP, message: TRUST_WALL_MESSAGE }],
      }],
    },
  },
  // ── Chain containment, inside the trust layer ───────────────────────────
  // Design B files may import trust internals (they ARE the internals), but no
  // file in the trust layer outside designA/ may reach for an EVM/JOSE library.
  // The gateway pattern only holds if `ethers` has exactly one importer.
  {
    files: ["src/domain/trust/**/*.ts"],
    ignores: ["src/domain/trust/designA/**", "src/**/*.test.ts"],
    rules: {
      "no-restricted-imports": ["error", {
        patterns: [{ group: CHAIN_LIBS, message: CHAIN_LIB_MESSAGE }],
      }],
    },
  },
  // ── One design decision, one place ──────────────────────────────────────
  // `config.trustMode` is read EXACTLY ONCE, by the boot selector in
  // domain/trust/index.ts. Every other read would be a design branch outside
  // the seam — the precise thing the seam exists to prevent. This is a property
  // access, not an import, so no-restricted-imports cannot see it.
  //
  // config.ts is exempt because it DEFINES the value (and resolves the A-mode
  // config block from it); tests are exempt because they legitimately assert on
  // both modes.
  {
    files: ["src/**/*.ts"],
    ignores: [
      "src/domain/trust/index.ts",
      "src/config.ts",
      "src/**/*.test.ts",
      // designA/ IS the design — reading its own configuration there is the
      // intended shape, not a leak.
      "src/domain/trust/designA/**",
      // The documented exception, same reasoning as NOBLE_ALLOWED: Design A's
      // SIWE front door needs the chain binding, and the auth router cannot
      // reach into designA/ to get it.
      "src/services/identity.ts",
    ],
    rules: {
      "no-restricted-syntax": ["error", {
        selector: "MemberExpression[object.name='config'][property.name='trustMode']",
        message: "Design branch outside the seam: config.trustMode is read once, in domain/trust/index.ts. Everything design-specific belongs behind the TrustProvider interface — if you need mode here, expose it as data (trust.mode) or add a provider method.",
      }, {
        // The SECOND way Design A escapes the seam, and the one that was open.
        // `config.designA` carries the chain id, the registry addresses and the
        // relayer key: any file reading it is Design A code, wherever it happens
        // to sit. Restricting only `trustMode` stopped the design BRANCH while
        // leaving the design's CONFIGURATION readable everywhere — which is how
        // 1,200 lines of Design A ended up outside domain/trust/.
        selector: "MemberExpression[object.name='config'][property.name='designA']",
        message: "Design A configuration outside the seam: config.designA belongs to domain/trust/designA/. A file that reads it is Design A code and should live there — otherwise deleting the design stops being a folder removal. If this file genuinely must read it, add it to the documented exception list in this config so the compromise is visible.",
      }],
    },
  },
);
