/// <reference types="vite/client" />

/**
 * ─── Design A's build-time inputs ─────────────────────────────────────────────
 * Declared next to the code that reads them (`web3auth.ts`) rather than in the
 * shared `vite-env.d.ts`, because they are wallet-boundary configuration and
 * nothing outside this directory may read them. Vite's own `ImportMetaEnv` has
 * an index signature, so without this every one of these would type as `any` and
 * a typo would only surface as an empty client id at runtime.
 */
interface ImportMetaEnv {
  /** Web3Auth project id from the dashboard. Public by design. */
  readonly VITE_WEB3AUTH_CLIENT_ID: string;
  /** `sapphire_mainnet` | `sapphire_devnet` — separate networks, separate keys. */
  readonly VITE_WEB3AUTH_NETWORK: string;
  /** Decimal chain id. Must equal the backend's `CHAIN_ID`. */
  readonly VITE_CHAIN_ID: string;
  /** JSON-RPC endpoint the wallet provider talks to. Must be in `connect-src`. */
  readonly VITE_RPC_URL: string;
  /** Display-only chain metadata for the wallet UI. */
  readonly VITE_CHAIN_NAME?: string;
  readonly VITE_CHAIN_TICKER?: string;
  readonly VITE_CHAIN_TICKER_NAME?: string;
  readonly VITE_BLOCK_EXPLORER_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
