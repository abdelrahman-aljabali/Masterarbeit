import type { WalletCeremonyOptions, WalletPhaseListener } from "./index";
// Type-only: erased at build time, so this stays outside the wallet wall.
import type { CeremonySession, WalletSigner } from "./web3auth";

/**
 * ─── EIP-712: the operator's ceremonies ───────────────────────────────────────
 * The file `index.ts` reserved. Five payloads, one function, and deliberately no
 * encoder: `Approval` and `ChainHeadCheckpoint` (off-chain, zero gas) and
 * `ClaimProduct`, `SetIssuer` and `Anchor` (queued for the relayer, paid in gas)
 * are all built by the server, displayed by `lib/trust/ceremony.ts`, and hashed
 * by the WALLET.
 */

/** Phase sink for callers that pass none — see `web3auth.ts`. */
const NO_PHASES: WalletPhaseListener = () => {};

export interface TypedDataSignature {
  /** `0x` + 65 bytes, `r ‖ s ‖ v` with `v ∈ {27, 28}` — what
   *  `eth_signTypedData_v4` returns and what the server's
   *  `recoverTypedDataSigner` accepts (it takes 27/28 or 0/1). */
  signature: string;
  /** The address the wallet signed as, lower case. */
  signerAddress: string;
}

/**
 * Open the wallet, sign one typed-data payload, tear the session down.
 */
export async function signTypedData(
  payload: unknown,
  expectedAddress: string,
  opts: WalletCeremonyOptions & { session?: CeremonySession } = {},
): Promise<TypedDataSignature> {
  const onPhase = opts.onPhase ?? NO_PHASES;
  const expected = expectedAddress.toLowerCase();
  if (!/^0x[0-9a-fA-F]{40}$/.test(expected)) {
    throw new Error(`Refusing to sign: "${expectedAddress}" is not an address this ceremony can check against.`);
  }

  const run = async (signer: WalletSigner) => {
    assertSignerAddress(signer, expected);
    const signature = await signer.signTypedData(payload);
    return { signature, signerAddress: signer.address.toLowerCase() };
  };

  // Inside a held ceremony session the wallet is already open — no phases, no
  // second connect, same address check.
  if (opts.session) return run(opts.session.signer);

  onPhase("loading-wallet");
  const { withWallet } = await import("./web3auth");
  return withWallet(run, onPhase);
}

/** The wallet answers for a DIFFERENT org than the one signing — refuse before
 *  any signature exists rather than after the server rejects it. */
function assertSignerAddress(signer: WalletSigner, expected: string): void {
  if (signer.address.toLowerCase() !== expected) {
    throw new Error(
      `This wallet controls ${signer.address}, but your organization signs as ${expected}. ` +
        "Sign in with the account whose wallet is bound to your organization.",
    );
  }
}

/**
 * Sign several payloads in ONE wallet session.
 */
export async function signTypedDataBatch<K extends string>(
  items: ReadonlyArray<{ key: K; payload: unknown }>,
  expectedAddress: string,
  opts: WalletCeremonyOptions & { onEach?: (done: number, total: number) => void; session?: CeremonySession } = {},
): Promise<{ signatures: Array<{ key: K; signature: string }>; signerAddress: string }> {
  const onPhase = opts.onPhase ?? NO_PHASES;
  const expected = expectedAddress.toLowerCase();
  if (!items.length) throw new Error("Refusing to open a wallet with nothing to sign.");
  if (!/^0x[0-9a-fA-F]{40}$/.test(expected)) {
    throw new Error(`Refusing to sign: "${expectedAddress}" is not an address this ceremony can check against.`);
  }

  const run = async (signer: WalletSigner) => {
    assertSignerAddress(signer, expected);
    const signatures: Array<{ key: K; signature: string }> = [];
    for (const item of items) {
      signatures.push({ key: item.key, signature: await signer.signTypedData(item.payload) });
      opts.onEach?.(signatures.length, items.length);
    }
    return { signatures, signerAddress: signer.address.toLowerCase() };
  };

  if (opts.session) return run(opts.session.signer);

  onPhase("loading-wallet");
  const { withWallet } = await import("./web3auth");
  return withWallet(run, onPhase);
}
