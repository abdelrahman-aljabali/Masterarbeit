#!/usr/bin/env bash
# Stamp deploy transaction hashes and the real deploy block into deployments/<name>.json.
#
# Foundry scripts cannot know their own transaction hashes or the block they land in — the broadcast
# happens after `run()` returns — so Deploy.s.sol writes the addresses and leaves `*Tx` empty and
# `blockNumber` at the simulation head. This merges the real values in from the broadcast artifact.
#
#   ./script/finalize-deployment.sh <chainId> <name>
#   ./script/finalize-deployment.sh 80002 amoy
set -euo pipefail

CHAIN_ID="${1:?usage: finalize-deployment.sh <chainId> <name>}"
NAME="${2:?usage: finalize-deployment.sh <chainId> <name>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json"
OUT="$ROOT/deployments/$NAME.json"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[ -f "$RUN" ] || { echo "no broadcast artifact at $RUN — did you pass --broadcast?" >&2; exit 1; }
[ -f "$OUT" ] || { echo "no deployment artifact at $OUT — run the deploy script first" >&2; exit 1; }

tx_for() {
  jq -r --arg n "$1" \
    '[.transactions[] | select(.transactionType == "CREATE" and .contractName == $n) | .hash][0] // ""' "$RUN"
}

ANCHOR_TX="$(tx_for TrustAnchorRegistry)"
DID_TX="$(tx_for EthereumDIDRegistry)"

# Lowest block any of this deployment's transactions landed in. This is the correct `fromBlock`
# for a backend scanning `Anchored` logs: no anchor can exist before the registry did. Receipt
# block numbers are hex strings; bash arithmetic understands the 0x prefix.
DEPLOY_BLOCK=""
for b in $(jq -r '.receipts[].blockNumber' "$RUN"); do
  n=$((b))
  if [ -z "$DEPLOY_BLOCK" ] || [ "$n" -lt "$DEPLOY_BLOCK" ]; then DEPLOY_BLOCK="$n"; fi
done
[ -n "$DEPLOY_BLOCK" ] || { echo "no receipts in $RUN" >&2; exit 1; }

tmp="$(mktemp)"
jq --arg a "$ANCHOR_TX" --arg d "$DID_TX" --argjson b "$DEPLOY_BLOCK" \
  '.trustAnchorRegistryTx = $a | .ethereumDidRegistryTx = $d | .blockNumber = $b' "$OUT" >"$tmp"
mv "$tmp" "$OUT"

echo "updated $OUT"
jq . "$OUT"
