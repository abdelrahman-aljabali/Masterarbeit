#!/usr/bin/env python3
"""Compare the runtime bytecode at the deployed TrustAnchorRegistry addresses with the
current Foundry build, masking the immutable slots the compiler reports, and count
CALLER (0x33) opcodes in the bytes read from the chain. Standard library only.
Run from contracts/ after `forge build`."""
import json, urllib.request, datetime, subprocess, sys, os
art = json.load(open('out/TrustAnchorRegistry.sol/TrustAnchorRegistry.json'))
compiled = bytearray(bytes.fromhex(art['deployedBytecode']['object'][2:]))
refs = art['deployedBytecode'].get('immutableReferences', {})
slots = [(r['start'], r['length']) for v in refs.values() for r in v]
inslot = lambda i: any(s <= i < s + l for s, l in slots)
URL = os.environ.get('RPC_URL', 'https://polygon-amoy.drpc.org')
def rpc(m, p):
    req = urllib.request.Request(URL, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': p}).encode(),
                                 headers={'content-type': 'application/json', 'user-agent': 'thesis-bytecode-check/1.0'})
    return json.load(urllib.request.urlopen(req, timeout=40))['result']
def opcodes(b):
    i = n = caller = 0
    while i < len(b):
        op = b[i]; n += 1; caller += (op == 0x33)
        i += (op - 0x5f + 1) if 0x60 <= op <= 0x7f else 1
    return n, caller
git = lambda a: subprocess.check_output(['git'] + a, cwd='..', text=True).strip()
meta = art.get('metadata', {}); settings = meta.get('settings', {})
out = {'tool': 'bytecode-equality (thesis check)', 'formatVersion': 1, 'takenAt': datetime.datetime.utcnow().isoformat() + 'Z',
       'provenance': {'git': {'commit': git(['rev-parse', 'HEAD']), 'shortCommit': git(['rev-parse', '--short', 'HEAD']), 'dirty': bool(git(['status', '--porcelain']))},
                      'machine': os.uname().machine + ' ' + os.uname().sysname + ' ' + os.uname().release, 'python': sys.version.split()[0],
                      'forge': subprocess.check_output(['forge', '--version'], text=True).split('\n')[0], 'rpc': URL, 'chainId': int(rpc('eth_chainId', []), 16)},
       'compiler': {'solc': meta.get('compiler', {}).get('version'), 'evmVersion': settings.get('evmVersion'), 'optimizer': settings.get('optimizer'), 'bytecodeHash': settings.get('metadata', {}).get('bytecodeHash')},
       'immutableReferences': {'count': len(slots), 'bytes': sum(l for _, l in slots), 'method': 'slots from deployedBytecode.immutableReferences zeroed on both sides before comparison'},
       'results': {}}
for label, addr in [('TrustAnchorRegistry', '0x03dd7e09263a24e5e6aBACA533EeE9d992b85479'), ('superseded', '0xf4e0Ab431a2F5df241fa0E9c6A87DBa86b0E0d93')]:
    onchain = bytearray(bytes.fromhex(rpc('eth_getCode', [addr, 'latest'])[2:]))
    n, caller = opcodes(onchain)
    same_len = len(onchain) == len(compiled)
    diff = [i for i in range(min(len(onchain), len(compiled))) if onchain[i] != compiled[i]] if same_len else None
    res = {'address': addr, 'onchainBytes': len(onchain), 'compiledBytes': len(compiled), 'opcodesScanned': n, 'callerOpcodeCountOnChain': caller,
           'byteEqualModuloImmutables': same_len and all(inslot(i) for i in diff), 'differingBytes': len(diff) if diff is not None else None,
           'differingBytesOutsideImmutableSlots': (len([i for i in diff if not inslot(i)]) if diff is not None else None)}
    if label == 'TrustAnchorRegistry':
        res['immutablesOnChain'] = {name: onchain[v[0]['start']:v[0]['start'] + v[0]['length']].hex() for name, v in refs.items()}
    out['results'][label] = res
    print(label, addr, 'bytes', len(onchain), 'opcodes', n, 'CALLER', caller, 'equal-modulo-immutables', res['byteEqualModuloImmutables'])
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '2026-09-19_bytecode-equality.json'), 'w'), indent=2)
