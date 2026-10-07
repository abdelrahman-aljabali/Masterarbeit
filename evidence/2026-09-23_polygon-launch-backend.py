import os, re, subprocess, sys
def load(path):
    env = {}
    for line in open(path):
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        k, v = line.split('=', 1); v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")): v = v[1:-1]
        env[k.strip()] = v
    return env
base = load('/Users/abdelrahmanaljabali/Desktop/DPP/dev/.env.a')
contracts = load('/Users/abdelrahmanaljabali/Desktop/DPP/dev/contracts/.env')
env = dict(os.environ); env.update(base)
env.update({
  'PORT': '3011', 'NODE_ENV': 'development', 'TRUST_MODE': 'design-a',
  'DATABASE_URL': 'postgresql://trustdpp:trustdpp@localhost:5433/trustdpp?schema=public',
  'DIRECT_URL': 'postgresql://trustdpp:trustdpp@localhost:5433/trustdpp?schema=public',
  'REDIS_URL': 'redis://localhost:6390',
  'ALLOWED_ORIGINS': 'http://localhost:3011,http://localhost:5173', 'APP_URL': 'http://localhost:3011', 'COOKIE_SECURE': 'false',
  'CHAIN_ID': '137', 'CHAIN_NAME': 'polygon',
  'RPC_URL': 'https://polygon-bor-rpc.publicnode.com', 'RPC_URL_FALLBACK': 'https://polygon.drpc.org',
  'DID_REGISTRY_ADDRESS': '0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B',
  'ANCHOR_REGISTRY_ADDRESS': '0x8c7F06eDe1C36FDc7d36AAb77D2Ac5bfB0aABb65', 'ANCHOR_REGISTRY_BLOCK': '94303476',
  'RELAYER_PRIVATE_KEY': contracts['PRIVATE_KEY']  # the funded deployer key; never printed,
})
for k in ('SMTP_HOST',): env.pop(k, None)   # log verification links instead of sending mail
log = open(os.path.join(os.path.dirname(__file__), 'backend.log'), 'w')
p = subprocess.Popen(['npx', 'tsx', 'src/server.ts'], cwd='/Users/abdelrahmanaljabali/Desktop/DPP/dev/backend_dpp', env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
open(os.path.join(os.path.dirname(__file__), 'backend.pid'), 'w').write(str(p.pid))
print('backend pid', p.pid)
