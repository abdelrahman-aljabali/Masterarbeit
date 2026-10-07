// Wall-clock timing of verify-passport.mjs, end to end (process start to exit), N runs after W warm-ups.
// Quantiles: Hyndman & Fan type 7 (linear interpolation), as the thesis protocol states.
import { spawnSync } from "node:child_process";
import { writeFileSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
const VER = "/Users/abdelrahmanaljabali/Desktop/DPP/dev/backend_dpp/scripts/verify-passport.mjs";
const [,, bundle, mode, nStr, label, ...extra] = process.argv;
const N = Number(nStr || 30), W = 3;
const args = mode === "offline" ? ["--offline", ...extra] : ["--rpc", process.env.RPC_URL, ...extra];
const q7 = (xs, p) => { const s=[...xs].sort((a,b)=>a-b); const h=(s.length-1)*p; const lo=Math.floor(h), hi=Math.ceil(h); return s[lo]+(h-lo)*(s[hi]-s[lo]); };
const dist = (xs) => ({ n: xs.length, min: Math.min(...xs), p25: q7(xs,.25), median: q7(xs,.5), p75: q7(xs,.75), iqr: q7(xs,.75)-q7(xs,.25), p95: q7(xs,.95), max: Math.max(...xs), quantileDefinition: "Hyndman-Fan type 7 (linear interpolation)" });
const once = (a) => { const t0=process.hrtime.bigint(); const r=spawnSync(process.execPath,[VER,bundle,"--json",...a],{encoding:"utf8",maxBuffer:64e6}); const ms=Number(process.hrtime.bigint()-t0)/1e6; return { ms, exit: r.status, verdict: (r.stdout.match(/"verdict"\s*:\s*"([A-Z]+)"/)||[])[1] ?? null }; };
const floorOnce = () => { const t0=process.hrtime.bigint(); spawnSync(process.execPath,["-e","0"]); return Number(process.hrtime.bigint()-t0)/1e6; };
for (let i=0;i<W;i++) once(args);
const samples=[], verdicts=new Set(), exits=new Set();
for (let i=0;i<N;i++){ const r=once(args); samples.push(r.ms); verdicts.add(r.verdict); exits.add(r.exit); }
const floor=[]; for (let i=0;i<W;i++) floorOnce(); for (let i=0;i<N;i++) floor.push(floorOnce());
const git = (a) => { try { return execSync(`git ${a}`,{cwd:"/Users/abdelrahmanaljabali/Desktop/DPP/dev",encoding:"utf8"}).trim(); } catch { return null; } };
const out = { tool:"timeit (thesis harness)", label, takenAt:new Date().toISOString(), mode, bundle:{ path:bundle.split("/").pop(), bytes:statSync(bundle).size }, rpcHost: mode==="offline"?null:new URL(process.env.RPC_URL).host, chainId:80002,
  provenance:{ git:{ commit:git("rev-parse HEAD"), dirty: !!git("status --porcelain") }, node:process.version, machine:{ platform:`${process.platform} ${execSync("uname -r",{encoding:"utf8"}).trim()}`, arch:process.arch, cpuModel: execSync("sysctl -n machdep.cpu.brand_string",{encoding:"utf8"}).trim(), loadAvg1m: (await import("node:os")).loadavg()[0] } },
  protocol:{ warmups:W, n:N, timing:"process start to exit, hrtime, ms" }, verdicts:[...verdicts], exitCodes:[...exits], wallClock: dist(samples), nodeStartupFloor: dist(floor), samples };
writeFileSync(`${label}.json`, JSON.stringify(out,null,2));
console.log(label, mode, `n=${N}`, `median=${out.wallClock.median.toFixed(1)}ms iqr=${out.wallClock.iqr.toFixed(1)} p95=${out.wallClock.p95.toFixed(1)}`, `verdict=${[...verdicts]}`, `floor=${out.nodeStartupFloor.median.toFixed(1)}ms`);
