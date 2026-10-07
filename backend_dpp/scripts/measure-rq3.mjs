#!/usr/bin/env node
/**
 * ─── RQ3 measurement harness (thesis artifact) ────────────────────────────────
 * RQ3 asks the only question in this thesis with a numeric answer:
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const BACKEND = resolve(HERE, "..");
const REPO = resolve(BACKEND, "..");
const VERIFIER = join(HERE, "verify-passport.mjs");

/*
 * §1 Statistics
 */

/**
 * Linear-interpolated percentile (method R-7: the NumPy/Excel default).
 * Named rather than inlined because *which* of the nine percentile definitions
 * was used is exactly the kind of thing a thesis reviewer is entitled to ask.
 */
function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  if (sorted.length === 1) return sorted[0];
  const rank = (sorted.length - 1) * p;
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo);
}

/** Quantiles below this n are refused, not computed. See `describe`. */
const QUANTILE_MIN_N = 5;

function describe(samples) {
  if (!samples || samples.length === 0) return null;
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  const mean = s.reduce((a, b) => a + b, 0) / n;
  /*
   * honesty gate: a number is not reported under a label it did not earn.
   */
  // Sample standard deviation (n−1). These are a sample of possible runs, not
  // the population of them, so Bessel's correction is the right denominator.
  const variance = n > 1 ? s.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1) : null;
  const quantiles = n >= QUANTILE_MIN_N;
  const p25 = quantiles ? percentile(s, 0.25) : null;
  const p75 = quantiles ? percentile(s, 0.75) : null;
  return {
    n,
    min: round(s[0]),
    p25: round(p25),
    median: quantiles ? round(percentile(s, 0.5)) : null,
    p75: round(p75),
    iqr: quantiles ? round(p75 - p25) : null,
    p95: quantiles ? round(percentile(s, 0.95)) : null,
    max: round(s[n - 1]),
    mean: round(mean),
    stddev: variance === null ? null : round(Math.sqrt(variance)),
  };
}

const round = (x) => (x === null || x === undefined ? null : Math.round(x * 1000) / 1000);

/**
 * Milli-precision is right for milliseconds and catastrophic for POL: one
 * `anchor` at 30 gwei is 0.00115335 POL, which `round` would flatten to 0.001 —
 * a 15 % error introduced by the formatter, in the exact column §24 quotes to
 * three significant figures. Currency amounts get nine decimals (gwei
 * resolution) instead.
 */
const roundPol = (x) => (x === null || x === undefined ? null : Math.round(x * 1e9) / 1e9);

/**
 * Run `fn` `warmup + n` times, discard the warmups, return a distribution.
 */
function timeRepeated(fn, { n, warmup }) {
  for (let i = 0; i < warmup; i++) fn(i, true);
  const samples = [];
  const extras = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    const extra = fn(i, false);
    const t1 = process.hrtime.bigint();
    samples.push(Number(t1 - t0) / 1e6); // ns → ms
    if (extra !== undefined) extras.push(extra);
  }
  return { samples, extras };
}

/*
 * §2 The measurement record
 */

const results = [];

/**
 * Categories exist so the printed table can put Design A's row and Design B's
 * row for the SAME quantity next to each other. They are derived from the id
 * prefix rather than passed in, so a new measurement cannot forget to declare
 * one and silently fall out of the table's grouping.
 */
const CATEGORIES = [
  ["verification.nodeStartup", "INSTRUMENT (not an RQ3 metric)"],
  ["verification.", "Graph-Verifikations-Latenz  (RQ3 §13)"],
  ["gas.", "Gas & Kosten  (RQ3 §13)"],
  ["anchor.", "Verankerung  (nicht in §13 versprochen — Zugabe)"],
  ["onboarding.", "Onboarding-Latenz  (RQ3 §13 — Primärmetrik)"],
  ["signing.", "Signierlatenz  (RQ3 §13)"],
  ["serviceCost.", "Servicekosten  (RQ3 §13)"],
];

function categoryOf(id) {
  for (const [prefix, label] of CATEGORIES) if (id === prefix || id.startsWith(prefix)) return label;
  return "Sonstige";
}

function record(rec) {
  const full = {
    id: rec.id,
    category: categoryOf(rec.id),
    metric: rec.metric,
    design: rec.design ?? null,
    unit: rec.unit ?? null,
    state: rec.state,
    provenance: rec.provenance ?? null,
    value: rec.value ?? null,
    dist: rec.dist ?? null,
    reason: rec.reason ?? null,
    precondition: rec.precondition ?? null,
    includes: rec.includes ?? [],
    excludes: rec.excludes ?? [],
    notes: rec.notes ?? null,
    detail: rec.detail ?? null,
    samples: rec.samples ?? null,
  };
  results.push(full);
  return full;
}

const measured = (r) => record({ ...r, state: "measured" });
/** Takeable in principle, not today. MUST carry the precondition that unblocks it. */
const unavailable = (r) => record({ ...r, state: "unavailable" });
/** The category does not exist in this design. MUST carry the reason. */
const notApplicable = (r) => record({ ...r, state: "n/a" });
/** Known exactly from the design rather than from a timer. */
const structural = (r) => record({ ...r, state: "structural" });

/* ════════════════════════════════════════════════════════════════════════════
 * §3  Instruments
 * ════════════════════════════════════════════════════════════════════════════ */

/** Run a command, return {code, stdout, stderr}. Never throws on non-zero. */
function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...opts,
  });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

/** True if a binary is on PATH. Used to degrade to `unavailable`, never to guess. */
function have(bin) {
  const r = run("sh", ["-c", `command -v ${bin}`]);
  return r.code === 0 && r.stdout.trim().length > 0;
}

/**
 * Minimal JSON-RPC client. Counts its own calls, because "how much of this
 * number is network" is a question every latency row here has to be able to
 * answer, and the call count is the cheapest honest proxy.
 */
function makeRpc(url) {
  if (!url) return null;
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    async send(method, params = []) {
      calls++;
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: calls, method, params }),
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status} for ${method}`);
      const body = await res.json();
      if (body.error) throw new Error(`RPC error for ${method}: ${body.error.message}`);
      return body.result;
    },
  };
}

/**
 * Read the RPC URL from the usual places. `contracts/.env` is the last resort
 * and is parsed by hand rather than sourced — this file will not execute a
 * dotenv, and the deploy env holds a private key.
 */
function discoverRpc(explicit) {
  if (explicit) return { url: explicit, source: "--rpc" };
  if (process.env.RPC_URL) return { url: process.env.RPC_URL, source: "$RPC_URL" };
  if (process.env.AMOY_RPC_URL) return { url: process.env.AMOY_RPC_URL, source: "$AMOY_RPC_URL" };
  const envPath = join(REPO, "contracts", ".env");
  if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, "utf8").split("\n")) {
      const m = /^\s*AMOY_RPC_URL\s*=\s*(.+?)\s*$/.exec(line);
      if (m && m[1] && !m[1].startsWith("#")) return { url: m[1], source: "contracts/.env" };
    }
  }
  return { url: null, source: null };
}

/**
 * The host, and only the host. RPC URLs carry API keys and this report is meant
 * to be pasted into a thesis appendix — `verify-passport.mjs` takes the same
 * precaution for the same reason.
 */
function rpcHost(url) {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return "unparseable";
  }
}

/** A `psql` shell-out through docker: the technique scripts/README.md documents. */
function makeDb({ container, user, name }) {
  return {
    available() {
      if (!have("docker")) return { ok: false, why: "docker is not on PATH" };
      const r = run("docker", ["exec", container, "psql", "-U", user, "-d", name, "-tAc", "select 1"]);
      if (r.code !== 0) {
        return { ok: false, why: `container ${container} did not answer psql (${(r.stderr || "").trim().split("\n")[0] || "no output"})` };
      }
      return { ok: true };
    },
    query(sql) {
      const r = run("docker", ["exec", container, "psql", "-U", user, "-d", name, "-tAc", sql]);
      if (r.code !== 0) throw new Error(`psql failed: ${(r.stderr || "").trim()}`);
      return r.stdout.trim();
    },
  };
}

/*
 * §4 Provenance
 */

function collectProvenance(cfg, deployment) {
  const git = (args) => {
    const r = run("git", ["-C", REPO, ...args]);
    return r.code === 0 ? r.stdout.trim() : null;
  };
  const forgeVersion = have("forge") ? (run("forge", ["--version"]).stdout.trim().split("\n")[0] ?? null) : null;
  const cpus = os.cpus();
  return {
    tool: "measure-rq3",
    formatVersion: 1,
    takenAt: new Date().toISOString(),
    git: {
      commit: git(["rev-parse", "HEAD"]),
      shortCommit: git(["rev-parse", "--short", "HEAD"]),
      branch: git(["rev-parse", "--abbrev-ref", "HEAD"]),
      // A dirty tree is not disqualifying — it is the normal state during a
      // build phase — but it must be stated, because the commit alone then does
      // not reconstruct what ran.
      dirty: git(["status", "--porcelain"]) ? true : false,
    },
    machine: {
      platform: `${os.platform()} ${os.release()}`,
      arch: os.arch(),
      cpuModel: cpus[0]?.model ?? null,
      cpuCount: cpus.length,
      totalMemGb: round(os.totalmem() / 1024 ** 3),
      loadAvg1m: round(os.loadavg()[0]),
    },
    runtime: {
      node: process.version,
      v8: process.versions.v8,
      forge: forgeVersion,
    },
    chain: {
      chainId: deployment?.chainId ?? null,
      network: deployment?.network ?? null,
      trustAnchorRegistry: deployment?.trustAnchorRegistry ?? null,
      ethereumDidRegistry: deployment?.ethereumDidRegistry ?? null,
      ethereumDidRegistryIsCanonical: deployment?.ethereumDidRegistryIsCanonical ?? null,
      deploymentBlock: deployment?.blockNumber ?? null,
      // Host only — see rpcHost().
      rpcHost: rpcHost(cfg.rpcUrl),
      rpcSource: cfg.rpcSource,
      mainnetRpcHost: rpcHost(cfg.mainnetRpcUrl),
    },
    parameters: {
      n: cfg.n,
      warmup: cfg.warmup,
      percentileMethod: "R-7 (linear interpolation; NumPy/Excel default)",
      publishRuns: cfg.publishRuns,
      onboardingRuns: cfg.onboardingRuns,
      bBundleSource: cfg.bBundleSource,
    },
  };
}

/*
 * §5 Measurement A — verification latency
 */

function verifierRun(bundlePath, extraArgs) {
  const r = run(process.execPath, [VERIFIER, bundlePath, "--json", ...extraArgs]);
  // Exit 3 (INCOMPLETE) is the *expected* verdict for a Design B bundle: its
  // signatures are unverifiable without a JSON-LD processor and it has no
  // anchor. Only 2 (usage/self-test failure) means the instrument itself broke.
  if (r.code === 2) throw new Error(`verify-passport exited 2: ${(r.stderr || r.stdout).trim().split("\n")[0]}`);
  let parsed = null;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {
    /* left null; the caller records the exit code regardless */
  }
  return { exitCode: r.code, report: parsed };
}

/**
 * Per-design row labels and the offline-mode note, keyed by what the BUNDLE
 * turned out to be (`detectBundleDesign`), never by which flag delivered it.
 * One bundle per run fills one design's rows; `measureVerificationUnfilled`
 * emits the other design's rows as `unavailable` with the reason.
 */
const VERIFICATION_LABELS = {
  A: {
    local: "Graph-Verifikations-Latenz — Design A, offline (Rechenanteil)",
    full: "Graph-Verifikations-Latenz — Design A, mit Netz (ERC-1056 + Autorisierung + Anker)",
    offlineNote:
      "Verdict INCOMPLETE is expected and correct: with --offline every network-dependent check SKIPs. " +
      "Design A's ES256K-R signatures DO verify in this mode — the issuer key is recovered from the " +
      "signature itself, so no network is needed to check them; what --offline forgoes is chain state " +
      "(DID liveness, the authorization root, the anchor event).",
    fullPrecondition: "a reachable JSON-RPC endpoint — the resolution being timed is ERC-1056 chain reads",
  },
  B: {
    local: "Graph-Verifikations-Latenz — Design B, offline (Rechenanteil)",
    full: "Graph-Verifikations-Latenz — Design B, mit Netz (did:web-Auflösung)",
    offlineNote:
      "Verdict INCOMPLETE is expected and correct: with --offline every network-dependent check SKIPs, " +
      "and Design B's eddsa-rdfc-2022 signatures are never verified by this verifier in any mode.",
    fullPrecondition:
      "a bundle whose did:web issuer domain is live — i.e. the production baseline: " +
      "--b-export-url https://app.trustdpp.co/api/public/passports/<id>/export",
  },
};

function measureVerification(cfg, bundle) {
  /* The design under measurement. `detectBundleDesign` read it from the
   * credentials; `null` (undetectable) falls back to the historical assumption
   * — B, which is what every bundle was before Design A could export one — and
   * the fallback is RECORDED in each row's detail so a reader of the artifact
   * can see the difference between "detected" and "assumed". */
  const design = bundle.design ?? "B";
  const designDetection = bundle.path ? (bundle.design ? "detected from credentials" : "assumed (undetectable)") : null;
  const L = VERIFICATION_LABELS[design];
  // The subprocess floor, so it can be subtracted from everything below.
  const startup = timeRepeated(() => run(process.execPath, ["-e", ""]), { n: cfg.n, warmup: cfg.warmup });
  measured({
    id: "verification.nodeStartup",
    metric: "Node process startup floor (subtract from verification rows)",
    design: null,
    unit: "ms",
    provenance: "independent",
    dist: describe(startup.samples),
    includes: ["spawning `node -e \"\"` and waiting for exit"],
    excludes: ["any verification work"],
    notes:
      "Not an RQ3 metric. Recorded so the verification numbers can be reported either as " +
      "'what a verifier costs end to end' or as 'what the verification work costs', without re-running anything.",
    samples: cfg.keepSamples ? startup.samples.map(round) : null,
  });

  if (!bundle.path) {
    for (const [id, label] of [
      [`verification.design${design}.local`, L.local],
      [`verification.design${design}.full`, L.full],
    ]) {
      unavailable({
        id,
        metric: label,
        design,
        unit: "ms",
        provenance: "independent",
        reason: bundle.why,
        precondition:
          "an export bundle: `--bundle <path>` (either design — it is detected from the credentials), " +
          "`--b-export-url <url>`, or a reachable database with a published PassportVersion",
      });
    }
    return;
  }

  // ── B, offline: the computational half.
  const offlineArgs = ["--offline"];
  let offlineReport = null;
  const offline = timeRepeated(
    () => {
      const { report } = verifierRun(bundle.path, offlineArgs);
      offlineReport = report ?? offlineReport;
    },
    { n: cfg.n, warmup: cfg.warmup },
  );
  measured({
    id: `verification.design${design}.local`,
    metric: L.local,
    design,
    unit: "ms",
    provenance: "independent",
    dist: describe(offline.samples),
    includes: [
      "node process startup (see verification.nodeStartup)",
      "keccak-256 + secp256k1 self-test vectors (run on every verifier invocation)",
      "bundle parse, canonical serialisation, credential digests, snapshot digest, Merkle root",
      ...(design === "A" ? ["ES256K-R JWS verification per credential (key recovered from the signature — no network)"] : []),
      `${bundle.credentialCount ?? "?"} credentials`,
    ],
    excludes: ["all network I/O (--offline)", "did:web resolution", "chain reads"],
    detail: {
      bundlePath: bundle.path,
      bundleBytes: bundle.bytes,
      credentialCount: bundle.credentialCount,
      designDetection,
      verdict: offlineReport?.verdict ?? null,
      checks: offlineReport ? offlineReport.counts : null,
    },
    notes: L.offlineNote,
    samples: cfg.keepSamples ? offline.samples.map(round) : null,
  });

  // ── Full: adds the network. See the anchor-window note above.
  if (!cfg.rpcUrl) {
    unavailable({
      id: `verification.design${design}.full`,
      metric: L.full,
      design,
      unit: "ms",
      provenance: "independent",
      reason: "no JSON-RPC endpoint was configured",
      precondition: "--rpc <url>, $RPC_URL, or AMOY_RPC_URL in contracts/.env",
    });
    return;
  }

  /*
   * inverts a measurement:
   */
  const block = cfg.deployment?.blockNumber;
  const fullArgs = ["--rpc", cfg.rpcUrl];
  if (design === "B") {
    if (block) fullArgs.push("--from-block", String(block), "--to-block", String(block));
  } else if (!bundle.anchorTxHash && block) {
    fullArgs.push("--from-block", String(block));
  }
  let fullReport = null;
  const full = timeRepeated(
    () => {
      const { report } = verifierRun(bundle.path, fullArgs);
      fullReport = report ?? fullReport;
    },
    { n: cfg.nNetwork, warmup: cfg.warmup },
  );
  // ── The honesty gate on this row.
  const resolutions = fullReport?.checks?.filter((c) => c.name === "issuer-resolution") ?? [];
  const anyResolved = resolutions.some((c) => c.status === "PASS");
  if (resolutions.length > 0 && !anyResolved) {
    unavailable({
      id: `verification.design${design}.full`,
      metric: L.full,
      design,
      unit: "ms",
      provenance: "independent",
      reason:
        design === "A"
          ? `none of the ${resolutions.length} issuer DIDs in this bundle resolved against ERC-1056, so the ` +
            `timed runs measured a chain-read FAILURE, not a resolution — a dead or rate-limited RPC endpoint ` +
            `answers on a different clock than a working one`
          : `none of the ${resolutions.length} issuer DIDs in this bundle resolved, so the timed runs measured a ` +
            `did:web resolution FAILURE, not a resolution — and a failure is systematically faster than a success`,
      precondition: L.fullPrecondition,
      detail: {
        observedButRejected: describe(full.samples),
        rpcCalls: fullReport?.chain?.rpcCalls ?? null,
        issuerResolution: resolutions.map((c) => c.status),
        verdict: fullReport?.verdict ?? null,
      },
      notes:
        "This is the harness refusing to report a number it did not take. " +
        (design === "A"
          ? "Design A resolution is JSON-RPC reads against the ERC-1056 registry; every one failing means the " +
            "endpoint, not the design, was measured."
          : "The dev database's passports carry did:web issuers on a domain that does not resolve, which " +
            "coincidentally reproduces the shutdown scenario — interesting, but it is not the baseline. " +
            "Take this one against production."),
    });
    return;
  }

  measured({
    id: `verification.design${design}.full`,
    metric: L.full,
    design,
    unit: "ms",
    provenance: "independent",
    dist: describe(full.samples),
    includes: [
      `everything in verification.design${design}.local`,
      "one eth_chainId round trip to the configured endpoint",
      design === "A"
        ? `ERC-1056 resolution + authorization-root read per distinct issuer, and the anchor check (${fullReport?.credentials?.length ?? "?"} credentials)`
        : `did:web resolution over HTTPS for each distinct issuer (${fullReport?.credentials?.length ?? "?"} credentials)`,
    ],
    excludes:
      design === "A"
        ? [
            bundle.anchorTxHash
              ? "an anchor log sweep — the bundle's anchorTxHash hint lets the verifier fetch the one transaction directly (the hinted log is still fully checked)"
              : "nothing network-side: resolution, authorization and the anchor sweep are all in the timed span",
          ]
        : [
            "the anchor log sweep — collapsed to one block, because Design B has no anchor and sweeping " +
              "for one measures the endpoint's eth_getLogs window cap, not Design B",
            "Design B signature verification, which this verifier never performs (no JSON-LD processor)",
          ],
    detail: {
      rpcCalls: fullReport?.chain?.rpcCalls ?? null,
      designDetection,
      anchorTxHint: bundle.anchorTxHash ?? null,
      verdict: fullReport?.verdict ?? null,
      checks: fullReport ? fullReport.counts : null,
      issuerResolution:
        fullReport?.checks?.filter((c) => c.name === "issuer-resolution").map((c) => c.status) ?? null,
    },
    notes:
      design === "A"
        ? "The network cost here is JSON-RPC round trips, so the endpoint IS part of the measurand — record " +
          "which endpoint took it (provenance does) and do not compare against numbers taken on another. " +
          "`detail.issuerResolution` says whether resolution genuinely happened."
        : "IMPORTANT for interpretation: whether this number reflects a *working* did:web resolution depends " +
          "entirely on which instance the bundle came from. A dev-database bundle whose issuer DIDs point at a " +
          "domain that does not resolve will time a DNS failure, not a resolution — check `detail.issuerResolution`. " +
          "Take the production baseline with --b-export-url against app.trustdpp.co.",
    samples: cfg.keepSamples ? full.samples.map(round) : null,
  });
}

/*
 * The PRODUCTION Design B baseline (`--b-prod-url`).
 */

/**
 * did:web → the HTTPS URL its document is served from, per the did:web method
 * spec: colons after the host become path segments, and a bare host gets
 * `/.well-known/`. Implemented here rather than assumed, because the whole
 * point of the isolated row is to fetch exactly what the verifier fetches.
 */
function didWebToUrl(did) {
  if (!did?.startsWith("did:web:")) return null;
  const parts = did.slice("did:web:".length).split(":");
  const host = decodeURIComponent(parts[0]);
  const path = parts.slice(1).map(decodeURIComponent);
  return path.length === 0
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${path.join("/")}/did.json`;
}

async function measureProductionBaseline(cfg) {
  const ids = [
    ["verification.designB.prod.compute", "Design B (PROD-Projektion) — Rechenanteil, offline"],
    ["verification.designB.prod.full", "Design B (PROD-Projektion) — mit realer did:web-Auflösung"],
    ["verification.designB.prod.didwebOnly", "Design B (PROD) — nur did:web-Auflösung (isoliert)"],
  ];
  const blocked = (reason, precondition) => {
    for (const [id, metric] of ids) {
      unavailable({ id, metric, design: "B", unit: "ms", provenance: "independent", reason, precondition });
    }
  };

  if (!cfg.bProdUrl) {
    blocked(
      "no production passport URL was given, so no baseline was taken against deployed infrastructure",
      "--b-prod-url https://app.trustdpp.co/api/public/passports/<id>",
    );
    return;
  }

  // Fetch the projection once, up front. This fetch is NOT part of any timing —
  // it is the harness acquiring its input, not a verifier doing work.
  const tmp = join(os.tmpdir(), `rq3-prod-${process.pid}.json`);
  let projection;
  try {
    const res = await fetch(cfg.bProdUrl);
    if (!res.ok) return blocked(`--b-prod-url answered HTTP ${res.status}`, "a published, publicly visible passport");
    const text = await res.text();
    writeFileSync(tmp, text);
    projection = JSON.parse(text);
  } catch (err) {
    return blocked(`--b-prod-url fetch failed: ${err.message}`, "network access to the production host");
  }

  const creds = Array.isArray(projection.credentials) ? projection.credentials : [];
  const issuers = creds.map((c) => (typeof c.issuer === "string" ? c.issuer : c.issuer?.id)).filter(Boolean);
  const distinctIssuers = [...new Set(issuers)];
  const host = new URL(cfg.bProdUrl).host;
  const shapeNote =
    "FLATTENED PUBLIC PROJECTION, not a full evidence bundle: production does not yet serve /export, so the " +
    "frozen snapshot is absent and version-hash, merkle-root and anchor all SKIP. This is NOT an end-to-end " +
    "verification time.";

  // ── compute-only.
  let computeReport = null;
  const compute = timeRepeated(
    () => {
      const { report } = verifierRun(tmp, ["--offline"]);
      computeReport = report ?? computeReport;
    },
    { n: cfg.n, warmup: cfg.warmup },
  );
  measured({
    id: ids[0][0],
    metric: ids[0][1],
    design: "B",
    unit: "ms",
    provenance: "independent",
    dist: describe(compute.samples),
    includes: [
      "node process startup (see verification.nodeStartup)",
      "keccak-256 + secp256k1 self-test vectors",
      `parse and inspect ${creds.length} credentials from the production projection`,
    ],
    excludes: ["all network I/O (--offline)", "did:web resolution", "version-hash / merkle-root / anchor (absent from the projection)"],
    detail: { source: cfg.bProdUrl, host, credentialCount: creds.length, distinctIssuers: distinctIssuers.length, verdict: computeReport?.verdict ?? null, checks: computeReport?.counts ?? null },
    notes: shapeNote,
    samples: cfg.keepSamples ? compute.samples.map(round) : null,
  });

  // ── full, with the real network.
  const block = cfg.deployment?.blockNumber;
  const fullArgs = cfg.rpcUrl ? ["--rpc", cfg.rpcUrl] : [];
  if (cfg.rpcUrl && block) fullArgs.push("--from-block", String(block), "--to-block", String(block));
  let fullReport = null;
  const full = timeRepeated(
    () => {
      const { report } = verifierRun(tmp, fullArgs);
      fullReport = report ?? fullReport;
    },
    { n: cfg.nNetwork, warmup: cfg.warmup },
  );

  // Same honesty gate as the dev row: if nothing resolved, nothing was measured.
  const resolutions = fullReport?.checks?.filter((c) => c.name === "issuer-resolution") ?? [];
  const resolved = resolutions.filter((c) => c.status === "PASS").length;
  if (resolutions.length > 0 && resolved === 0) {
    unavailable({
      id: ids[1][0],
      metric: ids[1][1],
      design: "B",
      unit: "ms",
      provenance: "independent",
      reason: `none of the ${resolutions.length} issuer DIDs resolved against ${host}, so this timed a failure path`,
      precondition: "a production host actually serving the issuers' did.json documents",
      detail: { observedButRejected: describe(full.samples), issuerResolution: resolutions.map((c) => c.status) },
    });
  } else {
    const computeMedian = describe(compute.samples)?.median ?? null;
    const fullMedian = describe(full.samples)?.median ?? null;
    measured({
      id: ids[1][0],
      metric: ids[1][1],
      design: "B",
      unit: "ms",
      provenance: "independent",
      dist: describe(full.samples),
      includes: [
        "everything in the compute row",
        `did:web resolution over the PUBLIC INTERNET from this machine to ${host}: DNS, TLS handshake and HTTP GET`,
        `${resolutions.length} issuer-resolution checks across ${distinctIssuers.length} distinct issuer DID(s)`,
        cfg.rpcUrl ? "one eth_chainId round trip" : "no chain call (no RPC configured)",
      ],
      excludes: [
        "version-hash, merkle-root and anchor — absent from the projection, so they SKIP",
        "signature verification — eddsa-rdfc-2022 is never verified by this verifier",
        "the anchor log sweep, collapsed to one block (Design B has no anchor)",
      ],
      detail: {
        source: cfg.bProdUrl,
        host,
        credentialCount: creds.length,
        distinctIssuers: distinctIssuers.length,
        issuerResolutionPass: resolved,
        issuerResolutionTotal: resolutions.length,
        rpcCalls: fullReport?.chain?.rpcCalls ?? null,
        verdict: fullReport?.verdict ?? null,
        checks: fullReport?.counts ?? null,
        // The cheap split: what the network added, by subtraction.
        networkComponentBySubtraction:
          computeMedian !== null && fullMedian !== null ? round(fullMedian - computeMedian) : null,
        // Normalised, because the raw figure is only interpretable against the
        // number of resolutions that produced it.
        networkPerResolution:
          computeMedian !== null && fullMedian !== null && resolutions.length > 0
            ? round((fullMedian - computeMedian) / resolutions.length)
            : null,
      },
      notes:
        shapeNote +
        " NETWORK CONDITIONS ARE PART OF THIS NUMBER: it was taken over the public internet from the machine in " +
        "`provenance.machine`, and the link is not a property of Design B. Quote it with the compute row and the " +
        "isolated resolution row beside it, never alone. Note also that the verifier does NOT cache DID " +
        `resolution, so ${resolutions.length} credentials cost ${resolutions.length} fetches even though only ` +
        `${distinctIssuers.length} distinct issuer(s) are involved — a caching verifier would be faster, and that ` +
        "is an implementation property, not an architectural one.",
      samples: cfg.keepSamples ? full.samples.map(round) : null,
    });
  }

  // ── the resolution, isolated.
  //
  // Measured in a FRESH SUBPROCESS per run, deliberately. Node's fetch keeps
  // connections alive within a process, so an in-process loop would reuse one
  // TCP+TLS session and report an HTTP round trip where the verifier — a new
  // process every time — really pays DNS and a full handshake. Matching the
  // process model is what makes this subtractable from the row above.
  const urls = distinctIssuers.map(didWebToUrl).filter(Boolean);
  if (urls.length === 0) {
    unavailable({
      id: ids[2][0],
      metric: ids[2][1],
      design: "B",
      unit: "ms",
      provenance: "independent",
      reason: "no did:web issuer could be extracted from the projection",
      precondition: "a projection whose credentials carry did:web issuers",
    });
    return;
  }
  const fetchScript = `const u=${JSON.stringify(urls)};(async()=>{for(const x of u){const r=await fetch(x);await r.text();if(!r.ok)process.exit(9);}})()`;
  let lastCode = 0;
  const didweb = timeRepeated(
    () => {
      const r = run(process.execPath, ["-e", fetchScript]);
      lastCode = r.code;
    },
    { n: cfg.nNetwork, warmup: cfg.warmup },
  );
  if (lastCode !== 0) {
    unavailable({
      id: ids[2][0],
      metric: ids[2][1],
      design: "B",
      unit: "ms",
      provenance: "independent",
      reason: `fetching the did.json documents exited ${lastCode} — at least one did not return 200`,
      precondition: "all issuer did.json documents reachable",
      detail: { urls, observedButRejected: describe(didweb.samples) },
    });
    return;
  }
  const startupRow = results.find((r) => r.id === "verification.nodeStartup");
  const startupMedian = startupRow?.dist?.median ?? null;
  const didwebMedian = describe(didweb.samples)?.median ?? null;
  measured({
    id: ids[2][0],
    metric: ids[2][1],
    design: "B",
    unit: "ms",
    provenance: "independent",
    dist: describe(didweb.samples),
    includes: [
      "node process startup",
      `DNS + TLS handshake + HTTP GET for ${urls.length} distinct did.json document(s) on ${host}`,
    ],
    excludes: ["all verification work — this fetches the documents and discards them"],
    detail: {
      urls,
      distinctIssuers: distinctIssuers.length,
      // Subtracting the startup floor leaves the network cost proper. Reported
      // as a derived figure, not as something a timer produced directly.
      networkOnlyByStartupSubtraction:
        didwebMedian !== null && startupMedian !== null ? round(didwebMedian - startupMedian) : null,
      fetchCount: urls.length,
      networkPerFetch:
        didwebMedian !== null && startupMedian !== null && urls.length > 0
          ? round((didwebMedian - startupMedian) / urls.length)
          : null,
    },
    notes:
      "This is the cost of resolving the DISTINCT issuer documents once — the resolution floor. It is NOT " +
      "directly comparable with `prod.full.detail.networkComponentBySubtraction`, and the two were measured " +
      "and found to disagree (≈279 ms here against ≈526 ms there on the reference run). Both figures are " +
      "correct; they count different things, for two compounding reasons. (1) FETCH COUNT: the verifier does " +
      "not cache DID resolution, so it fetches once per CREDENTIAL (5) while this row fetches once per DISTINCT " +
      "ISSUER (2). (2) CONNECTION REUSE: within one process the first fetch pays DNS plus a TLS handshake " +
      "(~140 ms measured) and every later fetch to the same host reuses the connection (~35 ms measured), so " +
      "cost is emphatically NOT linear in fetch count. Use `networkPerFetch` and `networkPerResolution` for " +
      "comparison, and treat neither as 'the' network cost. A fresh subprocess per run is deliberate: it makes " +
      "this row pay DNS and the handshake exactly as the verifier does.",
    samples: cfg.keepSamples ? didweb.samples.map(round) : null,
  });
}

/*
 * The design the bundle did NOT cover — mirror rows, honestly labelled.
 */

function measureVerificationUnfilled(cfg, bundle) {
  const covered = bundle.path ? (bundle.design ?? "B") : "B";
  const other = covered === "A" ? "B" : "A";
  const L = VERIFICATION_LABELS[other];
  for (const [id, label] of [
    [`verification.design${other}.local`, L.local],
    [`verification.design${other}.full`, L.full],
  ]) {
    unavailable({
      id,
      metric: label,
      design: other,
      unit: "ms",
      provenance: "independent",
      reason: bundle.path
        ? `this run's bundle is Design ${covered} (${bundle.source}), and one bundle fills one design's rows`
        : `no bundle was available at all (${bundle.why})`,
      precondition:
        other === "A"
          ? "a Design A export: --bundle <path> pointing at a design-a stack's " +
            "GET /api/public/passports/<id>/export (or scripts/out/design-a-export-*.json from seed-design-a.ts)"
          : "a Design B export: --b-export-url https://app.trustdpp.co/api/public/passports/<id>/export " +
            "for the production baseline, or --bundle <path>",
      notes:
        "Not a defect — a per-run complement. Run once per design and merge the two artifacts; the design " +
        "of each bundle is detected from its credentials, so the same flag fills whichever column the " +
        "bundle belongs to.",
    });
  }
}

/*
 * §6 Measurement B — gas
 */

function measureGasFromSnapshot() {
  const p = join(REPO, "contracts", "snapshots", "TrustAnchorRegistry.json");
  if (!existsSync(p)) {
    unavailable({
      id: "gas.execution",
      metric: "Gas — Ausführung (ohne intrinsische Kosten)",
      design: "A",
      unit: "gas",
      provenance: "artifact",
      reason: "contracts/snapshots/TrustAnchorRegistry.json is missing",
      precondition: "`forge snapshot` in contracts/",
    });
    return null;
  }
  const snap = JSON.parse(readFileSync(p, "utf8"));
  const value = Object.fromEntries(Object.entries(snap).map(([k, v]) => [k, Number(v)]));
  measured({
    id: "gas.execution",
    metric: "Gas — Ausführung (ohne intrinsische Kosten)",
    design: "A",
    unit: "gas",
    provenance: "artifact",
    value,
    includes: ["contract execution with cold storage slots (vm.coolSlot before each call)"],
    excludes: ["the 21 000 intrinsic transaction cost", "EIP-2028 calldata cost"],
    notes:
      "NOT what a relayer pays — see gas.totalTx. Kept because it is the committed, machine-readable " +
      "artifact and it isolates contract design from transaction overhead: `anchor` writes no storage " +
      "beyond its nonce, which is why its execution cost is a third of claimProduct's.",
    detail: { source: "contracts/snapshots/TrustAnchorRegistry.json (forge snapshot)" },
  });
  return value;
}

/**
 * Re-run Foundry's gas test and parse its console output for the TOTAL TX
 * column. Parsed from the live run rather than transcribed from
 * `contracts/README.md`, because a measurement tool that hardcodes the number
 * it is supposed to measure is a transcription, not a measurement.
 */
function measureGasTotalTx(cfg) {
  const contractsDir = join(REPO, "contracts");
  if (!have("forge")) {
    unavailable({
      id: "gas.totalTx",
      metric: "Gas — vollständige Transaktion (was der Relayer zahlt)",
      design: "A",
      unit: "gas",
      provenance: "artifact",
      reason: "forge is not on PATH",
      precondition: "Foundry installed (`foundryup`), then re-run",
    });
    return null;
  }
  const r = run("forge", ["test", "--match-test", "test_Gas_PerOperation", "-vv"], { cwd: contractsDir });
  if (r.code !== 0) {
    unavailable({
      id: "gas.totalTx",
      metric: "Gas — vollständige Transaktion (was der Relayer zahlt)",
      design: "A",
      unit: "gas",
      provenance: "artifact",
      reason: `forge test exited ${r.code}`,
      precondition: "a green `forge test --match-test test_Gas_PerOperation` in contracts/",
      detail: { stderr: (r.stderr || "").trim().split("\n").slice(0, 4) },
    });
    return null;
  }
  // The test prints: "  claimProduct 51805 23516 75321"
  const totals = {};
  const exec = {};
  const intrinsic = {};
  for (const line of r.stdout.split("\n")) {
    const m = /^\s*(claimProduct|setIssuer|anchor)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/.exec(line);
    if (m) {
      exec[m[1]] = Number(m[2]);
      intrinsic[m[1]] = Number(m[3]);
      totals[m[1]] = Number(m[4]);
    }
  }
  if (Object.keys(totals).length === 0) {
    unavailable({
      id: "gas.totalTx",
      metric: "Gas — vollständige Transaktion (was der Relayer zahlt)",
      design: "A",
      unit: "gas",
      provenance: "artifact",
      reason: "forge ran but its gas table did not parse — the test's console2.log format may have changed",
      precondition: "test_Gas_PerOperation printing `<op> <execution> <intrinsic> <total>` lines",
    });
    return null;
  }
  measured({
    id: "gas.totalTx",
    metric: "Gas — vollständige Transaktion (was der Relayer zahlt)",
    design: "A",
    unit: "gas",
    provenance: "artifact",
    value: totals,
    includes: ["contract execution (cold slots)", "21 000 intrinsic", "EIP-2028 calldata (16/non-zero byte, 4/zero)"],
    excludes: ["gas price — deliberately a separate, timestamped row (see gas.price)"],
    notes:
      "`anchor` is the RECURRING per-publish cost; claimProduct and setIssuer are one-off per product and " +
      "per authorised issuer. More than 60 % of `anchor` is calldata plus the flat transaction fee rather " +
      "than execution — the event-log design paying off against a storage-based anchor (~20 000 gas more).",
    detail: { execution: exec, intrinsicPlusCalldata: intrinsic, source: "forge test --match-test test_Gas_PerOperation -vv" },
  });
  return totals;
}

async function measureGasOnChain(cfg, rpc) {
  if (!rpc) {
    for (const [id, metric] of [
      ["gas.price", "Gaspreis (volatil — mit Zeitstempel)"],
      ["gas.deployment", "Gas — einmalige Contract-Deployments"],
      ["gas.realCeremonyTx", "Gas — reale Zeremonie-Transaktionen (gasUsed aus Receipts)"],
    ]) {
      unavailable({
        id,
        metric,
        design: "A",
        unit: id === "gas.price" ? "wei" : "gas",
        provenance: "chain",
        reason: "no JSON-RPC endpoint was configured",
        precondition: "--rpc <url>, $RPC_URL, or AMOY_RPC_URL in contracts/.env",
      });
    }
    return null;
  }

  // ── Gas price: volatile, so it is its own row with its own timestamp.
  const prices = {};
  try {
    const wei = BigInt(await rpc.send("eth_gasPrice"));
    prices.amoy = { wei: wei.toString(), gwei: round(Number(wei) / 1e9) };
  } catch (err) {
    prices.amoy = { error: String(err.message) };
  }
  if (cfg.mainnetRpcUrl) {
    // §13 asks for gas on "Amoy + Mainnet". The gas UNITS are identical — same
    // bytecode, same calldata — so only the price differs, and only the price
    // is fetched here. Quoting a separate "mainnet gas" figure would imply a
    // measurement that was never taken.
    const mrpc = makeRpc(cfg.mainnetRpcUrl);
    try {
      const wei = BigInt(await mrpc.send("eth_gasPrice"));
      prices.mainnet = { wei: wei.toString(), gwei: round(Number(wei) / 1e9) };
    } catch (err) {
      prices.mainnet = { error: String(err.message) };
    }
  } else {
    prices.mainnet = null;
  }

  measured({
    id: "gas.price",
    metric: "Gaspreis (volatil — mit Zeitstempel)",
    design: "A",
    unit: "gwei",
    provenance: "chain",
    value: prices,
    includes: ["a single eth_gasPrice observation per endpoint, at the timestamp in provenance.takenAt"],
    excludes: ["any averaging over time — one observation is one observation"],
    notes:
      "A SPOT price, not a distribution: repeating eth_gasPrice would measure the endpoint's oracle, not " +
      "the market. Gas units are deterministic and belong in gas.totalTx; this row is the volatile half and " +
      "must be re-quoted with its timestamp. Mainnet is null unless --mainnet-rpc is given — §13 asks for " +
      "'Amoy + Mainnet', and the gas UNITS are identical on both (same bytecode, same calldata); only price differs.",
  });

  // ── Deployment receipts: real gasUsed for transactions that actually happened.
  const dep = cfg.deployment;
  const txs = [
    ["trustAnchorRegistry", dep?.trustAnchorRegistryTx],
    ["ethereumDidRegistry", dep?.ethereumDidRegistryTx],
  ].filter(([, tx]) => tx);
  if (txs.length === 0) {
    unavailable({
      id: "gas.deployment",
      metric: "Gas — einmalige Contract-Deployments",
      design: "A",
      unit: "gas",
      provenance: "chain",
      reason: "no deployment transaction hashes in contracts/deployments/amoy.json",
      precondition: "a recorded deployment",
    });
  } else {
    const deployGas = {};
    for (const [name, tx] of txs) {
      try {
        const r = await rpc.send("eth_getTransactionReceipt", [tx]);
        deployGas[name] = r
          ? {
              gasUsed: parseInt(r.gasUsed, 16),
              effectiveGasPriceWei: parseInt(r.effectiveGasPrice, 16),
              effectiveGasPriceGwei: round(parseInt(r.effectiveGasPrice, 16) / 1e9),
              costPol: roundPol((parseInt(r.gasUsed, 16) * parseInt(r.effectiveGasPrice, 16)) / 1e18),
              blockNumber: parseInt(r.blockNumber, 16),
              status: r.status === "0x1" ? "success" : "reverted",
              txHash: tx,
            }
          : { error: "receipt not found" };
      } catch (err) {
        deployGas[name] = { error: String(err.message) };
      }
    }
    measured({
      id: "gas.deployment",
      metric: "Gas — einmalige Contract-Deployments",
      design: "A",
      unit: "gas",
      provenance: "chain",
      value: deployGas,
      includes: ["real gasUsed and the real effectiveGasPrice actually paid, from the mined receipts"],
      excludes: ["anything recurring — this is paid once per chain, ever"],
      notes:
        "The only Design A gas figures in this report that come from transactions that REALLY HAPPENED. " +
        "They are also a cross-check on the instrument: these receipts must agree with contracts/README.md.",
    });
  }

  // ── The ceremony transactions themselves: nothing to read yet.
  unavailable({
    id: "gas.realCeremonyTx",
    metric: "Gas — reale Zeremonie-Transaktionen (claimProduct / setIssuer / anchor, gasUsed aus Receipts)",
    design: "A",
    unit: "gas",
    provenance: "chain",
    reason:
      "no claimProduct, setIssuer or anchor transaction has been submitted to Amoy — the AnchorTx outbox is empty",
    precondition:
      "one Design A publication driven end to end: brand claims the product, authorises issuers, and the " +
      "relayer drains one anchor to a confirmed receipt",
    notes:
      "Until then gas.totalTx (Foundry, cold slots, corroborated by a local-node cast send) is the defensible " +
      "figure. contracts/README.md records that a real cast send matched it exactly for claimProduct and anchor, " +
      "and to within 12 gas for setIssuer — signature bytes differ per key and a zero calldata byte costs 4 gas " +
      "against 16, so the live figure moves slightly.",
  });

  return prices;
}

/**
 * Cost = gas × price. Computed, not measured, and labelled as such — and the USD
 * leg is refused outright without an explicit rate. §24 quotes "$0.002–0.008 pro
 * Publikation"; converting to dollars needs a POL/USD rate, and a rate scraped
 * from a price API at run time is unciteable and irreproducible.
 */
function measureGasCost(cfg, totals, prices) {
  if (!totals || !prices?.amoy?.wei) {
    unavailable({
      id: "gas.costPerPublication",
      metric: "Gaskosten pro Publikation (Anker; + einmalig Claim/Autorisierung)",
      design: "A",
      unit: "POL",
      provenance: "chain",
      reason: !totals ? "gas.totalTx was not measured" : "gas.price was not measured",
      precondition: "both a gas-unit source and a live gas price",
    });
    return;
  }
  const priceWei = BigInt(prices.amoy.wei);
  const pol = (gas) => roundPol((gas * Number(priceWei)) / 1e18);
  const value = {
    recurringPerPublication: { op: "anchor", gas: totals.anchor, pol: pol(totals.anchor) },
    oncePerProduct: { op: "claimProduct", gas: totals.claimProduct, pol: pol(totals.claimProduct) },
    oncePerAuthorisedIssuer: { op: "setIssuer", gas: totals.setIssuer, pol: pol(totals.setIssuer) },
    gasPriceGwei: prices.amoy.gwei,
  };
  // A 5-actor passport, the killer-demo shape: one claim, five authorisations,
  // one anchor. Spelled out because it is the figure §24's dollar range refers to.
  const fiveActor = totals.claimProduct + 5 * totals.setIssuer + totals.anchor;
  value.fiveActorFirstPublication = { gas: fiveActor, pol: pol(fiveActor) };

  measured({
    id: "gas.costPerPublication",
    metric: "Gaskosten pro Publikation (Anker; + einmalig Claim/Autorisierung)",
    design: "A",
    unit: "POL",
    provenance: "chain",
    value,
    includes: ["measured gas units × the gas price observed at provenance.takenAt"],
    excludes: [
      "USD conversion (see gas.costUsd)",
      "any claim that this price will hold — gas price is volatile and this is one observation",
    ],
    notes:
      "Paid by the platform relayer and re-billed in euros (§19 gas abstraction). No supply-chain actor and " +
      "no brand ever holds POL — the only funded wallet in the system is the platform treasury.",
  });

  if (cfg.polUsd === null) {
    unavailable({
      id: "gas.costUsd",
      metric: "Gaskosten in USD (für §24's Dollar-Spalte)",
      design: "A",
      unit: "USD",
      provenance: "chain",
      reason:
        "no POL/USD rate was supplied, and this harness deliberately does not fetch one — a rate scraped " +
        "from a price API at run time is unciteable and irreproducible in a thesis",
      precondition: "--pol-usd <rate>, with a source and a date the thesis can cite",
    });
  } else {
    measured({
      id: "gas.costUsd",
      metric: "Gaskosten in USD (für §24's Dollar-Spalte)",
      design: "A",
      unit: "USD",
      provenance: "chain",
      value: {
        rateUsedPolUsd: cfg.polUsd,
        // roundPol, not round: §24 quotes "$0.002–0.008 pro Publikation", so
        // three decimal places would quantise the answer to the width of the
        // claim being tested.
        recurringPerPublication: roundPol(value.recurringPerPublication.pol * cfg.polUsd),
        fiveActorFirstPublication: roundPol(value.fiveActorFirstPublication.pol * cfg.polUsd),
      },
      includes: ["gas × price × the rate supplied on the command line"],
      excludes: ["any independent verification of that rate — it is an input, not a measurement"],
      notes: "The rate is an ARGUMENT. Cite it with its source and date in the thesis.",
    });
  }

  // Two rows that exist to prevent a false zero and a false equivalence.
  structural({
    id: "gas.perActorDid",
    metric: "Gaskosten pro Akteur-DID",
    design: "A",
    unit: "gas",
    provenance: "structural",
    value: 0,
    notes:
      "Exactly zero, and known by construction rather than by measurement: a did:ethr identifier is DERIVED " +
      "from the address (did:ethr:<chain>:0x…), so it exists the moment a key exists. ERC-1056 is consulted " +
      "only for CHANGES (rotation, delegation, revocation); an unchanged DID has no registry entry and needs " +
      "no transaction. This is the row that makes §24's onboarding claim affordable, so it is stated as a " +
      "design property rather than smuggled in as a measured 0.",
  });

  notApplicable({
    id: "gas.designB",
    metric: "Gaskosten — Design B",
    design: "B",
    unit: "gas",
    provenance: "structural",
    reason:
      "Design B touches no chain at all. Plain B — the deployed status quo (§15) — signs centrally and does " +
      "not anchor, so there is no transaction to price. Reporting '0' here would be a FALSE EQUIVALENCE: it " +
      "would read as 'Design B does the same thing for free' rather than 'Design B does not do this'.",
  });
}

/*
 * §7 Measurement C — time-to-anchor
 */

function measureTimeToAnchor(cfg, db) {
  const avail = db.available();
  if (!avail.ok) {
    unavailable({
      id: "anchor.timeToConfirm",
      metric: "Time-to-Anchor (Outbox-Queue → bestätigter Receipt)",
      design: "A",
      unit: "ms",
      provenance: "platform",
      reason: avail.why,
      precondition: `a reachable database (--db-container, default ${cfg.dbContainer})`,
    });
    return;
  }

  let rows;
  try {
    rows = db.query(
      `select coalesce(status,'?') || '|' || coalesce(kind,'?') || '|' ||
              coalesce(extract(epoch from ("confirmedAt" - "createdAt"))*1000, -1)::text
       from "AnchorTx";`,
    );
  } catch (err) {
    unavailable({
      id: "anchor.timeToConfirm",
      metric: "Time-to-Anchor (Outbox-Queue → bestätigter Receipt)",
      design: "A",
      unit: "ms",
      provenance: "platform",
      reason: `AnchorTx could not be read: ${err.message}`,
      precondition: "a migrated database containing the AnchorTx outbox table",
    });
    return;
  }

  const parsed = rows
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [status, kind, ms] = l.split("|");
      return { status, kind, ms: Number(ms) };
    });
  const byStatus = {};
  for (const r of parsed) byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
  const confirmed = parsed.filter((r) => r.status === "confirmed" && r.ms >= 0).map((r) => r.ms);

  if (confirmed.length === 0) {
    unavailable({
      id: "anchor.timeToConfirm",
      metric: "Time-to-Anchor (Outbox-Queue → bestätigter Receipt)",
      design: "A",
      unit: "ms",
      provenance: "platform",
      reason: `the AnchorTx outbox holds ${parsed.length} row(s) and none is confirmed with both timestamps`,
      precondition:
        "at least one anchor driven to a confirmed receipt — i.e. Phase 5 ceremony complete and the relayer " +
        "worker running against a funded treasury wallet on Amoy",
      detail: { totalRows: parsed.length, byStatus },
      notes:
        "This row costs nothing to fill once anchors exist: createdAt and confirmedAt are already written by " +
        "the outbox and the relayer. It needs no new instrumentation and no polling.",
    });
    return;
  }

  measured({
    id: "anchor.timeToConfirm",
    metric: "Time-to-Anchor (Outbox-Queue → bestätigter Receipt)",
    design: "A",
    unit: "ms",
    provenance: "platform",
    dist: describe(confirmed),
    includes: [
      "outbox queue wait (nextTryAt scheduling, relayer poll interval)",
      "transaction broadcast",
      "Polygon block time and the relayer's confirmation depth",
    ],
    excludes: ["the publish itself — the clock starts when the AnchorTx row is created"],
    detail: { totalRows: parsed.length, byStatus },
    notes:
      "Read from stored timestamps, NOT re-measured by polling: polling would measure this harness's poll " +
      "interval rather than the system's. Note this is dominated by the relayer's scheduling policy, which is " +
      "an implementation choice, not a property of the chain.",
  });
}

/*
 * §8 Measurement D — onboarding and signing latency
 */

function measureOnboardingAndSigning(cfg) {
  unavailable({
    id: "onboarding.designA",
    metric: "tKey-Onboarding-Zeit (Google-Login → did:ethr registriert) — §13 PRIMÄRMETRIK",
    design: "A",
    unit: "ms",
    provenance: "platform",
    reason:
      "the tKey ceremony is browser-side (OAuth redirect, 2-of-3 share reconstruction, key derivation in the " +
      "page) and Phase 4 identity — Web3Auth login, wallet-login endpoints, org wallet binding — is not shipped",
    precondition:
      "Phase 4 complete, plus ONE of: (a) the frontend emitting performance marks at login-start and " +
      "did-bound, which this harness would read; or (b) a headless browser driving the real login. " +
      "(b) is the defensible one — it times what a user actually waits for.",
    notes:
      "§7 and §24 claim 30–60 s. That is an ESTIMATE and is currently unverified. It is also the single most " +
      "load-bearing number in the onboarding argument (the Minespider failure was an onboarding failure), so " +
      "it should not ship as an estimate.",
  });

  notApplicable({
    id: "signing.designB.actor",
    metric: "Akteur-Signierlatenz — Design B",
    design: "B",
    unit: "ms",
    provenance: "structural",
    reason:
      "Design B actors never sign. The platform signs the whole graph centrally at publish time with its own " +
      "key — that IS the status quo this thesis is arguing against. There is no actor-side signing step to " +
      "time, so this is n/a rather than the '~0 Sek.' §24 currently prints. '0' would imply Design B does the " +
      "same thing instantly; it does not do it at all.",
  });

  unavailable({
    id: "signing.designA.ceremony",
    metric: "tKey-Signierlatenz (Sign-Button → VC auf dem Server)",
    design: "A",
    unit: "ms",
    provenance: "platform",
    reason:
      "the signing ceremony (Phase 5) is being built — client-side ES256K-R signing, attestation upload and " +
      "verification, PendingAttestation staleness — and the operator-side signing UI does not exist yet",
    precondition:
      "Phase 5 complete, then a headless-browser or instrumented-frontend timer from the sign action to the " +
      "attestation being accepted by the upload route",
    notes: "§24 estimates 0.5–1.2 s. Unverified.",
  });

  // ── Design B, platform side. Implemented; opt-in because it writes.
  const gate = (id, metric, extra) => {
    if (cfg.publishRuns === 0 && id === "signing.designB.platformPublish") return true;
    if (cfg.onboardingRuns === 0 && id === "onboarding.designB") return true;
    return false;
  };

  if (gate("signing.designB.platformPublish")) {
    unavailable({
      id: "signing.designB.platformPublish",
      metric: "Plattform-Signierlatenz — Design B (POST /api/dpps/:id/publish)",
      design: "B",
      unit: "ms",
      provenance: "platform",
      reason: "not run: this measurement MUTATES (each run freezes a new PassportVersion), so it is opt-in",
      precondition: "--publish-runs <n> --api-base <url> --api-token <jwt>, against a dev instance",
      notes:
        "This is the closest Design B analogue to Design A's signing ceremony, but it is NOT the same quantity: " +
        "it covers the platform signing the entire credential graph at once, not one actor signing one " +
        "contribution. Compare with care, and only after saying so.",
    });
  }

  if (gate("onboarding.designB")) {
    unavailable({
      id: "onboarding.designB",
      metric: "Onboarding-Zeit — Design B (Registrierung → Plattform-Issuer bereit)",
      design: "B",
      unit: "ms",
      provenance: "platform",
      reason: "not run: this measurement MUTATES (each run creates an organization), so it is opt-in",
      precondition: "--onboarding-runs <n> --api-base <url>, against a dev instance",
      notes:
        "§24 estimates 10–30 s for Design B. Note that the technical portion — did:web document plus a " +
        "platform-held signing key — is server-side and fast; most of the estimate is human form-filling, " +
        "which is the same in both designs and therefore not the discriminating quantity.",
    });
  }
}

/**
 * The opt-in mutating measurements. Kept in one function so the guard rails —
 * localhost-only, explicit run count, explicit token — are all visible together.
 */
async function measureMutating(cfg) {
  if (cfg.publishRuns === 0 && cfg.onboardingRuns === 0) return;
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(cfg.apiBase ?? "");
  if (!cfg.apiBase || (!isLocal && !cfg.allowRemoteMutation)) {
    // Refusing is the correct behaviour: these write to whatever they point at.
    for (const id of ["signing.designB.platformPublish", "onboarding.designB"]) {
      unavailable({
        id,
        metric: id === "onboarding.designB" ? "Onboarding-Zeit — Design B" : "Plattform-Signierlatenz — Design B",
        design: "B",
        unit: "ms",
        provenance: "platform",
        reason: !cfg.apiBase
          ? "--api-base was not given"
          : "refusing to run a mutating measurement against a non-localhost target",
        precondition: "--api-base http://localhost:3001 (or --allow-remote-mutation, which you should not need)",
      });
    }
    return;
  }

  if (cfg.publishRuns > 0) {
    if (!cfg.apiToken || !cfg.publishPassportId) {
      unavailable({
        id: "signing.designB.platformPublish",
        metric: "Plattform-Signierlatenz — Design B (POST /api/dpps/:id/publish)",
        design: "B",
        unit: "ms",
        provenance: "platform",
        reason: !cfg.apiToken ? "--api-token was not given" : "--publish-passport-id was not given",
        precondition: "--publish-runs <n> --api-base <url> --api-token <jwt> --publish-passport-id <id>",
      });
    } else {
      const samples = [];
      let lastStatus = null;
      const url = `${cfg.apiBase.replace(/\/$/, "")}/api/dpps/${cfg.publishPassportId}/publish`;
      for (let i = 0; i < cfg.warmup + cfg.publishRuns; i++) {
        const t0 = process.hrtime.bigint();
        const res = await fetch(url, {
          method: "POST",
          headers: { authorization: `Bearer ${cfg.apiToken}`, "content-type": "application/json" },
          body: "{}",
        });
        await res.text();
        const t1 = process.hrtime.bigint();
        lastStatus = res.status;
        if (i >= cfg.warmup) samples.push(Number(t1 - t0) / 1e6);
      }
      if (lastStatus >= 400) {
        unavailable({
          id: "signing.designB.platformPublish",
          metric: "Plattform-Signierlatenz — Design B (POST /api/dpps/:id/publish)",
          design: "B",
          unit: "ms",
          provenance: "platform",
          reason: `the publish endpoint answered HTTP ${lastStatus} — nothing was timed that represents a publish`,
          precondition: "a valid token with a write role and a publishable passport id",
        });
      } else {
        measured({
          id: "signing.designB.platformPublish",
          metric: "Plattform-Signierlatenz — Design B (POST /api/dpps/:id/publish)",
          design: "B",
          unit: "ms",
          provenance: "platform",
          dist: describe(samples),
          includes: [
            "HTTP round trip to the platform",
            "credential issuance for every tier (eddsa-rdfc-2022 over URDNA2015)",
            "snapshot freeze, version-hash, Merkle root, audit-chain append",
          ],
          excludes: ["any actor-side work — in Design B there is none"],
          detail: { httpStatus: lastStatus, target: cfg.apiBase },
          notes: "MUTATING: this froze one new PassportVersion per run.",
        });
      }
    }
  }

  if (cfg.onboardingRuns > 0) {
    unavailable({
      id: "onboarding.designB",
      metric: "Onboarding-Zeit — Design B (Registrierung → Plattform-Issuer bereit)",
      design: "B",
      unit: "ms",
      provenance: "platform",
      reason:
        "not implemented as an automated driver: registration is a multi-step flow (register, verify, " +
        "provision) whose exact contract is still moving, and a half-driven flow would time the wrong span",
      precondition:
        "a stable registration contract, then a driver that stops the clock when the org's did:web document " +
        "and signing key exist — not when the HTTP call returns",
    });
  }
}

/* ════════════════════════════════════════════════════════════════════════════
 * §9  Measurement E — the rows that are prices, not measurements
 * ════════════════════════════════════════════════════════════════════════════ */

function measureServiceCost(cfg) {
  if (cfg.web3authUsdPerMaw === null) {
    unavailable({
      id: "serviceCost.web3auth",
      metric: "tKey-Servicekosten (Web3Auth, pro MAW) — §13 versprochen",
      design: "A",
      unit: "USD/MAW",
      provenance: "artifact",
      reason:
        "this is a published LIST PRICE, not an observable quantity — no timer or receipt can produce it, and " +
        "this harness will not scrape a vendor pricing page into a thesis table",
      precondition: "--web3auth-usd-per-maw <rate>, cited in the thesis with the plan tier and the date read",
      notes:
        "§13's RQ3 table promises this row. It is the recurring operational cost of Design A's key custody and " +
        "it has no Design B counterpart (Design B holds its own key). Flagged so it is not silently dropped: it " +
        "is the one RQ3 row that is answered by a citation rather than by this harness.",
    });
  } else {
    measured({
      id: "serviceCost.web3auth",
      metric: "tKey-Servicekosten (Web3Auth, pro MAW)",
      design: "A",
      unit: "USD/MAW",
      provenance: "artifact",
      value: cfg.web3authUsdPerMaw,
      includes: ["the rate supplied on the command line"],
      excludes: ["any verification of it — it is an input"],
      notes: "Cite the plan tier and the date the price was read.",
    });
  }

  notApplicable({
    id: "serviceCost.designB",
    metric: "Key-Custody-Servicekosten — Design B",
    design: "B",
    unit: "USD/MAW",
    provenance: "structural",
    reason:
      "Design B holds one platform key in its own infrastructure and buys no custody service, so there is no " +
      "per-wallet fee. This asymmetry is a real finding — Design A trades a recurring vendor cost for the " +
      "property that the platform cannot sign — and printing '0' would erase it.",
  });
}

/* ════════════════════════════════════════════════════════════════════════════
 * §10  Rendering
 * ════════════════════════════════════════════════════════════════════════════ */

const C = {
  on: true,
  dim: (s) => (C.on ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s) => (C.on ? `\x1b[1m${s}\x1b[0m` : s),
  green: (s) => (C.on ? `\x1b[32m${s}\x1b[0m` : s),
  yellow: (s) => (C.on ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s) => (C.on ? `\x1b[36m${s}\x1b[0m` : s),
  red: (s) => (C.on ? `\x1b[31m${s}\x1b[0m` : s),
};

/** Uncoloured widths, so column alignment does not count ANSI escape bytes. */
const PLAIN_STATE = { measured: "MEASURED", unavailable: "null", "n/a": "n/a", structural: "structural" };

const STATE_LABEL = {
  measured: () => C.green(PLAIN_STATE.measured),
  unavailable: () => C.yellow(PLAIN_STATE.unavailable),
  "n/a": () => C.cyan(PLAIN_STATE["n/a"]),
  structural: () => C.green(PLAIN_STATE.structural),
};

function fmtValue(r) {
  if (r.state === "measured" && r.dist) {
    const d = r.dist;
    // Below QUANTILE_MIN_N the quantiles are null by policy (see describe);
    // what remains true of a tiny sample is its range and its size.
    if (d.median === null) return `n=${d.n}  observed [${d.min}–${d.max}]${r.unit ?? ""}  (too few for quantiles)`;
    return `n=${d.n}  med ${d.median}${r.unit ?? ""}  IQR ${d.p25}–${d.p75}  p95 ${d.p95}  [${d.min}–${d.max}]`;
  }
  if ((r.state === "measured" || r.state === "structural") && r.value !== null) {
    if (typeof r.value === "object") {
      return Object.entries(r.value)
        .map(([k, v]) => `${k}=${typeof v === "object" && v !== null ? (v.gas ?? v.gasUsed ?? v.gwei ?? JSON.stringify(v)) : v}`)
        .join("  ");
    }
    return `${r.value}${r.unit ? " " + r.unit : ""}`;
  }
  return C.dim("—");
}

function renderHuman(report) {
  const out = [];
  const p = report.provenance;
  out.push("");
  out.push(C.bold("  RQ3 — operative Kompromisse: Design A vs. Design B (plain, Status quo)"));
  out.push("");
  out.push(
    C.dim(
      `  ${p.takenAt}   git ${p.git.shortCommit}${p.git.dirty ? C.yellow("+dirty") : ""} (${p.git.branch})   ` +
        `node ${p.runtime.node}   ${p.machine.cpuModel} ×${p.machine.cpuCount}`,
    ),
  );
  out.push(
    C.dim(
      `  chain ${p.chain.chainId} (${p.chain.network})   registry ${p.chain.trustAnchorRegistry}   ` +
        `rpc ${p.chain.rpcHost ?? "none"}   n=${p.parameters.n} warmup=${p.parameters.warmup}`,
    ),
  );
  out.push("");

  // Grouped by CATEGORY, not by design, with the design as a column — the whole
  // point of the table is to read Design A's row against Design B's for the same
  // quantity, and grouping by design puts the two halves pages apart.
  const rows = report.measurements;
  const w = Math.min(76, Math.max(...rows.map((r) => r.metric.length)));
  const sw = Math.max(...rows.map((r) => PLAIN_STATE[r.state].length));
  let lastCat = null;
  for (const r of rows) {
    if (r.category !== lastCat) {
      out.push("");
      out.push(C.bold(`  ── ${r.category} ` + "─".repeat(Math.max(2, w + 12 - r.category.length))));
      lastCat = r.category;
    }
    const pad = " ".repeat(Math.max(0, sw - PLAIN_STATE[r.state].length));
    const label = r.metric.length > w ? r.metric.slice(0, w - 1) + "…" : r.metric;
    out.push(`  ${C.bold((r.design ?? "–").padEnd(2))} ${label.padEnd(w)}  ${STATE_LABEL[r.state](r)}${pad}  ${fmtValue(r)}`);
    if (r.reason) out.push(C.dim(`       ${wrap(`why:   ${r.reason}`)}`));
    if (r.precondition) out.push(C.dim(`       ${wrap(`needs: ${r.precondition}`)}`));
    if (r.state === "measured" && r.provenance) out.push(C.dim(`       ${wrap(`taken: ${r.provenance}`)}`));
  }

  out.push("");
  const c = report.counts;
  out.push(
    `  ${c.measured} measured · ${c.structural} structural · ${C.yellow(String(c.unavailable))} unavailable (null) · ${C.cyan(String(c["n/a"]))} n/a · ${c.failed ? C.red(String(c.failed) + " failed") : "0 failed"}`,
  );
  const verdictColor = report.verdict === "COMPLETE" ? C.green : report.verdict === "FAILED" ? C.red : C.yellow;
  out.push(`  verdict: ${verdictColor(C.bold(report.verdict))}  (exit ${report.exitCode})`);
  if (report.verdict === "INCOMPLETE") {
    out.push(
      C.dim(
        "  INCOMPLETE is not a failure of the harness — it is the honest state of the system. Each null above\n" +
          "  carries the precondition that would fill it. Report the gaps; do not estimate them.",
      ),
    );
  }
  out.push("");
  return out.join("\n");
}

function wrap(s) {
  const width = 96;
  const words = s.split(/\s+/);
  const lines = [];
  let line = "";
  for (const word of words) {
    if (line.length + word.length + 1 > width) {
      lines.push(line);
      line = "  " + word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.join("\n    ");
}

/** The thesis §24 table, as markdown — so numbers go in without retyping. */
function renderMarkdown(report) {
  // Flattens ONE level of nesting: the gas rows are {op: {gas, pol}} shaped, and
  // a cell that says "see JSON" for the single most quotable number in the
  // thesis defeats the purpose of emitting a table at all.
  const flat = (v) => {
    if (v === null || v === undefined) return null;
    if (typeof v !== "object") return String(v);
    for (const k of ["gas", "gasUsed", "gwei", "pol"]) {
      if (v[k] !== undefined) {
        const extra = v.pol !== undefined && k !== "pol" ? ` (${v.pol} POL)` : "";
        return `${v[k]}${extra}`;
      }
    }
    return null;
  };
  // Long `reason` prose belongs in the JSON; the table needs the first clause.
  const shortReason = (s) => {
    if (!s) return "not measured";
    const first = s.split(/(?<=[.:])\s|\s—\s/)[0].trim();
    return first.length < s.length ? `${first} …` : first;
  };
  const cell = (r) => {
    if (r.state === "measured" && r.dist) {
      if (r.dist.median === null) return `${r.dist.min}–${r.dist.max} ${r.unit} (n=${r.dist.n}, zu wenige für Quantile)`;
      return `${r.dist.median} ${r.unit} (IQR ${r.dist.p25}–${r.dist.p75}, n=${r.dist.n})`;
    }
    if (r.state === "structural" && typeof r.value !== "object") return `**${r.value}** ${r.unit ?? ""} (by construction)`;
    if (r.state === "measured" && typeof r.value === "object" && r.value !== null) {
      const parts = Object.entries(r.value)
        .map(([k, v]) => {
          const f = flat(v);
          return f === null ? null : `${k}: ${f}`;
        })
        .filter(Boolean);
      return parts.length ? parts.join("; ") : "see JSON";
    }
    if (r.state === "measured") return `${r.value} ${r.unit ?? ""}`;
    if (r.state === "n/a") return `n/a — ${shortReason(r.reason)}`;
    return `*null* — ${shortReason(r.reason)}`;
  };
  const lines = [
    `<!-- generated by scripts/measure-rq3.mjs at ${report.provenance.takenAt} -->`,
    `<!-- git ${report.provenance.git.shortCommit}${report.provenance.git.dirty ? "+dirty" : ""} · chain ${report.provenance.chain.chainId} · n=${report.provenance.parameters.n} -->`,
    "",
    "| Metrik | Design | Wert | Erhoben durch |",
    "| --- | --- | --- | --- |",
  ];
  for (const r of report.measurements) {
    lines.push(`| ${r.metric} | ${r.design ?? "–"} | ${cell(r)} | ${r.provenance ?? "–"} |`);
  }
  return lines.join("\n");
}

function renderLatex(report) {
  const esc = (s) => String(s).replace(/([&%$#_{}])/g, "\\$1").replace(/—/g, "---").replace(/→/g, "$\\rightarrow$");
  const cell = (r) => {
    if (r.state === "measured" && r.dist) {
      if (r.dist.median === null) return esc(`${r.dist.min}--${r.dist.max} (n=${r.dist.n}, zu wenige f\u00fcr Quantile)`);
      return esc(`${r.dist.median} (IQR ${r.dist.p25}--${r.dist.p75}, n=${r.dist.n})`);
    }
    if (r.state === "structural" && typeof r.value !== "object") return `\\textbf{${esc(r.value)}}`;
    if (r.state === "n/a") return "n/a";
    if (r.state === "measured") return "s.\\ Anhang";
    return "\\textit{null}";
  };
  const lines = [
    `% generated by scripts/measure-rq3.mjs at ${report.provenance.takenAt}`,
    `% git ${report.provenance.git.shortCommit}${report.provenance.git.dirty ? "+dirty" : ""}, chain ${report.provenance.chain.chainId}, n=${report.provenance.parameters.n}`,
    "\\begin{tabular}{llll}",
    "\\toprule",
    "Metrik & Design & Wert & Erhoben durch \\\\",
    "\\midrule",
  ];
  for (const r of report.measurements) {
    lines.push(`${esc(r.metric)} & ${r.design ?? "--"} & ${cell(r)} & ${esc(r.provenance ?? "--")} \\\\`);
  }
  lines.push("\\bottomrule", "\\end{tabular}");
  return lines.join("\n");
}

/*
 * §11 Bundle acquisition
 */

async function acquireBundle(cfg, db) {
  const tmp = join(os.tmpdir(), `rq3-bundle-${process.pid}.json`);

  if (cfg.bBundle) {
    if (!existsSync(cfg.bBundle)) return { path: null, why: `--b-bundle ${cfg.bBundle} does not exist` };
    return finish(cfg.bBundle, "--bundle (file)");
  }

  if (cfg.bExportUrl) {
    try {
      const res = await fetch(cfg.bExportUrl);
      if (!res.ok) return { path: null, why: `--b-export-url answered HTTP ${res.status}` };
      writeFileSync(tmp, await res.text());
      return finish(tmp, `--b-export-url ${new URL(cfg.bExportUrl).host}`);
    } catch (err) {
      return { path: null, why: `--b-export-url fetch failed: ${err.message}` };
    }
  }

  const avail = db.available();
  if (!avail.ok) return { path: null, why: `no bundle source: ${avail.why}` };
  try {
    // The query documented in scripts/README.md: the four members the Merkle
    // root is computed over, straight from the jsonb columns, plus the product
    // DID the verifier needs to key its chain lookups.
    const sql = `select jsonb_build_object(
        'passportId', v."passportId", 'version', v.version, 'hash', v.hash,
        'productDid', pr.did, 'snapshot', v.snapshot::jsonb, 'credentials', v.credentials::jsonb
      )::text
      from "PassportVersion" v
      join "Passport" p on p.id = v."passportId"
      join "Product"  pr on pr.id = p."productId"
      where p.status = 'published'
      order by v.version desc limit 1;`;
    const json = db.query(sql);
    if (!json) return { path: null, why: "no published PassportVersion in the database" };
    writeFileSync(tmp, json);
    return finish(tmp, `database ${cfg.dbContainer} (newest published version)`);
  } catch (err) {
    return { path: null, why: `database bundle export failed: ${err.message}` };
  }

  function finish(path, source) {
    const raw = readFileSync(path, "utf8");
    let parsed = null;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { path: null, why: `${source} is not valid JSON` };
    }
    const b = parsed.passportVersion ?? parsed.bundle ?? parsed.payload ?? parsed;
    return {
      path,
      source,
      bytes: Buffer.byteLength(raw),
      credentialCount: Array.isArray(b.credentials) ? b.credentials.length : null,
      version: b.version ?? null,
      passportId: b.passportId ?? null,
      productDid: b.productDid ?? null,
      design: detectBundleDesign(b),
      // The verifier's fast-path hint (same two spellings it accepts). Design A
      // only; decides whether the full row needs an anchor sweep window at all.
      anchorTxHash:
        (typeof b.anchorTxHash === "string" ? b.anchorTxHash : null) ??
        (typeof b.anchor?.txHash === "string" ? b.anchor.txHash : null),
      why: null,
    };
  }
}

/**
 * Which design produced this bundle — read from the CREDENTIALS, never from the
 * flag that delivered it.
 */
function detectBundleDesign(b) {
  const creds = Array.isArray(b?.credentials) ? b.credentials : [];
  if (creds.length === 0) return null;
  let enveloped = 0;
  let embedded = 0;
  for (const c of creds) {
    const types = Array.isArray(c?.type) ? c.type : [c?.type];
    const isEnveloped =
      types.includes("EnvelopedVerifiableCredential") || String(c?.id ?? "").startsWith("data:application/vc");
    const isEmbedded = c?.proof != null;
    if (isEnveloped && !isEmbedded) enveloped++;
    else if (isEmbedded && !isEnveloped) embedded++;
  }
  if (enveloped === creds.length) return "A";
  if (embedded === creds.length) return "B";
  return null;
}

/* ════════════════════════════════════════════════════════════════════════════
 * §12  CLI + main
 * ════════════════════════════════════════════════════════════════════════════ */

function parseArgs(argv) {
  const cfg = {
    n: 30, // §12: N ≥ 30
    nNetwork: null, // network sets default to n unless overridden; see below
    warmup: 3,
    json: false,
    markdown: false,
    latex: false,
    out: null,
    keepSamples: false,
    bBundle: null,
    bExportUrl: null,
    bProdUrl: null,
    dbContainer: "trustdpp-db-dev",
    dbUser: "trustdpp",
    dbName: "trustdpp",
    rpc: null,
    mainnetRpcUrl: null,
    polUsd: null,
    web3authUsdPerMaw: null,
    publishRuns: 0,
    onboardingRuns: 0,
    apiBase: null,
    apiToken: null,
    publishPassportId: null,
    allowRemoteMutation: false,
  };
  const num = (v, what) => {
    const x = Number(v);
    if (!Number.isFinite(x)) usage(`${what} must be a number`);
    return x;
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--n": cfg.n = num(argv[++i], "--n"); break;
      case "--n-network": cfg.nNetwork = num(argv[++i], "--n-network"); break;
      case "--warmup": cfg.warmup = num(argv[++i], "--warmup"); break;
      case "--json": cfg.json = true; C.on = false; break;
      case "--markdown": cfg.markdown = true; break;
      case "--latex": cfg.latex = true; break;
      case "--out": cfg.out = argv[++i]; break;
      case "--keep-samples": cfg.keepSamples = true; break;
      // `--bundle` is the honest name now that the design is detected from the
      // credentials; `--b-bundle` remains as an alias because runbooks and the
      // 08-08 artifact's own notes reference it.
      case "--bundle":
      case "--b-bundle": cfg.bBundle = argv[++i]; break;
      case "--b-export-url": cfg.bExportUrl = argv[++i]; break;
      case "--b-prod-url": cfg.bProdUrl = argv[++i]; break;
      case "--db-container": cfg.dbContainer = argv[++i]; break;
      case "--db-user": cfg.dbUser = argv[++i]; break;
      case "--db-name": cfg.dbName = argv[++i]; break;
      case "--rpc": cfg.rpc = argv[++i]; break;
      case "--mainnet-rpc": cfg.mainnetRpcUrl = argv[++i]; break;
      case "--pol-usd": cfg.polUsd = num(argv[++i], "--pol-usd"); break;
      case "--web3auth-usd-per-maw": cfg.web3authUsdPerMaw = num(argv[++i], "--web3auth-usd-per-maw"); break;
      case "--publish-runs": cfg.publishRuns = num(argv[++i], "--publish-runs"); break;
      case "--onboarding-runs": cfg.onboardingRuns = num(argv[++i], "--onboarding-runs"); break;
      case "--api-base": cfg.apiBase = argv[++i]; break;
      case "--api-token": cfg.apiToken = argv[++i]; break;
      case "--publish-passport-id": cfg.publishPassportId = argv[++i]; break;
      case "--allow-remote-mutation": cfg.allowRemoteMutation = true; break;
      case "--no-color": C.on = false; break;
      case "-h":
      case "--help": usage(null); break;
      default: usage(`unknown option: ${a}`);
    }
  }
  // Network-bound repetitions default to a smaller n than local ones: 30 runs
  // that each pay a live DNS + TLS round trip take minutes and measure the link
  // as much as the design. The reduced n is REPORTED per row (dist.n), so it is
  // never mistaken for the headline n.
  if (cfg.nNetwork === null) cfg.nNetwork = Math.min(cfg.n, 10);
  if (cfg.n < 1 || cfg.warmup < 0) usage("--n must be ≥ 1 and --warmup ≥ 0");
  if (!C.on) {
    for (const k of Object.keys(STATE_LABEL)) {
      const plain = { measured: "MEASURED", unavailable: "null", "n/a": "n/a", structural: "structural" }[k];
      STATE_LABEL[k] = () => plain;
    }
  }
  return cfg;
}

function usage(err) {
  const text = `
measure-rq3 — the RQ3 measurement harness

  node scripts/measure-rq3.mjs [options]

  --n <count>              repetitions per latency metric            (default 30)
  --n-network <count>      repetitions for network-bound metrics  (default min(n,10))
  --warmup <count>         discarded runs before each set            (default 3)
  --json | --markdown | --latex | --out <path> | --keep-samples | --no-color

  --bundle <path>          export bundle to verify — design detected from its credentials
  --b-bundle <path>        alias of --bundle (historical name)
  --b-export-url <url>     …or fetch it from a running platform
  --b-prod-url <url>       PRODUCTION baseline: the public passport projection,
                           e.g. https://app.trustdpp.co/api/public/passports/<id>
                           Adds three rows (compute / full / did:web-only) beside
                           the bundle rows rather than replacing them.
  --db-container <name>    Postgres container            (default trustdpp-db-dev)
  --db-user / --db-name    psql credentials                (default trustdpp/trustdpp)

  --rpc <url>              JSON-RPC endpoint (or $RPC_URL / $AMOY_RPC_URL /
                           AMOY_RPC_URL in contracts/.env). Only the host is printed.
  --mainnet-rpc <url>      second endpoint, for the mainnet gas-price column
  --pol-usd <rate>         POL/USD. Never fetched — cite it.
  --web3auth-usd-per-maw <rate>   Web3Auth list price. A citation, not a measurement.

  MUTATING, opt-in, localhost only:
  --publish-runs <n> --api-base <url> --api-token <jwt> --publish-passport-id <id>
  --onboarding-runs <n>
  --allow-remote-mutation

  exit 0 COMPLETE · 1 FAILED · 2 usage · 3 INCOMPLETE (some measurements are null)
`;
  if (err) {
    console.error(`measure-rq3: ${err}\n${text}`);
    process.exit(2);
  }
  console.log(text);
  process.exit(0);
}

async function main() {
  const cfg = parseArgs(process.argv);

  // Deployment addresses: the same file verify-passport.mjs defaults to, read
  // rather than hardcoded for the same reason.
  const depPath = join(REPO, "contracts", "deployments", "amoy.json");
  cfg.deployment = existsSync(depPath) ? JSON.parse(readFileSync(depPath, "utf8")) : null;

  const discovered = discoverRpc(cfg.rpc);
  cfg.rpcUrl = discovered.url;
  cfg.rpcSource = discovered.source;

  const db = makeDb({ container: cfg.dbContainer, user: cfg.dbUser, name: cfg.dbName });
  const bundle = await acquireBundle(cfg, db);
  cfg.bBundleSource = bundle.path ? bundle.source : `unavailable (${bundle.why})`;

  const rpc = makeRpc(cfg.rpcUrl);

  // Order matters only for readability of the table.
  measureVerification(cfg, bundle);
  await measureProductionBaseline(cfg);
  measureVerificationUnfilled(cfg, bundle);
  const execGas = measureGasFromSnapshot();
  const totals = measureGasTotalTx(cfg);
  const prices = await measureGasOnChain(cfg, rpc);
  measureGasCost(cfg, totals, prices);
  measureTimeToAnchor(cfg, db);
  measureOnboardingAndSigning(cfg);
  await measureMutating(cfg);
  measureServiceCost(cfg);

  // Stable ordering by category, then by emission order within it — so the
  // table is reproducible run to run and diffable between runs.
  const catIndex = new Map(CATEGORIES.map(([, label], i) => [label, i]));
  results.forEach((r, i) => (r._seq = i));
  results.sort(
    (a, b) => (catIndex.get(a.category) ?? 99) - (catIndex.get(b.category) ?? 99) || a._seq - b._seq,
  );
  for (const r of results) delete r._seq;

  const counts = { measured: 0, unavailable: 0, "n/a": 0, structural: 0, failed: 0 };
  for (const r of results) counts[r.state] = (counts[r.state] ?? 0) + 1;

  // Mirrors verify-passport.mjs deliberately: "incomplete" is not "complete",
  // and the exit code must say so without a human reading the table.
  const verdict = counts.failed > 0 ? "FAILED" : counts.unavailable > 0 ? "INCOMPLETE" : "COMPLETE";
  const exitCode = verdict === "FAILED" ? 1 : verdict === "INCOMPLETE" ? 3 : 0;

  const report = {
    tool: "measure-rq3",
    formatVersion: 1,
    provenance: collectProvenance(cfg, cfg.deployment),
    bundle: bundle.path
      ? {
          source: bundle.source,
          bytes: bundle.bytes,
          credentialCount: bundle.credentialCount,
          passportId: bundle.passportId,
          version: bundle.version,
          productDid: bundle.productDid,
        }
      : { source: null, reason: bundle.why },
    measurements: results,
    counts,
    verdict,
    exitCode,
  };

  if (cfg.out) writeFileSync(cfg.out, JSON.stringify(report, null, 2));
  if (cfg.json) console.log(JSON.stringify(report, null, 2));
  else if (cfg.markdown) console.log(renderMarkdown(report));
  else if (cfg.latex) console.log(renderLatex(report));
  else {
    console.log(renderHuman(report));
    if (cfg.out) console.log(C.dim(`  full JSON written to ${cfg.out}\n`));
  }
  process.exit(exitCode);
}

main().catch((err) => {
  console.error(`measure-rq3: ${err.stack ?? err.message}`);
  process.exit(2);
});
