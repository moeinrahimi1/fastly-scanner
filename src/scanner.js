const fs = require("node:fs");
const os = require("node:os");
const { spawn } = require("node:child_process");
const http = require("node:http");

const port = 80;

// ---------- helpers: networking / cidr ----------
function ipToInt(ip) {
  return ip.split(".").map(Number).reduce((a, b) => (a << 8) + b);
}
function intToIp(n) {
  return [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255].join(".");
}
function parseCIDR(cidr) {
  const [base, bitsStr] = cidr.split("/");
  const bits = parseInt(bitsStr, 10);
  if (!base || isNaN(bits) || bits < 0 || bits > 32) throw new Error(`Bad CIDR: ${cidr}`);
  const baseInt = ipToInt(base);
  const mask = bits === 0 ? 0 : ((~0 << (32 - bits)) >>> 0) >>> 0;
  const network = baseInt & mask;
  const size = 2 ** (32 - bits);
  const first = network >>> 0;
  const last = (network + size - 1) >>> 0;
  return { first, last };
}
function list24Blocks(cidr) {
  const { first, last } = parseCIDR(cidr);
  const start24 = first & 0xffffff00;
  const end24 = last & 0xffffff00;
  const blocks = [];
  for (let b = start24; b <= end24; b += 256) blocks.push(b >>> 0);
  return blocks;
}
function sampleIPsIn24(blockStartInt, k) {
  const picks = new Set();
  const candidates = [10, 42, 77, 99, 123, 150, 180, 200, 220, 240].map((x) =>
    Math.min(254, Math.max(1, x))
  );
  let idx = 0;
  while (picks.size < Math.min(k, 254)) {
    const o = candidates[idx % candidates.length] + ((idx / candidates.length) | 0);
    const off = 1 + ((o - 1) % 254);
    picks.add(off);
    idx++;
  }
  return Array.from(picks)
    .slice(0, k)
    .map((off) => intToIp((blockStartInt + off) >>> 0));
}
function ipsOf24(blockStartInt, limit = 256) {
  const ips = [];
  for (let off = 0; off < Math.min(limit, 256); off++) ips.push(intToIp((blockStartInt + off) >>> 0));
  return ips;
}

// ---------- Fastly public IP fetch ----------
async function fetchFastlyCidrs({ timeout = 5000 } = {}) {
  const url = "https://api.fastly.com/public-ip-list";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "smart-scan/1.0", Accept: "application/json" },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`Fastly API HTTP ${res.status}`);
    const json = await res.json();
    const v4 = Array.isArray(json.addresses) ? json.addresses : [];
    if (!v4.length) throw new Error("Fastly API returned no IPv4 addresses");
    return v4;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- cheap TCP:80 open check ----------
function tcpOpen(ip, timeout = 1000) {
  return new Promise((resolve) => {
    const net = require("node:net");
    const sock = new net.Socket();

    const done = (ok) => {
      try {
        sock.destroy();
      } catch {}
      resolve(ok);
    };

    sock.setTimeout(timeout);

    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));

    sock.connect(port, ip);
  });
}

// ---------- optional HTTP HEAD verification ----------
function httpHead(ip, hostHeaderVal, timeout = 1000) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: ip,
        port,
        method: "HEAD",
        path: "/",
        setHost: false,
        timeout,
        headers: hostHeaderVal ? { Host: hostHeaderVal } : {}
      },
      (res) => {
        res.resume();
        resolve(true);
      }
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.on("error", () => resolve(false));
    req.end();
  });
}

// ---------- ping ----------
const isWin = process.platform === "win32";
function pingOnce(ip, timeout = 1000) {
  return new Promise((resolve) => {
    const pingArgs = isWin ? ["-n", "1", "-w", String(timeout), ip] : ["-c", "1", ip];
    const child = spawn("ping", pingArgs);
    let out = "";
    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {}
    }, timeout + 200);

    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (out += d.toString()));
    child.on("close", () => {
      clearTimeout(killer);
      const m = out.match(/time[=<]?\s*([\d.]+)\s*ms/i);
      if (m) return resolve({ ok: true, ms: parseFloat(m[1]) });
      resolve({ ok: false, ms: null });
    });
    child.on("error", () => {
      clearTimeout(killer);
      resolve({ ok: false, ms: null });
    });
  });
}

// ---------- queue ----------
function createQueue(limit) {
  let active = 0;
  const q = [];
  const pump = () => {
    while (active < limit && q.length) {
      active++;
      const job = q.shift();
      job
        .fn()
        .then(job.resolve, job.reject)
        .finally(() => {
          active--;
          pump();
        });
    }
  };
  return (fn) =>
    new Promise((resolve, reject) => {
      q.push({ fn, resolve, reject });
      pump();
    });
}

// ---------- main scan ----------
async function runSmartScan(config, hooks = {}) {
  const {
    cidrs = [],
    hostHeader = "",
    timeoutMs = 1000,
    concurrency = os.cpus().length * 100,
    samplesPer24 = 3,
    expandLimitPer24 = 256
  } = config;

  const onStage = hooks.onStage || (() => {});
  const onProgress = hooks.onProgress || (() => {});
  const onValid = hooks.onValid || (() => {});
  const onLog = hooks.onLog || (() => {});

  // gather cidrs
  let finalCidrs = [...cidrs];
 if (!finalCidrs.length) {
  onLog("No CIDR input provided; fetching from Fastly public IP list…");

  try {
    finalCidrs = await fetchFastlyCidrs({ timeout: 8000 });
    onLog(`Fetched ${finalCidrs.length} CIDR blocks from Fastly.`);
  } catch (e) {
    const msg = e?.message || String(e);
    onLog(`Fastly fetch failed: ${msg}`);
    onLog(`Falling back to local CIDR file...`);

    // fallback file path (relative to project root when running dev)
    const fallbackPath = config.fallbackFile || "cidrs.txt";

    try {
      const text = fs.readFileSync(fallbackPath, "utf8");
      finalCidrs = text
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);

      if (!finalCidrs.length) {
        throw new Error("Fallback file is empty.");
      }

      onLog(`Loaded ${finalCidrs.length} CIDRs from fallback file: ${fallbackPath}`);
    } catch (e2) {
      const msg2 = e2?.message || String(e2);
      throw new Error(
        `Fastly fetch failed AND fallback file could not be loaded.\n` +
          `Fastly error: ${msg}\n` +
          `Fallback error: ${msg2}`
      );
    }
  }
}


  const blocks = finalCidrs.flatMap((c) => list24Blocks(c));
  if (!blocks.length) throw new Error("No /24 blocks to scan.");

  const sampleTargets = [];
  for (const b of blocks) {
    const picks = sampleIPsIn24(b, samplesPer24);
    for (const ip of picks) sampleTargets.push({ block: b, ip });
  }

  const limitQ = createQueue(concurrency);

  // Stage A
  onStage({ name: "A", label: "Stage A (sample)", total: sampleTargets.length });
  let stageADone = 0;

  const hotBlocks = new Set();

  await Promise.all(
    sampleTargets.map((t) =>
      limitQ(async () => {
        const open = await tcpOpen(t.ip, timeoutMs);
        if (open) {
          if (hostHeader) {
            const ok = await httpHead(t.ip, hostHeader, timeoutMs);
            if (ok) hotBlocks.add(t.block);
          } else {
            hotBlocks.add(t.block);
          }
        }

        stageADone++;
        onProgress({ stage: "A", done: stageADone, total: sampleTargets.length });
      })
    )
  );

  // expand list
  const expandTargets = [];
  for (const b of hotBlocks) {
    for (const ip of ipsOf24(b, expandLimitPer24)) expandTargets.push(ip);
  }

  // Stage B
  onStage({ name: "B", label: "Stage B (expand)", total: expandTargets.length });
  let stageBDone = 0;

  const valid = [];

  await Promise.all(
    expandTargets.map((ip) =>
      limitQ(async () => {
        const open = await tcpOpen(ip, timeoutMs);
        if (!open) {
          stageBDone++;
          onProgress({ stage: "B", done: stageBDone, total: expandTargets.length });
          return;
        }

        if (hostHeader) {
          const ok = await httpHead(ip, hostHeader, timeoutMs);
          if (!ok) {
            stageBDone++;
            onProgress({ stage: "B", done: stageBDone, total: expandTargets.length });
            return;
          }
        }

        const p = await pingOnce(ip, timeoutMs);
        if (p.ok && typeof p.ms === "number") {
          const item = { ip, ms: p.ms };
          valid.push(item);
          onValid(item);
        }

        stageBDone++;
        onProgress({ stage: "B", done: stageBDone, total: expandTargets.length });
      })
    )
  );

  valid.sort((a, b) => a.ms - b.ms);

  const txt = valid.map((v) => v.ip).join("\n");
  const csv = "ip,ping_ms\n" + valid.map((v) => `${v.ip},${v.ms.toFixed(3)}`).join("\n");

  return {
    hotBlocks: hotBlocks.size,
    totalBlocks: blocks.length,
    validCount: valid.length,
    valid,
    txt,
    csv
  };
}

module.exports = { runSmartScan, fetchFastlyCidrs };
