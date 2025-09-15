#!/usr/bin/env node
/**
 * Smart CIDR scanner (fast) with Fastly fallback:
 *  A) sample a few IPs per /24 for TCP:80 -> prune dead /24s
 *  B) expand only hot /24s, then ICMP ping + port80 check
 *  C) (optional) HEAD / with Host header to verify CDN/app presence
 *
 * Usage examples:
 *   node smart-scan.js 151.101.0.0/16
 *   node smart-scan.js --file cidrs.txt --concurrency 400 --timeout 1200 --samples-per24 3 --host yourdomain.com
 *   node smart-scan.js            // -> auto-fetch CIDRs from https://api.fastly.com/public-ip-list
 *
 * Output:
 *   - valid.txt (IPs only, sorted by ping ascending)
 *   - valid.csv (ip,ping_ms,from_stage)
 */

const fs = require("fs");
const os = require("os");
const net = require("net");
const { spawn } = require("child_process");
const http = require("http");
const https = require("https");

// ---------- CLI ----------
const args = process.argv.slice(2);
const getFlag = (name, def = null) => {
  const i = args.findIndex(a => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i === -1) return def;
  const [k, v] = args[i].split("=");
  if (v !== undefined) return v;
  const next = args[i+1];
  if (!next || next.startsWith("--")) return true;
  return next;
};

const fileArg = getFlag("file", null);
const hostHeader = getFlag("host", "");             // optional Host: header for HTTP HEAD
const timeoutMs = parseInt(getFlag("timeout", "1000"), 10);
const concurrency = parseInt(getFlag("concurrency", ""), 10) || os.cpus().length * 100;
const samplesPer24 = Math.max(1, parseInt(getFlag("samples-per24", "3"), 10)); // how many IPs to sample per /24
const expandLimitPer24 = parseInt(getFlag("expand-limit", "256"), 10);         // how many IPs to scan in a hot /24 (<=256)
const port = 80;
console.log(concurrency,'hello')
// ---------- helpers: networking / cidr ----------
function ipToInt(ip) { return ip.split(".").map(Number).reduce((a,b)=> (a<<8)+b); }
function intToIp(n) { return [n>>>24,(n>>16)&255,(n>>8)&255,n&255].join("."); }
function parseCIDR(cidr) {
  const [base, bitsStr] = cidr.split("/");
  const bits = parseInt(bitsStr, 10);
  if (!base || isNaN(bits) || bits<0 || bits>32) throw new Error(`Bad CIDR: ${cidr}`);
  const baseInt = ipToInt(base);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const network = baseInt & mask;
  const size = 2 ** (32 - bits);
  const first = network;
  const last  = network + size - 1;
  return { first, last };
}
function list24Blocks(cidr) {
  const { first, last } = parseCIDR(cidr);
  const start24 = first & 0xFFFFFF00;
  const end24   = last  & 0xFFFFFF00;
  const blocks = [];
  for (let b = start24; b <= end24; b += 256) blocks.push(b >>> 0);
  return blocks;
}
function sampleIPsIn24(blockStartInt, k) {
  const picks = new Set();
  const candidates = [10, 42, 77, 99, 123, 150, 180, 200, 220, 240].map(x => Math.min(254, Math.max(1,x)));
  let idx = 0;
  while (picks.size < Math.min(k, 254)) {
    const o = candidates[idx % candidates.length] + ((idx / candidates.length) | 0);
    const off = 1 + ((o - 1) % 254);
    picks.add(off);
    idx++;
  }
  return Array.from(picks).slice(0, k).map(off => intToIp((blockStartInt + off) >>> 0));
}
function ipsOf24(blockStartInt, limit=256) {
  const ips = [];
  for (let off = 0; off < Math.min(limit, 256); off++) {
    ips.push(intToIp((blockStartInt + off) >>> 0));
  }
  return ips;
}

// ---------- Fastly public IP fetch ----------
function fetchFastlyCidrs({ timeout = 5000 } = {}) {
  const url = "https://api.fastly.com/public-ip-list";
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { "User-Agent": "smart-scan/1.0", "Accept": "application/json" },
      timeout
    }, res => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`Fastly API HTTP ${res.statusCode}`));
      }
      let data = "";
      res.setEncoding("utf8");
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          const v4 = Array.isArray(json.addresses) ? json.addresses : [];
          // Ignore ipv6_addresses for this IPv4 scanner
          if (!v4.length) return reject(new Error("Fastly API returned no IPv4 addresses"));
          resolve(v4);
        } catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(new Error("Fastly API request timed out")); });
  });
}

// ---------- cheap TCP:80 open check ----------
function tcpOpen(ip, timeout=1000) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host: ip, port, timeout });
    const done = (ok) => { try { sock.destroy(); } catch {} resolve(ok); };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

// ---------- optional HTTP HEAD verification ----------
function httpHead(ip, hostHeader, timeout=1000) {
  return new Promise(resolve => {
    const req = http.request({
      host: ip,
      port,
      method: "HEAD",
      path: "/",
      setHost: false,
      timeout,
      headers: hostHeader ? { Host: hostHeader } : {}
    }, (res) => { res.resume(); resolve(true); });
    req.on("timeout", ()=> { req.destroy(); resolve(false); });
    req.on("error", ()=> resolve(false));
    req.end();
  });
}

// ---------- ping ----------
const isWin = process.platform === "win32";
function pingOnce(ip, timeout=1000) {
  return new Promise((resolve) => {
    const pingArgs = isWin ? ["-n","1","-w", String(timeout), ip] : ["-c","1", ip];
    const child = spawn("ping", pingArgs);
    let out = "";
    const killer = setTimeout(()=> { try { child.kill("SIGKILL"); } catch{} }, timeout+200);
    child.stdout.on("data", d => out += d.toString());
    child.stderr.on("data", d => out += d.toString());
    child.on("close", () => {
      clearTimeout(killer);
      const m = out.match(/time[=<]?\s*([\d.]+)\s*ms/i);
      if (m) return resolve({ ok:true, ms: parseFloat(m[1]) });
      resolve({ ok:false, ms:null });
    });
    child.on("error", () => { clearTimeout(killer); resolve({ ok:false, ms:null }); });
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
      job.fn().then(job.resolve, job.reject).finally(()=>{ active--; pump(); });
    }
  };
  return fn => new Promise((resolve, reject) => { q.push({ fn, resolve, reject }); pump(); });
}

// ---------- progress (1% steps) ----------
function renderBar(pct) {
  const width = 40;
  const filled = Math.round((pct/100)*width);
  return `[${"#".repeat(filled)}${".".repeat(width-filled)}] ${pct}%`;
}
function Progress(total) {
  let done = 0, lastPct = -1;
  total = Math.max(1, total);
  const tick = () => {
    done++;
    const pct = Math.floor((done*100)/total);
    if (pct !== lastPct) {
      lastPct = pct;
      process.stdout.write("\r"+renderBar(Math.min(100, pct)));
      if (pct >= 100) process.stdout.write("\n");
    }
  };
  return { tick };
}

// ---------- main ----------
(async () => {
  // gather CIDRs
  let cidrs = [];
  if (fileArg) {
    const text = fs.readFileSync(fileArg, "utf8");
    cidrs.push(...text.split(/\r?\n/).map(s=>s.trim()).filter(Boolean));
  } else {
    const positional = args.filter(a => !a.startsWith("--"));
    if (positional.length) {
      cidrs.push(...positional);
    } else {
      // No file and no positional CIDRs -> fetch from Fastly API
      console.log("No CIDR input provided; fetching from Fastly public IP list…");
      try {
        cidrs = await fetchFastlyCidrs({ timeout: 8000 });
        console.log(`Fetched ${cidrs.length} CIDR blocks from Fastly.`);
      } catch (e) {
        console.error("Failed to fetch Fastly CIDRs:", e.message);
        process.exit(1);
      }
    }
  }

  // --- Stage A: sample few IPs per /24 to decide which /24 to expand
  const blocks = cidrs.flatMap(c => list24Blocks(c));
  if (!blocks.length) {
    console.error("No /24 blocks to scan. Exiting.");
    process.exit(1);
  }
  const sampleTargets = [];
  for (const b of blocks) {
    const picks = sampleIPsIn24(b, samplesPer24);
    for (const ip of picks) sampleTargets.push({ block: b, ip });
  }

  const stageATotal = sampleTargets.length;
  const stageAProgress = Progress(stageATotal);
  const limit = createQueue(concurrency);

  const hotBlocks = new Set(); // blocks where we saw any open:80 (and optional HEAD ok)
  await Promise.all(sampleTargets.map(t =>
    limit(async () => {
      const open = await tcpOpen(t.ip, timeoutMs);
      if (open) {
        if (hostHeader) {
          const ok = await httpHead(t.ip, hostHeader, timeoutMs);
          if (ok) hotBlocks.add(t.block);
        } else {
          hotBlocks.add(t.block);
        }
      }
      stageAProgress.tick();
    })
  ));

  // Build expansion list
  const expandTargets = [];
  for (const b of hotBlocks) {
    for (const ip of ipsOf24(b, expandLimitPer24)) {
      expandTargets.push(ip);
    }
  }

  // --- Stage B: on expanded IPs, require ping OK + port 80 open (+ optional HEAD)
  const stageBTotal = expandTargets.length;
  const stageBProgress = Progress(stageBTotal);
  const valid = [];
  await Promise.all(expandTargets.map(ip =>
    limit(async () => {
      const open = await tcpOpen(ip, timeoutMs);
      if (!open) { stageBProgress.tick(); return; }
      if (hostHeader) {
        const ok = await httpHead(ip, hostHeader, timeoutMs);
        if (!ok) { stageBProgress.tick(); return; }
      }
      const p = await pingOnce(ip, timeoutMs);
      if (p.ok) valid.push({ ip, ms: p.ms });
      stageBProgress.tick();
    })
  ));

  // Sort + save
  valid.sort((a,b)=> a.ms - b.ms);
  fs.writeFileSync("valid.txt", valid.map(v => v.ip).join("\n"), "utf8");
  fs.writeFileSync("valid.csv", "ip,ping_ms\n"+valid.map(v => `${v.ip},${v.ms.toFixed(3)}`).join("\n"), "utf8");

  console.log(`Hot /24 blocks: ${hotBlocks.size} / ${blocks.length}`);
  console.log(`Valid IPs: ${valid.length} (saved to valid.txt, valid.csv)`);
})().catch(e => { console.error(e); process.exit(1); });
