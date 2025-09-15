#!/usr/bin/env bun
/**
 * Smart CIDR scanner (fast) with Fastly fallback — TypeScript (Bun)
 * Visuals: colorful gradient progress bars + spinner + ETA + rate
 *
 * Usage:
 *   bun smart-scan.ts 151.101.0.0/16
 *   bun smart-scan.ts --file cidrs.txt --concurrency 400 --timeout 1200 --samples-per24 3 --host yourdomain.com
 *   bun smart-scan.ts
 *
 * Output:
 *   - valid.txt  (IPs only, sorted by ping ascending)
 *   - valid.csv  (ip,ping_ms)
 */

import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import { spawn } from "node:child_process";
import http from "node:http";

type Nullable<T> = T | null;
type FastlyIPResponse = { addresses?: string[]; ipv6_addresses?: string[] };
type PingResult = { ok: boolean; ms: number | null };
type Job<T> = { fn: () => Promise<T>; resolve: (v: T | PromiseLike<T>) => void; reject: (e?: unknown) => void };

// ---------- CLI ----------
const args = process.argv.slice(2);
const getFlag = (name: string, def: any = null): any => {
  const i = args.findIndex(a => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i === -1) return def;
  const [, v] = args[i].split("=");
  if (v !== undefined) return v;
  const next = args[i + 1];
  if (!next || next.startsWith("--")) return true;
  return next;
};

const fileArg = getFlag("file", null) as Nullable<string>;
const hostHeader = (getFlag("host", "") as string) || "";
const timeoutMs = parseInt(getFlag("timeout", "1000"), 10);
const concurrency = parseInt(getFlag("concurrency", ""), 10) || os.cpus().length * 100;
const samplesPer24 = Math.max(1, parseInt(getFlag("samples-per24", "3"), 10));
const expandLimitPer24 = parseInt(getFlag("expand-limit", "256"), 10);
const port = 80;

// ---------- helpers: networking / cidr ----------
function ipToInt(ip: string): number {
  return ip.split(".").map(Number).reduce((a, b) => (a << 8) + b);
}
function intToIp(n: number): string {
  return [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255].join(".");
}
function parseCIDR(cidr: string): { first: number; last: number } {
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
function list24Blocks(cidr: string): number[] {
  const { first, last } = parseCIDR(cidr);
  const start24 = first & 0xffffff00;
  const end24 = last & 0xffffff00;
  const blocks: number[] = [];
  for (let b = start24; b <= end24; b += 256) blocks.push(b >>> 0);
  return blocks;
}
function sampleIPsIn24(blockStartInt: number, k: number): string[] {
  const picks = new Set<number>();
  const candidates = [10, 42, 77, 99, 123, 150, 180, 200, 220, 240].map(x => Math.min(254, Math.max(1, x)));
  let idx = 0;
  while (picks.size < Math.min(k, 254)) {
    const o = candidates[idx % candidates.length] + ((idx / candidates.length) | 0);
    const off = 1 + ((o - 1) % 254);
    picks.add(off);
    idx++;
  }
  return Array.from(picks)
    .slice(0, k)
    .map(off => intToIp((blockStartInt + off) >>> 0));
}
function ipsOf24(blockStartInt: number, limit = 256): string[] {
  const ips: string[] = [];
  for (let off = 0; off < Math.min(limit, 256); off++) ips.push(intToIp((blockStartInt + off) >>> 0));
  return ips;
}

// ---------- Fastly public IP fetch ----------
async function fetchFastlyCidrs({ timeout = 5000 } = {}): Promise<string[]> {
  const url = "https://api.fastly.com/public-ip-list";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "smart-scan/1.0", Accept: "application/json" },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`Fastly API HTTP ${res.status}`);
    const json = (await res.json()) as FastlyIPResponse;
    const v4 = Array.isArray(json.addresses) ? json.addresses : [];
    if (!v4.length) throw new Error("Fastly API returned no IPv4 addresses");
    return v4;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- cheap TCP:80 open check ----------
function tcpOpen(ip: string, timeout = 1000): Promise<boolean> {
  return new Promise(resolve => {
    const sock = net.createConnection({ host: ip, port, timeout });
    const done = (ok: boolean) => {
      try {
        sock.destroy();
      } catch {}
      resolve(ok);
    };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

// ---------- optional HTTP HEAD verification ----------
function httpHead(ip: string, hostHeaderVal: string, timeout = 1000): Promise<boolean> {
  return new Promise(resolve => {
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
      res => {
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
function pingOnce(ip: string, timeout = 1000): Promise<PingResult> {
  return new Promise(resolve => {
    const pingArgs = isWin ? ["-n", "1", "-w", String(timeout), ip] : ["-c", "1", ip];
    const child = spawn("ping", pingArgs);
    let out = "";
    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {}
    }, timeout + 200);
    child.stdout.on("data", d => (out += d.toString()));
    child.stderr.on("data", d => (out += d.toString()));
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
function createQueue(limit: number) {
  let active = 0;
  const q: Job<unknown>[] = [];
  const pump = () => {
    while (active < limit && q.length) {
      active++;
      const job = q.shift()!;
      job
        .fn()
        .then(job.resolve, job.reject)
        .finally(() => {
          active--;
          pump();
        });
    }
  };
  return <T>(fn: () => Promise<T>) =>
    new Promise<T>((resolve, reject) => {
      q.push({ fn, resolve, reject } as Job<T>);
      pump();
    });
}

// ---------- colorful progress (1% steps) ----------
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const ESC = "\x1b[";
const reset = `${ESC}0m`;
const dim = (s: string) => (useColor ? `${ESC}2m${s}${reset}` : s);
const bold = (s: string) => (useColor ? `${ESC}1m${s}${reset}` : s);
const fg256 = (n: number) => (useColor ? `${ESC}38;5;${n}m` : "");
const bg256 = (n: number) => (useColor ? `${ESC}48;5;${n}m` : "");
const clearLine = () => process.stdout.write(useColor ? `\r${ESC}K` : "\r");

// pleasing rainbow-ish gradient across the bar
const PALETTE = [196, 202, 208, 214, 220, 190, 154, 118, 82, 46, 47, 48, 49, 51, 39, 33, 27, 21, 57, 93, 129, 165];
const spinnerFrames = ["⠋","⠙","⠚","⠞","⠖","⠦","⠴","⠲","⠳","⠓"];
let spinnerIdx = 0;

function gradientBlock(idx: number, total: number) {
  const p = total <= 1 ? 0 : idx / (total - 1);
  const colorIndex = Math.floor(p * (PALETTE.length - 1));
  return bg256(PALETTE[colorIndex]) + " " + reset; // block = background-colored space
}
function renderBar(label: string, pct: number, done: number, total: number, startedAt: number) {
  const width = 40;
  const filled = Math.max(0, Math.min(width, Math.round((pct / 100) * width)));
  const spinner = spinnerFrames[spinnerIdx++ % spinnerFrames.length];

  // Single color: green blocks
  const block = useColor ? `${ESC}42m ${reset}` : "#";
  let bar = block.repeat(filled) + ".".repeat(width - filled);

  // Stats: ETA + rate
  const elapsed = Math.max(1, Date.now() - startedAt) / 1000;
  const rate = done / elapsed;
  const remaining = Math.max(0, total - done);
  const etaSec = rate > 0 ? Math.ceil(remaining / rate) : 0;
  const etaStr =
    etaSec >= 60 ? `${Math.floor(etaSec / 60)}m${etaSec % 60}s` : `${etaSec}s`;

  const pctTxt = `${pct.toString().padStart(3, " ")}%`;

  clearLine();
  process.stdout.write(
    `${label} ${spinner} [${bar}] ${pctTxt}  ETA:${etaStr}  Rate:${rate.toFixed(1)}/s`
  );

  if (pct >= 100) process.stdout.write("\n");
}



function Progress(total: number, label = "Progress") {
  let done = 0;
  let lastPct = -1;
  total = Math.max(1, total);
  const startedAt = Date.now();

  const tick = (n = 1) => {
    done += n;
    const pct = Math.floor((done * 100) / total);
    if (pct !== lastPct) {
      lastPct = pct;
      renderBar(label, Math.min(100, pct), Math.min(done, total), total, startedAt);
    }
  };
  // draw once at start (0%)
  renderBar(label, 0, 0, total, startedAt);
  return { tick };
}

// ---------- main ----------
(async () => {
  // gather CIDRs
  let cidrs: string[] = [];
  if (fileArg) {
    const text = fs.readFileSync(fileArg, "utf8");
    cidrs.push(...text.split(/\r?\n/).map(s => s.trim()).filter(Boolean));
  } else {
    const positional = args.filter(a => !a.startsWith("--"));
    if (positional.length) {
      cidrs.push(...positional);
    } else {
      console.log("No CIDR input provided; fetching from Fastly public IP list…");
      try {
        cidrs = await fetchFastlyCidrs({ timeout: 8000 });
        console.log(`Fetched ${cidrs.length} CIDR blocks from Fastly.`);
      } catch (e: any) {
        console.error("Failed to fetch Fastly CIDRs:", e?.message ?? e);
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

  const sampleTargets: { block: number; ip: string }[] = [];
  for (const b of blocks) {
    const picks = sampleIPsIn24(b, samplesPer24);
    for (const ip of picks) sampleTargets.push({ block: b, ip });
  }

  const stageATotal = sampleTargets.length;
  const stageAProgress = Progress(stageATotal, "Stage A (sample)");
  const limitQ = createQueue(concurrency);

  const hotBlocks = new Set<number>();
  await Promise.all(
    sampleTargets.map(t =>
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
        stageAProgress.tick();
      })
    )
  );

  // Build expansion list
  const expandTargets: string[] = [];
  for (const b of hotBlocks) {
    for (const ip of ipsOf24(b, expandLimitPer24)) expandTargets.push(ip);
  }

  // --- Stage B: on expanded IPs, require ping OK + port 80 open (+ optional HEAD)
  const stageBTotal = expandTargets.length;
  const stageBProgress = Progress(stageBTotal || 1, "Stage B (expand)");
  const valid: { ip: string; ms: number }[] = [];

  await Promise.all(
    expandTargets.map(ip =>
      limitQ(async () => {
        const open = await tcpOpen(ip, timeoutMs);
        if (!open) {
          stageBProgress.tick();
          return;
        }
        if (hostHeader) {
          const ok = await httpHead(ip, hostHeader, timeoutMs);
          if (!ok) {
            stageBProgress.tick();
            return;
          }
        }
        const p = await pingOnce(ip, timeoutMs);
        if (p.ok && typeof p.ms === "number") valid.push({ ip, ms: p.ms });
        stageBProgress.tick();
      })
    )
  );

  // Sort + save
  valid.sort((a, b) => a.ms - b.ms);
  fs.writeFileSync("valid.txt", valid.map(v => v.ip).join("\n"), "utf8");
  fs.writeFileSync("valid.csv", "ip,ping_ms\n" + valid.map(v => `${v.ip},${v.ms.toFixed(3)}`).join("\n"), "utf8");

  console.log(`\nHot /24 blocks: ${hotBlocks.size} / ${blocks.length}`);
  console.log(`Valid IPs: ${valid.length} (saved to valid.txt, valid.csv)`);
})().catch(e => {
  console.error(e);
  process.exit(1);
});
