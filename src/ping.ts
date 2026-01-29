import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const inputFile = "./valid.txt";
const outputFile = "./reachable.txt";

const ips = readFileSync(inputFile, "utf-8").split("\n").map(line => line.trim()).filter(Boolean);
const concurrency = 80;

async function checkIP(ip: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    await fetch(`http://${ip}`, { signal: controller.signal });
    clearTimeout(timeout);
    return true;
  } catch {
    return false;
  }
}

async function run() {
  const reachableIPs: string[] = [];
  let currentIndex = 0;

  async function worker() {
    while (currentIndex < ips.length) {
      const ip = ips[currentIndex++];
      const isAlive = await checkIP(ip);
      if (isAlive) {
        reachableIPs.push(ip);
        console.log(`Reachable: ${ip}`);
      } else {
        console.log(`No response: ${ip}`);
      }
    }
  }

  // Start concurrency number of workers
  const workers = [];
  for (let i = 0; i < concurrency; i++) {
    workers.push(worker());
  }

  await Promise.all(workers);

  writeFileSync(outputFile, reachableIPs.join("\n"));
  console.log(`Reachable IPs saved to ${outputFile}`);
}

run();