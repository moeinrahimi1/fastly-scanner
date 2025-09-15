# Smart Scan

A high-performance IP range scanner written in **TypeScript** (runs with [Bun](https://bun.com/)).

It was designed to scan [Fastly’s public IP ranges](https://api.fastly.com/public-ip-list) in order to discover “alive” IPv4 addresses that:

- respond to **ICMP ping**, and  
- accept **TCP connections on port 80** (optional: with a `Host:` header check).  

The goal: quickly filter out dead or unused IPs and produce a clean, sorted list of working ones.

⚠️ **Disclaimer**  
This project is provided for **educational and research purposes only**.  
Do **not** use it for unauthorized scanning of networks or services you don’t own or operate.

---

## ✨ Features

- Fetches Fastly IPv4 ranges automatically (if no input file is provided).
- Supports reading custom CIDRs from a file or CLI.
- Samples only a few IPs per `/24` to prune dead subnets → expands only “hot” ranges.
- ICMP ping + TCP:80 probe (plus optional HTTP `HEAD` check).
- Concurrency scaled to CPU cores.
- Single-color progress bar with spinner, ETA, and rate.
- Exports results:
  - `valid.txt` → plain list of alive IPs (sorted by ping latency).
  - `valid.csv` → `ip,ping_ms`.

---

## 🚀 How to Run

### Prerequisites
- Download From Release Page
- Works on Linux, macOS, and Windows.



### Usage Examples
```bash
1. Scan Fastly IP ranges (default)
./smart-scan

2. Scan specific CIDR ranges
./smart-scan 151.101.0.0/16 104.156.80.0/20

3. Scan from a file
./smart-scan --file cidrs.txt


cidrs.txt format must be like below format:

151.101.0.0/16
104.156.80.0/20

4. Extra options
./smart-scan --concurrency 400 --timeout 1200 --samples-per24 5 --host example.com


Options:

--host example.com → send HTTP HEAD / with Host: example.com

--concurrency 400 → set concurrency level

--timeout 1200 → probe timeout in ms

--samples-per24 5 → how many sample IPs per /24

--expand-limit 256 → max IPs to expand per /24