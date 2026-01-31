# Fastly Scanner

A high-performance IP range scanner written in **TypeScript** (runs with [Bun](https://bun.com/)).

It was designed to scan [Fastly’s public IP ranges](https://api.fastly.com/public-ip-list) in order to discover “alive” IPv4 addresses that:

- respond to **ICMP ping**, and  
- accept **TCP connections on port 80** (optional: with a `Host:` header check).  

The goal: quickly find fastly clean ip for usage of xray configs

provide the app with following fastly ip ranges:
# fastly ip ranges
23.235.32.0/20

43.249.72.0/22

103.244.50.0/24

103.245.222.0/23

103.245.224.0/24

104.156.80.0/20

140.248.64.0/18

140.248.128.0/17

146.75.0.0/17

151.101.0.0/16

157.52.64.0/18

167.82.0.0/17

167.82.128.0/20

167.82.160.0/20

167.82.224.0/20


172.111.64.0/18

185.31.16.0/22

199.27.72.0/21

199.232.0.0/1


---

## ✨ Features

- Fetches Fastly IPv4 ranges automatically (if no input file is provided).
- Supports reading custom CIDRs from a file or CLI.
- Samples only a few IPs per `/24` to prune dead subnets → expands only “hot” ranges.
- ICMP ping + TCP:80 probe (plus optional HTTP `HEAD` check).
- Concurrency scaled to CPU cores.
---


--timeout 1200 → probe timeout in ms

--samples-per24 5 → how many sample IPs per /24

--expand-limit 256 → max IPs to expand per /24
