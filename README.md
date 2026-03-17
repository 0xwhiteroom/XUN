<div align="center">

```
  ██╗  ██╗██╗   ██╗███╗   ██╗
  ╚██╗██╔╝██║   ██║████╗  ██║
   ╚███╔╝ ██║   ██║██╔██╗ ██║
   ██╔██╗ ██║   ██║██║╚██╗██║
  ██╔╝ ██╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

# xun 迅

### *Fast Port Scanner*

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux%20amd64-lightgrey?style=flat-square&logo=linux)](.)
[![Version](https://img.shields.io/badge/Version-1.0.0-blueviolet?style=flat-square)](.)
[![0xAscension](https://img.shields.io/badge/0xAscension-red?style=flat-square)](https://github.com/0xAscension)

> Ultra-fast TCP/UDP port scanner with **nmap-style output**, banner grabbing, domain resolution, CIDR support and automatic nmap handoff.


</div>

---

##  Why xun?

| Feature | |  | **xun** |
|---------|----------|---------|---------|
| Nmap-style output |  |  | ✅ |
| Domain DNS resolve |  |  | ✅ |
| Banner grab |  |  | ✅ |
| Service version |  |  | ✅ |
| UDP scan |  |  | ✅ |
| CIDR support | |  | ✅ |
| Nmap handoff |  |  | ✅ |
| JSON output |  |  | ✅ |
| `>>` redirect |  |  | ✅ |

---

##  Features

-  **Ultra Fast** — 1000 concurrent threads by default
-  **Domain Resolve** — `-d domain` auto-resolves IP and shows it
-  **Banner Grab** — SSH · FTP · HTTP · MySQL · Redis version detection
-  **CIDR Support** — scan entire subnets at once
-  **Nmap Handoff** — auto-generates ready-to-run nmap command
-  **UDP Scan** — common UDP ports (DNS, SNMP, NTP, etc.)
-  **Nmap-style Output** — clean table format grouped per host
-  **Output Formats** — TXT · JSON · JSONL
-  **Pipe Friendly** — stdout/stderr split, `>>` works perfectly

---

##  Flags

```
INPUT
  -h <host>            Single host, IP, or CIDR (e.g. 192.168.1.0/24)
  -d <domain>          Domain — auto DNS resolve then scan
  -l <file>            File of hosts/IPs (one per line)

SCAN
  -p <ports>           Custom ports: 80,443 or 1-1000
  -top100              Top 100 common ports           (default)
  -top1000             Top 1000 common ports
  -all                 All 65535 ports
  -udp                 UDP scan (common ports)

FEATURES
  -banner              Banner grab + service version detect
  -nmap                Auto generate + show nmap command
  -nmap-flags          Custom nmap flags               (default: -sV -sC)

CONFIG
  -c <int>             Concurrent threads              (default: 1000)
  -timeout <ms>        Timeout in milliseconds         (default: 500)

OUTPUT
  -o <file>            Save as TXT
  -oj <file>           Save as JSON
  -ojl <file>          Save as JSONL
  -silent              host:port only to stdout — pipe friendly
  -version             Print version
  --install-license    Activate license on this machine
```

---

##  Examples

```bash
# Basic scan — top 100 ports (default)
xun -h 192.168.1.1

# Domain — auto resolve IP + scan
xun -d target.com

# Domain with top 1000 + banner
xun -d target.com -top1000 -banner

# CIDR subnet scan
xun -h 192.168.1.0/24 -top100

# Full scan + nmap handoff
xun -h target.com -all -nmap

# Custom port range
xun -h target.com -p 80,443,8000-9000

# UDP scan
xun -h target.com -udp

# Save JSON results
xun -d target.com -top1000 -banner -oj ports.json

# Silent mode — pipe to file
xun -h target.com -top1000 -silent >> open_ports.txt

# Scan from file
xun -l hosts.txt -top100 -silent

# Custom nmap flags
xun -h target.com -all -nmap -nmap-flags '-sV -O --script vuln'
```

---

##  Output

```
  Scan report for target.com (93.184.216.34)
  PORT              STATE     SERVICE         VERSION
  ────────────────────────────────────────────────────────────
  22/tcp            open      ssh             OpenSSH 8.9p1 Ubuntu
  80/tcp            open      http            nginx 1.24.0
  443/tcp           open      https           nginx 1.24.0
  3306/tcp          open      mysql           MySQL 8.0.32
  6379/tcp          open      redis           6.2.6  ⚠ NO AUTH

  [✓]  5 open port(s)  scanned in 1.23s

  [→ nmap]
  nmap -sV -sC -p 22,80,443,3306,6379 93.184.216.34
```

---

##  Installation

```bash
# Build
unzip xun-v1.zip -d xun && cd xun
bash build.sh

# Install
sudo dpkg -i xun_1.0.0_amd64.deb

# Or manual
sudo mv xun /usr/local/bin/
sudo xun --install-license

# Verify
xun -version
```

> **Requirements:** Go 1.21+ · Linux amd64

---

##  Disclaimer

> For authorized security testing and educational purposes only.
> Use only on systems you have explicit permission to test.

---

<div align="center">

*xun 迅 v1.0 — by 0xWHITEROOM 「0xホワイトルーム」*

**[0xwhiteroom](https://github.com/0xwhiteroom)** · *We don't hack systems. We ascend them.*

</div>
