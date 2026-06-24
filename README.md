# mcp-guard

[![npm](https://img.shields.io/npm/v/@zent7x/mcp-guard)](https://www.npmjs.com/package/@zent7x/mcp-guard)
[![npm downloads](https://img.shields.io/npm/dm/@zent7x/mcp-guard)](https://www.npmjs.com/package/@zent7x/mcp-guard)
[![license](https://img.shields.io/github/license/zent7x/mcp-guard)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.21+-blue)](https://golang.org)
[![mcp-guard MCP server](https://glama.ai/mcp/servers/zent7x/mcp-guard/badges/score.svg)](https://glama.ai/mcp/servers/zent7x/mcp-guard)

Security and network MCP server for Claude Code and Cursor. Written in Go.

---

## Why mcp-guard

Most MCP servers are API wrappers. Claude could look up the same data itself if it had web access.

mcp-guard is different. **12 of its 20 tools require a physical machine to function.** Wi-Fi scanning needs a radio chip. Bluetooth scanning needs an adapter. ARP discovery sends Layer 2 frames that never leave your local network — no cloud service receives them. File watching subscribes to kernel events on your machine's filesystem. USB enumeration reads your physical ports.

Claude runs in a data center. It has none of these things. These tools only work because the binary is running on your computer.

---

## Tools

### Local hardware (impossible for any remote service)

| Tool | What it does |
|------|-------------|
| `wifi_scan` | Scan nearby Wi-Fi networks via your wireless hardware — SSID, BSSID, signal, channel, security |
| `bluetooth_scan` | Enumerate nearby Bluetooth devices via your adapter — name, address, type, pairing status |
| `usb_devices` | List all USB devices connected to this machine — vendor, product ID, speed, manufacturer |
| `arp_scan` | Layer 2 LAN discovery — finds every device on your network including ones that block ICMP/TCP, with MAC addresses and vendor IDs |
| `ping_sweep` | ICMP host discovery across a CIDR range from your machine's network stack |
| `traceroute` | Hop-by-hop network path from this machine via ICMP TTL probes |
| `file_watch` | Kernel FS event stream (FSEvents on macOS, inotify on Linux) — real-time create/write/delete/rename |
| `sys_info` | Local hardware: CPU model, RAM, disk, uptime, all network interfaces with IPs and MACs |
| `open_files` | Every file, socket, and pipe held open by processes on this machine via `lsof` |
| `proc_list` | Running processes with CPU% and memory — filter by name |
| `net_connections` | Live TCP connections on this machine (`netstat -an`) |
| `scan_secrets` | Walk local files for hardcoded credentials — 20+ patterns (AWS, GitHub, OpenAI, Stripe, Slack, DB URLs, private keys) |
| `hash_files` | SHA-256 every file in a directory — integrity baseline before/after deploys |

### Network utilities

| Tool | What it does |
|------|-------------|
| `port_scan` | Concurrent TCP scanner — 200 goroutines, service name lookup |
| `banner_grab` | Raw TCP banner from any protocol — SSH, FTP, SMTP, Redis, MySQL |
| `ssl_inspect` | Full TLS certificate chain — key size, algorithm, expiry, SANs |
| `dns_enum` | A, AAAA, MX, NS, TXT, CNAME — detects missing SPF/DMARC |
| `audit_headers` | HTTP security header audit scored 0–100 with letter grade |
| `check_cves` | npm dependency CVE check via OSV — no API key |
| `jwt_decode` | Local JWT decode — algorithm, expiry, security warnings |

---

## Setup

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx",
      "args": ["-y", "@zent7x/mcp-guard"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx",
      "args": ["-y", "@zent7x/mcp-guard"]
    }
  }
}
```

### Global install

```bash
npm install -g @zent7x/mcp-guard
```

Then use `"command": "mcp-guard"` instead of `npx` in the config above.

---

## Example output

```
> wifi_scan

Wi-Fi networks (8 found)

SSID                              BSSID               SIGNAL    CHANNEL  SECURITY
──────────────────────────────────────────────────────────────────────────────────────────
HomeNetwork                       a4:c3:f0:11:22:33   -42 dBm   6        WPA2 Personal
OfficeWifi                        b8:27:eb:44:55:66   -67 dBm   11       WPA2 Enterprise
```

```
> arp_scan 192.168.1.0/24

LAN devices in 192.168.1.0/24 (6 found)

IP                  MAC                  HOSTNAME              VENDOR
────────────────────────────────────────────────────────────────────────────────
192.168.1.1         a4:c3:f0:ab:cd:ef    router.local          Apple
192.168.1.42        b8:27:eb:12:34:56    raspberrypi.local     Raspberry Pi
192.168.1.100       00:0c:29:78:90:ab                          VMware
```

```
> bluetooth_scan

Bluetooth devices (4 found)

NAME                            ADDRESS               TYPE                  STATUS
─────────────────────────────────────────────────────────────────────────────────────────
AirPods Pro                     a1:b2:c3:d4:e5:f6                           paired
MX Keys                         11:22:33:44:55:66     Keyboard              paired
Sony WH-1000XM5                 aa:bb:cc:dd:ee:ff     Headphones            not paired
```

---

## How it works

The npm package downloads a pre-compiled Go binary for your platform on first run. The binary speaks the MCP stdio protocol — your editor spawns it on startup and the tools appear automatically.

Platform binaries: `darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`, `windows-amd64`.

---

## Build from source

```bash
git clone https://github.com/zent7x/mcp-guard
cd mcp-guard
go build -o mcp-guard .
```

Requires Go 1.21+.

---

## License

MIT
