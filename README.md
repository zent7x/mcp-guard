# mcp-guard

MCP server for Claude Code and Cursor. Written in Go.

Most MCP servers wrap APIs — things Claude could look up anyway. mcp-guard gives Claude tools that **require a physical machine to exist**: your Wi-Fi radio, your kernel's file event stream, your local network segment, your running processes. There is no API endpoint for these. No cloud service can see them. They only work because the binary is running on your computer.

## Tools

### Local hardware and OS

**`wifi_scan`** — scan nearby Wi-Fi networks via your wireless hardware. Returns SSID, BSSID, signal strength, channel, security type. Requires a physical Wi-Fi adapter.

**`sys_info`** — CPU model, core count, RAM, disk, uptime, network interfaces with IPs and MACs. Read from local hardware via sysctl/proc — not from an API.

**`file_watch`** — subscribe to kernel FS events (FSEvents on macOS, inotify on Linux) on any path. Returns real-time create/write/delete/rename events as they happen.

**`open_files`** — list every file, socket, and pipe currently held open by processes on this machine. Filter by process name or PID. Uses `lsof`.

**`proc_list`** — list running processes with CPU% and memory. Filter by name.

**`net_connections`** — live TCP connections on this machine (`netstat -an`).

### Local network (LAN only)

**`arp_scan`** — Layer 2 host discovery. Finds every device on your local network including ones that block all ICMP and TCP. Returns IP, MAC address, hostname, vendor. Only works from a machine on the same network segment — a remote service receives no ARP frames.

**`ping_sweep`** — ICMP sweep across a CIDR range. Concurrent, 64 goroutines. Returns live hosts with latency.

**`traceroute`** — network path to any host, hop by hop. Shows the actual path packets take from this machine.

### Local file access

**`scan_secrets`** — walk a directory and find hardcoded credentials using 20+ regex patterns: AWS keys, GitHub tokens, OpenAI/Anthropic keys, Stripe, Slack, Twilio, private key blocks, DB connection strings, JWT secrets. Skips `node_modules`, `.git`, binaries.

**`hash_files`** — SHA-256 every file in a directory. Use it to create an integrity baseline before and after a deploy, or verify nothing changed in a dependency.

### Network utilities

**`port_scan`** — concurrent TCP scanner, 200 goroutines, service name lookup.

**`ssl_inspect`** — full TLS certificate chain inspection. Key size, algo, expiry, SANs.

**`dns_enum`** — A, AAAA, MX, NS, TXT, CNAME. Detects missing SPF/DMARC.

**`banner_grab`** — raw TCP banner grab for any protocol (SSH, FTP, SMTP, Redis, memcached).

**`audit_headers`** — HTTP security header audit. Score 0–100, letter grade.

**`check_cves`** — check all npm deps in a `package.json` against OSV. No API key.

**`jwt_decode`** — local JWT decode and analysis. Algorithm, expiry, security warnings.

## Setup

### Claude Code

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

Add to `~/.claude/settings.json` (global) or `.claude/settings.json` (per project).

### Cursor

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

Add to `.cursor/mcp.json`.

### Global install

```bash
npm install -g @zent7x/mcp-guard
```

Then use `"command": "mcp-guard"` in the config above.

## How it works

The npm package downloads a pre-compiled Go binary for your platform on install. The binary runs as a stdio MCP server — your editor spawns it and speaks the Model Context Protocol over stdin/stdout.

Platform binaries ship for `darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`, `windows-amd64`.

## Build from source

```bash
git clone https://github.com/zent7x/mcp-guard
cd mcp-guard
go build -o mcp-guard .
```

Requires Go 1.21+.

## License

MIT
