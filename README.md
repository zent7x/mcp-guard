# mcp-guard

Security MCP server written in Go. Gives Claude Code and Cursor the ability to do things they fundamentally cannot do on their own: scan TCP ports, inspect TLS certificate chains, enumerate DNS records, list running processes, and watch live network connections — alongside the standard security audits (secrets scanning, CVE checking, HTTP header analysis).

## Tools

### `port_scan`
Concurrent TCP port scanner using 200 goroutines. Scans a host and returns open ports with service identification.

```
port_scan("192.168.1.1", start=1, end=1024, timeout_ms=500)
```

Returns: port number, service name (ssh, http, mysql, redis, etc.)

---

### `ssl_inspect`
Fetches and inspects the full TLS certificate chain for a host. Checks key size, signature algorithm, expiry countdown, and SANs.

```
ssl_inspect("github.com")
ssl_inspect("mysite.com", port=8443)
```

Returns: leaf cert, intermediate(s), root CA — with expiry warnings if under 30 days.

---

### `dns_enum`
Enumerates all DNS record types for a domain: A, AAAA, MX, NS, TXT, CNAME. Detects missing SPF and DMARC records.

```
dns_enum("example.com")
```

Returns: all records grouped by type, plus email security warnings.

---

### `proc_list`
Lists running processes on the local machine. Optionally filter by name.

```
proc_list()
proc_list("node")
proc_list("python")
```

Returns: PID, CPU%, memory usage, command name.

---

### `net_connections`
Lists active TCP connections on the local machine (equivalent to `netstat -an`).

```
net_connections()
```

Returns: local address, remote address, connection state.

---

### `scan_secrets`
Scans a file or directory for hardcoded secrets using 20+ provider-specific patterns. Covers AWS keys, GitHub tokens, Anthropic/OpenAI API keys, Stripe, Slack, Twilio, SendGrid, database URLs, private key blocks, JWT secrets, and generic patterns.

```
scan_secrets("/path/to/project")
```

Returns: file path, line number, secret type, redacted match, severity.

---

### `audit_headers`
Fetches a URL and audits its HTTP security headers. Scores 0–100 and assigns a letter grade.

```
audit_headers("https://example.com")
```

Returns: score, grade (A+ to F), per-header breakdown, missing required headers.

---

### `check_cves`
Checks all npm dependencies in a `package.json` against the OSV vulnerability database. No API key required.

```
check_cves("/path/to/package.json")
```

Returns: vulnerable package, version, CVE ID, severity, summary, advisory link.

---

## Setup

mcp-guard runs as a background process managed by your editor. Add it to your config and the tools become available automatically.

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

Then use `"command": "mcp-guard"` instead of `"command": "npx"` in the config.

## Build from source

Requires Go 1.21+:

```bash
git clone https://github.com/zent7x/mcp-guard
cd mcp-guard
go build -o mcp-guard-bin .
```

## Architecture

The core is a Go binary built with [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go). The npm package downloads the correct platform binary on install and spawns it as the MCP stdio server.

Platform binaries: `darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`, `windows-amd64`.

## License

MIT
