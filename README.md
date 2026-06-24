# mcp-guard

Security analysis MCP server for Claude Code and Cursor. Gives your AI assistant the ability to scan for hardcoded secrets, check dependencies for known CVEs, and audit HTTP security headers — all without leaving your editor.

## Tools

### `scan_secrets`
Scans a file or directory for hardcoded secrets. Detects AWS keys, GitHub tokens, Anthropic/OpenAI API keys, Stripe keys, Slack tokens, database URLs, private key blocks, and generic secret patterns using entropy analysis and provider-specific regex.

```
scan_secrets("/path/to/project")
```

Returns: file path, line number, secret type, redacted match, severity (high/medium/low).

---

### `check_cves`
Checks all npm dependencies in a `package.json` against the [OSV vulnerability database](https://osv.dev). No API key required.

```
check_cves("/path/to/package.json")
```

Returns: vulnerable package, version, CVE ID, severity, summary, and link to the advisory.

---

### `audit_headers`
Fetches a URL and audits its HTTP security headers. Checks for HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. Returns a score out of 100 and a letter grade.

```
audit_headers("https://example.com")
```

Returns: score, grade (A+ to F), per-header breakdown, list of missing required headers.

---

## Install

```bash
npm install -g mcp-guard
```

## Setup

### Claude Code

Add to your `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "mcp-guard"
    }
  }
}
```

### Cursor

Add to your MCP config:

```json
{
  "mcp-guard": {
    "command": "npx",
    "args": ["mcp-guard"]
  }
}
```

### Run without installing

```bash
npx mcp-guard
```

## Build from source

```bash
git clone https://github.com/zent7x/mcp-guard
cd mcp-guard
npm install
npm run build
```

## License

MIT
