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

## Setup

mcp-guard runs as a background process managed by your editor — you don't invoke it directly. Add it to your editor config and the tools become available in your AI assistant automatically.

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx",
      "args": ["-y", "mcp-guard"]
    }
  }
}
```

Then ask Claude: *"scan /path/to/project for secrets"* or *"audit the headers on https://mysite.com"*

### Cursor

Add to `.cursor/mcp.json` in your project (or the global Cursor MCP config):

```json
{
  "mcpServers": {
    "mcp-guard": {
      "command": "npx",
      "args": ["-y", "mcp-guard"]
    }
  }
}
```

### Global install (optional)

If you prefer not to use `npx`:

```bash
npm install -g mcp-guard
```

Then use `"command": "mcp-guard"` instead of `"command": "npx"` in the config above.

## Build from source

```bash
git clone https://github.com/zent7x/mcp-guard
cd mcp-guard
npm install
npm run build
```

## License

MIT
