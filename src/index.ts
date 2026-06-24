#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanSecrets } from "./secrets.js";
import { checkCves } from "./cve.js";
import { auditHeaders } from "./headers.js";

const server = new McpServer({
  name: "mcp-guard",
  version: "0.1.0",
});

// ── Tool: scan_secrets ────────────────────────────────────────────────────────
server.tool(
  "scan_secrets",
  "Scan a file or directory for hardcoded secrets, API keys, tokens, and passwords. Returns findings with file path, line number, secret type, and severity.",
  { path: z.string().describe("Absolute path to a file or directory to scan") },
  async ({ path }) => {
    const findings = scanSecrets(path);

    if (findings.length === 0) {
      return {
        content: [{ type: "text", text: `No secrets found in ${path}` }],
      };
    }

    const byFile = new Map<string, typeof findings>();
    for (const f of findings) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file)!.push(f);
    }

    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;

    const lines: string[] = [
      `Found ${findings.length} potential secret(s) — ${high} high, ${medium} medium severity`,
      "",
    ];

    for (const [file, items] of byFile) {
      lines.push(file);
      for (const item of items) {
        lines.push(`  Line ${item.line} [${item.severity.toUpperCase()}] ${item.type}: ${item.match}`);
      }
      lines.push("");
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

// ── Tool: check_cves ─────────────────────────────────────────────────────────
server.tool(
  "check_cves",
  "Check npm dependencies in a package.json file against the OSV vulnerability database. Returns known CVEs with severity and advisory links.",
  { path: z.string().describe("Absolute path to a package.json file") },
  async ({ path }) => {
    const findings = await checkCves(path);

    if (findings.length === 0) {
      return {
        content: [{ type: "text", text: `No known vulnerabilities found in dependencies from ${path}` }],
      };
    }

    const bySeverity: Record<string, typeof findings> = {
      CRITICAL: [], HIGH: [], MODERATE: [], MEDIUM: [], LOW: [], UNKNOWN: [],
    };
    for (const f of findings) {
      const key = f.severity.toUpperCase();
      (bySeverity[key] ?? bySeverity["UNKNOWN"]).push(f);
    }

    const lines: string[] = [`Found ${findings.length} vulnerabilities in ${path}`, ""];

    for (const [sev, vulns] of Object.entries(bySeverity)) {
      if (!vulns.length) continue;
      lines.push(`── ${sev} (${vulns.length}) ──`);
      for (const v of vulns) {
        lines.push(`  ${v.package}@${v.version}  ${v.id}`);
        lines.push(`  ${v.summary}`);
        lines.push(`  ${v.url}`);
        lines.push("");
      }
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

// ── Tool: audit_headers ───────────────────────────────────────────────────────
server.tool(
  "audit_headers",
  "Audit the HTTP security headers of a URL. Checks for HSTS, CSP, X-Frame-Options, and more. Returns a score, grade, and actionable findings.",
  { url: z.string().describe("URL to audit (e.g. https://example.com)") },
  async ({ url }) => {
    const result = await auditHeaders(url);

    const lines: string[] = [
      `Security header audit: ${result.url}`,
      `Score: ${result.score}/100  Grade: ${result.grade}`,
      "",
    ];

    if (result.missing.length) {
      lines.push(`Missing required headers: ${result.missing.join(", ")}`);
      lines.push("");
    }

    lines.push("Header breakdown:");
    for (const check of result.checks) {
      const status = check.present ? "✓" : (check.required ? "✗" : "–");
      const value = check.value ? `  →  ${check.value.slice(0, 80)}${check.value.length > 80 ? "…" : ""}` : "";
      lines.push(`  ${status}  ${check.header}${value}`);
      if (check.note !== check.note) lines.push(`       ${check.note}`);
    }

    lines.push("");
    lines.push("Notes:");
    for (const check of result.checks) {
      lines.push(`  ${check.header}: ${check.note}`);
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

// ── Start server ──────────────────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);
