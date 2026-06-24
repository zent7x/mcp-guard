import { readFileSync, statSync, readdirSync } from "fs";
import { join, extname } from "path";

export interface SecretFinding {
  file: string;
  line: number;
  type: string;
  match: string;
  severity: "high" | "medium" | "low";
}

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage",
  "__pycache__", ".venv", "venv", ".tox",
]);

const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
  ".pdf", ".zip", ".tar", ".gz", ".woff", ".woff2", ".ttf",
  ".eot", ".mp4", ".mp3", ".lock",
]);

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; severity: "high" | "medium" | "low" }> = [
  // High severity — known provider key formats
  { name: "AWS Access Key", regex: /\bAKIA[0-9A-Z]{16}\b/, severity: "high" },
  { name: "AWS Secret Key", regex: /aws_secret_access_key\s*=\s*["']?[A-Za-z0-9/+=]{40}["']?/i, severity: "high" },
  { name: "GitHub Token", regex: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/, severity: "high" },
  { name: "Anthropic API Key", regex: /\bsk-ant-[A-Za-z0-9\-_]{90,}\b/, severity: "high" },
  { name: "OpenAI API Key", regex: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/, severity: "high" },
  { name: "Stripe Secret Key", regex: /\bsk_live_[A-Za-z0-9]{24,}\b/, severity: "high" },
  { name: "Stripe Test Key", regex: /\bsk_test_[A-Za-z0-9]{24,}\b/, severity: "medium" },
  { name: "Slack Bot Token", regex: /\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/, severity: "high" },
  { name: "Slack Webhook", regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: "high" },
  { name: "Twilio Auth Token", regex: /(?:twilio|auth_token)\s*[:=]\s*["']?[a-f0-9]{32}["']?/i, severity: "high" },
  { name: "Sendgrid API Key", regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, severity: "high" },
  { name: "Private Key Block", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "high" },

  // Medium severity — generic patterns
  { name: "Generic API Key", regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?/i, severity: "medium" },
  { name: "Generic Secret", regex: /(?:secret|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/i, severity: "medium" },
  { name: "Bearer Token", regex: /Authorization\s*:\s*["']?Bearer\s+[A-Za-z0-9\-._~+/]+=*["']?/i, severity: "medium" },
  { name: "Database URL", regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/, severity: "medium" },
  { name: "JWT Secret", regex: /jwt[_\-]?secret\s*[:=]\s*["'][^"']{16,}["']/i, severity: "medium" },
];

function scanFile(filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  let content: string;

  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of SECRET_PATTERNS) {
      const match = pattern.regex.exec(line);
      if (match) {
        const raw = match[0];
        // Redact everything after the first 6 chars
        const redacted = raw.length > 10
          ? raw.slice(0, 6) + "..." + raw.slice(-4)
          : raw.slice(0, 3) + "***";
        findings.push({
          file: filePath,
          line: i + 1,
          type: pattern.name,
          match: redacted,
          severity: pattern.severity,
        });
        break; // One finding per line per file
      }
    }
  }

  return findings;
}

function walkDir(dir: string, findings: SecretFinding[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      walkDir(full, findings);
    } else if (!SKIP_EXTS.has(extname(entry).toLowerCase())) {
      findings.push(...scanFile(full));
    }
  }
}

export function scanSecrets(target: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  let stat;
  try {
    stat = statSync(target);
  } catch {
    throw new Error(`Path not found: ${target}`);
  }

  if (stat.isDirectory()) {
    walkDir(target, findings);
  } else {
    findings.push(...scanFile(target));
  }

  return findings;
}
