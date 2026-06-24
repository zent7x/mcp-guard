export interface HeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  required: boolean;
  note: string;
}

export interface HeadersResult {
  url: string;
  score: number;
  grade: string;
  checks: HeaderCheck[];
  missing: string[];
}

const CHECKS: Array<{
  header: string;
  required: boolean;
  validate?: (value: string) => string | null;
  note: string;
}> = [
  {
    header: "strict-transport-security",
    required: true,
    validate: (v) => {
      const maxAge = /max-age=(\d+)/.exec(v);
      if (!maxAge) return "missing max-age directive";
      if (parseInt(maxAge[1]) < 31536000) return "max-age should be at least 31536000 (1 year)";
      return null;
    },
    note: "Enforces HTTPS for future visits",
  },
  {
    header: "content-security-policy",
    required: true,
    validate: (v) => {
      if (v.includes("unsafe-eval")) return "contains unsafe-eval";
      if (!v.includes("default-src")) return "missing default-src directive";
      return null;
    },
    note: "Controls which resources can be loaded",
  },
  {
    header: "x-content-type-options",
    required: true,
    validate: (v) => (v.trim() === "nosniff" ? null : "value should be 'nosniff'"),
    note: "Prevents MIME-type sniffing",
  },
  {
    header: "x-frame-options",
    required: true,
    validate: (v) => {
      const norm = v.trim().toUpperCase();
      if (norm !== "DENY" && norm !== "SAMEORIGIN") return "value should be DENY or SAMEORIGIN";
      return null;
    },
    note: "Prevents clickjacking via iframes",
  },
  {
    header: "referrer-policy",
    required: true,
    note: "Controls how much referrer info is sent",
  },
  {
    header: "permissions-policy",
    required: false,
    note: "Restricts browser feature access (camera, mic, geolocation)",
  },
  {
    header: "x-powered-by",
    required: false,
    validate: (v) => (v ? "reveals server technology — consider removing" : null),
    note: "Should be absent to avoid leaking stack info",
  },
  {
    header: "server",
    required: false,
    validate: (v) => (v ? "reveals server version — consider removing" : null),
    note: "Should be absent or generic to avoid leaking version info",
  },
];

function grade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

export async function auditHeaders(url: string): Promise<HeadersResult> {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  let res: Response;
  try {
    res = await fetch(url, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new Error(`Failed to fetch ${url}: ${err instanceof Error ? err.message : String(err)}`);
  }

  const checks: HeaderCheck[] = [];
  const missing: string[] = [];
  let earned = 0;
  let possible = 0;

  for (const rule of CHECKS) {
    const value = res.headers.get(rule.header);
    const present = value !== null;

    let note = rule.note;
    if (present && rule.validate) {
      const warn = rule.validate(value!);
      if (warn) note = `Warning: ${warn}`;
    }

    // Scoring: required headers = 15pts each, optional = 5pts
    const pts = rule.required ? 15 : 5;

    // Special case: x-powered-by and server lose points if PRESENT
    const isLeakHeader = rule.header === "x-powered-by" || rule.header === "server";
    if (isLeakHeader) {
      possible += pts;
      if (!present) earned += pts;
    } else if (rule.required || present) {
      possible += pts;
      if (present && (!rule.validate || !rule.validate(value!))) earned += pts;
    }

    if (rule.required && !present) missing.push(rule.header);

    checks.push({ header: rule.header, present, value, required: rule.required, note });
  }

  const score = possible > 0 ? Math.round((earned / possible) * 100) : 0;

  return { url: res.url || url, score, grade: grade(score), checks, missing };
}
