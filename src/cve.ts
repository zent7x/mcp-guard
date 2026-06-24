import { readFileSync } from "fs";

export interface CveFinding {
  package: string;
  version: string;
  ecosystem: string;
  severity: string;
  id: string;
  summary: string;
  url: string;
}

interface OsvQuery {
  version: string;
  package: { name: string; ecosystem: string };
}

interface OsvVuln {
  id: string;
  summary?: string;
  database_specific?: { severity?: string };
}

async function queryOsv(queries: OsvQuery[]): Promise<Map<string, OsvVuln[]>> {
  const res = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });
  if (!res.ok) throw new Error(`OSV API error: ${res.status}`);

  const data = (await res.json()) as { results: Array<{ vulns?: OsvVuln[] }> };
  const map = new Map<string, OsvVuln[]>();

  for (let i = 0; i < queries.length; i++) {
    const key = `${queries[i].package.name}@${queries[i].version}`;
    map.set(key, data.results[i]?.vulns ?? []);
  }

  return map;
}

function parseDeps(pkgPath: string): Array<{ name: string; version: string }> {
  let raw: string;
  try {
    raw = readFileSync(pkgPath, "utf-8");
  } catch {
    throw new Error(`Cannot read file: ${pkgPath}`);
  }

  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const all = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  return Object.entries(all).map(([name, version]) => ({
    name,
    version: version.replace(/^[\^~>=<]/, ""),
  }));
}

export async function checkCves(pkgJsonPath: string): Promise<CveFinding[]> {
  const deps = parseDeps(pkgJsonPath);
  if (deps.length === 0) return [];

  const BATCH = 100;
  const findings: CveFinding[] = [];

  for (let i = 0; i < deps.length; i += BATCH) {
    const chunk = deps.slice(i, i + BATCH);
    const queries: OsvQuery[] = chunk.map((d) => ({
      version: d.version,
      package: { name: d.name, ecosystem: "npm" },
    }));

    const results = await queryOsv(queries);

    for (const [key, vulns] of results) {
      if (!vulns.length) continue;
      const [name, version] = key.split("@");
      for (const vuln of vulns) {
        findings.push({
          package: name,
          version,
          ecosystem: "npm",
          severity: vuln.database_specific?.severity ?? "UNKNOWN",
          id: vuln.id,
          summary: vuln.summary ?? "No summary available",
          url: `https://osv.dev/vulnerability/${vuln.id}`,
        });
      }
    }
  }

  return findings;
}
