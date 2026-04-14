const OSV_BASE = "https://api.osv.dev/v1";

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  aliases?: string[];
}

export interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

export interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[] }>;
}

export interface VulnSummary {
  id: string;
  summary: string;
  severity: string;
  affected_versions: string[];
  fixed_versions: string[];
  references: string[];
}

function extractSeverity(vuln: OsvVulnerability): string {
  if (!vuln.severity?.length) return "UNKNOWN";
  const cvss = vuln.severity.find((s) => s.type === "CVSS_V3") ?? vuln.severity[0];
  return cvss.score;
}

function extractFixedVersions(vuln: OsvVulnerability): string[] {
  const fixed: string[] = [];
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed) fixed.push(event.fixed);
      }
    }
  }
  return [...new Set(fixed)];
}

function extractAffectedVersions(vuln: OsvVulnerability): string[] {
  const versions: string[] = [];
  for (const aff of vuln.affected ?? []) {
    if (aff.versions) versions.push(...aff.versions);
  }
  return versions.length > 10 ? [...versions.slice(0, 10), `... and ${versions.length - 10} more`] : versions;
}

export function summarizeVuln(vuln: OsvVulnerability): VulnSummary {
  return {
    id: vuln.id,
    summary: vuln.summary ?? vuln.details?.slice(0, 200) ?? "No description available",
    severity: extractSeverity(vuln),
    affected_versions: extractAffectedVersions(vuln),
    fixed_versions: extractFixedVersions(vuln),
    references: (vuln.references ?? []).map((r) => r.url).slice(0, 5),
  };
}

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`OSV API error (${res.status}): ${text || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export async function queryVulnerabilities(
  pkg: string,
  ecosystem: string,
  version?: string,
): Promise<OsvVulnerability[]> {
  const body: Record<string, unknown> = {
    package: { name: pkg, ecosystem },
  };
  if (version) body.version = version;

  const data = await fetchJson<OsvQueryResponse>(`${OSV_BASE}/query`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return data.vulns ?? [];
}

export async function lookupVuln(id: string): Promise<OsvVulnerability> {
  return fetchJson<OsvVulnerability>(`${OSV_BASE}/vulns/${encodeURIComponent(id)}`);
}

export interface BatchQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

export async function batchQuery(queries: BatchQuery[]): Promise<OsvBatchResponse> {
  return fetchJson<OsvBatchResponse>(`${OSV_BASE}/querybatch`, {
    method: "POST",
    body: JSON.stringify({ queries }),
  });
}
