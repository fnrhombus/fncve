import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { queryVulnerabilities, lookupVuln, batchQuery, summarizeVuln } from "./osv.js";
import { parseLockfile } from "./parsers.js";

const ECOSYSTEMS = ["npm", "PyPI", "crates.io", "NuGet", "Go", "Maven"] as const;
const BATCH_SIZE = 1000;

const server = new McpServer({
  name: "fncve",
  version: "0.1.0",
});

server.tool(
  "search_vulnerabilities",
  "Search OSV.dev for known vulnerabilities affecting a package",
  {
    package: z.string().describe("Package name (e.g. 'lodash', 'requests')"),
    ecosystem: z.enum(ECOSYSTEMS).describe("Package ecosystem"),
    version: z.string().optional().describe("Specific version to check"),
  },
  async ({ package: pkg, ecosystem, version }) => {
    try {
      const vulns = await queryVulnerabilities(pkg, ecosystem, version);
      if (vulns.length === 0) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ package: pkg, ecosystem, version, vulnerabilities: [], message: "No known vulnerabilities found" }, null, 2),
            },
          ],
        };
      }
      const summaries = vulns.map(summarizeVuln);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ package: pkg, ecosystem, version, count: summaries.length, vulnerabilities: summaries }, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `Error querying vulnerabilities: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "lookup_cve",
  "Look up a specific CVE or vulnerability by ID (e.g. CVE-2024-1234, GHSA-xxxx)",
  {
    cve_id: z.string().describe("CVE or vulnerability ID (e.g. 'CVE-2024-1234', 'GHSA-xxxx-xxxx-xxxx')"),
  },
  async ({ cve_id }) => {
    try {
      const vuln = await lookupVuln(cve_id);
      const result = {
        id: vuln.id,
        aliases: vuln.aliases ?? [],
        summary: vuln.summary ?? "No summary available",
        details: vuln.details ?? "No details available",
        severity: vuln.severity ?? [],
        affected: (vuln.affected ?? []).map((a) => ({
          package: a.package,
          ranges: a.ranges,
          versions: a.versions?.slice(0, 20),
        })),
        references: (vuln.references ?? []).map((r) => ({ type: r.type, url: r.url })),
        fix_versions: (() => {
          const fixes: string[] = [];
          for (const aff of vuln.affected ?? []) {
            for (const range of aff.ranges ?? []) {
              for (const event of range.events) {
                if (event.fixed) fixes.push(event.fixed);
              }
            }
          }
          return [...new Set(fixes)];
        })(),
      };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `Error looking up ${cve_id}: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "check_lockfile",
  "Parse a lockfile and check all dependencies for known vulnerabilities via OSV.dev",
  {
    path: z.string().describe("Absolute path to a lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock)"),
  },
  async ({ path }) => {
    try {
      const deps = await parseLockfile(path);
      if (deps.length === 0) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ total: 0, vulnerable: 0, vulnerabilities: [], message: "No dependencies found in lockfile" }, null, 2) }],
        };
      }

      // Query in batches
      const allResults: Array<{ package: string; version: string; vulns: ReturnType<typeof summarizeVuln>[] }> = [];

      for (let i = 0; i < deps.length; i += BATCH_SIZE) {
        const batch = deps.slice(i, i + BATCH_SIZE);
        const queries = batch.map((d) => ({
          package: { name: d.name, ecosystem: "npm" as const },
          version: d.version,
        }));

        const response = await batchQuery(queries);

        for (let j = 0; j < batch.length; j++) {
          const vulns = response.results[j]?.vulns ?? [];
          if (vulns.length > 0) {
            allResults.push({
              package: batch[j].name,
              version: batch[j].version,
              vulns: vulns.map(summarizeVuln),
            });
          }
        }
      }

      const result = {
        total: deps.length,
        vulnerable: allResults.length,
        vulnerabilities: allResults,
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `Error checking lockfile: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
