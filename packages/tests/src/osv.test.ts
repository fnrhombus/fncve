import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { queryVulnerabilities, lookupVuln, batchQuery, summarizeVuln } from "fncve/osv";
import type { OsvVulnerability } from "fncve/osv";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function mockResponse(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  };
}

const sampleVuln: OsvVulnerability = {
  id: "GHSA-test-1234-5678",
  summary: "Prototype Pollution in lodash",
  details: "A prototype pollution vulnerability exists in lodash before 4.17.21.",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [
        {
          type: "SEMVER",
          events: [{ introduced: "0" }, { fixed: "4.17.21" }],
        },
      ],
      versions: ["4.17.20", "4.17.19", "4.17.18"],
    },
  ],
  references: [
    { type: "ADVISORY", url: "https://github.com/advisories/GHSA-test-1234-5678" },
    { type: "WEB", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" },
  ],
  aliases: ["CVE-2021-23337"],
};

describe("summarizeVuln", () => {
  it("extracts summary fields from a vulnerability", () => {
    const summary = summarizeVuln(sampleVuln);

    expect(summary.id).toBe("GHSA-test-1234-5678");
    expect(summary.summary).toBe("Prototype Pollution in lodash");
    expect(summary.severity).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(summary.fixed_versions).toContain("4.17.21");
    expect(summary.references).toHaveLength(2);
  });

  it("handles missing severity", () => {
    const vuln = { ...sampleVuln, severity: undefined };
    expect(summarizeVuln(vuln).severity).toBe("UNKNOWN");
  });

  it("handles missing summary (falls back to details)", () => {
    const vuln = { ...sampleVuln, summary: undefined };
    expect(summarizeVuln(vuln).summary).toContain("prototype pollution");
  });

  it("handles completely empty vulnerability", () => {
    const summary = summarizeVuln({ id: "CVE-0000-0000" });
    expect(summary.id).toBe("CVE-0000-0000");
    expect(summary.severity).toBe("UNKNOWN");
    expect(summary.summary).toBe("No description available");
    expect(summary.fixed_versions).toEqual([]);
    expect(summary.affected_versions).toEqual([]);
  });
});

describe("queryVulnerabilities", () => {
  it("sends correct request and returns vulnerabilities", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ vulns: [sampleVuln] }));

    const result = await queryVulnerabilities("lodash", "npm", "4.17.20");

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/query",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          package: { name: "lodash", ecosystem: "npm" },
          version: "4.17.20",
        }),
      }),
    );
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("GHSA-test-1234-5678");
  });

  it("sends request without version when not provided", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ vulns: [] }));

    await queryVulnerabilities("lodash", "npm");

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/query",
      expect.objectContaining({
        body: JSON.stringify({ package: { name: "lodash", ecosystem: "npm" } }),
      }),
    );
  });

  it("returns empty array when no vulns found", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({}));

    const result = await queryVulnerabilities("safe-package", "npm", "1.0.0");
    expect(result).toEqual([]);
  });

  it("throws on API error", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse("Not Found", 404));

    await expect(queryVulnerabilities("nonexistent", "npm")).rejects.toThrow("OSV API error (404)");
  });
});

describe("lookupVuln", () => {
  it("fetches vulnerability by ID", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(sampleVuln));

    const result = await lookupVuln("GHSA-test-1234-5678");

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/vulns/GHSA-test-1234-5678",
      expect.objectContaining({ headers: expect.any(Object) }),
    );
    expect(result.id).toBe("GHSA-test-1234-5678");
  });

  it("encodes special characters in ID", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(sampleVuln));

    await lookupVuln("CVE-2024-1234");

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/vulns/CVE-2024-1234",
      expect.any(Object),
    );
  });

  it("throws on 404 for invalid CVE ID", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse("Not Found", 404));

    await expect(lookupVuln("CVE-0000-0000")).rejects.toThrow("OSV API error (404)");
  });

  it("throws on network error", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Network error"));

    await expect(lookupVuln("CVE-2024-1234")).rejects.toThrow("Network error");
  });
});

describe("batchQuery", () => {
  it("sends batch request and returns results", async () => {
    const batchResponse = {
      results: [{ vulns: [sampleVuln] }, { vulns: [] }],
    };
    mockFetch.mockResolvedValueOnce(mockResponse(batchResponse));

    const queries = [
      { package: { name: "lodash", ecosystem: "npm" as const }, version: "4.17.20" },
      { package: { name: "express", ecosystem: "npm" as const }, version: "4.18.2" },
    ];

    const result = await batchQuery(queries);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/querybatch",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ queries }),
      }),
    );
    expect(result.results).toHaveLength(2);
    expect(result.results[0].vulns).toHaveLength(1);
    expect(result.results[1].vulns).toEqual([]);
  });

  it("throws on API error", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse("Server Error", 500));

    await expect(batchQuery([])).rejects.toThrow("OSV API error (500)");
  });
});
