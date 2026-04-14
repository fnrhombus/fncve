import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Import the parsers from the core package source directly
// We need to test the parsing logic, so we import from the source
const fixturesDir = resolve(fileURLToPath(import.meta.url), "../../fixtures");

// Since the parsers aren't separately exported from the package bin,
// we'll inline-test the parsing logic by importing source files.
// The core package exports from src/ via workspace link.

// We need to dynamically import the parsers module
async function importParsers() {
  // vitest resolves workspace packages, so we can import from source
  const mod = await import("fncve/parsers");
  return mod;
}

describe("package-lock.json parser", () => {
  it("extracts all dependencies with correct names and versions", async () => {
    const { parsePackageLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "package-lock.json"), "utf-8");
    const deps = parsePackageLock(content);

    expect(deps).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.20" },
        { name: "express", version: "4.18.2" },
        { name: "@types/node", version: "20.10.0" },
      ]),
    );
  });

  it("handles nested node_modules (hoisted deps)", async () => {
    const { parsePackageLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "package-lock.json"), "utf-8");
    const deps = parsePackageLock(content);

    const bodyParser = deps.find((d) => d.name === "body-parser");
    expect(bodyParser).toEqual({ name: "body-parser", version: "1.20.1" });
  });

  it("skips the root package entry", async () => {
    const { parsePackageLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "package-lock.json"), "utf-8");
    const deps = parsePackageLock(content);

    expect(deps.find((d) => d.name === "test-project")).toBeUndefined();
  });

  it("returns empty array for empty packages object", async () => {
    const { parsePackageLock } = await importParsers();
    const deps = parsePackageLock(JSON.stringify({ packages: {} }));
    expect(deps).toEqual([]);
  });
});

describe("pnpm-lock.yaml parser", () => {
  it("extracts dependencies with correct names and versions", async () => {
    const { parsePnpmLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "pnpm-lock.yaml"), "utf-8");
    const deps = parsePnpmLock(content);

    expect(deps).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.21" },
        { name: "express", version: "4.18.2" },
        { name: "@types/node", version: "20.10.0" },
        { name: "body-parser", version: "1.20.1" },
      ]),
    );
  });

  it("handles scoped packages", async () => {
    const { parsePnpmLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "pnpm-lock.yaml"), "utf-8");
    const deps = parsePnpmLock(content);

    const typesNode = deps.find((d) => d.name === "@types/node");
    expect(typesNode).toEqual({ name: "@types/node", version: "20.10.0" });
  });

  it("handles older pnpm format with slash separators", async () => {
    const { parsePnpmLock } = await importParsers();
    const content = `
lockfileVersion: 5.4

packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-abc}
  /@scope/pkg/2.0.0:
    resolution: {integrity: sha512-def}
`;
    const deps = parsePnpmLock(content);

    expect(deps).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.21" },
        { name: "@scope/pkg", version: "2.0.0" },
      ]),
    );
  });
});

describe("yarn.lock parser", () => {
  it("extracts dependencies with correct names and versions", async () => {
    const { parseYarnLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "yarn.lock"), "utf-8");
    const deps = parseYarnLock(content);

    expect(deps).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.21" },
        { name: "express", version: "4.18.2" },
        { name: "@types/node", version: "20.10.0" },
      ]),
    );
  });

  it("deduplicates packages with multiple version ranges", async () => {
    const { parseYarnLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "yarn.lock"), "utf-8");
    const deps = parseYarnLock(content);

    const bodyParsers = deps.filter((d) => d.name === "body-parser");
    expect(bodyParsers).toHaveLength(1);
    expect(bodyParsers[0]).toEqual({ name: "body-parser", version: "1.20.1" });
  });

  it("handles scoped packages", async () => {
    const { parseYarnLock } = await importParsers();
    const content = readFileSync(resolve(fixturesDir, "yarn.lock"), "utf-8");
    const deps = parseYarnLock(content);

    const typesNode = deps.find((d) => d.name === "@types/node");
    expect(typesNode).toEqual({ name: "@types/node", version: "20.10.0" });
  });
});

describe("parseLockfile", () => {
  it("throws for unsupported lockfile formats", async () => {
    const { parseLockfile } = await import("fncve/parsers");
    await expect(parseLockfile("/some/path/requirements.txt")).rejects.toThrow(
      "Unsupported lockfile format",
    );
  });
});
