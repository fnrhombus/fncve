import { readFile } from "node:fs/promises";
import { basename } from "node:path";

export interface Dependency {
  name: string;
  version: string;
}

/**
 * Parse package-lock.json (v2/v3).
 * The `packages` object has keys like `node_modules/lodash` or
 * `node_modules/@scope/pkg` with a `version` field.
 */
function parsePackageLock(content: string): Dependency[] {
  const json = JSON.parse(content);
  const packages: Record<string, { version?: string }> = json.packages ?? {};
  const deps: Dependency[] = [];

  for (const [key, value] of Object.entries(packages)) {
    if (!key || key === "") continue; // root package
    if (!value.version) continue;

    // key is like "node_modules/lodash" or "node_modules/@scope/pkg"
    // Could also be nested: "node_modules/foo/node_modules/bar"
    const lastNm = key.lastIndexOf("node_modules/");
    if (lastNm === -1) continue;
    const name = key.slice(lastNm + "node_modules/".length);
    if (!name) continue;

    deps.push({ name, version: value.version });
  }

  return deps;
}

/**
 * Parse pnpm-lock.yaml without a YAML library.
 * The `packages:` section has entries like:
 *   lodash@4.17.21:        (pnpm v9+ format)
 *   /lodash/4.17.21:       (older format)
 *   '@scope/pkg@1.0.0':    (scoped, pnpm v9+)
 *   /@scope/pkg/1.0.0:     (scoped, older)
 */
function parsePnpmLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  let inPackages = false;

  for (const line of lines) {
    // Detect the packages: section
    if (/^packages:/.test(line)) {
      inPackages = true;
      continue;
    }

    // End of packages section (next top-level key)
    if (inPackages && /^\S/.test(line) && !line.startsWith(" ") && !line.startsWith("'") && !line.startsWith('"')) {
      inPackages = false;
      continue;
    }

    if (!inPackages) continue;

    // Match package entries — they're indented with 2 spaces or at root level with quotes
    // pnpm v9+: "  lodash@4.17.21:" or "  '@scope/pkg@1.0.0':"
    // older:    "  /lodash/4.17.21:" or "  /@scope/pkg/1.0.0:"
    const trimmed = line.replace(/^ +/, "").replace(/['"]/g, "");

    // Older format: /name/version: or /@scope/name/version:
    const slashMatch = trimmed.match(/^\/(@[^/]+\/[^/]+)\/([^:/\s]+)/) ?? trimmed.match(/^\/([^/@][^/]*)\/([^:/\s]+)/);
    if (slashMatch) {
      deps.push({ name: slashMatch[1], version: slashMatch[2] });
      continue;
    }

    // pnpm v9+ format: name@version: or @scope/name@version:
    const atMatch = trimmed.match(/^(@[^@\s]+\/)/)
      ? trimmed.match(/^(@[^@\s]+)@([^:(\s]+)/)    // scoped: @scope/name@version
      : trimmed.match(/^([^@\s/]+)@([^:(\s]+)/);    // unscoped: name@version
    if (atMatch) {
      deps.push({ name: atMatch[1], version: atMatch[2] });
    }
  }

  return deps;
}

/**
 * Parse yarn.lock v1.
 * Entries look like:
 *   "lodash@^4.17.0", "lodash@~4.17.0":
 *     version "4.17.21"
 */
function parseYarnLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  const seen = new Set<string>();

  let currentNames: string[] = [];

  for (const line of lines) {
    // Skip comments and blank lines
    if (line.startsWith("#") || line.trim() === "") {
      currentNames = [];
      continue;
    }

    // Entry header: "pkg@^version", "pkg@~version":
    // or: pkg@^version, pkg@~version:
    if (!line.startsWith(" ") && line.endsWith(":")) {
      currentNames = [];
      // Extract package names from the header
      const header = line.slice(0, -1); // remove trailing :
      const parts = header.split(",").map((p) => p.trim().replace(/^["']|["']$/g, ""));
      for (const part of parts) {
        // Extract name from "name@version-range"
        const lastAt = part.lastIndexOf("@");
        if (lastAt > 0) {
          currentNames.push(part.slice(0, lastAt));
        }
      }
      continue;
    }

    // Version line: `  version "4.17.21"`
    const versionMatch = line.match(/^\s+version\s+"([^"]+)"/);
    if (versionMatch && currentNames.length > 0) {
      const version = versionMatch[1];
      for (const name of currentNames) {
        const key = `${name}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          deps.push({ name, version });
        }
      }
      currentNames = [];
    }
  }

  return deps;
}

const PARSERS: Record<string, (content: string) => Dependency[]> = {
  "package-lock.json": parsePackageLock,
  "pnpm-lock.yaml": parsePnpmLock,
  "yarn.lock": parseYarnLock,
};

const SUPPORTED_FORMATS = Object.keys(PARSERS);

export async function parseLockfile(path: string): Promise<Dependency[]> {
  const filename = basename(path);
  const parser = PARSERS[filename];
  if (!parser) {
    throw new Error(
      `Unsupported lockfile format: ${filename}. Supported: ${SUPPORTED_FORMATS.join(", ")}`,
    );
  }

  const content = await readFile(path, "utf-8");
  return parser(content);
}

// Export individual parsers for testing
export { parsePackageLock, parsePnpmLock, parseYarnLock };
