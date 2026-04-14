# fncve

**Know if your dependencies are safe. Before your CI does.**

[![npm version](https://img.shields.io/npm/v/fncve.svg)](https://www.npmjs.com/package/fncve)
[![license](https://img.shields.io/npm/l/fncve.svg)](https://github.com/fnrhombus/fncve/blob/main/LICENSE)

An [MCP server](https://modelcontextprotocol.io/) that gives AI coding assistants the ability to look up CVEs and check your dependencies for known vulnerabilities, powered by [OSV.dev](https://osv.dev/).

## What your AI assistant sees

```
Tool: search_vulnerabilities
> { "package": "lodash", "ecosystem": "npm", "version": "4.17.20" }

Found 3 vulnerabilities:
- GHSA-35jh-r3h4-6jhm: Prototype Pollution (CVSS 7.2)
  Fixed in: 4.17.21
...
```

## The problem

AI coding agents add and update dependencies all the time. But they have no way to check whether a package version has known vulnerabilities. `npm audit` exists, but it's not in the AI's toolkit -- it requires a full `node_modules` install and parses human-readable output.

**fncve** gives your AI assistant direct access to the OSV.dev vulnerability database through three focused tools.

## Setup

Add to your Claude Code MCP settings (`~/.claude.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "fncve": {
      "command": "npx",
      "args": ["-y", "fncve"]
    }
  }
}
```

For Cursor, add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "fncve": {
      "command": "npx",
      "args": ["-y", "fncve"]
    }
  }
}
```

## Tools

### `search_vulnerabilities`

Search for known vulnerabilities affecting a specific package.

| Parameter   | Type   | Required | Description                                        |
| ----------- | ------ | -------- | -------------------------------------------------- |
| `package`   | string | yes      | Package name (e.g. `lodash`, `requests`)           |
| `ecosystem` | string | yes      | `npm`, `PyPI`, `crates.io`, `NuGet`, `Go`, `Maven` |
| `version`   | string | no       | Specific version to check                          |

### `lookup_cve`

Look up a specific vulnerability by its ID.

| Parameter | Type   | Required | Description                                       |
| --------- | ------ | -------- | ------------------------------------------------- |
| `cve_id`  | string | yes      | CVE or advisory ID (e.g. `CVE-2024-1234`, `GHSA-...`) |

### `check_lockfile`

Parse a lockfile and check **all** dependencies for known vulnerabilities in a single batch.

| Parameter | Type   | Required | Description                                                  |
| --------- | ------ | -------- | ------------------------------------------------------------ |
| `path`    | string | yes      | Absolute path to `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` |

## Data source

All vulnerability data comes from [OSV.dev](https://osv.dev/), a free, open vulnerability database that aggregates data from dozens of sources including the GitHub Advisory Database, NVD, and ecosystem-specific databases.

## Support

If you find this useful:

- [GitHub Sponsors](https://github.com/sponsors/fnrhombus)
- [Buy Me a Coffee](https://buymeacoffee.com/fnrhombus)

## License

MIT
