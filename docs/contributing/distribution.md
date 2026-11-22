# Distribution

Where Autoremediator is listed, what each listing reads, and what to do after a release. People find it
by searching for the problem, and coding agents find it by searching, by reading a registry, or by
reading `llms.txt`. Each of those reads different fields, so each has an owner file here.

## What each listing reads

| Listing | Read by | Source of truth | Kept in step by |
| ------- | ------- | --------------- | --------------- |
| npm | `npm search`, agents running `npm view`, package pages | `packages/core/package.json`: `description`, `keywords`, `mcpName` | by hand |
| Official MCP registry | MCP clients and directories that mirror it | `server.json` at the repository root | generated, see below |
| Claude Code plugin | `/plugin` listings and Anthropic's directory | `integrations/claude-code/.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | generated, see below |
| `llms.txt` | Agents that read a project's own summary | `llms.txt` (copied into the npm package on pack) | by hand |
| GitHub | Search, topics, crawlers that index marketplaces and MCP servers | The repository description and topics, set in GitHub | by hand |

`server.json` and the plugin files are written by `packages/core/src/features/init/plugin-files.ts`,
and a test fails when they drift from it or from `package.json` (name, version, `mcpName`).
`pnpm version-packages` regenerates them, so a release never leaves them on the old version.

## Writing for a reader that is choosing

- Lead with the problem in the words someone would search for: a vulnerable npm dependency, a CVE or
  GHSA id, `npm audit`. Put the mechanism second.
- Say what it will not do. An agent deciding between tools skips one whose limits it cannot see.
- Keep the MCP registry description to 100 characters (its schema enforces it).
- Keywords name what it is, what it reads and where it runs. Do not add the name of a product it
  does not work with.

## After a release

1. Publish to npm. The registry checks the published tarball for `mcpName`, so the package comes first.
2. Publish the registry entry from the repository root:

   ```bash
   mcp-publisher login github
   mcp-publisher publish
   ```

   Install `mcp-publisher` from the
   [registry releases](https://github.com/modelcontextprotocol/registry/releases). The name must
   start with `io.github.Diffra/`, so the login has to be an account that can act for that
   organisation.
3. Check the listing: `https://registry.modelcontextprotocol.io/v0/servers?search=autoremediator`.

## Set once, in GitHub

The repository settings are not in the repository. Set the description to one sentence that matches
the package, and add topics. Marketplace and MCP directories crawl these.

```bash
gh repo edit Diffra/autoremediator \
  --description "Fix vulnerable npm dependencies from a CVE, GHSA or audit: smallest safe upgrade, agent repair, verified, rolled back on failure. CLI, MCP server, Claude Code plugin." \
  --homepage "https://www.npmjs.com/package/autoremediator" \
  --add-topic mcp --add-topic mcp-server --add-topic claude-code --add-topic claude-code-plugin \
  --add-topic security --add-topic vulnerability --add-topic cve --add-topic npm --add-topic npm-audit \
  --add-topic supply-chain --add-topic dependabot-alternative --add-topic ai-agent
```

## Submit to directories

These are submissions made by a person, once. Nothing here is automated.

- Anthropic's plugin directory: see
  [Submit to Anthropic's directory](https://code.claude.com/docs/en/plugins/publish.md#submit-to-anthropics-directory).
  The listing reads `documentationUrl`, `supportUrl` and `icon` from `plugin.json`. No icon is set yet;
  add `icon` with a path to an image inside the plugin when there is one.
- MCP directories that do not mirror the official registry (Smithery, Glama, PulseMCP) take a
  repository URL.
