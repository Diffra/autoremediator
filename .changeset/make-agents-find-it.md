---
"autoremediator": minor
---

Make it easier for people and coding agents to find and start. `autoremediator mcp` starts the MCP server, so `npx autoremediator mcp` works for any client that launches a package by name. `package.json` now carries `mcpName` and a shorter, problem-first description and keyword list, and the repository ships `server.json` for the official MCP registry. The Claude Code plugin lists a version, a display name, support and documentation links, and tags, and its description says what it fixes and what it will not do unasked.
