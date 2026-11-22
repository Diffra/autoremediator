import type { Command } from "commander";

/**
 * `autoremediator mcp` starts the MCP server, the same as the `autoremediator-mcp` binary. It
 * exists because a registry or an agent that launches a package by name gets the package's main
 * binary, which is the CLI. The server is imported when the command runs so the other commands
 * do not pay for loading it.
 */
export function registerMcpCommand(program: Command): void {
  program
    .command("mcp")
    .description("Start the MCP server on stdio, for coding agents and MCP clients")
    .option("--http", "serve streamable HTTP on 127.0.0.1 instead of stdio")
    .action(async () => {
      const { startMcpServer } = await import("../../mcp/server.js");
      await startMcpServer();
    });
}
