import type { ToolSet } from "ai";

import type { MemoryProposal } from "../memory/index.js";
import { createReadTools, hasNestedQuantifier } from "./read-tools.js";
import type { RepairBudget, RepairCommands } from "./repair-agent.js";
import type { ScopeGuard } from "./scope-guard.js";
import { createWriteTools } from "./write-tools.js";

export { hasNestedQuantifier };

/** Mutable record of what an agent did, shared between the tools and the loop around them. */
export interface RepairState {
  commandRuns: number;
  filesChanged: Set<string>;
  submitted?: string;
  gaveUp?: string;
  /** Memory proposals made so far in this attempt. */
  memoryProposals?: number;
}

export interface RepairToolContext {
  guard: ScopeGuard;
  commands: RepairCommands;
  budget: RepairBudget;
  state: RepairState;
  /** Present when the host takes memory proposals; adds the `proposeMemory` tool. */
  proposeMemory?: (proposal: MemoryProposal) => Promise<string>;
}

/** The tools a built-in agent works with. Each is confined by the guard; none runs free-form commands. */
export function createRepairTools(context: RepairToolContext): ToolSet {
  return { ...createWriteTools(context), ...createReadTools(context.guard) };
}
