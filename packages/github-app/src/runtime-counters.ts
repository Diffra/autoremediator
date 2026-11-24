/**
 * Runtime counters for the webhook server: creation, per-request recording and the queue snapshot
 * reported by the health route.
 */
import type { QueueRuntimeSnapshot, RuntimeCounters } from "./server-types.js";
import type { QueueJob } from "./types.js";

export function createRuntimeCounters(): RuntimeCounters {
  return {
    startedAt: new Date().toISOString(),
    totalRequests: 0,
    webhookRequests: 0,
    handled: 0,
    ignored: 0,
    duplicate: 0,
    rejected: 0,
    totalLatencyMs: 0,
    maxLatencyMs: 0,
    byEvent: {},
    byStatusCode: {},
    jobsDequeued: 0,
    jobsSucceeded: 0,
    jobsRetried: 0,
    jobsFailed: 0,
  };
}

export function incrementCounter(map: Record<string, number>, key: string): void {
  map[key] = (map[key] ?? 0) + 1;
}

export function recordWebhookLatency(counters: RuntimeCounters, latencyMs: number): void {
  counters.totalLatencyMs += latencyMs;
  counters.maxLatencyMs = Math.max(counters.maxLatencyMs, latencyMs);
  counters.lastProcessedAt = new Date().toISOString();
}

export function summarizeQueue(jobs: QueueJob[]): QueueRuntimeSnapshot {
  const snapshot: QueueRuntimeSnapshot = {
    depth: jobs.length,
    queued: 0,
    running: 0,
    completed: 0,
    failed: 0,
  };

  for (const job of jobs) {
    snapshot[job.status] += 1;
  }

  return snapshot;
}
