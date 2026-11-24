/**
 * The GET /health route: service status, runtime counters and queue depth.
 */
import type { ServerResponse } from "node:http";

import { writeJson } from "./http-io.js";
import type { ServerOptions } from "./server-types.js";

export function handleHealth(
  response: ServerResponse,
  options: ServerOptions,
  requestId: string,
): void {
  const counters = options.runtimeCounters;
  const uptimeSeconds = counters
    ? Math.floor((Date.now() - new Date(counters.startedAt).getTime()) / 1000)
    : undefined;
  const averageLatencyMs =
    counters && counters.webhookRequests + counters.rejected > 0
      ? counters.totalLatencyMs / (counters.webhookRequests + counters.rejected)
      : 0;
  const queue = options.runtimeQueueSnapshot?.();

  response.setHeader("x-request-id", requestId);
  writeJson(response, {
    statusCode: 200,
    body: {
      status: "ok",
      service: "github-app",
      uptimeSeconds,
      counters,
      latency: {
        averageMs: averageLatencyMs,
        maxMs: counters?.maxLatencyMs ?? 0,
      },
      queue,
    },
  });
}
