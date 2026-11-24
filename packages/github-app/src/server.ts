/**
 * The GitHub App webhook HTTP server: routes requests to the health, setup and webhook handlers
 * and wires the job queue, worker, status publisher and scheduler around them.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join } from "node:path";

import { createInstallationTokenProvider, type InstallationTokenProvider } from "./auth.js";
import { handleHealth } from "./health-route.js";
import { writeJson } from "./http-io.js";
import {
  createJobFailedHandler,
  createJobProcessor,
  createQueuedRequestHandler,
  type JobFlowDeps,
} from "./job-processing.js";
import { createFileBackedJobQueue, createInMemoryJobQueue, type JobQueue } from "./queue.js";
import { createDefaultRemediationHandler } from "./remediation-handler.js";
import { createRuntimeCounters, summarizeQueue } from "./runtime-counters.js";
import { startWorkflowDispatchScheduler } from "./scheduler.js";
import type { ServerOptions } from "./server-types.js";
import { handleSetupRoute } from "./setup-routes.js";
import { type AppStateStore, createInMemoryAppStateStore } from "./state.js";
import { createJobStatusPublisher } from "./status-publisher.js";
import { handleWebhookRequest, readRequestId } from "./webhook-request.js";
import { startJobWorker } from "./worker.js";

export async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: ServerOptions,
): Promise<void> {
  const requestStartedAt = Date.now();
  const requestId = readRequestId(request);

  if (request.method === "GET" && request.url === "/health") {
    handleHealth(response, options, requestId);
    return;
  }

  const isSetupRequest = options.enableSetupRoutes !== false && request.method === "GET";
  if (isSetupRequest && (await handleSetupRoute(request, response, options))) {
    return;
  }

  if (request.url === "/webhook" && request.method !== "POST") {
    response.setHeader("allow", "POST");
    response.setHeader("x-request-id", requestId);
    writeJson(response, {
      statusCode: 405,
      body: { error: "Method not allowed" },
    });
    return;
  }

  if (request.method !== "POST" || request.url !== "/webhook") {
    response.setHeader("x-request-id", requestId);
    writeJson(response, {
      statusCode: 404,
      body: { error: "Not found" },
    });
    return;
  }

  await handleWebhookRequest(request, {
    response,
    options,
    requestId,
    startedAt: requestStartedAt,
  });
}

export function createGitHubAppServer(options: ServerOptions): Server {
  const tokenProvider = createTokenProvider(options);
  const stateStore =
    options.stateStore ?? createInMemoryAppStateStore(options.maxTrackedDeliveries);

  const defaultRemediationHandler = createDefaultHandler(options, tokenProvider, stateStore);
  const counters = options.runtimeCounters ?? createRuntimeCounters();

  const normalizedOptions: ServerOptions = {
    ...options,
    stateStore,
    onRemediationRequested: options.onRemediationRequested ?? defaultRemediationHandler,
    runtimeCounters: counters,
  };

  const remediationHandler = normalizedOptions.onRemediationRequested;
  const queue = createQueue(normalizedOptions);

  const statusPublisher = createJobStatusPublisher({
    enabled: normalizedOptions.enableStatusPublishing ?? false,
    checkName: normalizedOptions.statusCheckName,
    githubApiUrl: normalizedOptions.githubApiUrl,
    onTrace: (message) => {
      void normalizedOptions.onStatusTrace?.(message);
    },
  });

  const jobFlow: JobFlowDeps = {
    counters,
    statusPublisher,
    tokenProvider: createTokenProvider(normalizedOptions),
    remediationHandler,
    onError: normalizedOptions.onError,
    onStatusTrace: normalizedOptions.onStatusTrace,
  };

  normalizedOptions.runtimeQueueSnapshot = () => summarizeQueue(queue.listJobs());
  normalizedOptions.onRemediationRequested = createQueuedRequestHandler(
    jobFlow,
    queue,
    normalizedOptions.queueMaxAttempts ?? 3,
  );

  const workerHandle = startJobWorker({
    queue,
    pollIntervalMs: normalizedOptions.queuePollIntervalMs ?? 2000,
    concurrency: normalizedOptions.jobWorkerConcurrency ?? 1,
    retryDelayMs: normalizedOptions.queueRetryDelayMs ?? 15_000,
    processJob: createJobProcessor(jobFlow),
    onJobFailed: createJobFailedHandler(jobFlow),
  });

  const schedulerHandle = normalizedOptions.enableScheduler
    ? startWorkflowDispatchScheduler({
        queue,
        intervalMs: normalizedOptions.scheduleIntervalMs ?? 3_600_000,
        queueMaxAttempts: normalizedOptions.queueMaxAttempts ?? 3,
      })
    : undefined;

  const server = createServer((request, response) => {
    void handleRequestSafely(request, response, normalizedOptions);
  });

  server.on("close", () => {
    workerHandle.stop();
    schedulerHandle?.stop();
  });

  return server;
}

function createTokenProvider(options: ServerOptions): InstallationTokenProvider | undefined {
  return options.appId && options.privateKey
    ? createInstallationTokenProvider({
        appId: options.appId,
        privateKey: options.privateKey,
      })
    : undefined;
}

function createDefaultHandler(
  options: ServerOptions,
  tokenProvider: InstallationTokenProvider | undefined,
  stateStore: AppStateStore,
): ServerOptions["onRemediationRequested"] {
  if (!options.enableDefaultRemediationHandler || !tokenProvider) {
    return undefined;
  }

  return createDefaultRemediationHandler({
    octokitFactory: async (installationId: number) => {
      const { token } = await tokenProvider.getInstallationToken(installationId);
      const { Octokit } = await import("@octokit/rest");
      return new Octokit({ auth: token });
    },
    onError: options.onError,
    stateStore,
    selfAppId: options.appId,
  });
}

function createQueue(options: ServerOptions): JobQueue {
  if (options.enableJobQueue === false || !options.dataDir) {
    return createInMemoryJobQueue();
  }

  return createFileBackedJobQueue(join(options.dataDir, "job-queue.json"));
}

async function handleRequestSafely(
  request: IncomingMessage,
  response: ServerResponse,
  options: ServerOptions,
): Promise<void> {
  try {
    await handleRequest(request, response, options);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected server error";
    void options.onError?.({
      timestamp: new Date().toISOString(),
      source: "github-app",
      level: "error",
      context: "server.handleRequest",
      message,
      error: message,
      stack: error instanceof Error ? error.stack : undefined,
    });
    writeJson(response, {
      statusCode: 500,
      body: { error: message },
    });
  }
}
