import type { InstallationTokenProvider } from "./auth.js";
/**
 * Job lifecycle wiring for the webhook server: enqueue a remediation request with a queued status,
 * run a job through the remediation handler with running/completed statuses, and record failures.
 */
import { errorMessage } from "./errors.js";
import type { JobQueue } from "./queue.js";
import type { RuntimeCounters } from "./server-types.js";
import { readRemediationStatusTarget } from "./status-publisher.js";
import type { JobStatusPublisher, RemediationJobStatusTarget } from "./status-publisher.js";
import type {
  ErrorLogger,
  QueueJob,
  RemediationJobCompletion,
  RemediationJobResult,
  RemediationTriggerContext,
} from "./types.js";

export interface JobFlowDeps {
  counters: RuntimeCounters;
  statusPublisher: JobStatusPublisher;
  tokenProvider: InstallationTokenProvider | undefined;
  remediationHandler:
    | ((
        context: RemediationTriggerContext,
      ) => Promise<RemediationJobResult | void> | RemediationJobResult | void)
    | undefined;
  onError: ErrorLogger | undefined;
  onStatusTrace: ((message: string) => Promise<void> | void) | undefined;
}

export function createQueuedRequestHandler(
  deps: JobFlowDeps,
  queue: JobQueue,
  maxAttempts: number,
): (context: RemediationTriggerContext) => void {
  return (context) => {
    const statusTarget = readRemediationStatusTarget(context.payload);

    queue.enqueue({
      eventName: context.eventName,
      installationId: context.installationId,
      deliveryId: context.deliveryId,
      payload: context.payload,
      dedupeKey: context.deliveryId,
      maxAttempts,
    });

    if (!statusTarget) {
      void deps.onStatusTrace?.(
        `Status publish skipped (queued): missing repository/head_sha for delivery=${context.deliveryId ?? "none"}`,
      );
      return;
    }

    void publishQueuedStatus(deps, context, statusTarget, maxAttempts).catch((error: unknown) => {
      const message = errorMessage(error);
      void deps.onStatusTrace?.(`Status publish failed (queued): ${message}`);
    });
  };
}

export function createJobProcessor(deps: JobFlowDeps): (job: QueueJob) => Promise<void> {
  return (job) => processJob(deps, job);
}

export function createJobFailedHandler(deps: JobFlowDeps): (job: QueueJob) => void {
  return (job) => {
    if (job.status === "queued") {
      deps.counters.jobsRetried += 1;
    }

    if (job.status === "failed") {
      deps.counters.jobsFailed += 1;
      reportTerminalFailure(deps, job);
    }

    deps.counters.lastJobProcessedAt = new Date().toISOString();
  };
}

async function readInstallationToken(
  deps: JobFlowDeps,
  installationId: number | undefined,
): Promise<string | undefined> {
  if (installationId === undefined) {
    return undefined;
  }
  const token = await deps.tokenProvider?.getInstallationToken(installationId);
  return token?.token;
}

async function publishQueuedStatus(
  deps: JobFlowDeps,
  context: RemediationTriggerContext,
  statusTarget: RemediationJobStatusTarget,
  maxAttempts: number,
): Promise<void> {
  const installationToken = await readInstallationToken(deps, context.installationId);
  const now = new Date().toISOString();

  await deps.statusPublisher.publishQueued({
    job: {
      id: context.deliveryId ?? "queued",
      eventName: context.eventName,
      installationId: context.installationId,
      deliveryId: context.deliveryId,
      payload: context.payload,
      status: "queued",
      attempts: 0,
      maxAttempts,
      nextRunAt: now,
      createdAt: now,
      updatedAt: now,
    },
    installationToken,
    target: statusTarget,
  });
}

async function processJob(deps: JobFlowDeps, job: QueueJob): Promise<void> {
  deps.counters.jobsDequeued += 1;

  if (!deps.remediationHandler) {
    throw new Error("No remediation handler configured to process job");
  }

  const installationToken = await readInstallationToken(deps, job.installationId);
  const statusTarget = readRemediationStatusTarget(job.payload);
  if (!statusTarget) {
    void deps.onStatusTrace?.(
      `Status publish skipped (running): missing repository/head_sha for job=${job.id}`,
    );
  } else {
    await deps.statusPublisher.publishRunning({ job, installationToken, target: statusTarget });
  }

  const remediationResult: RemediationJobResult | void = await deps.remediationHandler({
    eventName: job.eventName,
    installationId: job.installationId,
    deliveryId: job.deliveryId,
    payload: job.payload,
    installationToken,
  });

  if (remediationResult?.status === "failed") {
    if (statusTarget) {
      await publishCompletedOrWarn(deps, {
        job,
        installationToken,
        target: statusTarget,
        outcome: "failed",
        reason: remediationResult.reason,
      });
    }
    throw new Error(remediationResult.reason ?? "Remediation job failed");
  }

  if (statusTarget) {
    await publishCompletedOrWarn(deps, {
      job,
      installationToken,
      target: statusTarget,
      outcome: remediationResult?.status ?? "success",
      reason: remediationResult?.reason,
    });
  }

  deps.counters.jobsSucceeded += 1;
  deps.counters.lastJobProcessedAt = new Date().toISOString();
}

interface CompletedStatus {
  job: QueueJob;
  installationToken: string | undefined;
  target: RemediationJobStatusTarget;
  outcome: RemediationJobCompletion;
  reason: string | undefined;
}

/** A failed completion status must not fail the job itself: it is logged as a warning. */
async function publishCompletedOrWarn(deps: JobFlowDeps, status: CompletedStatus): Promise<void> {
  await deps.statusPublisher.publishCompleted(status).catch((err: unknown) => {
    void deps.onError?.({
      timestamp: new Date().toISOString(),
      source: "github-app",
      level: "warn",
      context: "server.publishCompleted",
      message: `Failed to publish completed status: ${errorMessage(err)}`,
      error: errorMessage(err),
    });
  });
}

function reportTerminalFailure(deps: JobFlowDeps, job: QueueJob): void {
  const statusTarget = readRemediationStatusTarget(job.payload);
  if (!statusTarget) {
    void deps.onStatusTrace?.(
      `Status publish skipped (completed): missing repository/head_sha for job=${job.id}`,
    );
    return;
  }

  void (async () => {
    try {
      const installationToken = await readInstallationToken(deps, job.installationId);

      await deps.statusPublisher.publishCompleted({
        job,
        installationToken,
        target: statusTarget,
        outcome: "failed",
        reason: job.lastError,
      });
    } catch (err) {
      void deps.onError?.({
        timestamp: new Date().toISOString(),
        source: "github-app",
        level: "error",
        context: "server.onJobFailed.publishCompleted",
        message: `Failed to publish terminal failed status: ${errorMessage(err)}`,
        error: errorMessage(err),
      });
    }
  })();
}
