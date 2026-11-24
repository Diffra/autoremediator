/**
 * Option and runtime-state shapes shared by the webhook server and the modules it is split into.
 */
import type { AppStateStore } from "./state.js";
import type {
  ErrorLogger,
  EventProcessingTrace,
  RemediationJobResult,
  RemediationTriggerContext,
} from "./types.js";

export interface ServerOptions {
  webhookSecret: string;
  maxTrackedDeliveries?: number;
  stateStore?: AppStateStore;
  onRemediationRequested?: (
    context: RemediationTriggerContext,
  ) => Promise<RemediationJobResult | void> | RemediationJobResult | void;
  remediationTriggerTimeoutMs?: number;
  enableDefaultRemediationHandler?: boolean;
  onEventProcessed?: (trace: EventProcessingTrace) => Promise<void> | void;
  maxWebhookBodyBytes?: number;
  requireJsonContentType?: boolean;
  allowedEvents?: string[];
  requireDeliveryId?: boolean;
  runtimeCounters?: RuntimeCounters;
  appId?: string;
  privateKey?: string;
  dataDir?: string;
  enableJobQueue?: boolean;
  queuePollIntervalMs?: number;
  queueRetryDelayMs?: number;
  queueMaxAttempts?: number;
  jobWorkerConcurrency?: number;
  enableScheduler?: boolean;
  scheduleIntervalMs?: number;
  runtimeQueueSnapshot?: () => QueueRuntimeSnapshot;
  enableStatusPublishing?: boolean;
  statusCheckName?: string;
  onStatusTrace?: (message: string) => Promise<void> | void;
  baseUrl?: string;
  enableSetupRoutes?: boolean;
  setupSecret?: string;
  githubUrl?: string;
  githubApiUrl?: string;
  onError?: ErrorLogger;
}

export interface RuntimeCounters {
  startedAt: string;
  totalRequests: number;
  webhookRequests: number;
  handled: number;
  ignored: number;
  duplicate: number;
  rejected: number;
  totalLatencyMs: number;
  maxLatencyMs: number;
  lastProcessedAt?: string;
  byEvent: Record<string, number>;
  byStatusCode: Record<string, number>;
  jobsDequeued: number;
  jobsSucceeded: number;
  jobsRetried: number;
  jobsFailed: number;
  lastJobProcessedAt?: string;
}

export interface QueueRuntimeSnapshot {
  depth: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
}
