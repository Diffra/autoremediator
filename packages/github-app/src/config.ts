import type { GitHubAppConfig } from "./types.js";

function parseBooleanEnv(name: string, value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) {
    return defaultValue;
  }

  if (value === "true") {
    return true;
  }

  if (value === "false") {
    return false;
  }

  throw new Error(`Invalid ${name}: ${value}. Expected true or false.`);
}

function parseCsvEnv(name: string, value: string | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  const parsed = value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

  if (parsed.length === 0) {
    throw new Error(`Invalid ${name}: expected a comma-separated list with at least one value.`);
  }

  return [...new Set(parsed)];
}

function parsePositiveIntEnv(
  name: string,
  value: string | undefined,
  defaultValue: number,
): number {
  if (value === undefined) {
    return defaultValue;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${name}: ${value}`);
  }

  return parsed;
}

function parseOptionalStringEnv(name: string, value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  const parsed = value.trim();
  if (parsed.length === 0) {
    throw new Error(`Invalid ${name}: expected a non-empty string`);
  }

  return parsed;
}

const ENV_PREFIX = "AUTOREMEDIATOR_GITHUB_APP_";

function requireEnv(env: NodeJS.ProcessEnv, suffix: string): string {
  const value = env[`${ENV_PREFIX}${suffix}`];
  if (!value) {
    throw new Error(`Missing required environment variable: ${ENV_PREFIX}${suffix}`);
  }
  return value;
}

export function loadGitHubAppConfig(env: NodeJS.ProcessEnv = process.env): GitHubAppConfig {
  const flag = (suffix: string, fallback: boolean): boolean =>
    parseBooleanEnv(`${ENV_PREFIX}${suffix}`, env[`${ENV_PREFIX}${suffix}`], fallback);
  const positive = (suffix: string, fallback: number): number =>
    parsePositiveIntEnv(`${ENV_PREFIX}${suffix}`, env[`${ENV_PREFIX}${suffix}`], fallback);
  const text = (suffix: string): string | undefined =>
    parseOptionalStringEnv(`${ENV_PREFIX}${suffix}`, env[`${ENV_PREFIX}${suffix}`]);

  const appId = requireEnv(env, "ID");
  const privateKey = requireEnv(env, "PRIVATE_KEY");
  const webhookSecret = requireEnv(env, "WEBHOOK_SECRET");

  return {
    appId,
    privateKey,
    webhookSecret,
    port: positive("PORT", 3001),
    dataDir: env.AUTOREMEDIATOR_GITHUB_APP_DATA_DIR,
    remediationTriggerTimeoutMs:
      env[`${ENV_PREFIX}TRIGGER_TIMEOUT_MS`] === undefined
        ? undefined
        : positive("TRIGGER_TIMEOUT_MS", 0),
    enableDefaultRemediationHandler: flag("ENABLE_DEFAULT_REMEDIATION", false),
    logEventTraces: flag("LOG_EVENT_TRACES", false),
    maxWebhookBodyBytes: positive("MAX_WEBHOOK_BODY_BYTES", 262_144),
    requireJsonContentType: flag("REQUIRE_JSON_CONTENT_TYPE", true),
    allowedEvents: parseCsvEnv(`${ENV_PREFIX}ALLOWED_EVENTS`, env[`${ENV_PREFIX}ALLOWED_EVENTS`]),
    requireDeliveryId: flag("REQUIRE_DELIVERY_ID", false),
    enableJobQueue: flag("ENABLE_JOB_QUEUE", true),
    queuePollIntervalMs: positive("QUEUE_POLL_INTERVAL_MS", 2000),
    queueRetryDelayMs: positive("QUEUE_RETRY_DELAY_MS", 15_000),
    queueMaxAttempts: positive("QUEUE_MAX_ATTEMPTS", 3),
    jobWorkerConcurrency: positive("WORKER_CONCURRENCY", 1),
    enableScheduler: flag("ENABLE_SCHEDULER", false),
    scheduleIntervalMs: positive("SCHEDULE_INTERVAL_MS", 3_600_000),
    enableStatusPublishing: flag("ENABLE_STATUS_PUBLISHING", false),
    statusCheckName: text("STATUS_CHECK_NAME"),
    baseUrl: text("BASE_URL"),
    enableSetupRoutes: flag("ENABLE_SETUP_ROUTES", true),
    setupSecret: text("SETUP_SECRET"),
    githubUrl: text("GITHUB_URL"),
    githubApiUrl: text("GITHUB_API_URL"),
  };
}

export function requireWebhookSecret(env: NodeJS.ProcessEnv = process.env): string {
  return requireEnv(env, "WEBHOOK_SECRET");
}
