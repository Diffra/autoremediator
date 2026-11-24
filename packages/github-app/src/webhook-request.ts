/**
 * The POST /webhook route: validates the delivery (headers, content type, body, signature,
 * payload), then ignores, de-duplicates or dispatches the event and records what happened.
 */
import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import { dispatchGitHubEvent } from "./events.js";
import { firstHeader, isJsonContentType, readBody, writeJson } from "./http-io.js";
import { incrementCounter, recordWebhookLatency } from "./runtime-counters.js";
import type { RuntimeCounters, ServerOptions } from "./server-types.js";
import { verifyWebhookSignature } from "./signature.js";
import type { DispatchResult, EventProcessingTrace } from "./types.js";

export interface WebhookExchange {
  response: ServerResponse;
  options: ServerOptions;
  requestId: string;
  startedAt: number;
}

interface Rejection {
  statusCode: number;
  error: string;
}

interface Delivery {
  eventName: string;
  deliveryId: string | undefined;
}

export function readRequestId(request: IncomingMessage): string {
  return firstHeader(request.headers["x-request-id"]) ?? randomUUID();
}

export async function handleWebhookRequest(
  request: IncomingMessage,
  exchange: WebhookExchange,
): Promise<void> {
  const { options } = exchange;
  if (options.runtimeCounters) {
    options.runtimeCounters.totalRequests += 1;
  }

  const eventName = firstHeader(request.headers["x-github-event"]);
  const deliveryId = readDeliveryId(request.headers["x-github-delivery"]);
  const eventNameForTrace = eventName ?? "unknown";
  const reject = (rejection: Rejection) =>
    emitRejected(exchange, { ...rejection, eventName: eventNameForTrace, deliveryId });

  const headerRejection = checkDeliveryHeaders(request, options, deliveryId);
  if (headerRejection) {
    return reject(headerRejection);
  }

  const body = await readWebhookBody(request, options);
  if (typeof body !== "string") {
    return reject(body);
  }

  const signatureHeader = firstHeader(request.headers["x-hub-signature-256"]);
  if (!verifyWebhookSignature(options.webhookSecret, body, signatureHeader)) {
    return reject({ statusCode: 401, error: "Invalid webhook signature" });
  }

  const payload = parsePayload(body);
  if (!payload) {
    return reject({ statusCode: 400, error: "Invalid JSON payload" });
  }

  if (!eventName) {
    return reject({ statusCode: 400, error: "Missing x-github-event header" });
  }

  const delivery: Delivery = { eventName, deliveryId };
  if (options.allowedEvents && !options.allowedEvents.includes(eventName)) {
    return respondIgnored(exchange, delivery);
  }

  if (deliveryId && options.stateStore?.hasProcessedDelivery(deliveryId)) {
    return respondDuplicate(exchange, delivery);
  }

  return dispatchAndRespond(exchange, delivery, payload);
}

/** Drops delivery ids with unsafe characters (log injection prevention). */
function readDeliveryId(header: string | string[] | undefined): string | undefined {
  const deliveryId = firstHeader(header);
  if (deliveryId && (deliveryId.length > 256 || !/^[\w.-]+$/.test(deliveryId))) {
    return undefined;
  }
  return deliveryId;
}

function checkDeliveryHeaders(
  request: IncomingMessage,
  options: ServerOptions,
  deliveryId: string | undefined,
): Rejection | undefined {
  if (options.requireDeliveryId && !deliveryId) {
    return { statusCode: 400, error: "Missing x-github-delivery header" };
  }

  if (options.requireJsonContentType !== false) {
    const contentType = firstHeader(request.headers["content-type"]);
    if (!isJsonContentType(contentType)) {
      return { statusCode: 415, error: "Unsupported content type" };
    }
  }

  return undefined;
}

async function readWebhookBody(
  request: IncomingMessage,
  options: ServerOptions,
): Promise<string | Rejection> {
  try {
    return await readBody(request, options.maxWebhookBodyBytes);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to read webhook payload";
    if (message === "Payload too large") {
      return { statusCode: 413, error: "Payload too large" };
    }
    return { statusCode: 400, error: message };
  }
}

function parsePayload(rawBody: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(rawBody) as Record<string, unknown>;
  } catch {
    // Not valid JSON: the caller answers with a 400 for the malformed payload.
    return undefined;
  }
}

async function emitRejected(
  exchange: WebhookExchange,
  details: Rejection & { eventName: string; deliveryId?: string },
): Promise<void> {
  const { response, options, requestId, startedAt } = exchange;
  if (options.runtimeCounters) {
    const latencyMs = Date.now() - startedAt;
    options.runtimeCounters.rejected += 1;
    incrementCounter(options.runtimeCounters.byStatusCode, String(details.statusCode));
    incrementCounter(options.runtimeCounters.byEvent, details.eventName);
    recordWebhookLatency(options.runtimeCounters, latencyMs);
  }

  await options.onEventProcessed?.({
    requestId,
    eventName: details.eventName,
    deliveryId: details.deliveryId,
    status: "rejected",
    statusCode: details.statusCode,
    latencyMs: Date.now() - startedAt,
    reason: details.error,
    processedAt: new Date().toISOString(),
  });

  response.setHeader("x-request-id", requestId);
  writeJson(response, {
    statusCode: details.statusCode,
    body: { error: details.error },
  });
}

async function respondIgnored(exchange: WebhookExchange, delivery: Delivery): Promise<void> {
  const { options, requestId, startedAt } = exchange;
  const { eventName, deliveryId } = delivery;
  if (options.runtimeCounters) {
    options.runtimeCounters.webhookRequests += 1;
    options.runtimeCounters.ignored += 1;
    incrementCounter(options.runtimeCounters.byEvent, eventName);
    incrementCounter(options.runtimeCounters.byStatusCode, "202");
  }

  const reason = `Event not allowed: ${eventName}`;
  const trace: EventProcessingTrace = {
    requestId,
    eventName,
    deliveryId,
    status: "ignored",
    statusCode: 202,
    latencyMs: Date.now() - startedAt,
    reason,
    processedAt: new Date().toISOString(),
  };
  await options.onEventProcessed?.(trace);

  respondAccepted(exchange, { status: "ignored", reason, delivery });
}

async function respondDuplicate(exchange: WebhookExchange, delivery: Delivery): Promise<void> {
  const { options, requestId, startedAt } = exchange;
  const { eventName, deliveryId } = delivery;
  if (options.runtimeCounters) {
    const latencyMs = Date.now() - startedAt;
    options.runtimeCounters.webhookRequests += 1;
    options.runtimeCounters.duplicate += 1;
    incrementCounter(options.runtimeCounters.byEvent, eventName);
    incrementCounter(options.runtimeCounters.byStatusCode, "202");
    recordWebhookLatency(options.runtimeCounters, latencyMs);
  }

  const trace: EventProcessingTrace = {
    requestId,
    eventName,
    deliveryId,
    status: "duplicate",
    statusCode: 202,
    latencyMs: Date.now() - startedAt,
    reason: "Webhook delivery already processed",
    processedAt: new Date().toISOString(),
  };
  await options.onEventProcessed?.(trace);

  respondAccepted(exchange, { status: trace.status, reason: trace.reason, delivery });
}

async function dispatchAndRespond(
  exchange: WebhookExchange,
  delivery: Delivery,
  payload: Record<string, unknown>,
): Promise<void> {
  const { options, requestId, startedAt } = exchange;
  const { eventName, deliveryId } = delivery;
  const result = await dispatchGitHubEvent({ eventName, deliveryId }, payload, {
    stateStore: options.stateStore,
    onRemediationRequested: options.onRemediationRequested,
    remediationTriggerTimeoutMs: options.remediationTriggerTimeoutMs,
  });

  if (deliveryId && options.stateStore && result.status !== "ignored") {
    options.stateStore.markDeliveryProcessed(deliveryId);
  }

  if (options.runtimeCounters) {
    recordDispatchResult(options.runtimeCounters, eventName, result.status, startedAt);
  }

  const trace: EventProcessingTrace = {
    requestId,
    eventName,
    deliveryId,
    installationId: readInstallationId(payload),
    status: result.status,
    statusCode: 202,
    latencyMs: Date.now() - startedAt,
    reason: result.reason,
    processedAt: new Date().toISOString(),
  };
  await options.onEventProcessed?.(trace);

  respondAccepted(exchange, { status: result.status, reason: result.reason, delivery });
}

function recordDispatchResult(
  counters: RuntimeCounters,
  eventName: string,
  status: DispatchResult["status"],
  startedAt: number,
): void {
  const latencyMs = Date.now() - startedAt;
  counters.webhookRequests += 1;
  incrementCounter(counters.byEvent, eventName);
  incrementCounter(counters.byStatusCode, "202");
  if (status === "handled") {
    counters.handled += 1;
  }
  if (status === "ignored") {
    counters.ignored += 1;
  }
  if (status === "duplicate") {
    counters.duplicate += 1;
  }
  recordWebhookLatency(counters, latencyMs);
}

function respondAccepted(
  exchange: WebhookExchange,
  details: { status: string; reason: string | undefined; delivery: Delivery },
): void {
  exchange.response.setHeader("x-request-id", exchange.requestId);
  writeJson(exchange.response, {
    statusCode: 202,
    body: {
      status: details.status,
      reason: details.reason,
      event: details.delivery.eventName,
      deliveryId: details.delivery.deliveryId,
    },
  });
}

function readInstallationId(payload: Record<string, unknown>): number | undefined {
  const installation = payload.installation;
  if (!installation || typeof installation !== "object") {
    return undefined;
  }

  const id = (installation as { id?: unknown }).id;
  return typeof id === "number" && Number.isFinite(id) ? id : undefined;
}
