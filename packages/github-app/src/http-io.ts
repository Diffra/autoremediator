/**
 * Request and response plumbing for the webhook server: JSON responses with the fixed security
 * headers, HTML responses, bounded body reads and header normalisation.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

export interface JsonResponse {
  statusCode: number;
  body: Record<string, unknown>;
}

export function writeJson(response: ServerResponse, payload: JsonResponse): void {
  response.statusCode = payload.statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("cache-control", "no-store");
  response.end(JSON.stringify(payload.body));
}

export function writeHtml(
  response: ServerResponse,
  statusCode: number,
  html: string,
  setCookie?: string,
): void {
  response.statusCode = statusCode;
  response.setHeader("content-type", "text/html; charset=utf-8");
  if (setCookie !== undefined) {
    response.setHeader("Set-Cookie", setCookie);
  }
  response.end(html);
}

/** First value of a header that Node may deliver as a string or an array of strings. */
export function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function isJsonContentType(headerValue: string | undefined): boolean {
  if (!headerValue) {
    return false;
  }

  return headerValue.toLowerCase().startsWith("application/json");
}

export async function readBody(
  request: IncomingMessage,
  maxWebhookBodyBytes?: number,
): Promise<string> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  for await (const chunk of request) {
    const bufferChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += bufferChunk.byteLength;

    if (maxWebhookBodyBytes !== undefined && totalBytes > maxWebhookBodyBytes) {
      throw new Error("Payload too large");
    }

    chunks.push(bufferChunk);
  }

  return Buffer.concat(chunks).toString("utf8");
}
