/**
 * The GET setup routes of the GitHub App manifest flow: /setup, /setup/complete and /install.
 */
import type { IncomingMessage, ServerResponse } from "node:http";

import { writeHtml } from "./http-io.js";
import type { ServerOptions } from "./server-types.js";
import {
  exchangeManifestCode,
  generateStateToken,
  parseStateCookie,
  renderAlreadyConfiguredPage,
  renderInstallPage,
  renderSetupCompletePage,
  renderSetupErrorPage,
  renderSetupForbiddenPage,
  renderSetupPage,
  resolveBaseUrl,
} from "./setup.js";

const CLEAR_STATE_COOKIE =
  "autoremediator_setup_state=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";

/** Handles a setup route. Returns true when the request was answered, false to fall through. */
export async function handleSetupRoute(
  request: IncomingMessage,
  response: ServerResponse,
  options: ServerOptions,
): Promise<boolean> {
  const parsedUrl = new URL(request.url ?? "/", "http://placeholder");

  if (parsedUrl.pathname === "/setup") {
    handleSetupPage(request, response, options, parsedUrl);
    return true;
  }

  if (parsedUrl.pathname === "/setup/complete") {
    await handleSetupComplete(request, response, options, parsedUrl);
    return true;
  }

  if (parsedUrl.pathname === "/install") {
    const installationId = parsedUrl.searchParams.get("installation_id") ?? undefined;
    writeHtml(response, 200, renderInstallPage(installationId));
    return true;
  }

  return false;
}

function handleSetupPage(
  request: IncomingMessage,
  response: ServerResponse,
  options: ServerOptions,
  parsedUrl: URL,
): void {
  // If already configured, show a safe "already registered" page instead
  if (options.appId) {
    writeHtml(response, 200, renderAlreadyConfiguredPage());
    return;
  }
  // Enforce setup secret when configured
  if (options.setupSecret) {
    const providedSecret = parsedUrl.searchParams.get("secret");
    if (providedSecret !== options.setupSecret) {
      writeHtml(response, 403, renderSetupForbiddenPage());
      return;
    }
  }
  const baseUrl = options.baseUrl ?? resolveBaseUrl(request.headers.host);
  const state = generateStateToken();
  writeHtml(
    response,
    200,
    renderSetupPage(baseUrl, options.githubUrl, state),
    `autoremediator_setup_state=${state}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`,
  );
}

async function handleSetupComplete(
  request: IncomingMessage,
  response: ServerResponse,
  options: ServerOptions,
  parsedUrl: URL,
): Promise<void> {
  const code = parsedUrl.searchParams.get("code");
  if (!code) {
    writeHtml(response, 400, renderSetupErrorPage("Missing code parameter from GitHub."));
    return;
  }
  if (code.length < 5 || code.length > 512) {
    writeHtml(response, 400, renderSetupErrorPage("Invalid code parameter length."));
    return;
  }
  const returnedState = parsedUrl.searchParams.get("state");
  const cookieState = parseStateCookie(request.headers.cookie);
  if (!returnedState || !cookieState || returnedState !== cookieState) {
    writeHtml(
      response,
      400,
      renderSetupErrorPage(
        "Invalid or missing state parameter. Possible CSRF attempt. Please start the setup process again.",
      ),
      CLEAR_STATE_COOKIE,
    );
    return;
  }
  response.setHeader("Set-Cookie", CLEAR_STATE_COOKIE);
  try {
    const result = await exchangeManifestCode(code, options.githubApiUrl);
    writeHtml(response, 200, renderSetupCompletePage(result));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error during code exchange";
    writeHtml(response, 500, renderSetupErrorPage(message));
  }
}
