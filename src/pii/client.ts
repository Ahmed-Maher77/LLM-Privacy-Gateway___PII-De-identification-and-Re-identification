// Presidio analyzer HTTP client
  // it has timeouts and retries (in specific status codes), and throws PresidioUnavailableError if the service is down


import type { AnalyzeRequest, PresidioRecognizerResult } from "./types";

const PresidioClientConfig = {
  ANALYZER_URL: process.env.PRESIDIO_ANALYZER_URL ?? "http://localhost:5002",
  TIMEOUT_MS: 30_000,
  RETRIES: 2,
  RETRY_DELAY_MS: 250,
  RETRYABLE_STATUS: new Set([502, 503, 504]),
};

class RetryableHttpError extends Error {}

export class PresidioUnavailableError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "PresidioUnavailableError";
  }
}

export class PresidioClient {
  // Send a JSON POST request to Presidio + Handle transient errors with retries
  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const payload = JSON.stringify(body);
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.postOnce<T>(path, payload);
      } catch (err) {
        const transient = err instanceof PresidioUnavailableError || err instanceof RetryableHttpError;
        if (!transient || attempt >= PresidioClientConfig.RETRIES) {
          if (err instanceof RetryableHttpError) throw new Error(err.message);
          throw err;
        }
        await new Promise((r) => setTimeout(r, PresidioClientConfig.RETRY_DELAY_MS * 2 ** attempt));
      }
    }
  }

  // Send a single JSON POST request to Presidio with AbortController timeout
  private async postOnce<T>(path: string, payload: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PresidioClientConfig.TIMEOUT_MS);
    try {
      let res: Response;
      try {
        res = await fetch(`${PresidioClientConfig.ANALYZER_URL}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: payload,
          signal: controller.signal,
        });
      } catch (err) {
        throw new PresidioUnavailableError(
          `Could not reach Presidio at ${PresidioClientConfig.ANALYZER_URL}${path}` +
            `${controller.signal.aborted ? ` (timed out after ${PresidioClientConfig.TIMEOUT_MS} ms)` : ""}. ` +
            `Is the sidecar running (presidio/docker-compose.yml, \`npm run presidio:up\`)?`,
          err,
        );
      }

      if (!res.ok) {
        const bodyText = await res.text().catch(() => "<unreadable body>");
        const message = `Presidio ${path} returned HTTP ${res.status}: ${bodyText}`;
        throw PresidioClientConfig.RETRYABLE_STATUS.has(res.status) ? new RetryableHttpError(message) : new Error(message);
      }

      try {
        return (await res.json()) as T;
      } catch (err) {
        if (controller.signal.aborted) {
          throw new PresidioUnavailableError(`Presidio ${path} timed out after ${PresidioClientConfig.TIMEOUT_MS} ms reading the response`, err);
        }
        throw err;
      }
    } finally {
      clearTimeout(timer);
    }
  }

  // Analyze text for PII using Presidio
  async analyze(req: AnalyzeRequest): Promise<PresidioRecognizerResult[]> {
    return this.postJson<PresidioRecognizerResult[]>("/analyze", req);
  }
}
