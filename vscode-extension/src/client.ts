import type { AnalyzeResponse, ProfileResponse, VibeGuardConfig } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function postJson<T>(
  url: string,
  code: string,
  options: { headers?: Record<string, string>; timeoutMs: number },
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      body: JSON.stringify({ code }),
      signal: controller.signal,
    });

    const text = await response.text();
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new ApiError(`Invalid JSON from ${url}: ${text.slice(0, 200)}`, response.status);
    }

    if (!response.ok) {
      const detail =
        typeof payload === "object" && payload !== null && "detail" in payload
          ? (payload as { detail: unknown }).detail
          : payload;
      const message =
        typeof detail === "object" && detail !== null && "error_message" in detail
          ? String((detail as { error_message: string }).error_message)
          : typeof detail === "string"
            ? detail
            : `Request failed (${response.status})`;
      throw new ApiError(message, response.status, detail);
    }

    return payload as T;
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    if (err instanceof Error && err.name === "AbortError") {
      throw new ApiError(`Request timed out after ${options.timeoutMs}ms`);
    }
    throw new ApiError(err instanceof Error ? err.message : String(err));
  } finally {
    clearTimeout(timer);
  }
}

export async function checkHealth(baseUrl: string, timeoutMs: number): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(timeoutMs, 10000));
  try {
    const response = await fetch(`${baseUrl}/health`, { signal: controller.signal });
    if (!response.ok) {
      return false;
    }
    const data = (await response.json()) as { status?: string };
    return data.status === "ok";
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export function analyzeCode(config: VibeGuardConfig, code: string): Promise<AnalyzeResponse> {
  return postJson<AnalyzeResponse>(`${config.securityApiUrl}/analyze`, code, {
    timeoutMs: config.requestTimeoutMs,
    headers: {
      "X-Min-Severity": config.minSeverity,
    },
  });
}

export function profileCode(config: VibeGuardConfig, code: string): Promise<ProfileResponse> {
  return postJson<ProfileResponse>(`${config.sandboxApiUrl}/profile`, code, {
    timeoutMs: config.requestTimeoutMs,
  });
}
