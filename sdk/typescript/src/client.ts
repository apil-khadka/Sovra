import { SovraError } from "./errors.js";
import {
  AuthResource,
  ConsentResource,
  CustodyResource,
  EnrollmentResource,
  ExtractionResource,
  IssuanceResource,
  OpsResource,
  QuarantineResource,
  TrustResource,
  VaultResource,
  VerificationResource,
} from "./resources.js";

export type {
  AuthResource,
  ConsentResource,
  CustodyResource,
  EnrollmentResource,
  ExtractionResource,
  IssuanceResource,
  OpsResource,
  QuarantineResource,
  TrustResource,
  VaultResource,
  VerificationResource,
};

export interface SovraClientOptions {
  /** Base URL: https, or http loopback for local demos. */
  baseUrl: string;
  /** Service-account token. Lives in memory only; scrubbed from messages. */
  token: string;
  /** Per-request timeout in ms. Default 30000. */
  timeoutMs?: number;
  /** Fetch override (tests). Defaults to global fetch. */
  fetchFn?: typeof fetch;
}

export interface Tagged<T> {
  value: T;
  etag: string;
}

/**
 * Sovra machine-API client (SOV-021, OD-16). One client talks to
 * one base URL. Reads retry at most three times on transport
 * failure or 503; writes never retry automatically — callers
 * replay idempotent operations with the original key.
 */
export class SovraClient {
  /** API contract version this SDK targets. */
  static readonly SUPPORTED_CONTRACT = "0.16.0";

  private static readonly MAX_READ_ATTEMPTS = 3;

  readonly ops: OpsResource;
  readonly trust: TrustResource;
  readonly auth: AuthResource;
  readonly issuance: IssuanceResource;
  readonly consent: ConsentResource;
  readonly verification: VerificationResource;
  readonly vault: VaultResource;
  readonly quarantine: QuarantineResource;
  readonly extraction: ExtractionResource;
  readonly enrollment: EnrollmentResource;
  readonly custody: CustodyResource;

  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: SovraClientOptions) {
    this.baseUrl = SovraClient.validatedBase(options.baseUrl);
    if (!options.token || options.token.trim().length === 0) {
      throw new Error("token is required");
    }
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 30000;
    this.fetchFn = options.fetchFn ?? fetch;
    this.ops = new OpsResource(this);
    this.trust = new TrustResource(this);
    this.auth = new AuthResource(this);
    this.issuance = new IssuanceResource(this);
    this.consent = new ConsentResource(this);
    this.verification = new VerificationResource(this);
    this.vault = new VaultResource(this);
    this.quarantine = new QuarantineResource(this);
    this.extraction = new ExtractionResource(this);
    this.enrollment = new EnrollmentResource(this);
    this.custody = new CustodyResource(this);
  }

  toString(): string {
    return `SovraClient{baseUrl=${this.baseUrl}}`;
  }

  static validatedBase(raw: string | undefined): string {
    let url: URL;
    try {
      url = new URL((raw ?? "").trim());
    } catch {
      throw new Error("base URL is malformed");
    }
    const host = url.hostname.toLowerCase();
    const loopback =
      host === "localhost" || host === "127.0.0.1" || host === "::1";
    if (url.protocol === "https:" || (url.protocol === "http:" && loopback)) {
      return url.toString().replace(/\/$/, "");
    }
    throw new Error("base URL must be https, or http loopback for demos");
  }

  /** Plain GET; throws 304 not_modified if the server 304s without a precondition. */
  async get<T>(path: string, ifNoneMatch?: string): Promise<T> {
    const found = await this.getOptional<T>(path, ifNoneMatch);
    if (found === undefined) {
      throw new SovraError(
        304,
        "not_modified",
        "server answered 304 without a precondition",
        false,
      );
    }
    return found;
  }

  /** Raw-text GET for JWKS. */
  async getText(path: string): Promise<string> {
    return this.getRaw(path);
  }

  /**
   * Conditional-read primitive: undefined when the server answers
   * 304. Single attempt, like the Java SDK's getTagged.
   */
  async getTagged<T>(
    path: string,
    ifNoneMatch?: string,
  ): Promise<Tagged<T> | undefined> {
    const headers: Record<string, string> = this.authed();
    if (ifNoneMatch !== undefined) {
      headers["if-none-match"] = ifNoneMatch;
    }
    let res: Response;
    try {
      res = await this.send(path, "GET", headers, undefined);
    } catch (e) {
      throw connectError(e);
    }
    if (res.status === 304) {
      return undefined;
    }
    const etag = res.headers.get("etag") ?? "";
    return { value: await this.requireOk<T>(res), etag };
  }

  /** GET with retries; undefined on 304. */
  async getOptional<T>(
    path: string,
    ifNoneMatch?: string,
  ): Promise<T | undefined> {
    const headers: Record<string, string> = this.authed();
    if (ifNoneMatch !== undefined) {
      headers["if-none-match"] = ifNoneMatch;
    }
    let attempt = 0;
    for (;;) {
      attempt++;
      try {
        const res = await this.send(path, "GET", headers, undefined);
        if (res.status === 304) {
          return undefined;
        }
        if (res.status === 503 && attempt < SovraClient.MAX_READ_ATTEMPTS) {
          await backoff(attempt);
          continue;
        }
        return await this.requireOk<T>(res);
      } catch (e) {
        if (e instanceof SovraError) {
          throw e;
        }
        if (attempt >= SovraClient.MAX_READ_ATTEMPTS) {
          throw connectError(e);
        }
        await backoff(attempt);
      }
    }
  }

  /** POST without automatic retries. Extra headers carry idempotency keys. */
  async post<T>(
    path: string,
    body: unknown,
    headers?: Record<string, string>,
  ): Promise<T> {
    const merged: Record<string, string> = {
      ...this.authed(),
      "content-type": "application/json",
      ...(headers ?? {}),
    };
    let payload: string;
    try {
      payload = JSON.stringify(body ?? {});
    } catch {
      throw new Error("request body is not serializable");
    }
    let res: Response;
    try {
      res = await this.send(path, "POST", merged, payload);
    } catch (e) {
      if (e instanceof SovraError) {
        throw e;
      }
      throw connectError(e);
    }
    return this.requireOk<T>(res);
  }

  private authed(): Record<string, string> {
    return { authorization: `Bearer ${this.token}` };
  }

  private async send(
    path: string,
    method: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<Response> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const init: RequestInit = {
        method,
        headers,
        signal: ctrl.signal,
        redirect: "manual",
      };
      if (body !== undefined) {
        init.body = body;
      }
      const res = await this.fetchFn(this.baseUrl + path, init);
      if (res.status === 0 || res.type === "opaqueredirect") {
        throw new SovraError(0, "redirect_blocked", "redirects are not followed", false);
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  private async getRaw(path: string): Promise<string> {
    const headers: Record<string, string> = this.authed();
    let attempt = 0;
    for (;;) {
      attempt++;
      try {
        const res = await this.send(path, "GET", headers, undefined);
        if (res.status === 503 && attempt < SovraClient.MAX_READ_ATTEMPTS) {
          await backoff(attempt);
          continue;
        }
        if (res.status >= 200 && res.status < 300) {
          return await res.text();
        }
        throw await this.apiError(res);
      } catch (e) {
        if (e instanceof SovraError) {
          throw e;
        }
        if (attempt >= SovraClient.MAX_READ_ATTEMPTS) {
          throw connectError(e);
        }
        await backoff(attempt);
      }
    }
  }

  private async requireOk<T>(res: Response): Promise<T> {
    if (res.status >= 200 && res.status < 300) {
      const text = await res.text();
      if (text.length === 0) {
        return undefined as T;
      }
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new SovraError(
          res.status,
          "decode_error",
          "response shape is not this SDK's contract",
          false,
        );
      }
    }
    throw await this.apiError(res);
  }

  private async apiError(res: Response): Promise<SovraError> {
    let code = `http_${res.status}`;
    let message = `backend responded ${res.status}`;
    try {
      const node = (await res.json()) as Record<string, unknown>;
      if (node !== null && typeof node === "object") {
        const named = node["code"] ?? node["title"] ?? node["error"];
        if (typeof named === "string") {
          code = named;
        }
        const reason = node["reason"];
        message = code + (typeof reason === "string" ? `:${reason}` : "");
      }
    } catch {
      // Fall through with the generic shape.
    }
    return new SovraError(res.status, code, this.scrub(message), res.status === 503);
  }

  private scrub(message: string): string {
    return this.token.length === 0
      ? message
      : message.split(this.token).join("[redacted]");
  }
}

function connectError(_cause: unknown): SovraError {
  return new SovraError(0, "connect_error", "backend unreachable", true);
}

function backoff(attempt: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 200 * attempt));
}
