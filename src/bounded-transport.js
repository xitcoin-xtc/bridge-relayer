import { types } from "node:util";
import { readBoundedText, withDeadline } from "./bounded-response.js";

// Bounded HTTP/JSON-RPC transport for destination adapters. One overall deadline
// covers connection, headers and every body read; streamed bytes are counted
// before retention and before JSON parsing; redirects are forbidden; errors are
// sanitized to stable codes and never contain URLs, bodies or upstream text.
export class TransportError extends Error {
  constructor(code, rpcCode, httpStatus) {
    super("bounded transport unavailable");
    this.code = code;
    if (Number.isSafeInteger(rpcCode)) this.rpcCode = rpcCode;
    if (Number.isSafeInteger(httpStatus)) this.httpStatus = httpStatus;
  }
}

const LOOPBACK = new Set(["127.0.0.1", "[::1]", "localhost"]);
const TRANSPORT_CODES = Object.freeze({ SIGNER_TIMEOUT: "timeout", SIGNER_SIZE: "response_too_large",
  SIGNER_LENGTH: "response_too_large", SIGNER_ENCODING: "invalid_encoding", SIGNER_STREAM: "invalid_response" });
export const TRANSPORT_LIMITS = Object.freeze({ maxTimeoutMs: 60_000, maxBytes: 16 * 1024 * 1024, maxRequestBytes: 131_072 });
// The only request header a caller may add: a Cosmos SDK REST query at one
// committed height. Everything else is fixed by this module.
const REQUEST_HEADERS = Object.freeze({ "x-cosmos-block-height": /^[1-9][0-9]{0,18}$/ });

// HTTPS only, or loopback HTTP when explicitly allowed (reviewed local tunnels).
// Credentials, query strings and fragments are rejected: API keys never belong
// in a public manifest or an RPC URL.
export function endpoint(value, { allowLoopbackHttp = false } = {}) {
  let url;
  try {
    if (typeof value !== "string" || value.length > 2048 || typeof allowLoopbackHttp !== "boolean") throw new Error();
    url = new URL(value);
  } catch { throw new TransportError("invalid_endpoint"); }
  const loopback = LOOPBACK.has(url.hostname);
  if (url.username || url.password || url.search || url.hash || value.includes("#") || value.includes("?")
      || (url.protocol !== "https:" && !(allowLoopbackHttp && loopback && url.protocol === "http:"))) {
    throw new TransportError("invalid_endpoint");
  }
  return url;
}

export function independentEndpoints(values, options = {}) {
  if (!Array.isArray(values) || values.length < 2 || values.length > 4) throw new TransportError("invalid_endpoint");
  const urls = values.map((value) => endpoint(value, options));
  if (new Set(urls.map((url) => url.origin)).size !== urls.length) throw new TransportError("endpoints_not_independent");
  return Object.freeze(urls);
}

function limits(timeoutMs, maxBytes) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TRANSPORT_LIMITS.maxTimeoutMs
      || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > TRANSPORT_LIMITS.maxBytes) throw new TransportError("invalid_limits");
}

export async function boundedRequest(url, { method = "GET", body, timeoutMs = 10_000, maxBytes = 1_048_576,
  fetchImpl = globalThis.fetch, signal, headers = {} } = {}) {
  limits(timeoutMs, maxBytes);
  if (!(url instanceof URL) || typeof fetchImpl !== "function" || !["GET", "POST"].includes(method)
      || (method === "POST" && (typeof body !== "string" || Buffer.byteLength(body) > TRANSPORT_LIMITS.maxRequestBytes))
      || (method === "GET" && body !== undefined)) throw new TransportError("invalid_request");
  if (!headers || typeof headers !== "object" || Array.isArray(headers) || types.isProxy(headers)
      || Object.getPrototypeOf(headers) !== Object.prototype
      || Object.entries(headers).some(([name, value]) => !Object.hasOwn(REQUEST_HEADERS, name)
        || typeof value !== "string" || !REQUEST_HEADERS[name].test(value))) throw new TransportError("invalid_request");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const forward = () => controller.abort();
  if (signal?.aborted) controller.abort();
  signal?.addEventListener?.("abort", forward, { once: true });
  let response, reading = false;
  try {
    response = await withDeadline(() => fetchImpl(url, {
      method, body, redirect: "error", signal: controller.signal, cache: "no-store", credentials: "omit",
      headers: method === "POST" ? { ...headers, accept: "application/json", "content-type": "application/json" }
        : { ...headers, accept: "application/json" },
    }), controller.signal);
    if (!response || typeof response !== "object" || !Number.isSafeInteger(response.status)) throw new TransportError("invalid_response");
    if (response.status < 200 || response.status > 299 || response.redirected === true) {
      throw new TransportError("http_status", undefined, response.status);
    }
    reading = true;
    return await readBoundedText(response, { maxBytes, signal: controller.signal });
  } catch (error) {
    if (error instanceof TransportError) throw error;
    // Read only an own data property; never invoke getters on untrusted errors.
    let category;
    try {
      const descriptor = error && typeof error === "object" && !types.isProxy(error) ? Object.getOwnPropertyDescriptor(error, "code") : undefined;
      category = descriptor && Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
    } catch { /* Untrusted error object. */ }
    throw new TransportError(Object.hasOwn(TRANSPORT_CODES, String(category)) ? TRANSPORT_CODES[category] : "unavailable");
  } finally {
    if (response && !reading) {
      try { Promise.resolve(response.body?.cancel?.()).catch(() => {}); } catch { /* Untrusted cleanup. */ }
    }
    signal?.removeEventListener?.("abort", forward);
    controller.abort();
    clearTimeout(timer);
  }
}

// JSON.parse runs only on byte-bounded text. The iterative walk additionally
// bounds depth and node count before any caller inspects the value.
export function parseBoundedJson(text, { maxDepth = 24, maxNodes = 250_000 } = {}) {
  let value;
  try { value = JSON.parse(text); } catch { throw new TransportError("invalid_json"); }
  const stack = [[value, 0]];
  let nodes = 0;
  while (stack.length) {
    const [item, depth] = stack.pop();
    if (++nodes > maxNodes || depth > maxDepth) throw new TransportError("invalid_json_shape");
    if (item && typeof item === "object") for (const child of Object.values(item)) stack.push([child, depth + 1]);
  }
  return value;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && !types.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

export class BoundedJsonRpcClient {
  #url;
  #timeoutMs;
  #maxBytes;
  #fetch;
  #id = 0;

  constructor({ url, allowLoopbackHttp = false, timeoutMs = 10_000, maxBytes = 1_048_576, fetchImpl = globalThis.fetch }) {
    limits(timeoutMs, maxBytes);
    if (typeof fetchImpl !== "function") throw new TransportError("invalid_request");
    this.#url = endpoint(url, { allowLoopbackHttp });
    this.#timeoutMs = timeoutMs;
    this.#maxBytes = maxBytes;
    this.#fetch = fetchImpl;
  }

  get origin() { return this.#url.origin; }

  async call(method, params = []) {
    if (typeof method !== "string" || !/^[a-z]{2,16}_[A-Za-z]{2,48}$/.test(method) || !Array.isArray(params)) {
      throw new TransportError("invalid_request");
    }
    const id = (this.#id = (this.#id % 1_000_000_000) + 1);
    const text = await boundedRequest(this.#url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      timeoutMs: this.#timeoutMs, maxBytes: this.#maxBytes, fetchImpl: this.#fetch });
    const response = parseBoundedJson(text);
    if (!plainObject(response) || response.jsonrpc !== "2.0" || response.id !== id) throw new TransportError("invalid_response");
    const keys = Object.keys(response).filter((key) => key !== "jsonrpc" && key !== "id");
    if (keys.length !== 1 || !["result", "error"].includes(keys[0])) throw new TransportError("invalid_response");
    if (keys[0] === "error") {
      const rpcCode = plainObject(response.error) ? response.error.code : undefined;
      throw new TransportError("rpc_error", Number.isSafeInteger(rpcCode) ? rpcCode : undefined);
    }
    return response.result;
  }
}

// Adapter for CometBftHttpClient's injected fetch: the body is fully bounded
// before the client sees it, so its JSON parsing never handles unbounded input.
export function createBoundedGetFetch({ timeoutMs = 10_000, maxBytes = 4 * 1024 * 1024, fetchImpl = globalThis.fetch } = {}) {
  limits(timeoutMs, maxBytes);
  if (typeof fetchImpl !== "function") throw new TransportError("invalid_request");
  return async function boundedGet(target, options = {}) {
    const url = target instanceof URL ? target : new URL(String(target));
    const text = await boundedRequest(url, { method: "GET", timeoutMs, maxBytes, fetchImpl, signal: options.signal });
    return Object.freeze({ ok: true, status: 200, headers: Object.freeze({ get: () => null }), text: async () => text });
  };
}
