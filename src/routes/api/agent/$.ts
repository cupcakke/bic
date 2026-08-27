import { createFileRoute } from "@tanstack/react-router";
import { createHmac, timingSafeEqual } from "crypto";

type Json = Record<string, unknown>;

const ALIAS_PRIMARY = "primary";
const ALIAS_ESCALATION = "escalation";
const ALIAS_CODER = "coder";
const VALID_ALIASES = [ALIAS_PRIMARY, ALIAS_ESCALATION, ALIAS_CODER] as const;

const VALID_INTENTS = ["general", "code", "research", "creative", "analysis"] as const;
type Intent = (typeof VALID_INTENTS)[number];

const TASK_STATES = [
  "pending",
  "running",
  "paused",
  "waiting_human",
  "completed",
  "failed",
  "cancelled",
] as const;

type TaskState = (typeof TASK_STATES)[number];

const TRANSITIONS: Record<TaskState, TaskState[]> = {
  pending: ["running", "paused", "cancelled", "failed", "waiting_human"],
  running: ["paused", "waiting_human", "completed", "failed", "cancelled"],
  paused: ["running", "cancelled", "failed"],
  waiting_human: ["running", "paused", "cancelled", "failed"],
  completed: [],
  failed: ["pending", "running"],
  cancelled: [],
};

const PHASES = [
  "created",
  "planning",
  "researching",
  "executing",
  "reviewing",
  "writing",
  "blocked",
  "finished",
] as const;

type Phase = (typeof PHASES)[number];

const VALID_WEBHOOK_TYPES = [
  "github",
  "slack",
  "stripe",
  "task_update",
  "custom",
  "external",
] as const;

const SUPPORTED_TOOLS = [
  "shell.exec",
  "sandbox.provision",
  "sandbox.terminate",
  "browser.session",
  "browser.navigate",
  "browser.close",
  "research.search",
  "mcp.invoke",
  "artifact.write",
  "model.complete",
] as const;

const SENSITIVE_KEYS = new Set([
  "authorization",
  "token",
  "secret",
  "password",
  "api_key",
  "apikey",
  "modal_proxy_token_secret",
  "modal_proxy_token_id",
  "requesty_api_key",
  "exa_api_key",
  "instavm_api_key",
  "agent_master_key",
  "agent_webhook_secret",
  "cookie",
  "set-cookie",
  "private_key",
  "ciphertext",
  "iv",
]);

const SCHEMA_ASSUMPTIONS = {
  agent_tasks: ["id", "session_id", "tenant_id", "created_by", "objective", "success_criteria", "autonomous", "priority", "state", "phase", "trace_id", "state_data", "version", "lease_owner", "lease_expires_at", "heartbeat_at", "scheduled_at", "final_response", "final_writer_alias", "error", "human_request", "human_input", "human_challenge_hash", "human_challenge_expires_at", "retry_history", "deleted_at", "created_at", "updated_at"],
  agent_sessions: ["id", "external_key", "tenant_id", "created_by", "label", "deleted_at", "created_at", "updated_at"],
  agent_agents: ["id", "task_id", "tenant_id", "parent_id", "role", "alias", "instruction", "depth", "workspace_path", "state", "result", "error", "created_at", "updated_at"],
  agent_sandboxes: ["id", "task_id", "tenant_id", "remote_id", "workspace_path", "status", "metadata", "created_at", "updated_at"],
  agent_browser_sessions: ["id", "task_id", "sandbox_id", "tenant_id", "status", "remote_id", "remote_session_id", "current_url", "history", "metadata", "created_at", "updated_at"],
  agent_sources: ["id", "task_id", "tenant_id", "provider", "url", "canonical_url", "title", "snippet", "published_at", "score", "created_at"],
  agent_mcp_servers: ["id", "name", "tenant_id", "url", "transport", "auth_credential", "tools", "status", "created_at", "updated_at"],
  agent_credentials: ["id", "name", "tenant_id", "ciphertext", "iv", "key_version", "history", "created_at", "updated_at"],
  agent_artifacts: ["id", "task_id", "agent_id", "tenant_id", "path", "mime_type", "size_bytes", "sha256", "content", "created_at", "updated_at"],
  agent_leases: ["id", "name", "owner", "tenant_id", "expires_at", "heartbeat_at", "history", "created_at", "updated_at"],
  agent_events: ["id", "task_id", "agent_id", "tenant_id", "kind", "payload", "trace_id", "created_at"],
  agent_audit: ["id", "actor", "action", "target", "tenant_id", "detail", "trace_id", "created_at"],
  agent_tool_calls: ["id", "task_id", "agent_id", "tenant_id", "tool", "input", "output", "status", "error", "trace_id", "created_at", "finished_at"],
} as const;

const encoder = new TextEncoder();

class ValidationError extends Error {
  public field: string;
  constructor(field: string, message: string) {
    super(message);
    this.name = "ValidationError";
    this.field = field;
  }
}

class CredentialNotFound extends Error {
  constructor(name: string) {
    super(`Credential not found: ${name}`);
    this.name = "CredentialNotFound";
  }
}

class InvalidBase64 extends Error {
  constructor(message = "Invalid base64 encoding") {
    super(message);
    this.name = "InvalidBase64";
  }
}

class WrongKeyVersion extends Error {
  constructor(version: number | string) {
    super(`Unsupported or invalid encryption key version: ${version}`);
    this.name = "WrongKeyVersion";
  }
}

class CorruptedCiphertext extends Error {
  constructor(message = "Ciphertext corrupted or decryption failed") {
    super(message);
    this.name = "CorruptedCiphertext";
  }
}

class CryptoUnavailable extends Error {
  constructor(message = "Cryptographic subsystem unavailable") {
    super(message);
    this.name = "CryptoUnavailable";
  }
}

class ProviderError extends Error {
  public code: string;
  public status: number;
  constructor(message: string, code = "PROVIDER_ERROR", status = 502) {
    super(message);
    this.name = "ProviderError";
    this.code = code;
    this.status = status;
  }
}

interface AuthContext {
  userId: string;
  tenantId: string;
  role: string;
  token: string;
  isWorker: boolean;
}

function isPlainObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, fieldName: string, maxLength = 65536): string {
  if (typeof value !== "string") {
    throw new ValidationError(fieldName, `${fieldName} must be a string`);
  }
  if (value.length > maxLength) {
    throw new ValidationError(fieldName, `${fieldName} exceeds maximum length of ${maxLength} characters`);
  }
  return value;
}

function requireNonEmptyString(value: unknown, fieldName: string, maxLength = 65536): string {
  const str = requireString(value, fieldName, maxLength).trim();
  if (str.length === 0) {
    throw new ValidationError(fieldName, `${fieldName} cannot be empty`);
  }
  return str;
}

function requireIntegerInRange(value: unknown, fieldName: string, min: number, max: number, defaultValue?: number): number {
  if (value === undefined || value === null) {
    if (defaultValue !== undefined) return defaultValue;
    throw new ValidationError(fieldName, `${fieldName} is required`);
  }
  const num = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(num) || num < min || num > max) {
    throw new ValidationError(fieldName, `${fieldName} must be an integer between ${min} and ${max}`);
  }
  return num;
}

function requirePlainObject(value: unknown, fieldName: string): Json {
  if (!isPlainObject(value)) {
    throw new ValidationError(fieldName, `${fieldName} must be a JSON object`);
  }
  return value;
}

type ChatMessage = { role: string; content: string };

function isValidChatMessage(msg: unknown): msg is ChatMessage {
  if (!isPlainObject(msg)) return false;
  const role = msg["role"];
  const content = msg["content"];
  return (
    typeof role === "string" &&
    ["system", "user", "assistant"].includes(role) &&
    typeof content === "string" &&
    content.trim().length > 0
  );
}

function isValidHttpUrl(stringUrl: string): boolean {
  try {
    const u = new URL(stringUrl);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function normalizeIntent(rawIntent: string | undefined): Intent {
  if (!rawIntent) return "general";
  const lowered = rawIntent.trim().toLowerCase();
  if (lowered === "code" || lowered === "coding" || lowered === "programming" || lowered === "engineer") return "code";
  if (lowered === "research" || lowered === "researcher" || lowered === "search") return "research";
  if (lowered === "creative" || lowered === "writer" || lowered === "writing") return "creative";
  if (lowered === "analysis" || lowered === "analyst") return "analysis";
  if (VALID_INTENTS.includes(lowered as Intent)) return lowered as Intent;
  return "general";
}

function redactSensitiveData(obj: unknown, depth = 0): unknown {
  if (depth > 6) return "[TRUNCATED_DEPTH]";
  if (typeof obj === "string") {
    if (obj.length > 8192) return `${obj.slice(0, 8192)}... [TRUNCATED]`;
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => redactSensitiveData(item, depth + 1));
  }
  if (isPlainObject(obj)) {
    const sanitized: Json = {};
    for (const [k, v] of Object.entries(obj)) {
      if (SENSITIVE_KEYS.has(k.toLowerCase())) {
        sanitized[k] = "[REDACTED]";
      } else {
        sanitized[k] = redactSensitiveData(v, depth + 1);
      }
    }
    return sanitized;
  }
  return obj;
}

function sanitizeExternalErrorMessage(err: unknown, defaultMessage = "External service request failed"): string {
  if (err instanceof ProviderError) return err.message;
  if (err instanceof Error) {
    const msg = err.message;
    if (msg.includes("API key") || msg.includes("Bearer") || msg.includes("token") || msg.includes("secret")) {
      return defaultMessage;
    }
    if (msg.includes("timeout") || msg.includes("abort")) {
      return "External service request timed out";
    }
    return defaultMessage;
  }
  return defaultMessage;
}

function json(data: unknown, status = 200, traceIdValue?: string) {
  try {
    const serialized = JSON.stringify(data);
    const headers: Record<string, string> = {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      "pragma": "no-cache",
      "expires": "0",
      "surrogate-control": "no-store",
    };
    if (traceIdValue) {
      headers["x-trace-id"] = traceIdValue;
    }
    return new Response(serialized, { status, headers });
  } catch (serializationError) {
    const errorBody = JSON.stringify({
      ok: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "Failed to serialize response data",
      },
    });
    return new Response(errorBody, {
      status: 500,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      },
    });
  }
}

function fail(message: string, status = 400, extra: Json = {}, traceIdValue?: string) {
  const { message: _ignored, ...sanitizedExtra } = extra;
  const code = typeof sanitizedExtra["code"] === "string" ? sanitizedExtra["code"] : status === 401 ? "UNAUTHORIZED" : status === 403 ? "FORBIDDEN" : status === 404 ? "NOT_FOUND" : status === 409 ? "CONFLICT" : status === 503 ? "CAPABILITY_UNAVAILABLE" : status >= 500 ? "INTERNAL_ERROR" : "VALIDATION_ERROR";
  return json({ ok: false, error: { code, message, ...sanitizedExtra } }, status, traceIdValue);
}

function env(name: string): string | undefined {
  try {
    if (typeof process !== "undefined" && process?.env) {
      const val = process.env[name];
      return val && val.trim().length > 0 ? val.trim() : undefined;
    }
  } catch {
  }
  try {
    const globalEnv = (globalThis as any)?.env?.[name] ?? (globalThis as any)?.__ENV__?.[name];
    if (typeof globalEnv === "string" && globalEnv.trim().length > 0) return globalEnv.trim();
  } catch {
  }
  return undefined;
}

function traceId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function nowIso() {
  return new Date().toISOString();
}

interface QueryFilter<T = unknown> {
  eq(column: string, value: unknown): QueryFilter<T>;
  neq(column: string, value: unknown): QueryFilter<T>;
  is(column: string, value: unknown): QueryFilter<T>;
  in(column: string, values: unknown[]): QueryFilter<T>;
  lt(column: string, value: unknown): QueryFilter<T>;
  lte(column: string, value: unknown): QueryFilter<T>;
  gt(column: string, value: unknown): QueryFilter<T>;
  gte(column: string, value: unknown): QueryFilter<T>;
  or(filters: string): QueryFilter<T>;
  order(column: string, options?: { ascending?: boolean }): QueryFilter<T>;
  limit(count: number): QueryFilter<T>;
  select(columns?: string): QueryFilter<T>;
  single(): Promise<{ data: T | null; error: { message: string; code?: string } | null }>;
  maybeSingle(): Promise<{ data: T | null; error: { message: string; code?: string } | null }>;
  then<TResult1 = { data: T[] | null; error: { message: string; code?: string } | null }>(
    onfulfilled?: ((value: { data: T[] | null; error: { message: string; code?: string } | null }) => TResult1 | PromiseLike<TResult1>) | null,
  ): Promise<TResult1>;
}

interface DatabaseTable<T = Json> {
  select(columns?: string): QueryFilter<T>;
  insert(values: unknown): QueryFilter<T>;
  update(values: unknown): QueryFilter<T>;
  upsert(values: unknown, options?: { onConflict?: string }): QueryFilter<T>;
  delete(): QueryFilter<T>;
}

interface DatabaseClient {
  from(table: string): DatabaseTable;
  rpc(name: string, args?: Json): Promise<{ data: unknown; error: { message: string } | null }>;
}

let verifiedSchema = false;

async function db(): Promise<DatabaseClient> {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const client = supabaseAdmin as unknown as DatabaseClient;
  if (!verifiedSchema) {
    if (!client || typeof client.from !== "function") {
      throw new Error("Supabase client initialized improperly: missing from() method");
    }
    verifiedSchema = true;
  }
  return client;
}

async function audit(actor: string, action: string, target: string | null, detail: Json = {}, traceIdVal?: string, tenantIdVal?: string) {
  try {
    const client = await db();
    await client.from("agent_audit").insert({
      actor,
      action,
      target,
      tenant_id: tenantIdVal ?? null,
      detail: redactSensitiveData(detail),
      trace_id: traceIdVal ?? null,
      created_at: nowIso(),
    });
  } catch {
  }
}

async function emit(taskId: string | null, kind: string, payload: Json = {}, agentId: string | null = null, traceIdVal?: string, tenantIdVal?: string) {
  try {
    const client = await db();
    await client.from("agent_events").insert({
      task_id: taskId,
      agent_id: agentId,
      tenant_id: tenantIdVal ?? null,
      kind,
      payload: redactSensitiveData(payload),
      trace_id: traceIdVal ?? null,
      created_at: nowIso(),
    });
  } catch {
  }
}

function parseBearerToken(authHeader: string | null): { token: string } {
  if (!authHeader || !authHeader.trim().startsWith("Bearer ")) {
    throw new Error("missing or invalid authorization header");
  }
  const token = authHeader.trim().slice(7).trim();
  if (!token) {
    throw new Error("empty bearer token");
  }
  return { token };
}

function verifyAndExtractAuth(token: string): AuthContext {
  const jwtSecret = env("AGENT_JWT_SECRET") ?? env("AGENT_MASTER_KEY") ?? env("SUPABASE_JWT_SECRET");
  const parts = token.split(".");
  if (parts.length === 3) {
    const [headerB64, payloadB64, signatureB64] = parts;
    if (jwtSecret) {
      const dataToSign = `${headerB64}.${payloadB64}`;
      const expectedSig = createHmac("sha256", jwtSecret).update(dataToSign).digest("base64url");
      const sigBuf = Buffer.from(signatureB64);
      const expBuf = Buffer.from(expectedSig);
      if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
        throw new Error("invalid token signature");
      }
    } else {
      throw new Error("server JWT verification secret is not configured");
    }
    try {
      const payloadJson = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
      if (!isPlainObject(payloadJson)) throw new Error("invalid token payload");
      const exp = Number(payloadJson["exp"]);
      if (Number.isFinite(exp) && exp * 1000 < Date.now()) {
        throw new Error("token has expired");
      }
      const tenantId = String(payloadJson["tenant_id"] ?? payloadJson["app_metadata"]?.["tenant_id"] ?? payloadJson["sub"] ?? "default_tenant");
      const userId = String(payloadJson["sub"] ?? payloadJson["user_id"] ?? "anonymous_user");
      const role = String(payloadJson["role"] ?? payloadJson["app_metadata"]?.["role"] ?? "authenticated");
      const isWorker = role === "worker" || payloadJson["worker"] === true || role === "admin" || tenantId === "system";
      return { userId, tenantId, role, token, isWorker };
    } catch (err) {
      if ((err as Error).message.includes("expired") || (err as Error).message.includes("signature")) throw err;
      throw new Error("failed to parse token payload");
    }
  }

  const staticAdminKey = env("AGENT_ADMIN_KEY") ?? env("AGENT_MASTER_KEY");
  if (staticAdminKey && token === staticAdminKey) {
    return { userId: "admin", tenantId: "system", role: "admin", token, isWorker: true };
  }

  throw new Error("invalid authorization token format: cryptographic verification failed");
}

const cryptoKeyCache = new Map<string, CryptoKey>();

function getMasterKeyMaterial(version: number): string {
  const versionSpecific = env(`AGENT_MASTER_KEY_V${version}`);
  if (versionSpecific) return versionSpecific;
  const currentKey = env("AGENT_MASTER_KEY");
  if (!currentKey) {
    throw new CryptoUnavailable("AGENT_MASTER_KEY is not configured in environment");
  }
  return currentKey;
}

async function getAesKey(version = 1, credentialName = ""): Promise<CryptoKey> {
  const keyMaterial = getMasterKeyMaterial(version);
  const salt = env("AGENT_KDF_SALT") ?? "agent_credentials_salt_v1";
  const cacheKey = `${version}:${salt}:${credentialName}:${keyMaterial}`;

  const cached = cryptoKeyCache.get(cacheKey);
  if (cached) return cached;

  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new CryptoUnavailable("Web Crypto API is not available in current runtime");
  }

  const kdfInput = encoder.encode(`${salt}:v${version}:${credentialName}:${keyMaterial}`);
  const rawHash = await crypto.subtle.digest("SHA-256", kdfInput);
  const importedKey = await crypto.subtle.importKey(
    "raw",
    rawHash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );

  cryptoKeyCache.set(cacheKey, importedKey);
  return importedKey;
}

function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  try {
    if (typeof Buffer !== "undefined") {
      const buf = Buffer.from(value, "base64");
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    throw new InvalidBase64("invalid base64 encoding in stored credential");
  }
}

async function encryptSecret(plain: string, credentialName = ""): Promise<{ ciphertext: string; iv: string; key_version: number }> {
  const currentVersion = env("AGENT_KEY_VERSION") ? Number(env("AGENT_KEY_VERSION")) : 1;
  if (!Number.isInteger(currentVersion) || currentVersion <= 0) {
    throw new WrongKeyVersion(currentVersion);
  }
  const key = await getAesKey(currentVersion, credentialName);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    const additionalData = encoder.encode(credentialName);
    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData },
      key,
      encoder.encode(plain),
    );
    return {
      ciphertext: toBase64(new Uint8Array(cipher)),
      iv: toBase64(iv),
      key_version: currentVersion,
    };
  } catch (err) {
    throw new CorruptedCiphertext(`encryption operation failed: ${(err as Error).message}`);
  }
}

async function decryptSecret(ciphertext: string, iv: string, keyVersion = 1, credentialName = ""): Promise<string> {
  if (!Number.isInteger(keyVersion) || keyVersion <= 0) {
    throw new WrongKeyVersion(keyVersion);
  }
  const ivBytes = fromBase64(iv);
  if (ivBytes.length !== 12) {
    throw new CorruptedCiphertext(`invalid initialization vector length: expected 12 bytes, got ${ivBytes.length}`);
  }
  const cipherBytes = fromBase64(ciphertext);
  const key = await getAesKey(keyVersion, credentialName);
  try {
    const additionalData = encoder.encode(credentialName);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes, additionalData },
      key,
      cipherBytes,
    );
    return new TextDecoder().decode(plain);
  } catch {
    try {
      const legacyKey = await getAesKey(keyVersion, "");
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes },
        legacyKey,
        cipherBytes,
      );
      return new TextDecoder().decode(plain);
    } catch {
      throw new CorruptedCiphertext("decryption failed: invalid key, corrupted ciphertext, or AAD mismatch");
    }
  }
}

async function readCredential(name: string, auth?: AuthContext): Promise<string> {
  const client = await db();
  let query = client
    .from("agent_credentials")
    .select("ciphertext, iv, key_version, tenant_id")
    .eq("name", name);
  if (auth && auth.tenantId !== "system" && auth.role !== "admin") {
    query = query.or(`tenant_id.is.null,tenant_id.eq.${auth.tenantId}`);
  }
  const { data, error } = await query.maybeSingle();
  if (error) throw new Error(`database error reading credential '${name}': ${error.message}`);
  if (!data) throw new CredentialNotFound(name);

  const row = data as { ciphertext: string; iv: string; key_version?: number };
  const keyVer = Number(row.key_version ?? 1);
  return decryptSecret(row.ciphertext, row.iv, keyVer, name);
}

async function resolveKey(envName: string, credentialName: string, auth?: AuthContext): Promise<string | undefined> {
  const envVal = env(envName);
  if (envVal) return envVal;
  if (!env("AGENT_MASTER_KEY")) return undefined;
  try {
    return await readCredential(credentialName, auth);
  } catch {
    return undefined;
  }
}

async function assertTaskOwnership(taskId: string, auth: AuthContext): Promise<Json> {
  const client = await db();
  const { data, error } = await client
    .from("agent_tasks")
    .select("*")
    .eq("id", taskId)
    .is("deleted_at", null)
    .maybeSingle();
  if (error) throw new Error(`database error fetching task: ${error.message}`);
  if (!data) throw new Error("task not found");
  const taskRow = data as Json;
  if (auth.tenantId !== "system" && auth.role !== "admin") {
    if (taskRow["tenant_id"] && taskRow["tenant_id"] !== auth.tenantId) {
      throw new Error("forbidden: resource belongs to another tenant");
    }
  }
  return taskRow;
}

async function assertSessionOwnership(sessionId: string, auth: AuthContext): Promise<Json> {
  const client = await db();
  const { data, error } = await client
    .from("agent_sessions")
    .select("*")
    .eq("id", sessionId)
    .is("deleted_at", null)
    .maybeSingle();
  if (error) throw new Error(`database error fetching session: ${error.message}`);
  if (!data) throw new Error("session not found");
  const sessionRow = data as Json;
  if (auth.tenantId !== "system" && auth.role !== "admin") {
    if (sessionRow["tenant_id"] && sessionRow["tenant_id"] !== auth.tenantId) {
      throw new Error("forbidden: resource belongs to another tenant");
    }
  }
  return sessionRow;
}

async function assertAgentOwnership(agentId: string, auth: AuthContext): Promise<Json> {
  const client = await db();
  const { data, error } = await client
    .from("agent_agents")
    .select("*")
    .eq("id", agentId)
    .maybeSingle();
  if (error) throw new Error(`database error fetching agent: ${error.message}`);
  if (!data) throw new Error("agent not found");
  const agentRow = data as Json;
  if (auth.tenantId !== "system" && auth.role !== "admin") {
    if (agentRow["tenant_id"] && agentRow["tenant_id"] !== auth.tenantId) {
      throw new Error("forbidden: resource belongs to another tenant");
    }
  }
  return agentRow;
}

async function assertSandboxOwnership(sandboxId: string, auth: AuthContext): Promise<Json> {
  const client = await db();
  const { data, error } = await client
    .from("agent_sandboxes")
    .select("*")
    .eq("id", sandboxId)
    .maybeSingle();
  if (error) throw new Error(`database error fetching sandbox: ${error.message}`);
  if (!data) throw new Error("sandbox not found");
  const sandboxRow = data as Json;
  if (auth.tenantId !== "system" && auth.role !== "admin") {
    if (sandboxRow["tenant_id"] && sandboxRow["tenant_id"] !== auth.tenantId) {
      throw new Error("forbidden: resource belongs to another tenant");
    }
  }
  return sandboxRow;
}

async function assertBrowserSessionOwnership(sessionId: string, auth: AuthContext): Promise<Json> {
  const client = await db();
  const { data, error } = await client
    .from("agent_browser_sessions")
    .select("*")
    .eq("id", sessionId)
    .maybeSingle();
  if (error) throw new Error(`database error fetching browser session: ${error.message}`);
  if (!data) throw new Error("browser session not found");
  const browserRow = data as Json;
  if (auth.tenantId !== "system" && auth.role !== "admin") {
    if (browserRow["tenant_id"] && browserRow["tenant_id"] !== auth.tenantId) {
      throw new Error("forbidden: resource belongs to another tenant");
    }
  }
  return browserRow;
}

async function getCapabilities(auth?: AuthContext) {
  const modalUrl = await resolveKey("MODAL_BASE_URL", "modal_base_url", auth);
  const modalKey = await resolveKey("MODAL_PROXY_TOKEN_SECRET", "modal_proxy_token_secret", auth);
  const modalTokenId = await resolveKey("MODAL_PROXY_TOKEN_ID", "modal_proxy_token_id", auth);
  const requestyKey = await resolveKey("REQUESTY_API_KEY", "requesty_api_key", auth);
  const exaKey = await resolveKey("EXA_API_KEY", "exa_api_key", auth);
  const instavmKey = await resolveKey("INSTAVM_API_KEY", "instavm_api_key", auth);
  const webhookSecret = await resolveKey("AGENT_WEBHOOK_SECRET", "agent_webhook_secret", auth);
  const masterKey = env("AGENT_MASTER_KEY");

  return {
    model_primary: Boolean(modalUrl && modalTokenId && modalKey),
    model_router: Boolean(requestyKey),
    research: Boolean(exaKey),
    sandbox: Boolean(instavmKey),
    browser: Boolean(instavmKey),
    mcp: true,
    artifacts: true,
    webhooks: Boolean(webhookSecret),
    credentials: Boolean(masterKey),
  };
}

async function callPrimary(messages: ChatMessage[], maxTokens = 2048, auth?: AuthContext, traceIdVal?: string): Promise<string> {
  const baseUrl = await resolveKey("MODAL_BASE_URL", "modal_base_url", auth);
  const tokenId = await resolveKey("MODAL_PROXY_TOKEN_ID", "modal_proxy_token_id", auth);
  const tokenSecret = await resolveKey("MODAL_PROXY_TOKEN_SECRET", "modal_proxy_token_secret", auth);
  const modelName =
    (await resolveKey("MODAL_MODEL", "modal_model", auth)) ??
    env("MODAL_MODEL");

  if (!baseUrl || !tokenId || !tokenSecret || !modelName) {
    throw new ProviderError("Primary model is unconfigured or missing credentials", "CONFIG_ERROR", 503);
  }

  const normalizedBase = baseUrl.replace(/\/+$/, "");
  const url = normalizedBase.endsWith("/chat/completions") ? normalizedBase : `${normalizedBase}/chat/completions`;

  const payloadObj: Json = {
    model: modelName,
    messages,
    max_tokens: maxTokens,
    temperature: 0.7,
    top_p: 0.9,
    stream: false,
  };

  if (env("MODAL_ENABLE_REASONING") === "true") {
    payloadObj["reasoning"] = { enabled: true };
  }

  const payload = JSON.stringify(payloadObj);
  const started = Date.now();
  let attempt = 0;

  while (Date.now() - started < 240_000) {
    attempt++;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60_000);

    try {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        Authorization: `Bearer ${tokenId}.${tokenSecret}`,
        "Modal-Key": tokenId,
        "Modal-Secret": tokenSecret,
      };
      if (traceIdVal) headers["X-Trace-Id"] = traceIdVal;

      const res = await fetch(url, {
        method: "POST",
        headers,
        body: payload,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = (await res.json()) as any;
        const content = data?.choices?.[0]?.message?.content;
        if (typeof content !== "string" || content.trim().length === 0) {
          throw new ProviderError("Primary model returned an empty response", "EMPTY_PROVIDER_RESPONSE", 502);
        }
        return content;
      }

      if (res.status < 500 && res.status !== 429) {
        throw new ProviderError("Primary model rejected the request", "PROVIDER_REJECTED", 502);
      }
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof ProviderError) throw error;
    }

    await new Promise((r) => setTimeout(r, Math.min(2000 + attempt * 1000, 8000)));
  }

  throw new ProviderError("Primary model request timed out after multiple retries", "PROVIDER_TIMEOUT", 504);
}

async function callRequesty(model: string, messages: ChatMessage[], maxTokens: number, auth?: AuthContext, traceIdVal?: string): Promise<string> {
  const apiKey = await resolveKey("REQUESTY_API_KEY", "requesty_api_key", auth);
  if (!apiKey) throw new ProviderError("Router model capability is disabled: missing API key", "CONFIG_ERROR", 503);
  if (!model || typeof model !== "string" || model.trim().length === 0) {
    throw new ProviderError("Invalid model parameter specified", "CONFIG_ERROR", 400);
  }

  const routerBaseUrl = env("REQUESTY_BASE_URL") ?? "https://router.requesty.ai/v1";
  const normalizedBase = routerBaseUrl.replace(/\/+$/, "");
  const url = normalizedBase.endsWith("/chat/completions") ? normalizedBase : `${normalizedBase}/chat/completions`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 60_000);

  const payloadObj: Json = {
    model: model.trim(),
    messages,
    max_tokens: maxTokens,
  };

  if (env("REQUESTY_ENABLE_REASONING") === "true") {
    payloadObj["reasoning_effort"] = "high";
  }

  try {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    };
    if (traceIdVal) headers["X-Trace-Id"] = traceIdVal;

    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(payloadObj),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new ProviderError("Router model service request rejected", "PROVIDER_REJECTED", 502);
    }

    const data = (await res.json()) as any;
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || content.trim().length === 0) {
      throw new ProviderError("Router model returned an empty response", "EMPTY_PROVIDER_RESPONSE", 502);
    }
    return content;
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof ProviderError) throw err;
    throw new ProviderError(sanitizeExternalErrorMessage(err, "Router model invocation failed"), "PROVIDER_UNAVAILABLE", 502);
  }
}

function looksRefused(text: string): boolean {
  if (!text || text.trim().length === 0) return true;
  const trimmed = text.trim();
  const refusalPatterns = [
    /^(i\s+cannot|i\s+can't|i\s+am\s+unable\s+to|i'm\s+unable\s+to)\s+(help|assist|comply|fulfill|process|answer)/i,
    /^(as\s+an\s+ai|sorry,\s+but\s+i\s+(cannot|can't)|i\s+must\s+decline)/i,
    /^against\s+(my|our|safety)\s+guidelines/i,
  ];
  return refusalPatterns.some((pattern) => pattern.test(trimmed));
}

function needsEscalation(text: string): boolean {
  if (!text) return true;
  const trimmed = text.trim();
  if (trimmed.length < 5) return true;
  if (/^\[\s*escalate\s*\]$/i.test(trimmed)) return true;
  if (/^i\s+(cannot|can't)\s+solve\s+this/i.test(trimmed)) return true;
  return false;
}

async function routeCompletion(messages: ChatMessage[], intent: string, maxTokens = 2048, auth?: AuthContext, traceIdVal?: string) {
  const normalizedIntent = normalizeIntent(intent);

  if (normalizedIntent === "code") {
    const coderModel = env("REQUESTY_CODER_MODEL") ?? "openai/gpt-5.6-sol:flex";
    try {
      const text = await callRequesty(coderModel, messages, maxTokens, auth, traceIdVal);
      if (!looksRefused(text)) return { alias: ALIAS_CODER, content: text };
    } catch {
    }
    const fallback = await callPrimary(messages, maxTokens, auth, traceIdVal);
    return { alias: ALIAS_PRIMARY, content: fallback };
  }

  let primaryText = "";
  try {
    primaryText = await callPrimary(messages, maxTokens, auth, traceIdVal);
  } catch {
    primaryText = "";
  }

  if (primaryText && !needsEscalation(primaryText)) {
    return { alias: ALIAS_PRIMARY, content: primaryText };
  }

  const escalationModel = env("REQUESTY_ESCALATION_MODEL") ?? "grok-4.3";
  try {
    const escalated = await callRequesty(escalationModel, messages, maxTokens, auth, traceIdVal);
    if (!looksRefused(escalated)) return { alias: ALIAS_ESCALATION, content: escalated };
  } catch {
  }

  if (primaryText) return { alias: ALIAS_PRIMARY, content: primaryText };

  try {
    const finalText = await callPrimary(
      [...messages, { role: "system", content: "Answer fully and directly." }],
      maxTokens,
      auth,
      traceIdVal,
    );
    return { alias: ALIAS_PRIMARY, content: finalText };
  } catch (finalError) {
    throw new ProviderError(sanitizeExternalErrorMessage(finalError, "Model completion failed across all configured routes"), "PROVIDER_UNAVAILABLE", 502);
  }
}

async function instavm(path: string, body?: Json, method = "POST", auth?: AuthContext) {
  const apiKey = await resolveKey("INSTAVM_API_KEY", "instavm_api_key", auth);
  if (!apiKey) throw new ProviderError("Sandbox service capability disabled: missing credentials", "CONFIG_ERROR", 503);
  const base = env("INSTAVM_BASE_URL") ?? "https://api.instavm.io/v1";
  const normalizedPath = `/${path.replace(/^\/+/, "")}`;
  const endpoint = `${base.replace(/\/+$/, "")}${normalizedPath}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120_000);

  try {
    const headers: Record<string, string> = { Authorization: `Bearer ${apiKey}` };
    const options: RequestInit = {
      method: method.toUpperCase(),
      headers,
      signal: controller.signal,
    };
    if (body !== undefined && method.toUpperCase() !== "GET" && method.toUpperCase() !== "HEAD") {
      headers["content-type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const res = await fetch(endpoint, options);
    clearTimeout(timeoutId);
    const text = await res.text();
    if (!res.ok) {
      throw new ProviderError("Sandbox provider request rejected", "PROVIDER_REJECTED", res.status === 404 ? 404 : 502);
    }
    try {
      return JSON.parse(text) as Json;
    } catch {
      return { raw: "[NON_JSON_RESPONSE]" } as Json;
    }
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof ProviderError) throw err;
    throw new ProviderError(sanitizeExternalErrorMessage(err, "Sandbox service communication error"), "PROVIDER_UNAVAILABLE", 502);
  }
}

async function exaSearch(query: string, numResults: number, auth?: AuthContext) {
  const apiKey = await resolveKey("EXA_API_KEY", "exa_api_key", auth);
  if (!apiKey) throw new ProviderError("Research capability disabled: missing API key", "CONFIG_ERROR", 503);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30_000);

  try {
    const res = await fetch("https://api.exa.ai/search", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({
        query,
        numResults,
        type: "auto",
        contents: { text: { maxCharacters: 1200 } },
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const text = await res.text();
    if (!res.ok) {
      throw new ProviderError("Research provider request rejected", "PROVIDER_REJECTED", 502);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new ProviderError("Research provider returned invalid data", "PROVIDER_ERROR", 502);
    }
    if (!isPlainObject(parsed) || !Array.isArray(parsed["results"])) {
      throw new ProviderError("Research provider response format unrecognized", "PROVIDER_ERROR", 502);
    }
    const results = parsed["results"].filter(isPlainObject);
    return { results };
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof ProviderError) throw err;
    throw new ProviderError(sanitizeExternalErrorMessage(err, "Research service invocation failed"), "PROVIDER_UNAVAILABLE", 502);
  }
}

function canonicalUrl(raw: string): string | null {
  if (typeof raw !== "string" || !raw.trim()) return null;
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    url.hash = "";
    url.hostname = url.hostname.replace(/^www\./, "").toLowerCase();
    if ((url.protocol === "http:" && url.port === "80") || (url.protocol === "https:" && url.port === "443")) {
      url.port = "";
    }
    const trackingParams = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "_ga", "mc_eid", "yclid"]);
    const keys = [...url.searchParams.keys()];
    for (const key of keys) {
      if (trackingParams.has(key.toLowerCase())) {
        url.searchParams.delete(key);
      }
    }
    url.searchParams.sort();
    let pathname = url.pathname.replace(/\/+$/, "");
    if (pathname === "") pathname = "/";
    url.pathname = pathname;
    return url.toString();
  } catch {
    return null;
  }
}

function validateAndParseTimestamp(raw: unknown): string | null {
  if (typeof raw !== "string" || !raw.trim()) return null;
  const parsed = new Date(raw.trim());
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function validateAndParseScore(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string" && raw.trim().length > 0) {
    const num = Number(raw.trim());
    if (Number.isFinite(num)) return num;
  }
  return null;
}

async function sha256Hex(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function getTask(id: string) {
  const client = await db();
  const { data, error } = await client
    .from("agent_tasks")
    .select("*")
    .eq("id", id)
    .is("deleted_at", null)
    .maybeSingle();
  if (error) throw new Error(`database error fetching task: ${error.message}`);
  return data as Json | null;
}

async function transition(task: Json, next: TaskState, patch: Json = {}) {
  const rawCurrent = String(task["state"] ?? "");
  if (!TASK_STATES.includes(rawCurrent as TaskState)) {
    throw new Error(`invalid current task state: ${rawCurrent}`);
  }
  const current = rawCurrent as TaskState;

  if (current === next) {
    throw new Error(`illegal self-transition: task is already in state '${current}'`);
  }

  if (["completed", "failed", "cancelled"].includes(current)) {
    throw new Error(`task is in terminal state '${current}' and cannot be transitioned`);
  }

  const allowed = TRANSITIONS[current] ?? [];
  if (!allowed.includes(next)) {
    throw new Error(`illegal transition ${current} -> ${next}`);
  }

  const client = await db();
  const currentVersion = Number.isInteger(Number(task["version"])) ? Number(task["version"]) : 1;
  const currentPatch = { ...patch };

  if (["completed", "failed", "cancelled", "paused", "waiting_human"].includes(next)) {
    currentPatch["lease_owner"] = null;
    currentPatch["lease_expires_at"] = null;
    currentPatch["heartbeat_at"] = null;
  }

  let updateQuery = client
    .from("agent_tasks")
    .update({
      ...currentPatch,
      state: next,
      version: currentVersion + 1,
      updated_at: nowIso(),
    })
    .eq("id", task["id"])
    .eq("state", current)
    .is("deleted_at", null);

  if (task["version"] === null || task["version"] === undefined) {
    updateQuery = updateQuery.is("version", null);
  } else {
    updateQuery = updateQuery.eq("version", task["version"]);
  }

  const { data, error } = await updateQuery.select().maybeSingle();
  if (error) throw new Error(error.message);
  if (!data) throw new Error("task version or state CAS conflict");

  emit(String(task["id"]), "task.state", { from: current, to: next }, null, typeof task["trace_id"] === "string" ? task["trace_id"] : undefined, typeof task["tenant_id"] === "string" ? task["tenant_id"] : undefined);
  return data as Json;
}

async function ensureSession(sessionId: string | undefined, externalKey: string | undefined, auth: AuthContext, label?: string) {
  const client = await db();
  if (sessionId) {
    const { data, error } = await client
      .from("agent_sessions")
      .select("*")
      .eq("id", sessionId)
      .is("deleted_at", null)
      .maybeSingle();
    if (error) throw new Error(`database error fetching session: ${error.message}`);
    if (!data) throw new Error(`session not found: ${sessionId}`);
    const sessionRecord = data as Json;
    if (auth.tenantId !== "system" && auth.role !== "admin" && sessionRecord["tenant_id"] && sessionRecord["tenant_id"] !== auth.tenantId) {
      throw new Error("forbidden: session belongs to another tenant");
    }
    if (externalKey) {
      const { data: extData, error: extError } = await client
        .from("agent_sessions")
        .select("*")
        .eq("external_key", externalKey)
        .is("deleted_at", null)
        .maybeSingle();
      if (extError) throw new Error(`database error validating external_key: ${extError.message}`);
      if (extData && (extData as Json)["id"] !== sessionId) {
        throw new Error(`external_key ${externalKey} belongs to session ${(extData as Json)["id"]}, not ${sessionId}`);
      }
    }
    return { session: sessionRecord, created: false };
  }
  if (externalKey) {
    const { data, error } = await client
      .from("agent_sessions")
      .select("*")
      .eq("external_key", externalKey)
      .is("deleted_at", null)
      .maybeSingle();
    if (error) throw new Error(`database error fetching session by external_key: ${error.message}`);
    if (data) {
      const extSession = data as Json;
      if (auth.tenantId !== "system" && auth.role !== "admin" && extSession["tenant_id"] && extSession["tenant_id"] !== auth.tenantId) {
        throw new Error("forbidden: session belongs to another tenant");
      }
      return { session: extSession, created: false };
    }
  }
  const { data, error } = await client
    .from("agent_sessions")
    .insert({ external_key: externalKey ?? null, label: label ?? null, tenant_id: auth.tenantId, created_by: auth.userId, created_at: nowIso(), updated_at: nowIso() })
    .select()
    .single();
  if (error || !data) throw new Error(error?.message ?? "failed to create session");
  return { session: data as Json, created: true };
}

async function spawnAgents(taskId: string, objective: string, auth: AuthContext) {
  const client = await db();
  const { data: root, error: rootError } = await client
    .from("agent_agents")
    .insert({
      task_id: taskId,
      tenant_id: auth.tenantId,
      role: "orchestrator",
      alias: ALIAS_PRIMARY,
      instruction: objective,
      depth: 0,
      workspace_path: `/workspaces/${taskId}`,
      state: "running",
      created_at: nowIso(),
      updated_at: nowIso(),
    })
    .select()
    .single();
  if (rootError || !root) throw new Error(rootError?.message ?? "failed to create root agent");
  const rootAgent = root as { id: string };
  const children = [
    { role: "researcher", alias: ALIAS_PRIMARY, instruction: `Research: ${objective}` },
    { role: "engineer", alias: ALIAS_CODER, instruction: `Implement and verify: ${objective}` },
    { role: "writer", alias: ALIAS_ESCALATION, instruction: `Produce the final answer: ${objective}` },
  ].map((child) => ({
    ...child,
    task_id: taskId,
    tenant_id: auth.tenantId,
    parent_id: rootAgent.id,
    depth: 1,
    workspace_path: `/workspaces/${taskId}/${child.role}`,
    state: "pending",
    created_at: nowIso(),
    updated_at: nowIso(),
  }));
  const { error: childrenError } = await client.from("agent_agents").insert(children);
  if (childrenError) throw new Error(childrenError.message);
  return root as Json;
}

async function buildTaskExecutionContext(taskId: string, auth: AuthContext): Promise<{ contextPrompt: string; task: Json }> {
  const client = await db();
  const task = await assertTaskOwnership(taskId, auth);

  const [sourcesRes, artifactsRes, agentsRes] = await Promise.all([
    client.from("agent_sources").select("title, url, snippet").eq("task_id", taskId).limit(10),
    client.from("agent_artifacts").select("path, mime_type, content").eq("task_id", taskId).limit(10),
    client.from("agent_agents").select("role, state, result, instruction").eq("task_id", taskId).limit(10),
  ]);

  const sources = (sourcesRes.data ?? []) as Array<{ title?: string; url: string; snippet?: string }>;
  const artifacts = (artifactsRes.data ?? []) as Array<{ path: string; mime_type: string; content: string }>;
  const agents = (agentsRes.data ?? []) as Array<{ role: string; state: string; result?: Json; instruction?: string }>;

  let prompt = `Task Objective: ${task["objective"]}\n`;
  if (Array.isArray(task["success_criteria"]) && task["success_criteria"].length > 0) {
    prompt += `Success Criteria (All must be fulfilled for completion):\n${task["success_criteria"].map((c: string) => `- ${c}`).join("\n")}\n`;
  }
  if (isPlainObject(task["state_data"]) && Object.keys(task["state_data"]).length > 0) {
    prompt += `Task State Data: ${JSON.stringify(task["state_data"])}\n`;
  }
  if (task["human_input"]) {
    prompt += `Prior Human Input: ${JSON.stringify(task["human_input"])}\n`;
  }
  if (sources.length > 0) {
    prompt += `Research Sources:\n${sources.map((s) => `- ${s.title ?? "Source"}: ${s.url} (Snippet: ${s.snippet ?? "N/A"})`).join("\n")}\n`;
  }
  if (artifacts.length > 0) {
    prompt += `Available Artifacts:\n${artifacts.map((a) => `- ${a.path} (${a.mime_type}):\n${a.content.slice(0, 500)}`).join("\n")}\n`;
  }
  const completedAgents = agents.filter((a) => a.state === "completed" && a.result);
  if (completedAgents.length > 0) {
    prompt += `Prior Completed Agent Results:\n${completedAgents.map((a) => `- ${a.role}: ${JSON.stringify(a.result)}`).join("\n")}\n`;
  }

  return { contextPrompt: prompt, task };
}

async function reclaimQuery(client: DatabaseClient, maxBatch = 50) {
  const now = nowIso();
  const boundedLimit = Math.min(Math.max(Number.isInteger(maxBatch) ? maxBatch : 50, 1), 50);
  const { data: expired, error } = await client
    .from("agent_tasks")
    .select("id, version, state, priority, objective")
    .eq("state", "running")
    .is("deleted_at", null)
    .lt("lease_expires_at", now)
    .limit(boundedLimit);

  if (error || !expired || expired.length === 0) return { data: [] };
  const reclaimed: Json[] = [];
  for (const item of expired as Array<{ id: string; version: number | null; state: string; priority: number; objective: string }>) {
    const { data, error: updateError } = await client
      .from("agent_tasks")
      .update({
        state: "pending",
        phase: "created",
        lease_owner: null,
        lease_expires_at: null,
        heartbeat_at: null,
        version: Number(item.version ?? 1) + 1,
        updated_at: nowIso(),
      })
      .eq("id", item.id)
      .eq("version", item.version)
      .eq("state", "running")
      .lt("lease_expires_at", now)
      .is("deleted_at", null)
      .select("id, version, state, priority, objective")
      .maybeSingle();
    if (!updateError && data) reclaimed.push(data as Json);
  }
  return { data: reclaimed };
}

function parseCliArgs(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let inQuotes: "'" | '"' | null = null;
  let escapeNext = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (escapeNext) {
      current += char;
      escapeNext = false;
      continue;
    }
    if (char === "\\") {
      escapeNext = true;
      continue;
    }
    if (inQuotes) {
      if (char === inQuotes) {
        inQuotes = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      inQuotes = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current.length > 0) {
        args.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current.length > 0) {
    args.push(current);
  }
  return args;
}

async function mcpInvokeDirect(
  serverUrl: string,
  transport: string,
  authCredential: string | null,
  rpcMethod: string,
  params: Json,
  auth?: AuthContext,
) {
  if (!isValidHttpUrl(serverUrl)) {
    throw new ProviderError("Invalid server URL specified for MCP invocation", "VALIDATION_ERROR", 400);
  }
  if (transport !== "http" && transport !== "sse") {
    throw new ProviderError(`Unsupported MCP transport: ${transport}`, "VALIDATION_ERROR", 400);
  }

  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (authCredential) {
    const token = await readCredential(authCredential, auth);
    if (!token) {
      throw new ProviderError(`Referenced auth_credential '${authCredential}' is missing or empty`, "NOT_FOUND", 404);
    }
    headers["authorization"] = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30_000);

  try {
    const reqId = crypto.randomUUID();
    const res = await fetch(serverUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: reqId, method: rpcMethod, params }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const contentType = res.headers.get("content-type") ?? "";
    const text = await res.text();
    if (!res.ok) {
      throw new ProviderError("MCP server request rejected", "MCP_REQUEST_FAILED", 502);
    }

    let parsedResult: any = null;
    if (contentType.includes("text/event-stream") || text.includes("event:") || text.includes("data:")) {
      const blocks = text.replace(/^\uFEFF/, "").split(/\r?\n\r?\n/);
      for (const block of blocks) {
        const lines = block.split(/\r?\n/);
        const dataLines = lines
          .map((l) => l.trimStart())
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trim());
        if (dataLines.length === 0) continue;
        const joined = dataLines.join("\n");
        try {
          const evtJson = JSON.parse(joined);
          if (evtJson && (evtJson.id === reqId || evtJson.result !== undefined || evtJson.error !== undefined)) {
            parsedResult = evtJson;
            break;
          }
        } catch {
        }
      }
      if (!parsedResult) {
        throw new ProviderError("No valid JSON-RPC message found in SSE event stream", "MCP_REQUEST_FAILED", 502);
      }
    } else {
      try {
        parsedResult = JSON.parse(text);
      } catch {
        throw new ProviderError("MCP server returned invalid JSON", "MCP_REQUEST_FAILED", 502);
      }
    }

    if (parsedResult && parsedResult.error) {
      throw new ProviderError("MCP server execution error", "MCP_REQUEST_FAILED", 502);
    }

    return parsedResult;
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof ProviderError) throw err;
    throw new ProviderError(sanitizeExternalErrorMessage(err, "MCP server communication error"), "MCP_REQUEST_FAILED", 502);
  }
}

async function mcpInvoke(serverName: string, rpcMethod: string, params: Json, auth?: AuthContext) {
  const canonicalName = serverName.trim().toLowerCase();
  const client = await db();
  let query = client
    .from("agent_mcp_servers")
    .select("*")
    .eq("name", canonicalName);
  if (auth && auth.tenantId !== "system" && auth.role !== "admin") {
    query = query.or(`tenant_id.is.null,tenant_id.eq.${auth.tenantId}`);
  }
  const { data: server, error } = await query.maybeSingle();
  if (error) throw new Error(`database error fetching MCP server: ${error.message}`);
  if (!server) throw new Error(`mcp server not registered: ${canonicalName}`);
  const s = server as { url: string; transport?: string; auth_credential?: string | null };

  if (s.auth_credential) {
    await readCredential(s.auth_credential, auth);
  }

  return mcpInvokeDirect(
    s.url,
    s.transport ?? "http",
    s.auth_credential ?? null,
    rpcMethod,
    params,
    auth,
  );
}

async function recordDirectToolExecution(
  toolName: string,
  input: Json,
  handler: () => Promise<Json>,
  auth: AuthContext,
  taskId: string | null = null,
  agentId: string | null = null,
  traceIdVal?: string,
): Promise<{ ok: boolean; call_id: string; output?: Json; error?: string }> {
  const client = await db();
  const { data: call, error: insertError } = await client
    .from("agent_tool_calls")
    .insert({
      task_id: taskId,
      agent_id: agentId,
      tenant_id: auth.tenantId,
      tool: toolName,
      input: redactSensitiveData(input),
      status: "pending",
      trace_id: traceIdVal ?? null,
      created_at: nowIso(),
    })
    .select()
    .single();

  if (insertError || !call) {
    throw new Error("failed to record tool call lifecycle");
  }
  const callId = (call as { id: string }).id;

  try {
    const output = await handler();
    const { data: updateData, error: updateErr } = await client
      .from("agent_tool_calls")
      .update({
        status: "succeeded",
        output: redactSensitiveData(output),
        finished_at: nowIso(),
      })
      .eq("id", callId)
      .select()
      .single();

    if (updateErr || !updateData) {
      throw new Error("failed to persist tool execution success status");
    }

    emit(taskId, "tool.succeeded", { tool: toolName }, agentId, traceIdVal, auth.tenantId);
    return { ok: true, call_id: callId, output: redactSensitiveData(output) as Json };
  } catch (error) {
    const sanitizedMsg = sanitizeExternalErrorMessage(error, (error as Error).message);
    await client
      .from("agent_tool_calls")
      .update({
        status: "failed",
        error: sanitizedMsg,
        finished_at: nowIso(),
      })
      .eq("id", callId);

    emit(taskId, "tool.failed", { tool: toolName, message: sanitizedMsg }, agentId, traceIdVal, auth.tenantId);
    throw error;
  }
}

async function handle(segments: string[], request: Request, auth: AuthContext): Promise<Response> {
  const method = request.method.toUpperCase();
  const url = new URL(request.url);
  const [root, second, third, fourth] = segments;

  if (root === "health" && !second) {
    let dbOk = false;
    let cryptoOk = false;
    let primaryConfigOk = false;

    try {
      const client = await db();
      const { error } = await client.from("agent_tasks").select("id").limit(1);
      dbOk = !error;
    } catch {
      dbOk = false;
    }

    try {
      const testEnc = await encryptSecret("health_probe", "probe");
      const testDec = await decryptSecret(testEnc.ciphertext, testEnc.iv, testEnc.key_version, "probe");
      cryptoOk = testDec === "health_probe";
    } catch {
      cryptoOk = false;
    }

    try {
      const caps = await getCapabilities(auth);
      primaryConfigOk = caps.model_primary;
    } catch {
      primaryConfigOk = false;
    }

    const isHealthy = dbOk && cryptoOk;
    const status = isHealthy ? 200 : 503;
    const caps = await getCapabilities(auth);

    return json({
      ok: isHealthy,
      status: isHealthy ? "ready" : "degraded",
      probes: {
        database: dbOk ? "connected" : "unreachable",
        encryption: cryptoOk ? "operational" : "failed",
        primary_model_config: primaryConfigOk ? "configured" : "missing_credentials",
      },
      capabilities: caps,
      time: nowIso(),
    }, status);
  }

  const client = await db();
  let body: Json = {};

  if (method === "POST" || method === "PATCH" || method === "PUT") {
    const raw = await request.clone().text();
    if (raw && raw.trim().length > 0) {
      try {
        const parsed = JSON.parse(raw);
        if (!isPlainObject(parsed)) {
          return fail("request body must be a valid JSON object", 400);
        }
        body = parsed;
      } catch {
        return fail("malformed JSON in request body", 400);
      }
    }
  }

  if (root === "sessions") {
    if (method === "POST" && !second) {
      try {
        const sessId = typeof body["session_id"] === "string" ? body["session_id"] : undefined;
        const extKey = typeof body["external_key"] === "string" ? body["external_key"] : undefined;
        const lbl = typeof body["label"] === "string" ? body["label"] : undefined;
        const { session } = await ensureSession(sessId, extKey, auth, lbl);
        return json({ ok: true, session });
      } catch (err) {
        return fail((err as Error).message, 400);
      }
    }
    if (method === "GET" && second && !third) {
      try {
        const session = await assertSessionOwnership(second, auth);
        return json({ ok: true, session });
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("session not found", 404);
      }
    }
    return fail("unknown session endpoint", 404);
  }

  if (root === "tasks") {
    if (method === "POST" && !second) {
      const objective = requireNonEmptyString(body["objective"], "objective", 8192);

      let sessionRes: { session: Json; created: boolean };
      try {
        const sessId = typeof body["session_id"] === "string" ? body["session_id"] : undefined;
        const extKey = typeof body["external_key"] === "string" ? body["external_key"] : undefined;
        sessionRes = await ensureSession(sessId, extKey, auth);
      } catch (sessionErr) {
        return fail((sessionErr as Error).message, 400);
      }
      const session = sessionRes.session;

      const idempotencyKey =
        (typeof body["idempotency_key"] === "string" && body["idempotency_key"].trim().length > 0
          ? body["idempotency_key"].trim()
          : undefined) ??
        request.headers.get("idempotency-key")?.trim() ??
        null;

      if (idempotencyKey) {
        const { data: existing, error: existingError } = await client
          .from("agent_tasks")
          .select("*")
          .eq("session_id", session["id"])
          .eq("idempotency_key", idempotencyKey)
          .is("deleted_at", null)
          .maybeSingle();
        if (existingError) return fail(existingError.message, 500);
        if (existing) return json({ ok: true, task: existing, idempotent: true });
      }

      const priority = requireIntegerInRange(body["priority"], "priority", 1, 10, 5);

      let successCriteria: string[] = [];
      if (body["success_criteria"] !== undefined) {
        if (!Array.isArray(body["success_criteria"]) || !body["success_criteria"].every((item) => typeof item === "string" && item.trim().length > 0)) {
          return fail("success_criteria must be an array of non-empty strings", 400);
        }
        successCriteria = body["success_criteria"].map((s) => (s as string).trim());
      }

      const stateData = body["state_data"] !== undefined ? requirePlainObject(body["state_data"], "state_data") : {};
      const generatedTraceId = traceId();

      const { data, error } = await client
        .from("agent_tasks")
        .insert({
          session_id: session["id"],
          tenant_id: auth.tenantId,
          created_by: auth.userId,
          idempotency_key: idempotencyKey,
          objective,
          success_criteria: successCriteria,
          autonomous: body["autonomous"] !== false,
          priority,
          state: "pending",
          phase: "created",
          trace_id: generatedTraceId,
          state_data: stateData,
          created_at: nowIso(),
          updated_at: nowIso(),
        })
        .select()
        .single();

      if (error) {
        if (sessionRes.created) {
          await client.from("agent_sessions").delete().eq("id", session["id"]);
        }
        if (
          idempotencyKey &&
          (error.code === "23505" ||
            error.message.includes("duplicate key") ||
            error.message.includes("unique"))
        ) {
          const { data: existing, error: fetchDupError } = await client
            .from("agent_tasks")
            .select("*")
            .eq("session_id", session["id"])
            .eq("idempotency_key", idempotencyKey)
            .is("deleted_at", null)
            .maybeSingle();
          if (fetchDupError) return fail(fetchDupError.message, 500);
          if (existing) return json({ ok: true, task: existing, idempotent: true });
        }
        return fail(error.message, 500);
      }
      if (!data) {
        if (sessionRes.created) {
          await client.from("agent_sessions").delete().eq("id", session["id"]);
        }
        return fail("database returned no data row after task creation", 500);
      }

      const taskRow = data as { id: string };

      try {
        await spawnAgents(taskRow.id, objective, auth);
      } catch (agentError) {
        await client.from("agent_tasks").delete().eq("id", taskRow.id);
        if (sessionRes.created) {
          await client.from("agent_sessions").delete().eq("id", session["id"]);
        }
        return fail((agentError as Error).message, 500);
      }

      emit(taskRow.id, "task.created", { objective }, null, generatedTraceId, auth.tenantId);
      audit(auth.userId, "task.create", taskRow.id, { objective, tenant_id: auth.tenantId }, generatedTraceId, auth.tenantId);

      return json({ ok: true, task: data }, 201, generatedTraceId);
    }

    if (method === "GET" && !second) {
      const limit = requireIntegerInRange(url.searchParams.get("limit"), "limit", 1, 100, 50);
      let query = client
        .from("agent_tasks")
        .select("*")
        .is("deleted_at", null)
        .order("priority", { ascending: false })
        .order("created_at", { ascending: false })
        .limit(limit);

      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }

      const sessionId = url.searchParams.get("session_id");
      const state = url.searchParams.get("state");
      if (sessionId) query = query.eq("session_id", sessionId);
      if (state) {
        if (!TASK_STATES.includes(state as TaskState)) {
          return fail(`invalid state filter: ${state}`, 400);
        }
        query = query.eq("state", state);
      }
      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      return json({ ok: true, tasks: data ?? [] });
    }

    if (second && !third) {
      if (method === "GET") {
        try {
          const task = await assertTaskOwnership(second, auth);
          return json({ ok: true, task }, 200, typeof task["trace_id"] === "string" ? task["trace_id"] : undefined);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }
      }
      if (method === "PATCH" || method === "PUT") {
        let task: Json;
        try {
          task = await assertTaskOwnership(second, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }

        const patchUpdates: Json = {};
        if (body["priority"] !== undefined) {
          patchUpdates["priority"] = requireIntegerInRange(body["priority"], "priority", 1, 10);
        }
        if (body["success_criteria"] !== undefined) {
          if (!Array.isArray(body["success_criteria"]) || !body["success_criteria"].every((item) => typeof item === "string" && item.trim().length > 0)) {
            return fail("success_criteria must be an array of non-empty strings", 400);
          }
          patchUpdates["success_criteria"] = body["success_criteria"].map((s) => (s as string).trim());
        }
        if (body["state_data"] !== undefined) {
          patchUpdates["state_data"] = requirePlainObject(body["state_data"], "state_data");
        }
        if (body["objective"] !== undefined) {
          patchUpdates["objective"] = requireNonEmptyString(body["objective"], "objective", 8192);
        }
        if (Object.keys(patchUpdates).length === 0) {
          return fail("no valid update fields provided", 400);
        }
        patchUpdates["updated_at"] = nowIso();

        const { data, error } = await client
          .from("agent_tasks")
          .update(patchUpdates)
          .eq("id", second)
          .is("deleted_at", null)
          .select()
          .maybeSingle();

        if (error) return fail(error.message, 500);
        if (!data) return fail("task not found or conflict", 409);
        return json({ ok: true, task: data }, 200, typeof task["trace_id"] === "string" ? task["trace_id"] : undefined);
      }
      if (method === "DELETE") {
        let task: Json;
        try {
          task = await assertTaskOwnership(second, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }

        const currentVersion = Number.isInteger(Number(task["version"])) ? Number(task["version"]) : 1;
        let deleteQuery = client
          .from("agent_tasks")
          .update({
            deleted_at: nowIso(),
            state: "cancelled",
            version: currentVersion + 1,
            lease_owner: null,
            lease_expires_at: null,
            heartbeat_at: null,
            updated_at: nowIso(),
          })
          .eq("id", second)
          .is("deleted_at", null);

        if (task["version"] === null || task["version"] === undefined) {
          deleteQuery = deleteQuery.is("version", null);
        } else {
          deleteQuery = deleteQuery.eq("version", task["version"]);
        }

        const { data, error } = await deleteQuery.select().maybeSingle();
        if (error) return fail(error.message, 500);
        if (!data) return fail("task deletion conflict", 409);

        await client
          .from("agent_agents")
          .update({ state: "cancelled", updated_at: nowIso() })
          .eq("task_id", second)
          .in("state", ["pending", "running"]);

        await client
          .from("agent_browser_sessions")
          .update({ status: "closed", updated_at: nowIso() })
          .eq("task_id", second)
          .eq("status", "open");

        await client
          .from("agent_sandboxes")
          .update({ status: "terminated", updated_at: nowIso() })
          .eq("task_id", second)
          .eq("status", "ready");

        const tid = typeof task["trace_id"] === "string" ? task["trace_id"] : undefined;
        emit(second, "task.deleted", {}, null, tid, auth.tenantId);
        audit(auth.userId, "task.delete", second, { tenant_id: auth.tenantId }, tid, auth.tenantId);
        return json({ ok: true }, 200, tid);
      }
      return fail("unknown method on task", 405);
    }

    if (second && third && !fourth) {
      if (third === "events" && (method === "GET" || method === "POST")) {
        let task: Json;
        try {
          task = await assertTaskOwnership(second, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }

        const limit = requireIntegerInRange(url.searchParams.get("limit") ?? (isPlainObject(body) && body["limit"] ? body["limit"] : 100), "limit", 1, 500, 100);
        const validAfter = requireIntegerInRange(url.searchParams.get("after") ?? (isPlainObject(body) && body["after"] ? body["after"] : 0), "after", 0, Number.MAX_SAFE_INTEGER, 0);

        const { data, error } = await client
          .from("agent_events")
          .select("*")
          .eq("task_id", second)
          .gt("id", validAfter)
          .order("id", { ascending: true })
          .limit(limit);

        if (error) return fail(error.message, 500);
        const events = data ?? [];
        const nextCursor = events.length > 0 ? (events[events.length - 1] as { id: number }).id : null;
        return json({
          ok: true,
          events,
          has_more: events.length === limit,
          next_cursor: nextCursor,
        }, 200, typeof task["trace_id"] === "string" ? task["trace_id"] : undefined);
      }

      if (third === "stream" && method === "GET") {
        let task: Json;
        try {
          task = await assertTaskOwnership(second, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }

        const rawAfter = Number(url.searchParams.get("after") ?? 0);
        let lastId = Number.isInteger(rawAfter) && rawAfter >= 0 ? rawAfter : 0;

        let isClosed = false;
        const stream = new ReadableStream<Uint8Array>({
          async start(controller) {
            const abortHandler = () => {
              isClosed = true;
              try {
                controller.close();
              } catch {
              }
            };
            request.signal.addEventListener("abort", abortHandler);

            try {
              controller.enqueue(encoder.encode(": open\n\n"));
              const deadline = Date.now() + 300_000;
              let idleInterval = 2000;

              while (Date.now() < deadline && !isClosed && !request.signal.aborted) {
                const { data, error } = await client
                  .from("agent_events")
                  .select("*")
                  .eq("task_id", second)
                  .gt("id", lastId)
                  .order("id", { ascending: true })
                  .limit(100);

                if (error) {
                  controller.enqueue(
                    encoder.encode(`event: error\ndata: ${JSON.stringify({ error: "Event stream internal error" })}\n\n`),
                  );
                  break;
                }

                const events = data ?? [];
                if (events.length > 0) {
                  idleInterval = 1000;
                  for (const event of events as Array<{ id: number; kind: string }>) {
                    lastId = Number(event.id);
                    controller.enqueue(
                      encoder.encode(`id: ${event.id}\nevent: ${event.kind}\ndata: ${JSON.stringify(event)}\n\n`),
                    );
                  }
                } else {
                  idleInterval = Math.min(idleInterval + 500, 5000);
                }

                const currentTask = await getTask(second);
                if (!currentTask || ["completed", "failed", "cancelled"].includes(String(currentTask["state"]))) {
                  controller.enqueue(
                    encoder.encode(`event: end\ndata: ${JSON.stringify({ state: currentTask ? currentTask["state"] : "deleted" })}\n\n`),
                  );
                  break;
                }

                controller.enqueue(encoder.encode(": ping\n\n"));
                await new Promise((r) => setTimeout(r, idleInterval));
              }
            } catch {
              try {
                controller.enqueue(
                  encoder.encode(`event: error\ndata: ${JSON.stringify({ error: "Stream terminated" })}\n\n`),
                );
              } catch {
              }
            } finally {
              request.signal.removeEventListener("abort", abortHandler);
              if (!isClosed) {
                try {
                  controller.close();
                } catch {
                }
              }
            }
          },
          cancel() {
            isClosed = true;
          },
        });

        const headers: Record<string, string> = {
          "content-type": "text/event-stream; charset=utf-8",
          "cache-control": "no-cache, no-transform",
          "x-accel-buffering": "no",
        };
        if (task["trace_id"]) headers["x-trace-id"] = String(task["trace_id"]);

        return new Response(stream, { headers });
      }

      if (method === "POST") {
        let task: Json;
        try {
          task = await assertTaskOwnership(second, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }

        const taskTraceId = typeof task["trace_id"] === "string" ? task["trace_id"] : undefined;

        try {
          if (third === "pause") {
            if (String(task["state"]) !== "running") {
              return fail("only running tasks can be paused", 409, {}, taskTraceId);
            }
            if (task["lease_owner"] && task["lease_owner"] !== auth.userId && !auth.isWorker && auth.role !== "admin") {
              return fail("forbidden: only the lease owner may pause a running task", 403, {}, taskTraceId);
            }

            const currentPhase = String(task["phase"] ?? "executing");
            const stateData = isPlainObject(task["state_data"]) ? { ...task["state_data"] } : {};
            stateData["pre_pause_phase"] = currentPhase;

            const updated = await transition(task, "paused", {
              phase: "blocked",
              state_data: stateData,
              lease_owner: null,
              lease_expires_at: null,
              heartbeat_at: null,
            });
            audit(auth.userId, "task.pause", second, { reason: typeof body["reason"] === "string" ? body["reason"].slice(0, 256) : null }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated }, 200, taskTraceId);
          }

          if (third === "resume") {
            if (!["paused", "waiting_human"].includes(String(task["state"]))) {
              return fail("task is not in a resumable state", 409, {}, taskTraceId);
            }

            if (task["scheduled_at"]) {
              const schedTime = new Date(String(task["scheduled_at"])).getTime();
              if (schedTime > Date.now()) {
                return fail(`task is scheduled for future execution at ${task["scheduled_at"]}`, 409, {}, taskTraceId);
              }
            }

            const leaseDuration = requireIntegerInRange(body["lease_seconds"] ?? body["ttl_seconds"], "lease_seconds", 1, 3600, 60);
            const stateData = isPlainObject(task["state_data"]) ? task["state_data"] : {};
            const restoredPhase = typeof stateData["pre_pause_phase"] === "string" && (PHASES as readonly string[]).includes(stateData["pre_pause_phase"]) ? stateData["pre_pause_phase"] : "executing";

            const updated = await transition(task, "running", {
              phase: restoredPhase,
              scheduled_at: nowIso(),
              lease_owner: auth.userId,
              lease_expires_at: new Date(Date.now() + leaseDuration * 1000).toISOString(),
              heartbeat_at: nowIso(),
            });
            audit(auth.userId, "task.resume", second, { lease_owner: auth.userId, restored_phase: restoredPhase }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated }, 200, taskTraceId);
          }

          if (third === "start") {
            const currentState = String(task["state"]);
            if (!["pending", "failed"].includes(currentState)) {
              return fail(`cannot start task from state '${currentState}'`, 409, {}, taskTraceId);
            }

            if (task["scheduled_at"]) {
              const schedTime = new Date(String(task["scheduled_at"])).getTime();
              if (schedTime > Date.now()) {
                return fail(`task is scheduled for future execution at ${task["scheduled_at"]}`, 409, {}, taskTraceId);
              }
            }

            const currentOwner = task["lease_owner"];
            const leaseExpires = task["lease_expires_at"] ? new Date(String(task["lease_expires_at"])).getTime() : 0;
            if (currentOwner && currentOwner !== auth.userId && leaseExpires > Date.now()) {
              return fail("task execution lease is actively held by another worker", 409, {}, taskTraceId);
            }

            const leaseDuration = requireIntegerInRange(body["lease_seconds"] ?? body["ttl_seconds"], "lease_seconds", 1, 3600, 60);
            const newExpiresAt = new Date(Date.now() + leaseDuration * 1000).toISOString();
            const currentVersion = Number(task["version"] ?? 1);

            let retryHistory = Array.isArray(task["retry_history"]) ? task["retry_history"] : [];
            if (currentState === "failed" && task["error"]) {
              retryHistory = [
                ...retryHistory,
                {
                  failed_at: nowIso(),
                  error: task["error"],
                  attempt_version: currentVersion,
                  claimed_by: auth.userId,
                },
              ];
            }

            let claimQuery = client
              .from("agent_tasks")
              .update({
                state: "running",
                phase: "planning",
                lease_owner: auth.userId,
                lease_expires_at: newExpiresAt,
                heartbeat_at: nowIso(),
                final_response: null,
                final_writer_alias: null,
                error: null,
                human_input: null,
                human_request: null,
                human_challenge_hash: null,
                human_challenge_expires_at: null,
                continuation_token: null,
                retry_history: retryHistory,
                version: currentVersion + 1,
                updated_at: nowIso(),
              })
              .eq("id", second)
              .eq("version", task["version"])
              .is("deleted_at", null);

            if (currentState === "pending") {
              claimQuery = claimQuery.eq("state", "pending");
            } else {
              claimQuery = claimQuery.eq("state", "failed");
            }

            const { data: claimed, error: claimErr } = await claimQuery.select().maybeSingle();
            if (claimErr) return fail(claimErr.message, 500, {}, taskTraceId);
            if (!claimed) return fail("task claim conflict: already claimed or updated by another worker", 409, {}, taskTraceId);

            emit(second, "task.state", { from: currentState, to: "running", worker: auth.userId }, null, taskTraceId, auth.tenantId);
            audit(auth.userId, "task.start", second, { from: currentState, lease_owner: auth.userId }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: claimed }, 200, taskTraceId);
          }

          if (third === "heartbeat") {
            if (String(task["state"]) !== "running") return fail("task is not in running state", 409, {}, taskTraceId);
            if (task["lease_owner"] !== auth.userId && auth.role !== "admin") {
              return fail("forbidden: lease is owned by another worker", 403, {}, taskTraceId);
            }
            const leaseExpires = task["lease_expires_at"] ? new Date(String(task["lease_expires_at"])).getTime() : 0;
            if (leaseExpires <= Date.now()) {
              return fail("task lease has expired and cannot be renewed; must be reclaimed", 409, {}, taskTraceId);
            }

            const leaseDuration = requireIntegerInRange(body["lease_seconds"] ?? body["ttl_seconds"], "lease_seconds", 1, 3600, 60);
            const currentVersion = Number.isInteger(Number(task["version"])) ? Number(task["version"]) : 1;

            const { data, error } = await client
              .from("agent_tasks")
              .update({
                heartbeat_at: nowIso(),
                lease_expires_at: new Date(Date.now() + leaseDuration * 1000).toISOString(),
                version: currentVersion + 1,
                updated_at: nowIso(),
              })
              .eq("id", second)
              .eq("state", "running")
              .eq("version", task["version"])
              .eq("lease_owner", task["lease_owner"])
              .gt("lease_expires_at", nowIso())
              .is("deleted_at", null)
              .select()
              .maybeSingle();

            if (error) return fail(error.message, 500, {}, taskTraceId);
            if (!data) return fail("heartbeat CAS failed: task expired, changed owner, or version mismatch", 409, {}, taskTraceId);
            return json({ ok: true, task: data }, 200, taskTraceId);
          }

          if (third === "complete") {
            if (String(task["state"]) !== "running") return fail("task is not in running state", 409, {}, taskTraceId);
            if (task["lease_owner"] && task["lease_owner"] !== auth.userId && auth.role !== "admin") {
              return fail("forbidden: only the lease owner can complete the task", 403, {}, taskTraceId);
            }

            const finalResponse = requireNonEmptyString(body["final_response"], "final_response", 1048576);
            const rawAlias = requireNonEmptyString(body["final_writer_alias"] ?? ALIAS_PRIMARY, "final_writer_alias", 64);
            if (!VALID_ALIASES.includes(rawAlias as any)) {
              return fail(`invalid final_writer_alias: ${rawAlias}. Must be one of: ${VALID_ALIASES.join(", ")}`, 400, {}, taskTraceId);
            }

            const updated = await transition(task, "completed", {
              phase: "finished",
              final_response: finalResponse,
              final_writer_alias: rawAlias,
              lease_owner: null,
              lease_expires_at: null,
              heartbeat_at: null,
            });

            await client
              .from("agent_agents")
              .update({ state: "completed", updated_at: nowIso() })
              .eq("task_id", second)
              .in("state", ["pending", "running"]);

            emit(second, "task.completed", {}, null, taskTraceId, auth.tenantId);
            audit(auth.userId, "task.complete", second, { alias: rawAlias }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated }, 200, taskTraceId);
          }

          if (third === "error") {
            if (!["running", "pending", "paused", "waiting_human"].includes(String(task["state"]))) {
              return fail("task is not in an active state to mark failed", 409, {}, taskTraceId);
            }
            if (String(task["state"]) === "running" && task["lease_owner"] && task["lease_owner"] !== auth.userId && auth.role !== "admin") {
              return fail("forbidden: only the current worker can fail an active running task", 403, {}, taskTraceId);
            }

            const errorMessage = requireNonEmptyString(body["message"], "message", 4096);
            const errorCode = typeof body["code"] === "string" && body["code"].trim().length > 0 ? body["code"].trim().slice(0, 64) : "EXECUTION_ERROR";

            const updated = await transition(task, "failed", {
              phase: "blocked",
              error: {
                message: errorMessage,
                code: errorCode,
                failed_by: auth.userId,
                at: nowIso(),
              },
              lease_owner: null,
              lease_expires_at: null,
              heartbeat_at: null,
            });

            await client
              .from("agent_agents")
              .update({
                state: "failed",
                error: { message: errorMessage },
                updated_at: nowIso(),
              })
              .eq("task_id", second)
              .in("state", ["pending", "running"]);

            emit(second, "task.failed", { message: errorMessage }, null, taskTraceId, auth.tenantId);
            audit(auth.userId, "task.error", second, { code: errorCode }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated }, 200, taskTraceId);
          }

          if (third === "await-human") {
            if (String(task["state"]) !== "running") return fail("only running tasks can await human input", 409, {}, taskTraceId);
            if (task["lease_owner"] && task["lease_owner"] !== auth.userId && auth.role !== "admin") {
              return fail("forbidden: only the lease owner can transition task to waiting_human", 403, {}, taskTraceId);
            }

            const question = requireNonEmptyString(body["question"] ?? "Human input required", "question", 4096);
            const rawFields = Array.isArray(body["fields"]) ? body["fields"] : [];
            const fieldsJson = JSON.stringify(rawFields);
            if (fieldsJson.length > 60000) {
              return fail("fields array exceeds maximum payload size", 400, {}, taskTraceId);
            }

            const challengeSecret = crypto.randomUUID();
            const challengeSecretHash = await sha256Hex(challengeSecret);
            const challengeExpiresAt = new Date(Date.now() + 1800_000).toISOString();

            const stateData = isPlainObject(task["state_data"]) ? { ...task["state_data"] } : {};
            if (task["human_request"]) {
              const reqHistory = Array.isArray(stateData["human_request_history"]) ? stateData["human_request_history"] : [];
              stateData["human_request_history"] = [...reqHistory, task["human_request"]];
            }

            const updated = await transition(task, "waiting_human", {
              phase: "blocked",
              state_data: stateData,
              continuation_token: null,
              human_challenge_hash: challengeSecretHash,
              human_challenge_expires_at: challengeExpiresAt,
              human_expected_user_id: typeof body["expected_user_id"] === "string" ? body["expected_user_id"].slice(0, 128) : null,
              lease_owner: null,
              lease_expires_at: null,
              heartbeat_at: null,
              human_request: {
                question,
                fields: rawFields,
                asked_at: nowIso(),
                expires_at: challengeExpiresAt,
              },
            });

            emit(second, "task.waiting_human", { question }, null, taskTraceId, auth.tenantId);
            audit(auth.userId, "task.await_human", second, { asked_at: nowIso() }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated, continuation_token: challengeSecret, expires_at: challengeExpiresAt }, 200, taskTraceId);
          }

          if (third === "human-input") {
            if (String(task["state"]) !== "waiting_human") return fail("task is not waiting for human input", 409, {}, taskTraceId);

            const expectedUserId = task["human_expected_user_id"];
            if (expectedUserId && expectedUserId !== auth.userId && auth.role !== "admin") {
              return fail("forbidden: only the designated human respondent can fulfill this input challenge", 403, {}, taskTraceId);
            }

            const expiresAtStr = typeof task["human_challenge_expires_at"] === "string" ? task["human_challenge_expires_at"] : null;
            if (expiresAtStr && new Date(expiresAtStr).getTime() < Date.now()) {
              return fail("human input continuation token has expired", 403, {}, taskTraceId);
            }

            const storedHash = typeof task["human_challenge_hash"] === "string" ? task["human_challenge_hash"] : "";
            const providedToken = requireNonEmptyString(body["continuation_token"], "continuation_token", 512);

            const providedHash = await sha256Hex(providedToken);
            const storedBuf = Buffer.from(storedHash);
            const providedBuf = Buffer.from(providedHash);
            if (storedBuf.length !== providedBuf.length || !timingSafeEqual(storedBuf, providedBuf)) {
              return fail("invalid continuation token", 403, {}, taskTraceId);
            }

            const inputValue = body["input"];
            if (inputValue === undefined) {
              return fail("input value is required", 400, {}, taskTraceId);
            }
            const serializedInput = JSON.stringify(inputValue);
            if (serializedInput.length > 65536) {
              return fail("human input payload exceeds maximum allowed size of 64KB", 400, {}, taskTraceId);
            }

            const currentVersion = Number(task["version"] ?? 1);
            const stateData = isPlainObject(task["state_data"]) ? task["state_data"] : {};
            const restoredPhase = typeof stateData["pre_pause_phase"] === "string" && (PHASES as readonly string[]).includes(stateData["pre_pause_phase"]) ? stateData["pre_pause_phase"] : "executing";

            const { data: updated, error: inputErr } = await client
              .from("agent_tasks")
              .update({
                state: "running",
                phase: restoredPhase,
                human_input: {
                  value: inputValue,
                  received_at: nowIso(),
                  submitted_by: auth.userId,
                },
                human_challenge_hash: null,
                human_challenge_expires_at: null,
                human_expected_user_id: null,
                continuation_token: null,
                lease_owner: auth.userId,
                lease_expires_at: new Date(Date.now() + 60_000).toISOString(),
                heartbeat_at: nowIso(),
                version: currentVersion + 1,
                updated_at: nowIso(),
              })
              .eq("id", second)
              .eq("version", task["version"])
              .eq("state", "waiting_human")
              .is("deleted_at", null)
              .select()
              .maybeSingle();

            if (inputErr) return fail(inputErr.message, 500, {}, taskTraceId);
            if (!updated) return fail("human input CAS conflict: task state changed or challenge already consumed", 409, {}, taskTraceId);

            emit(second, "task.human_input", {}, null, taskTraceId, auth.tenantId);
            audit(auth.userId, "task.human_input", second, { tenant_id: auth.tenantId }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated }, 200, taskTraceId);
          }

          if (third === "phase") {
            const phase = requireNonEmptyString(body["phase"], "phase", 64);
            if (!(PHASES as readonly string[]).includes(phase)) return fail("unknown phase", 400, {}, taskTraceId);
            const currentState = String(task["state"]);

            if (["completed", "failed", "cancelled"].includes(currentState)) {
              return fail("cannot update phase of terminal task", 409, {}, taskTraceId);
            }
            if (phase === "finished" && currentState !== "running") {
              return fail("phase cannot be set to 'finished' on a non-running task", 409, {}, taskTraceId);
            }
            if (["planning", "researching", "executing", "reviewing", "writing"].includes(phase) && ["paused", "waiting_human"].includes(currentState)) {
              return fail(`cannot set active phase '${phase}' while task is ${currentState}`, 409, {}, taskTraceId);
            }
            if (currentState === "running" && task["lease_owner"] && task["lease_owner"] !== auth.userId && auth.role !== "admin") {
              return fail("forbidden: only the lease owner can update task phase", 403, {}, taskTraceId);
            }

            const currentVersion = Number.isInteger(Number(task["version"])) ? Number(task["version"]) : 1;
            const { data, error } = await client
              .from("agent_tasks")
              .update({
                phase,
                version: currentVersion + 1,
                updated_at: nowIso(),
              })
              .eq("id", second)
              .eq("version", task["version"])
              .is("deleted_at", null)
              .select()
              .maybeSingle();

            if (error) return fail(error.message, 500, {}, taskTraceId);
            if (!data) return fail("phase update CAS conflict", 409, {}, taskTraceId);
            emit(second, "task.phase", { phase }, null, taskTraceId, auth.tenantId);
            return json({ ok: true, task: data }, 200, taskTraceId);
          }

          if (third === "run") {
            if (task["autonomous"] === false) {
              const currentPhase = String(task["phase"]);
              if (currentPhase === "planning" || currentPhase === "created") {
                const question = "Task is configured non-autonomous. Please review plan and authorize execution.";
                const challengeSecret = crypto.randomUUID();
                const challengeSecretHash = await sha256Hex(challengeSecret);
                const challengeExpiresAt = new Date(Date.now() + 1800_000).toISOString();

                const updated = await transition(task, "waiting_human", {
                  phase: "blocked",
                  human_challenge_hash: challengeSecretHash,
                  human_challenge_expires_at: challengeExpiresAt,
                  lease_owner: null,
                  lease_expires_at: null,
                  heartbeat_at: null,
                  human_request: {
                    question,
                    fields: ["authorization"],
                    asked_at: nowIso(),
                    expires_at: challengeExpiresAt,
                  },
                });
                return json({
                  ok: true,
                  task: updated,
                  non_autonomous_blocked: true,
                  continuation_token: challengeSecret,
                  expires_at: challengeExpiresAt,
                }, 200, taskTraceId);
              }
            }

            if (task["scheduled_at"]) {
              const schedTime = new Date(String(task["scheduled_at"])).getTime();
              if (schedTime > Date.now()) {
                return fail(`task is scheduled for future execution at ${task["scheduled_at"]}`, 409, {}, taskTraceId);
              }
            }

            const currentOwner = auth.userId;
            const runningTask = await transition(task, "running", {
              phase: "executing",
              lease_owner: currentOwner,
              lease_expires_at: new Date(Date.now() + 300_000).toISOString(),
              heartbeat_at: nowIso(),
            });

            const { data: childAgents } = await client
              .from("agent_agents")
              .select("*")
              .eq("task_id", second)
              .neq("role", "orchestrator")
              .order("depth", { ascending: true });

            let researcherResult = "";
            let engineerResult = "";
            let writerResult = "";
            let finalAlias = ALIAS_PRIMARY;

            for (const child of (childAgents ?? []) as Array<Json>) {
              const childId = String(child["id"]);
              const childRole = String(child["role"]);

              await client
                .from("agent_agents")
                .update({ state: "running", updated_at: nowIso() })
                .eq("id", childId);

              const childContext = await buildTaskExecutionContext(second, auth);
              const childMessages: ChatMessage[] = [
                {
                  role: "system",
                  content: `Role: ${childRole}. Task Context:\n${childContext.contextPrompt}\nExecute this role comprehensively.`,
                },
                { role: "user", content: String(child["instruction"]) },
              ];

              const childIntent = childRole === "engineer" ? "code" : childRole === "researcher" ? "research" : "creative";
              const childRes = await routeCompletion(childMessages, childIntent, 4096, auth, taskTraceId);

              await client
                .from("agent_agents")
                .update({
                  state: "completed",
                  result: { alias: childRes.alias, content: childRes.content },
                  updated_at: nowIso(),
                })
                .eq("id", childId);

              if (childRole === "researcher") researcherResult = childRes.content;
              if (childRole === "engineer") engineerResult = childRes.content;
              if (childRole === "writer") {
                writerResult = childRes.content;
                finalAlias = childRes.alias as any;
              }
            }

            const taskContext = await buildTaskExecutionContext(second, auth);
            const orchestratorMessages: ChatMessage[] = [
              {
                role: "system",
                content:
                  "You are the root autonomous execution agent. Review all task context, success criteria, and child agent outputs to produce the final comprehensive response that satisfies every success criterion.",
              },
              {
                role: "user",
                content: `${taskContext.contextPrompt}\n\nResearcher Output:\n${researcherResult}\n\nEngineer Output:\n${engineerResult}\n\nWriter Draft:\n${writerResult}\n\nSynthesize the final authoritative answer meeting all success criteria.`,
              },
            ];

            const finalExec = await routeCompletion(orchestratorMessages, String(body["intent"] ?? "general"), 4096, auth, taskTraceId);
            const finalAnswer = finalExec.content || writerResult || engineerResult || researcherResult;
            finalAlias = (finalExec.alias || finalAlias) as any;

            await client
              .from("agent_agents")
              .update({
                state: "completed",
                result: { alias: finalAlias, content: finalAnswer },
                updated_at: nowIso(),
              })
              .eq("task_id", second)
              .eq("role", "writer");

            const updated = await transition(runningTask, "completed", {
              phase: "finished",
              final_response: finalAnswer,
              final_writer_alias: finalAlias,
              lease_owner: null,
              lease_expires_at: null,
              heartbeat_at: null,
            });

            await client
              .from("agent_agents")
              .update({ state: "completed", updated_at: nowIso() })
              .eq("task_id", second)
              .in("state", ["pending", "running"]);

            emit(second, "task.answer", { alias: finalAlias }, null, taskTraceId, auth.tenantId);
            emit(second, "task.completed", {}, null, taskTraceId, auth.tenantId);
            audit(auth.userId, "task.run", second, { alias: finalAlias }, taskTraceId, auth.tenantId);
            return json({ ok: true, task: updated, alias: finalAlias }, 200, taskTraceId);
          }
          return fail(`unknown task action: ${third}`, 404, {}, taskTraceId);
        } catch (error) {
          return fail((error as Error).message, 409, {}, taskTraceId);
        }
      }
      return fail(`unknown task sub-action: ${third}`, 404);
    }
    return fail("unknown task route pattern", 404);
  }

  if (root === "agents") {
    if (method === "GET" && !second) {
      const taskId = url.searchParams.get("task_id");
      if (taskId) {
        try {
          await assertTaskOwnership(taskId, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }
      }

      let query = client.from("agent_agents").select("*").order("depth", { ascending: true });
      if (taskId) query = query.eq("task_id", taskId);
      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }

      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      return json({ ok: true, agents: data ?? [] });
    }

    if (method === "POST" && !second) {
      const taskId = requireNonEmptyString(body["task_id"], "task_id", 128);

      try {
        await assertTaskOwnership(taskId, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("task not found", 404);
      }

      const parentId = typeof body["parent_id"] === "string" && body["parent_id"].trim().length > 0
        ? body["parent_id"].trim()
        : null;
      let depth = 0;
      if (parentId) {
        const { data: parent, error: parentError } = await client
          .from("agent_agents")
          .select("id, depth, task_id, tenant_id")
          .eq("id", parentId)
          .maybeSingle();
        if (parentError) return fail(parentError.message, 500);
        if (!parent) return fail("parent agent not found", 404);
        const parentRow = parent as { depth: number; task_id: string; tenant_id?: string };
        if (auth.tenantId !== "system" && auth.role !== "admin" && parentRow.tenant_id && parentRow.tenant_id !== auth.tenantId) {
          return fail("forbidden: parent agent belongs to another tenant", 403);
        }
        if (parentRow.task_id !== taskId) return fail("parent agent belongs to a different task", 400);
        depth = Number(parentRow.depth ?? 0) + 1;
      }
      if (depth > 4) return fail("maximum sub-agent depth exceeded", 409);

      const role = requireNonEmptyString(body["role"] ?? "worker", "role", 64);
      const alias = requireNonEmptyString(body["alias"] ?? ALIAS_PRIMARY, "alias", 64);
      const instruction = typeof body["instruction"] === "string" ? body["instruction"].slice(0, 8192) : "";

      const { data, error } = await client
        .from("agent_agents")
        .insert({
          task_id: taskId,
          tenant_id: auth.tenantId,
          parent_id: parentId,
          role,
          alias,
          instruction,
          depth,
          workspace_path: `/workspaces/${taskId}/${role}-${depth}`,
          created_at: nowIso(),
          updated_at: nowIso(),
        })
        .select()
        .single();

      if (error || !data) return fail(error?.message ?? "failed to create agent", 500);
      const agentRow = data as { id: string; role: string };
      emit(taskId, "agent.created", { role: agentRow.role }, agentRow.id, undefined, auth.tenantId);
      return json({ ok: true, agent: data }, 201);
    }

    if (second && third === "run" && method === "POST" && !fourth) {
      let agentRecord: Json;
      try {
        agentRecord = await assertAgentOwnership(second, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("agent not found", 404);
      }

      if (agentRecord["state"] === "running") {
        return fail("agent is already running", 409);
      }

      const { data: claimed, error: claimError } = await client
        .from("agent_agents")
        .update({ state: "running", updated_at: nowIso() })
        .eq("id", second)
        .eq("state", agentRecord["state"])
        .select()
        .maybeSingle();
      if (claimError) return fail(claimError.message, 500);
      if (!claimed) return fail("agent execution race detected", 409);

      const taskId = String(agentRecord["task_id"]);
      const taskContext = await buildTaskExecutionContext(taskId, auth);

      const messages: ChatMessage[] = [
        {
          role: "system",
          content: `Role: ${agentRecord["role"]}. Workspace: ${agentRecord["workspace_path"]}\nTask Context:\n${taskContext.contextPrompt}\nComplete instruction fully.`,
        },
        { role: "user", content: typeof body["input"] === "string" ? body["input"] : String(agentRecord["instruction"]) },
      ];
      const intent = agentRecord["role"] === "engineer" ? "code" : "general";

      let result;
      try {
        result = await routeCompletion(messages, intent, 4096, auth);
      } catch (error) {
        await client
          .from("agent_agents")
          .update({
            state: "failed",
            error: { message: sanitizeExternalErrorMessage(error) },
            updated_at: nowIso(),
          })
          .eq("id", second);
        return fail(sanitizeExternalErrorMessage(error), 502);
      }

      const content = result.content ? result.content.trim() : "";
      const isEscalated = content === "[ESCALATE]";
      const isEmpty = content.length === 0;
      const isFailed = isEscalated || isEmpty;
      const nextState = isFailed ? "failed" : "completed";

      const { data: updated, error: updateError } = await client
        .from("agent_agents")
        .update({
          state: nextState,
          result: { alias: result.alias, content: result.content },
          error: isFailed
            ? { message: isEscalated ? "agent escalated execution" : "empty model response" }
            : null,
          updated_at: nowIso(),
        })
        .eq("id", second)
        .select()
        .maybeSingle();

      if (updateError || !updated) {
        return fail(updateError?.message ?? "failed to update agent record", 500);
      }

      if (isFailed) {
        emit(
          taskId,
          "agent.failed",
          { alias: result.alias, reason: isEscalated ? "escalated" : "empty_response" },
          second,
          undefined,
          auth.tenantId,
        );
        return fail(
          isEscalated ? "agent execution escalated" : "empty response from model",
          502,
          { agent: updated, alias: result.alias },
        );
      }

      emit(taskId, "agent.completed", { alias: result.alias }, second, undefined, auth.tenantId);
      return json({ ok: true, agent: updated, alias: result.alias });
    }
    return fail("unknown agent route", 404);
  }

  if (root === "models" && second === "complete" && method === "POST" && !third) {
    const rawMessages = body["messages"];
    if (!Array.isArray(rawMessages) || rawMessages.length === 0 || !rawMessages.every(isValidChatMessage)) {
      return fail("messages must be a non-empty array of valid chat message objects", 400);
    }
    const maxTokens = requireIntegerInRange(body["max_tokens"], "max_tokens", 1, 32768, 2048);
    const intent = normalizeIntent(typeof body["intent"] === "string" ? body["intent"] : undefined);

    const execRes = await recordDirectToolExecution(
      "model.complete",
      { intent, max_tokens: maxTokens, message_count: rawMessages.length },
      async () => {
        const result = await routeCompletion(rawMessages, intent, maxTokens, auth);
        return { alias: result.alias, content: result.content };
      },
      auth,
    );

    return json({ ok: true, alias: (execRes.output as Json)?.alias, content: (execRes.output as Json)?.content, call_id: execRes.call_id });
  }

  if (root === "tools") {
    if (method === "GET" && !second) {
      const caps = await getCapabilities(auth);
      return json({
        ok: true,
        tools: [
          { name: "shell.exec", capability: "sandbox" },
          { name: "sandbox.provision", capability: "sandbox" },
          { name: "sandbox.terminate", capability: "sandbox" },
          { name: "browser.session", capability: "browser" },
          { name: "browser.navigate", capability: "browser" },
          { name: "browser.close", capability: "browser" },
          { name: "research.search", capability: "research" },
          { name: "mcp.invoke", capability: "mcp" },
          { name: "artifact.write", capability: "artifacts" },
          { name: "model.complete", capability: "model_primary" },
        ],
        capabilities: caps,
      });
    }

    if (method === "POST" && second === "invoke" && !third) {
      const tool = requireNonEmptyString(body["tool"], "tool", 64);
      if (!SUPPORTED_TOOLS.includes(tool as any)) {
        return fail(`unsupported tool: ${tool}`, 400);
      }

      const caps = await getCapabilities(auth);
      if (tool.startsWith("shell.") || tool.startsWith("sandbox.")) {
        if (!caps.sandbox) return fail("sandbox capability is unavailable", 503, { code: "CAPABILITY_UNAVAILABLE" });
      }
      if (tool.startsWith("browser.")) {
        if (!caps.browser) return fail("browser capability is unavailable", 503, { code: "CAPABILITY_UNAVAILABLE" });
      }
      if (tool.startsWith("research.")) {
        if (!caps.research) return fail("research capability is unavailable", 503, { code: "CAPABILITY_UNAVAILABLE" });
      }
      if (tool.startsWith("model.")) {
        if (!caps.model_primary) return fail("model capability is unavailable", 503, { code: "CAPABILITY_UNAVAILABLE" });
      }

      const taskId = typeof body["task_id"] === "string" && body["task_id"].trim().length > 0
        ? body["task_id"].trim()
        : null;
      const agentId = typeof body["agent_id"] === "string" && body["agent_id"].trim().length > 0
        ? body["agent_id"].trim()
        : null;

      if (taskId) {
        try {
          await assertTaskOwnership(taskId, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("referenced task_id not found", 404);
        }
      }

      if (agentId) {
        try {
          const aObj = await assertAgentOwnership(agentId, auth);
          if (taskId && aObj["task_id"] !== taskId) {
            return fail("referenced agent_id does not belong to the specified task_id", 400);
          }
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("referenced agent_id not found", 404);
        }
      }

      const input = body["input"] !== undefined ? requirePlainObject(body["input"], "input") : {};

      const execRes = await recordDirectToolExecution(
        tool,
        input,
        async () => {
          if (tool === "shell.exec") {
            const command = requireNonEmptyString(input["command"], "command", 32768);
            let resolvedRemoteId: string | null = null;
            if (typeof input["sandbox_id"] === "string" && input["sandbox_id"].trim().length > 0) {
              const sb = await assertSandboxOwnership(input["sandbox_id"].trim(), auth);
              if (sb["status"] !== "ready" || !sb["remote_id"]) {
                throw new Error("specified sandbox is not ready");
              }
              resolvedRemoteId = String(sb["remote_id"]);
            } else if (taskId) {
              const { data: sb } = await client
                .from("agent_sandboxes")
                .select("remote_id, status")
                .eq("task_id", taskId)
                .eq("status", "ready")
                .order("created_at", { ascending: false })
                .limit(1)
                .maybeSingle();
              if (sb && sb["remote_id"]) resolvedRemoteId = String(sb["remote_id"]);
            }

            if (!resolvedRemoteId) {
              throw new Error("No ready sandbox available for shell execution");
            }

            const timeout = requireIntegerInRange(input["timeout"], "timeout", 1, 600, 120);
            const cwd = typeof input["cwd"] === "string" && input["cwd"].trim().length > 0 ? input["cwd"].trim() : "/workspace";

            return (await instavm("/vm/exec", {
              vm_id: resolvedRemoteId,
              command,
              cwd,
              timeout,
            }, "POST", auth)) as Json;
          }

          if (tool === "sandbox.provision") {
            const workspacePath = `/workspaces/${taskId ?? "shared"}`;
            const image = typeof input["image"] === "string" ? input["image"].trim() : "nixos";
            const nixPackages = Array.isArray(input["nix_packages"]) ? input["nix_packages"] : ["bash", "coreutils", "git"];

            const remote = await instavm("/vm/create", {
              image,
              nix_packages: nixPackages,
              persistent: input["persistent"] !== false,
              label: `task-${taskId ?? "shared"}`,
              workspace_path: workspacePath,
              mount_path: workspacePath,
            }, "POST", auth);

            const remoteId = String((remote as any)?.id ?? (remote as any)?.vm_id ?? "").trim();
            if (!remoteId) throw new Error("sandbox provider did not return an instance id");

            const { data: sb, error: sbError } = await client
              .from("agent_sandboxes")
              .insert({
                task_id: taskId,
                tenant_id: auth.tenantId,
                remote_id: remoteId,
                workspace_path: workspacePath,
                status: "ready",
                metadata: redactSensitiveData(remote),
                created_at: nowIso(),
                updated_at: nowIso(),
              })
              .select()
              .single();
            if (sbError || !sb) throw new Error(sbError?.message ?? "failed to record sandbox");
            return { sandbox_id: (sb as { id: string }).id, remote_id: remoteId, status: "ready" };
          }

          if (tool === "sandbox.terminate") {
            const sbId = requireNonEmptyString(input["sandbox_id"], "sandbox_id", 128);
            const sb = await assertSandboxOwnership(sbId, auth);
            if (sb["remote_id"]) {
              try {
                await instavm(`/vm/${sb["remote_id"]}`, undefined, "DELETE", auth);
              } catch {
              }
            }
            await client.from("agent_sandboxes").update({ status: "terminated", updated_at: nowIso() }).eq("id", sbId);
            return { sandbox_id: sbId, status: "terminated" };
          }

          if (tool === "browser.session") {
            let remoteId: string | null = null;
            const sandboxId = typeof input["sandbox_id"] === "string" && input["sandbox_id"].trim().length > 0
              ? input["sandbox_id"].trim()
              : null;
            if (sandboxId) {
              const sandbox = await assertSandboxOwnership(sandboxId, auth);
              if (sandbox["status"] !== "ready" || !sandbox["remote_id"]) {
                throw new Error("referenced sandbox is not ready");
              }
              remoteId = String(sandbox["remote_id"]);
            } else if (taskId) {
              const { data: sb } = await client
                .from("agent_sandboxes")
                .select("remote_id, status")
                .eq("task_id", taskId)
                .eq("status", "ready")
                .order("created_at", { ascending: false })
                .limit(1)
                .maybeSingle();
              if (sb && sb["remote_id"]) remoteId = String(sb["remote_id"]);
            }

            if (!remoteId) {
              throw new Error("Browser session requires an active, ready sandbox instance");
            }

            const startUrl = typeof input["url"] === "string" && input["url"].trim().length > 0
              ? input["url"].trim()
              : "about:blank";
            const remote = await instavm("/browser/session", {
              vm_id: remoteId,
              start_url: startUrl,
              headless: input["headless"] !== false,
            }, "POST", auth);
            const remoteSessionId = String((remote as any)?.session_id ?? (remote as any)?.id ?? (remote as any)?.browser_session_id ?? "");

            const { data: bs, error: bsError } = await client
              .from("agent_browser_sessions")
              .insert({
                task_id: taskId,
                sandbox_id: sandboxId,
                tenant_id: auth.tenantId,
                status: "open",
                remote_id: remoteSessionId || null,
                remote_session_id: remoteSessionId || null,
                current_url: startUrl,
                history: [{ url: startUrl, at: nowIso() }],
                metadata: redactSensitiveData(remote),
                created_at: nowIso(),
                updated_at: nowIso(),
              })
              .select()
              .single();
            if (bsError || !bs) throw new Error(bsError?.message ?? "failed to record browser session");
            return { browser_session_id: (bs as { id: string }).id, status: "open" };
          }

          if (tool === "browser.navigate") {
            const bsId = requireNonEmptyString(input["browser_session_id"], "browser_session_id", 128);
            const navUrl = requireNonEmptyString(input["url"], "url", 2048);
            const bs = await assertBrowserSessionOwnership(bsId, auth);
            if (bs["status"] !== "open") throw new Error("browser session is not open");

            await instavm("/browser/navigate", {
              session_id: bs["remote_session_id"],
              url: navUrl,
            }, "POST", auth);

            const hist = Array.isArray(bs["history"]) ? bs["history"] : [];
            await client.from("agent_browser_sessions").update({
              current_url: navUrl,
              history: [...hist, { url: navUrl, at: nowIso() }],
              updated_at: nowIso(),
            }).eq("id", bsId);

            return { browser_session_id: bsId, current_url: navUrl };
          }

          if (tool === "browser.close") {
            const bsId = requireNonEmptyString(input["browser_session_id"], "browser_session_id", 128);
            const bs = await assertBrowserSessionOwnership(bsId, auth);
            if (bs["remote_session_id"]) {
              try {
                await instavm(`/browser/session/${bs["remote_session_id"]}`, undefined, "DELETE", auth);
              } catch {
              }
            }
            await client.from("agent_browser_sessions").update({ status: "closed", updated_at: nowIso() }).eq("id", bsId);
            return { browser_session_id: bsId, status: "closed" };
          }

          if (tool === "artifact.write") {
            const path = requireNonEmptyString(input["path"], "path", 1024);
            if (!/^[a-zA-Z0-9_\-\.\/]+$/.test(path) || path.includes("..")) {
              throw new Error("invalid artifact path format");
            }
            const content = typeof input["content"] === "string" ? input["content"] : "";
            const mimeType = typeof input["mime_type"] === "string" && input["mime_type"].trim().length > 0 ? input["mime_type"].trim() : "text/plain";
            if (!/^[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.\+]+$/.test(mimeType) || mimeType.length > 128) {
              throw new Error("invalid mime_type format");
            }
            const contentBytes = encoder.encode(content);
            if (contentBytes.length > 5 * 1024 * 1024) {
              throw new Error("artifact content exceeds maximum size of 5MB");
            }
            const sha256 = await sha256Hex(content);

            let q = client.from("agent_artifacts").select("id").eq("path", path);
            if (taskId) q = q.eq("task_id", taskId);
            else q = q.is("task_id", null);

            const { data: existingArt, error: findArtError } = await q.maybeSingle();
            if (findArtError) throw new Error(findArtError.message);

            let artRecord: Json;
            if (existingArt) {
              const { data: updatedArt, error: updateArtErr } = await client
                .from("agent_artifacts")
                .update({
                  agent_id: agentId,
                  mime_type: mimeType,
                  size_bytes: contentBytes.length,
                  sha256,
                  content,
                  updated_at: nowIso(),
                })
                .eq("id", (existingArt as { id: string }).id)
                .select()
                .single();
              if (updateArtErr || !updatedArt) throw new Error(updateArtErr?.message ?? "failed to update artifact");
              artRecord = updatedArt as Json;
            } else {
              const { data: insertedArt, error: insertArtErr } = await client
                .from("agent_artifacts")
                .insert({
                  task_id: taskId,
                  agent_id: agentId,
                  tenant_id: auth.tenantId,
                  path,
                  mime_type: mimeType,
                  size_bytes: contentBytes.length,
                  sha256,
                  content,
                  created_at: nowIso(),
                  updated_at: nowIso(),
                })
                .select()
                .single();
              if (insertArtErr || !insertedArt) throw new Error(insertArtErr?.message ?? "failed to insert artifact");
              artRecord = insertedArt as Json;
            }
            return {
              artifact_id: artRecord["id"],
              path: artRecord["path"],
              sha256: artRecord["sha256"],
              size_bytes: artRecord["size_bytes"],
            };
          }

          if (tool === "research.search") {
            const query = requireNonEmptyString(input["query"], "query", 1024);
            const numResults = requireIntegerInRange(input["num_results"], "num_results", 1, 50, 8);
            const search = await exaSearch(query, numResults, auth);
            return { results: search.results ?? [] };
          }

          if (tool === "model.complete") {
            const messages = input["messages"];
            if (!Array.isArray(messages) || messages.length === 0 || !messages.every(isValidChatMessage)) {
              throw new Error("messages must be a non-empty array of valid chat message objects");
            }
            const maxTokens = requireIntegerInRange(input["max_tokens"], "max_tokens", 1, 32768, 2048);
            const intent = normalizeIntent(typeof input["intent"] === "string" ? input["intent"] : undefined);
            const result = await routeCompletion(messages, intent, maxTokens, auth);
            return { alias: result.alias, content: result.content };
          }

          if (tool === "mcp.invoke") {
            const server = requireNonEmptyString(input["server"], "server", 128);
            const rpcMethod = requireNonEmptyString(input["method"], "method", 128);
            const params = isPlainObject(input["params"]) ? input["params"] : {};
            return await mcpInvoke(server, rpcMethod, params, auth);
          }

          throw new Error(`unsupported tool execution: ${tool}`);
        },
        auth,
        taskId,
        agentId,
      );

      return json({ ok: true, call_id: execRes.call_id, output: execRes.output });
    }
    return fail("unknown tool route", 404);
  }

  if (root === "sandboxes") {
    if (method === "POST" && !second) {
      const taskId = typeof body["task_id"] === "string" && body["task_id"].trim().length > 0
        ? body["task_id"].trim()
        : null;

      if (taskId) {
        try {
          await assertTaskOwnership(taskId, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("referenced task_id not found", 404);
        }
      }

      const execRes = await recordDirectToolExecution(
        "sandbox.provision",
        { task_id: taskId, image: body["image"], nix_packages: body["nix_packages"], persistent: body["persistent"] },
        async () => {
          const workspacePath = `/workspaces/${taskId ?? "shared"}`;
          const image = typeof body["image"] === "string" ? body["image"].trim() : "nixos";
          const nixPackages = Array.isArray(body["nix_packages"]) ? body["nix_packages"] : ["bash", "coreutils", "git"];

          const remote = await instavm("/vm/create", {
            image,
            nix_packages: nixPackages,
            persistent: body["persistent"] !== false,
            label: `task-${taskId ?? "shared"}`,
            workspace_path: workspacePath,
            mount_path: workspacePath,
          }, "POST", auth);

          const remoteId = String((remote as any)?.id ?? (remote as any)?.vm_id ?? "").trim();
          if (!remoteId) throw new Error("sandbox provider did not return a valid vm instance id");

          const { data: sb, error: sbError } = await client
            .from("agent_sandboxes")
            .insert({
              task_id: taskId,
              tenant_id: auth.tenantId,
              remote_id: remoteId,
              workspace_path: workspacePath,
              status: "ready",
              metadata: redactSensitiveData(remote),
              created_at: nowIso(),
              updated_at: nowIso(),
            })
            .select()
            .single();

          if (sbError || !sb) throw new Error(sbError?.message ?? "failed to create sandbox record");
          return sb as Json;
        },
        auth,
        taskId,
      );

      return json({ ok: true, sandbox: execRes.output });
    }

    if (method === "GET" && !second) {
      const taskId = url.searchParams.get("task_id");
      const status = url.searchParams.get("status");
      const limit = requireIntegerInRange(url.searchParams.get("limit"), "limit", 1, 100, 50);
      const cursor = url.searchParams.get("cursor");

      let query = client
        .from("agent_sandboxes")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(limit);

      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }

      if (taskId) query = query.eq("task_id", taskId);
      if (status) query = query.eq("status", status);
      if (cursor) query = query.lt("created_at", cursor);

      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      const sandboxes = data ?? [];
      const nextCursor = sandboxes.length === limit ? (sandboxes[sandboxes.length - 1] as { created_at: string }).created_at : null;
      return json({ ok: true, sandboxes, has_more: sandboxes.length === limit, next_cursor: nextCursor });
    }

    if (second && !third) {
      if (method === "GET") {
        try {
          const sandbox = await assertSandboxOwnership(second, auth);
          return json({ ok: true, sandbox });
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("sandbox not found", 404);
        }
      }
    }

    if (second && third === "terminate" && method === "POST" && !fourth) {
      let sb: Json;
      try {
        sb = await assertSandboxOwnership(second, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("sandbox not found", 404);
      }

      const execRes = await recordDirectToolExecution(
        "sandbox.terminate",
        { sandbox_id: second },
        async () => {
          if (sb["remote_id"]) {
            try {
              await instavm(`/vm/${sb["remote_id"]}`, undefined, "DELETE", auth);
            } catch {
            }
          }
          const { data: updated } = await client
            .from("agent_sandboxes")
            .update({ status: "terminated", updated_at: nowIso() })
            .eq("id", second)
            .select()
            .single();
          return updated as Json;
        },
        auth,
        typeof sb["task_id"] === "string" ? sb["task_id"] : null,
      );

      return json({ ok: true, sandbox: execRes.output });
    }
    return fail("unknown sandbox route", 404);
  }

  if (root === "browser") {
    if (method === "POST" && !second) {
      const taskId = typeof body["task_id"] === "string" && body["task_id"].trim().length > 0
        ? body["task_id"].trim()
        : null;
      const sandboxId = typeof body["sandbox_id"] === "string" && body["sandbox_id"].trim().length > 0
        ? body["sandbox_id"].trim()
        : null;

      if (taskId) {
        try {
          await assertTaskOwnership(taskId, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("referenced task_id not found", 404);
        }
      }

      const execRes = await recordDirectToolExecution(
        "browser.session",
        { task_id: taskId, sandbox_id: sandboxId, url: body["url"] },
        async () => {
          let remoteId: string | null = null;
          if (sandboxId) {
            const sandbox = await assertSandboxOwnership(sandboxId, auth);
            if (sandbox["status"] !== "ready" || !sandbox["remote_id"]) {
              throw new Error("specified sandbox is not ready");
            }
            remoteId = String(sandbox["remote_id"]);
          } else if (taskId) {
            const { data: sb } = await client
              .from("agent_sandboxes")
              .select("remote_id, id")
              .eq("task_id", taskId)
              .eq("status", "ready")
              .order("created_at", { ascending: false })
              .limit(1)
              .maybeSingle();
            if (sb && sb["remote_id"]) remoteId = String(sb["remote_id"]);
          }

          if (!remoteId) {
            throw new Error("Browser session requires an active, ready sandbox instance");
          }

          const startUrl = typeof body["url"] === "string" && body["url"].trim().length > 0 ? body["url"].trim() : "about:blank";
          const remote = await instavm("/browser/session", {
            vm_id: remoteId,
            start_url: startUrl,
            headless: body["headless"] !== false,
          }, "POST", auth);

          const remoteSessionId = String((remote as any)?.session_id ?? (remote as any)?.id ?? (remote as any)?.browser_session_id ?? "");

          const { data: bs, error: bsError } = await client
            .from("agent_browser_sessions")
            .insert({
              task_id: taskId,
              sandbox_id: sandboxId,
              tenant_id: auth.tenantId,
              status: "open",
              remote_id: remoteSessionId || null,
              remote_session_id: remoteSessionId || null,
              current_url: startUrl,
              history: [{ url: startUrl, at: nowIso() }],
              metadata: redactSensitiveData(remote),
              created_at: nowIso(),
              updated_at: nowIso(),
            })
            .select()
            .single();

          if (bsError || !bs) throw new Error(bsError?.message ?? "failed to create browser session");
          return bs as Json;
        },
        auth,
        taskId,
      );

      return json({ ok: true, browser_session: execRes.output });
    }

    if (method === "GET" && !second) {
      const taskId = url.searchParams.get("task_id");
      const status = url.searchParams.get("status");
      const limit = requireIntegerInRange(url.searchParams.get("limit"), "limit", 1, 100, 50);
      const cursor = url.searchParams.get("cursor");

      let query = client
        .from("agent_browser_sessions")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(limit);

      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }

      if (taskId) query = query.eq("task_id", taskId);
      if (status) query = query.eq("status", status);
      if (cursor) query = query.lt("created_at", cursor);

      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      const sessions = data ?? [];
      const nextCursor = sessions.length === limit ? (sessions[sessions.length - 1] as { created_at: string }).created_at : null;
      return json({ ok: true, browser_sessions: sessions, has_more: sessions.length === limit, next_cursor: nextCursor });
    }

    if (second && third === "navigate" && method === "POST" && !fourth) {
      let bs: Json;
      try {
        bs = await assertBrowserSessionOwnership(second, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("browser session not found", 404);
      }

      const navUrl = requireNonEmptyString(body["url"], "url", 2048);
      const execRes = await recordDirectToolExecution(
        "browser.navigate",
        { browser_session_id: second, url: navUrl },
        async () => {
          if (bs["status"] !== "open") throw new Error("browser session is not open");
          await instavm("/browser/navigate", {
            session_id: bs["remote_session_id"],
            url: navUrl,
          }, "POST", auth);

          const hist = Array.isArray(bs["history"]) ? bs["history"] : [];
          const { data: updated } = await client.from("agent_browser_sessions").update({
            current_url: navUrl,
            history: [...hist, { url: navUrl, at: nowIso() }],
            updated_at: nowIso(),
          }).eq("id", second).select().single();

          return updated as Json;
        },
        auth,
        typeof bs["task_id"] === "string" ? bs["task_id"] : null,
      );

      return json({ ok: true, browser_session: execRes.output });
    }

    if (second && third === "close" && method === "POST" && !fourth) {
      let bs: Json;
      try {
        bs = await assertBrowserSessionOwnership(second, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("browser session not found", 404);
      }

      const execRes = await recordDirectToolExecution(
        "browser.close",
        { browser_session_id: second },
        async () => {
          if (bs["remote_session_id"]) {
            try {
              await instavm(`/browser/session/${bs["remote_session_id"]}`, undefined, "DELETE", auth);
            } catch {
            }
          }
          const { data: updated } = await client
            .from("agent_browser_sessions")
            .update({ status: "closed", updated_at: nowIso() })
            .eq("id", second)
            .select()
            .single();
          return updated as Json;
        },
        auth,
        typeof bs["task_id"] === "string" ? bs["task_id"] : null,
      );

      return json({ ok: true, browser_session: execRes.output });
    }
    return fail("unknown browser route", 404);
  }

  if (root === "research" && method === "POST" && !second) {
    const query = requireNonEmptyString(body["query"], "query", 1024);
    const numResults = requireIntegerInRange(body["num_results"], "num_results", 1, 50, 8);
    const taskId = typeof body["task_id"] === "string" && body["task_id"].trim().length > 0 ? body["task_id"].trim() : null;

    if (taskId) {
      try {
        await assertTaskOwnership(taskId, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("referenced task_id not found", 404);
      }
    }

    const execRes = await recordDirectToolExecution(
      "research.search",
      { query, num_results: numResults, task_id: taskId },
      async () => {
        const search = await exaSearch(query, numResults, auth);
        const seen = new Set<string>();
        const rows: Json[] = [];
        for (const item of search.results ?? []) {
          const rawUrl = String(item.url ?? "");
          const canonical = canonicalUrl(rawUrl);
          if (!canonical) continue;
          if (seen.has(canonical)) continue;
          seen.add(canonical);
          rows.push({
            task_id: taskId,
            tenant_id: auth.tenantId,
            provider: "exa",
            url: rawUrl,
            canonical_url: canonical,
            title: typeof item.title === "string" ? item.title.slice(0, 512) : null,
            snippet: typeof item.text === "string" ? item.text.slice(0, 1200) : null,
            published_at: validateAndParseTimestamp(item.publishedDate),
            score: validateAndParseScore(item.score),
            created_at: nowIso(),
          });
        }

        let returnedSources = rows;
        if (taskId && rows.length > 0) {
          const { data: upserted, error: upsertError } = await client
            .from("agent_sources")
            .upsert(rows, { onConflict: "task_id,canonical_url" })
            .select();
          if (upsertError) throw new Error(upsertError.message);
          returnedSources = upserted ?? rows;
        }

        return { sources: returnedSources };
      },
      auth,
      taskId,
    );

    return json({ ok: true, sources: (execRes.output as Json)?.sources });
  }

  if (root === "sources" && method === "GET" && !second) {
    const taskId = url.searchParams.get("task_id");
    if (taskId) {
      try {
        await assertTaskOwnership(taskId, auth);
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes("forbidden")) return fail(msg, 403);
        return fail("task not found", 404);
      }
    }

    const limit = requireIntegerInRange(url.searchParams.get("limit"), "limit", 1, 200, 50);
    const cursor = url.searchParams.get("cursor");

    let query = client
      .from("agent_sources")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (auth.tenantId !== "system" && auth.role !== "admin") {
      query = query.eq("tenant_id", auth.tenantId);
    }

    if (taskId) query = query.eq("task_id", taskId);
    if (cursor) query = query.lt("created_at", cursor);

    const { data, error } = await query;
    if (error) return fail(error.message, 500);
    const sources = data ?? [];
    const nextCursor = sources.length === limit ? (sources[sources.length - 1] as { created_at: string }).created_at : null;
    return json({ ok: true, sources, has_more: sources.length === limit, next_cursor: nextCursor });
  }

  if (root === "mcp") {
    if (method === "POST" && !second) {
      const name = requireNonEmptyString(body["name"], "name", 128);
      const canonicalName = name.toLowerCase();
      const serverUrl = requireNonEmptyString(body["url"], "url", 2048);
      const transport = requireNonEmptyString(body["transport"] ?? "http", "transport", 32);
      const authCredential = typeof body["auth_credential"] === "string" && body["auth_credential"].trim().length > 0
        ? body["auth_credential"].trim()
        : null;

      if (!isValidHttpUrl(serverUrl)) return fail("url must be a valid http or https URL", 400);

      if (authCredential) {
        try {
          await readCredential(authCredential, auth);
        } catch {
          return fail(`auth_credential '${authCredential}' does not exist`, 404);
        }
      }

      let tools: unknown[] = [];
      try {
        const listed = await mcpInvokeDirect(serverUrl, transport, authCredential, "tools/list", {}, auth);
        tools = ((listed as any)?.result?.tools ?? (listed as any)?.tools ?? []) as unknown[];
      } catch (validationErr) {
        return fail(`MCP server unreachable or failed initialization: ${sanitizeExternalErrorMessage(validationErr)}`, 502);
      }

      const { data, error } = await client
        .from("agent_mcp_servers")
        .upsert(
          {
            name: canonicalName,
            tenant_id: auth.tenantId,
            url: serverUrl,
            transport,
            auth_credential: authCredential,
            tools: redactSensitiveData(tools),
            status: "connected",
            created_at: nowIso(),
            updated_at: nowIso(),
          },
          { onConflict: "name" },
        )
        .select()
        .single();

      if (error || !data) return fail(error?.message ?? "failed to persist MCP server record", 500);
      return json({ ok: true, server: data });
    }

    if (method === "GET" && !second) {
      let query = client.from("agent_mcp_servers").select("*").order("name");
      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.or(`tenant_id.is.null,tenant_id.eq.${auth.tenantId}`);
      }
      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      return json({ ok: true, servers: data ?? [] });
    }

    if (method === "POST" && second === "invoke" && !third) {
      const server = requireNonEmptyString(body["server"], "server", 128);
      const rpcMethod = requireNonEmptyString(body["method"], "method", 128);
      const params = body["params"] !== undefined ? requirePlainObject(body["params"], "params") : {};

      const execRes = await recordDirectToolExecution(
        "mcp.invoke",
        { server, method: rpcMethod, params },
        async () => {
          return await mcpInvoke(server, rpcMethod, params, auth);
        },
        auth,
      );

      return json({ ok: true, result: execRes.output });
    }
    return fail("unknown mcp route", 404);
  }

  if (root === "credentials") {
    if ((method === "POST" || method === "PUT") && !second) {
      const name = requireNonEmptyString(body["name"], "name", 128);
      const value = requireString(body["value"], "value", 65536);
      if (!/^[a-zA-Z0-9_\-\.]{1,128}$/.test(name)) {
        return fail("credential name must be between 1 and 128 alphanumeric, underscore, hyphen, or dot characters", 400);
      }

      let historyArray: Json[] = [];
      const { data: existing } = await client.from("agent_credentials").select("ciphertext, iv, key_version, updated_at, history").eq("name", name).maybeSingle();
      if (existing) {
        const prevHist = Array.isArray(existing.history) ? existing.history : [];
        historyArray = [...prevHist, {
          ciphertext: existing.ciphertext,
          iv: existing.iv,
          key_version: existing.key_version,
          archived_at: existing.updated_at ?? nowIso(),
        }];
      }

      try {
        const { ciphertext, iv, key_version } = await encryptSecret(value, name);
        const { data, error } = await client
          .from("agent_credentials")
          .upsert({
            name,
            tenant_id: auth.tenantId,
            ciphertext,
            iv,
            key_version,
            history: historyArray,
            created_at: nowIso(),
            updated_at: nowIso(),
          }, { onConflict: "name" })
          .select("name, created_at, updated_at")
          .single();

        if (error || !data) return fail(error?.message ?? "failed to persist credential", 500);
        audit(auth.userId, "credential.write", name, { tenant_id: auth.tenantId, key_version }, undefined, auth.tenantId);
        return json({ ok: true, name });
      } catch (encryptionErr) {
        if (encryptionErr instanceof WrongKeyVersion) return fail(encryptionErr.message, 400);
        if (encryptionErr instanceof CryptoUnavailable) return fail(encryptionErr.message, 503);
        return fail("credential encryption failed", 500);
      }
    }

    if (method === "GET" && !second) {
      const limit = requireIntegerInRange(url.searchParams.get("limit"), "limit", 1, 100, 50);
      const cursor = url.searchParams.get("cursor");

      let query = client
        .from("agent_credentials")
        .select("name, key_version, created_at, updated_at")
        .order("name", { ascending: true })
        .limit(limit);

      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.or(`tenant_id.is.null,tenant_id.eq.${auth.tenantId}`);
      }

      if (cursor) query = query.gt("name", cursor);

      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      const credentials = data ?? [];
      const nextCursor = credentials.length === limit ? (credentials[credentials.length - 1] as { name: string }).name : null;
      return json({ ok: true, credentials, has_more: credentials.length === limit, next_cursor: nextCursor });
    }

    if (second && method === "DELETE" && !third) {
      let existingQuery = client.from("agent_credentials").select("name, tenant_id").eq("name", second);
      if (auth.tenantId !== "system" && auth.role !== "admin") {
        existingQuery = existingQuery.eq("tenant_id", auth.tenantId);
      }
      const { data: existing, error: findError } = await existingQuery.maybeSingle();
      if (findError) return fail(findError.message, 500);
      if (!existing) return fail("credential not found", 404);

      const { data, error } = await client
        .from("agent_credentials")
        .delete()
        .eq("name", second)
        .select("name")
        .maybeSingle();
      if (error) return fail(error.message, 500);
      if (!data) return fail("credential deletion conflict or missing", 404);
      audit(auth.userId, "credential.delete", second, { tenant_id: auth.tenantId }, undefined, auth.tenantId);
      return json({ ok: true });
    }
    return fail("unknown credential route", 404);
  }

  if (root === "artifacts") {
    if (method === "POST" && !second) {
      const content = requireString(body["content"] ?? "", "content", 5242880);
      const path = requireNonEmptyString(body["path"], "path", 1024);
      if (!/^[a-zA-Z0-9_\-\.\/]+$/.test(path) || path.includes("..")) {
        return fail("invalid artifact path", 400);
      }
      const mimeType = requireNonEmptyString(body["mime_type"] ?? "text/plain", "mime_type", 128);
      if (!/^[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.\+]+$/.test(mimeType)) {
        return fail("invalid mime_type format", 400);
      }

      const taskId = typeof body["task_id"] === "string" && body["task_id"].trim().length > 0 ? body["task_id"].trim() : null;
      const agentId = typeof body["agent_id"] === "string" && body["agent_id"].trim().length > 0 ? body["agent_id"].trim() : null;

      if (taskId) {
        try {
          await assertTaskOwnership(taskId, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("referenced task_id not found", 404);
        }
      }

      if (agentId) {
        try {
          const aObj = await assertAgentOwnership(agentId, auth);
          if (taskId && aObj["task_id"] !== taskId) {
            return fail("referenced agent_id does not belong to the specified task_id", 400);
          }
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("referenced agent_id not found", 404);
        }
      }

      const contentBytes = encoder.encode(content);
      const sha256 = await sha256Hex(content);

      let q = client.from("agent_artifacts").select("id").eq("path", path);
      if (taskId) q = q.eq("task_id", taskId);
      else q = q.is("task_id", null);

      const { data: existingArt, error: findArtError } = await q.maybeSingle();
      if (findArtError) return fail(findArtError.message, 500);

      let artifactRecord: Json;
      if (existingArt) {
        const { data: updatedArt, error: updateArtErr } = await client
          .from("agent_artifacts")
          .update({
            agent_id: agentId,
            mime_type: mimeType,
            size_bytes: contentBytes.length,
            sha256,
            content,
            updated_at: nowIso(),
          })
          .eq("id", (existingArt as { id: string }).id)
          .select("id, task_id, agent_id, path, mime_type, size_bytes, sha256, created_at, updated_at")
          .single();
        if (updateArtErr || !updatedArt) return fail(updateArtErr?.message ?? "failed to update artifact", 500);
        artifactRecord = updatedArt as Json;
      } else {
        const { data: insertedArt, error: insertArtErr } = await client
          .from("agent_artifacts")
          .insert({
            task_id: taskId,
            agent_id: agentId,
            tenant_id: auth.tenantId,
            path,
            mime_type: mimeType,
            size_bytes: contentBytes.length,
            sha256,
            content,
            created_at: nowIso(),
            updated_at: nowIso(),
          })
          .select("id, task_id, agent_id, path, mime_type, size_bytes, sha256, created_at, updated_at")
          .single();
        if (insertArtErr || !insertedArt) return fail(insertArtErr?.message ?? "failed to insert artifact", 500);
        artifactRecord = insertedArt as Json;
      }

      emit(taskId, "artifact.created", { path }, null, undefined, auth.tenantId);
      return json({ ok: true, artifact: artifactRecord }, 201);
    }

    if (method === "GET" && !second) {
      const taskId = url.searchParams.get("task_id");
      if (taskId) {
        try {
          await assertTaskOwnership(taskId, auth);
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes("forbidden")) return fail(msg, 403);
          return fail("task not found", 404);
        }
      }

      const limit = requireIntegerInRange(url.searchParams.get("limit"), "limit", 1, 200, 50);
      const cursor = url.searchParams.get("cursor");

      let query = client
        .from("agent_artifacts")
        .select("id, task_id, agent_id, path, mime_type, size_bytes, sha256, created_at, updated_at")
        .order("created_at", { ascending: false })
        .limit(limit);

      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }

      if (taskId) query = query.eq("task_id", taskId);
      if (cursor) query = query.lt("created_at", cursor);

      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      const artifacts = data ?? [];
      const nextCursor = artifacts.length === limit ? (artifacts[artifacts.length - 1] as { created_at: string }).created_at : null;
      return json({ ok: true, artifacts, has_more: artifacts.length === limit, next_cursor: nextCursor });
    }

    if (second && method === "GET" && !third) {
      let query = client.from("agent_artifacts").select("*").eq("id", second);
      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }
      const { data, error } = await query.maybeSingle();
      if (error) return fail(error.message, 500);
      if (!data) return fail("artifact not found", 404);
      const art = data as { content: string; sha256: string; size_bytes: number };
      if (typeof art.content === "string" && art.sha256) {
        const computedSha = await sha256Hex(art.content);
        if (computedSha !== art.sha256) {
          return fail("artifact integrity check failed: sha256 mismatch", 500);
        }
      }

      const includeContent = url.searchParams.get("include_content") === "true";
      if (!includeContent) {
        const { content: _ignored, ...metadataOnly } = data as Json;
        return json({ ok: true, artifact: metadataOnly });
      }

      return json({ ok: true, artifact: data });
    }
    return fail("unknown artifact route", 404);
  }

  if (root === "leases") {
    if (method === "POST" && !second) {
      const name = requireNonEmptyString(body["name"], "name", 128);
      const owner = requireNonEmptyString(body["owner"], "owner", 128);
      const ttl = requireIntegerInRange(body["ttl_seconds"], "ttl_seconds", 1, 86400, 60);

      const now = nowIso();
      const expires = new Date(Date.now() + ttl * 1000).toISOString();
      const { data: existing, error: fetchLeaseError } = await client.from("agent_leases").select("*").eq("name", name).maybeSingle();
      if (fetchLeaseError) return fail(fetchLeaseError.message, 500);

      const existingLease = existing as { owner: string; expires_at: string; tenant_id?: string; history?: Json[] } | null;
      if (existingLease && auth.tenantId !== "system" && auth.role !== "admin" && existingLease.tenant_id && existingLease.tenant_id !== auth.tenantId) {
        return fail("forbidden: lease belongs to another tenant", 403);
      }
      if (existingLease && existingLease.owner !== owner && new Date(existingLease.expires_at).getTime() > Date.now()) {
        return fail("lease held by another owner", 409, { owner: existingLease.owner });
      }

      let history = Array.isArray(existingLease?.history) ? existingLease.history : [];
      history = [...history, { acquired_by: owner, at: now, expires_at: expires }];

      const { data, error } = await client
        .from("agent_leases")
        .upsert({
          name,
          owner,
          tenant_id: auth.tenantId,
          expires_at: expires,
          heartbeat_at: now,
          history,
          created_at: nowIso(),
          updated_at: nowIso(),
        }, { onConflict: "name" })
        .select()
        .maybeSingle();

      if (error) return fail(error.message, 500);
      if (!data) return fail("lease acquisition failed", 500);
      return json({ ok: true, lease: data });
    }

    if (method === "GET" && !second) {
      const includeExpired = url.searchParams.get("include_expired") === "true";
      const now = nowIso();
      let query = client.from("agent_leases").select("*").order("name", { ascending: true });
      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }
      if (!includeExpired) {
        query = query.gt("expires_at", now);
      }
      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      return json({ ok: true, leases: data ?? [] });
    }
    return fail("unknown lease route", 404);
  }

  if (root === "recover" && method === "POST" && !second) {
    if (!auth.isWorker && auth.role !== "admin") {
      return fail("forbidden: recovery endpoint requires worker or admin authorization", 403);
    }

    const limit = requireIntegerInRange(body["limit"], "limit", 1, 50, 20);
    const { data: reclaimed } = await reclaimQuery(client, limit);
    const now = nowIso();
    const owner = typeof body["owner"] === "string" && body["owner"].trim().length > 0 ? body["owner"].trim() : auth.userId;

    let pendingQuery = client
      .from("agent_tasks")
      .select("id, version, state, priority, objective, scheduled_at, created_at, tenant_id")
      .is("deleted_at", null)
      .eq("state", "pending")
      .or(`scheduled_at.is.null,scheduled_at.lte.${now}`)
      .order("priority", { ascending: false })
      .limit(limit);

    if (auth.tenantId !== "system" && auth.role !== "admin") {
      pendingQuery = pendingQuery.eq("tenant_id", auth.tenantId);
    }

    const { data: pending, error } = await pendingQuery;
    if (error) return fail(error.message, 500);

    let scheduledTasks = pending ?? [];
    if (owner && scheduledTasks.length > 0) {
      const leaseDuration = requireIntegerInRange(body["lease_seconds"] ?? body["ttl_seconds"], "lease_seconds", 1, 3600, 60);
      const expiresAt = new Date(Date.now() + leaseDuration * 1000).toISOString();
      const claimedList: Json[] = [];
      for (const item of scheduledTasks as Array<{ id: string; version: number | null }>) {
        const { data: claimed, error: claimErr } = await client
          .from("agent_tasks")
          .update({
            state: "running",
            phase: "planning",
            lease_owner: owner,
            lease_expires_at: expiresAt,
            heartbeat_at: nowIso(),
            version: Number(item.version ?? 1) + 1,
            updated_at: nowIso(),
          })
          .eq("id", item.id)
          .eq("version", item.version)
          .eq("state", "pending")
          .is("deleted_at", null)
          .select("id, version, state, priority, objective, scheduled_at, created_at, lease_owner, lease_expires_at")
          .maybeSingle();
        if (!claimErr && claimed) {
          claimedList.push(claimed as Json);
        }
      }
      scheduledTasks = claimedList;
    }

    audit(auth.userId, "recover", null, { reclaimed: (reclaimed ?? []).length, scheduled: scheduledTasks.length, tenant_id: auth.tenantId }, undefined, auth.tenantId);
    return json({ ok: true, reclaimed: reclaimed ?? [], scheduled: scheduledTasks });
  }

  if (root === "schedule" && method === "POST" && !second) {
    const taskId = requireNonEmptyString(body["task_id"], "task_id", 128);
    const scheduledAtRaw = requireNonEmptyString(body["scheduled_at"] ?? nowIso(), "scheduled_at", 64);
    const parsedDate = new Date(scheduledAtRaw);
    if (Number.isNaN(parsedDate.getTime())) {
      return fail("scheduled_at must be a valid ISO-8601 timestamp string", 400);
    }
    const at = parsedDate.toISOString();

    let task: Json;
    try {
      task = await assertTaskOwnership(taskId, auth);
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes("forbidden")) return fail(msg, 403);
      return fail("task not found or deleted", 404);
    }

    const taskState = String(task["state"]);
    if (["completed", "failed", "cancelled"].includes(taskState)) {
      return fail(`cannot schedule task in terminal state '${taskState}'`, 409);
    }

    const currentOwner = task["lease_owner"];
    const leaseExpires = task["lease_expires_at"] ? new Date(String(task["lease_expires_at"])).getTime() : 0;
    if (currentOwner && leaseExpires > Date.now()) {
      return fail("cannot schedule an actively leased task", 409);
    }

    const currentVersion = Number(task["version"] ?? 1);
    const { data, error } = await client
      .from("agent_tasks")
      .update({ scheduled_at: at, version: currentVersion + 1, updated_at: nowIso() })
      .eq("id", taskId)
      .eq("version", task["version"])
      .is("deleted_at", null)
      .select()
      .maybeSingle();

    if (error) return fail(error.message, 500);
    if (!data) return fail("scheduling conflict: task modified concurrently", 409);
    return json({ ok: true, task: data });
  }

  if (root === "cli" && method === "POST" && !second) {
    const command = requireNonEmptyString(body["command"], "command", 4096);
    const argv = parseCliArgs(command);
    if (argv.length === 0) return fail("command is required", 400);
    const [verb, ...rest] = argv;

    if (verb === "tasks") {
      let query = client
        .from("agent_tasks")
        .select("id, state, phase, objective")
        .is("deleted_at", null)
        .order("created_at", { ascending: false })
        .limit(20);
      if (auth.tenantId !== "system" && auth.role !== "admin") {
        query = query.eq("tenant_id", auth.tenantId);
      }
      const { data, error } = await query;
      if (error) return fail(error.message, 500);
      return json({
        ok: true,
        stdout: (data ?? [])
          .map((t: any) => `${t.id} ${t.state}/${t.phase} ${String(t.objective ?? "").replace(/[\r\n]+/g, " ")}`)
          .join("\n"),
      });
    }
    if (verb === "capabilities") {
      const caps = await getCapabilities(auth);
      return json({ ok: true, stdout: JSON.stringify(caps, null, 2) });
    }
    if (verb === "ask") {
      const prompt = rest.join(" ").trim();
      if (!prompt) return fail("ask requires a non-empty question", 400);

      const execRes = await recordDirectToolExecution(
        "model.complete",
        { intent: "general", prompt },
        async () => {
          const result = await routeCompletion([{ role: "user", content: prompt }], "general", 2048, auth);
          return { alias: result.alias, content: result.content };
        },
        auth,
      );

      return json({ ok: true, stdout: (execRes.output as Json)?.content, alias: (execRes.output as Json)?.alias, call_id: execRes.call_id });
    }
    if (verb === "exec") {
      const cmd = rest.join(" ").trim();
      if (!cmd) return fail("exec requires a non-empty command", 400);

      const execRes = await recordDirectToolExecution(
        "shell.exec",
        { command: cmd, sandbox_id: body["sandbox_id"] },
        async () => {
          let resolvedRemoteId: string | null = null;
          if (typeof body["sandbox_id"] === "string" && body["sandbox_id"].trim().length > 0) {
            const sb = await assertSandboxOwnership(body["sandbox_id"].trim(), auth);
            if (sb["status"] !== "ready" || !sb["remote_id"]) throw new Error("sandbox is not ready");
            resolvedRemoteId = String(sb["remote_id"]);
          } else {
            const { data: sb } = await client
              .from("agent_sandboxes")
              .select("remote_id, status")
              .eq("status", "ready")
              .order("created_at", { ascending: false })
              .limit(1)
              .maybeSingle();
            if (sb && sb["remote_id"]) resolvedRemoteId = String(sb["remote_id"]);
          }

          if (!resolvedRemoteId) throw new Error("No active ready sandbox found for execution");

          return (await instavm("/vm/exec", {
            vm_id: resolvedRemoteId,
            command: cmd,
            cwd: "/workspace",
            timeout: 120,
          }, "POST", auth)) as Json;
        },
        auth,
      );

      return json({ ok: true, stdout: JSON.stringify(execRes.output), call_id: execRes.call_id });
    }
    return fail(`unknown command: ${verb}`, 400);
  }

  if (root === "webhooks" && method === "POST" && second && !third) {
    if (!VALID_WEBHOOK_TYPES.includes(second as any)) {
      return fail(`unsupported webhook type: ${second}`, 400);
    }
    const secret = await resolveKey("AGENT_WEBHOOK_SECRET", "agent_webhook_secret", auth);
    if (!secret) return fail("webhook capability disabled: missing secret", 503);

    const raw = await request.clone().text();
    const provided = request.headers.get("x-agent-signature") ?? "";

    if (provided.length === 0 || provided.length > 512) {
      audit("webhook", "rejected", second, { reason: "invalid signature header length" }, undefined, auth.tenantId);
      return fail("invalid signature header length or missing signature", 400);
    }

    const expected = createHmac("sha256", secret).update(raw).digest("hex");
    const providedBuf = Buffer.from(provided);
    const expectedBuf = Buffer.from(expected);

    if (providedBuf.length !== expectedBuf.length || !timingSafeEqual(providedBuf, expectedBuf)) {
      audit("webhook", "rejected", second, { reason: "signature mismatch" }, undefined, auth.tenantId);
      return fail("invalid signature", 401);
    }

    const rawTimestamp = request.headers.get("x-agent-timestamp");
    if (rawTimestamp) {
      const ts = Number(rawTimestamp);
      if (!Number.isFinite(ts) || Math.abs(Date.now() - (ts > 1e11 ? ts : ts * 1000)) > 300_000) {
        return fail("webhook timestamp expired or invalid", 400);
      }
    }

    let parsedPayload: Json;
    try {
      const parsed = JSON.parse(raw);
      if (!isPlainObject(parsed)) {
        return fail("invalid webhook JSON payload structure", 400);
      }
      parsedPayload = parsed;
    } catch {
      return fail("invalid webhook JSON payload", 400);
    }

    const deliveryId =
      request.headers.get("x-agent-delivery-id") ??
      (typeof parsedPayload["delivery_id"] === "string" ? parsedPayload["delivery_id"] : null);

    if (deliveryId) {
      const { data: existing, error: dupCheckError } = await client
        .from("agent_events")
        .select("id")
        .eq("kind", `webhook.${second}`)
        .eq("payload->>delivery_id", deliveryId)
        .maybeSingle();
      if (dupCheckError) return fail(dupCheckError.message, 500);
      if (existing) {
        return json({ ok: true, duplicate: true });
      }
    }

    let taskId: string | null = null;
    if (typeof parsedPayload["task_id"] === "string" && parsedPayload["task_id"].trim().length > 0) {
      try {
        const task = await getTask(parsedPayload["task_id"].trim());
        if (!task) return fail("referenced task_id does not exist", 404);
        taskId = (task as { id: string }).id;
      } catch (err) {
        return fail((err as Error).message, 500);
      }
    }

    const minimizedPayload: Json = {
      event_type: second,
      delivery_id: deliveryId,
      task_id: taskId,
      action: typeof parsedPayload["action"] === "string" ? parsedPayload["action"] : null,
      summary: typeof parsedPayload["summary"] === "string" ? parsedPayload["summary"].slice(0, 512) : null,
      received_at: nowIso(),
    };

    emit(taskId, `webhook.${second}`, minimizedPayload, null, undefined, auth.tenantId);
    audit("webhook", "accepted", second, { delivery_id: deliveryId }, undefined, auth.tenantId);
    return json({ ok: true });
  }

  return fail("unknown endpoint", 404);
}

function segmentsFrom(request: Request) {
  const path = new URL(request.url).pathname;
  const match = path.match(/(?:\/api\/agent|\/agent)?\/(.+)$/);
  if (!match) return path.split("/").filter(Boolean);
  return match[1].split("/").filter(Boolean);
}

async function dispatch(request: Request) {
  const segments = segmentsFrom(request);
  const isHealth = segments.length === 1 && segments[0] === "health";

  let auth: AuthContext = { userId: "anonymous", tenantId: "public", role: "public", token: "", isWorker: false };
  if (!isHealth) {
    try {
      const { token } = parseBearerToken(request.headers.get("authorization"));
      auth = verifyAndExtractAuth(token);
    } catch (authErr) {
      return fail((authErr as Error).message || "unauthorized", 401, { code: "UNAUTHORIZED" });
    }
  }

  try {
    return await handle(segments, request, auth);
  } catch (error) {
    if (error instanceof ValidationError) {
      return fail(error.message, 400, { code: "VALIDATION_ERROR", field: error.field });
    }
    if (error instanceof CredentialNotFound) {
      return fail(error.message, 404, { code: "NOT_FOUND" });
    }
    if (error instanceof InvalidBase64 || error instanceof WrongKeyVersion) {
      return fail(error.message, 400, { code: "VALIDATION_ERROR" });
    }
    if (error instanceof CorruptedCiphertext) {
      return fail(error.message, 422, { code: "DECRYPTION_FAILED" });
    }
    if (error instanceof CryptoUnavailable) {
      return fail(error.message, 503, { code: "CRYPTO_UNAVAILABLE" });
    }
    if (error instanceof ProviderError) {
      return fail(error.message, error.status, { code: error.code });
    }
    const message =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : isPlainObject(error) && typeof error["message"] === "string"
            ? error["message"]
            : "Internal server error";

    if (message.includes("forbidden")) {
      return fail(message, 403, { code: "FORBIDDEN" });
    }
    return fail(message, 500, { code: "INTERNAL_ERROR" });
  }
}

export const Route = createFileRoute("/api/agent/$")({
  server: {
    handlers: {
      GET: async ({ request }) => dispatch(request),
      POST: async ({ request }) => dispatch(request),
      PUT: async ({ request }) => dispatch(request),
      PATCH: async ({ request }) => dispatch(request),
      DELETE: async ({ request }) => dispatch(request),
    },
  },
});
