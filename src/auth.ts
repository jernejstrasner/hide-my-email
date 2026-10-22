import { Client, Hash, Mode, Srp, util } from "@foxt/js-srp";
import { getPreferenceValues, LocalStorage } from "@raycast/api";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const exec = promisify(execFile);

/**
 * Apple ID (SRP) authentication for iCloud, ported from foxt/icloud.js and
 * mandarons/icloudpy (including icloudpy's early-2026 fix that requires a PUT to
 * trigger the 2FA push before the code can be submitted).
 *
 * Flow per command run (fresh Node process):
 *   0. authorize/signin GET (OAuth prelude, sets the aasp cookie on idmsa)
 *   1. signin/init + signin/complete  (SRP-6a, GSA mode)  ─ uses a stored trust
 *      token so 2FA is skipped for ~30 days
 *   2. if 409 → 2FA: trigger push (PUT) → user enters code → verify → trust
 *   3. accountLogin (with the webapp's client query params) → fresh iCloud
 *      cookies — the full web-session set incl. X-APPLE-WEBAUTH-TOKEN, which
 *      the Hide My Email service requires — + webservices (premiummailsettings)
 *
 * Because we re-auth each run from the trust token, the iCloud session cookies
 * are always freshly minted — no more cookie expiry to manage by hand.
 */

interface ExtensionPreferences {
  appleId: string;
  password: string;
  region: "global" | "china";
  authStore: "stored" | "prompt";
}

const prefs = getPreferenceValues<ExtensionPreferences>();
const CHINA = prefs.region === "china";
// Prompt mode: the password is never persisted anywhere by this extension.
// The user types it whenever the cached session has expired; it lives only in
// this process's memory. The trust token / session cache below make that rare.
const PROMPT_MODE = prefs.authStore === "prompt";

const CLIENT_ID =
  "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";
const AUTH_ENDPOINT = CHINA
  ? "https://idmsa.apple.com.cn/appleauth/auth/"
  : "https://idmsa.apple.com/appleauth/auth/";
const SETUP_ENDPOINT = CHINA
  ? "https://setup.icloud.com.cn/setup/ws/1/accountLogin"
  : "https://setup.icloud.com/setup/ws/1/accountLogin";
const ICLOUD_ORIGIN = CHINA
  ? "https://www.icloud.com.cn"
  : "https://www.icloud.com";

const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0";

// The icloud.com web app identifies itself with these build numbers in query
// parameters on setup/ws and premiummailsettings calls; accountLogin only
// returns the full web-session cookie set (incl. X-APPLE-WEBAUTH-TOKEN, which
// the Hide My Email service requires) when they are present.
// Value observed from the current web client (2638Build27, Oct 2026).
const WEBAPP_BUILD = "2638Build27";

const DEFAULT_HEADERS: Record<string, string> = {
  "User-Agent": USER_AGENT,
  Accept: "application/json",
  "Content-Type": "application/json",
  Origin: ICLOUD_ORIGIN,
};

const AUTH_HEADERS: Record<string, string> = {
  ...DEFAULT_HEADERS,
  Origin: AUTH_ENDPOINT.replace("/appleauth/auth/", ""),
  Referer: AUTH_ENDPOINT.replace("/appleauth/auth/", "/"),
  "X-Apple-Widget-Key": CLIENT_ID,
  "X-Apple-OAuth-Client-Id": CLIENT_ID,
  "X-Apple-I-FD-Client-Info": JSON.stringify({
    U: USER_AGENT,
    L: "en-GB",
    Z: "GMT+01:00",
    V: "1.1",
    F: "",
  }),
  "X-Apple-OAuth-Response-Type": "code",
  "X-Apple-OAuth-Response-Mode": "web_message",
  "X-Apple-OAuth-Client-Type": "firstPartyAuth",
};

export class ICloudError extends Error {}
export class InvalidCredentialsError extends ICloudError {}
export class InvalidMfaCodeError extends ICloudError {}
/** Thrown in prompt mode when the cached session has expired and the user
 *  needs to enter their password (which is never written to disk). */
export class PasswordRequiredError extends ICloudError {}

// --- SRP-6a (GSA variant) — vendored from foxt/icloud.js iCSRPAuthenticator ---

const srp = new Srp(Mode.GSA, Hash.SHA256, 2048);
const enc = (s: string) => new TextEncoder().encode(s);
const b64ToBytes = (s: string) => Uint8Array.from(Buffer.from(s, "base64"));

interface SrpInitResponse {
  iteration: number;
  salt: string;
  protocol: "s2k" | "s2k_fo";
  b: string;
  c: string;
}

class GSASRPAuthenticator {
  private client?: Client;
  constructor(private username: string) {}

  private async derivePassword(
    protocol: "s2k" | "s2k_fo",
    password: string,
    salt: Uint8Array,
    iterations: number,
  ): Promise<Uint8Array> {
    let passHash: Uint8Array = new Uint8Array(
      await util.hash(srp.h, enc(password).buffer as ArrayBuffer),
    );
    if (protocol === "s2k_fo") passHash = enc(util.toHex(passHash));

    const imported = await crypto.subtle.importKey(
      "raw",
      passHash,
      { name: "PBKDF2" },
      false,
      ["deriveBits"],
    );
    const derived = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: { name: "SHA-256" }, iterations, salt },
      imported,
      256,
    );
    return new Uint8Array(derived);
  }

  async getInit(): Promise<{
    a: string;
    accountName: string;
    protocols: string[];
  }> {
    this.client = await srp.newClient(enc(this.username), new Uint8Array());
    const a = Buffer.from(util.bytesFromBigint(this.client.A)).toString(
      "base64",
    );
    return { a, protocols: ["s2k", "s2k_fo"], accountName: this.username };
  }

  async getComplete(
    password: string,
    server: SrpInitResponse,
  ): Promise<{ accountName: string; m1: string; m2: string; c: string }> {
    if (!this.client) throw new Error("SRP not initialized");
    if (server.protocol !== "s2k" && server.protocol !== "s2k_fo")
      throw new ICloudError(`Unsupported SRP protocol ${server.protocol}`);
    const salt = b64ToBytes(server.salt);
    const serverPub = b64ToBytes(server.b);
    this.client.p = await this.derivePassword(
      server.protocol,
      password,
      salt,
      server.iteration,
    );
    await this.client.generate(salt, serverPub);
    const m1 = Buffer.from(this.client._M).toString("base64");
    const m2 = Buffer.from(await this.client.generateM2()).toString("base64");
    return { accountName: this.username, m1, m2, c: server.c };
  }
}

// --- Session state (per process) ---

type Phase = "idle" | "ready" | "mfa";

interface Session {
  phase: Phase;
  sessionId?: string;
  sessionToken?: string;
  scnt?: string;
  aasp?: string;
  trustToken?: string;
  cookies: string[];
  webservices?: Record<string, { url: string; status: string }>;
  dsid?: string;
  clientId?: string;
}

const session: Session = { phase: "idle", cookies: [] };

// --- Secret storage (trust token + session cache) ---
//
// Secrets live in the macOS login Keychain (encrypted at rest by the OS, and
// outside Raycast's data directory). If the Keychain is unavailable for any
// reason we degrade to Raycast LocalStorage, and any pre-hardening plaintext
// LocalStorage values are migrated to the Keychain on first read.

const KC_SERVICE = "raycast.hide-my-email";
type SecretKind = "trust" | "session";
const LEGACY_KEYS: Record<SecretKind, string> = {
  trust: `trust-token:${prefs.appleId.toLowerCase()}`,
  session: `session-cache:${prefs.appleId.toLowerCase()}`,
};

function kcAccount(kind: SecretKind): string {
  return `${kind}:${prefs.appleId.toLowerCase()}`;
}

/** Returns the stored secret, or undefined. Checks the Keychain first, then
 *  falls back to (and migrates) a legacy plaintext LocalStorage value. */
async function secretGet(kind: SecretKind): Promise<string | undefined> {
  try {
    const { stdout } = await exec("security", [
      "find-generic-password",
      "-s",
      KC_SERVICE,
      "-a",
      kcAccount(kind),
      "-w",
    ]);
    const value = stdout.trim();
    if (value) return value;
  } catch {
    // Not in the Keychain (or `security` unavailable) — fall through.
  }
  const legacy = await LocalStorage.getItem<string>(LEGACY_KEYS[kind]);
  if (!legacy) return undefined;
  // Migrate the legacy value into the Keychain; only drop the plaintext copy
  // if the Keychain write actually succeeded.
  if (await secretSet(kind, legacy)) {
    await LocalStorage.removeItem(LEGACY_KEYS[kind]);
  }
  return legacy;
}

/** Stores a secret. Returns true if it went into the Keychain, false if we
 *  had to degrade to (plaintext) LocalStorage. */
async function secretSet(kind: SecretKind, value: string): Promise<boolean> {
  try {
    await exec("security", [
      "add-generic-password",
      "-U",
      "-s",
      KC_SERVICE,
      "-a",
      kcAccount(kind),
      "-w",
      value,
    ]);
    return true;
  } catch {
    await LocalStorage.setItem(LEGACY_KEYS[kind], value);
    return false;
  }
}

async function secretDelete(kind: SecretKind): Promise<void> {
  try {
    await exec("security", [
      "delete-generic-password",
      "-s",
      KC_SERVICE,
      "-a",
      kcAccount(kind),
    ]);
  } catch {
    // Already absent.
  }
  await LocalStorage.removeItem(LEGACY_KEYS[kind]);
}

// Reuse a session this long before re-running SRP, to avoid Apple rate-limiting.
// Staleness within the window is still handled by retry-on-expiry in authedFetch.
const SESSION_TTL_MS = 60 * 60 * 1000;

/** Loads cached cookies + webservices so repeat command runs skip SRP entirely. */
async function loadSessionCache(): Promise<boolean> {
  try {
    const raw = await secretGet("session");
    if (!raw) return false;
    const c = JSON.parse(raw) as {
      cookies: string[];
      webservices: Session["webservices"];
      dsid?: string;
      clientId?: string;
      ts: number;
    };
    if (!c.cookies?.length || !c.webservices?.premiummailsettings?.url)
      return false;
    if (Date.now() - c.ts > SESSION_TTL_MS) return false;
    session.cookies = c.cookies;
    session.webservices = c.webservices;
    session.dsid = c.dsid;
    session.clientId = c.clientId;
    session.phase = "ready";
    return true;
  } catch {
    return false;
  }
}

async function saveSessionCache(): Promise<void> {
  await secretSet(
    "session",
    JSON.stringify({
      cookies: session.cookies,
      webservices: session.webservices,
      dsid: session.dsid,
      clientId: session.clientId,
      ts: Date.now(),
    }),
  );
}

async function clearSessionCache(): Promise<void> {
  session.phase = "idle";
  session.cookies = [];
  session.webservices = undefined;
  await secretDelete("session");
}

function setCookiesFrom(res: Response) {
  const set = res.headers.getSetCookie?.() ?? [];
  if (set.length) session.cookies = set;
  return set;
}

/** Cookie header value: browsers send only name=value pairs back — never the
 *  Domain/Path/Secure attributes from Set-Cookie. */
function cookieHeader(): string {
  return session.cookies.map((c) => c.split(";")[0].trim()).join("; ");
}

function captureSecrets(res: Response) {
  const sessionToken = res.headers.get("X-Apple-Session-Token");
  if (sessionToken) {
    session.sessionId = sessionToken;
    session.sessionToken = sessionToken;
  }
  const scnt = res.headers.get("scnt");
  if (scnt) session.scnt = scnt;
  captureAuthCookies(res);
}

function mfaHeaders(): Record<string, string> {
  return {
    ...AUTH_HEADERS,
    scnt: session.scnt ?? "",
    "X-Apple-ID-Session-Id": session.sessionId ?? "",
    Cookie: authCookieHeader() || `aasp=${session.aasp ?? ""}`,
  };
}

// Cookies set on idmsa.apple.com during sign-in (aasp, dslang, …), sent
// back on subsequent idmsa requests like a browser would.
const authCookies = new Map<string, string>();

function captureAuthCookies(res: Response) {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const pair = c.split(";")[0];
    const eq = pair.indexOf("=");
    if (eq > 0) authCookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1));
  }
  const aasp = authCookies.get("aasp");
  if (aasp) session.aasp = aasp;
}

function authCookieHeader(): string {
  return [...authCookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

/** Registers an OAuth "authorize" session with Apple — the same GET the
 *  icloud.com sign-in iframe performs before running SRP. It sets the aasp
 *  (and friends) cookies on idmsa.apple.com that the rest of the sign-in
 *  calls are expected to carry; without this prelude, accountLogin only
 *  returns a reduced cookie set missing X-APPLE-WEBAUTH-TOKEN. */
async function authorizePrelude(): Promise<void> {
  const frameId = crypto.randomUUID();
  const qs = new URLSearchParams({
    frame_id: frameId,
    language: "en_US",
    skVersion: "7",
    iframeId: frameId,
    client_id: CLIENT_ID,
    redirect_uri: ICLOUD_ORIGIN,
    response_type: "code",
    response_mode: "web_message",
    state: frameId,
    authVersion: "latest",
  });
  const res = await fetch(`${AUTH_ENDPOINT}authorize/signin?${qs}`, {
    headers: { ...AUTH_HEADERS, Accept: "*/*" },
  });
  captureAuthCookies(res);
}

async function accountLogin(): Promise<void> {
  if (!session.clientId) session.clientId = crypto.randomUUID();
  // Webapp-style identification query params — with them the response sets the
  // full web-session cookie set (17 cookies incl. X-APPLE-WEBAUTH-TOKEN);
  // without them only a reduced 6-cookie set comes back.
  const qs = new URLSearchParams({
    requestId: crypto.randomUUID(),
    clientBuildNumber: WEBAPP_BUILD,
    clientMasteringNumber: WEBAPP_BUILD,
    clientId: session.clientId,
  });
  const res = await fetch(`${SETUP_ENDPOINT}?${qs}`, {
    method: "POST",
    headers: DEFAULT_HEADERS,
    body: JSON.stringify({
      dsWebAuthToken: session.sessionToken,
      trustToken: session.trustToken ?? "",
      extended_login: true,
    }),
  });
  if (!res.ok)
    throw new ICloudError(`iCloud accountLogin failed (${res.status}).`);
  setCookiesFrom(res);
  const data = (await res.json()) as {
    webservices?: Session["webservices"];
    dsInfo?: { dsid?: string };
  };
  if (!data.webservices?.premiummailsettings?.url) {
    throw new ICloudError(
      "Signed in, but this account has no Hide My Email service (an active iCloud+ subscription is required).",
    );
  }
  session.webservices = data.webservices;
  session.dsid = data.dsInfo?.dsid;
  // A stable pseudo client id, like the icloud.com web app's device identifier.
  if (!session.clientId) session.clientId = crypto.randomUUID();
  session.phase = "ready";
  await saveSessionCache();
}

/** Asks Apple to push a 2FA code to trusted devices (required since early 2026). */
async function triggerMfaPush(): Promise<void> {
  try {
    await fetch(`${AUTH_ENDPOINT}verify/trusteddevice/securitycode`, {
      method: "PUT",
      headers: mfaHeaders(),
    });
  } catch {
    // Non-fatal: a code may still arrive via SMS / another path.
  }
}

let signInInFlight: Promise<"ready" | "mfa"> | null = null;

/**
 * Performs SRP sign-in. Returns "ready" if trusted, or "mfa" if a code is needed.
 *
 * De-duplicates concurrent calls: Raycast/React can fire the auth effect twice
 * on mount (StrictMode), and two parallel SRP flows would clobber each other's
 * shared session secrets (scnt/aasp/sessionId) — making the first attempt fail
 * and also invalidating the 2FA push. Sharing one in-flight promise prevents that.
 */
export function signIn(): Promise<"ready" | "mfa"> {
  if (session.phase === "ready") return Promise.resolve("ready");
  if (!signInInFlight) {
    signInInFlight = doSignIn().finally(() => {
      signInInFlight = null;
    });
  }
  return signInInFlight;
}

// In prompt mode the password the user typed for this process. Never persisted.
let promptPassword: string | undefined;

/** The Apple ID password for this sign-in. In stored mode it comes from
 *  Raycast's encrypted preferences; in prompt mode from the in-memory value
 *  captured by signInWithPassword — otherwise PasswordRequiredError is thrown
 *  so the UI can ask for it. */
function getPassword(): string {
  if (PROMPT_MODE) {
    if (!promptPassword)
      throw new PasswordRequiredError(
        "Enter your Apple ID password to continue. It is used only in memory and never stored.",
      );
    return promptPassword;
  }
  if (!prefs.password) {
    throw new InvalidCredentialsError(
      "Add your Apple ID and password in the extension preferences, or set Password Storage to “Prompt on use”.",
    );
  }
  return prefs.password;
}

/** As signIn(), but supplies the password for prompt mode. The password is
 *  kept in memory for the lifetime of this command run only (it is needed
 *  again if the session silently expires mid-run and SRP re-authenticates). */
export function signInWithPassword(password: string): Promise<"ready" | "mfa"> {
  if (session.phase === "ready") return Promise.resolve("ready");
  if (!signInInFlight) {
    promptPassword = password;
    signInInFlight = doSignIn().finally(() => {
      signInInFlight = null;
    });
  }
  return signInInFlight;
}

async function doSignIn(): Promise<"ready" | "mfa"> {
  if (session.phase === "ready") return "ready";
  // Fast path: reuse a recent session and skip the SRP round-trips entirely.
  if (await loadSessionCache()) return "ready";
  if (!prefs.appleId) {
    throw new InvalidCredentialsError(
      "Add your Apple ID in the extension preferences.",
    );
  }
  // May throw PasswordRequiredError (prompt mode) — the UI handles that.
  const password = getPassword();

  // Register the OAuth authorize session before SRP (see authorizePrelude).
  await authorizePrelude();

  session.trustToken = (await secretGet("trust")) ?? undefined;

  const auth = new GSASRPAuthenticator(prefs.appleId);
  const init = await auth.getInit();
  const initRes = await fetch(`${AUTH_ENDPOINT}signin/init`, {
    method: "POST",
    headers: { ...AUTH_HEADERS, Cookie: authCookieHeader() },
    body: JSON.stringify(init),
  });
  if (!initRes.ok)
    throw new InvalidCredentialsError(
      `Sign-in failed to start (${initRes.status}).`,
    );
  const complete = await auth.getComplete(
    password,
    (await initRes.json()) as SrpInitResponse,
  );

  const res = await fetch(
    `${AUTH_ENDPOINT}signin/complete?isRememberMeEnabled=true`,
    {
      method: "POST",
      headers: { ...AUTH_HEADERS, Cookie: authCookieHeader() },
      body: JSON.stringify({
        ...complete,
        rememberMe: true,
        trustTokens: session.trustToken ? [session.trustToken] : [],
      }),
    },
  );

  captureSecrets(res);

  if (res.status === 200) {
    await accountLogin();
    return "ready";
  }
  if (res.status === 409) {
    session.phase = "mfa";
    await triggerMfaPush();
    return "mfa";
  }
  if (res.status === 401) {
    throw new InvalidCredentialsError("Incorrect Apple ID or password.");
  }
  throw new ICloudError(`Sign-in failed (${res.status}).`);
}

/** Submits the 6-digit 2FA code, trusts the device, and completes sign-in. */
export async function submitMfa(code: string): Promise<void> {
  const res = await fetch(`${AUTH_ENDPOINT}verify/trusteddevice/securitycode`, {
    method: "POST",
    headers: mfaHeaders(),
    body: JSON.stringify({ securityCode: { code } }),
  });
  if (res.status !== 204 && res.status !== 200) {
    throw new InvalidMfaCodeError("That code was not accepted. Try again.");
  }

  // Trust this "device" so future runs skip 2FA (~30 days).
  const trustRes = await fetch(`${AUTH_ENDPOINT}2sv/trust`, {
    headers: mfaHeaders(),
  });
  const newSession = trustRes.headers.get("x-apple-session-token");
  const newTrust = trustRes.headers.get("x-apple-twosv-trust-token");
  if (newSession) session.sessionToken = newSession;
  if (newTrust) {
    session.trustToken = newTrust;
    await secretSet("trust", newTrust);
  }

  await accountLogin();
}

/** Forgets the cached session and trust token (forces a fresh 2FA sign-in). */
export async function signOut(): Promise<void> {
  await secretDelete("trust");
  session.trustToken = undefined;
  await clearSessionCache();
}

interface RequestContext {
  baseUrl: string;
  headers: Record<string, string>;
}

/** Returns the authenticated context for premiummailsettings calls.
 *  Mirrors the webapp's request shape: text/plain content type, a wildcard
 *  Accept header, and the explicit :443 port stripped from the service URL
 *  (the default port must not appear in the URL/Host header or Apple's edge
 *  drops the session cookies). */
async function getContext(): Promise<RequestContext> {
  if (session.phase !== "ready" || !session.webservices) {
    const result = await signIn();
    if (result !== "ready") {
      throw new ICloudError("Two-factor authentication is required.");
    }
  }
  return {
    baseUrl: session.webservices!.premiummailsettings.url.replace(/:443$/, ""),
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "*/*",
      "Content-Type": "text/plain",
      Origin: ICLOUD_ORIGIN,
      Cookie: cookieHeader(),
    },
  };
}

/**
 * Fetches a premiummailsettings path with the authenticated session. If the
 * session has expired (401/421/450), clears the cache, re-authenticates once
 * (silently, via the trust token) and retries.
 */
export async function authedFetch(
  path: string,
  init: { method: "GET" | "POST"; body?: string },
): Promise<Response> {
  const doFetch = async () => {
    const ctx = await getContext();
    // Webapp-style identification query params — required by the HME service
    // (without them the server 401s with "Missing X-APPLE-WEBAUTH-TOKEN cookie"
    // even though the session is valid).
    const qs = new URLSearchParams({
      clientBuildNumber: WEBAPP_BUILD,
      clientMasteringNumber: WEBAPP_BUILD,
    });
    if (session.clientId) qs.set("clientId", session.clientId);
    if (session.dsid) qs.set("dsid", session.dsid);
    return fetch(`${ctx.baseUrl}${path}?${qs}`, {
      method: init.method,
      headers: ctx.headers,
      body: init.body,
    });
  };

  let res = await doFetch();
  if (res.status === 401 || res.status === 421 || res.status === 450) {
    await clearSessionCache();
    res = await doFetch();
  }
  return res;
}
