/**
 * Core for the ECNU open-data plugin: config resolution, OAuth2 token
 * management, gateway error mapping and a small token bucket.
 *
 * Everything here is transport-neutral: no Cordis, no DSH types. That keeps
 * the behaviour testable against a local mock server.
 */

export const DEFAULT_API_BASE = 'https://api.ecnu.edu.cn'
export const API_PREFIX = '/api/v1'
export const DEFAULT_SCOPE = 'ECNU-Basic'
export const DEFAULT_REQUEST_TIMEOUT_MS = 20_000
export const DEFAULT_REFRESH_SKEW_MS = 5 * 60 * 1000
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 240
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024
export const MAX_RECORDS = 200
export const MAX_PHOTO_BYTES = 512 * 1024

export const SSO_ENDPOINTS = Object.freeze({
  authorize: 'https://sso.ecnu.edu.cn/oauth2.0/authorize',
  token: 'https://sso.ecnu.edu.cn/oauth2.0/accessToken',
  profile: 'https://sso.ecnu.edu.cn/oauth2.0/profile',
  logout: 'https://sso.ecnu.edu.cn/logout',
})

export const API_TOKEN_URL = 'https://api.ecnu.edu.cn/oauth2/token'

export const DEFAULT_CREDENTIAL_REFS = Object.freeze({
  clientId: 'ECNU_OPENAPI_CLIENT_ID',
  clientSecret: 'ECNU_OPENAPI_CLIENT_SECRET',
  userToken: 'ECNU_OPENAPI_USER_TOKEN',
})

/** Gateway rejects a token with this header code; the caller must re-issue. */
export const TOKEN_REJECTED_CODE = 'A401OT'

/** Endpoints below are the only ones the generic query tool may reach. */
export const QUERYABLE_PREFIXES = Object.freeze([
  '/user/',
  '/student/',
  '/staff/',
  '/edu/',
  '/org/',
  '/ecard/',
  '/research/',
  '/asset/',
  '/device/',
  '/finance/',
  '/network/',
  '/mail/',
  '/message/',
])

/** Sensitive paths are never reachable through the generic tool. */
export const BLOCKED_PREFIXES = Object.freeze([
  '/user/sensitive/',
  '/face/',
  '/verify/',
  '/sync/',
  '/app/',
  '/info/',
])

const PROFILE_ROUTES = Object.freeze({
  student: '/user/profile/student',
  staff: '/user/profile/staff',
  bks: '/user/profile/bks',
  yjs: '/user/profile/yjs',
})

function text(value, field, maximum) {
  if (typeof value !== 'string') throw new Error(`${field} must be a string`)
  const normalized = value.trim()
  if (normalized.length === 0) throw new Error(`${field} must not be empty`)
  if (Array.from(normalized).length > maximum) throw new Error(`${field} is longer than ${maximum} characters`)
  return normalized
}

function integer(value, fallback, field, minimum, maximum) {
  const normalized = value ?? fallback
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw new Error(`${field} must be an integer between ${minimum} and ${maximum}`)
  }
  return normalized
}

function origin(value, field) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`${field} must be an absolute URL`)
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new Error(`${field} must use HTTP or HTTPS`)
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${field} must not contain credentials, query or fragment`)
  }
  return parsed.origin
}

/**
 * Resolves the row config. An environment variable may override the value of
 * any key that supports it, so deployments can inject secrets without editing
 * the profile.
 */
export function resolveConfig(raw = {}, environment = process.env) {
  const apiBase = origin(
    String(raw.apiBaseURL ?? environment.ECNU_OPENAPI_BASE_URL ?? DEFAULT_API_BASE).trim().replace(/\/+$/, ''),
    'apiBaseURL',
  )
  const credentialRefs = {
    clientId: text(raw.clientIdRef ?? DEFAULT_CREDENTIAL_REFS.clientId, 'clientIdRef', 128),
    clientSecret: text(raw.clientSecretRef ?? DEFAULT_CREDENTIAL_REFS.clientSecret, 'clientSecretRef', 128),
    userToken: text(raw.userTokenRef ?? DEFAULT_CREDENTIAL_REFS.userToken, 'userTokenRef', 128),
  }
  const ssoBase = origin(
    String(raw.ssoBaseURL ?? environment.ECNU_OPENAPI_SSO_URL ?? 'https://sso.ecnu.edu.cn').trim().replace(/\/+$/, ''),
    'ssoBaseURL',
  )
  const sso = Object.freeze({
    authorize: `${ssoBase}/oauth2.0/authorize`,
    token: `${ssoBase}/oauth2.0/accessToken`,
    profile: `${ssoBase}/oauth2.0/profile`,
    logout: `${ssoBase}/logout`,
  })
  const redirectUri = String(raw.redirectUri ?? 'http://127.0.0.1:47823/oauth2/callback').trim()
  let redirect
  try {
    redirect = new URL(redirectUri)
  } catch {
    throw new Error('redirectUri must be an absolute URL')
  }
  if (redirect.protocol !== 'http:' || redirect.hostname !== '127.0.0.1') {
    throw new Error('redirectUri must be a loopback HTTP URL, for example http://127.0.0.1:47823/oauth2/callback')
  }
  if (raw.scope !== undefined && typeof raw.scope !== 'string') throw new Error('scope must be a string')
  return Object.freeze({
    apiBase,
    apiTokenURL: `${apiBase}/oauth2/token`,
    sso,
    scope: text(raw.scope ?? DEFAULT_SCOPE, 'scope', 128),
    redirectUri: redirect.href,
    redirectPort: Number(redirect.port || 80),
    redirectPath: redirect.pathname,
    credentialRefs: Object.freeze(credentialRefs),
    requestTimeoutMs: integer(raw.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS, 'requestTimeoutMs', 1_000, 120_000),
    refreshSkewMs: integer(raw.refreshSkewMs, DEFAULT_REFRESH_SKEW_MS, 'refreshSkewMs', 0, 60 * 60 * 1000),
    rateLimitPerMinute: integer(raw.rateLimitPerMinute, DEFAULT_RATE_LIMIT_PER_MINUTE, 'rateLimitPerMinute', 1, 300),
    allowGenericQuery: raw.allowGenericQuery !== false,
    recordLimit: integer(raw.recordLimit, MAX_RECORDS, 'recordLimit', 1, MAX_RECORDS),
  })
}

/** A plain token bucket; one bucket per plugin instance is enough for a gateway limit. */
export class TokenBucket {
  constructor(perMinute, now = () => Date.now()) {
    this.capacity = Math.max(1, perMinute)
    this.tokens = this.capacity
    this.refillPerMs = this.capacity / 60_000
    this.updatedAt = now()
    this.now = now
  }

  /** Waits, at most `maxWaitMs`, until a token is available. */
  async take(maxWaitMs = 5_000) {
    const deadline = this.now() + maxWaitMs
    for (;;) {
      const now = this.now()
      this.tokens = Math.min(this.capacity, this.tokens + (now - this.updatedAt) * this.refillPerMs)
      this.updatedAt = now
      if (this.tokens >= 1) {
        this.tokens -= 1
        return
      }
      const waitMs = Math.ceil((1 - this.tokens) / this.refillPerMs)
      if (now + waitMs > deadline) throw new Error('ECNU gateway rate limit reached locally; retry in a moment')
      await new Promise(resolve => setTimeout(resolve, waitMs))
    }
  }
}

/** Thrown when the platform answers with a business or gateway error. */
export class EcnuError extends Error {
  constructor(message, { code, requestId, status, kind } = {}) {
    super(message)
    this.name = 'EcnuError'
    this.code = code
    this.requestId = requestId
    this.status = status
    this.kind = kind ?? 'api'
  }
}

export function isTokenRejection(error) {
  return error instanceof EcnuError && (error.code === TOKEN_REJECTED_CODE || error.status === 401)
}

function envelopeMessage(payload, headers) {
  const headerCode = headers?.get?.('x-ca-error-code') ?? undefined
  const headerMessage = headers?.get?.('x-ca-error-message') ?? undefined
  const headerRequestId = headers?.get?.('x-ca-request-id') ?? undefined
  if (headerCode || headerMessage) {
    return { code: headerCode, message: headerMessage ?? 'API gateway rejected the request', requestId: headerRequestId, fromGateway: true }
  }
  if (payload && typeof payload === 'object') {
    const code = payload.errCode
    if (Number.isFinite(code) && code !== 0) {
      return { code: String(code), message: String(payload.errMsg ?? 'request failed'), requestId: payload.requestId, fromGateway: false }
    }
  }
  return undefined
}

function truncateRecords(records, limit) {
  return Array.isArray(records) ? records.slice(0, limit) : records
}

/**
 * One HTTP call against the open-data gateway. Returns the `data` member of a
 * successful envelope and throws `EcnuError` for gateway and business errors.
 */
export async function callApi({
  url,
  token,
  signal,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  headers = {},
}) {
  if (!token) throw new EcnuError('No access token. Sign in or configure the client credentials first.', { kind: 'auth' })
  const abort = signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs)
  let response
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${token}`, ...headers },
      signal: abort,
      redirect: 'error',
    })
  } catch (error) {
    if (error?.name === 'TimeoutError' || abort.aborted) throw new EcnuError('ECNU open API request timed out', { kind: 'network' })
    throw new EcnuError(`ECNU open API request failed: ${error?.message ?? error}`, { kind: 'network' })
  }
  const declared = Number(response.headers.get('content-length') ?? 0)
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new EcnuError('ECNU open API response is larger than the plugin allows', { kind: 'response', status: response.status })
  }
  const buffer = Buffer.from(await response.arrayBuffer())
  if (buffer.byteLength > MAX_RESPONSE_BYTES) {
    throw new EcnuError('ECNU open API response is larger than the plugin allows', { kind: 'response', status: response.status })
  }
  const body = buffer.toString('utf8')
  let payload
  try {
    payload = body.length === 0 ? undefined : JSON.parse(body)
  } catch {
    payload = undefined
  }
  const problem = envelopeMessage(payload, response.headers)
  if (!response.ok || problem) {
    const code = problem?.code ?? String(response.status)
    const requestId = problem?.requestId
    const message = problem?.message ?? response.statusText ?? 'request failed'
    throw new EcnuError(`ECNU open API ${problem?.fromGateway ? 'gateway' : 'service'} error ${code}: ${message}`, {
      code,
      requestId,
      status: response.status,
      kind: code === TOKEN_REJECTED_CODE ? 'auth' : 'api',
    })
  }
  if (payload === undefined) throw new EcnuError('ECNU open API returned a non-JSON body', { kind: 'response', status: response.status })
  return { data: payload.data ?? payload, requestId: payload.requestId }
}

export function buildApiUrl(apiBase, path, search = {}) {
  const normalized = String(path ?? '').trim()
  if (!normalized.startsWith('/')) throw new Error('path must start with /')
  const url = new URL(apiBase + API_PREFIX + normalized)
  for (const [key, value] of Object.entries(search)) {
    if (value === undefined || value === null || value === '') continue
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') continue
    url.searchParams.set(key, String(value))
  }
  return url.toString()
}

export function assertQueryablePath(path) {
  const normalized = String(path ?? '').trim()
  if (!normalized.startsWith('/') || normalized.includes('..') || normalized.includes('//')) {
    throw new Error('path must be a single absolute API path such as /user/info')
  }
  if (BLOCKED_PREFIXES.some(prefix => normalized.startsWith(prefix))) {
    throw new Error(`path ${normalized} is sensitive and is not available through the generic query tool`)
  }
  if (!QUERYABLE_PREFIXES.some(prefix => normalized.startsWith(prefix))) {
    throw new Error(`path ${normalized} is outside the allowlist`)
  }
  return normalized
}

export function profileRoute(kind) {
  const route = PROFILE_ROUTES[kind]
  if (!route) throw new Error(`kind must be one of ${Object.keys(PROFILE_ROUTES).join(', ')}`)
  return route
}

export function normalizeUserId(value, { optional = false } = {}) {
  if (value === undefined || value === null || value === '') {
    if (optional) return undefined
    throw new Error('userId is required; it is the school work number (学工号)')
  }
  return text(value, 'userId', 32)
}

export function maskSensitive(value) {
  const source = String(value ?? '')
  if (source.length <= 6) return source.length === 0 ? '' : '*'.repeat(source.length)
  return `${source.slice(0, 3)}${'*'.repeat(Math.max(3, source.length - 5))}${source.slice(-2)}`
}

/**
 * Keeps only the fields a caller asked for and always masks the identifier
 * card number, which the platform treats as personal sensitive data.
 */
export function shapeRecords(records, { fields, limit = MAX_RECORDS } = {}) {
  const rows = Array.isArray(records) ? records : records === undefined ? [] : [records]
  const picked = fields && fields.length > 0
    ? rows.map(row => {
        const out = {}
        for (const field of fields) if (row && Object.hasOwn(row, field)) out[field] = row[field]
        return out
      })
    : rows
  const masked = picked.map(row => {
    if (!row || typeof row !== 'object') return row
    if (typeof row.zjhm === 'string') return { ...row, zjhm: maskSensitive(row.zjhm) }
    return row
  })
  return { records: truncateRecords(masked, limit), total: rows.length, truncated: rows.length > limit }
}

/**
 * Client-credentials token cache. The platform allows several concurrent
 * client tokens and rate-limits the token endpoint, so one cached token is
 * shared per plugin instance and refreshed shortly before expiry.
 */
export class ClientCredentialsToken {
  constructor({ tokenURL, clientId, clientSecret, scope = DEFAULT_SCOPE, skewMs = DEFAULT_REFRESH_SKEW_MS, fetchImpl = globalThis.fetch, now = () => Date.now() }) {
    this.tokenURL = tokenURL
    this.clientId = clientId
    this.clientSecret = clientSecret
    this.scope = scope
    this.skewMs = skewMs
    this.fetchImpl = fetchImpl
    this.now = now
    this.cached = undefined
    this.pending = undefined
  }

  invalidate() {
    this.cached = undefined
  }

  async token() {
    if (this.cached && this.cached.expiresAt - this.skewMs > this.now()) return this.cached.value
    if (!this.pending) this.pending = this.issue().finally(() => { this.pending = undefined })
    return this.pending
  }

  async issue() {
    if (!this.clientId || !this.clientSecret) {
      throw new EcnuError('ECNU open platform client credentials are not configured', { kind: 'auth' })
    }
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: this.scope,
    })
    const response = await this.fetchImpl(this.tokenURL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: body.toString(),
      signal: AbortSignal.timeout(DEFAULT_REQUEST_TIMEOUT_MS),
      redirect: 'error',
    })
    const textBody = await response.text()
    let payload
    try {
      payload = JSON.parse(textBody)
    } catch {
      throw new EcnuError('ECNU token endpoint returned a non-JSON body', { kind: 'auth', status: response.status })
    }
    const code = response.headers.get('x-ca-error-code') ?? undefined
    if (!response.ok || !payload?.access_token) {
      throw new EcnuError(
        `ECNU token endpoint refused the client credentials${code ? ` (${code})` : ''}: ${String(payload?.error_description ?? payload?.error ?? payload?.errMsg ?? response.statusText)}`,
        { kind: 'auth', status: response.status, code },
      )
    }
    const expiresIn = Number(payload.expires_in ?? 7200)
    const value = String(payload.access_token)
    this.cached = { value, expiresAt: this.now() + (Number.isFinite(expiresIn) ? expiresIn : 7200) * 1000 }
    return value
  }
}

/** Builds the authorization-code URL for the signed-in-user mode. */
export function authorizationUrl({ sso, clientId, redirectUri, scope, state }) {
  const url = new URL(sso.authorize)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('scope', scope)
  url.searchParams.set('state', state)
  return url.toString()
}

/** Exchanges a short-lived authorization code for a user token. */
export async function exchangeAuthorizationCode({
  ssoTokenURL,
  code,
  clientId,
  clientSecret,
  redirectUri,
  fetchImpl = globalThis.fetch,
}) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    code,
  })
  const response = await fetchImpl(ssoTokenURL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: body.toString(),
    signal: AbortSignal.timeout(DEFAULT_REQUEST_TIMEOUT_MS),
    redirect: 'error',
  })
  const payload = await response.json().catch(() => undefined)
  if (!response.ok || !payload?.access_token) {
    throw new EcnuError(`ECNU SSO refused the authorization code: ${String(payload?.error_description ?? payload?.error ?? response.statusText)}`, {
      kind: 'auth',
      status: response.status,
    })
  }
  return {
    accessToken: String(payload.access_token),
    refreshToken: payload.refresh_token ? String(payload.refresh_token) : undefined,
    expiresIn: Number(payload.expires_in ?? 7200),
    scope: payload.scope ? String(payload.scope) : undefined,
  }
}

/** Fetches the SSO profile of the signed-in user (id, name, identity codes). */
export async function fetchProfile({ ssoProfileURL, accessToken, fetchImpl = globalThis.fetch }) {
  const response = await fetchImpl(ssoProfileURL, {
    headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(DEFAULT_REQUEST_TIMEOUT_MS),
    redirect: 'error',
  })
  const payload = await response.json().catch(() => undefined)
  if (!response.ok || !payload) throw new EcnuError('ECNU SSO profile request failed', { kind: 'auth', status: response.status })
  const identity = payload.parentIdentityInfo ?? {}
  return {
    userId: String(payload.id ?? ''),
    active: payload.active !== false,
    name: identity.name ? String(identity.name) : undefined,
    identityCode: identity.code ? String(identity.code) : undefined,
    departmentCode: payload.attributes?.BMBM ? String(payload.attributes.BMBM) : undefined,
    departmentName: payload.attributes?.BMMC ? String(payload.attributes.BMMC) : undefined,
    loginName: payload.attributes?.XGH ? String(payload.attributes.XGH) : undefined,
    displayName: payload.attributes?.XM ? String(payload.attributes.XM) : undefined,
    sessionIndex: payload.attributes?.tgt ? String(payload.attributes.tgt) : undefined,
  }
}
