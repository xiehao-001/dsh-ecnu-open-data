/**
 * ECNU open-data plugin.
 *
 * Two authentication surfaces of the university platform are exposed here:
 * client credentials for institutional reads, and the SSO authorization-code
 * flow for the signed-in person's own record. Tools only ever read data.
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import {
  ClientCredentialsToken,
  EcnuError,
  TokenBucket,
  assertQueryablePath,
  buildApiUrl,
  callApi,
  isTokenRejection,
  maskSensitive,
  normalizeUserId,
  profileRoute,
  resolveConfig,
  shapeRecords,
  MAX_PHOTO_BYTES,
} from './core.js'
import { UserSession, defaultCachePath } from './auth.js'

export const name = 'ecnu-open-data'
export const inject = ['tools', 'credentials']

const CREDENTIAL_CACHE_MS = 30_000
const PHOTO_TIMEOUT_MS = 15_000

const PERSONAL_HINT = 'Sign in once with ecnu_open_login; the request then uses your own token and userId can be omitted.'
const INSTITUTIONAL_HINT = 'Needs the open-platform client id and secret in the credentials store (ECNU_OPENAPI_CLIENT_ID / ECNU_OPENAPI_CLIENT_SECRET).'

function trim(value) {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined
}

function textTool(tag, payload, extra = '') {
  return [{ type: 'text', text: `<${tag}${extra}>\n${payload}\n</${tag}>` }]
}

function jsonBlock(value) {
  return JSON.stringify(value, null, 2)
}

export function apply(ctx, rawConfig = {}) {
  const config = resolveConfig(rawConfig)
  const bucket = new TokenBucket(config.rateLimitPerMinute)
  const logger = ctx.logger?.('ecnu-open-data')

  let credentialsCache
  let clientToken
  let session

  async function secrets() {
    if (credentialsCache && credentialsCache.expiresAt > Date.now()) return credentialsCache.value
    const read = async ref => {
      try {
        const hit = await ctx.credentials.resolve(ref)
        return trim(hit?.value)
      } catch {
        return undefined
      }
    }
    const value = {
      clientId: await read(config.credentialRefs.clientId),
      clientSecret: await read(config.credentialRefs.clientSecret),
      userToken: await read(config.credentialRefs.userToken),
    }
    credentialsCache = { value, expiresAt: Date.now() + CREDENTIAL_CACHE_MS }
    return value
  }

  function userSession() {
    if (!session) {
      session = new UserSession({ config, cachePath: defaultCachePath(ctx.get?.('home') ?? process.env.DSH_HOME) })
      session.load().catch(error => logger?.warn?.(`failed to load the cached ECNU session: ${error?.message ?? error}`))
    }
    return session
  }

  async function clientAuth() {
    const secret = await secrets()
    if (!secret.clientId || !secret.clientSecret) {
      throw new EcnuError(`ECNU open platform client credentials are not configured. ${INSTITUTIONAL_HINT}`, { kind: 'auth' })
    }
    if (!clientToken || clientToken.clientId !== secret.clientId || clientToken.clientSecret !== secret.clientSecret) {
      clientToken = new ClientCredentialsToken({
        tokenURL: config.apiTokenURL,
        clientId: secret.clientId,
        clientSecret: secret.clientSecret,
        scope: config.scope,
        skewMs: config.refreshSkewMs,
      })
    }
    return clientToken.token()
  }

  async function personalAuth() {
    const state = userSession()
    const secret = await secrets()
    if (secret.clientId && secret.clientSecret) state.setCredentials({ clientId: secret.clientId, clientSecret: secret.clientSecret })
    if (!state.token && secret.userToken) {
      // A token pasted into the credentials store wins over the browser flow.
      state.token = { accessToken: secret.userToken, expiresAt: Date.now() + 60 * 60 * 1000 }
    }
    return state.ensure()
  }

  /**
   * Resolves which token a read should use: `auto` prefers the signed-in
   * person (so userId may be omitted) and falls back to client credentials.
   */
  async function auth(mode = 'auto') {
    if (mode === 'institutional') return { token: await clientAuth(), personal: false }
    if (mode === 'personal') return { token: await personalAuth(), personal: true }
    const state = userSession()
    const secret = await secrets()
    if (state.token || secret.userToken) {
      try {
        return { token: await personalAuth(), personal: true }
      } catch (error) {
        if (secret.clientId && secret.clientSecret) return { token: await clientAuth(), personal: false }
        throw error
      }
    }
    if (secret.clientId && secret.clientSecret) return { token: await clientAuth(), personal: false }
    throw new EcnuError(`No ECNU credential is available. ${INSTITUTIONAL_HINT} ${PERSONAL_HINT}`, { kind: 'auth' })
  }

  /** One gateway read with local pacing and one retry after a token rejection. */
  async function read(path, search, { signal, mode = 'auto', timeoutMs } = {}) {
    await bucket.take()
    let authState = await auth(mode)
    const url = buildApiUrl(config.apiBase, path, search)
    const run = token => callApi({
      url,
      token,
      signal,
      timeoutMs: Math.min(timeoutMs ?? config.requestTimeoutMs, 120_000),
    })
    try {
      const result = await run(authState.token)
      return { ...result, personal: authState.personal, path }
    } catch (error) {
      if (!isTokenRejection(error)) throw error
      if (clientToken) clientToken.invalidate()
      if (session?.token) await session.clear()
      credentialsCache = undefined
      // A rejected token is the documented way to learn it was rotated: re-issue once.
      authState = await auth(authState.personal ? 'personal' : mode)
      const result = await run(authState.token)
      return { ...result, personal: authState.personal, path, reissued: true }
    }
  }

  const commonOutput = properties => ({
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        ok: { type: 'boolean', required: true },
        ...properties,
      },
    },
  })

  // ---------------------------------------------------------------- auth ----

  ctx.tools.register(defineTool({
    name: 'ecnu_open_auth_status',
    description: 'Report whether the ECNU open platform is usable: client credentials configured, signed-in user, token lifetime. Read-only.',
    parameters: {},
    output: commonOutput({
      clientCredentials: { type: 'boolean', required: true },
      signedIn: { type: 'boolean', required: true },
      userId: { type: 'string' },
      name: { type: 'string' },
      expiresAt: { type: 'string' },
      expiresInSeconds: { type: 'integer' },
      refreshable: { type: 'boolean', required: true },
      credentialRefs: { type: 'string', required: true },
      apiBase: { type: 'string', required: true },
    }),
    timeoutMs: 15_000,
    async execute() {
      const secret = await secrets()
      const state = userSession()
      const status = state.status()
      return {
        ok: Boolean(secret.clientId && secret.clientSecret) || status.signedIn,
        clientCredentials: Boolean(secret.clientId && secret.clientSecret),
        signedIn: status.signedIn,
        userId: status.userId,
        name: status.name,
        expiresAt: status.expiresAt,
        expiresInSeconds: status.expiresInSeconds,
        refreshable: Boolean(status.refreshable),
        credentialRefs: `${config.credentialRefs.clientId}, ${config.credentialRefs.clientSecret}, ${config.credentialRefs.userToken}`,
        apiBase: config.apiBase,
      }
    },
    presentCall: () => ({ card: 'generic', title: '华师大开放平台状态', kind: 'read' }),
    presentResult: () => ({ card: 'generic', title: '华师大开放平台状态' }),
  }))

  ctx.tools.register(defineTool({
    name: 'ecnu_open_login',
    description: 'Start the university SSO login and return the authorize URL to open in a browser. The redirect is caught on a loopback port; poll ecnu_open_auth_status afterwards. Needed only for data about the signed-in person.',
    parameters: {
      scope: { type: 'string', description: 'OAuth2 scope; defaults to ECNU-Basic.' },
    },
    output: commonOutput({
      url: { type: 'string', required: true },
      redirectUri: { type: 'string', required: true },
      waiting: { type: 'boolean', required: true },
    }),
    timeoutMs: 15_000,
    async execute(args) {
      const secret = await secrets()
      if (!secret.clientId || !secret.clientSecret) {
        throw new EcnuError(`登录需要开放平台的 client_id 与 client_secret。${INSTITUTIONAL_HINT}`, { kind: 'auth' })
      }
      const state = userSession()
      state.setCredentials({ clientId: secret.clientId, clientSecret: secret.clientSecret })
      const { url, wait } = await state.beginLogin()
      // The browser completes the redirect later; failures surface through
      // ecnu_open_auth_status instead of an unhandled rejection here.
      wait.catch(error => logger?.warn?.(`ECNU SSO login did not complete: ${error?.message ?? error}`))
      logger?.info?.('ECNU SSO login started')
      return { ok: true, url, redirectUri: config.redirectUri, waiting: true }
    },
    presentCall: () => ({ card: 'generic', title: '打开华师大统一身份认证', kind: 'execute' }),
    presentResult: (_args, value) => value.isError ? undefined : ({ card: 'generic', title: '华师大登录授权链接' }),
  }))

  ctx.tools.register(defineTool({
    name: 'ecnu_open_logout',
    description: 'Forget the signed-in university account on this machine and stop the loopback login listener. Client credentials are untouched.',
    parameters: {},
    output: commonOutput({ signedOut: { type: 'boolean', required: true } }),
    timeoutMs: 15_000,
    async execute() {
      const state = userSession()
      await state.clear()
      await state.close()
      return { ok: true, signedOut: true }
    },
    presentCall: () => ({ card: 'generic', title: '退出华师大账号', kind: 'execute' }),
    presentResult: () => ({ card: 'generic', title: '已退出华师大账号' }),
  }))

  // ---------------------------------------------------------------- reads ----

  ctx.tools.register(defineTool({
    name: 'ecnu_open_user_info',
    description: 'Look up one person in the ECNU personnel directory: name, identity type, department and active status. Reads /user/info. Personal data; returns masked identifiers only.',
    parameters: {
      userId: { type: 'string', description: 'School work number (学工号). Omit for the signed-in person when a personal token is available.' },
      mode: { type: 'string', description: 'auto | personal | institutional; defaults to auto.' },
    },
    output: commonOutput({
      recordsJSON: { type: 'string', required: true },
      count: { type: 'integer', required: true },
      personal: { type: 'boolean', required: true },
      requestId: { type: 'string' },
    }),
    timeoutMs: 30_000,
    async execute(args, exec) {
      const authState = await auth(args.mode ?? 'auto')
      const userId = authState.personal ? trim(args.userId) : normalizeUserId(args.userId)
      const result = await read('/user/info', userId ? { userId } : {}, { signal: exec.signal, mode: authState.personal ? 'personal' : 'institutional' })
      const shaped = shapeRecords(result.data, { limit: config.recordLimit })
      return {
        ok: true,
        recordsJSON: jsonBlock(shaped.records),
        count: shaped.total,
        personal: result.personal,
        requestId: result.requestId,
      }
    },
    presentCall: args => ({ card: 'generic', title: `华东师大人员 · ${args.userId ?? '本人'}`, kind: 'read' }),
    presentResult: () => ({ card: 'generic', title: '人员基本信息' }),
  }))

  ctx.tools.register(defineTool({
    name: 'ecnu_open_user_profile',
    description: 'Read a full student or staff profile from the ECNU directory: department, major, class, supervisor, title, post and hire dates. Reads /user/profile/{student|staff|bks|yjs}. Personal data; stays local to this conversation.',
    parameters: {
      kind: { type: 'string', required: true, description: 'student | staff | bks | yjs.' },
      userId: { type: 'string', description: 'School work number. Omit for the signed-in person when a personal token is available.' },
      fields: { type: 'string', description: 'Comma-separated field names to keep, e.g. xm,departmentName,zymc. Omit for all fields.' },
      mode: { type: 'string', description: 'auto | personal | institutional; defaults to auto.' },
    },
    output: commonOutput({
      kind: { type: 'string', required: true },
      recordsJSON: { type: 'string', required: true },
      count: { type: 'integer', required: true },
      personal: { type: 'boolean', required: true },
      requestId: { type: 'string' },
    }),
    timeoutMs: 30_000,
    async execute(args, exec) {
      const path = profileRoute(args.kind)
      const authState = await auth(args.mode ?? 'auto')
      const userId = authState.personal ? trim(args.userId) : normalizeUserId(args.userId)
      const fields = trim(args.fields)?.split(',').map(item => item.trim()).filter(Boolean)
      const result = await read(path, userId ? { userId } : {}, { signal: exec.signal, mode: authState.personal ? 'personal' : 'institutional' })
      const shaped = shapeRecords(result.data, { fields, limit: config.recordLimit })
      return {
        ok: true,
        kind: args.kind,
        recordsJSON: jsonBlock(shaped.records),
        count: shaped.total,
        personal: result.personal,
        requestId: result.requestId,
      }
    },
    presentCall: args => ({ card: 'generic', title: `华东师大档案 · ${args.kind}`, kind: 'read' }),
    presentResult: () => ({ card: 'generic', title: '人员档案' }),
  }))

  ctx.tools.register(defineTool({
    name: 'ecnu_open_positions',
    description: 'Read identity-governance positions: either the positions held by one person, or everyone holding one position code. Reads /user/position and /user/positionusers.',
    parameters: {
      userId: { type: 'string', description: 'School work number, for the person-to-position direction.' },
      positionCode: { type: 'string', description: 'Position code, for the position-to-people direction.' },
      mode: { type: 'string', description: 'auto | personal | institutional; defaults to auto.' },
    },
    output: commonOutput({
      recordsJSON: { type: 'string', required: true },
      count: { type: 'integer', required: true },
      requestId: { type: 'string' },
    }),
    timeoutMs: 30_000,
    async execute(args, exec) {
      const positionCode = trim(args.positionCode)
      const userId = trim(args.userId)
      if (!positionCode && !userId) throw new Error('Provide userId or positionCode')
      const path = positionCode ? '/user/positionusers' : '/user/position'
      const query = positionCode ? { positionCode } : { userId }
      const result = await read(path, query, { signal: exec.signal, mode: args.mode ?? 'auto' })
      const shaped = shapeRecords(result.data, { limit: config.recordLimit })
      return { ok: true, recordsJSON: jsonBlock(shaped.records), count: shaped.total, requestId: result.requestId }
    },
    presentCall: args => ({ card: 'generic', title: `华东师大岗位 · ${args.positionCode ?? args.userId ?? ''}`, kind: 'read' }),
    presentResult: () => ({ card: 'generic', title: '岗位信息' }),
  }))

  ctx.tools.register(defineTool({
    name: 'ecnu_open_user_photo',
    description: 'Fetch the portrait photo of one person as a base64 image. Reads /user/photo. Only useful when the answer needs the image itself; photos stay in this conversation.',
    parameters: {
      userId: { type: 'string', description: 'School work number. Omit for the signed-in person when a personal token is available.' },
      mode: { type: 'string', description: 'auto | personal | institutional; defaults to auto.' },
    },
    output: commonOutput({
      mediaType: { type: 'string', required: true },
      bytes: { type: 'integer', required: true },
      dataURL: { type: 'string', required: true },
    }),
    timeoutMs: 30_000,
    async execute(args, exec) {
      const authState = await auth(args.mode ?? 'auto')
      const userId = authState.personal ? trim(args.userId) : normalizeUserId(args.userId)
      const url = buildApiUrl(config.apiBase, '/user/photo', userId ? { userId } : {})
      const response = await fetch(url, {
        headers: { authorization: `Bearer ${authState.token}`, accept: 'image/jpeg,image/png' },
        signal: exec.signal ? AbortSignal.any([exec.signal, AbortSignal.timeout(PHOTO_TIMEOUT_MS)]) : AbortSignal.timeout(PHOTO_TIMEOUT_MS),
        redirect: 'error',
      }).catch(error => { throw new EcnuError(`照片请求失败：${error?.message ?? error}`, { kind: 'network' }) })
      if (!response.ok) {
        throw new EcnuError(`照片接口返回 ${response.status}${response.headers.get('x-ca-error-code') ? ` (${response.headers.get('x-ca-error-code')})` : ''}`, { kind: 'api', status: response.status })
      }
      const buffer = Buffer.from(await response.arrayBuffer())
      if (buffer.byteLength > MAX_PHOTO_BYTES) throw new Error('照片超过插件允许的大小')
      const mediaType = response.headers.get('content-type')?.split(';')[0] ?? 'image/jpeg'
      return {
        ok: true,
        mediaType,
        bytes: buffer.byteLength,
        dataURL: `data:${mediaType};base64,${buffer.toString('base64')}`,
      }
    },
    presentCall: args => ({ card: 'generic', title: `华东师大照片 · ${args.userId ?? '本人'}`, kind: 'read' }),
    presentResult: () => ({ card: 'generic', title: '人员照片' }),
  }))

  if (config.allowGenericQuery) {
    ctx.tools.register(defineTool({
      name: 'ecnu_open_query',
      description: 'Read any allowlisted ECNU open-data path (for example /student/course, /edu/calendar, /org/tree). Use it when a specific directory, teaching or campus-card read is needed and no dedicated tool covers it. Sensitive, facial-recognition, verification, message-sending and sync endpoints are refused by design.',
      parameters: {
        path: { type: 'string', required: true, description: 'API path after /api/v1, such as /student/course.' },
        query: { type: 'string', description: 'Query string, for example "term=2025-2026-1&page=1".' },
        mode: { type: 'string', description: 'auto | personal | institutional; defaults to auto.' },
      },
      output: commonOutput({
        path: { type: 'string', required: true },
        recordsJSON: { type: 'string', required: true },
        count: { type: 'integer', required: true },
        truncated: { type: 'boolean', required: true },
        personal: { type: 'boolean', required: true },
        requestId: { type: 'string' },
      }),
      timeoutMs: 30_000,
      async execute(args, exec) {
        const path = assertQueryablePath(args.path)
        const search = {}
        const raw = trim(args.query)
        if (raw) {
          for (const [key, value] of new URLSearchParams(raw)) search[key] = value
        }
        const result = await read(path, search, { signal: exec.signal, mode: args.mode ?? 'auto' })
        const shaped = shapeRecords(result.data, { limit: config.recordLimit })
        return {
          ok: true,
          path,
          recordsJSON: jsonBlock(shaped.records),
          count: shaped.total,
          truncated: shaped.truncated,
          personal: result.personal,
          requestId: result.requestId,
        }
      },
      presentCall: args => ({ card: 'generic', title: `华东师大开放数据 · ${args.path ?? ''}`, kind: 'read' }),
      presentResult: () => ({ card: 'generic', title: '开放数据查询结果' }),
    }))
  }

  ctx.effect(() => () => { userSession().close().catch(() => {}) }, 'ecnu open data session')
}

export { resolveConfig, maskSensitive }
