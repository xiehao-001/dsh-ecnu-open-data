/**
 * Signed-in-user support for the ECNU open-data plugin.
 *
 * The platform has two OAuth2 surfaces: client credentials for institutional
 * reads (handled in core.js) and the SSO authorization-code flow for data that
 * belongs to one person. This module owns the second one: a loopback receiver
 * that catches the redirect, the token exchange, refresh, and an optional
 * on-disk cache under the DSH home directory.
 */

import { createServer } from 'node:http'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import {
  EcnuError,
  authorizationUrl,
  exchangeAuthorizationCode,
  fetchProfile,
  DEFAULT_SCOPE,
} from './core.js'

const STATE_TTL_MS = 10 * 60 * 1000
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000

function randomState() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('')
}

function escapeHtml(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')
}

function page(title, body) {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>body{font:16px/1.6 system-ui,-apple-system,"Segoe UI","PingFang SC",sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7f4;color:#1b1b19}
main{max-width:32rem;padding:2.5rem;background:#fdfdfb;border:1px solid #dedcd4;border-radius:12px}
h1{font-size:1.25rem;margin:0 0 .75rem}p{margin:0 0 .5rem}p:last-child{margin:0}</style>
<main><h1>${escapeHtml(title)}</h1>${body}</main></html>`
}

/**
 * Serves the OAuth2 redirect on a loopback address. Only one authorization
 * attempt may be pending at a time, which is enough for an interactive login.
 */
export class LoopbackReceiver {
  constructor({ redirectPort, redirectPath, onCode }) {
    this.redirectPort = redirectPort
    this.redirectPath = redirectPath
    this.onCode = onCode
    this.server = undefined
    this.pending = undefined
    this.listening = undefined
  }

  async start() {
    if (this.listening) return
    if (this.pending) throw new Error('已有一次登录正在进行，请先在浏览器完成或等待超时')
    this.listening = new Promise((resolve, reject) => {
      this.server = createServer((request, response) => {
        this.handle(request, response).catch(error => {
          response.writeHead(500, { 'content-type': 'text/html; charset=utf-8' })
          response.end(page('登录失败', `<p>${escapeHtml(error?.message ?? String(error))}</p><p>可以关闭本页，回到 DSH 重试。</p>`))
        })
      })
      this.server.once('error', error => {
        this.listening = undefined
        reject(new Error(`无法在 127.0.0.1:${this.redirectPort} 启动登录回调：${error.message}`))
      })
      this.server.listen(this.redirectPort, '127.0.0.1', () => resolve())
    })
    await this.listening
  }

  async stop() {
    if (!this.server) return
    const server = this.server
    this.server = undefined
    this.listening = undefined
    this.pending = undefined
    await new Promise(resolve => server.close(() => resolve()))
  }

  async handle(request, response) {
    const url = new URL(request.url ?? '/', `http://127.0.0.1:${this.redirectPort}`)
    if (url.pathname !== this.redirectPath) {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('not found')
      return
    }
    const pending = this.pending
    if (!pending) {
      response.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
      response.end(page('没有待处理的登录', '<p>这次回调已经使用过，或登录已经超时。请回到 DSH 重新发起登录。</p>'))
      return
    }
    const state = url.searchParams.get('state') ?? ''
    if (state !== pending.state) {
      response.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
      response.end(page('登录校验失败', '<p>state 不匹配，已忽略这次回调。请回到 DSH 重新发起登录。</p>'))
      return
    }
    const code = url.searchParams.get('code')
    const error = url.searchParams.get('error')
    if (error) {
      this.pending = undefined
      response.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
      response.end(page('登录被取消', `<p>${escapeHtml(error)}</p>`))
      pending.reject(new Error(`登录被取消：${error}`))
      return
    }
    if (!code) {
      response.writeHead(400, { 'content-type': 'text/html; charset=utf-8' })
      response.end(page('缺少授权码', '<p>回调里没有 code 参数，请重新发起登录。</p>'))
      return
    }
    this.pending = undefined
    try {
      const result = await this.onCode(code)
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      response.end(page('登录成功', `<p>已登录${result?.name ? `：${escapeHtml(result.name)}` : ''}${result?.userId ? `（${escapeHtml(result.userId)}）` : ''}。</p><p>可以关闭本页，回到 DSH。</p>`))
      pending.resolve(result)
    } catch (failure) {
      response.writeHead(500, { 'content-type': 'text/html; charset=utf-8' })
      response.end(page('登录失败', `<p>${escapeHtml(failure?.message ?? String(failure))}</p>`))
      pending.reject(failure)
    }
  }

  /** Resolves once the browser hits the callback, or rejects on timeout. */
  waitForCode() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = undefined
        reject(new Error('登录等待超时（5 分钟），请重新发起登录'))
      }, CALLBACK_TIMEOUT_MS)
      this.pending = {
        state: this.state,
        resolve: value => { clearTimeout(timer); resolve(value) },
        reject: error => { clearTimeout(timer); reject(error) },
      }
    })
  }

  begin() {
    this.state = randomState()
    return this.state
  }
}

/**
 * Holds the signed-in user's token, refreshes it shortly before expiry, and
 * optionally mirrors it to disk so a restart does not force another login.
 */
export class UserSession {
  constructor({ config, cachePath, fetchImpl = globalThis.fetch, now = () => Date.now() }) {
    this.config = config
    this.cachePath = cachePath
    this.fetchImpl = fetchImpl
    this.now = now
    this.token = undefined
    this.profile = undefined
    this.receiver = new LoopbackReceiver({
      redirectPort: config.redirectPort,
      redirectPath: config.redirectPath,
      onCode: code => this.completeLogin(code),
    })
  }

  async load() {
    if (!this.cachePath) return
    try {
      const raw = JSON.parse(await readFile(this.cachePath, 'utf8'))
      if (raw && typeof raw.accessToken === 'string' && typeof raw.expiresAt === 'number') {
        this.token = { accessToken: raw.accessToken, refreshToken: raw.refreshToken, expiresAt: raw.expiresAt }
        if (raw.profile) this.profile = raw.profile
      }
    } catch { /* no cache yet */ }
  }

  async persist() {
    if (!this.cachePath || !this.token) return
    await mkdir(dirname(this.cachePath), { recursive: true, mode: 0o700 })
    await writeFile(this.cachePath, JSON.stringify({ ...this.token, profile: this.profile }, null, 2), { mode: 0o600 })
  }

  async clear() {
    this.token = undefined
    this.profile = undefined
    if (this.cachePath) await rm(this.cachePath, { force: true })
  }

  status() {
    const now = this.now()
    return {
      signedIn: Boolean(this.token && this.token.accessToken),
      expiresAt: this.token ? new Date(this.token.expiresAt).toISOString() : undefined,
      expiresInSeconds: this.token ? Math.max(0, Math.round((this.token.expiresAt - now) / 1000)) : undefined,
      refreshable: Boolean(this.token?.refreshToken),
      userId: this.profile?.userId,
      name: this.profile?.name,
    }
  }

  /** Returns a usable user token, refreshing it when it is about to expire. */
  async ensure() {
    if (!this.token?.accessToken) {
      throw new EcnuError('还没有登录学校账号：先调用 ecnu_open_login 打开授权页，或让工具以本人身份运行', { kind: 'auth' })
    }
    if (this.token.expiresAt - 60_000 > this.now()) return this.token.accessToken
    if (!this.token.refreshToken) {
      throw new EcnuError('登录已过期且没有 refresh token，请重新调用 ecnu_open_login', { kind: 'auth' })
    }
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.clientId(),
      client_secret: this.clientSecret(),
      refresh_token: this.token.refreshToken,
    })
    const response = await this.fetchImpl(this.config.apiTokenURL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: body.toString(),
      signal: AbortSignal.timeout(20_000),
      redirect: 'error',
    })
    const payload = await response.json().catch(() => undefined)
    if (!response.ok || !payload?.access_token) {
      throw new EcnuError('刷新学校账号 token 失败，请重新登录', { kind: 'auth', status: response.status })
    }
    this.token = {
      accessToken: String(payload.access_token),
      refreshToken: payload.refresh_token ? String(payload.refresh_token) : this.token.refreshToken,
      expiresAt: this.now() + Number(payload.expires_in ?? 7200) * 1000,
    }
    await this.persist()
    return this.token.accessToken
  }

  setCredentials({ clientId, clientSecret }) {
    this.credentials = { clientId, clientSecret }
  }

  clientId() {
    if (!this.credentials?.clientId) throw new EcnuError('未配置 ECNU 开放平台 client_id', { kind: 'auth' })
    return this.credentials.clientId
  }

  clientSecret() {
    if (!this.credentials?.clientSecret) throw new EcnuError('未配置 ECNU 开放平台 client_secret', { kind: 'auth' })
    return this.credentials.clientSecret
  }

  /** Returns the authorize URL and starts waiting for the redirect. */
  async beginLogin() {
    await this.receiver.start()
    const state = this.receiver.begin()
    const url = authorizationUrl({
      sso: this.config.sso,
      clientId: this.clientId(),
      redirectUri: this.config.redirectUri,
      scope: this.config.scope ?? DEFAULT_SCOPE,
      state,
    })
    const wait = this.receiver.waitForCode()
    return { url, state, wait }
  }

  async completeLogin(code) {
    const exchanged = await exchangeAuthorizationCode({
      ssoTokenURL: this.config.sso.token,
      code,
      clientId: this.clientId(),
      clientSecret: this.clientSecret(),
      redirectUri: this.config.redirectUri,
      fetchImpl: this.fetchImpl,
    })
    this.token = {
      accessToken: exchanged.accessToken,
      refreshToken: exchanged.refreshToken,
      expiresAt: this.now() + exchanged.expiresIn * 1000,
    }
    try {
      this.profile = await fetchProfile({ ssoProfileURL: this.config.sso.profile, accessToken: exchanged.accessToken, fetchImpl: this.fetchImpl })
    } catch {
      this.profile = undefined
    }
    await this.persist()
    return this.profile
  }

  async close() {
    await this.receiver.stop()
  }
}

/** Default on-disk location, kept beside other DSH runtime state. */
export function defaultCachePath(homeDirectory) {
  const home = homeDirectory ?? process.env.DSH_HOME ?? ''
  return home ? join(home, 'ecnu-open-data', 'user-token.json') : undefined
}
