import http from 'node:http'
import { readFileSync } from 'node:fs'
import { config as cfg } from './config.mjs'
import { createHmac, timingSafeEqual } from 'node:crypto'

const G = cfg.guard
const PORT = G.port
const UPSTREAM_HOST = G.upstream.host
const UPSTREAM_PORT = G.upstream.port
const AUTH_ORIGIN = G.authOrigin
const COOKIE = 'gm-sso'
// public dashboard stays public; only management surfaces need SSO
const GATED = G.gated
const SESSION_MAX_AGE = 60 * 60 * 24 * 30
const KEY = readFileSync(G.sessionKeyPath, 'utf8').trim()
const PANEL_FILE = G.panelFile
let panelCookie = null, panelAt = 0

function postJson(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body)
    const up = http.request({
      host: UPSTREAM_HOST, port: UPSTREAM_PORT, path, method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) },
    }, (r) => {
      const chunks = []
      r.on('data', (c) => chunks.push(c))
      r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body: Buffer.concat(chunks).toString('utf8') }))
    })
    up.on('error', reject)
    up.write(data)
    up.end()
  })
}

function getJson(path, cookie) {
  return new Promise((resolve, reject) => {
    const up = http.request({
      host: UPSTREAM_HOST, port: UPSTREAM_PORT, path, method: 'GET',
      headers: cookie ? { cookie } : {},
    }, (r) => {
      const chunks = []
      r.on('data', (c) => chunks.push(c))
      r.on('end', () => resolve({ status: r.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
    })
    up.on('error', reject)
    up.end()
  })
}

async function panelAlive() {
  if (!panelCookie) return false
  try {
    const r = await getJson('/api/me', panelCookie)
    return r.status === 200 && r.body.indexOf('"logged_in":true') >= 0
  } catch (e) { return false }
}

async function panelLogin() {
  if (panelCookie && Date.now() - panelAt < 1800000) return panelCookie
  let creds = null
  try { creds = JSON.parse(readFileSync(PANEL_FILE, 'utf8')) } catch (e) { return null }
  if (!creds || !creds.password) return null
  try {
    const r = await postJson('/api/login', { username: creds.username || '', password: creds.password })
    const sc = r.headers['set-cookie']
    if (sc && sc.length) {
      panelCookie = sc[0].split(';')[0]
      panelAt = Date.now()
      console.log('[guard] panel login ok')
      return panelCookie
    }
    console.log('[guard] panel login rejected', r.status, String(r.body).slice(0, 120))
  } catch (e) {
    console.log('[guard] panel login error', e.message)
  }
  return null
}

const agent = new http.Agent({ keepAlive: true, maxSockets: 64, keepAliveMsecs: 15000 })
const usedTickets = new Map()

const sign = (p) => createHmac('sha256', KEY).update(p).digest('base64url')

function mkSession() {
  const exp = Date.now() + SESSION_MAX_AGE * 1000
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url')
  return payload + '.' + sign(payload)
}

function verifySession(v) {
  if (!v) return false
  const i = v.lastIndexOf('.')
  if (i < 0) return false
  const payload = v.slice(0, i), sig = v.slice(i + 1)
  const expect = sign(payload)
  if (sig.length !== expect.length) return false
  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return false
  try {
    const d = JSON.parse(Buffer.from(payload, 'base64url').toString())
    return typeof d.exp === 'number' && d.exp > Date.now()
  } catch { return false }
}

function readTicket(t) {
  if (!t || typeof t !== 'string') return null
  const i = t.lastIndexOf('.')
  if (i < 0) return null
  const payload = t.slice(0, i), sig = t.slice(i + 1)
  const expect = sign(payload)
  if (sig.length !== expect.length) return null
  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null
  let d
  try { d = JSON.parse(Buffer.from(payload, 'base64url').toString()) } catch { return null }
  if (!d || typeof d.e !== 'number' || d.e < Date.now()) return null
  if (usedTickets.has(payload)) return null
  usedTickets.set(payload, d.e)
  return d
}

function cookiesOf(req) {
  const out = []
  const raw = req.headers.cookie
  if (!raw) return out
  for (const seg of raw.split(';')) {
    const at = seg.indexOf('=')
    if (at < 0) continue
    if (seg.slice(0, at).trim() === COOKIE) out.push(seg.slice(at + 1).trim())
  }
  return out
}

function domainFor(host) {
  const d = G.cookieDomain
  return d && d[0] === '.' ? d : '.' + host.split('.').slice(-2).join('.')
}

const authed = (req) => cookiesOf(req).some(verifySession)
const hostOf = (req) => String(req.headers.host || '').split(':')[0].toLowerCase()

// canonicalise the request path before any authorisation decision
function normPath(raw) {
  let p = String(raw || '/')
  const q = p.indexOf('?')
  if (q >= 0) p = p.slice(0, q)
  const h = p.indexOf('#')
  if (h >= 0) p = p.slice(0, h)
  p = p.split(';').join('')
  try { p = decodeURIComponent(p) } catch (e) {}
  p = p.split('\\').join('/')
  p = p.replace(/\/{2,}/g, '/')
  const segs = []
  for (const seg of p.split('/')) {
    if (seg === '..') segs.pop()
    else if (seg !== '.' && seg !== '') segs.push(seg)
  }
  return ('/' + segs.join('/')).toLowerCase()
}

const isGated = (p) => {
  const n = normPath(p)
  return GATED.some((x) => n === x || n.startsWith(x + '/'))
}

function redirect(res, location, extra) {
  const h = { location, 'cache-control': 'no-store' }
  if (extra) for (const k of Object.keys(extra)) h[k] = extra[k]
  res.writeHead(302, h)
  res.end()
}

function stripCookie(raw, name) {
  if (!raw) return ''
  return String(raw).split(';').map((x) => x.trim()).filter((x) => x && !x.startsWith(name + '=')).join('; ')
}
function applyStrippedCookie(headers) {
  const c = stripCookie(headers.cookie, G.panelCookie)
  if (c) headers.cookie = c
  else delete headers.cookie
}

function proxy(req, res, extraCookie, isAuth) {
  const headers = { ...req.headers }
  if (!isAuth) applyStrippedCookie(headers)
  if (extraCookie) {
    const name = extraCookie.split('=')[0]
    const kept = String(headers.cookie || '').split(';').map((x) => x.trim()).filter((x) => x && !x.startsWith(name + '='))
    headers.cookie = kept.concat(extraCookie).join('; ')
  }
  const up = http.request({
    host: UPSTREAM_HOST, port: UPSTREAM_PORT, path: req.url, method: req.method,
    headers, agent,
  }, (r) => {
    const out = { ...r.headers }
    delete out['transfer-encoding']
    if (extraCookie) {
      const sc = extraCookie + '; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Lax'
      out['set-cookie'] = out['set-cookie'] ? [].concat(out['set-cookie'], sc) : sc
    }
    res.writeHead(r.statusCode, out)
    r.pipe(res)
  })
  up.on('error', (e) => {
    console.log('[guard] upstream error', e.message)
    if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('bad gateway') }
    else res.end()
  })
  if (req.method === 'GET' || req.method === 'HEAD') up.end()
  else req.pipe(up)
}

const server = http.createServer(async (req, res) => {
  let url
  try { url = new URL(req.url, 'http://x') } catch { res.writeHead(400); return res.end() }
  const path = url.pathname

  if (normPath(req.url) === '/_sso') {
    const host = hostOf(req)
    const d = readTicket(url.searchParams.get('t'))
    if (!d || d.h !== host) return redirect(res, AUTH_ORIGIN + '/sso?next=' + encodeURIComponent('https://' + host + GATED[0]))
    const target = (typeof d.p === 'string' && d.p[0] === '/' && d.p[1] !== '/') ? d.p : '/'
    return redirect(res, target, { 'set-cookie': COOKIE + '=' + mkSession() + '; Path=/; Domain=' + domainFor(host) + '; HttpOnly; Secure; SameSite=Lax; Max-Age=' + SESSION_MAX_AGE })
  }

  if (normPath(req.url) === '/_sso/logout') {
    let dest = AUTH_ORIGIN + '/logout/done'
    const nx = url.searchParams.get('next')
    if (nx) {
      try {
        const u = new URL(nx)
        const h = u.hostname.toLowerCase()
        if (u.protocol === 'https:' && (h === hostOf(req) || h === new URL(AUTH_ORIGIN).hostname)) dest = u.href
      } catch (e) {}
    }
    res.writeHead(302, { location: dest, 'cache-control': 'no-store',
      'set-cookie': [
        COOKIE + '=; Path=/; Domain=' + domainFor(hostOf(req)) + '; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
        'session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
      ] })
    return res.end()
  }

  const np = normPath(req.url)
  if ((np === '/api/me' || np === '/api/session') && authed(req)) {
    if (!(await panelAlive())) {
      panelCookie = null
      panelAt = 0
    }
    const pc0 = await panelLogin()
    return proxy(req, res, pc0, true)
  }

  if (!isGated(req.url)) return proxy(req, res, null, authed(req))

  if (!authed(req)) {
    const wantsHtml = (req.headers.accept || '').includes('text/html')
    if ((req.method === 'GET' || req.method === 'HEAD') && wantsHtml) {
      return redirect(res, AUTH_ORIGIN + '/sso?next=' + encodeURIComponent('https://' + hostOf(req) + (req.url || '/')))
    }
    res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    return res.end(JSON.stringify({ error: 'authentication required', login: AUTH_ORIGIN }))
  }

  if (!(await panelAlive())) {
    panelCookie = null
    panelAt = 0
  }
  const pc = await panelLogin()
  return proxy(req, res, pc, true)
})

server.on('upgrade', (req, socket, head) => {
  let url
  try { url = new URL(req.url, 'http://x') } catch { socket.destroy(); return }
  const isAuth = authed(req)
  if (isGated(req.url) && !isAuth) { socket.destroy(); return }
  const headers = { ...req.headers }
  if (!isAuth) applyStrippedCookie(headers)
  const up = http.request({
    host: UPSTREAM_HOST, port: UPSTREAM_PORT, path: req.url, method: 'GET', headers,
  })
  up.on('upgrade', (r, upSocket, upHead) => {
    const lines = ['HTTP/1.1 101 Switching Protocols']
    for (let i = 0; i < r.rawHeaders.length; i += 2) lines.push(r.rawHeaders[i] + ': ' + r.rawHeaders[i + 1])
    socket.write(lines.join('\r\n') + '\r\n\r\n')
    if (upHead && upHead.length) socket.write(upHead)
    upSocket.pipe(socket)
    socket.pipe(upSocket)
    upSocket.on('error', () => socket.destroy())
    socket.on('error', () => upSocket.destroy())
  })
  up.on('error', () => socket.destroy())
  up.end()
})

setInterval(() => {
  const now = Date.now()
  for (const [k, v] of usedTickets) if (v < now) usedTickets.delete(k)
}, 30000).unref?.()

server.listen(PORT, '127.0.0.1', () => {
  console.log('[guard] listening on 127.0.0.1:' + PORT + ' -> ' + UPSTREAM_HOST + ':' + UPSTREAM_PORT)
  console.log('[guard] gated paths:', GATED.join(', '))
})
