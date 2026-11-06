import http from 'node:http'
import https from 'node:https'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { createHmac, randomBytes, randomInt, timingSafeEqual, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { config as cfg } from './config.mjs'
import * as OTPAuth from 'otpauth'
import QRCode from 'qrcode'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server'

// ============ config ============
const PORT = cfg.port || 3081
const AUTH_HOST = cfg.authHost
const AUTH_ORIGIN = 'https://' + AUTH_HOST
const RP_ID = cfg.rpId
const RP_NAME = cfg.rpName
const DATA = cfg.dataDir
const CRED_FILE = DATA + '/credentials.json'
const SESSION_KEY_FILE = DATA + '/session.key'
const BOOTSTRAP_FILE = DATA + '/bootstrap.key'
const TOTP_FILE = DATA + '/totp.json'
const DSH_LOG = cfg.dshLogPath || '/var/log/dsh-web.log'
const SESSION_MAX_AGE = 60 * 60 * 24 * 30
const SESSION_COOKIE = 'gm-sso'
const PARTIAL_COOKIE = 'gm-partial'
const PARTIAL_TTL = 10 * 60 * 1000
const TICKET_TTL = 120 * 1000
const CF_TEAM_DOMAIN = cfg.cfTeamDomain
const CF_AUD = cfg.cfAud
const OWNER_EMAIL = cfg.ownerEmail
const MAGPIE_KEY = cfg.magpieKey || ''

const SERVICES = cfg.services
const DSH_SERVICE_HOST = Object.keys(SERVICES).find((h) => SERVICES[h].dsh) || ''
const SERVICE_ORDER = Object.keys(SERVICES).filter((h) => !SERVICES[h].hidden)

mkdirSync(DATA, { recursive: true })

function loadOrCreate(file, bytes) {
  if (!existsSync(file)) writeFileSync(file, randomBytes(bytes).toString('base64url'), { mode: 0o600 })
  return readFileSync(file, 'utf8').trim()
}
const SESSION_KEY = loadOrCreate(SESSION_KEY_FILE, 32)
const BOOTSTRAP_KEY = loadOrCreate(BOOTSTRAP_FILE, 24)

// one-time-ish invite link so the bootstrap key never has to be typed by hand
const INVITE_FILE = DATA + '/invite.json'
const INVITE_TTL = 7 * 24 * 60 * 60 * 1000
function loadInvite() {
  const cur = readJson(INVITE_FILE, null)
  if (cur && cur.token && typeof cur.exp === 'number' && cur.exp > Date.now()) return cur
  const next = { token: randomBytes(18).toString('base64url'), exp: Date.now() + INVITE_TTL }
  writeJson(INVITE_FILE, next)
  return next
}
let INVITE = loadInvite()
function availableMethods() {
  const m = []
  if (activeCreds().length > 0) m.push('webauthn')
  if (totpConfirmed()) m.push('totp')
  m.push('github')
  if (emailReady()) m.push('email')
  return m
}
function completeStep(req, res, method, rawNext) {
  const avail = availableMethods()
  const need = Math.min(2, avail.length)
  const cur = readPartial(req).filter((x) => avail.indexOf(x) >= 0)
  if (cur.indexOf(method) < 0) cur.push(method)
  const n = parseNext(rawNext)
  if (cur.length >= need) {
    res.writeHead(302, {
      location: destOf(n),
      'set-cookie': [sessionCookie(), PARTIAL_COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'],
      'cache-control': 'no-store',
    })
    return res.end()
  }
  const back = '/login?next=' + encodeURIComponent(n.kind === 'remote' ? n.url : n.path)
  res.writeHead(302, {
    location: back,
    'set-cookie': PARTIAL_COOKIE + '=' + makePartial(cur) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600',
    'cache-control': 'no-store',
  })
  res.end()
}
function totpConfirmed() {
  const t = loadTotp()
  return !!(t && t.confirmed)
}
// bootstrap key always works (recovery channel).
// invite token only works while the thing it configures is still unconfigured,
// so a leaked invite cannot be replayed once setup is done.
function keyOk(k, allowInvite) {
  if (!k) return false
  if (safeEq(k, BOOTSTRAP_KEY)) return true
  if (!allowInvite) return false
  return !!(INVITE && INVITE.exp > Date.now() && safeEq(k, INVITE.token))
}

function readJson(file, fallback) {
  try { return JSON.parse(readFileSync(file, 'utf8')) } catch { return fallback }
}
function writeJson(file, data) { writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 }) }

const PANELS_FILE = DATA + '/panels.json'
let panelsCache = null, panelsAt = 0
function loadPanels() {
  if (panelsCache && Date.now() - panelsAt < 10000) return panelsCache
  panelsCache = existsSync(PANELS_FILE) ? readJson(PANELS_FILE, {}) : {}
  panelsAt = Date.now()
  return panelsCache
}
function savePanels(d) {
  writeJson(PANELS_FILE, d)
  panelsCache = d
  panelsAt = Date.now()
}
const PANELDEF_FILE = DATA + '/paneldefs.json'
const DEFAULT_PANEL_DEFS = cfg.panelTargets || []
let panelDefsCache = null, panelDefsAt = 0
function loadPanelDefs() {
  if (panelDefsCache && Date.now() - panelDefsAt < 10000) return panelDefsCache
  const d = readJson(PANELDEF_FILE, null)
  if (Array.isArray(d)) {
    panelDefsCache = d
  } else {
    panelDefsCache = DEFAULT_PANEL_DEFS
    writeJson(PANELDEF_FILE, DEFAULT_PANEL_DEFS)
    console.log('[gw] seeded paneldefs.json')
  }
  panelDefsAt = Date.now()
  return panelDefsCache
}
function savePanelDefs(d) {
  writeJson(PANELDEF_FILE, d)
  panelDefsCache = d
  panelDefsAt = Date.now()
}
const loadCreds = () => readJson(CRED_FILE, { credentials: [] })
const saveCreds = (d) => writeJson(CRED_FILE, d)
const loadTotp = () => readJson(TOTP_FILE, null)
const saveTotp = (d) => writeJson(TOTP_FILE, d)

// only credentials bound to the current RP ID are usable
function activeCreds() {
  return loadCreds().credentials.filter((c) => c.rpId === RP_ID)
}

// ============ crypto / session ============
const sign = (p) => createHmac('sha256', SESSION_KEY).update(p).digest('base64url')

function makeSession() {
  const exp = Date.now() + SESSION_MAX_AGE * 1000
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url')
  return payload + '.' + sign(payload)
}
function verifySession(value) {
  if (!value) return false
  const i = value.lastIndexOf('.')
  if (i < 0) return false
  const payload = value.slice(0, i), sig = value.slice(i + 1)
  const expect = sign(payload)
  if (sig.length !== expect.length) return false
  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return false
  try {
    const d = JSON.parse(Buffer.from(payload, 'base64url').toString())
    return typeof d.exp === 'number' && d.exp > Date.now()
  } catch { return false }
}

const usedTickets = new Map()
function sweepTickets() {
  const now = Date.now()
  for (const [k, v] of usedTickets) if (v < now) usedTickets.delete(k)
}
setInterval(sweepTickets, 30000).unref?.()

function makeTicket(host, path) {
  const payload = Buffer.from(JSON.stringify({ h: host, p: path, e: Date.now() + TICKET_TTL, n: randomBytes(8).toString('base64url') })).toString('base64url')
  return payload + '.' + sign(payload)
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

function cookiesOf(req, name) {
  const out = []
  const raw = req.headers.cookie
  if (!raw) return out
  for (const seg of raw.split(';')) {
    const at = seg.indexOf('=')
    if (at < 0) continue
    if (seg.slice(0, at).trim() === name) out.push(seg.slice(at + 1).trim())
  }
  return out
}
function makePartial(methods) {
  const payload = Buffer.from(JSON.stringify({ m: methods, exp: Date.now() + PARTIAL_TTL })).toString('base64url')
  return payload + '.' + sign(payload)
}
function readPartial(req) {
  const v = cookieOf(req, PARTIAL_COOKIE)
  if (!v) return []
  const i = v.lastIndexOf('.')
  if (i < 0) return []
  const payload = v.slice(0, i), sig = v.slice(i + 1)
  const expect = sign(payload)
  if (sig.length !== expect.length) return []
  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return []
  try {
    const d = JSON.parse(Buffer.from(payload, 'base64url').toString())
    if (!Array.isArray(d.m) || typeof d.exp !== 'number' || d.exp < Date.now()) return []
    return d.m.filter((x) => typeof x === 'string')
  } catch { return [] }
}
function cookieOf(req, name) {
  return cookiesOf(req, name)[0]
}
const isAuthed = (req) => cookiesOf(req, SESSION_COOKIE).some(verifySession)
function domainAttr(svc) {
  return svc && svc.cookieDomain ? '; Domain=' + svc.cookieDomain : ''
}
function serviceCookie(svc) {
  return SESSION_COOKIE + '=' + makeSession() + '; Path=/' + domainAttr(svc) + '; HttpOnly; Secure; SameSite=Lax; Max-Age=' + SESSION_MAX_AGE
}
function serviceClearCookie(svc) {
  return SESSION_COOKIE + '=; Path=/' + domainAttr(svc) + '; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
}

function sessionCookie() {
  return SESSION_COOKIE + '=' + makeSession() + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + SESSION_MAX_AGE
}
function clearCookie() {
  return SESSION_COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
}

// next can be a local path on the auth host, or an absolute url of a known service
function parseNext(raw) {
  if (raw && typeof raw === 'string') {
    if (raw[0] === '/' && raw[1] !== '/' && raw[1] !== '\\') return { kind: 'local', path: raw }
    try {
      const u = new URL(raw)
      if (u.protocol === 'https:' && SERVICES[u.hostname.toLowerCase()]) return { kind: 'remote', url: u.href }
    } catch {}
  }
  return { kind: 'local', path: '/' }
}
function destOf(n) {
  return n.kind === 'local' ? n.path : '/sso?next=' + encodeURIComponent(n.url)
}
function safeLogoutNext(nx) {
  if (!nx || typeof nx !== 'string') return null
  try {
    const u = new URL(nx)
    if (u.protocol !== 'https:') return null
    const h = u.hostname.toLowerCase()
    if (h === AUTH_HOST || SERVICES[h]) return u.href
  } catch {}
  return null
}
function hostOf(req) {
  const h = req.headers.host || req.headers['x-forwarded-host'] || ''
  return String(h).split(',')[0].trim().split(':')[0].toLowerCase()
}

// ============ cloudflare access jwt ============
let jwksCache = null, jwksAt = 0
function b64u(s) {
  const t = s.split('-').join('+').split('_').join('/')
  return Buffer.from(t, 'base64')
}
async function getJwks(force) {
  if (!force && jwksCache && Date.now() - jwksAt < 3600000) return jwksCache
  const r = await fetch('https://' + CF_TEAM_DOMAIN + '/cdn-cgi/access/certs')
  const j = await r.json()
  jwksCache = j.keys || []
  jwksAt = Date.now()
  return jwksCache
}
async function verifyAccessJwt(token) {
  if (!token || typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 3) return null
  let header, payload
  try {
    header = JSON.parse(b64u(parts[0]).toString('utf8'))
    payload = JSON.parse(b64u(parts[1]).toString('utf8'))
  } catch { return null }
  const aud = payload.aud
  const audOk = aud === CF_AUD || (Array.isArray(aud) && aud.indexOf(CF_AUD) >= 0)
  if (!audOk) return null
  if (payload.iss !== 'https://' + CF_TEAM_DOMAIN) return null
  const now = Math.floor(Date.now() / 1000)
  if (typeof payload.exp !== 'number' || payload.exp < now - 120) return null
  if (typeof payload.nbf === 'number' && payload.nbf > now + 120) return null
  const data = Buffer.from(parts[0] + '.' + parts[1])
  const sig = b64u(parts[2])
  const tryKey = (jwk) => {
    try { return cryptoVerify('RSA-SHA256', data, createPublicKey({ key: jwk, format: 'jwk' }), sig) } catch { return false }
  }
  let keys = await getJwks(false)
  let jwk = keys.find((k) => k.kid === header.kid)
  if (jwk && tryKey(jwk)) return payload
  keys = await getJwks(true)
  jwk = keys.find((k) => k.kid === header.kid)
  if (jwk && tryKey(jwk)) return payload
  return null
}

// ============ email codes ============
const EMAIL_FILE = DATA + '/email.json'
function loadEmail() {
  const d = readJson(EMAIL_FILE, null)
  if (d) return d
  return { addresses: [OWNER_EMAIL], mailerUrl: cfg.mailerUrl || '', mailerKey: '' }
}
function saveEmail(d) { writeJson(EMAIL_FILE, d) }
function emailReady() {
  const cfg = loadEmail()
  return !!(cfg.mailerUrl && cfg.mailerKey && (cfg.addresses || []).length)
}

const emailCodes = new Map()
const EMAIL_CODE_TTL = 5 * 60 * 1000
const EMAIL_MAX_TRIES = 5

async function sendMail(to, subject, text) {
  const cfg = loadEmail()
  if (!cfg.mailerUrl || !cfg.mailerKey) throw new Error('mailer not configured')
  const r = await fetch(cfg.mailerUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-mailer-key': cfg.mailerKey },
    body: JSON.stringify({ to, subject, text }),
  })
  if (!r.ok) throw new Error('mailer ' + r.status + ' ' + String(await r.text()).slice(0, 120))
}

// ============ rate limiting ============
const attemptBuckets = new Map()
function rateHit(key, limit, windowMs) {
  const now = Date.now()
  let rec = attemptBuckets.get(key)
  if (!rec || now - rec.start > windowMs) {
    rec = { n: 0, start: now }
    attemptBuckets.set(key, rec)
  }
  rec.n += 1
  return rec.n > limit
}
function clientIp(req) {
  const h = req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || ''
  return String(h).split(',')[0].trim() || 'unknown'
}
setInterval(() => {
  const now = Date.now()
  for (const [k, v] of attemptBuckets) if (now - v.start > 3600000) attemptBuckets.delete(k)
}, 300000).unref?.()

// ============ totp ============
function totpOf(secretBase32) {
  return new OTPAuth.TOTP({
    issuer: RP_NAME, label: cfg.totpLabel || 'sso-owner', algorithm: 'SHA1',
    digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secretBase32),
  })
}
function validateTotpSecret(secretBase32, code) {
  if (!secretBase32 || !code) return false
  const delta = totpOf(secretBase32).validate({ token: String(code).replace(/\D/g, ''), window: 1 })
  return delta !== null
}
function checkTotp(code) {
  const t = loadTotp()
  if (!t || !t.confirmed) return false
  return validateTotpSecret(t.secret, code)
}

// ============ webauthn challenges ============
// challenges are keyed per client so one visitor cannot invalidate another's
const pending = { login: new Map(), register: new Map() }
const CHALLENGE_TTL = 5 * 60 * 1000
function setChallenge(kind, v, ip) {
  const m = pending[kind]
  m.set(ip, { v, exp: Date.now() + CHALLENGE_TTL })
  if (m.size > 64) m.delete(m.keys().next().value)
}
function takeChallenge(kind, ip) {
  const m = pending[kind]
  const rec = m.get(ip)
  m.delete(ip)
  if (!rec || rec.exp < Date.now()) return undefined
  return rec.v
}

// ============ dsh upstream ============
function dshRequest(path, method, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1', port: SERVICES[DSH_SERVICE_HOST].port, path, method,
      headers: { ...headers, host: DSH_SERVICE_HOST }, rejectUnauthorized: false,
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
    req.end()
  })
}
let dshCookie = null, dshCookieAt = 0
function readToken() {
  try {
    const log = readFileSync(DSH_LOG, 'utf8')
    const all = [...log.matchAll(/dsh web: (\S+)/g)]
    if (!all.length) return null
    return new URL(all[all.length - 1][1]).searchParams.get('token')
  } catch { return null }
}
async function refreshDshCookie(force) {
  if (!force && dshCookie && Date.now() - dshCookieAt < 5 * 60 * 1000) return dshCookie
  const token = readToken()
  if (!token) return null
  try {
    const r = await dshRequest('/?token=' + encodeURIComponent(token), 'GET', {})
    const sc = r.headers['set-cookie']
    if (sc && sc.length) {
      dshCookie = sc[0].split(';')[0]; dshCookieAt = Date.now()
      console.log('[gw] refreshed DSH cookie')
      return dshCookie
    }
  } catch (e) { console.log('[gw] dsh token exchange failed:', e.message) }
  return null
}
function mergeCookie(existing, extra) {
  if (!extra) return existing || ''
  if (!existing) return extra
  const name = extra.split('=')[0]
  const kept = existing.split(';').map((s) => s.trim()).filter((s) => s && !s.startsWith(name + '='))
  return [...kept, extra].join('; ')
}

// ============ ui ============
const LIGHT_VARS = '--bg:#f5f6f8;--surface:#ffffff;--surface2:#f1f3f6;--line:#e9ebf0;--text:#14171c;--dim:#6b7280;--mute:#9aa1ac;--green:#16a34a;--green-soft:#e7f6ec;--red:#dc2626;--red-soft:#fdecec;--amber:#b45309;--amber-soft:#fdf3e2;--violet:#7c3aed;--blue:#2563eb;--shadow:0 1px 2px rgba(16,24,40,.04),0 10px 30px rgba(16,24,40,.06);--seg-on:#ffffff;--seg-shadow:rgba(16,24,40,.14);--btn-bg:#1b1f26;--btn-bg-hover:#2a3039;--btn-fg:#ffffff;--ease:cubic-bezier(.22,.61,.36,1);color-scheme:light'
const DARK_VARS = '--bg:#0b0d11;--surface:#14171d;--surface2:#1a1e26;--line:#252a35;--text:#e8eaed;--dim:#9aa4b8;--mute:#6b7280;--green:#34d399;--green-soft:#12291f;--red:#f87171;--red-soft:#2c1616;--amber:#fbbf24;--amber-soft:#2a2110;--violet:#a78bfa;--blue:#60a5fa;--shadow:0 1px 2px rgba(0,0,0,.35),0 16px 40px rgba(0,0,0,.45);--seg-on:#2c3342;--seg-shadow:rgba(0,0,0,.55);--btn-bg:#e8eaed;--btn-bg-hover:#ffffff;--btn-fg:#14171c;--ease:cubic-bezier(.22,.61,.36,1);color-scheme:dark'

const CSS = [
  ':root{'+LIGHT_VARS+'}',
  ':root[data-theme="dark"]{'+DARK_VARS+'}',
  '@media (prefers-color-scheme:dark){:root[data-theme="auto"]{'+DARK_VARS+'}}',
  '*{box-sizing:border-box}',
  'body{margin:0;background:var(--bg);color:var(--text);min-height:100vh;',
  'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",system-ui,"PingFang SC","Microsoft YaHei",sans-serif;',
  '-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;',
  'transition:background-color .25s var(--ease),color .25s var(--ease)}',
  '.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:13px 28px;background:var(--surface);',
  'border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20}',
  '.brand{display:flex;align-items:center;gap:11px;font-size:15px;font-weight:600;letter-spacing:-.01em;',
  'color:inherit;text-decoration:none;border-radius:10px;padding:3px 8px 3px 3px;margin:-3px 0 -3px -3px;',
  'transition:background .15s}',
  '.brand:hover{background:var(--surface2);text-decoration:none}',
  '.logo{width:34px;height:34px;border-radius:10px;background:#111418;display:grid;place-items:center;flex:none}',
  '.top-right{display:flex;align-items:center;gap:10px}',
  '.seg{display:flex;gap:2px;background:var(--surface2);border-radius:11px;padding:3px}',
  '.seg button{width:34px;height:28px;display:grid;place-items:center;border:0;background:transparent;border-radius:8px;',
  'cursor:pointer;color:var(--dim);padding:0;transition:background .15s,color .15s}',
  '.seg button:hover{color:var(--text);background:var(--surface)}',
  '.seg button:active{transform:scale(.94)}',
  '.seg button.on{background:var(--seg-on);color:var(--text);box-shadow:0 1px 2px var(--seg-shadow)}',
  '.seg svg{width:15px;height:15px;display:block}',
  '.link-btn{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 14px;border-radius:10px;',
  'border:1px solid var(--line);background:var(--surface);color:var(--text);font-size:13px;text-decoration:none;font-weight:500}',
  '.link-btn:hover{border-color:var(--mute);text-decoration:none}',
  'main{padding:44px 24px 80px;display:flex;justify-content:center}',
  '.wrap{width:100%;max-width:480px}.wrap.wide{max-width:780px}',
  '.page-head{margin-bottom:22px}',
  'h1{font-size:28px;font-weight:700;letter-spacing:-.025em;margin:0;line-height:1.25}',
  'p.sub{color:var(--dim);font-size:13.5px;line-height:1.65;margin:8px 0 0}',
  'p.sub b{color:var(--text);font-weight:600}',
  '.card{background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:26px 28px;box-shadow:var(--shadow);',
  'animation:cardIn .34s var(--ease) both}',
  '@keyframes cardIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}',
  '@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}',
  '#opts{max-height:560px;opacity:1;overflow:hidden;padding:6px 0;margin:-6px 0;',
  'transition:max-height .34s var(--ease),opacity .34s var(--ease),padding .34s var(--ease),margin .34s var(--ease)}',
  '#opts.hide{max-height:0;opacity:0;padding-top:0;padding-bottom:0;margin-top:0;margin-bottom:0}',
  '.opt.done{opacity:.55;animation:rowOut .8s var(--ease) .4s forwards}',
  '.opt.done .arw.done{color:var(--green);opacity:1;font-weight:700}',
  '@keyframes rowOut{0%{opacity:.55}45%{opacity:.5}',
  '100%{opacity:0;max-height:0;padding-top:0;padding-bottom:0;margin-top:0;border-top-width:0;border-bottom-width:0}}',
  '.stepbar{font-size:12.5px;line-height:1.6;color:var(--amber);background:var(--amber-soft);',
  'border-radius:12px;padding:10px 13px;margin-bottom:14px}',
  '.authbox{max-height:0;opacity:0;overflow:hidden;margin-top:0;',
  'transition:max-height .34s var(--ease),opacity .34s var(--ease)}',
  '.authbox.show{max-height:620px;opacity:1}',
  '.backlink{display:inline-block;margin-bottom:10px;font-size:12.5px;color:var(--dim);',
  'transition:color .16s var(--ease)}',
  '.backlink:hover{color:var(--text);text-decoration:none}',
  '.emrow{display:flex;align-items:center;gap:0;transition:gap .32s var(--ease)}',
  '.emrow.show{gap:10px}',
  '.emrow input.code{flex:0 1 0%;min-width:0;opacity:0;padding-left:0;padding-right:0;border-width:0;',
  'transition:flex-grow .32s var(--ease),opacity .24s var(--ease),padding .32s var(--ease),border-width .32s var(--ease)}',
  '.emrow.show input.code{flex:1 1 auto;opacity:1;padding-left:15px;padding-right:15px;border-width:1px}',
  '.emrow button{flex:1 1 auto;width:auto;white-space:nowrap;',
  'transition:flex-grow .32s var(--ease),background-color .18s var(--ease),transform .12s var(--ease),box-shadow .18s var(--ease)}',
  '.emrow.show button{flex:0 0 auto}',
  '.emreveal{display:none;margin-top:12px}',
  '.emreveal.show{display:inline-flex;animation:fadeIn .26s var(--ease) both}',
  '@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}',
  '.card+.card{margin-top:14px}',
  '.ico{width:36px;height:36px;border-radius:11px;background:var(--surface2);display:grid;place-items:center;color:var(--dim);flex:none}',
  '.ico svg{width:17px;height:17px;display:block}',
  '.sec-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:26px 0 2px;',
  'padding-bottom:9px;border-bottom:1px solid var(--line)}',
  '.sec-head:first-child{margin-top:0}',
  '.sec-t{font-size:12px;font-weight:700;color:var(--mute);text-transform:uppercase;letter-spacing:.08em}',
  '.btn-sm{width:auto;padding:6px 13px;font-size:12.5px;font-weight:500;border-radius:9px}',
  '.hint{font-size:11.5px;color:var(--mute);margin-top:10px}',
  '.prow{display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid var(--line)}',
  '.prow .meta{flex:1;font-size:13.5px;font-weight:500}',
  '.prow input{width:150px;padding:8px 11px;font-size:13px;border-radius:9px}',
  '.prow input.lbl{width:170px;font-weight:500;background:transparent;border-color:transparent}',
  '.prow input.lbl:hover{background:var(--surface2);border-color:var(--line)}',
  '.prow input.lbl:focus{background:var(--surface);border-color:var(--green)}',
  '.prow.addrow{margin-top:4px;border-top:1px dashed var(--line);border-bottom:0;padding-top:14px}',
  '.prow .chk{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--dim);white-space:nowrap}',
  '.prow .chk input{width:auto;margin:0;padding:0}',
  '#ndHost{width:205px}#ndPath{width:175px}',
  '.row .note{font-size:12px;color:var(--mute);font-family:inherit}',
  'button{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;border-radius:12px;padding:13px 18px;',
  'font-size:14.5px;font-weight:600;font-family:inherit;cursor:pointer;border:1px solid transparent;',
  'background:var(--btn-bg);color:var(--btn-fg);',
  'transition:background-color .18s var(--ease),border-color .18s var(--ease),color .18s var(--ease),',
  'box-shadow .18s var(--ease),transform .12s var(--ease),opacity .18s var(--ease)}',
  'button:hover:not(:disabled){background:var(--btn-bg-hover);box-shadow:0 4px 14px rgba(16,24,40,.14);transform:translateY(-1px)}',
  'button:active:not(:disabled){transform:translateY(0) scale(.995);box-shadow:0 1px 3px rgba(16,24,40,.12)}',
  'button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}',
  'button:disabled{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}',
  'button.ghost{background:var(--surface);color:var(--text);border-color:var(--line)}',
  'button.ghost:hover:not(:disabled){border-color:var(--mute);background:var(--surface2);box-shadow:none;transform:translateY(-1px)}',
  'button.danger{background:var(--red-soft);color:var(--red)}',
  'button.danger:hover:not(:disabled){background:var(--red);color:#fff;box-shadow:0 4px 14px rgba(220,38,38,.25)}',
  'input{width:100%;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:13px 15px;color:var(--text);',
  'font-size:15px;font-family:inherit;outline:none;transition:border-color .15s,box-shadow .15s}',
  'input::placeholder{color:var(--mute)}',
  'input{transition:border-color .18s var(--ease),box-shadow .18s var(--ease),background-color .18s var(--ease)}',
  'input:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--green-soft)}',
  'input.code{letter-spacing:.28em;text-indent:.28em;text-align:center;font-size:23px;font-weight:600;padding:14px;',
  'font-family:inherit;font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1}',
  'input.code::placeholder{letter-spacing:.28em;font-weight:400;color:var(--mute);opacity:.7}',
  '.msg{margin-top:14px;font-size:13px;color:var(--red);min-height:18px;line-height:1.55}',
  '.msg.ok{color:var(--green)}',
  '.divider{display:flex;align-items:center;gap:12px;color:var(--mute);font-size:12px;margin:20px 0}',
  '.divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--line)}',
  '.banner{font-size:12.5px;line-height:1.6;color:var(--amber);background:var(--amber-soft);border-radius:12px;padding:12px 14px;margin-bottom:18px}',
  '.banner a{color:inherit;text-decoration:underline}',
  '.svc{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:15px 17px;border:1px solid var(--line);',
  'border-radius:14px;margin-bottom:10px;text-decoration:none;color:inherit;',
  'transition:border-color .18s var(--ease),background-color .18s var(--ease),',
  'transform .16s var(--ease),box-shadow .18s var(--ease)}',
  '.svc:last-child{margin-bottom:0}',
  '.svc:hover{border-color:var(--mute);background:var(--surface2);text-decoration:none;',
  'transform:translateY(-1px);box-shadow:inset 0 0 0 1px var(--line)}',
  '.svc:active{background:var(--surface);transform:translateY(0);box-shadow:none}',
  '.svc .go{transition:transform .2s var(--ease),color .2s var(--ease)}',
  '.svc:hover .go{transform:translateX(5px);color:var(--text)}',
  '.svc .nm{font-size:14.5px;font-weight:600;letter-spacing:-.01em}',
  '.svc .ds{font-size:12px;color:var(--dim);margin-top:3px}',
  '.svc .go{font-size:12.5px;color:var(--dim);white-space:nowrap}',
  '.row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 0;border-bottom:1px solid var(--line)}',
  '.row:last-of-type{border-bottom:0}',
  '.row .meta{font-size:13.5px;font-weight:500}',
  '.row .dim{font-size:11.5px;color:var(--mute);margin-top:3px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}',
  '.row button{width:auto;padding:7px 14px;font-size:12.5px;border-radius:9px}',
  '.pill{display:inline-block;font-size:11px;font-weight:600;padding:3px 9px;border-radius:999px;background:var(--green-soft);',
  'color:var(--green);margin-left:8px;vertical-align:middle}',
  '.pill.off{background:var(--red-soft);color:var(--red)}',
  '.keybox{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--dim);background:var(--surface2);',
  'border-radius:10px;padding:11px 13px;word-break:break-all;margin-top:8px;line-height:1.55}',
  '.qr{display:block;margin:2px auto 18px;border-radius:14px;background:#fff;padding:12px;width:212px;height:212px;border:1px solid var(--line)}',
  '.foot{margin-top:20px;text-align:center;font-size:12.5px;color:var(--mute)}',
  'a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}',
  '.actions{display:flex;gap:10px;justify-content:center;margin-top:18px;flex-wrap:wrap}',
  '.actions a{display:inline-flex;align-items:center;gap:7px;padding:10px 18px;border-radius:11px;border:1px solid var(--line);',
  'background:var(--surface);color:var(--text);font-size:13px;font-weight:500;text-decoration:none;box-shadow:var(--shadow);',
  'transition:border-color .18s var(--ease),background-color .18s var(--ease),',
  'transform .16s var(--ease),box-shadow .18s var(--ease)}',
  '.actions a:hover{border-color:var(--mute);background:var(--surface2);text-decoration:none;',
  'transform:translateY(-1px);box-shadow:inset 0 0 0 1px var(--line)}',
  '.actions a:active{transform:translateY(0);box-shadow:none}',
  '.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;border-radius:12px;padding:13px 18px;',
  'font-size:14.5px;font-weight:600;text-decoration:none;border:1px solid var(--line);background:var(--surface);color:var(--text)}',
  '.btn:hover{border-color:var(--mute);text-decoration:none}',
  '.opt{display:flex;align-items:center;gap:11px;width:100%;margin-top:10px;padding:14px 16px;border:1px solid var(--line);max-height:80px;overflow:hidden;',
  'border-radius:14px;background:var(--surface);color:var(--text);font-size:14px;font-weight:500;font-family:inherit;',
  'text-align:left;cursor:pointer;text-decoration:none;',
  'transition:border-color .18s var(--ease),background-color .18s var(--ease),transform .16s var(--ease),box-shadow .18s var(--ease)}',
  '.opt:hover,button.opt:hover:not(:disabled){border-color:var(--mute);background:var(--surface2);color:var(--text);',
  'filter:none;text-decoration:none;transform:translateY(-1px);box-shadow:inset 0 0 0 1px var(--line)}',
  '.opt:active,button.opt:active:not(:disabled){box-shadow:none;background:var(--surface);transform:translateY(0)}',
  '.opt .arw{transition:transform .2s var(--ease),color .2s var(--ease)}',
  '.opt:hover .arw{transform:translateX(5px);color:var(--text)}',
  '.opt:hover .arw.done{transform:none}',
  'button.opt:disabled{opacity:.45;transform:none}',
  '.opt:disabled{opacity:.45;cursor:not-allowed}',
  '.opt .oi{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;color:var(--dim);flex:none}',
  '.opt .oi svg{width:17px;height:17px;display:block}',
  '.opt .arw{margin-left:auto;color:var(--mute);font-size:13px}',
  '.mt12{margin-top:12px}.mt16{margin-top:16px}.mt20{margin-top:20px}',
  '@media (max-width:560px){main{padding:28px 16px 60px}.top{padding:11px 16px}.card{padding:22px 18px}h1{font-size:24px}}',
].join('')

const THEME_BOOT = 'try{var q=new URLSearchParams(location.search).get("theme");var t=q||localStorage.getItem("gm-theme")||"auto";document.documentElement.setAttribute("data-theme",t)}catch(e){}'
const THEME_WIRE = [
  'document.querySelectorAll(".seg button").forEach(function(b){',
  'b.classList.toggle("on",b.dataset.t===(document.documentElement.getAttribute("data-theme")||"auto"));',
  'b.onclick=function(){var t=b.dataset.t;try{localStorage.setItem("gm-theme",t)}catch(e){}',
  'document.documentElement.setAttribute("data-theme",t);',
  'document.querySelectorAll(".seg button").forEach(function(x){x.classList.toggle("on",x.dataset.t===t)})}});',
].join('')

const ICON_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.2v2.4M12 19.4v2.4M4.6 4.6l1.7 1.7M17.7 17.7l1.7 1.7M2.2 12h2.4M19.4 12h2.4M4.6 19.4l1.7-1.7M17.7 6.3l1.7-1.7"/></svg>'
const ICON_MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 13.2A8.6 8.6 0 1 1 10.8 3.5a6.8 6.8 0 0 0 9.7 9.7z"/></svg>'
const ICON_MON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2.6" y="4" width="18.8" height="13" rx="2.4"/><path d="M8.6 20.8h6.8M12 17v3.8"/></svg>'
const ICON_LOGO = '<svg width="19" height="19" viewBox="0 0 20 20"><rect x="1" y="1" width="8" height="8" rx="2.6" fill="#f0563f"/><rect x="11" y="1" width="8" height="8" rx="2.6" fill="#f5b23d"/><rect x="1" y="11" width="8" height="8" rx="2.6" fill="#3ecf72"/><rect x="11" y="11" width="8" height="8" rx="2.6" fill="#4b8cf5"/></svg>'
const ICON_GH = '<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>'
const ICON_MAIL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.8" y="5" width="18.4" height="14" rx="2.4"/><path d="M3.5 6.5l8.5 6 8.5-6"/></svg>'
const ICON_SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7.5 3v5.5c0 4.4-3.1 8.3-7.5 9.5-4.4-1.2-7.5-5.1-7.5-9.5V6z"/></svg>'
const ICON_KEY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="3.5"/><path d="M10 13L20 3M17.5 5.5L20 8M15 8l2.5 2.5"/></svg>'
const ICON_PHONE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>'
const ICON_GEAR = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 3 15a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.3 8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 10 4.1V4a2 2 0 1 1 4 0v.1A1.7 1.7 0 0 0 17 5.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.7 1z"/></svg>'

function topBar(authed, isAdmin) {
  return [
    '<header class="top">',
    '<a class="brand" href="/" title="返回首页"><span class="logo">' + ICON_LOGO + '</span>Galmaster 统一登录</a>',
    '<div class="top-right">',
    '<div class="seg" role="group" aria-label="外观">',
    '<button data-t="light" title="日间" aria-label="日间">' + ICON_SUN + '</button>',
    '<button data-t="dark" title="夜间" aria-label="夜间">' + ICON_MOON + '</button>',
    '<button data-t="auto" title="跟随系统" aria-label="跟随系统">' + ICON_MON + '</button>',
    '</div>',
    authed && !isAdmin ? '<a class="link-btn" href="/admin">后台</a>' : '',
    '</div>',
    '</header>',
  ].join('')
}

function page(title, inner, script, authed, isAdmin) {
  return '<!doctype html><html lang="zh-CN" data-theme="auto"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="color-scheme" content="light dark">'
    + '<title>' + title + '</title>'
    + '<script>' + THEME_BOOT + '</script>'
    + '<style>' + CSS + '</style></head>'
    + '<body>' + topBar(!!authed, !!isAdmin) + '<main>' + inner + '</main>'
    + '<script>' + THEME_WIRE + (script || '') + '</script>'
    + '</body></html>'
}

const B64HELPERS = [
  'const b64=s=>{const t=s.replace(/-/g,"+").replace(/_/g,"/");const p=t.padEnd(t.length+(4-t.length%4)%4,"=");',
  'const bin=atob(p);const u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u.buffer};',
  'const enc=b=>{const u=new Uint8Array(b);let s="";for(const x of u)s+=String.fromCharCode(x);',
  'return btoa(s).split("+").join("-").split("/").join("_").replace(/=+$/,"")};',
  'const msg=(t,ok)=>{const m=document.getElementById("msg");if(!m)return;m.textContent=t;m.className="msg"+(ok?" ok":"")};',
].join('')

function portalPage(authed, nCred, totpOn) {
  const items = SERVICE_ORDER.map((h) => {
    const s = SERVICES[h]
    return '<a class="svc" href="https://' + h + '/"><div><div class="nm">' + s.name + '</div>'
      + '<div class="ds">' + s.desc + '</div></div><div class="go">打开 →</div></a>'
  }).join('')
  const warn = (nCred === 0 && !totpOn)
    ? '<div class="banner">尚未配置任何登录方式，请先 <a href="/auth/setup">添加硬件密钥或绑定动态验证码</a>。</div>'
    : ''
  const body = [
    '<div class="wrap wide">',
    '<div class="page-head"><h1>服务入口</h1>',
    '<p class="sub">' + (authed ? '已验证身份，打开下面任一服务无需再次登录。' : '当前未验证，打开服务时会跳转到登录页。') + '</p></div>',
    warn,
    '<div class="card">' + items + '</div>',
    '<div class="actions">'
      + (authed
        ? '<a href="/admin">后台管理</a><a href="#" id="lo">退出登录</a>'
        : '<a href="/login">去登录</a><a href="/auth/github?next=%2F">' + ICON_GH + ' 使用 GitHub 登录</a>')
      + '</div>',
    '</div>',
  ].join('')
  const script = [
    'const lo=document.getElementById("lo");',
    'if(lo)lo.onclick=(e)=>{e.preventDefault();location.href="/auth/logout"};',
  ].join('')
  return page('Galmaster 统一登录', body, script, authed)
}

function ghFailPage(msg) {
  return page('登录失败',
    '<div class="wrap"><div class="page-head"><h1>登录失败</h1><p class="sub">' + msg + '</p></div>'
    + '<div class="card"><a class="btn" href="/login">返回登录</a></div></div>', '', false)
}

const METHOD_LABEL = { webauthn: '硬件密钥', totp: '动态验证码', github: 'GitHub', email: '邮箱验证码' }

function loginPage(hasCred, hasTotp, hasEmail, n, passed) {
  const dest = destOf(n)
  const rawNext = n.kind === 'remote' ? n.url : n.path
  const LOCAL_LABEL = { '/': '', '/admin': '后台管理' }
  const target = n.kind === 'remote'
    ? new URL(n.url).hostname
    : (LOCAL_LABEL[n.path] !== undefined ? LOCAL_LABEL[n.path] : 'Galmaster')
  const done = passed || []
  const need = Math.min(2, availableMethods().length)
  const mark = (k) => (done.indexOf(k) >= 0 ? '<span class="arw done">✓</span>' : '<span class="arw">→</span>')
  const stepHint = done.length
    ? '<div class="stepbar">已通过 ' + done.map((k) => METHOD_LABEL[k] || k).join('、')
      + '　还需再验证' + (need - done.length) + ' 种</div>'
    : ''
  const body = [
    '<div class="wrap">',
    '<div class="page-head"><h1>身份验证</h1><p class="sub">'
      + (target ? '即将访问 <b>' + target + '</b>' : '验证后即可访问全部服务') + '</p></div>',
    '<div class="card">',
    stepHint,
    '<div id="opts">',
    hasTotp ? '<button class="opt' + (done.indexOf('totp') >= 0 ? ' done' : '') + '" id="tp"><span class="oi">' + ICON_PHONE + '</span>动态验证码' + mark('totp') + '</button>' : '',
    hasCred ? '<button class="opt' + (done.indexOf('webauthn') >= 0 ? ' done' : '') + '" id="wa"><span class="oi">' + ICON_KEY + '</span>硬件密钥 / Windows Hello' + mark('webauthn') + '</button>' : '',
    '<a class="opt' + (done.indexOf('github') >= 0 ? ' done' : '') + '" href="/auth/github?next=' + encodeURIComponent(rawNext) + '"><span class="oi">' + ICON_GH + '</span>使用 GitHub 登录' + mark('github') + '</a>',
    hasEmail ? '<button class="opt' + (done.indexOf('email') >= 0 ? ' done' : '') + '" id="em"><span class="oi">' + ICON_MAIL + '</span>邮箱验证码' + mark('email') + '</button>' : '',
    '</div>',
    '<div id="totpbox" class="authbox">'
      + '<a href="#" class="backlink" id="totpback">← 返回其他登录方式</a>'
      + '<input class="code" id="code" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code">'
      + '<button id="totp" class="mt12">验证动态码</button>'
      + '</div>',
    '<div id="embox" class="authbox">'
      + '<a href="#" class="backlink" id="emback">← 返回其他登录方式</a>'
      + '<input id="emaddr" type="email" placeholder="邮箱地址" autocomplete="email" style="margin-bottom:10px">'
      + '<div class="emrow" id="emrow">'
      + '<input class="code" id="emcode" inputmode="numeric" maxlength="6" placeholder="000000">'
      + '<button id="emsend">发送验证码</button>'
      + '</div>'
      + '<button id="emverify" class="emreveal">登录</button>'
      + '</div>',
    !hasCred && !hasTotp ? '<div class="banner" style="margin:16px 0 0">尚未配置任何登录方式，请使用引导密钥链接完成首次配置。</div>' : '',
    '<div class="msg" id="msg"></div>',
    '</div>',
    '</div>',
  ].join('')
  const script = B64HELPERS + [
    'const NX=' + JSON.stringify(dest) + ';',
    'const go=()=>{location.href=NX};',
    'const wa=document.getElementById("wa");',
    'if(wa)wa.onclick=async()=>{wa.disabled=true;try{',
    'const o=await (await fetch("/auth/login/options",{method:"POST"})).json();',
    'if(o.error){msg(o.error);return}',
    'o.challenge=b64(o.challenge);',
    'if(o.allowCredentials)o.allowCredentials=o.allowCredentials.map(c=>({...c,id:b64(c.id)}));',
    'o.timeout=300000;',
    'const cred=await navigator.credentials.get({publicKey:o});',
    'const body={id:cred.id,rawId:enc(cred.rawId),type:cred.type,',
    'clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},',
    'response:{clientDataJSON:enc(cred.response.clientDataJSON),',
    'authenticatorData:enc(cred.response.authenticatorData),signature:enc(cred.response.signature),',
    'userHandle:cred.response.userHandle?enc(cred.response.userHandle):null}};',
    'const r=await fetch("/auth/login/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});',
    'if(r.ok)go();else msg(await r.text());',
    '}catch(e){let t=(e&&e.name?e.name+": ":"")+(e&&e.message||String(e));',
    'if(e&&e.name==="NotAllowedError")t="验证超时或已取消";msg(t)}finally{wa.disabled=false}};',
    'const tb=document.getElementById("totp");',
    'if(tb)tb.onclick=async()=>{const c=document.getElementById("code").value.replace(/\\D/g,"");',
    'if(c.length!==6)return msg("请输入 6 位数字");tb.disabled=true;try{',
    'const r=await fetch("/auth/totp/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({code:c})});',
    'if(r.ok)go();else msg(await r.text());}catch(e){msg(String(e))}finally{tb.disabled=false}};',
    'const ci=document.getElementById("code");if(ci)ci.addEventListener("keydown",e=>{if(e.key==="Enter")document.getElementById("totp").click()});',
    'const em=document.getElementById("em");',
    'const emb=document.getElementById("embox");',
    'const optbox=document.getElementById("opts");',
    'const tpb=document.getElementById("totpbox"),tp=document.getElementById("tp");',
    'if(tp)tp.onclick=()=>{if(emb)emb.classList.remove("show");optbox.classList.add("hide");',
    'tpb.classList.add("show");setTimeout(()=>{const c=document.getElementById("code");if(c)c.focus()},360)};',
    'const tpbk=document.getElementById("totpback");',
    'if(tpbk)tpbk.onclick=(e)=>{e.preventDefault();tpb.classList.remove("show");optbox.classList.remove("hide")};',
    'if(em)em.onclick=()=>{if(tpb)tpb.classList.remove("show");if(optbox)optbox.classList.add("hide");',
    'emb.classList.add("show");setTimeout(()=>{document.getElementById("emaddr").focus()},360)};',
    'const ebk=document.getElementById("emback");',
    'if(ebk)ebk.onclick=(e)=>{e.preventDefault();emb.classList.remove("show");if(optbox)optbox.classList.remove("hide");};',
    'const es=document.getElementById("emsend");',
    'if(es)es.onclick=async()=>{const a=document.getElementById("emaddr").value.trim();',
    'if(!a)return msg("请输入邮箱地址");es.disabled=true;try{',
    'const r=await fetch("/auth/email/start",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email:a})});',
    'if(r.ok){msg("验证码已发送，请查收邮件",true);',
    'document.getElementById("emrow").classList.add("show");',
    'document.getElementById("emverify").classList.add("show");',
    'es.textContent="重新发送";document.getElementById("emcode").focus()}else msg(await r.text());',
    '}catch(e){msg(String(e))}finally{es.disabled=false}};',
    'const ev=document.getElementById("emverify");',
    'if(ev)ev.onclick=async()=>{const a=document.getElementById("emaddr").value.trim();',
    'const c=document.getElementById("emcode").value.replace(/\\D/g,"");',
    'if(c.length!==6)return msg("请输入 6 位验证码");ev.disabled=true;try{',
    'const r=await fetch("/auth/email/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email:a,code:c})});',
    'if(r.ok)go();else msg(await r.text());',
    '}catch(e){msg(String(e))}finally{ev.disabled=false}};',
  ].join('')
  return page('身份验证', body, script, false)
}

function setupPage(prefill) {
  const body = [
    '<div class="wrap">',
    '<div class="page-head"><h1>配置登录方式</h1>',
    '<p class="sub">需要引导密钥（bootstrap key）才能添加新的登录方式。建议同时绑定动态验证码，这样在电脑上也能用手机验证。</p></div>',
    '<div class="card">',
    '<input id="bk" placeholder="bootstrap key" autocomplete="off" value="' + (prefill || '') + '">',
    '<div class="divider">下一步</div>',
    '<button class="opt" id="ltotp"><span class="oi">' + ICON_PHONE + '</span>绑定动态验证码<span class="arw">→</span></button>',
    '<button class="opt" id="lwa"><span class="oi">' + ICON_KEY + '</span>添加硬件密钥<span class="arw">→</span></button>',
    '<div class="msg" id="msg"></div>',
    '</div>',
    '<div class="actions"><a href="/">返回首页</a></div>',
    '</div>',
  ].join('')
  const script = [
    'const msg=(t,ok)=>{const m=document.getElementById("msg");m.textContent=t;m.className="msg"+(ok?" ok":"")};',
    'const K=()=>document.getElementById("bk").value.trim();',
    'const go=(p)=>{if(!K())return msg("请先填写 bootstrap key");location.href=p+"?key="+encodeURIComponent(K())};',
    'document.getElementById("ltotp").onclick=()=>go("/auth/totp/setup");',
    'document.getElementById("lwa").onclick=()=>go("/auth/register");',
  ].join('')
  return page('配置登录方式', body, script, false)
}

function registerPage(bootstrap, n) {
  const body = [
    '<div class="wrap">',
    '<div class="page-head"><h1>注册硬件密钥</h1>',
    '<p class="sub">插入安全密钥，或使用本机 Windows Hello / Touch ID。在哪台设备上打开，就绑定哪台设备。</p></div>',
    '<div class="card">',
    '<button id="go">注册此密钥</button>',
    '<div class="msg" id="msg"></div>',
    '</div>',
    '<div class="actions"><a href="/">返回首页</a></div>',
    '</div>',
  ].join('')
  const script = B64HELPERS + [
    'const K=' + JSON.stringify(bootstrap) + ';',
    'const NX=' + JSON.stringify(destOf(n)) + ';',
    '(async()=>{if(!window.PublicKeyCredential){msg("此浏览器不支持 WebAuthn");return}',
    'try{if(PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable){',
    'const ok=await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();',
    'if(!ok)msg("提示：本机未配置 Windows Hello / Touch ID，请插入 USB 安全密钥")}}catch(_){}})();',
    'document.getElementById("go").onclick=async()=>{const btn=document.getElementById("go");btn.disabled=true;try{',
    'const o=await (await fetch("/auth/register/options?key="+encodeURIComponent(K),{method:"POST"})).json();',
    'if(o.error){msg(o.error);return}',
    'o.challenge=b64(o.challenge);o.user.id=b64(o.user.id);',
    'o.pubKeyCredParams=(o.pubKeyCredParams||[]).filter(p=>p.alg===-7||p.alg===-257);',
    'if(!o.pubKeyCredParams.length)o.pubKeyCredParams=[{alg:-7,type:"public-key"},{alg:-257,type:"public-key"}];',
    'o.timeout=300000;',
    'o.authenticatorSelection={residentKey:"discouraged",requireResidentKey:false,userVerification:"preferred"};',
    'if(o.excludeCredentials)o.excludeCredentials=o.excludeCredentials.map(c=>({...c,id:b64(c.id)}));',
    'msg("等待密钥确认…");',
    'const cred=await navigator.credentials.create({publicKey:o});',
    'msg("密钥已响应，正在提交…");',
    'const body={id:cred.id,rawId:enc(cred.rawId),type:cred.type,',
    'clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},',
    'response:{clientDataJSON:enc(cred.response.clientDataJSON),',
    'attestationObject:enc(cred.response.attestationObject),',
    'transports:cred.response.getTransports?cred.response.getTransports():[]}};',
    'const r=await fetch("/auth/register/verify?key="+encodeURIComponent(K),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});',
    'if(r.ok){msg("注册成功，正在跳转…",true);setTimeout(()=>location.href=NX,900)}else{msg("注册失败("+r.status+"): "+await r.text())}',
    '}catch(e){let t=(e&&e.name?e.name+": ":"")+(e&&e.message||String(e));',
    'if(e&&e.name==="NotAllowedError")t="操作超时或未获允许。请确认已插入安全密钥，或系统已配置 Windows Hello。";',
    'else if(e&&e.name==="InvalidStateError")t="这把密钥已经注册过了。";',
    'msg(t)}finally{btn.disabled=false}};',
  ].join('')
  return page('注册硬件密钥', body, script, false)
}

function totpSetupPage(bootstrap, secret, dataUrl) {
  const body = [
    '<div class="wrap">',
    '<div class="page-head"><h1>绑定动态验证码</h1>',
    '<p class="sub">用手机上的验证器 App 扫描二维码。绑定后在任何设备上都能用手机上的 6 位数字登录。</p></div>',
    '<div class="card">',
    '<img class="qr" src="' + dataUrl + '" alt="TOTP QR">',
    '<div class="keybox">手动输入密钥：' + secret + '</div>',
    '<input class="code mt20" id="code" inputmode="numeric" maxlength="6" placeholder="000000">',
    '<button id="ok" class="mt12">确认绑定</button>',
    '<div class="msg" id="msg"></div>',
    '</div>',
    '<div class="actions"><a href="/">返回首页</a></div>',
    '</div>',
  ].join('')
  const script = [
    'const K=' + JSON.stringify(bootstrap) + ';',
    'const msg=(t,ok)=>{const m=document.getElementById("msg");m.textContent=t;m.className="msg"+(ok?" ok":"")};',
    'document.getElementById("ok").onclick=async()=>{const b=document.getElementById("ok");',
    'const c=document.getElementById("code").value.replace(/\\D/g,"");',
    'if(c.length!==6)return msg("请输入 6 位数字");b.disabled=true;try{',
    'const r=await fetch("/auth/totp/confirm?key="+encodeURIComponent(K),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({code:c})});',
    'if(r.ok){msg("绑定成功，正在跳转…",true);setTimeout(()=>location.href="/",900)}else msg(await r.text());',
    '}catch(e){msg(String(e))}finally{b.disabled=false}};',
    'const ci=document.getElementById("code");if(ci){ci.addEventListener("keydown",e=>{if(e.key==="Enter")document.getElementById("ok").click()});ci.focus()}',
  ].join('')
  return page('绑定动态验证码', body, script, false)
}

function adminPage(creds, totp, panels, emailCfg) {
  const credRows = creds.length
    ? creds.map((c, i) => [
      '<div class="row"><div><div class="meta">密钥 ' + (i + 1) + '</div>',
      '<div class="dim">' + c.id.slice(0, 24) + '…</div>',
      '<div class="dim">' + (c.createdAt || '未知时间') + '</div></div>',
      '<button class="danger btn-sm" data-id="' + c.id + '">删除</button></div>',
    ].join('')).join('')
    : '<div class="row"><div class="note">尚未注册任何硬件密钥</div></div>'
  const totpRow = totp && totp.confirmed
    ? '<div class="row"><div><div class="meta">已启用<span class="pill">正常</span></div>'
      + '<div class="dim">' + totp.secret.slice(0, 8) + '…</div></div>'
      + '<button class="danger btn-sm" id="rt">重置</button></div>'
    : '<div class="row"><div><div class="meta">未启用<span class="pill off">关闭</span></div>'
      + '<div class="note" style="margin-top:4px">绑定后可在任何设备用手机验证码登录</div></div>'
      + '<button class="ghost btn-sm" id="st">绑定</button></div>'
  const panelRows = loadPanelDefs().map((t) => {
    const cur = panels[t.host] || {}
    const lbl = String(t.label || t.host).replace(/"/g, '&quot;')
    return '<div class="prow">'
      + '<input class="lbl" data-label="' + t.host + '" value="' + lbl + '" title="显示名，改完回车保存">'
      + (cur.password ? '<span class="pill">已配置</span>' : '<span class="pill off">未配置</span>')
      + (t.needsUser ? '<input data-u="' + t.host + '" placeholder="用户名" value="' + (cur.username || '') + '">' : '')
      + '<input type="password" data-p="' + t.host + '" placeholder="密码" value="">'
      + '<button class="ghost btn-sm" data-save="' + t.host + '">保存</button>'
      + '<button class="danger btn-sm" data-del="' + t.host + '" title="移除这一行">×</button>'
      + '</div>'
  }).join('')
  + [
    '<div class="prow addrow">',
    '<input id="ndHost" placeholder="主机名 如 app.example.com">',
    '<input id="ndLabel" placeholder="显示名">',
    '<input id="ndPath" placeholder="/api/login（可选）">',
    '<label class="chk"><input type="checkbox" id="ndUser">需用户名</label>',
    '<button class="ghost btn-sm" id="ndAdd">＋ 添加</button>',
    '</div>',
  ].join('')
  const body = [
    '<div class="wrap wide">',
    '<div class="page-head"><h1>后台管理</h1>',
    '<p class="sub">管理统一登录凭据与引导密钥，所有受保护的服务共用这套凭据。</p></div>',
    '<div class="card">',
    '<div class="sec-head"><span class="sec-t">硬件密钥</span>',
    '<button class="ghost btn-sm" id="addwa">＋ 添加</button></div>',
    credRows,
    '<div class="sec-head"><span class="sec-t">动态验证码</span></div>',
    totpRow,
    '<div class="sec-head"><span class="sec-t">引导密钥</span></div>',
    '<div class="keybox">' + BOOTSTRAP_KEY + '</div>',
    '<div class="hint">免手输邀请链接（7 天有效）</div>',
    '<div class="keybox">' + AUTH_ORIGIN + '/auth/setup?key=' + INVITE.token + '</div>',
    '<div class="row"><div class="note">重新生成后旧引导密钥立即失效</div>',
    '<button class="ghost btn-sm" id="rb">重新生成</button></div>',
    '<div class="sec-head"><span class="sec-t">邮箱验证码登录</span></div>',
    '<div class="prow"><div class="meta">允许的邮箱' + (emailCfg.mailerKey ? '<span class="pill">已启用</span>' : '<span class="pill off">未配置发信</span>') + '</div>',
    '<input data-em="addr" placeholder="多个用逗号分隔" value="' + (emailCfg.addresses || []).join(',') + '" style="width:260px">',
    '<button class="ghost btn-sm" data-save-email="1">保存</button></div>',
    '<div class="prow"><div class="meta">发信密钥</div>',
    '<input data-em="key" type="password" placeholder="' + (emailCfg.mailerKey ? '已设置，留空不修改' : '未设置') + '" style="width:260px">',
    '<button class="ghost btn-sm" data-save-email="1">保存</button></div>',
    '<div class="sec-head"><span class="sec-t">面板自动登录</span></div>',
    panelRows,
    '<div class="sec-head"><span class="sec-t">会话</span></div>',
    '<div class="row"><div class="note">当前浏览器已登录，有效期 30 天</div>',
    '<button class="danger btn-sm" id="lo">退出登录</button></div>',
    '<div class="msg" id="msg"></div>',
    '</div>',
    '<div class="actions"><a href="/">返回首页</a></div>',
    '</div>',
  ].join('')
  const script = [
    'const BK=' + JSON.stringify(BOOTSTRAP_KEY) + ';',
    'const msg=(t,ok)=>{const m=document.getElementById("msg");m.textContent=t;m.className="msg"+(ok?" ok":"")};',
    'const post=async(u,b)=>{const r=await fetch(u,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(b||{})});',
    'return {ok:r.ok,text:await r.text()}};',
    'document.querySelectorAll("button[data-id]").forEach(b=>b.onclick=async()=>{',
    'if(!confirm("确定删除这把密钥？"))return;b.disabled=true;',
    'const r=await post("/admin/delete-credential",{id:b.dataset.id});',
    'if(r.ok)location.reload();else{msg(r.text);b.disabled=false}});',
    'document.getElementById("addwa").onclick=()=>{location.href="/auth/register?key="+encodeURIComponent(BK)+"&next=/admin"};',
    'const st=document.getElementById("st");if(st)st.onclick=()=>{location.href="/auth/totp/setup?key="+encodeURIComponent(BK)+"&next=/admin"};',
    'const rt=document.getElementById("rt");if(rt)rt.onclick=async()=>{if(!confirm("重置后旧验证码立即失效，确定？"))return;',
    'const r=await post("/admin/totp/reset");if(r.ok)location.reload();else msg(r.text)};',
    'document.getElementById("rb").onclick=async()=>{if(!confirm("重新生成后旧引导密钥立即失效，确定？"))return;',
    'const r=await post("/admin/bootstrap/reset");if(r.ok)location.reload();else msg(r.text)};',
    'document.getElementById("lo").onclick=()=>{location.href="/auth/logout"};',
    'document.querySelectorAll("button[data-save-email]").forEach(b=>b.onclick=async()=>{',
    'const a=document.querySelector(\'input[data-em="addr"]\').value.trim();',
    'const k=document.querySelector(\'input[data-em="key"]\').value.trim();b.disabled=true;',
    'const r=await post("/admin/email",{addresses:a,mailerKey:k});',
    'if(r.ok){msg("已保存",true);setTimeout(()=>location.reload(),600)}else{msg(r.text);b.disabled=false}});',
    'document.querySelectorAll("input[data-label]").forEach(inp=>inp.onchange=async()=>{',
    'const r=await post("/admin/paneldef",{action:"rename",host:inp.dataset.label,label:inp.value.trim()});',
    'if(!r.ok)msg(r.text)});',
    'document.querySelectorAll("button[data-del]").forEach(b=>b.onclick=async()=>{',
    'if(!confirm("移除这一行的自动登录配置？已存的密码也会一起删掉。"))return;b.disabled=true;',
    'const r=await post("/admin/paneldef",{action:"delete",host:b.dataset.del});',
    'if(r.ok)location.reload();else{msg(r.text);b.disabled=false}});',
    'const nd=document.getElementById("ndAdd");',
    'if(nd)nd.onclick=async()=>{const h=document.getElementById("ndHost").value.trim();',
    'if(!h)return msg("请填主机名");nd.disabled=true;',
    'const r=await post("/admin/paneldef",{action:"add",host:h,',
    'label:document.getElementById("ndLabel").value.trim(),',
    'loginPath:document.getElementById("ndPath").value.trim(),',
    'needsUser:document.getElementById("ndUser").checked});',
    'if(r.ok)location.reload();else{msg(r.text);nd.disabled=false}};',
    'document.querySelectorAll("button[data-save]").forEach(b=>b.onclick=async()=>{',
    'const h=b.dataset.save;const u=document.querySelector(\'input[data-u="\'+h+\'"]\');',
    'const pw=document.querySelector(\'input[data-p="\'+h+\'"]\');b.disabled=true;',
    'const r=await post("/admin/panel",{host:h,username:u?u.value.trim():"",password:pw?pw.value:""});',
    'if(r.ok){msg("已保存",true);setTimeout(()=>location.reload(),600)}else{msg(r.text);b.disabled=false}});',
  ].join('')
  return page('后台管理', body, script, true, true)
}

// ============ http helpers ============
function send(res, status, body, headers = {}) {
  const buf = Buffer.from(body)
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-length': buf.length, 'cache-control': 'no-store', ...headers })
  res.end(buf)
}
function json(res, status, obj) {
  const buf = Buffer.from(JSON.stringify(obj))
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': buf.length, 'cache-control': 'no-store' })
  res.end(buf)
}
function redirect(res, location, extra = {}) {
  res.writeHead(302, { location, 'cache-control': 'no-store', ...extra })
  res.end()
}
function readBody(req, limit = 1 << 20) {
  return new Promise((resolve, reject) => {
    let n = 0
    const chunks = []
    req.on('data', (c) => {
      n += c.length
      if (n > limit) { reject(new Error('body too large')); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b))
  return x.length === y.length && timingSafeEqual(x, y)
}

// ============ upstream proxy ============
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128, keepAliveMsecs: 15000 })
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128, keepAliveMsecs: 15000, rejectUnauthorized: false })
const STATIC_RE = /^\/(assets|plugins|fonts|static|_next|public)\//i
const STATIC_EXT_RE = /\.(ico|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|otf|eot|css|js|mjs|map)$/i

function normaliseForStatic(raw) {
  let p = String(raw || '/')
  const q = p.indexOf('?')
  if (q >= 0) p = p.slice(0, q)
  try { p = decodeURIComponent(p) } catch (e) {}
  const segs = []
  for (const seg of p.split('/')) {
    if (seg === '..') segs.pop()
    else if (seg !== '.' && seg !== '') segs.push(seg)
  }
  return '/' + segs.join('/')
}

function isStatic(path, method) {
  if (method !== 'GET' && method !== 'HEAD') return false
  return STATIC_RE.test(path) || STATIC_EXT_RE.test(path)
}

function upstreamTarget(svc) {
  if (svc.origin) {
    const u = new URL(svc.origin)
    return {
      host: u.hostname.replace(/^\[|\]$/g, ''),
      port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)),
      tls: u.protocol === 'https:',
      prefix: u.pathname.replace(/\/$/, ''),
    }
  }
  return { host: '127.0.0.1', port: svc.port, tls: !!svc.tls, prefix: '' }
}

function proxy(req, res, svc, host, retried, extraCookies) {
  const headers = { ...req.headers }
  delete headers.host
  delete headers.connection
  if (extraCookies && extraCookies.length) {
    headers.cookie = mergeCookie(headers.cookie, extraCookies.map((c) => c.split(';')[0]).join('; '))
  }
  if (svc.dsh) {
    headers.cookie = mergeCookie(headers.cookie, dshCookie || '')
  }
  if (svc.authHeaders && svc.authToken) {
    for (const h of svc.authHeaders) headers[h.n] = h.p + svc.authToken
  }
  if (svc.injectStorage) delete headers['accept-encoding']
  const t = upstreamTarget(svc)
  const lib = t.tls ? https : http
  const opts = {
    host: t.host, port: t.port, path: t.prefix + req.url, method: req.method,
    headers: { ...headers, host }, agent: svc.dsh ? false : (t.tls ? httpsAgent : httpAgent),
  }
  if (t.tls) opts.rejectUnauthorized = false
  const up = lib.request(opts, (r) => {
    const ctype = String(r.headers['content-type'] || '')
    if (svc.injectStorage && svc.authToken && ctype.indexOf('text/html') >= 0) {
      const chunks = []
      r.on('data', (c) => chunks.push(c))
      r.on('end', () => {
        let html = Buffer.concat(chunks).toString('utf8')
        const store = svc.injectStorage.type === 'session' ? 'sessionStorage' : 'localStorage'
        const inject = '<script>try{' + store + '.setItem(' + JSON.stringify(svc.injectStorage.key) + ',' + JSON.stringify(svc.authToken) + ')}catch(e){}</script>'
        if (/<head[^>]*>/i.test(html)) html = html.replace(/<head[^>]*>/i, (m) => m + inject)
        else html = inject + html
        const buf = Buffer.from(html, 'utf8')
        const out = { ...r.headers }
        delete out['content-encoding']
        delete out['transfer-encoding']
        delete out['content-length']
        out['content-length'] = buf.length
        out['cache-control'] = 'no-store'
        res.writeHead(r.statusCode, out)
        res.end(buf)
      })
      return
    }
    if (r.statusCode === 401 && svc.dsh && !retried) {
      r.resume()
      refreshDshCookie(true).then(() => proxy(req, res, svc, host, true))
      return
    }
    const out = { ...r.headers }
    delete out['transfer-encoding']
    if (extraCookies && extraCookies.length) {
      out['set-cookie'] = out['set-cookie'] ? [].concat(out['set-cookie'], extraCookies) : extraCookies
    }
    res.writeHead(r.statusCode, out)
    r.pipe(res)
  })
  up.setTimeout(120000, () => {
    console.log('[gw] upstream timeout', host, req.method, String(req.url).slice(0, 80))
    up.destroy(new Error('upstream timeout'))
  })
  up.on('error', (e) => {
    console.log('[gw] upstream error', host, e.message)
    if (!res.headersSent) send(res, 502, 'upstream error: ' + e.message)
    else res.end()
  })
  if (req.method === 'GET' || req.method === 'HEAD') up.end()
  else req.pipe(up)
}

// ============ auth host ============
async function handleAuth(req, res, url) {
  const path = url.pathname
  const rawNext = url.searchParams.get('next')

  if (path === '/healthz') {
    if (isAuthed(req)) {
      const t = loadTotp()
      return json(res, 200, { ok: true, host: AUTH_HOST, creds: activeCreds().length, totp: !!(t && t.confirmed), services: Object.keys(SERVICES) })
    }
    return json(res, 200, { ok: true })
  }
  if (path === '/robots.txt') return send(res, 200, 'User-agent: *\nDisallow: /\n', { 'content-type': 'text/plain' })
  if (path === '/favicon.ico') { res.writeHead(204); return res.end() }

  if (path === '/') {
    if (req.method !== 'GET') return send(res, 405, 'method not allowed')
    if (!isAuthed(req)) return redirect(res, '/login?next=' + encodeURIComponent('/'))
    const t = loadTotp()
    return send(res, 200, portalPage(true, activeCreds().length, !!(t && t.confirmed)))
  }

  // ticket issuance
  if (path === '/sso' && req.method === 'GET') {
    const n = parseNext(rawNext)
    if (n.kind !== 'remote') return redirect(res, n.path)
    if (!isAuthed(req)) return redirect(res, '/login?next=' + encodeURIComponent(n.url))
    const u = new URL(n.url)
    const ticket = makeTicket(u.hostname.toLowerCase(), u.pathname + u.search + u.hash)
    return redirect(res, 'https://' + u.hostname.toLowerCase() + '/_sso?t=' + encodeURIComponent(ticket))
  }

  if (path === '/auth/github' && req.method === 'GET') {
    const n = parseNext(rawNext)
    return redirect(res, '/gh-login?next=' + encodeURIComponent(n.kind === 'remote' ? n.url : n.path))
  }

  if (path === '/gh-login' && req.method === 'GET') {
    const payload = await verifyAccessJwt(req.headers['cf-access-jwt-assertion'])
    if (!payload) return send(res, 403, ghFailPage('GitHub 登录未通过（缺少有效的 Cloudflare Access 断言）'))
    const email = String(payload.email || '').toLowerCase()
    if (email !== OWNER_EMAIL) return send(res, 403, ghFailPage('此 GitHub 账号不在允许列表：' + (email || '未知')))
    console.log('[gw] github step ok', email)
    return completeStep(req, res, 'github', rawNext)
  }

  if (path === '/login' && req.method === 'GET') {
    const n = parseNext(rawNext)
    if (isAuthed(req)) {
      if (n.kind === 'remote') {
        const u = new URL(n.url)
        const ticket = makeTicket(u.hostname.toLowerCase(), u.pathname + u.search + u.hash)
        return redirect(res, 'https://' + u.hostname.toLowerCase() + '/_sso?t=' + encodeURIComponent(ticket))
      }
      return redirect(res, n.path)
    }
    const t = loadTotp()
    return send(res, 200, loginPage(activeCreds().length > 0, !!(t && t.confirmed), emailReady(), n, readPartial(req)))
  }

  if (path === '/auth/setup' && req.method === 'GET') {
    return send(res, 200, setupPage(url.searchParams.get('key') || ''))
  }

  if (path === '/auth/login/options' && req.method === 'POST') {
    if (rateHit('options:' + clientIp(req), 60, 60 * 1000)) return json(res, 429, { error: 'too many requests' })
    const creds = activeCreds()
    if (!creds.length) return json(res, 400, { error: 'no credentials registered' })
    const opts = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: 'preferred',
      allowCredentials: creds.map((c) => ({ id: c.id, transports: c.transports || [] })),
    })
    setChallenge('login', opts.challenge, clientIp(req))
    return json(res, 200, opts)
  }

  if (path === '/auth/login/verify' && req.method === 'POST') {
    const body = JSON.parse(await readBody(req))
    const creds = loadCreds()
    const stored = creds.credentials.find((c) => c.id === body.id)
    if (!stored) return send(res, 400, '未知密钥')
    const expected = takeChallenge('login', clientIp(req))
    if (!expected) return send(res, 400, '会话已过期，请重试')
    let v
    try {
      v = await verifyAuthenticationResponse({
        response: body, expectedChallenge: expected, expectedOrigin: AUTH_ORIGIN, expectedRPID: RP_ID,
        credential: {
          id: stored.id, publicKey: Buffer.from(stored.publicKey, 'base64url'),
          counter: stored.counter, transports: stored.transports || [],
        },
      })
    } catch (e) { return send(res, 400, '验证失败：' + e.message) }
    if (!v.verified) return send(res, 400, '验证未通过')
    stored.counter = v.authenticationInfo.newCounter
    stored.lastUsedAt = new Date().toISOString()
    saveCreds(creds)
    return completeStep(req, res, 'webauthn', rawNext)
  }

  if (path === '/auth/email/start' && req.method === 'POST') {
    const ip = clientIp(req)
    if (rateHit('email:ip:' + ip, 10, 60 * 60 * 1000)) return send(res, 429, '请求过于频繁，请稍后再试')
    const body = JSON.parse(await readBody(req))
    const email = String(body.email || '').trim().toLowerCase()
    const cfg = loadEmail()
    const allowed = (cfg.addresses || []).map((x) => String(x).toLowerCase())
    if (!email || allowed.indexOf(email) < 0) return send(res, 403, '该邮箱不在允许列表')
    if (rateHit('email:addr:' + email, 1, 60 * 1000)) return send(res, 429, '发送过于频繁，请 60 秒后再试')
    const code = String(randomInt(0, 1000000)).padStart(6, '0')
    emailCodes.set(email, { code, exp: Date.now() + EMAIL_CODE_TTL, tries: 0 })
    try {
      await sendMail(email, '[Galmaster] 登录验证码 ' + code,
        '你的 Galmaster 登录验证码是：' + code + '\n\n5 分钟内有效，仅可使用一次。\n如果不是你本人操作，请忽略这封邮件。')
      console.log('[gw] email code sent to', email)
      return json(res, 200, { ok: true })
    } catch (e) {
      console.log('[gw] email send failed', e.message)
      return send(res, 502, '邮件发送失败，请稍后再试')
    }
  }

  if (path === '/auth/email/verify' && req.method === 'POST') {
    const ip = clientIp(req)
    if (rateHit('emailv:ip:' + ip, 20, 10 * 60 * 1000)) return send(res, 429, '尝试过于频繁，请稍后再试')
    const body = JSON.parse(await readBody(req))
    const email = String(body.email || '').trim().toLowerCase()
    const code = String(body.code || '').replace(/\D/g, '')
    const rec = emailCodes.get(email)
    if (!rec || rec.exp < Date.now()) return send(res, 400, '验证码已过期，请重新发送')
    if (rec.tries >= EMAIL_MAX_TRIES) { emailCodes.delete(email); return send(res, 400, '错误次数过多，请重新发送') }
    if (rec.code !== code) {
      rec.tries += 1
      return send(res, 400, '验证码不正确')
    }
    emailCodes.delete(email)
    console.log('[gw] email step ok', email)
    return completeStep(req, res, 'email', rawNext)
  }

  if (path === '/auth/totp/verify' && req.method === 'POST') {
    const ip = clientIp(req)
    if (rateHit('totp:ip:' + ip, 5, 5 * 60 * 1000) || rateHit('totp:all', 20, 10 * 60 * 1000)) {
      console.log('[gw] totp rate limit hit', ip)
      return send(res, 429, '尝试过于频繁，请稍后再试')
    }
    const body = JSON.parse(await readBody(req))
    if (!checkTotp(body.code)) return send(res, 400, '验证码不正确')
    return completeStep(req, res, 'totp', rawNext)
  }

  if (path === '/auth/register' && req.method === 'GET') {
    const key = url.searchParams.get('key') || ''
    if (!keyOk(key, activeCreds().length === 0)) return send(res, 403, '引导密钥不正确')
    return send(res, 200, registerPage(key, parseNext(rawNext)))
  }

  if (path === '/auth/register/options' && req.method === 'POST') {
    const key = url.searchParams.get('key') || ''
    if (!keyOk(key, activeCreds().length === 0)) return json(res, 403, { error: 'forbidden' })
    const creds = activeCreds()
    const opts = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: RP_ID,
      userID: Buffer.from(cfg.webauthnUser || 'sso-owner'), userName: cfg.webauthnUser || 'sso-owner', userDisplayName: RP_NAME + ' Owner',
      attestationType: 'none',
      excludeCredentials: creds.map((c) => ({ id: c.id, transports: c.transports || [] })),
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
      timeout: 300000,
    })
    setChallenge('register', opts.challenge, clientIp(req))
    return json(res, 200, opts)
  }

  if (path === '/auth/register/verify' && req.method === 'POST') {
    const key = url.searchParams.get('key') || ''
    if (!keyOk(key, activeCreds().length === 0)) return send(res, 403, 'forbidden')
    const body = JSON.parse(await readBody(req))
    const expected = takeChallenge('register', clientIp(req))
    if (!expected) return send(res, 400, '会话已过期，请重试')
    let v
    try {
      v = await verifyRegistrationResponse({
        response: body, expectedChallenge: expected, expectedOrigin: AUTH_ORIGIN, expectedRPID: RP_ID,
      })
    } catch (e) { console.log('[gw] register error:', e.message); return send(res, 400, '注册失败：' + e.message) }
    if (!v.verified || !v.registrationInfo) return send(res, 400, '注册未通过')
    const c = v.registrationInfo.credential
    const creds = loadCreds()
    creds.credentials.push({
      id: c.id,
      rpId: RP_ID,
      publicKey: Buffer.from(c.publicKey).toString('base64url'),
      counter: c.counter,
      transports: body.response?.transports || [],
      createdAt: new Date().toISOString(),
    })
    saveCreds(creds)
    console.log('[gw] registered credential', c.id.slice(0, 16))
    return json(res, 200, { ok: true })
  }

  if (path === '/auth/totp/setup' && req.method === 'GET') {
    const key = url.searchParams.get('key') || ''
    const allowed = keyOk(key, !totpConfirmed()) || isAuthed(req)
    if (!allowed) return send(res, 403, '引导密钥不正确')
    let t = loadTotp()
    if (t && t.confirmed) {
      return send(res, 409, '动态验证码已绑定。如需重新绑定，请先在后台重置。')
    }
    if (!t) { t = { secret: new OTPAuth.Secret({ size: 20 }).base32, confirmed: false }; saveTotp(t) }
    const uri = totpOf(t.secret).toString()
    const dataUrl = await QRCode.toDataURL(uri, { margin: 1, width: 220, color: { dark: '#000000', light: '#ffffff' } })
    return send(res, 200, totpSetupPage(keyOk(key) ? key : '', t.secret, dataUrl))
  }

  if (path === '/auth/totp/confirm' && req.method === 'POST') {
    const key = url.searchParams.get('key') || ''
    const allowed = keyOk(key, !totpConfirmed()) || isAuthed(req)
    if (!allowed) return send(res, 403, 'forbidden')
    const body = JSON.parse(await readBody(req))
    const t = loadTotp()
    if (!t) return send(res, 400, '未初始化')
    if (!validateTotpSecret(t.secret, body.code)) return send(res, 400, '验证码不正确')
    t.confirmed = true
    t.createdAt = new Date().toISOString()
    saveTotp(t)
    console.log('[gw] totp confirmed')
    return json(res, 200, { ok: true })
  }

  if ((path === '/auth/logout' || path === '/logout') && (req.method === 'POST' || req.method === 'GET')) {
    const hosts = cfg.logoutHosts || []
    const step = (i) => i >= hosts.length
      ? AUTH_ORIGIN + '/logout/done'
      : 'https://' + hosts[i] + '/_sso/logout?next=' + encodeURIComponent(step(i + 1))
    return redirect(res, step(0))
  }

  if (path === '/logout/done') {
    res.writeHead(302, { location: '/', 'set-cookie': clearCookie(), 'cache-control': 'no-store' })
    return res.end()
  }

  if (path === '/admin' && req.method === 'GET') {
    if (!isAuthed(req)) return redirect(res, '/login?next=' + encodeURIComponent('/admin'))
    return send(res, 200, adminPage(activeCreds(), loadTotp(), loadPanels(), loadEmail()))
  }

  if (path === '/admin/delete-credential' && req.method === 'POST') {
    if (!isAuthed(req)) return send(res, 401, 'unauthorized')
    const body = JSON.parse(await readBody(req))
    const creds = loadCreds()
    const before = creds.credentials.length
    creds.credentials = creds.credentials.filter((c) => c.id !== body.id)
    if (creds.credentials.length === before) return send(res, 404, '未找到')
    saveCreds(creds)
    console.log('[gw] deleted credential', String(body.id).slice(0, 16))
    return json(res, 200, { ok: true })
  }

  if (path === '/admin/email' && req.method === 'POST') {
    if (!isAuthed(req)) return send(res, 401, 'unauthorized')
    const body = JSON.parse(await readBody(req))
    const cfg = loadEmail()
    const list = String(body.addresses || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)
    if (list.length) cfg.addresses = list
    if (body.mailerKey) cfg.mailerKey = String(body.mailerKey).trim()
    if (!cfg.mailerUrl) cfg.mailerUrl = cfg.mailerUrl || ''
    saveEmail(cfg)
    console.log('[gw] email config updated, addresses:', (cfg.addresses || []).length)
    return json(res, 200, { ok: true })
  }

  if (path === '/admin/paneldef' && req.method === 'POST') {
    if (!isAuthed(req)) return send(res, 401, 'unauthorized')
    const body = JSON.parse(await readBody(req))
    const act = String(body.action || '')
    let defs = loadPanelDefs().slice()
    const host = String(body.host || '').trim().toLowerCase()
    if (act === 'delete') {
      defs = defs.filter((d) => d.host !== host)
      const pn = loadPanels()
      delete pn[host]
      savePanels(pn)
    } else if (act === 'add') {
      if (!host) return send(res, 400, '主机名不能为空')
      if (defs.some((d) => d.host === host)) return send(res, 400, '该主机名已存在')
      const item = { host, label: String(body.label || host), needsUser: !!body.needsUser }
      if (body.loginPath) item.loginPath = String(body.loginPath)
      defs = defs.concat([item])
    } else if (act === 'rename') {
      if (!defs.some((d) => d.host === host)) return send(res, 404, '未找到该面板')
      defs = defs.map((d) => (d.host === host ? { ...d, label: String(body.label || d.label) } : d))
    } else {
      return send(res, 400, '未知操作')
    }
    savePanelDefs(defs)
    console.log('[gw] paneldefs', act, host, '->', defs.length, 'entries')
    return json(res, 200, { ok: true })
  }

  if (path === '/admin/panel' && req.method === 'POST') {
    if (!isAuthed(req)) return send(res, 401, 'unauthorized')
    const body = JSON.parse(await readBody(req))
    const host = String(body.host || '')
    const target = loadPanelDefs().find((t) => t.host === host)
    if (!target) return send(res, 400, '未知面板')
    const panels = loadPanels()
    const cur = panels[host] || {}
    if (body.password) {
      cur.password = String(body.password)
      delete cur.cookieName
    }
    if (target.needsUser) cur.username = String(body.username || '')
    panels[host] = cur
    if (target.alias) panels[target.alias] = { ...cur }
    savePanels(panels)
    console.log('[gw] panel credentials updated:', host)
    return json(res, 200, { ok: true })
  }

  if (path === '/admin/totp/reset' && req.method === 'POST') {
    if (!isAuthed(req)) return send(res, 401, 'unauthorized')
    try { writeFileSync(TOTP_FILE, 'null') } catch {}
    console.log('[gw] totp reset')
    return json(res, 200, { ok: true })
  }

  if (path === '/admin/bootstrap/reset' && req.method === 'POST') {
    if (!isAuthed(req)) return send(res, 401, 'unauthorized')
    writeFileSync(BOOTSTRAP_FILE, randomBytes(24).toString('base64url'), { mode: 0o600 })
    console.log('[gw] bootstrap key rotated')
    return json(res, 200, { ok: true })
  }

  return send(res, 404, 'not found')
}

// ============ service host ============
async function handleService(req, res, url, host, svc) {
  const path = url.pathname

  if (path === '/_sso') {
    const d = readTicket(url.searchParams.get('t'))
    if (!d || d.h !== host) return redirect(res, AUTH_ORIGIN + '/sso?next=' + encodeURIComponent('https://' + host + path))
    const target = (typeof d.p === 'string' && d.p[0] === '/' && d.p[1] !== '/') ? d.p : '/'
    return redirect(res, target, { 'set-cookie': serviceCookie(svc) })
  }

  if (path === '/_sso/logout') {
    const nx = safeLogoutNext(url.searchParams.get('next')) || AUTH_ORIGIN + '/logout/done'
    res.writeHead(302, { location: nx, 'set-cookie': serviceClearCookie(svc), 'cache-control': 'no-store' })
    return res.end()
  }

  if (svc.publicPaths && svc.publicPaths.some((p) => path === p || path.startsWith(p + '/'))) return proxy(req, res, svc, host)

  if (svc.gatedPaths && !svc.gatedPaths.some((p) => path === p || path.startsWith(p + '/'))) return proxy(req, res, svc, host)

  if (isStatic(normaliseForStatic(req.url), req.method)) return proxy(req, res, svc, host)

  if (!isAuthed(req)) {
    const wantsHtml = (req.headers.accept || '').includes('text/html')
    if ((req.method === 'GET' || req.method === 'HEAD') && wantsHtml) {
      const full = 'https://' + host + (req.url || '/')
      return redirect(res, AUTH_ORIGIN + '/sso?next=' + encodeURIComponent(full))
    }
    return json(res, 401, { error: 'authentication required', login: AUTH_ORIGIN })
  }

  const extra = await serviceAutoCookies(req, svc, host)
  if (svc.authHeaders || svc.injectStorage) {
    const tok = await panelToken(host, svc)
    if (tok) svc = { ...svc, authToken: tok }
  }
  return proxy(req, res, svc, host, false, extra)
}

function panelLoginRequest(host, svc, body, loginPath) {
  return new Promise((resolve, reject) => {
    const t = upstreamTarget(svc)
    const data = JSON.stringify(body)
    const lib = t.tls ? https : http
    const up = lib.request({
      host: t.host, port: t.port, path: t.prefix + (loginPath || '/api/login'), method: 'POST',
      headers: { host, 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) },
      agent: t.tls ? httpsAgent : httpAgent,
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

const tokenCache = new Map()
async function panelToken(host, svc) {
  const c = tokenCache.get(host)
  if (c && c.exp > Date.now()) return c.token
  const p = loadPanels()[host]
  if (!p || !p.password) return null
  const tgt = loadPanelDefs().find((t) => t.host === host)
  try {
    const body = p.username ? { username: p.username, password: p.password } : { password: p.password }
    const r = await panelLoginRequest(host, svc, body, tgt && tgt.loginPath)
    let tok = null
    try { tok = JSON.parse(r.body).token } catch (e) {}
    if (!tok) {
      const sc = r.headers['set-cookie']
      if (sc && sc.length) tok = sc[0].split(';')[0].split('=').slice(1).join('=')
    }
    if (tok) {
      tokenCache.set(host, { token: tok, exp: Date.now() + 30 * 60 * 1000 })
      console.log('[gw] panel token acquired', svc.name)
      return tok
    }
    console.log('[gw] panel token failed', svc.name, r.status, String(r.body).slice(0, 120))
  } catch (e) {
    console.log('[gw] panel token error', svc.name, e.message)
  }
  return null
}

async function serviceAutoCookies(req, svc, host) {
  if (svc.authHeaders || svc.injectStorage) return []
  if (svc.autoLogin && svc.authCookie) {
    if (cookiesOf(req, svc.authCookie).length) return []
    try {
      const cs = await svc.autoLogin()
      if (cs && cs.length) console.log('[gw] auto-login', svc.name)
      return cs || []
    } catch (e) {
      console.log('[gw] auto-login failed', svc.name, e.message)
      return []
    }
  }

  const panels = loadPanels()
  const entry = panels[host]
  if (!entry || !entry.password) return []
  if (entry.cookieName && cookiesOf(req, entry.cookieName).length) return []
  try {
    let body
    if (entry.field) body = { [entry.field]: entry.password }
    else if (entry.username) body = { username: entry.username, password: entry.password }
    else body = { password: entry.password }
    const r = await panelLoginRequest(host, svc, body, entry.loginPath)
    const sc = r.headers['set-cookie'] || []
    if (!sc.length) {
      console.log('[gw] panel login rejected', svc.name, r.status, r.body.slice(0, 120))
      return []
    }
    if (!entry.cookieName) {
      entry.cookieName = sc[0].split('=')[0].trim()
      panels[host] = entry
      savePanels(panels)
      console.log('[gw] panel cookie name learned:', host, entry.cookieName)
    }
    console.log('[gw] panel auto-login', svc.name)
    return sc
  } catch (e) {
    console.log('[gw] panel auto-login failed', svc.name, e.message)
    return []
  }
}

// ============ server ============
const server = http.createServer(async (req, res) => {
  const host = hostOf(req)
  try {
    let url
    try {
      url = new URL(req.url, 'http://localhost')
    } catch (e) {
      console.log('[gw] malformed request target', JSON.stringify(String(req.url).slice(0, 120)))
      return send(res, 400, 'bad request')
    }
    if (host === AUTH_HOST) return await handleAuth(req, res, url)
    const svc = SERVICES[host]
    if (svc) return await handleService(req, res, url, host, svc)
    console.log('[gw] unknown host', String(host).replace(/[^a-z0-9.:-]/gi, '?').slice(0, 80))
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    return res.end('unknown host')
  } catch (e) {
    console.log('[gw] error', e.message)
    if (!res.headersSent) send(res, 500, '内部错误')
    else res.end()
  }
})

server.on('upgrade', async (req, socket, head) => {
  const host = hostOf(req)
  const svc = SERVICES[host]
  if (!svc) { socket.destroy(); return }
  let wsPath = '/'
  try { wsPath = new URL(req.url, 'http://x').pathname } catch (e) { socket.destroy(); return }
  const openPath = svc.gatedPaths
    ? !svc.gatedPaths.some((p) => wsPath === p || wsPath.startsWith(p + '/'))
    : !!(svc.publicPaths && svc.publicPaths.some((p) => wsPath === p || wsPath.startsWith(p + '/')))
  if (!openPath && !isAuthed(req)) { socket.destroy(); return }
  const headers = { ...req.headers }
  delete headers.host
  if (svc.dsh) headers.cookie = mergeCookie(req.headers.cookie, dshCookie || '')
  const t = upstreamTarget(svc)
  const lib = t.tls ? https : http
  const opts = { host: t.host, port: t.port, path: t.prefix + req.url, method: 'GET', headers: { ...headers, host } }
  if (t.tls) opts.rejectUnauthorized = false
  const up = lib.request(opts)
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

server.listen(PORT, '127.0.0.1', () => {
  const t = loadTotp()
  console.log('[gw] listening on 127.0.0.1:' + PORT)
  console.log('[gw] auth host:', AUTH_HOST)
  console.log('[gw] services:', Object.keys(SERVICES).join(', '))
  console.log('[gw] credentials:', activeCreds().length, '| totp:', !!(t && t.confirmed))
  console.log('[gw] invite token:', INVITE.token.slice(0, 6) + '... (see /admin)')
  refreshDshCookie(true).catch(() => {})
})
