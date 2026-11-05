**English** | [简体中文](zh-CN/panels.md)

# Panel auto-login

Each panel has its own idea of what a session is. The gateway performs that
login once, then hands the result to the browser. Nothing here needs a second
prompt from the user.

Credentials live in `data/panels.json` (gateway side) and `panel.json`
(guard side), both `0600`, never rendered back to the page.

## The four transports

| Transport | What the gateway does | Config keys |
|---|---|---|
| **Cookie injection** | POSTs the panel's login endpoint, copies `Set-Cookie` onto its own response | `authCookie` |
| **Header injection** | Caches the token, sets it on every proxied request | `authHeaders`, `bearerAuth` |
| **Storage injection** | Rewrites the panel's HTML to seed `localStorage` / `sessionStorage` before its boot script runs | `injectStorage` |
| **Upstream cookie** | Mints a cookie server-side and injects it into the upstream request only | `dsh` |

## Worked examples

### Magpie — key in the URL

Magpie prints `http://127.0.0.1:8899/?k=<key>` at startup. Exchanging that
key for a cookie is a single GET:

```js
'magpie.example.com': {
  name: 'Magpie', port: 8899,
  cookieDomain: '.example.com',
  authCookie: 'magpie_web_8899',
  autoLogin: async () => {
    const sc = await getSetCookie('127.0.0.1', 8899, '/?k=' + encodeURIComponent(cfg.magpieKey))
    return sc.map((c) => c.split(';')[0] + '; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax')
  },
}
```

### SnowLuma — custom header plus localStorage

Its cookie is only for avatars (`Path=/avatar`); the real credential is a
token the front-end keeps in `localStorage.snowluma_token` and sends as
`X-SnowLuma-Token`. Both halves are needed:

```js
authHeaders: [
  { n: 'authorization', p: 'Bearer ' },
  { n: 'x-snowluma-token', p: '' },
],
injectStorage: { type: 'local', key: 'snowluma_token' },
```

The injected snippet is prepended to `<head>` so it runs before the app's own
boot check:

```html
<script>try{localStorage.setItem("snowluma_token","<token>")}catch(e){}</script>
```

### WorkBuddy — header plus sessionStorage

Same idea, different names. Its first-frame gate reads
`sessionStorage['wb-proxy-panel-token']` synchronously in `<head>`, so the
seed has to land before that script runs:

```js
authHeaders: [{ n: 'x-panel-token', p: '' }],
injectStorage: { type: 'session', key: 'wb-proxy-panel-token' },
```

Its login endpoint is `/panel/login` with a `panel_password` field, not the
usual `/api/login`.

### Komari / Lite Monitor — cookie, behind an edge guard

The panel sits on a different machine, so the guard performs the login:

```js
// guard.json
{ "username": "...", "password": "..." }
```

```
POST /api/login  {username, password}
  → Set-Cookie: session_token=...
  → guard caches it for 30 min, revalidates with /api/me
```

Two details matter:

- The guard **strips** `session_token` from unauthenticated requests. Without
  it, a signed-out browser still carries the panel cookie and the panel
  happily reports `logged_in: true`.
- The same stripping runs on the WebSocket upgrade. Real-time panels push
  user state over `/api/rpc2`; skipping the upgrade path lets the panel
  restore a logged-in UI a second after the page loads.

### DSH — token from the log

DSH prints a token to its log on boot. The gateway scrapes it, exchanges it
for a DSH cookie, and injects that into upstream requests only — the browser
never sees it.

```js
const token = readTokenFromLog(cfg.dshLogPath)   // dsh web: https://.../?token=...
const cookie = await exchange(token)             // cached 5 min, refreshed on 401
```

## Adding a panel

1. Work out its auth transport (cookie / header / storage / upstream).
2. Add an entry under `services`.
3. If it needs a password, add it to `panelTargets` so the admin page
   renders a field for it.
4. Sign in once and watch the log for `panel login ok` or the rejection body.

Rejections print the upstream status and the first 120 bytes of the response,
which is usually enough to spot a wrong field name.
