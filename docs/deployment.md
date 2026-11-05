# Deployment guide

End-to-end setup from a bare VPS to a working gateway with two services.
Every command is copy-pasteable; replace the placeholders as you go.

Throughout this guide:

| Placeholder | Meaning | Example |
|---|---|---|
| `example.com` | your domain, on Cloudflare | `acme.dev` |
| `auth.example.com` | the login portal hostname | `auth.acme.dev` |
| `app1.example.com` | first protected service | `panel.acme.dev` |
| `<tunnel-id>` | Cloudflare Tunnel UUID | `f79f040c-...` |

---

## 0. Prerequisites

| Item | Why |
|---|---|
| A domain on Cloudflare (free plan is fine) | DNS + Tunnel + Access |
| A Linux host with a public IP | anything ≥1 vCPU; the gateway is idle most of the time |
| Node.js ≥ 18 | `fetch`, `crypto.subtle` |
| `cloudflared` on that host | the only ingress path |
| SSH access | you will run the gateway as a systemd unit |

No inbound ports need to be open. The gateway binds `127.0.0.1` and
Cloudflare Tunnel dials out.

```bash
node -v          # v18.x or newer
cloudflared -v
```

---

## 1. Create the tunnel

```bash
cloudflared tunnel login          # opens a browser, authorises the zone
cloudflared tunnel create galmaster-sso
# → Created tunnel galmaster-sso with id <tunnel-id>
cloudflared tunnel token --credential-file <tunnel-id>.json
```

Simplest way to run it as a service:

```bash
sudo cloudflared service install <token>
sudo systemctl enable --now cloudflared
```

That writes `/etc/cloudflared/token`. Ingress is then managed remotely
(dashboard or API), not in a local YAML.

### Ingress rules

Every hostname points at the **same** port — the gateway routes on `Host`:

| Hostname | Service |
|---|---|
| `auth.example.com` | `http://localhost:3081` |
| `app1.example.com` | `http://localhost:3081` |
| `app2.example.com` | `http://localhost:3081` |
| *(catch-all)* | `http_status:404` |

Via API:

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT/cfd_tunnel/$TUNNEL/configurations" \
  -H "Authorization: Bearer $CF_TOKEN" -H "content-type: application/json" \
  -d '{"config":{"ingress":[
        {"hostname":"auth.example.com","service":"http://localhost:3081"},
        {"hostname":"app1.example.com","service":"http://localhost:3081"},
        {"service":"http_status:404"}]}}'
```

---

## 2. DNS

One CNAME per hostname, proxied, pointing at the tunnel:

```
auth.example.com   CNAME  <tunnel-id>.cfargotunnel.com   (proxied)
app1.example.com   CNAME  <tunnel-id>.cfargotunnel.com   (proxied)
```

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records" \
  -H "Authorization: Bearer $CF_TOKEN" -H "content-type: application/json" \
  -d '{"type":"CNAME","name":"auth","content":"'$TUNNEL'.cfargotunnel.com","proxied":true}'
```

---

## 3. Install the gateway

```bash
sudo mkdir -p /opt/sso && sudo chown $USER:$USER /opt/sso
git clone https://github.com/Lbcheng1145/galmaster-sso.git /opt/sso
cd /opt/sso
npm install --omit=dev

cp src/config.example.mjs src/config.mjs
chmod 600 src/config.mjs
```

Edit `src/config.mjs`. Minimum viable config:

```js
export const config = {
  authHost: 'auth.example.com',
  rpId: 'example.com',              // registrable suffix of authHost
  rpName: 'My SSO',
  ownerEmail: 'me@example.com',
  dataDir: '/opt/sso/data',
  port: 3081,
  logoutHosts: ['app1.example.com', 'example.com'],
  services: {
    'app1.example.com': {
      name: 'Panel',
      desc: 'My first panel',
      port: 8001,
      cookieDomain: '.example.com',
    },
  },
  panelTargets: [],
  guard: {},
}
```

Notes:

- `rpId` must be the **registrable domain** (`example.com`), not the full
  hostname. WebAuthn rejects credentials when the origin does not sit under it.
- `cookieDomain` makes every `*.example.com` service share one session. Drop
  it to fall back to per-host cookies (you then need the ticket flow).
- `logoutHosts` needs one entry per registrable domain, otherwise sign-out
  misses hosts.

Start it manually first, so errors are visible:

```bash
sudo mkdir -p /opt/sso/data
node src/gateway.mjs
# [gw] listening on 127.0.0.1:3081
# [gw] auth host: auth.example.com
```

---

## 4. systemd

```bash
sudo cp deploy/galmaster-sso.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now galmaster-sso
sudo systemctl status galmaster-sso --no-pager
sudo journalctl -u galmaster-sso -f
```

Adjust `User=`, `WorkingDirectory=` and the log path in the unit if your
layout differs.

---

## 5. First credential

The gateway created two files on first start:

```bash
ls -l /opt/sso/data
# bootstrap.key   ← recovery channel, keep secret
# session.key     ← signs sessions and tickets
```

```bash
cat /opt/sso/data/bootstrap.key
```

Open:

```
https://auth.example.com/auth/setup?key=<bootstrap.key>
```

Bind **TOTP** first — it is the only method that works from any device without
extra hardware. Scan the QR with any authenticator app, type the 6 digits.

Then add a hardware key if you want: **＋ 添加硬件密钥** on `/admin`, or
`/auth/register?key=<bootstrap.key>`. Register it on the machine you want it
bound to — Windows Hello stays on that machine, a USB key travels with you.

> The bootstrap key always works. The shorter *invite link* shown on
> `/admin` only works while its target is still unconfigured, so it cannot be
> replayed once setup is done.

---

## 6. Protect the first service

Point the service's hostname at the gateway (already done in step 1) and make
sure the origin listens on the configured port:

```bash
ss -ltnp | grep 8001
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8001/
```

Visit `https://app1.example.com/` in a private window. Expected:

```
302 → https://auth.example.com/sso?next=https%3A%2F%2Fapp1.example.com%2F
```

Sign in with two methods; you land back on `app1.example.com` with a session.

Static assets are exempt from the check so Cloudflare can still cache them:

```js
// handled automatically
/assets/  /plugins/  /fonts/  *.css *.js *.woff2 *.ico
```

If a service needs a public path (an API that uses its own keys), add
`publicPaths: ['/v1']` to its config entry.

---

## 7. GitHub sign-in (optional)

Delegating to Cloudflare Access means no OAuth secret is stored here.

1. **Zero Trust → Settings → Authentication → Login methods → Add → GitHub**
   (creates an OAuth app on your GitHub account)
2. **Access → Applications → Add → Self-hosted**
   - Application domain: `auth.example.com`
   - Path: `gh-login`
   - Session duration: 24h
   - Policy: *Allow* → *Emails* → your address only
   - Settings → *Automatic redirect to identity provider*: on
3. Copy the application's **AUD tag** (Application → Overview) into
   `config.cfAud`, and your team domain into `config.cfTeamDomain`

```js
cfTeamDomain: 'yourteam.cloudflareaccess.com',
cfAud: '<paste the AUD tag from the Access application>',
```

The gateway validates the `cf-access-jwt-assertion` header against Cloudflare's
JWKS: signature, `aud`, `iss`, `exp`, `nbf`, then compares the email.

> Only `/gh-login` sits behind Access. The rest of the portal must stay public,
> otherwise the login page itself would be gated.

---

## 8. Email one-time code (optional)

Codes go out through a Cloudflare Email Worker, so no SMTP credentials are
stored anywhere.

### 8.1 Verify the destination address

**Email → Email Routing → Destination addresses → Add**, then click the link
in the confirmation mail. Free plan can only send to verified addresses.

### 8.2 Deploy the worker

```js
// mailer.mjs
export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('method', { status: 405 })
    if (request.headers.get('x-mailer-key') !== env.MAILER_KEY)
      return new Response('forbidden', { status: 403 })
    const { to, subject, text } = await request.json()
    try {
      await env.SEND_EMAIL.send({ to, from: { email: 'login@example.com', name: 'SSO' }, subject, text })
      return new Response('ok')
    } catch (e) {
      return new Response('send failed: ' + e.message, { status: 500 })
    }
  },
}
```

Bindings:

| Type | Name | Value |
|---|---|---|
| `send_email` | `SEND_EMAIL` | (none) |
| `plain_text` | `MAILER_KEY` | a long random string |

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT/workers/scripts/mailer" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -F 'metadata=@metadata.json;type=application/json' \
  -F 'worker.mjs=@mailer.mjs;type=application/javascript+module'
```

`metadata.json`:

```json
{"main_module":"worker.mjs","bindings":[
  {"type":"send_email","name":"SEND_EMAIL"},
  {"type":"plain_text","name":"MAILER_KEY","text":"<your random key>"}
]}
```

Then attach a hostname (**Workers → your worker → Settings → Domains &
Routes → Add custom domain**), e.g. `mailer.example.com`, and put it in the
config:

```js
mailerUrl: 'https://mailer.example.com',
```

Finally, on `/admin → 邮箱验证码登录`, enter the allow-list address and the
mailer key. Send yourself a test code.

---

## 9. Edge guard (optional)

Use this when a service lives on **another** machine. The guard runs next to
the origin, so traffic does not hair-pin through the main gateway.

### 9.1 On the gateway

```bash
cat /opt/sso/data/session.key
```

### 9.2 On the origin machine

```bash
sudo mkdir -p /opt/sso-guard && cd /opt/sso-guard
# copy src/guard.mjs and src/config.mjs from the gateway repo
echo '<session.key contents>' | sudo tee session.key >/dev/null
sudo chmod 600 session.key
```

Set the `guard` block in that machine's `config.mjs`:

```js
guard: {
  port: 27778,
  upstream: { host: '127.0.0.1', port: 27777 },
  authOrigin: 'https://auth.example.com',
  cookieDomain: '.example.com',
  gated: ['/admin', '/admin-app', '/api/admin'],
  sessionKeyPath: '/opt/sso-guard/session.key',
  panelFile: '/opt/sso-guard/panel.json',
  panelCookie: 'session_token',
}
```

```bash
sudo cp deploy/galmaster-guard.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now galmaster-guard
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:27778/
```

Point that hostname's tunnel ingress at `http://localhost:27778` instead of
`3081`.

> Both sides must use the **same** `session.key`, otherwise every cookie and
> ticket is rejected.

---

## 10. Verification checklist

```bash
# gateway alive
curl -s https://auth.example.com/healthz
# → {"ok":true}

# service gated
curl -s -o /dev/null -w '%{http_code}\n' -H 'Accept: text/html' https://app1.example.com/
# → 302

# admin gated
curl -s -o /dev/null -w '%{http_code}\n' https://auth.example.com/admin
# → 302 (to /login)

# static still cached
curl -s -o /dev/null -D - https://app1.example.com/assets/app.js | grep -i cf-cache-status
# → HIT

# path normalisation
for p in '//admin' '/ADMIN' '/%61dmin' '/admin;/'; do
  curl -s -o /dev/null -w "$p %{http_code}\n" -H 'Accept: text/html' "https://app1.example.com$p"
done
# every line must be 302, never 200
```

Then in the browser:

1. Open a service in a private window → login page appears
2. Pass one method → banner says "还需再验证 1 种"
3. Pass a different method → you land on the service
4. Open another service on the same domain → no prompt
5. Sign out → every host redirects to login again

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `502 upstream error` | the origin port is wrong or nothing is listening |
| Login page loads but every method fails | `rpId` does not match the origin's registrable domain |
| Hardware key prompt never appears | the site is not HTTPS, or the key was registered under a different `rpId` |
| GitHub button loops | the Access app path is not exactly `/gh-login`, or `cfAud` is wrong |
| Email code never arrives | the address is not verified in Email Routing, or `MAILER_KEY` differs |
| Signed out but a panel still shows a user | the guard is not stripping the panel cookie — check `guard.panelCookie` |
| `EADDRINUSE` on start | another process holds `port`; `ss -ltnp \| grep 3081` |
| Everything 404 | tunnel ingress catch-all is swallowing the hostname |

Logs:

```bash
sudo journalctl -u galmaster-sso -n 100 --no-pager
sudo journalctl -u galmaster-guard -n 100 --no-pager
tail -f /var/log/sso.log
```
