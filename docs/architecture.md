**English** | [简体中文](zh-CN/architecture.md)

# Architecture

## Three trust zones

```
public internet
      │  HTTPS
      ▼
Cloudflare edge ── Access (only for /gh-login) ──┐
      │                                          │
      ▼  cloudflared tunnel                     │
auth gateway  (127.0.0.1:3081)  ◄────────────────┘
      │  Host header decides the route
      ├─► auth.example.com      login UI + ticket issuer
      ├─► app1.example.com      session check → proxy to :8001
      ├─► app2.example.com      session check → proxy to :8899
      └─► monitor.example.com   gatedPaths only → proxy to remote origin
```

The gateway listens on loopback only. Cloudflare Tunnel is the sole way in,
so `Host` and `X-Forwarded-*` cannot be forged by a client — Cloudflare
overwrites them.

## Login flow (multi-step)

```
GET  app1.example.com/foo
  → no session cookie
  → 302 https://auth.example.com/sso?next=https://app1.example.com/foo

GET  /sso?next=...
  → no session yet
  → 302 /login?next=...

POST /auth/totp/verify   (method #1)
  → 302 /login?next=...  + Set-Cookie: gm-partial=<signed {m:["totp"],exp}>

POST /auth/email/verify  (method #2, must be different)
  → 302 https://app1.example.com/foo + Set-Cookie: gm-sso=<session>

GET  app1.example.com/foo  (with gm-sso)
  → proxy to upstream
```

`gm-partial` is an HMAC-signed cookie carrying the list of methods already
passed. It expires in ten minutes. The session cookie is only issued once
`methods.length >= 2`.

If fewer than two methods are configured, `requiredSteps()` drops to one so
the operator cannot lock themselves out.

## Cross-domain ticket

When the auth host is on a different registrable domain than the services,
cookies cannot be shared. The gateway issues a ticket instead:

```
payload = base64url({ h: host, p: path, e: expiry, n: nonce })
ticket  = payload + "." + HMAC-SHA256(payload, sessionKey)
```

```
auth.example.com/sso   → 302  https://app1.example.com/_sso?t=<ticket>
app1.example.com/_sso  → verifies signature + host + expiry
                       → 302 to the original path + Set-Cookie
```

Properties:

- 120 second TTL
- single use (consumed payloads are remembered in memory until expiry)
- host-bound — a ticket minted for `app1` is rejected by `app2`
- same key on every node, so the edge guard can validate without calling back

## Cookie scope

Services on the same registrable domain share one cookie:

```
Set-Cookie: gm-sso=...; Domain=.example.com; HttpOnly; Secure; SameSite=Lax
```

Signing out walks `logoutHosts` (one representative host per registrable
domain) and clears the cookie on each, then returns to the auth host.

## Path normalisation

Every authorisation decision runs on a normalised path:

```js
decodeURIComponent → collapse "//" → resolve "." / ".." → drop ";" params → lowercase
```

Without this, `//admin`, `/ADMIN`, `/%61dmin`, `/admin;/ ` and `/admin%2f`
all slipped past a naive `startsWith('/admin')` check. See
`docs/security.md` for the full list of bypasses that were closed.

## Edge guard

A service hosted on another machine gets its own `cloudflared` tunnel. Instead
of hair-pinning traffic through the main gateway, a small guard runs next to
the origin:

```
tunnel → guard (127.0.0.1:27778) → origin (127.0.0.1:27777)
```

It shares only `session.key`, so it can verify the same cookie and ticket
offline. Everything else — the login UI, the credential store — stays on the
auth host.
