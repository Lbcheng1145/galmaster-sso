**English** | [简体中文](zh-CN/security.md)

# Security

## Threat model

The gateway is single-owner: one operator, one credential set, no user table.
The interesting attacker is therefore someone on the public internet with no
credentials, not a logged-in second user.

Assets, in order:

1. The panels themselves (shell access, model quota, billing data)
2. `data/session.key` — forges any session on any node
3. `data/bootstrap.key` — recovery channel, always accepted
4. `data/panels.json` — plaintext panel passwords

## Bypasses that were found and closed

Every item below was reproduced against a running instance before the fix.

### Path normalisation

A naive `startsWith('/admin')` check let all of these through:

| Request | Reason |
|---|---|
| `//admin` | protocol-relative, `new URL` throws or resolves to `/` |
| `/ADMIN` | upstream frameworks are case-insensitive |
| `/%61dmin` | percent-decoded by the upstream |
| `/admin;/` | matrix parameter stripped by the upstream |
| `/admin%2f` | trailing slash encoded |
| `/admin/../admin` | `..` resolved after the check |

Fix: decode, collapse slashes, resolve `.`/`..`, drop `;` params, lowercase —
then decide. `isStatic()` uses the same normalised path, otherwise
`/assets/../api/secret` would match the public prefix.

### Crash on malformed request target

```
GET // HTTP/1.1
→ TypeError: Invalid URL at new URL(req.url, 'http://localhost')
→ process exits, systemd restarts it
```

One unauthenticated request took every service down for the restart window;
a loop keeps them down. `new URL` is now inside `try` and answers 400.

### TOTP brute force

No rate limit meant a 6-digit code could be walked. With `window: 1` there
are three valid codes per 30 s window, so a fast attacker gets a realistic
shot. Now: 5 attempts per IP per 5 min **and** 20 globally per 10 min, so IP
rotation does not help.

### WebAuthn challenge overwrite

The pending challenge was a single global variable. Anyone hitting
`/auth/login/options` in a loop could invalidate the challenge the real user
just received, making hardware-key login impossible. Challenges are now keyed
per client IP.

### Invite token escalation

`/auth/totp/setup?key=<invite>` rendered the **existing** secret when TOTP
was already bound:

```js
if (!t || t.confirmed) { if (!t) { ...create... } }   // confirmed → no-op
const uri = totpOf(t.secret).toString()               // ...then leak it
```

An invite holder could read the secret, generate a valid code and take over.
Two changes: a confirmed secret is refused outright (409), and the invite
token only works while its target is still unconfigured. The bootstrap key
remains the unconditional recovery path.

### Signed-out state leaking back

Panel cookies were not cleared on sign-out, and the edge guard forwarded them
to the origin, so a signed-out visitor still saw a logged-in panel. The guard
now strips the panel cookie whenever SSO is not authenticated — including on
the WebSocket upgrade, which is what restored the state a second after load.

## Hardening that is in place

- Session and ticket signatures use `timingSafeEqual`
- Tickets are host-bound, single-use, 120 s TTL
- `parseNext` / `safeLogoutNext` only accept `https://` URLs on configured hosts
- `/gh-login` verifies the Cloudflare Access JWT against JWKS (signature, aud, iss, exp, nbf) and pins the owner email
- Panel credentials never round-trip to the browser; password inputs are always empty
- Injected tokens are served with `Cache-Control: no-store`
- All secret files are `0600`; the process runs as an unprivileged user
- `prefers-reduced-motion` disables every animation

## Known limits

These are deliberate trade-offs, not bugs:

1. **Shared cookie scope.** `Domain=.example.com` means an XSS on any
   subdomain can read the session. Per-host cookies would fix that but break
   single-sign-out, which is the whole point.
2. **TOTP has no replay guard.** The same code works twice inside its 30 s
   window. Adding a used-code cache would close it; the practical risk is low
   over HTTPS.
3. **Plaintext panel passwords at rest.** `panels.json` is `0600` and never
   leaves the box, but it is not encrypted. The gateway needs the plaintext to
   replay each panel's login.
4. **Single node state.** `usedTickets` is per-process. A ticket could in
   theory be replayed on a different node within its 120 s window; host
   binding keeps the blast radius to one host.
5. **No audit trail.** Login events are logged but not persisted or shipped.
