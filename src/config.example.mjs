// Galmaster SSO — configuration template.
//
//   cp src/config.example.mjs src/config.mjs
//   chmod 600 src/config.mjs
//
// config.mjs is git-ignored. Keep real hostnames, keys and panel
// credentials out of version control.

export const config = {
  // ---- identity of the auth portal -------------------------------------
  authHost: 'auth.example.com',      // where the login UI lives
  rpId: 'example.com',               // WebAuthn relying party ID (registrable suffix of authHost)
  rpName: 'Example SSO',
  ownerEmail: 'owner@example.com',   // only this GitHub/email account may sign in

  // ---- local state ------------------------------------------------------
  dataDir: '/opt/sso/data',          // credentials.json, session.key, bootstrap.key, totp.json live here
  port: 3081,
  dshLogPath: '/var/log/dsh-web.log',// optional: log file used to scrape the DSH token
  totpLabel: 'sso-owner',
  webauthnUser: 'sso-owner',

  // ---- Cloudflare Access (used for the GitHub login path) --------------
  cfTeamDomain: 'yourteam.cloudflareaccess.com',
  cfAud: 'YOUR_ACCESS_APPLICATION_AUD_TAG',

  // ---- outbound mail (Cloudflare Email Worker) -------------------------
  mailerUrl: 'https://mailer.example.com',
  magpieKey: '',

  // ---- logout chain -----------------------------------------------------
  // One representative host per registrable domain. Signing out walks these
  // in order so every host-scoped cookie gets cleared.
  logoutHosts: ['app1.example.com', 'example.com'],

  // ---- proxied services -------------------------------------------------
  // key   = public hostname
  // value = { name, desc, port | origin, tls, cookieDomain, ... }
  services: {
    'app1.example.com': {
      name: 'App One',
      desc: 'First panel',
      port: 8001,                       // 127.0.0.1:8001
      cookieDomain: '.example.com',     // shared session cookie scope
    },
    'app2.example.com': {
      name: 'App Two',
      desc: 'Second panel',
      port: 8899,
      cookieDomain: '.example.com',
      // Panel-specific auto-login hooks, see docs/panels.md
      authHeaders: [{ n: 'x-panel-token', p: '' }],
      injectStorage: { type: 'session', key: 'app2-panel-token' },
    },
    'monitor.example.com': {
      name: 'Monitor',
      desc: 'Public dashboard, admin needs SSO',
      origin: 'http://10.0.0.5:27777',  // remote origin instead of a local port
      gatedPaths: ['/admin', '/admin-app'],
      cookieDomain: '.example.com',
    },
  },

  // ---- panels whose own login the gateway performs for you -------------
  panelTargets: [
    { host: 'app1.example.com', label: 'App One', needsUser: false },
    { host: 'monitor.example.com', label: 'Monitor admin', needsUser: true, alias: 'monitor2.example.com' },
    { host: 'app2.example.com', label: 'App Two', needsUser: false, field: 'panel_password', loginPath: '/panel/login' },
  ],

  // ---- edge guard (only needed when a service lives on another box) ----
  guard: {
    port: 27778,
    upstream: { host: '127.0.0.1', port: 27777 },
    authOrigin: 'https://auth.example.com',
    cookieDomain: '.example.com',
    gated: ['/admin', '/admin-app', '/api/admin'],
    sessionKeyPath: '/opt/sso-guard/session.key',
    panelFile: '/opt/sso-guard/panel.json',
    panelCookie: 'session_token',
  },
}
