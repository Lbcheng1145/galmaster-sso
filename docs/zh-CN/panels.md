[English](../panels.md) | **简体中文**

# 面板自动登录

每个面板对「什么是一个会话」的理解都不一样。网关替你把那次登录做掉，然后把结果
交给浏览器。用户不需要再被提示第二次。

凭据存在 `data/panels.json`（网关侧）和 `panel.json`（守卫侧），都是 `0600`，
从不回显到页面。

## 四种传输方式

| 方式 | 网关做了什么 | 配置项 |
|---|---|---|
| **Cookie 注入** | 请求面板的登录接口，把 `Set-Cookie` 抄到自己的响应上 | `authCookie` |
| **请求头注入** | 缓存 token，在每个代理请求上补这个头 | `authHeaders`、`bearerAuth` |
| **存储注入** | 改写面板的 HTML，在它自己的启动脚本之前把值写进 `localStorage` / `sessionStorage` | `injectStorage` |
| **上游 cookie** | 服务端换出 cookie，只注入到上游请求里 | `dsh` |

## 具体例子

### Magpie —— 密钥在 URL 里

Magpie 启动时会打印 `http://127.0.0.1:8899/?k=<key>`。用这个 key 换 cookie
只是一次 GET：

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

### SnowLuma —— 自定义头加 localStorage

它的 cookie 只用于头像（`Path=/avatar`）；真正的凭据是前端存在
`localStorage.snowluma_token` 里的 token，用 `X-SnowLuma-Token` 头发出。两半都要：

```js
authHeaders: [
  { n: 'authorization', p: 'Bearer ' },
  { n: 'x-snowluma-token', p: '' },
],
injectStorage: { type: 'local', key: 'snowluma_token' },
```

注入的片段插在 `<head>` 最前面，这样它会在应用自己的启动检查之前执行：

```html
<script>try{localStorage.setItem("snowluma_token","<token>")}catch(e){}</script>
```

### WorkBuddy —— 请求头加 sessionStorage

思路相同，名字不同。它的首帧闸门在 `<head>` 里同步读取
`sessionStorage['wb-proxy-panel-token']`，所以种子必须抢在那个脚本之前落地：

```js
authHeaders: [{ n: 'x-panel-token', p: '' }],
injectStorage: { type: 'session', key: 'wb-proxy-panel-token' },
```

它的登录接口是 `/panel/login`、字段是 `panel_password`，不是常见的
`/api/login`。

### Komari / Lite Monitor —— cookie，且在守卫后面

这个面板在另一台机器上，所以由守卫执行登录：

```js
// panel.json
{ "username": "...", "password": "..." }
```

```
POST /api/login  {username, password}
  → Set-Cookie: session_token=...
  → 守卫缓存 30 分钟，用 /api/me 复核
```

两个细节很关键：

- 守卫会在**未认证**的请求上剥掉 `session_token`。不剥的话，已退出的浏览器
  仍然带着面板 cookie，面板会老老实实回 `logged_in: true`。
- WebSocket 升级同样要剥。实时面板会通过 `/api/rpc2` 推送用户状态；漏掉升级
  路径的话，页面加载一秒后面板又会把登录态恢复回来。

### DSH —— 从日志里取 token

DSH 启动时会把 token 打到日志里。网关把它捞出来换成 DSH 的 cookie，只注入到
上游请求里——浏览器永远看不到它。

```js
const token = readTokenFromLog(cfg.dshLogPath)   // dsh web: https://.../?token=...
const cookie = await exchange(token)             // 缓存 5 分钟，401 时强制刷新
```

## 接入一个新面板

1. 搞清楚它的认证走哪条路（cookie / 请求头 / 存储 / 上游）。
2. 在 `services` 下加一项。
3. 如果它需要密码，加进 `panelTargets`，后台页面才会渲染出输入框。
4. 登录一次，看日志里是 `panel login ok` 还是被拒的响应体。

被拒时会打印上游状态码和响应体前 120 字节，通常足够判断是字段名写错了。
