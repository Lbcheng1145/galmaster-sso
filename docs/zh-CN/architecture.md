[English](../architecture.md) | **简体中文**

# 架构

## 三个信任区

```
公网
      │  HTTPS
      ▼
Cloudflare 边缘 ── Access（只覆盖 /gh-login）──┐
      │                                        │
      ▼  cloudflared 隧道                      │
认证网关（127.0.0.1:3081）◄─────────────────────┘
      │  按 Host 头分流
      ├─► auth.example.com      登录界面 + 票据签发
      ├─► app1.example.com      校验会话 → 反代到 :8001
      ├─► app2.example.com      校验会话 → 反代到 :8899
      └─► monitor.example.com   只拦 gatedPaths → 反代到远端源站
```

网关只监听回环地址，Cloudflare Tunnel 是唯一入口。因此 `Host` 和
`X-Forwarded-*` 无法被客户端伪造——Cloudflare 会覆盖它们。

## 登录流程（多步）

```
GET  app1.example.com/foo
  → 没有会话 cookie
  → 302 https://auth.example.com/sso?next=https://app1.example.com/foo

GET  /sso?next=...
  → 还没有会话
  → 302 /login?next=...

POST /auth/totp/verify    （第一种方式）
  → 302 /login?next=...  + Set-Cookie: gm-partial=<签名 {m:["totp"],exp}>

POST /auth/email/verify   （第二种方式，必须不同）
  → 302 https://app1.example.com/foo + Set-Cookie: gm-sso=<会话>

GET  app1.example.com/foo  （带 gm-sso）
  → 反代到上游
```

`gm-partial` 是一张 HMAC 签名的 cookie，里面是「已通过的方式列表」，十分钟
过期。只有 `methods.length >= 2` 时才签发真正的会话 cookie。

如果可用方式不足两种，`requiredSteps()` 会自动降成一步，避免把自己锁在门外。

## 跨域票据

当认证站点和业务站点不在同一个注册域时，cookie 无法共享，网关改用票据：

```
payload = base64url({ h: host, p: path, e: expiry, n: nonce })
ticket  = payload + "." + HMAC-SHA256(payload, sessionKey)
```

```
auth.example.com/sso   → 302  https://app1.example.com/_sso?t=<ticket>
app1.example.com/_sso  → 校验签名、host、有效期
                       → 302 回原路径 + Set-Cookie
```

性质：

- 120 秒有效期
- 一次性（已消费的 payload 会记在内存里直到过期）
- 绑定 host——签发给 `app1` 的票据 `app2` 不收
- 每个节点用同一把密钥，因此边缘守卫可以离线校验，不用回调

## Cookie 作用域

同一注册域下的服务共用一个 cookie：

```
Set-Cookie: gm-sso=...; Domain=.example.com; HttpOnly; Secure; SameSite=Lax
```

退出登录时会沿着 `logoutHosts`（每个注册域一个代表主机）走一遍，逐个清除，
最后回到认证站点。

## 路径归一化

所有鉴权判断都跑在归一化之后的路径上：

```js
decodeURIComponent → 折叠 "//" → 解析 "." / ".." → 去掉 ";" 参数 → 转小写
```

没有这一步的话，`//admin`、`/ADMIN`、`/%61dmin`、`/admin;/ `、`/admin%2f`
全都能绕过朴素的 `startsWith('/admin')` 判断。完整的绕过清单见
[安全文档](security.md)。

## 边缘守卫

部署在另一台机器上的服务有自己的 `cloudflared` 隧道。为了避免流量绕回主网关，
在源站旁边放一个小守卫：

```
隧道 → 守卫（127.0.0.1:27778）→ 源站（127.0.0.1:27777）
```

它只共享 `session.key`，因此能离线校验同样的 cookie 和票据。其余一切——登录
界面、凭据存储——都留在认证主机上。
