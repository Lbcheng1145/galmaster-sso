[English](../security.md) | **简体中文**

# 安全

## 威胁模型

网关是单所有者的：一个运维者、一套凭据、没有用户表。所以值得考虑的对手是
**公网上没有任何凭据的人**，而不是第二个已登录用户。

按重要性排序的资产：

1. 面板本身（shell 权限、模型额度、账单数据）
2. `data/session.key` —— 能伪造任意节点上的任意会话
3. `data/bootstrap.key` —— 恢复通道，永远有效
4. `data/panels.json` —— 明文的面板密码

## 已发现并闭合的绕过

下面每一项都在运行中的实例上复现过，然后才修。

### 路径归一化

朴素的 `startsWith('/admin')` 判断会让下面这些全部通过：

| 请求 | 原因 |
|---|---|
| `//admin` | 协议相对 URL，`new URL` 抛错或解析成 `/` |
| `/ADMIN` | 上游框架大小写不敏感 |
| `/%61dmin` | 上游会做百分号解码 |
| `/admin;/` | 上游会剥掉 matrix 参数 |
| `/admin%2f` | 尾部斜杠被编码 |
| `/admin/../admin` | 判断之后才解析 `..` |

修复方式：先解码、折叠斜杠、解析 `.`/`..`、去掉 `;` 参数、转小写，再做判断。
`isStatic()` 也用同一条归一化路径，否则 `/assets/../api/secret` 会命中公开前缀。

### 畸形请求目标导致进程崩溃

```
GET // HTTP/1.1
→ TypeError: Invalid URL at new URL(req.url, 'http://localhost')
→ 进程退出，systemd 重启
```

一个未认证请求就能让所有服务在重启窗口内不可用；循环发就能一直打下去。
现在 `new URL` 包在 `try` 里，畸形目标返回 400。

### TOTP 可被爆破

原先没有限流，6 位码可以一路试下去。`window: 1` 时每个 30 秒窗口有三个有效
码，手速够快就有现实的成功概率。现在：**每 IP 每 5 分钟 5 次**，外加
**全局每 10 分钟 20 次**，换 IP 也没用。

### WebAuthn challenge 被覆盖

待验证的 challenge 原先是一个全局变量。任何人循环请求
`/auth/login/options`，就能让真实用户刚拿到的 challenge 失效，对方的硬件密钥
登录永远无法完成。现在 challenge 按客户端 IP 分开存。

### 邀请令牌越权

TOTP 已经绑定时，`/auth/totp/setup?key=<invite>` 会渲染**现有的**密钥：

```js
if (!t || t.confirmed) { if (!t) { ...创建... } }   // confirmed → 什么都不做
const uri = totpOf(t.secret).toString()               // ……然后把它泄露出去
```

拿着邀请令牌的人可以读出密钥、算出有效验证码、直接接管。改了两处：已确认的
密钥直接拒绝渲染（409），并且邀请令牌只在目标尚未配置时有效。bootstrap key
仍然是无条件的恢复通道。

### 退出后的登录态回流

面板 cookie 在退出时没有被清，边缘守卫又把它转给了上游，于是已退出的访客仍然
看到登录态的面板。现在守卫在 SSO 未认证时一律剥离面板 cookie——包括 WebSocket
升级，那正是它在页面加载一秒后恢复登录态的路径。

## 已经做到的加固

- 会话和票据签名用 `timingSafeEqual` 比较
- 票据绑定 host、一次性、120 秒过期
- `parseNext` / `safeLogoutNext` 只接受配置内主机上的 `https://` URL
- `/gh-login` 用 JWKS 校验 Cloudflare Access 的 JWT（签名、aud、iss、exp、nbf），
  并锁定所有者邮箱
- 面板凭据从不回传到浏览器；密码输入框永远是空的
- 注入 token 的响应带 `Cache-Control: no-store`
- 所有密钥文件 `0600`；进程以非特权用户运行
- `prefers-reduced-motion` 下所有动画关闭

## 已知限制

这些是刻意的权衡，不是缺陷：

1. **共享 cookie 作用域。** `Domain=.example.com` 意味着任一子域上的 XSS 都能
   读到会话。改成 per-host cookie 能解决，但单点登出就没了，而那正是这套系统
   存在的意义。
2. **TOTP 没有防重放。** 同一个码在 30 秒窗口内可以用两次。加一个已用码缓存
   就能闭合；HTTPS 下实际风险很低。
3. **面板密码明文落盘。** `panels.json` 是 `0600` 且不出机器，但没有加密。
   网关需要明文才能替你去登录。
4. **单节点状态。** `usedTickets` 在进程内存里。理论上票据可以在 120 秒窗口内
   在另一个节点重放一次；host 绑定把影响范围限制在单个主机。
5. **没有审计留痕。** 登录事件会写日志，但没有持久化，也没有外送。
