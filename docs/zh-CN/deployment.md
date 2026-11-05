[English](../deployment.md) | **简体中文**

# 部署教程

从一台刚开的 VPS 到一套能跑两个服务的网关。每条命令都可以直接复制，占位符
按实际情况替换。

全文约定：

| 占位符 | 含义 | 示例 |
|---|---|---|
| `example.com` | 你的域名，托管在 Cloudflare | `acme.dev` |
| `auth.example.com` | 登录门户的主机名 | `auth.acme.dev` |
| `app1.example.com` | 第一个受保护的服务 | `panel.acme.dev` |
| `<tunnel-id>` | Cloudflare Tunnel 的 UUID | `f79f040c-...` |

---

## 0. 前置条件

| 项目 | 用途 |
|---|---|
| Cloudflare 上托管的一个域名（免费版够用） | DNS + Tunnel + Access |
| 一台有公网 IP 的 Linux 主机 | 1 核就够，网关绝大部分时间闲着 |
| Node.js ≥ 18 | `fetch`、`crypto.subtle` |
| 该主机上的 `cloudflared` | 唯一入站通道 |
| SSH 权限 | 要以 systemd 单元方式运行 |

**不需要开任何入站端口**。网关只绑 `127.0.0.1`，由 Cloudflare Tunnel 主动外连。

```bash
node -v          # v18.x 或更高
cloudflared -v
```

---

## 1. 创建隧道

```bash
cloudflared tunnel login          # 开浏览器授权该 zone
cloudflared tunnel create galmaster-sso
# → Created tunnel galmaster-sso with id <tunnel-id>
cloudflared tunnel token --credential-file <tunnel-id>.json
```

最省事的服务化方式：

```bash
sudo cloudflared service install <token>
sudo systemctl enable --now cloudflared
```

它会把 token 写到 `/etc/cloudflared/token`。这种情况下 ingress 由远端托管
（面板或 API 管理），本地不再写 YAML。

### ingress 规则

所有主机名都指向**同一个**端口——网关按 `Host` 分流：

| 主机名 | 服务 |
|---|---|
| `auth.example.com` | `http://localhost:3081` |
| `app1.example.com` | `http://localhost:3081` |
| `app2.example.com` | `http://localhost:3081` |
| *（兜底）* | `http_status:404` |

用 API 配置：

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

每个主机名一条 CNAME，代理开启，指向隧道：

```
auth.example.com   CNAME  <tunnel-id>.cfargotunnel.com   （已代理）
app1.example.com   CNAME  <tunnel-id>.cfargotunnel.com   （已代理）
```

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records" \
  -H "Authorization: Bearer $CF_TOKEN" -H "content-type: application/json" \
  -d '{"type":"CNAME","name":"auth","content":"'$TUNNEL'.cfargotunnel.com","proxied":true}'
```

---

## 3. 安装网关

```bash
sudo mkdir -p /opt/sso && sudo chown $USER:$USER /opt/sso
git clone https://github.com/Lbcheng1145/galmaster-sso.git /opt/sso
cd /opt/sso
npm install --omit=dev

cp src/config.example.mjs src/config.mjs
chmod 600 src/config.mjs
```

编辑 `src/config.mjs`，最小可用配置：

```js
export const config = {
  authHost: 'auth.example.com',
  rpId: 'example.com',              // authHost 的注册域后缀
  rpName: 'My SSO',
  ownerEmail: 'me@example.com',
  dataDir: '/opt/sso/data',
  port: 3081,
  logoutHosts: ['app1.example.com', 'example.com'],
  services: {
    'app1.example.com': {
      name: 'Panel',
      desc: '我的第一个面板',
      port: 8001,
      cookieDomain: '.example.com',
    },
  },
  panelTargets: [],
  guard: {},
}
```

几个要点：

- `rpId` 必须是**注册域**（`example.com`），不能写完整主机名。WebAuthn 会拒绝
  不在该域之下的 origin。
- `cookieDomain` 让所有 `*.example.com` 服务共用同一个会话。去掉它就退回
  per-host cookie（那时必须依赖票据流程）。
- `logoutHosts` 每个注册域都要有一条，否则退出登录会漏掉某些域。

先手动启动一次，方便看报错：

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

如果目录结构不同，改一下单元里的 `User=`、`WorkingDirectory=` 和日志路径。

---

## 5. 第一个登录凭据

网关首次启动会生成两个文件：

```bash
ls -l /opt/sso/data
# bootstrap.key   ← 恢复通道，务必保密
# session.key     ← 签发会话和票据
```

```bash
cat /opt/sso/data/bootstrap.key
```

打开：

```
https://auth.example.com/auth/setup?key=<bootstrap.key>
```

**先绑动态验证码**——它是唯一不需要额外硬件、任何设备上都能用的方式。用任意
验证器 App 扫码，输 6 位数字。

然后可以再加硬件密钥：在 `/admin` 点 **＋ 添加硬件密钥**，或者访问
`/auth/register?key=<bootstrap.key>`。在哪台设备上注册就绑在哪台设备上——
Windows Hello 留在那台机器上，USB 安全钥匙随身带。

> bootstrap key 永远有效。`/admin` 上那条更短的**邀请链接**只在目标尚未配置
> 时可用，因此配置完成后无法被重放。

---

## 6. 保护第一个服务

把服务的域名指向网关（第 1 步已完成），并确认源站监听在配置里的端口：

```bash
ss -ltnp | grep 8001
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8001/
```

用无痕窗口访问 `https://app1.example.com/`，预期：

```
302 → https://auth.example.com/sso?next=https%3A%2F%2Fapp1.example.com%2F
```

用两种方式登录，回到 `app1.example.com` 时已经带上会话。

静态资源自动豁免鉴权，这样 Cloudflare 还能正常缓存：

```js
// 自动处理，无需配置
/assets/  /plugins/  /fonts/  *.css *.js *.woff2 *.ico
```

如果某个服务需要一个公开路径（用自己的密钥认证的 API），在它的配置项里加
`publicPaths: ['/v1']`。

---

## 7. GitHub 登录（可选）

借道 Cloudflare Access，这样本地不需要保存任何 OAuth 密钥。

1. **Zero Trust → Settings → Authentication → Login methods → Add → GitHub**
   （会在你的 GitHub 账号下创建一个 OAuth App）
2. **Access → Applications → Add → Self-hosted**
   - 应用域名：`auth.example.com`
   - 路径：`gh-login`
   - 会话时长：24h
   - 策略：*Allow* → *Emails* → 只填你自己的邮箱
   - Settings → *Automatic redirect to identity provider*：打开
3. 从应用概览里复制 **AUD tag** 填进 `config.cfAud`，团队域名填进
   `config.cfTeamDomain`

```js
cfTeamDomain: 'yourteam.cloudflareaccess.com',
cfAud: '<从 Access 应用里复制的 AUD tag>',
```

网关会拿 Cloudflare 的 JWKS 校验 `cf-access-jwt-assertion` 头：签名、`aud`、
`iss`、`exp`、`nbf`，最后比对邮箱。

> 只有 `/gh-login` 在 Access 后面。门户其余部分必须保持公开，否则登录页本身
> 也会被挡住。

---

## 8. 邮箱验证码（可选）

验证码通过 Cloudflare Email Worker 发出，所以本地不存任何 SMTP 凭据。

### 8.1 验证收件地址

**Email → Email Routing → Destination addresses → Add**，然后点确认邮件里的
链接。免费版只能发往已验证的地址。

### 8.2 部署 Worker

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

绑定：

| 类型 | 名称 | 值 |
|---|---|---|
| `send_email` | `SEND_EMAIL` | （无） |
| `plain_text` | `MAILER_KEY` | 一串长随机字符 |

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT/workers/scripts/mailer" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -F 'metadata=@metadata.json;type=application/json' \
  -F 'worker.mjs=@mailer.mjs;type=application/javascript+module'
```

`metadata.json`：

```json
{"main_module":"worker.mjs","bindings":[
  {"type":"send_email","name":"SEND_EMAIL"},
  {"type":"plain_text","name":"MAILER_KEY","text":"<你的随机密钥>"}
]}
```

然后给它挂一个主机名（**Workers → 你的 worker → Settings → Domains & Routes
→ Add custom domain**），例如 `mailer.example.com`，写进配置：

```js
mailerUrl: 'https://mailer.example.com',
```

最后在 `/admin → 邮箱验证码登录` 里填白名单邮箱和发信密钥，给自己发一条测试。

---

## 9. 边缘守卫（可选）

当一个服务部署在**另一台**机器上时用它。守卫跑在源站旁边，流量不用绕回主网关。

### 9.1 在网关机器上

```bash
cat /opt/sso/data/session.key
```

### 9.2 在源站机器上

```bash
sudo mkdir -p /opt/sso-guard && cd /opt/sso-guard
# 从网关仓库拷贝 src/guard.mjs 和 src/config.mjs
echo '<session.key 内容>' | sudo tee session.key >/dev/null
sudo chmod 600 session.key
```

在这台机器的 `config.mjs` 里设置 `guard` 段：

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

把该主机名的隧道 ingress 指向 `http://localhost:27778`，而不是 `3081`。

> 两边必须使用**同一把** `session.key`，否则所有 cookie 和票据都会被拒绝。

---

## 10. 验证清单

```bash
# 网关存活
curl -s https://auth.example.com/healthz
# → {"ok":true}

# 服务被拦
curl -s -o /dev/null -w '%{http_code}\n' -H 'Accept: text/html' https://app1.example.com/
# → 302

# 后台被拦
curl -s -o /dev/null -w '%{http_code}\n' https://auth.example.com/admin
# → 302（跳到 /login）

# 静态资源仍被缓存
curl -s -o /dev/null -D - https://app1.example.com/assets/app.js | grep -i cf-cache-status
# → HIT

# 路径归一化
for p in '//admin' '/ADMIN' '/%61dmin' '/admin;/'; do
  curl -s -o /dev/null -w "$p %{http_code}\n" -H 'Accept: text/html' "https://app1.example.com$p"
done
# 每一行都必须是 302，绝不能是 200
```

然后在浏览器里：

1. 无痕窗口打开某个服务 → 出现登录页
2. 通过一种方式 → 顶部提示「还需再验证 1 种」
3. 通过另一种不同的方式 → 落到服务页面
4. 打开同域下的另一个服务 → 不再提示
5. 退出登录 → 每个域都重新跳登录页

---

## 排错

| 现象 | 原因 |
|---|---|
| `502 upstream error` | 源站端口配错，或者根本没在监听 |
| 登录页能开，但每种方式都失败 | `rpId` 和 origin 的注册域不匹配 |
| 硬件密钥弹窗一直不出现 | 站点不是 HTTPS，或密钥是在别的 `rpId` 下注册的 |
| GitHub 按钮来回跳 | Access 应用路径不是正好 `/gh-login`，或 `cfAud` 填错 |
| 邮箱验证码一直收不到 | 地址没在 Email Routing 里验证，或 `MAILER_KEY` 不一致 |
| 已退出登录但面板仍显示用户 | 守卫没剥离面板 cookie——检查 `guard.panelCookie` |
| 启动报 `EADDRINUSE` | 端口被占：`ss -ltnp \| grep 3081` |
| 全部 404 | 隧道 ingress 的兜底规则把主机名吃掉了 |

日志：

```bash
sudo journalctl -u galmaster-sso -n 100 --no-pager
sudo journalctl -u galmaster-guard -n 100 --no-pager
tail -f /var/log/sso.log
```
