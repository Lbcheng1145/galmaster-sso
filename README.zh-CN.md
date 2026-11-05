**简体中文** | [English](README.md)

# Galmaster SSO

一套自建的单点登录网关，用来统一管理一台或多台服务器上的一堆 Web 面板。
建在 Cloudflare Tunnel 之上，一次登录覆盖全部服务，并且会顺手把每个面板
自己的会话也一并登录好。

```
                       ┌──────────────────────┐
   浏览器 ───────────► │  auth.example.com    │  登录界面
                       │  （本网关）           │  WebAuthn · TOTP · GitHub · 邮箱
                       └──────────┬───────────┘
                                  │ 签名票据
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
        app1.example.com    app2.example.com    monitor.example.com
         （本机端口）         （本机端口）         （远端源站）
```

## 它能做什么

- **一次会话，多台主机。** 登录一次，所有 `*.example.com` 服务共用同一个
  cookie，不再逐个提示。
- **默认两步验证。** 必须**两种不同**的方式都通过才算登录成功。可选四种：
  硬件密钥 / Windows Hello、动态验证码（TOTP）、GitHub（借道 Cloudflare
  Access）、邮箱验证码。
- **面板自动登录。** 每个面板有自己的认证机制，网关替你完成那次登录，把拿到
  的 cookie、请求头或存储值交给浏览器。开箱支持五种面板类型，详见
  [docs/panels.md](docs/zh-CN/panels.md)。
- **跨域票据。** 当认证站点和业务站点不在同一个注册域时，用一张短时效的
  HMAC 签名票据把会话传过去。票据一次性，两分钟过期。
- **边缘守卫。** 一个约 300 行、零依赖的伴生程序（`src/guard.mjs`），可以部署
  在另一台机器上，只共享 HMAC 密钥。流量在本地闭环，不用绕回主网关。

## 效果图

![登录页](screenshots/login.png)

完整导览见 **[docs/zh-CN/screenshots.md](docs/zh-CN/screenshots.md)**：四种登录
方式、邮箱验证码面板、多步验证进度、服务入口、后台管理。

## 快速开始

```bash
git clone https://github.com/Lbcheng1145/galmaster-sso.git && cd galmaster-sso
cp src/config.example.mjs src/config.mjs && chmod 600 src/config.mjs
npm install && node src/gateway.mjs
```

这样它只在本地回环上跑起来。其余全部内容——隧道 ingress、DNS、用于 GitHub
登录的 Cloudflare Access、发信用的 Email Worker、systemd 单元、边缘守卫、
验证清单和排错表——都在
**[部署教程](docs/zh-CN/deployment.md)** 里。

## 环境要求

| 组件 | 说明 |
|---|---|
| Node.js ≥ 18 | 用到 `fetch` 和 `crypto.subtle` |
| Cloudflare 上托管的一个域名 | DNS + Tunnel，可选 Access |
| `cloudflared` | 每台机器一条隧道，ingress 指向本网关 |
| HTTPS | WebAuthn 在明文 HTTP 下拒绝工作 |

## 文档

- **[部署教程](docs/zh-CN/deployment.md)** — 从一台裸 VPS 到可用网关的完整
  步骤：隧道、DNS、配置、systemd、首个凭据、GitHub、邮箱验证码、边缘守卫、
  验证清单、排错
- [效果图](docs/zh-CN/screenshots.md) — 每一个界面，附说明
- [架构](docs/zh-CN/architecture.md) — 请求流、票据交接、信任边界
- [面板接入](docs/zh-CN/panels.md) — 每种面板的自动登录是怎么做的
- [安全](docs/zh-CN/security.md) — 威胁模型、已闭合的绕过、已知限制

## 现状

从一个正在运行的个人部署里抽出来的。刻意做得小而依赖少，而不是通用产品：
只有一个所有者账号，没有用户表，配置就是一个 ES 模块。

## 许可证

MIT
