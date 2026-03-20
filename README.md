# OpenClaw + Cloudflare Tunnel 隐私部署脚本

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-999999.svg)](https://www.apple.com/macos/)
[![Privacy: Enhanced](https://img.shields.io/badge/Privacy-Enhanced-green.svg)](https://github.com/Peters-Pans/deploy-openclaw)

> 🦞 安全部署 OpenClaw + Cloudflare Tunnel，适配中国大陆动态 IPv4 环境  
> **无需公网 IP | 无需端口转发 | 无需备案 | 真实 IP 完全隐藏**

---

## ✨ 核心特性

### 隐私保护
- ✅ **真实 IP 完全隐藏** - 通过 Cloudflare Tunnel 反向代理
- ✅ **零公网端口暴露** - OpenClaw 仅监听 `127.0.0.1`
- ✅ **动态 IPv4 无感** - 出站连接，不受家庭宽带限制
- ✅ **自动 HTTPS** - Cloudflare 自动签发 SSL 证书

### 安全加固 (v3.0)
- ✅ **Token 文件存储** (权限 600) — 不输出到终端，不通过命令行传递
- ✅ **日志权限 600** — 写入 `~/.openclaw/` 而非 `/tmp`
- ✅ **Origin JWT 验证** — 可选 Cloudflare Access 集成，本地验证 JWT
- ✅ **DNS 配置保护** — 修改前自动备份，卸载时自动恢复
- ✅ **端口竞争防护** — 使用 `--force` 启动，防止 TOCTOU
- ✅ **macOS 兼容** — 兼容系统自带 Bash 3.2，不依赖 GNU 工具

### 中国大陆优化
- ✅ **绕过 80/443 封禁** - 使用出站连接（非入站）
- ✅ **无需备案** - 服务由 Cloudflare 边缘节点提供
- ✅ **DNS 污染防护** - 支持 DoH 配置
- ✅ **自动重连** - 网络波动后隧道自动恢复
- ✅ **开机自启** - LaunchAgent 配置

### 使用体验
- ✅ **交互式部署** — 无需手动编辑配置
- ✅ **一键卸载** — 完全清理（含 DNS 恢复）
- ✅ **幂等设计** — 可重复运行不冲突

---

## 🚀 快速开始

### 下载后验证再执行（推荐）

```bash
# 下载脚本
curl -fsSL https://raw.githubusercontent.com/Peters-Pans/deploy-openclaw/main/deploy-openclaw.sh -o deploy.sh

# 查看内容（确认无误后执行）
less deploy.sh
chmod +x deploy.sh
./deploy.sh
```

### 启用 Cloudflare Access (Zero Trust)

```bash
# 额外保护: CF Access 邮箱白名单 + Origin JWT 验证
./deploy.sh --domain claw.example.com --enable-access

# 或通过环境变量传入
CF_API_TOKEN=xxx CF_ACCOUNT_ID=yyy ./deploy.sh --domain claw.example.com --enable-access
```

### 安全传递 Token

```bash
# 通过环境变量（不经过命令行参数）
OPENCLAW_TOKEN=$(openssl rand -hex 32) ./deploy.sh --domain claw.example.com
```

### 卸载

```bash
./deploy.sh --uninstall
```

---

## 🔒 安全架构

### 默认模式（OpenClaw Token）

```
公网请求
 → Cloudflare Edge (DDoS / WAF / SSL)
 → Cloudflare Tunnel (出站连接，IP 隐藏)
 → OpenClaw Token (gateway.auth.token)
 → OpenClaw UI
```

### Zero Trust 模式 (`--enable-access`)

```
公网请求
 → Cloudflare Edge (DDoS / WAF)
 → CF Access (邮箱白名单 + 可选 MFA → RS256 JWT)
 → cloudflared 本地验证 (Origin JWT AUD + 签名 → 无效则 403)
 → OpenClaw Token
 → OpenClaw UI
```

---

## 🔧 配置说明

脚本通过 `openclaw config set` 写入以下配置：

| 配置项 | 值 | 说明 |
|--------|-----|------|
| `gateway.port` | 默认 10371 | Gateway 监听端口 |
| `gateway.bind` | `loopback` | 仅监听 127.0.0.1 |
| `gateway.mode` | `local` | 本地运行模式 |
| `gateway.auth.mode` | `token` | Token 认证 |
| `gateway.auth.token` | 自动生成 | 访问令牌（文件存储） |

### 选项

| 选项 | 说明 |
|------|------|
| `--domain <域名>` | 访问域名 |
| `--port <端口>` | 自定义端口 |
| `--enable-access` | 启用 CF Access Zero Trust |
| `--cf-api-token <token>` | CF API Token |
| `--cf-account-id <id>` | CF Account ID |
| `--access-email <email>` | Access 白名单邮箱 |
| `--uninstall` | 一键卸载 |
| `--debug` | 调试模式 |

### 环境变量

| 变量 | 说明 |
|------|------|
| `OPENCLAW_TOKEN` | 安全传递 Token（替代命令行参数） |
| `CF_API_TOKEN` | CF API Token（配合 `--enable-access`） |

---

## ⚠️ 安全说明

### 已修复的问题 (v3.0)

| 问题 | 状态 | 说明 |
|------|------|------|
| Token 终端明文显示 | ✅ 已修复 | 改为文件存储 (600) |
| `--token` 命令行参数 | ✅ 已移除 | 改用环境变量 |
| 日志文件全局可读 | ✅ 已修复 | 写入 `~/.openclaw/`，权限 600 |
| `noTLSVerify: true` | ✅ 已修复 | 改为 `false` |
| `api.ipify.org` 泄露 IP | ✅ 已移除 | 不再调用第三方 |
| DNS 配置不可回滚 | ✅ 已修复 | 卸载时自动恢复 |
| `grep -oP` 不兼容 | ✅ 已修复 | 改用 `sed` |
| `cloudflared tunnel route dns rm` | ✅ 已修复 | 改为 `delete` |
| `WHITE` 变量未定义 | ✅ 已修复 | 已添加定义 |
| 端口 TOCTOU 竞争 | ✅ 已缓解 | 使用 `--force` 启动 |

### 仍需注意

| 问题 | 风险 | 缓解措施 |
|------|------|----------|
| `curl | bash` | 🔴 高 | README 已改为下载后验证模式 |
| npm 无完整性校验 | 🟠 中 | 建议锁定版本 + `--integrity` |

---

## 📋 系统要求

- **操作系统**: macOS 11.0+ (Intel/Apple Silicon)
- **Bash**: 3.0+（macOS 自带即可）
- **依赖**: Homebrew, Node.js 18+, cloudflared（脚本自动安装）
- **网络**: 可访问互联网（出站 443 端口）
- **域名**: 已托管到 Cloudflare DNS
- **权限**: 标准用户（无需 sudo）

---

## 📁 文件结构

```
~/.openclaw/
├── openclaw.json        # OpenClaw 配置（自动写入）
├── .auth_token          # Token 文件（权限 600）
├── .dns_backup          # DNS 备份（卸载时恢复）
└── deploy-*.log         # 部署日志（权限 600）

~/.cloudflared/
├── config.yml           # Tunnel 配置（含可选 CF Access）
├── cert.pem             # Cloudflare 认证凭据
├── <tunnel-id>.json     # Tunnel 凭据
└── tunnel.log           # Tunnel 日志

~/Library/LaunchAgents/
├── ai.openclaw.gateway.plist       # OpenClaw 开机自启
└── com.cloudflare.cloudflared.plist # Tunnel 开机自启
```

---

## 📖 License

MIT
