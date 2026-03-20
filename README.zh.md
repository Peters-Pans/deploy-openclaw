# 私有化部署 OpenClaw — Cloudflare Zero Trust

> **无公网 IP | 零端口暴露 | 跨平台 (macOS + Linux)**  
> 🦞 适配中国大陆动态 IPv4，免备案，一键部署

[English](README.md)

---

## ✨ 特性

### 跨平台 + 多架构支持 (v3.1)

| 系统 | 包管理 | 服务管理 | 状态 |
|------|--------|----------|------|
| macOS 11.0+ | Homebrew | launchd | ✅ |
| Ubuntu 20.04+ / Debian 11+ | apt | systemd | ✅ |
| CentOS 7+ / RHEL 8+ / Rocky / AlmaLinux | yum | systemd | ✅ |
| Fedora 36+ | dnf | systemd | ✅ |

| 架构 | 状态 | 说明 |
|------|------|------|
| x86_64 / amd64 | ✅ | 所有平台 |
| aarch64 / arm64 | ✅ | macOS Apple Silicon、Linux ARM 服务器 |
| armv7l | ✅ | 仅 cloudflared 二进制 |

脚本自动检测 OS 和架构，无需手动指定。

### 安全加固

- ✅ **Token 文件存储** (权限 600) — 不输出到终端，不通过命令行传递
- ✅ **日志权限 600** — 写入 `~/.openclaw/` 而非 `/tmp`
- ✅ **DNS 备份恢复** — 修改前自动备份，卸载时自动恢复
- ✅ **端口竞争防护** — 使用 `--force` 启动
- ✅ **可选 CF Access** — 四层防线 (Edge → JWT → cloudflared → Token)

### 隐私保护

- ✅ **真实 IP 完全隐藏** — Cloudflare Tunnel 反向代理
- ✅ **零公网端口暴露** — 仅监听 127.0.0.1
- ✅ **自动 HTTPS** — Cloudflare 自动签发 SSL 证书
- ✅ **DNS 污染防护** — 自动配置 DoH (1.1.1.1)

---

## 📋 前置条件（运行脚本前必须完成）

脚本自动化部署流程，但**以下准备工作需要提前完成**：

### 1. 注册 Cloudflare 账号

1. 注册地址：https://dash.cloudflare.com/sign-up （免费即可）
2. 完成邮箱验证

### 2. 准备域名并托管到 Cloudflare

**如果还没有域名：**

| 方式 | 说明 |
|------|------|
| Cloudflare Registrar | 直接在 Cloudflare 注册，成本价无加价（推荐） |
| 其他注册商 | Namecheap、GoDaddy、阿里云万网等，然后转入 Cloudflare |

**将域名接入 Cloudflare：**

1. Cloudflare Dashboard → "Add a Site" → 输入你的域名
2. 选择 Free 套餐
3. Cloudflare 会提供 2 个 Nameserver（如 `anna.ns.cloudflare.com`）
4. 到你的域名注册商处，**替换原有的 NS 记录**为 Cloudflare 提供的
5. 等待生效（最长 24 小时，通常 < 1 小时）
6. Dashboard 显示 "Active" 即可

### 3. 准备一个子域名

脚本会用一个子域名指向 OpenClaw，例如：
- `claw.yourdomain.com`
- `ai.yourdomain.com`
- `oc.yourdomain.com`

脚本会通过 `cloudflared tunnel route dns` 自动创建 DNS 记录，**不需要手动添加**。

### 4.（可选）准备 Cloudflare Access 所需信息

如果要用 `--enable-access`（Zero Trust），提前准备好：

**获取 Account ID：**
1. Cloudflare Dashboard → 右侧边栏 → 复制 "Account ID"

**创建 API Token：**
1. 打开 https://dash.cloudflare.com/profile/api-tokens
2. 点 "Create Token"
3. 选 "Edit zone DNS" 模板，然后添加权限：
   - `Zone → DNS → Edit`
   - `Access → Apps and Policies → Edit`
4. "Zone Resources" 选你的域名
5. "Continue to summary" → "Create Token"
6. **立即复制 Token**（不会再次显示）

### 5. 验证环境

| 检查项 | 命令 | 预期结果 |
|--------|------|----------|
| Bash 3.0+ | `bash --version` | ≥ 3.0 |
| 网络可达 | `curl -s https://1.1.1.1` | 能连通 |
| sudo 权限 (Linux) | `sudo whoami` | `root` |
| 域名已生效 | `dig +short 你的域名` | 返回 CF 的 IP |

---

## 🚀 快速开始

### 下载 → 审查 → 执行

```bash
# 下载
curl -fsSL https://raw.githubusercontent.com/Peters-Pans/deploy-openclaw/main/deploy-openclaw.sh -o deploy.sh

# 审查（强烈建议执行前看看脚本内容）
less deploy.sh

# 执行
chmod +x deploy.sh
./deploy.sh
```

脚本会自动完成：
1. 检测 OS/架构，安装依赖（Node.js、cloudflared）
2. 提示输入域名和端口
3. 生成安全 Token 并存储到 `~/.openclaw/.auth_token`
4. 安装配置 OpenClaw（仅监听 127.0.0.1）
5. 创建 Cloudflare Tunnel + DNS 路由
6. **配置 Cloudflare Access (Zero Trust)** — 提示输入 API Token、Account ID、允许的邮箱
7. 配置开机自启（launchd 或 systemd）
8. 验证部署

### 默认启用 Zero Trust

```bash
./deploy.sh --domain claw.example.com
```

脚本会提示输入 CF API Token、Account ID 和允许登录的邮箱。  
自动启用四层防线：CF 边缘 → Access JWT → cloudflared 验证 → OpenClaw Token。

### 跳过 Zero Trust（不推荐）

```bash
./deploy.sh --domain claw.example.com --no-access
```

仅使用 OpenClaw Token 认证。适用于还没配置好 CF Access 或偏好简单认证的场景。

### 通过环境变量安全传递 Token

```bash
OPENCLAW_TOKEN=$(openssl rand -hex 32) ./deploy.sh --domain claw.example.com
```

### 卸载

```bash
./deploy.sh --uninstall
```

自动恢复 DNS、删除服务、清理配置。可选删除 OpenClaw CLI 和 Cloudflare Tunnel。

---

## 🔒 安全架构

### 默认模式：Zero Trust

```
公网 → CF 边缘 (DDoS/WAF) → CF Access (邮箱白名单 + JWT)
  → cloudflared 本地验证 (Origin JWT AUD + 签名 → 无效则 403)
  → OpenClaw Token → UI
```

攻击者需要同时突破：Cloudflare Access 认证 + JWT 签名伪造 + OpenClaw Token。

### 简单模式 (`--no-access`，不推荐)

```
公网 → CF 边缘 → Tunnel → OpenClaw Token → UI
```

仅依赖 OpenClaw Token。Token 泄露 = 服务暴露。

---

## ⚙️ 选项

| 选项 | 说明 |
|------|------|
| `--domain <域名>` | 访问域名 |
| `--port <端口>` | 监听端口 (默认 10371) |
| `--no-access` | 跳过 CF Access Zero Trust（不推荐） |
| `--cf-api-token <token>` | CF API Token |
| `--cf-account-id <id>` | CF Account ID |
| `--access-email <email>` | Access 白名单邮箱 |
| `--uninstall` | 卸载 |
| `--debug` | 调试模式 |

| 环境变量 | 说明 |
|----------|------|
| `OPENCLAW_TOKEN` | 安全传递 Token（避免经过命令行） |
| `CF_API_TOKEN` | CF API Token |

---

## 📁 文件结构

```
~/.openclaw/
├── openclaw.json         # OpenClaw 配置
├── .auth_token           # Token (权限 600)
├── .dns_backup           # DNS 备份 (卸载时恢复)
└── deploy-*.log          # 日志 (权限 600)

~/.cloudflared/
├── config.yml            # Tunnel 配置
├── cert.pem              # CF 认证凭据
├── <tunnel-id>.json      # Tunnel 凭据
└── tunnel.log            # Tunnel 日志

# macOS
~/Library/LaunchAgents/
├── ai.openclaw.gateway.plist
└── com.cloudflare.cloudflared.plist

# Linux
/etc/systemd/system/
├── openclaw-gateway.service
└── cloudflared-tunnel.service
```

---

## 🔧 故障排查

**部署后域名无法访问？**
- 等待 1-5 分钟 DNS 生效
- 检查：`dig +short 你的域名` 应返回 CF 的 IP
- 验证隧道：`cloudflared tunnel list`

**OpenClaw 启动失败？**
- macOS：`cat /tmp/openclaw-gateway.err.log`
- Linux：`journalctl -u openclaw-gateway`
- 检查端口：`lsof -i :10371` 或 `ss -tlnp | grep 10371`

**Tunnel 断开？**
- 检查进程：`pgrep -f cloudflared`
- 重启：macOS `launchctl start com.cloudflare.cloudflared` / Linux `sudo systemctl restart cloudflared-tunnel`

**Token 丢了？**
- 文件：`cat ~/.openclaw/.auth_token`
- 或：`openclaw config get gateway.auth.token`

---

## 📖 License

MIT
