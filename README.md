# OpenClaw + Cloudflare Tunnel 隐私部署脚本

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-999999.svg)](https://www.apple.com/macos/)
[![Privacy: Enhanced](https://img.shields.io/badge/Privacy-Enhanced-green.svg)](https://github.com/Peters-Pans/deploy-openclaw.sh)

> 🦞 一键部署 OpenClaw + Cloudflare Tunnel，适配中国大陆动态 IPv4 环境  
> **无需公网 IP | 无需端口转发 | 无需备案 | 真实 IP 完全隐藏**

---

## ✨ 核心特性

### 隐私保护
- ✅ **真实 IP 完全隐藏** - 通过 Cloudflare Tunnel 反向代理
- ✅ **零公网端口暴露** - OpenClaw 仅监听 `127.0.0.1:10371`
- ✅ **动态 IPv4 无感** - 出站连接，不受家庭宽带限制
- ✅ **自动 HTTPS** - Cloudflare 自动签发 SSL 证书
- ✅ **双重认证** - OpenClaw Token + 可选 BasicAuth
- ✅ **安全响应头** - HSTS、CSP、XSS 防护

### 中国大陆优化
- ✅ **绕过 80/443 封禁** - 使用出站连接（非入站）
- ✅ **无需备案** - 服务由 Cloudflare 边缘节点提供
- ✅ **DNS 污染防护** - 支持 DoH 配置
- ✅ **自动重连** - 网络波动后隧道自动恢复
- ✅ **开机自启** - LaunchAgent 配置

### 使用体验
- ✅ **一键部署** - 交互式配置，无需手动编辑
- ✅ **一键卸载** - 完全清理不留残留
- ✅ **端口自定义** - 支持自定义 OpenClaw 监听端口
- ✅ **日志记录** - 详细部署日志便于排查
- ✅ **幂等设计** - 可重复运行不冲突

---

## ⚠️ 重要警告

### 安全警告
1. **切勿在脚本中硬编码敏感信息**
   - ❌ 不要在脚本中写入 `authToken`、`API 密钥`、`真实域名`
   - ✅ 使用交互式输入或环境变量传入
2. **首次运行需完成 Cloudflare 认证**
   - 浏览器会打开授权页面，需登录 Cloudflare 账号
   - 域名需已托管到 Cloudflare DNS
3. **合规性提醒**
   - 个人非商业用途通常无风险
   - 避免提供大规模公开服务（可能触发运营商 ToS）
   - 请遵守当地法律法规

### 技术限制
- **Cloudflare 免费账户限制**
  - Tunnel 速率限制：约 1000 req/min
  - 并发连接数：100
  - 个人使用通常足够，如需更高配额请升级 Pro 计划
- **家庭宽带限制**
  - 部分运营商可能干扰出站连接（罕见）
  - 如遇 Tunnel 频繁断连，建议使用手机热点测试
- **DNS 传播延迟**
  - 新配置的 DNS 记录可能需要 1-5 分钟生效

---

## 📋 系统要求

- **操作系统**: macOS 11.0+ (Intel/Apple Silicon)
- **依赖软件**:
  - [Homebrew](https://brew.sh/) - 包管理器
  - [Node.js](https://nodejs.org/) - OpenClaw 运行环境
  - [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/) - Cloudflare Tunnel 客户端
- **网络环境**:
  - 可访问互联网（出站 443 端口）
  - 域名已托管到 Cloudflare DNS
- **权限要求**:
  - 标准用户权限（无需 sudo）

---

## 🚀 快速开始

### 方式一：一键下载并运行（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/Peters-Pans/deploy-openclaw.sh/main/deploy-openclaw.sh | bash
