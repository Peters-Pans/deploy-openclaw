# OpenClaw + Cloudflare Tunnel Privacy Deployment Script

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform: Cross-platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-999999.svg)]()
[![Privacy: Enhanced](https://img.shields.io/badge/Privacy-Enhanced-green.svg)](https://github.com/Peters-Pans/deploy-openclaw)

> Securely deploy OpenClaw behind Cloudflare Tunnel — no public IP, no port forwarding, no hassle.  
> **Cross-platform (macOS + Linux) | IPv4 dynamic-friendly | Real IP fully hidden**

[中文文档](README.zh.md)

---

## Features

### Cross-platform (v3.1)

| OS | Package Mgr | Service Mgr | Status |
|----|-------------|-------------|--------|
| macOS 11.0+ | Homebrew | launchd | ✅ |
| Ubuntu 20.04+ / Debian 11+ | apt | systemd | ✅ |
| CentOS 7+ / RHEL 8+ / Rocky / AlmaLinux | yum | systemd | ✅ |
| Fedora 36+ | dnf | systemd | ✅ |

Auto-detects OS — no manual flags needed.

### Architecture Support

| Arch | Status | Notes |
|------|--------|-------|
| x86_64 / amd64 | ✅ | All platforms |
| aarch64 / arm64 | ✅ | macOS Apple Silicon, Linux ARM servers |
| armv7l | ✅ | cloudflared binary only |

### Security Hardening

- **Token stored in file** (mode 600) — never printed to terminal or passed via CLI args
- **Logs in `~/.openclaw/`** (mode 600) — not world-readable `/tmp`
- **DNS backup/restore** — automatic rollback on uninstall
- **Port race prevention** — uses `--force` on start
- **Optional CF Access** — 4-layer defense (Edge → JWT → cloudflared → Token)

### Privacy

- **Real IP fully hidden** — Cloudflare Tunnel reverse proxy
- **Zero public ports** — only listens on 127.0.0.1
- **Automatic HTTPS** — Cloudflare auto-issues SSL certs
- **DNS anti-pollution** — auto-configures DoH (1.1.1.1)

---

## Prerequisites (Before You Run the Script)

The script automates deployment, but **you must complete these steps first**:

### 1. Cloudflare Account & Domain

1. **Create a Cloudflare account** — https://dash.cloudflare.com/sign-up (free tier works)
2. **Register or transfer a domain**
   - Option A: Buy a domain from any registrar (Namecheap, Cloudflare Registrar, etc.)
   - Option B: Use Cloudflare Registrar directly (at-cost pricing, no markup)
3. **Add your domain to Cloudflare**
   - Dashboard → "Add a Site" → enter your domain
   - Choose the Free plan
   - Cloudflare will provide 2 nameservers (e.g. `anna.ns.cloudflare.com`)
4. **Update your domain's nameservers**
   - Go to your domain registrar (where you bought the domain)
   - Replace existing NS records with the Cloudflare ones
   - Wait for propagation (can take up to 24 hours, usually < 1 hour)
   - Cloudflare dashboard will show "Active" when ready

### 2. Prepare a Subdomain for OpenClaw

You need a subdomain that will point to your OpenClaw instance. Examples:
- `claw.yourdomain.com`
- `ai.yourdomain.com`
- `oc.yourdomain.com`

The script will create the DNS record automatically via `cloudflared tunnel route dns`.

### 3. (Optional) Cloudflare Access for Zero Trust

If you want `--enable-access`, prepare these in advance:

**Get your Account ID:**
1. Go to Cloudflare Dashboard → right sidebar → copy "Account ID"

**Create an API Token:**
1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Click "Create Token"
3. Use the "Edit zone DNS" template, then add these permissions:
   - `Zone → DNS → Edit`
   - `Access → Apps and Policies → Edit`
4. Under "Zone Resources", select your domain
5. Click "Continue to summary" → "Create Token"
6. **Copy the token immediately** (it won't be shown again)

### 4. Verify Your Environment

| Check | Command | Expected |
|-------|---------|----------|
| Bash 3.0+ | `bash --version` | 3.0 or higher |
| Internet access | `curl -s https://1.1.1.1` | Connected |
| sudo (Linux) | `sudo whoami` | `root` |
| Domain resolves | `dig +short yourdomain.com` | CF nameservers active |

---

## Quick Start

### Download, Review, Execute

```bash
# Download
curl -fsSL https://raw.githubusercontent.com/Peters-Pans/deploy-openclaw/main/deploy-openclaw.sh -o deploy.sh

# Review the script before running!
less deploy.sh

# Execute
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Detect your OS and install dependencies (Node.js, cloudflared)
2. Prompt for your domain and port
3. Generate a secure auth token and save it to `~/.openclaw/.auth_token`
4. Install and configure OpenClaw (loopback-only)
5. Create a Cloudflare Tunnel and DNS route
6. Set up auto-start service (launchd or systemd)
7. Verify the deployment

### Enable Zero Trust (CF Access)

```bash
./deploy.sh --domain claw.example.com --enable-access
```

You'll be prompted for your API Token, Account ID, and allowed email.

### Pass Token via Environment Variable

```bash
OPENCLAW_TOKEN=$(openssl rand -hex 32) ./deploy.sh --domain claw.example.com
```

### Uninstall

```bash
./deploy.sh --uninstall
```

Restores DNS, removes services, cleans up config. Optionally removes OpenClaw CLI and Cloudflare Tunnel.

---

## Security Architecture

### Default Mode

```
Internet
 → Cloudflare Edge (DDoS / WAF / SSL termination)
 → Cloudflare Tunnel (outbound, IP hidden)
 → OpenClaw Token (gateway.auth.token)
 → OpenClaw UI
```

### Zero Trust Mode (`--enable-access`)

```
Internet
 → Cloudflare Edge (DDoS / WAF)
 → CF Access (email whitelist + optional MFA → RS256 JWT)
 → cloudflared local verification (Origin JWT AUD + signature → 403 if invalid)
 → OpenClaw Token
 → OpenClaw UI
```

Attackers need to break: Cloudflare Access auth + JWT signature + OpenClaw Token.

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--domain <domain>` | Access domain (e.g. `claw.example.com`) |
| `--port <port>` | Listen port (default: 10371) |
| `--enable-access` | Enable Cloudflare Access Zero Trust |
| `--cf-api-token <token>` | CF API Token |
| `--cf-account-id <id>` | CF Account ID |
| `--access-email <email>` | Allowed email for Access |
| `--uninstall` | Uninstall everything |
| `--debug` | Verbose logging |

| Env Variable | Description |
|--------------|-------------|
| `OPENCLAW_TOKEN` | Pass auth token securely (avoids CLI args) |
| `CF_API_TOKEN` | CF API Token (for `--enable-access`) |

---

## File Layout

```
~/.openclaw/
├── openclaw.json         # OpenClaw config
├── .auth_token           # Auth token (mode 600)
├── .dns_backup           # DNS backup (restored on uninstall)
└── deploy-*.log          # Deploy log (mode 600)

~/.cloudflared/
├── config.yml            # Tunnel config
├── cert.pem              # CF auth cert
├── <tunnel-id>.json      # Tunnel credentials
└── tunnel.log            # Tunnel log

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

## Troubleshooting

**DNS not resolving after deploy?**
- Wait 1-5 minutes for propagation
- Check: `dig +short yourdomain.com` should show CF IPs
- Verify tunnel: `cloudflared tunnel list`

**OpenClaw not starting?**
- Check logs: `cat /tmp/openclaw-gateway.err.log` (macOS) or `journalctl -u openclaw-gateway` (Linux)
- Check port: `lsof -i :10371` or `ss -tlnp | grep 10371`

**Tunnel disconnected?**
- Check: `pgrep -f cloudflared`
- Restart: `launchctl start com.cloudflare.cloudflared` (macOS) or `sudo systemctl restart cloudflared-tunnel` (Linux)

**Token lost?**
- File: `cat ~/.openclaw/.auth_token`
- Or: `openclaw config get gateway.auth.token`

---

## License

MIT
