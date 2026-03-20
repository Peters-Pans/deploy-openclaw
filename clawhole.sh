#!/bin/bash
# ClawHole — OpenClaw + Cloudflare Tunnel 隐私部署脚本 v3.5
# 支持 macOS + Linux (Ubuntu/Debian/CentOS/RHEL/Fedora/Arch)
#
# 用法: ./clawhole.sh [选项]

set -e
set -o pipefail

# ========== 全局常量 ==========
readonly SCRIPT_VERSION="3.5.0"
readonly SCRIPT_NAME="clawhole.sh"
readonly DEFAULT_PORT=10371
readonly TUNNEL_NAME="openclaw-tunnel"
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

OC_CONFIG_DIR=""
CF_CONFIG_DIR=""
LOG_FILE=""

# ========== 日志 ==========
log() {
    local msg="$1" level="${2:-INFO}" color="$BLUE"
    case "$level" in WARN) color="$YELLOW" ;; ERROR) color="$RED" ;; SUCCESS) color="$GREEN" ;; esac
    if [ -n "$LOG_FILE" ]; then
        echo -e "${color}[${level}]${NC} $msg" | tee -a "$LOG_FILE"
    else
        echo -e "${color}[${level}]${NC} $msg"
    fi
}
info() { log "$1" "INFO"; }
warn() { log "$1" "WARN" >&2; }
success() { log "$1" "SUCCESS"; }
error() { log "$1" "ERROR" >&2; exit 1; }

# ========== 敏感命令保护 ==========
_sensitive_begin() {
    case "$-" in *x*) _TRACE_WAS_ON=1 ;; *) _TRACE_WAS_ON=0 ;; esac
    { set +x; } 2>/dev/null
}
_sensitive_end() {
    [ "${_TRACE_WAS_ON:-0}" = "1" ] && set -x
    _TRACE_WAS_ON=0
}

# ========== 版本比较（纯 bash，兼容 3.2+）==========
version_gte() {
    local IFS='.'
    local -a aa bb
    read -ra aa <<< "$1"
    read -ra bb <<< "$2"
    local i
    for i in 0 1 2; do
        local av="${aa[$i]:-0}" bv="${bb[$i]:-0}"
        [ "$av" -gt "$bv" ] && return 0
        [ "$av" -lt "$bv" ] && return 1
    done
    return 0
}

# ========== 端口检测（三重回退）==========
port_in_use() {
    local port="$1"
    lsof -ti ":$port" &>/dev/null && return 0
    ss -tlnp 2>/dev/null | grep -q ":${port} " && return 0
    netstat -tlnp 2>/dev/null | grep -q ":${port} " && return 0
    return 1
}

# ========== JSON 提取（jq 优先，回退 sed）==========
json_field() {
    local json="$1" field="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$field" 2>/dev/null
    else
        local key
        key=$(echo "$field" | sed 's/.*\.\([^.]*\)$/\1/')
        echo "$json" | sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" | head -1
    fi
}

# ========== Token 写入（防 ps 泄露）==========
oc_set_token() {
    local token="$1"
    # 优先 stdin
    if echo -n "$token" | openclaw config set gateway.auth.token --stdin >> "$LOG_FILE" 2>&1; then
        return 0
    fi
    # 回退: 临时文件（trap 保证清理）
    local tmpf
    tmpf=$(mktemp) || error "无法创建临时文件"
    trap 'rm -f "$tmpf"' RETURN
    chmod 600 "$tmpf"
    printf '%s' "$token" > "$tmpf"
    openclaw config set gateway.auth.token --file "$tmpf" >> "$LOG_FILE" 2>&1 || \
    openclaw config set gateway.auth.token "$(cat "$tmpf")" >> "$LOG_FILE" 2>&1 || \
    error "无法写入 OpenClaw Token"
}

oc_config_set() {
    local key="$1" value="$2"
    if [ "$key" = "gateway.auth.token" ]; then
        oc_set_token "$value"
    else
        openclaw config set "$key" "$value" >> "$LOG_FILE" 2>&1
    fi
}

# ========== OS 检测 ==========
detect_os() {
    OS_NAME="" OS_VERSION="" OS_FAMILY="" PKG_MANAGER=""
    if [[ "$(uname)" == "Darwin" ]]; then
        OS_NAME="macos"
        OS_VERSION=$(sw_vers -productVersion)
        OS_FAMILY="macos"
        PKG_MANAGER="brew"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        case "$ID" in
            ubuntu|debian|linuxmint|pop) OS_FAMILY="debian"; PKG_MANAGER="apt" ;;
            centos|rhel|rocky|almalinux|ol|amzn) OS_FAMILY="rhel"; PKG_MANAGER="yum" ;;
            fedora) OS_FAMILY="fedora"; PKG_MANAGER="dnf" ;;
            arch|manjaro) OS_FAMILY="arch"; PKG_MANAGER="pacman" ;;
            *) OS_FAMILY="unknown" ;;
        esac
    else
        OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(uname -r)
        OS_FAMILY="unknown"
    fi
}

pkg_install() {
    case "$PKG_MANAGER" in
        brew) brew install "$1" >> "$LOG_FILE" 2>&1 ;;
        apt) sudo apt-get install -y "$1" >> "$LOG_FILE" 2>&1 ;;
        yum) sudo yum install -y "$1" >> "$LOG_FILE" 2>&1 ;;
        dnf) sudo dnf install -y "$1" >> "$LOG_FILE" 2>&1 ;;
        pacman) sudo pacman -S --noconfirm "$1" >> "$LOG_FILE" 2>&1 ;;
        *) error "不支持的包管理器: $PKG_MANAGER" ;;
    esac
}

check_system_compat() {
    info "系统: $OS_NAME $OS_VERSION ($OS_FAMILY) | 包管理: $PKG_MANAGER"
    case "$OS_FAMILY" in
        macos) version_gte "$OS_VERSION" "11.0" || warn "⚠️  建议 macOS 11.0+" ;;
        *) command -v sudo &>/dev/null || error "Linux 部署需要 sudo" ;;
    esac
}

# ========== 依赖安装 ==========
install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        success "✓ cloudflared $(cloudflared --version 2>/dev/null | awk '{print $2}') 已安装"
        return 0
    fi
    info "安装 cloudflared..."
    case "$OS_FAMILY" in
        macos) pkg_install "cloudflare/cloudflare/cloudflared" ;;
        debian)
            curl -fsSL https://pkg.cloudflare.com/cloudflared/gpg-key | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg 2>> "$LOG_FILE"
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs 2>/dev/null || echo focal) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list >> "$LOG_FILE" 2>&1
            sudo apt-get update >> "$LOG_FILE" 2>&1
            sudo apt-get install -y cloudflared >> "$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            local arch=$(uname -m)
            sudo rpm -i "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.rpm" >> "$LOG_FILE" 2>&1 || sudo yum install -y "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.rpm" >> "$LOG_FILE" 2>&1
            ;;
        *)
            local arch=$(uname -m)
            case "$arch" in x86_64|amd64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;; armv7l) arch="arm" ;; *) error "不支持的架构: $arch" ;; esac
            sudo curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" -o /usr/local/bin/cloudflared
            sudo chmod +x /usr/local/bin/cloudflared
            ;;
    esac
    command -v cloudflared &>/dev/null || error "cloudflared 安装失败"
    success "✓ cloudflared $(cloudflared --version 2>/dev/null | awk '{print $2}') 安装成功"
}

install_nodejs() {
    if command -v node &>/dev/null; then
        local ver=$(node --version 2>/dev/null | cut -c2-)
        if version_gte "$ver" "18"; then
            success "✓ Node.js $ver 已安装"
            return 0
        fi
        warn "⚠️  Node.js $ver < 18，需要升级"
    fi
    info "安装 Node.js 20..."
    case "$OS_FAMILY" in
        macos) pkg_install "node" ;;
        debian)
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >> "$LOG_FILE" 2>&1
            sudo apt-get install -y nodejs >> "$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash - >> "$LOG_FILE" 2>&1
            sudo yum install -y nodejs >> "$LOG_FILE" 2>&1
            ;;
        *) warn "⚠️  请手动安装 Node.js 18+"; return 1 ;;
    esac
    command -v node &>/dev/null || error "Node.js 安装失败"
    success "✓ Node.js $(node --version 2>/dev/null | cut -c2-) 安装成功"
}

install_openclaw() {
    info "安装 OpenClaw CLI..."
    if command -v openclaw &>/dev/null; then
        local ver=$(openclaw --version 2>/dev/null | head -n1)
        info "已安装 OpenClaw $ver"
        read -rp "更新到最新版? (y/n): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 0
    fi
    local npm_root
    npm_root=$(npm root -g 2>/dev/null) || npm_root=""
    if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then
        sudo npm install -g openclaw@latest >> "$LOG_FILE" 2>&1
    else
        npm install -g openclaw@latest >> "$LOG_FILE" 2>&1
    fi
    command -v openclaw &>/dev/null || error "OpenClaw 安装失败"
    success "✓ OpenClaw $(openclaw --version 2>/dev/null | head -n1) 安装成功"
}

check_dependencies() {
    info "检查依赖..."
    detect_os
    check_system_compat
    [[ "$OS_FAMILY" == "macos" ]] && { command -v brew &>/dev/null || error "需要 Homebrew: https://brew.sh"; success "✓ Homebrew"; }
    install_nodejs
    install_cloudflared
    success "依赖检查完成"
}

# ========== 服务管理 ==========
find_openclaw_bin() { command -v openclaw 2>/dev/null || echo "/usr/local/bin/openclaw"; }

_install_launchd() {
    local oc_bin="$1"
    local cf_bin=$(command -v cloudflared 2>/dev/null || echo "/opt/homebrew/bin/cloudflared")
    local dir="$HOME/Library/LaunchAgents"
    mkdir -p "$dir"
    cat > "$dir/ai.openclaw.gateway.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>ai.openclaw.gateway</string>
    <key>ProgramArguments</key><array><string>$oc_bin</string><string>gateway</string><string>start</string><string>--force</string></array>
    <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
    <key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>NetworkState</key><true/><key>SuccessfulExit</key><false/></dict>
    <key>StandardOutPath</key><string>/tmp/openclaw-gateway.log</string><key>StandardErrorPath</key><string>/tmp/openclaw-gateway.err.log</string>
    <key>ThrottleInterval</key><integer>30</integer>
</dict></plist>
EOF
    cat > "$dir/com.cloudflare.cloudflared.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>com.cloudflare.cloudflared</string>
    <key>ProgramArguments</key><array><string>$cf_bin</string><string>tunnel</string><string>--config</string><string>$CF_CONFIG_DIR/config.yml</string><string>run</string><string>$TUNNEL_NAME</string></array>
    <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
    <key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>NetworkState</key><true/><key>SuccessfulExit</key><false/><key>Crashed</key><true/></dict>
    <key>StandardOutPath</key><string>/tmp/cloudflared.log</string><key>StandardErrorPath</key><string>/tmp/cloudflared.err.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
EOF
    launchctl unload "$dir/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl load "$dir/ai.openclaw.gateway.plist"
    launchctl unload "$dir/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    launchctl load "$dir/com.cloudflare.cloudflared.plist"
}

_uninstall_launchd() {
    local dir="$HOME/Library/LaunchAgents"
    launchctl unload "$dir/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl unload "$dir/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    rm -f "$dir/ai.openclaw.gateway.plist" "$dir/com.cloudflare.cloudflared.plist"
}

_install_systemd() {
    local oc_bin="$1"
    local cf_bin=$(command -v cloudflared 2>/dev/null || echo "/usr/local/bin/cloudflared")
    sudo tee /etc/systemd/system/openclaw-gateway.service > /dev/null <<EOF
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$oc_bin gateway start --force
Restart=on-failure
RestartSec=10
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=true
ReadWritePaths=$OC_CONFIG_DIR /tmp
[Install]
WantedBy=multi-user.target
EOF
    sudo tee /etc/systemd/system/cloudflared-tunnel.service > /dev/null <<EOF
[Unit]
Description=Cloudflare Tunnel (ClawHole)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$cf_bin tunnel --config $CF_CONFIG_DIR/config.yml run $TUNNEL_NAME
Restart=on-failure
RestartSec=10
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=true
ReadWritePaths=$CF_CONFIG_DIR /tmp
[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable openclaw-gateway cloudflared-tunnel
}

_uninstall_systemd() {
    sudo systemctl stop openclaw-gateway cloudflared-tunnel 2>/dev/null || true
    sudo systemctl disable openclaw-gateway cloudflared-tunnel 2>/dev/null || true
    sudo rm -f /etc/systemd/system/openclaw-gateway.service /etc/systemd/system/cloudflared-tunnel.service
    sudo systemctl daemon-reload 2>/dev/null || true
}

service_install() {
    case "$OS_FAMILY" in
        macos) _install_launchd "$(find_openclaw_bin)" ;;
        *) _install_systemd "$(find_openclaw_bin)" ;;
    esac
}
service_uninstall() {
    case "$OS_FAMILY" in macos) _uninstall_launchd ;; *) _uninstall_systemd ;; esac
}
service_start() {
    case "$OS_FAMILY" in
        macos) launchctl start ai.openclaw.gateway 2>/dev/null || true; launchctl start com.cloudflare.cloudflared 2>/dev/null || true ;;
        *) sudo systemctl start openclaw-gateway 2>/dev/null || true; sudo systemctl start cloudflared-tunnel 2>/dev/null || true ;;
    esac
}
service_stop() {
    case "$OS_FAMILY" in
        macos) launchctl stop ai.openclaw.gateway 2>/dev/null || true; launchctl stop com.cloudflare.cloudflared 2>/dev/null || true; _uninstall_launchd ;;
        *) sudo systemctl stop openclaw-gateway cloudflared-tunnel 2>/dev/null || true; sudo systemctl disable openclaw-gateway cloudflared-tunnel 2>/dev/null || true ;;
    esac
}

# ========== DNS ==========
_macos_active_iface_name() {
    local default_dev
    default_dev=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
    [ -z "$default_dev" ] && return 1
    networksetup -listnetworkserviceorder 2>/dev/null | grep -B1 "Device: ${default_dev})" | head -1 | sed 's/^([0-9]*) //'
}

dns_backup() {
    local backup_file="$OC_CONFIG_DIR/.dns_backup"
    case "$OS_FAMILY" in
        macos)
            local iface
            iface=$(_macos_active_iface_name 2>/dev/null) || { warn "⚠️  无法检测网络接口，跳过 DNS 备份"; return 0; }
            { echo "macos"; echo "$iface"; networksetup -getdnsservers "$iface" 2>/dev/null || echo "Empty"; } > "$backup_file"
            chmod 600 "$backup_file"
            info "DNS 已备份 ($iface)"
            ;;
        *)
            [ -f /etc/resolv.conf ] && { echo "linux"; cat /etc/resolv.conf; } > "$backup_file" && chmod 600 "$backup_file" && info "DNS 已备份"
            ;;
    esac
}

dns_set() {
    info "配置 DNS → 1.1.1.1 / 1.0.0.1 ..."
    case "$OS_FAMILY" in
        macos)
            local iface
            iface=$(_macos_active_iface_name 2>/dev/null) || { warn "⚠️  无法检测网络接口"; return 0; }
            networksetup -setdnsservers "$iface" 1.1.1.1 1.0.0.1 2>/dev/null && success "✓ DNS 已设置 ($iface)" || warn "⚠️  DNS 设置失败"
            ;;
        *)
            if command -v resolvectl &>/dev/null; then
                local iface=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
                [ -n "$iface" ] && sudo resolvectl dns "$iface" 1.1.1.1 1.0.0.1 2>/dev/null && success "✓ DNS (resolvectl, $iface)" || warn "⚠️  resolvectl 失败"
            else
                sudo tee /etc/resolv.conf > /dev/null <<'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
options edns0
EOF
                success "✓ DNS (/etc/resolv.conf)"
            fi
            ;;
    esac
}

dns_restore() {
    local backup_file="$OC_CONFIG_DIR/.dns_backup"
    [ ! -f "$backup_file" ] && return 0
    local platform=$(sed -n '1p' "$backup_file")
    case "$platform" in
        macos)
            local iface=$(sed -n '2p' "$backup_file")
            [ -z "$iface" ] && { warn "⚠️  DNS 备份损坏"; rm -f "$backup_file"; return 0; }
            local dns_servers=$(sed -n '3,$p' "$backup_file" | tr '\n' ' ' | sed 's/ $//')
            if [ -z "$dns_servers" ] || echo "$dns_servers" | grep -qi "empty"; then
                networksetup -setdnsservers "$iface" "Empty" 2>/dev/null && success "✓ DNS → DHCP"
            else
                networksetup -setdnsservers "$iface" $dns_servers 2>/dev/null && success "✓ DNS → $dns_servers"
            fi
            ;;
        linux)
            sudo tee /etc/resolv.conf > /dev/null < <(sed -n '2,$p' "$backup_file")
            success "✓ DNS 已恢复"
            ;;
    esac
    rm -f "$backup_file"
}

# ========== 验证 ==========
validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || error "端口 '$1' 无效"
    [ "$1" -lt 1024 ] || [ "$1" -gt 65535 ] && error "端口范围: 1024-65535"
    port_in_use "$1" && error "端口 $1 已被占用"
    success "✓ 端口 $1 可用"
}

validate_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]] || error "域名格式无效: $1"
    success "✓ 域名 $1 有效"
}

# ========== 用户配置 ==========
get_user_config() {
    echo ""
    echo -e "${GREEN}===== 配置向导 =====${NC}"
    echo ""
    if [ -z "${DOMAIN:-}" ]; then
        while true; do
            read -rp "▶ 域名 (如 claw.example.com): " DOMAIN
            [ -z "$DOMAIN" ] && continue
            validate_domain "$DOMAIN" && break
        done
    else
        validate_domain "$DOMAIN"
    fi
    if [ -z "${PORT:-}" ]; then
        read -rp "▶ 端口 (默认 $DEFAULT_PORT): " PORT
        PORT="${PORT:-$DEFAULT_PORT}"
    fi
    validate_port "$PORT"
    if [ -n "${OPENCLAW_TOKEN:-}" ]; then
        TOKEN="$OPENCLAW_TOKEN"
        info "使用环境变量 OPENCLAW_TOKEN"
    else
        TOKEN=$(openssl rand -hex 32 2>/dev/null) || error "openssl 不可用，无法生成 Token"
    fi
    mkdir -p "$OC_CONFIG_DIR"
    printf '%s' "$TOKEN" > "$OC_CONFIG_DIR/.auth_token"
    chmod 600 "$OC_CONFIG_DIR/.auth_token"
    success "✓ Token → $OC_CONFIG_DIR/.auth_token (600)"
    echo ""
    read -rp "按 Enter 继续..."
    echo ""
}

# ========== OpenClaw 配置 ==========
configure_openclaw() {
    info "配置 OpenClaw..."
    mkdir -p "$OC_CONFIG_DIR"
    oc_config_set gateway.port "$PORT"
    oc_config_set gateway.bind "loopback"
    oc_config_set gateway.mode "local"
    oc_config_set gateway.auth.mode "token"
    oc_config_set gateway.auth.token "$TOKEN"
    success "✓ 配置已写入"
    openclaw config validate >> "$LOG_FILE" 2>&1 || error "配置验证失败"
    success "✓ 配置验证通过"
    openclaw gateway stop 2>/dev/null || true
    pkill -f "openclaw.*gateway" 2>/dev/null || true
    sleep 2
    info "启动 OpenClaw..."
    openclaw gateway start --force >> "$LOG_FILE" 2>&1 || error "启动失败"
    sleep 5
    port_in_use "$PORT" && success "✓ OpenClaw 运行中 (127.0.0.1:$PORT)" || error "未监听"
}

# ========== Cloudflare Tunnel ==========
configure_tunnel() {
    info "配置 Cloudflare Tunnel..."
    if [ ! -f "$CF_CONFIG_DIR/cert.pem" ]; then
        echo -e "${YELLOW}⚠️  需要完成 Cloudflare 认证${NC}"
        read -rp "按 Enter 继续..."
        cloudflared tunnel login >> "$LOG_FILE" 2>&1 || error "认证失败"
        success "✓ 认证成功"
    else
        success "✓ 已有认证凭据"
    fi
    local tunnel_id=""
    if cloudflared tunnel list 2>/dev/null | grep -qw "$TUNNEL_NAME"; then
        tunnel_id=$(cloudflared tunnel list 2>/dev/null | awk -v name="$TUNNEL_NAME" '$0 ~ name {print $1; exit}')
        warn "⚠️  复用隧道: $tunnel_id"
        [ ! -f "$CF_CONFIG_DIR/${tunnel_id}.json" ] && error "凭据文件 $CF_CONFIG_DIR/${tunnel_id}.json 不存在。请删除旧隧道: cloudflared tunnel delete $TUNNEL_NAME"
    else
        local create_out
        create_out=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1) || error "创建失败: $create_out"
        tunnel_id=$(echo "$create_out" | sed -n 's/.*Tunnel ID: *\([0-9a-f-]*\).*/\1/p')
        [ -z "$tunnel_id" ] && error "无法解析 Tunnel ID: $create_out"
        success "✓ 隧道创建: $tunnel_id"
    fi
    TUNNEL_ID="$tunnel_id"
    mkdir -p "$CF_CONFIG_DIR"
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $tunnel_id
credentials-file: $CF_CONFIG_DIR/$tunnel_id.json
protocol: http2
ingress:
  - hostname: $DOMAIN
    service: http://127.0.0.1:$PORT
    originRequest:
      noTLSVerify: false
      httpHostHeader: $DOMAIN
      connectTimeout: 30s
      keepAliveConnections: 100
      keepAliveTimeout: 90s
  - service: http_status:404
logfile: $CF_CONFIG_DIR/tunnel.log
loglevel: info
EOF
    success "✓ Tunnel 配置已生成"
    info "配置 DNS 路由..."
    local dns_out dns_exit=0
    dns_out=$(cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" 2>&1) || dns_exit=$?
    if [ "$dns_exit" -ne 0 ]; then
        echo "$dns_out" | grep -qi "already\|exists" && warn "⚠️  DNS 已存在" || warn "⚠️  DNS 失败: $dns_out"
    else
        success "✓ DNS 路由成功"
    fi
}

# ========== Cloudflare Access ==========
configure_cf_access() {
    [ "${NO_ACCESS:-false}" = "true" ] && info "跳过 CF Access (--no-access)" && return 0
    echo -e "${GREEN}===== Cloudflare Access =====${NC}"
    [ -z "${CF_API_TOKEN:-}" ] && { read -rsp "▶ CF API Token: " CF_API_TOKEN; echo ""; }
    [ -z "${CF_ACCOUNT_ID:-}" ] && read -rp "▶ CF Account ID: " CF_ACCOUNT_ID
    [ -z "${ACCESS_EMAIL:-}" ] && read -rp "▶ 允许的邮箱: " ACCESS_EMAIL
    [ -z "${CF_TEAM_NAME:-}" ] && read -rp "▶ Zero Trust Team Name (如 myteam): " CF_TEAM_NAME
    local api="https://api.cloudflare.com/client/v4"
    info "创建 Access Application..."
    local resp app_id app_aud
    _sensitive_begin
    resp=$(curl -sf -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
        -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
        -d "{\"name\":\"OpenClaw\",\"domain\":\"$DOMAIN\",\"type\":\"self_hosted\",\"session_duration\":\"24h\",\"auto_redirect_to_identity\":false}" \
        2>> "$LOG_FILE") || resp=""
    _sensitive_end
    app_id=$(json_field "$resp" '.result.id')
    app_aud=$(json_field "$resp" '.result.aud')
    if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
        local existing_resp
        _sensitive_begin
        existing_resp=$(curl -sf "$api/accounts/$CF_ACCOUNT_ID/access/apps" -H "Authorization: Bearer $CF_API_TOKEN" 2>> "$LOG_FILE") || existing_resp=""
        _sensitive_end
        if command -v jq &>/dev/null; then
            app_id=$(echo "$existing_resp" | jq -r ".result[] | select(.domain==\"$DOMAIN\") | .id" 2>/dev/null | head -1)
            app_aud=$(echo "$existing_resp" | jq -r ".result[] | select(.domain==\"$DOMAIN\") | .aud" 2>/dev/null | head -1)
        else
            app_id=$(echo "$existing_resp" | sed -n "s/.*\"domain\":\"$DOMAIN\".*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
            app_aud=$(echo "$existing_resp" | sed -n "s/.*\"domain\":\"$DOMAIN\".*\"aud\":\"\([^\"]*\)\".*/\1/p" | head -1)
        fi
    fi
    [ -z "$app_id" ] || [ "$app_id" = "null" ] && error "无法创建 Access Application"
    success "✓ Application: $app_id (AUD: $app_aud)"
    _sensitive_begin
    curl -sf -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps/$app_id/policies" \
        -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
        -d "{\"name\":\"Whitelist\",\"decision\":\"allow\",\"include\":[{\"email\":{\"email\":\"$ACCESS_EMAIL\"}}]}" \
        >> "$LOG_FILE" 2>&1 || warn "⚠️  Policy 创建失败"
    _sensitive_end
    success "✓ Policy 已创建"
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $TUNNEL_ID
credentials-file: $CF_CONFIG_DIR/$TUNNEL_ID.json
protocol: http2
ingress:
  - hostname: $DOMAIN
    service: http://127.0.0.1:$PORT
    originRequest:
      noTLSVerify: false
      httpHostHeader: $DOMAIN
      connectTimeout: 30s
      keepAliveConnections: 100
      keepAliveTimeout: 90s
      access:
        required: true
        teamName: "${CF_TEAM_NAME}.cloudflareaccess.com"
        audTag: ["$app_aud"]
  - service: http_status:404
logfile: $CF_CONFIG_DIR/tunnel.log
loglevel: info
EOF
    success "✓ Origin JWT 验证已启用"
}

# ========== 部署验证 ==========
verify_deployment() {
    echo -e "${GREEN}===== 部署验证 =====${NC}"
    local ok=true
    info "OpenClaw..."
    port_in_use "$PORT" && success "✓ 运行中" || { warn "⚠️  未监听"; ok=false; }
    info "Tunnel..."
    local waited=0
    while ! pgrep -f "cloudflared.*tunnel" &>/dev/null; do sleep 5; waited=$((waited+5)); [ "$waited" -ge 30 ] && break; done
    if pgrep -f "cloudflared.*tunnel" &>/dev/null; then
        success "✓ 进程运行中"
        if cloudflared tunnel info "$TUNNEL_NAME" 2>/dev/null | grep -qiE "HEALTHY|active|connected"; then
            success "✓ Tunnel 已连通"
        else
            warn "⚠️  Tunnel 尚未连通"
        fi
    else
        warn "⚠️  未检测到进程"; ok=false
    fi
    info "域名..."
    local code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$DOMAIN" 2>/dev/null || echo "000")
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] && success "✓ HTTP $code" || warn "⚠️  HTTP $code"
    echo ""
    [ "$ok" = true ] && success "✅ 验证通过" || warn "⚠️  部分检查未通过"
}

# ========== 卸载 ==========
uninstall() {
    echo -e "${RED}===== 卸载 =====${NC}"
    read -rp "确认卸载? (y/n): " -n 1 -r; echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    openclaw gateway stop 2>/dev/null || true
    service_stop
    service_uninstall
    openclaw config unset gateway.port 2>/dev/null || true
    openclaw config unset gateway.bind 2>/dev/null || true
    openclaw config unset gateway.auth.mode 2>/dev/null || true
    openclaw config unset gateway.auth.token 2>/dev/null || true
    rm -f "$OC_CONFIG_DIR/.auth_token"
    dns_restore
    read -rp "卸载 OpenClaw CLI? (y/n): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local npm_root; npm_root=$(npm root -g 2>/dev/null) || npm_root=""
        if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then sudo npm uninstall -g openclaw 2>/dev/null || true; else npm uninstall -g openclaw 2>/dev/null || true; fi
        success "✓ OpenClaw 已卸载"
    fi
    read -rp "删除 Cloudflare Tunnel? (y/n): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local tid; tid=$(cloudflared tunnel list 2>/dev/null | awk -v name="$TUNNEL_NAME" '$0 ~ name {print $1; exit}')
        if [ -n "$tid" ]; then
            if cloudflared tunnel delete "$tid" 2>/dev/null; then rm -rf "$CF_CONFIG_DIR"; success "✓ 隧道和 ~/.cloudflared 已删除"
            else warn "⚠️  删除失败，保留 $CF_CONFIG_DIR"; fi
        fi
    fi
    if [ -n "${DOMAIN:-}" ]; then
        read -rp "删除 DNS 记录? (y/n): " -n 1 -r; echo
        [[ $REPLY =~ ^[Yy]$ ]] && { cloudflared tunnel route dns delete "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null && success "✓ DNS 已删除" || warn "⚠️  删除失败"; }
    fi
    rm -f "$LOG_FILE"
    success "✅ 卸载完成"
    exit 0
}

# ========== Banner / Help ==========
banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗"
    echo -e "║${GREEN}  ClawHole v${SCRIPT_VERSION} — OpenClaw 隐私部署${CYAN}                   ║"
    echo -e "║${YELLOW}  ${OS_NAME} ${OS_VERSION} (${OS_FAMILY}) | ${PKG_MANAGER}${CYAN}                        ║"
    echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    cat <<EOF
ClawHole v${SCRIPT_VERSION} — OpenClaw + Cloudflare Tunnel 隐私部署

用法: ./$SCRIPT_NAME [选项]

选项:
  --domain <域名>           访问域名
  --port <端口>             监听端口 (默认 $DEFAULT_PORT)
  --no-access               跳过 CF Access (不推荐)
  --cf-api-token <token>    CF API Token
  --cf-account-id <id>      CF Account ID
  --cf-team-name <name>     Zero Trust Team Name
  --access-email <email>    Access 白名单邮箱
  --uninstall               卸载
  --debug                   调试模式 (set -x)
  --help                    帮助

环境变量:
  OPENCLAW_TOKEN            安全传递 Token
  CF_API_TOKEN              CF API Token

支持系统:
  macOS 11.0+ / Ubuntu 20.04+ / Debian 11+
  CentOS 7+ / RHEL 8+ / Fedora 36+ / Arch Linux
EOF
    exit 0
}

# ========== 主流程 ==========
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain) DOMAIN="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --no-access) NO_ACCESS=true; shift ;;
            --cf-api-token) CF_API_TOKEN="$2"; shift 2 ;;
            --cf-account-id) CF_ACCOUNT_ID="$2"; shift 2 ;;
            --cf-team-name) CF_TEAM_NAME="$2"; shift 2 ;;
            --access-email) ACCESS_EMAIL="$2"; shift 2 ;;
            --uninstall) UNINSTALL=true; shift ;;
            --debug) DEBUG=1; shift ;;
            --help) show_help ;;
            *) echo "未知参数: $1"; show_help ;;
        esac
    done
    [ "${DEBUG:-0}" = "1" ] && set -x
    detect_os
    OC_CONFIG_DIR="$HOME/.openclaw"
    CF_CONFIG_DIR="$HOME/.cloudflared"
    LOG_FILE="$OC_CONFIG_DIR/deploy-${TIMESTAMP}.log"
    mkdir -p "$OC_CONFIG_DIR"
    touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
    [ "${UNINSTALL:-false}" = "true" ] && uninstall
    banner
    check_dependencies
    get_user_config
    dns_backup
    dns_set
    install_openclaw
    configure_openclaw
    configure_tunnel
    configure_cf_access
    service_install
    service_start
    sleep 10
    verify_deployment
    echo ""
    echo -e "${GREEN}✅ 部署完成！${NC}"
    echo -e "  🌐 https://$DOMAIN"
    echo -e "  🔑 cat $OC_CONFIG_DIR/.auth_token"
    echo ""
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ "${BASH_VERSINFO[0]}" -lt 3 ] || { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
        echo "错误: 需要 Bash 3.2+ (当前: $BASH_VERSION)"
        exit 1
    fi
    if [[ $EUID -eq 0 ]] && [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${YELLOW}⚠️  不建议用 root，脚本会按需 sudo${NC}"
        read -rp "继续? (y/n): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    main "$@"
fi
