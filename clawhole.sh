#!/bin/bash
# ClawHole — OpenClaw + Cloudflare Tunnel 隐私部署脚本 v3.3
# 支持 macOS + Linux (Ubuntu/Debian/CentOS/RHEL/Fedora)
#
# 用法: ./clawhole.sh [选项]

set -e
set -o pipefail

# ========== 全局配置 ==========
readonly SCRIPT_VERSION="3.3.0"
readonly SCRIPT_NAME="clawhole.sh"
readonly DEFAULT_PORT=10371
readonly TUNNEL_NAME="openclaw-tunnel"
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# ========== 延迟初始化的路径变量 ==========
OC_CONFIG_DIR=""
CF_CONFIG_DIR=""
LOG_FILE=""

# ========== 版本比较（纯 bash，不依赖 sort -V）==========
version_gte() {
    local IFS='.'
    local aa bb
    read -ra aa <<< "$1"
    read -ra bb <<< "$2"
    for i in 0 1 2; do
        local a="${aa[$i]:-0}" b="${bb[$i]:-0}"
        [ "$a" -gt "$b" ] && return 0
        [ "$a" -lt "$b" ] && return 1
    done
    return 0
}

# ========== 端口检测（多工具回退）==========
port_in_use() {
    local port="$1"
    lsof -ti ":$port" &>/dev/null && return 0
    ss -tlnp 2>/dev/null | grep -q ":$port " && return 0
    netstat -tlnp 2>/dev/null | grep -q ":$port " && return 0
    return 1
}

# ========== 工具函数 ==========

log() {
    local msg="$1" level="${2:-INFO}" color="$BLUE"
    case "$level" in INFO) color="$BLUE" ;; WARN) color="$YELLOW" ;; ERROR) color="$RED" ;; SUCCESS) color="$GREEN" ;; esac
    if [ -n "$LOG_FILE" ]; then
        echo -e "${color}[${level}]${NC} $msg" | tee -a "$LOG_FILE"
    else
        echo -e "${color}[${level}]${NC} $msg"
    fi
}
info() { log "$1" "INFO"; }
warn() { log "$1" "WARN" >&2; }
error() { log "$1" "ERROR" >&2; exit 1; }
success() { log "$1" "SUCCESS"; }

generate_secure_token() {
    openssl rand -hex 32 2>/dev/null || error "openssl 不可用，无法生成安全 Token。请安装 openssl。"
}

# 安全写入 openclaw 配置项
# Token 通过临时文件传递，不暴露在 ps 中
# 其他值正常写入
oc_config_set() {
    local key="$1" value="$2"
    if [ "$key" = "gateway.auth.token" ]; then
        local tmpf
        tmpf=$(mktemp) || error "无法创建临时文件"
        # trap 保证无论成功失败都清理
        trap 'rm -f "$tmpf"' RETURN
        chmod 600 "$tmpf"
        echo -n "$value" > "$tmpf"
        # 尝试 --file，不支持则报错退出（不再有 ps 可见的 fallback）
        openclaw config set "$key" --file "$tmpf" >> "$LOG_FILE" 2>&1 || \
            error "openclaw config set 不支持 --file，请升级 OpenClaw"
    else
        openclaw config set "$key" "$value" >> "$LOG_FILE" 2>&1
    fi
}

# JSON 解析：优先 jq，回退 grep
json_field() {
    local json="$1" field="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$field" 2>/dev/null
    else
        local key
        key=$(echo "$field" | sed 's/.*\.//')
        echo "$json" | sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" | head -1
    fi
}

# 屏蔽 set -x 对敏感命令的输出（防止 Token 进日志）
# 用法: ( _safe; curl ... ; )
# 在 subshell 里 set +x，不影响父 shell
_safe() { set +x 2>/dev/null; }

# ========== 国际化 ==========

# 自动检测语言或通过 --lang 指定
# 支持: zh (中文，默认), en (English)
LANG_CODE="${LANG_CODE:-}"
if [ -z "$LANG_CODE" ]; then
    case "${LANG:-${LC_ALL:-}}" in
        en*|C|POSIX) LANG_CODE="en" ;;
        *) LANG_CODE="zh" ;;
    esac
fi

_t() {
    local key="$1"
    if [ "$LANG_CODE" = "en" ]; then
        case "$key" in
            checking_deps) echo "Checking dependencies..." ;;
            system_info) echo "System: $OS_NAME $OS_VERSION ($OS_FAMILY) | Pkg: $PKG_MANAGER" ;;
            installing) echo "Installing $1..." ;;
            installed) echo "✓ $1 installed" ;;
            already_installed) echo "✓ $1 already installed" ;;
            update_prompt) echo "Update to latest? (y/n): " ;;
            homebrew_needed) echo "Homebrew required" ;;
            sudo_needed) echo "sudo required for Linux deployment" ;;
            os_version_warn) echo "⚠️  macOS 11.0+ recommended" ;;
            config_wizard) echo "===== Configuration =====" ;;
            domain_prompt) echo "▶ Domain (e.g. claw.example.com): " ;;
            port_prompt) echo "▶ Port (default $DEFAULT_PORT): " ;;
            enter_continue) echo "Press Enter to continue..." ;;
            token_saved) echo "✓ Token → $OC_CONFIG_DIR/.auth_token (600)" ;;
            using_env_token) echo "Using OPENCLAW_TOKEN from environment" ;;
            config_written) echo "✓ Config written" ;;
            config_valid) echo "✓ Config validated" ;;
            starting) echo "Starting $1..." ;;
            start_failed) echo "Failed to start $1" ;;
            running) echo "✓ Running (127.0.0.1:$PORT)" ;;
            not_listening) echo "Not listening on 127.0.0.1:$PORT" ;;
            cf_auth_needed) echo "⚠️  Cloudflare authentication required" ;;
            cf_auth_done) echo "✓ Authenticated" ;;
            cf_auth_exists) echo "✓ Existing auth credentials found" ;;
            reusing_tunnel) echo "⚠️  Reusing tunnel: $1" ;;
            tunnel_created) echo "✓ Tunnel created: $1" ;;
            cred_missing) echo "Credential file missing. Delete old tunnel first: cloudflared tunnel delete $TUNNEL_NAME" ;;
            tunnel_config_done) echo "✓ Tunnel config generated" ;;
            dns_already) echo "⚠️  DNS record already exists" ;;
            dns_done) echo "✓ DNS route configured" ;;
            dns_failed) echo "⚠️  DNS route failed" ;;
            skip_access) echo "Skipping CF Access (--no-access)" ;;
            cf_access_title) echo "===== Cloudflare Access =====" ;;
            team_name_prompt) echo "▶ Zero Trust Team Name (e.g. myteam): " ;;
            email_prompt) echo "▶ Allowed email: " ;;
            creating_app) echo "Creating Access Application..." ;;
            app_created) echo "✓ Application created" ;;
            app_failed) echo "Cannot create Access Application" ;;
            policy_created) echo "✓ Policy created" ;;
            jwt_enabled) echo "✓ Origin JWT verification enabled" ;;
            verifying) echo "===== Deployment Verification =====" ;;
            openclaw_check) echo "OpenClaw listening..." ;;
            tunnel_check) echo "Tunnel process..." ;;
            tunnel_healthy) echo "✓ Tunnel connected" ;;
            tunnel_not_healthy) echo "⚠️  Tunnel process running but not yet connected" ;;
            tunnel_not_found) echo "⚠️  No tunnel process detected" ;;
            domain_check) echo "Domain reachable..." ;;
            deploy_ok) echo "✅ Deployment verified" ;;
            deploy_partial) echo "⚠️  Some checks failed" ;;
            uninstall_title) echo "===== Uninstall =====" ;;
            confirm_uninstall) echo "Confirm uninstall? (y/n): " ;;
            uninstall_oc) echo "Uninstall OpenClaw CLI? (y/n): " ;;
            uninstall_tunnel) echo "Delete Cloudflare Tunnel? (y/n): " ;;
            uninstall_dns) echo "Delete CF DNS record? (y/n): " ;;
            tunnel_delete_failed) echo "⚠️  Tunnel delete failed, keeping ~/.cloudflared" ;;
            no_domain_skip) echo "⚠️  No domain specified, skipping DNS deletion" ;;
            uninstall_done) echo "✅ Uninstall complete" ;;
            deploy_success) echo "✅ Deployment complete!" ;;
            unknown_arg) echo "Unknown argument: $1" ;;
            *) echo "$key" ;;
        esac
    else
        case "$key" in
            checking_deps) echo "检查依赖..." ;;
            system_info) echo "系统: $OS_NAME $OS_VERSION ($OS_FAMILY) | 包管理: $PKG_MANAGER" ;;
            installing) echo "安装 $1..." ;;
            installed) echo "✓ $1 安装成功" ;;
            already_installed) echo "✓ $1 已安装" ;;
            update_prompt) echo "更新到最新版? (y/n): " ;;
            homebrew_needed) echo "需要 Homebrew" ;;
            sudo_needed) echo "Linux 部署需要 sudo" ;;
            os_version_warn) echo "⚠️  建议 macOS 11.0+" ;;
            config_wizard) echo "===== 配置向导 =====" ;;
            domain_prompt) echo "▶ 域名 (如 claw.example.com): " ;;
            port_prompt) echo "▶ 端口 (默认 $DEFAULT_PORT): " ;;
            enter_continue) echo "按 Enter 继续..." ;;
            token_saved) echo "✓ Token → $OC_CONFIG_DIR/.auth_token (600)" ;;
            using_env_token) echo "使用环境变量 OPENCLAW_TOKEN" ;;
            config_written) echo "✓ 配置已写入" ;;
            config_valid) echo "✓ 配置验证通过" ;;
            starting) echo "启动 $1..." ;;
            start_failed) echo "$1 启动失败" ;;
            running) echo "✓ 运行中 (127.0.0.1:$PORT)" ;;
            not_listening) echo "未正确监听 127.0.0.1:$PORT" ;;
            cf_auth_needed) echo "⚠️  需要完成 Cloudflare 认证" ;;
            cf_auth_done) echo "✓ 认证成功" ;;
            cf_auth_exists) echo "✓ 已有认证凭据" ;;
            reusing_tunnel) echo "⚠️  复用隧道: $1" ;;
            tunnel_created) echo "✓ 隧道创建: $1" ;;
            cred_missing) echo "凭据文件不存在。请先删除旧隧道: cloudflared tunnel delete $TUNNEL_NAME" ;;
            tunnel_config_done) echo "✓ Tunnel 配置已生成" ;;
            dns_already) echo "⚠️  DNS 已存在" ;;
            dns_done) echo "✓ DNS 路由成功" ;;
            dns_failed) echo "⚠️  DNS 路由失败" ;;
            skip_access) echo "跳过 CF Access (--no-access)" ;;
            cf_access_title) echo "===== Cloudflare Access =====" ;;
            team_name_prompt) echo "▶ Zero Trust Team Name (如 myteam): " ;;
            email_prompt) echo "▶ 允许的邮箱: " ;;
            creating_app) echo "创建 Access Application..." ;;
            app_created) echo "✓ Application 已创建" ;;
            app_failed) echo "无法创建 Access Application" ;;
            policy_created) echo "✓ Policy 已创建" ;;
            jwt_enabled) echo "✓ Origin JWT 验证已启用" ;;
            verifying) echo "===== 部署验证 =====" ;;
            openclaw_check) echo "OpenClaw 监听..." ;;
            tunnel_check) echo "Tunnel 进程..." ;;
            tunnel_healthy) echo "✓ Tunnel 已连通" ;;
            tunnel_not_healthy) echo "⚠️  Tunnel 进程在但尚未连通" ;;
            tunnel_not_found) echo "⚠️  未检测到 Tunnel 进程" ;;
            domain_check) echo "域名可达性..." ;;
            deploy_ok) echo "✅ 部署验证通过" ;;
            deploy_partial) echo "⚠️  部分检查未通过" ;;
            uninstall_title) echo "===== 卸载 =====" ;;
            confirm_uninstall) echo "确认卸载? (y/n): " ;;
            uninstall_oc) echo "卸载 OpenClaw CLI? (y/n): " ;;
            uninstall_tunnel) echo "删除 Cloudflare Tunnel? (y/n): " ;;
            uninstall_dns) echo "删除 CF DNS 记录? (y/n): " ;;
            tunnel_delete_failed) echo "⚠️  隧道删除失败，保留 ~/.cloudflared" ;;
            no_domain_skip) echo "⚠️  未指定域名，跳过 DNS 删除" ;;
            uninstall_done) echo "✅ 卸载完成" ;;
            deploy_success) echo "✅ 部署成功！" ;;
            unknown_arg) echo "未知参数: $1" ;;
            *) echo "$key" ;;
        esac
    fi
}


# ========== OS 检测 ==========

detect_os() {
    OS_NAME=""
    OS_VERSION=""
    OS_FAMILY=""
    PKG_MANAGER=""

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
            ubuntu|debian|linuxmint|pop)  OS_FAMILY="debian"; PKG_MANAGER="apt" ;;
            centos|rhel|rocky|almalinux|ol|amzn) OS_FAMILY="rhel"; PKG_MANAGER="yum" ;;
            fedora)                        OS_FAMILY="fedora"; PKG_MANAGER="dnf" ;;
            arch|manjaro)                  OS_FAMILY="arch"; PKG_MANAGER="pacman" ;;
            *)                             OS_FAMILY="unknown" ;;
        esac
    else
        OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(uname -r)
        OS_FAMILY="unknown"
    fi
}

pkg_install() {
    local pkg="$1"
    case "$PKG_MANAGER" in
        brew)   brew install "$pkg" >> "$LOG_FILE" 2>&1 ;;
        apt)    sudo apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        yum)    sudo yum install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        dnf)    sudo dnf install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        pacman) sudo pacman -S --noconfirm "$pkg" >> "$LOG_FILE" 2>&1 ;;
        *)      error "不支持的包管理器: $PKG_MANAGER" ;;
    esac
}

check_system_compat() {
    info "系统: $OS_NAME $OS_VERSION ($OS_FAMILY) | 包管理: $PKG_MANAGER"
    case "$OS_FAMILY" in
        macos)
            version_gte "$OS_VERSION" "11.0" || warn "⚠️  建议 macOS 11.0+"
            ;;
        *)
            command -v sudo &>/dev/null || error "Linux 部署需要 sudo"
            ;;
    esac
}

# ========== 依赖安装 ==========

install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        local ver=$(cloudflared --version 2>/dev/null | awk '{print $2}')
        success "✓ cloudflared $ver 已安装"
        return 0
    fi
    info "安装 cloudflared..."
    case "$OS_FAMILY" in
        macos)
            pkg_install "cloudflare/cloudflare/cloudflared"
            ;;
        debian)
            curl -fsSL https://pkg.cloudflare.com/cloudflared/gpg-key | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg 2>> "$LOG_FILE"
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs 2>/dev/null || echo focal) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list >> "$LOG_FILE" 2>&1
            sudo apt-get update >> "$LOG_FILE" 2>&1
            sudo apt-get install -y cloudflared >> "$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            local arch=$(uname -m)
            local rpm_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.rpm"
            sudo rpm -i "$rpm_url" >> "$LOG_FILE" 2>&1 || sudo yum install -y "$rpm_url" >> "$LOG_FILE" 2>&1
            ;;
        *)
            local arch=$(uname -m)
            case "$arch" in x86_64|amd64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;; armv7l) arch="arm" ;; *) error "不支持的架构: $arch" ;; esac
            sudo curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" -o /usr/local/bin/cloudflared
            sudo chmod +x /usr/local/bin/cloudflared
            ;;
    esac
    command -v cloudflared &>/dev/null || error "cloudflared 安装失败"
    local ver=$(cloudflared --version 2>/dev/null | awk '{print $2}')
    success "✓ cloudflared $ver 安装成功"
}

install_nodejs() {
    if command -v node &>/dev/null; then
        local ver=$(node --version 2>/dev/null | cut -d'v' -f2)
        if version_gte "$ver" "18"; then
            success "✓ Node.js $ver 已安装"
            return 0
        fi
        warn "⚠️  Node.js $ver < 18，需要升级"
    fi
    info "安装 Node.js 20..."
    case "$OS_FAMILY" in
        macos)  pkg_install "node" ;;
        debian)
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >> "$LOG_FILE" 2>&1
            sudo apt-get install -y nodejs >> "$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash - >> "$LOG_FILE" 2>&1
            sudo yum install -y nodejs >> "$LOG_FILE" 2>&1
            ;;
        *)  warn "⚠️  请手动安装 Node.js 18+" && return 1 ;;
    esac
    command -v node &>/dev/null || error "Node.js 安装失败"
    local ver=$(node --version 2>/dev/null | cut -d'v' -f2)
    success "✓ Node.js $ver 安装成功"
}

install_openclaw() {
    info "安装 OpenClaw CLI..."
    if command -v openclaw &>/dev/null; then
        local ver=$(openclaw --version 2>/dev/null | head -n1)
        info "已安装 OpenClaw $ver"
        read -p "更新到最新版? (y/n): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 0
    fi
    local npm_root
    npm_root=$(npm root -g 2>/dev/null) || npm_root=""
    if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then
        sudo npm install -g openclaw@latest >> "$LOG_FILE" 2>&1
    else
        npm install -g openclaw@latest >> "$LOG_FILE" 2>&1
    fi
    local ver=$(openclaw --version 2>/dev/null | head -n1)
    success "✓ OpenClaw $ver 安装成功"
}

# ========== 服务管理 ==========

find_openclaw_bin() { command -v openclaw 2>/dev/null || echo "/usr/local/bin/openclaw"; }

service_install() {
    local oc_bin=$(find_openclaw_bin)
    case "$OS_FAMILY" in
        macos) _install_launchd "$oc_bin" ;;
        *)     _install_systemd "$oc_bin" ;;
    esac
}

service_uninstall() {
    case "$OS_FAMILY" in
        macos) _uninstall_launchd ;;
        *)     _uninstall_systemd ;;
    esac
}

service_start() {
    case "$OS_FAMILY" in
        macos)
            launchctl start ai.openclaw.gateway 2>/dev/null || true
            launchctl start com.cloudflare.cloudflared 2>/dev/null || true
            ;;
        *)
            sudo systemctl start openclaw-gateway 2>/dev/null || true
            sudo systemctl start cloudflared-tunnel 2>/dev/null || true
            ;;
    esac
}

service_stop() {
    case "$OS_FAMILY" in
        macos)
            launchctl stop ai.openclaw.gateway 2>/dev/null || true
            launchctl stop com.cloudflare.cloudflared 2>/dev/null || true
            launchctl unload "$HOME/Library/LaunchAgents/ai.openclaw.gateway.plist" 2>/dev/null || true
            launchctl unload "$HOME/Library/LaunchAgents/com.cloudflare.cloudflared.plist" 2>/dev/null || true
            ;;
        *)
            sudo systemctl stop openclaw-gateway 2>/dev/null || true
            sudo systemctl stop cloudflared-tunnel 2>/dev/null || true
            sudo systemctl disable openclaw-gateway 2>/dev/null || true
            sudo systemctl disable cloudflared-tunnel 2>/dev/null || true
            ;;
    esac
}

_install_launchd() {
    local oc_bin="$1"
    local dir="$HOME/Library/LaunchAgents"
    # 动态获取 cloudflared 路径（兼容 Intel / Apple Silicon）
    local cf_bin
    cf_bin=$(command -v cloudflared 2>/dev/null || echo "/opt/homebrew/bin/cloudflared")
    mkdir -p "$dir"
    cat > "$dir/ai.openclaw.gateway.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>ai.openclaw.gateway</string>
    <key>ProgramArguments</key><array><string>$oc_bin</string><string>gateway</string><string>start</string><string>--force</string></array>
    <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict><key>NetworkState</key><true/><key>SuccessfulExit</key><false/></dict>
    <key>StandardOutPath</key><string>/tmp/openclaw-gateway.log</string>
    <key>StandardErrorPath</key><string>/tmp/openclaw-gateway.err.log</string>
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
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict><key>NetworkState</key><true/><key>SuccessfulExit</key><false/><key>Crashed</key><true/></dict>
    <key>StandardOutPath</key><string>/tmp/cloudflared.log</string>
    <key>StandardErrorPath</key><string>/tmp/cloudflared.err.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
EOF
    launchctl unload "$dir/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl load "$dir/ai.openclaw.gateway.plist"
    launchctl unload "$dir/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    launchctl load "$dir/com.cloudflare.cloudflared.plist"
}

_uninstall_launchd() {
    rm -f "$HOME/Library/LaunchAgents/ai.openclaw.gateway.plist"
    rm -f "$HOME/Library/LaunchAgents/com.cloudflare.cloudflared.plist"
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
ReadWritePaths=$HOME/.openclaw /tmp
[Install]
WantedBy=multi-user.target
EOF
    sudo tee /etc/systemd/system/cloudflared-tunnel.service > /dev/null <<EOF
[Unit]
Description=Cloudflare Tunnel
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
    sudo systemctl enable openclaw-gateway
    sudo systemctl enable cloudflared-tunnel
}

_uninstall_systemd() {
    sudo systemctl stop openclaw-gateway 2>/dev/null || true
    sudo systemctl stop cloudflared-tunnel 2>/dev/null || true
    sudo systemctl disable openclaw-gateway 2>/dev/null || true
    sudo systemctl disable cloudflared-tunnel 2>/dev/null || true
    sudo rm -f /etc/systemd/system/openclaw-gateway.service
    sudo rm -f /etc/systemd/system/cloudflared-tunnel.service
    sudo systemctl daemon-reload 2>/dev/null || true
}

# ========== DNS ==========

dns_backup() {
    local backup_file="$OC_CONFIG_DIR/.dns_backup"
    case "$OS_FAMILY" in
        macos)
            local iface=""
            local default_if=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
            if [ -n "$default_if" ]; then
                iface=$(networksetup -listnetworkserviceorder | grep -B1 "$default_if" | head -1 | sed 's/.*Port: \(.*\),.*/\1/')
            fi
            if [ -n "$iface" ]; then
                echo "macos" > "$backup_file"
                echo "$iface" >> "$backup_file"
                networksetup -getdnsservers "$iface" 2>/dev/null >> "$backup_file" || echo "Empty" >> "$backup_file"
                chmod 600 "$backup_file"
                info "DNS 已备份 ($iface)"
            else
                warn "⚠️  无法检测网络接口，跳过 DNS 备份"
            fi
            ;;
        *)
            if [ -f /etc/resolv.conf ]; then
                echo "linux" > "$backup_file"
                cp /etc/resolv.conf "$OC_CONFIG_DIR/.resolv.conf.bak"
                chmod 600 "$backup_file" "$OC_CONFIG_DIR/.resolv.conf.bak"
                info "DNS 已备份"
            fi
            ;;
    esac
}

dns_set_doh() {
    info "配置 DNS (1.1.1.1 / 1.0.0.1)..."
    case "$OS_FAMILY" in
        macos)
            local iface=""
            local default_if=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
            if [ -n "$default_if" ]; then
                iface=$(networksetup -listnetworkserviceorder | grep -B1 "$default_if" | head -1 | sed 's/.*Port: \(.*\),.*/\1/')
            fi
            if [ -n "$iface" ]; then
                networksetup -setdnsservers "$iface" 1.1.1.1 1.0.0.1 2>/dev/null && success "✓ DNS 已设置 ($iface)" || warn "⚠️  DNS 设置失败"
            else
                warn "⚠️  无法检测网络接口，跳过 DNS 设置"
            fi
            ;;
        *)
            if command -v resolvectl &>/dev/null; then
                local iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
                if [ -n "$iface" ]; then
                    sudo resolvectl dns "$iface" 1.1.1.1 1.0.0.1 2>/dev/null && success "✓ DNS (resolvectl, $iface)" || warn "⚠️  resolvectl 失败"
                else
                    warn "⚠️  无法检测默认网卡，跳过 resolvectl"
                fi
            else
                sudo tee /etc/resolv.conf > /dev/null <<'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
options edns0
EOF
                success "✓ DNS (/etc/resolv.conf)"
                warn "⚠️  NetworkManager 可能覆盖此配置"
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
            [ -z "$iface" ] && { warn "⚠️  DNS 备份无接口信息"; rm -f "$backup_file"; return 0; }
            local dns=$(sed -n '3p' "$backup_file")
            if [ "$dns" = "Empty" ] || [ -z "$dns" ]; then
                networksetup -setdnsservers "$iface" "Empty" 2>/dev/null && success "✓ DNS 已恢复 (DHCP)"
            else
                networksetup -setdnsservers "$iface" $dns 2>/dev/null && success "✓ DNS 已恢复"
            fi
            ;;
        linux)
            if [ -f "$OC_CONFIG_DIR/.resolv.conf.bak" ]; then
                sudo cp "$OC_CONFIG_DIR/.resolv.conf.bak" /etc/resolv.conf && success "✓ DNS 已恢复"
                rm -f "$OC_CONFIG_DIR/.resolv.conf.bak"
            fi
            ;;
    esac
    rm -f "$backup_file"
}

# ========== 验证 ==========

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || error "端口 '$port' 无效"
    if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
        error "端口范围: 1024-65535"
    fi
    if port_in_use "$port"; then
        error "端口 $port 已被占用"
    fi
    success "✓ 端口 $port 可用"
}

validate_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]] || error "域名格式无效"
    success "✓ 域名 $1 有效"
}

# ========== 核心功能 ==========

check_dependencies() {
    info "检查依赖..."
    detect_os
    check_system_compat
    [[ "$OS_FAMILY" == "macos" ]] && { command -v brew &>/dev/null || error "需要 Homebrew"; success "✓ Homebrew"; }
    install_nodejs
    install_cloudflared
    success "依赖检查完成"
}

get_user_config() {
    echo ""
    echo -e "${GREEN}===== 配置向导 =====${NC}"
    echo ""
    if [ -z "$DOMAIN" ]; then
        while true; do
            read -p "▶ 域名 (如 claw.example.com): " DOMAIN
            [[ -z "$DOMAIN" ]] && continue
            validate_domain "$DOMAIN"; break
        done
    else
        validate_domain "$DOMAIN"
    fi
    if [ -z "$PORT" ]; then
        read -p "▶ 端口 (默认 $DEFAULT_PORT): " PORT
        PORT="${PORT:-$DEFAULT_PORT}"
    fi
    validate_port "$PORT"
    if [ -n "$OPENCLAW_TOKEN" ]; then
        TOKEN="$OPENCLAW_TOKEN"; info "使用环境变量 OPENCLAW_TOKEN"
    else
        TOKEN=$(generate_secure_token)
    fi
    mkdir -p "$OC_CONFIG_DIR"
    echo -n "$TOKEN" > "$OC_CONFIG_DIR/.auth_token"
    chmod 600 "$OC_CONFIG_DIR/.auth_token"
    success "✓ Token → $OC_CONFIG_DIR/.auth_token (600)"
    echo ""
    read -p "按 Enter 继续..."
    echo ""
}

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
    if port_in_use "$PORT"; then
        success "✓ OpenClaw 运行中 (127.0.0.1:$PORT)"
    else
        error "OpenClaw 未正确监听 127.0.0.1:$PORT"
    fi
}

configure_tunnel() {
    info "配置 Cloudflare Tunnel..."
    if [ ! -f "$HOME/.cloudflared/cert.pem" ]; then
        echo -e "${YELLOW}⚠️  需要完成 Cloudflare 认证${NC}"
        read -p "按 Enter 继续..."
        cloudflared tunnel login >> "$LOG_FILE" 2>&1 || error "认证失败"
        success "✓ 认证成功"
    else
        success "✓ 已有认证凭据"
    fi
    local tunnel_id=""
    if cloudflared tunnel list 2>/dev/null | grep -q "$TUNNEL_NAME"; then
        tunnel_id=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}')
        warn "⚠️  复用隧道: $tunnel_id"
        if [ ! -f "$CF_CONFIG_DIR/$tunnel_id.json" ]; then
            error "凭据文件 $CF_CONFIG_DIR/$tunnel_id.json 不存在。请先删除旧隧道: cloudflared tunnel delete $TUNNEL_NAME"
        fi
    else
        local out=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1)
        tunnel_id=$(echo "$out" | sed -n 's/.*Tunnel ID: *\([0-9a-f-]*\).*/\1/p')
        [[ -z "$tunnel_id" ]] && error "创建失败: $out"
        success "✓ 隧道创建: $tunnel_id"
    fi
    export TUNNEL_ID="$tunnel_id"
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
    local dns_out
    dns_out=$(cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" 2>&1) || { warn "⚠️  DNS 路由失败: $dns_out"; return 0; }
    echo "$dns_out" | grep -qi "already" && warn "⚠️  DNS 已存在" || success "✓ DNS 路由成功"
}

configure_cf_access() {
    [ "$NO_ACCESS" = "true" ] && info "跳过 CF Access (--no-access)" && return 0
    echo -e "${GREEN}===== Cloudflare Access =====${NC}"
    [ -z "$CF_API_TOKEN" ] && { read -s -p "▶ CF API Token: " CF_API_TOKEN; echo ""; }
    [ -z "$CF_ACCOUNT_ID" ] && read -p "▶ CF Account ID: " CF_ACCOUNT_ID
    [ -z "$ACCESS_EMAIL" ] && read -p "▶ 允许的邮箱: " ACCESS_EMAIL
    [ -z "$CF_TEAM_NAME" ] && read -p "▶ Zero Trust Team Name (如 myteam): " CF_TEAM_NAME
    local api="https://api.cloudflare.com/client/v4"

    # 屏蔽 set -x 防止 Token 进日志
    (_safe;
    info "创建 Access Application..."
    local resp=$(curl -s -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
        -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
        -d '{"name":"OpenClaw","domain":"'"$DOMAIN"'","type":"self_hosted","session_duration":"24h","auto_redirect_to_identity":false}' \
        2>> "$LOG_FILE")
    )

    local app_id=$(json_field "$resp" '.result.id')
    local app_aud=$(json_field "$resp" '.result.aud')
    if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
        (_safe;
        local existing=$(curl -s "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
            -H "Authorization: Bearer $CF_API_TOKEN" 2>> "$LOG_FILE")
        )
        if command -v jq &>/dev/null; then
            app_id=$(echo "$existing" | jq -r '.result[] | select(.domain=="'"$DOMAIN"'") | .id' 2>/dev/null)
            app_aud=$(echo "$existing" | jq -r '.result[] | select(.domain=="'"$DOMAIN"'") | .aud' 2>/dev/null)
        else
            app_id=$(echo "$existing" | sed -n '/"domain":"'"$DOMAIN"'"/{n;s/.*"id":"\([^"]*\)".*//p;}' | head -1)
            app_aud=$(echo "$existing" | sed -n '/"domain":"'"$DOMAIN"'"/{n;s/.*"aud":"\([^"]*\)".*//p;}' | head -1)
        fi
    fi
    [ -z "$app_id" ] || [ "$app_id" = "null" ] && error "无法创建 Access Application"
    success "✓ Application: $app_id (AUD: $app_aud)"

    (_safe;
    curl -s -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps/$app_id/policies" \
        -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
        -d '{"name":"Whitelist","decision":"allow","include":[{"email":{"email":"'"$ACCESS_EMAIL"'"}}]}' \
        >> "$LOG_FILE" 2>&1
    )
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

verify_deployment() {
    echo -e "${GREEN}===== 部署验证 =====${NC}"
    local ok=true
    info "OpenClaw 监听..."
    if port_in_use "$PORT"; then
        success "✓ 运行中"
    else
        ok=false
    fi
    info "Tunnel 进程..."
    if pgrep -f "cloudflared.*tunnel" &>/dev/null; then
        success "✓ 进程运行中"
        # 检查隧道是否真正连通
        if cloudflared tunnel info "$TUNNEL_NAME" 2>/dev/null | grep -qi "HEALTHY\|active\|connected"; then
            success "✓ Tunnel 已连通"
        else
            warn "⚠️  Tunnel 进程在但尚未连通（可能需要更多时间握手）"
        fi
    else
        sleep 15
        if pgrep -f "cloudflared.*tunnel" &>/dev/null; then
            success "✓ Tunnel 已启动"
        else
            warn "⚠️  未检测到 Tunnel 进程"
            ok=false
        fi
    fi
    info "域名可达性..."
    local code=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" 2>/dev/null || echo "000")
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] && success "✓ HTTP $code" || warn "⚠️  HTTP $code (DNS 可能需几分钟)"
    echo ""
    [ "$ok" = true ] && success "✅ 部署验证通过" || warn "⚠️  部分检查未通过"
}

uninstall() {
    echo -e "${RED}===== 卸载 =====${NC}"
    read -p "确认卸载? (y/n): " -n 1 -r; echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    openclaw gateway stop 2>/dev/null || true
    service_stop
    service_uninstall
    openclaw config unset gateway.port 2>/dev/null || true
    openclaw config unset gateway.bind 2>/dev/null || true
    openclaw config unset gateway.auth.mode 2>/dev/null || true
    openclaw config unset gateway.auth.token 2>/dev/null || true
    rm -f "$OC_CONFIG_DIR/.auth_token" "$LOG_FILE"
    dns_restore
    read -p "卸载 OpenClaw CLI? (y/n): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local npm_root
        npm_root=$(npm root -g 2>/dev/null) || npm_root=""
        if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then
            sudo npm uninstall -g openclaw 2>/dev/null || true
        else
            npm uninstall -g openclaw 2>/dev/null || true
        fi
    fi
    read -p "删除 Cloudflare Tunnel? (y/n): " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local tid=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}')
        if [ -n "$tid" ]; then
            if cloudflared tunnel delete "$tid" 2>/dev/null; then
                rm -rf "$HOME/.cloudflared"
            else
                warn "⚠️  隧道删除失败，保留 ~/.cloudflared"
            fi
        fi
    fi
    if [ -n "$DOMAIN" ]; then
        read -p "删除 CF DNS 记录? (y/n): " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cloudflared tunnel route dns delete "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null || true
        fi
    else
        warn "⚠️  未指定域名，跳过 DNS 记录删除"
    fi
    success "✅ 卸载完成"
    exit 0
}

show_help() {
    cat <<EOF
ClawHole v$SCRIPT_VERSION — OpenClaw 私有部署

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
  --lang <zh|en>            语言 (默认自动检测)
  --debug                   调试模式 (set -x)
  --help                    帮助

环境变量:
  OPENCLAW_TOKEN            安全传递 Token
  CF_API_TOKEN              CF API Token

支持系统:
  macOS 11.0+ (Intel/Apple Silicon)
  Ubuntu 20.04+ / Debian 11+
  CentOS 7+ / RHEL 8+ / Rocky / AlmaLinux
  Fedora 36+
EOF
    exit 0
}

banner() {
    cat <<EOF

${CYAN}╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ${GREEN}ClawHole v$SCRIPT_VERSION — OpenClaw 私有部署${CYAN}              ║
║                                                            ║
║   ${YELLOW}$OS_NAME $OS_VERSION ($OS_FAMILY) | $PKG_MANAGER${CYAN}                    ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝${NC}

EOF
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain) DOMAIN="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --no-access) NO_ACCESS=true; shift ;;
            --cf-api-token) CF_API_TOKEN="$2"; shift 2 ;;
            --cf-account-id) CF_ACCOUNT_ID="$2"; shift 2 ;;
            --cf-team-name) CF_TEAM_NAME="$2"; shift 2 ;;
            --access-email) ACCESS_EMAIL="$2"; shift 2 ;;
            --uninstall) UNINSTALL=true; shift ;;
            --lang) LANG_CODE="$2"; shift 2 ;;
            --help) show_help ;;
            --debug) DEBUG=1; shift ;;
            *) error "未知参数: $1" ;;
        esac
    done

    # --debug: 启用 set -x（CF API 调用在 subshell 里 _safe 屏蔽）
    [ "${DEBUG:-0}" = "1" ] && set -x

    detect_os

    OC_CONFIG_DIR="$HOME/.openclaw"
    CF_CONFIG_DIR="$HOME/.cloudflared"
    LOG_FILE="$OC_CONFIG_DIR/deploy-$TIMESTAMP.log"
    mkdir -p "$OC_CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    [ "$UNINSTALL" = "true" ] && uninstall

    banner
    check_dependencies
    get_user_config
    dns_backup
    dns_set_doh
    install_openclaw
    configure_openclaw
    configure_tunnel
    configure_cf_access
    service_install
    service_start
    sleep 10
    verify_deployment
    echo ""
    echo -e "${GREEN}✅ 部署成功！${NC}"
    echo -e "  🌐 https://$DOMAIN"
    echo -e "  🔑 cat $OC_CONFIG_DIR/.auth_token"
    echo ""
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $EUID -eq 0 ]] && [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${YELLOW}⚠️  不建议用 root，脚本会按需 sudo${NC}"
        read -p "继续? (y/n): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    [ "${BASH_VERSINFO[0]}" -lt 3 ] && { echo "需要 Bash 3.0+"; exit 1; }
    main "$@"
fi
