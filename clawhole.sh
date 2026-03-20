#!/bin/bash
# ClawHole — OpenClaw + Cloudflare Tunnel 隐私部署脚本 v3.5
# 支持 macOS + Linux (Ubuntu/Debian/CentOS/RHEL/Fedora/Arch)
#
# 用法: ./clawhole.sh [选项]
#   --domain <域名>         访问域名
#   --port <端口>           监听端口 (默认 10371)
#   --no-access             跳过 Cloudflare Access
#   --cf-api-token <token>  CF API Token
#   --cf-account-id <id>    CF Account ID
#   --cf-team-name <name>   Zero Trust Team Name
#   --access-email <email>  Access 白名单邮箱
#   --uninstall             卸载所有组件
#   --debug                 调试模式 (set -x，敏感命令除外)
#   --help                  显示帮助
#
# 环境变量:
#   OPENCLAW_TOKEN          预设 Token（避免交互输入）
#   CF_API_TOKEN            预设 CF API Token

set -e
set -o pipefail

# ============================================================
# 全局常量
# ============================================================
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

# 延迟初始化（在 main() 里赋值，保证 log() 安全使用）
OC_CONFIG_DIR=""
CF_CONFIG_DIR=""
LOG_FILE=""

# ============================================================
# 日志
# ============================================================
log() {
    local msg="$1" level="${2:-INFO}"
    local color="$BLUE"
    case "$level" in
        WARN)    color="$YELLOW" ;;
        ERROR)   color="$RED" ;;
        SUCCESS) color="$GREEN" ;;
    esac
    if [ -n "$LOG_FILE" ]; then
        echo -e "${color}[${level}]${NC} $msg" | tee -a "$LOG_FILE"
    else
        echo -e "${color}[${level}]${NC} $msg"
    fi
}
info()    { log "$1" "INFO"; }
warn()    { log "$1" "WARN" >&2; }
success() { log "$1" "SUCCESS"; }
error()   { log "$1" "ERROR" >&2; exit 1; }

# ============================================================
# 敏感命令保护：临时关闭 set -x，执行后恢复
# 必须在父 shell 中调用，不能用 subshell（否则变量无法返回）
# 用法:
#   _sensitive_begin
#   result=$(curl ...)
#   _sensitive_end
# ============================================================
_sensitive_begin() {
    # 记录当前是否开启了 set -x
    case "$-" in *x*) _TRACE_WAS_ON=1 ;; *) _TRACE_WAS_ON=0 ;; esac
    { set +x; } 2>/dev/null
}
_sensitive_end() {
    [ "${_TRACE_WAS_ON:-0}" = "1" ] && set -x
    _TRACE_WAS_ON=0
}

# ============================================================
# 版本比较（纯 bash，不依赖 sort -V，兼容 Bash 3.2+）
# version_gte A B：若 A >= B 返回 0，否则返回 1
# ============================================================
version_gte() {
    local a="$1" b="$2"
    local IFS='.'
    local -a aa bb
    read -ra aa <<< "$a"
    read -ra bb <<< "$b"
    local i
    for i in 0 1 2; do
        local av="${aa[$i]:-0}" bv="${bb[$i]:-0}"
        [ "$av" -gt "$bv" ] && return 0
        [ "$av" -lt "$bv" ] && return 1
    done
    return 0
}

# ============================================================
# 端口占用检测（lsof → ss → netstat 三重回退）
# ============================================================
port_in_use() {
    local port="$1"
    lsof -ti ":$port" &>/dev/null                      && return 0
    ss -tlnp 2>/dev/null | grep -q ":${port} "         && return 0
    netstat -tlnp 2>/dev/null | grep -q ":${port} "    && return 0
    return 1
}

# ============================================================
# JSON 字段提取（jq 优先，回退到 sed）
# 用法: json_field <json_string> <jq_filter>
# 例:   json_field "$resp" '.result.id'
# ============================================================
json_field() {
    local json="$1" field="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$field" 2>/dev/null
    else
        # 仅支持简单顶层字符串字段，如 .result.id → 提取 "id"
        local key
        key=$(echo "$field" | sed 's/.*\.\([^.]*\)$/\1/')
        echo "$json" | sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" | head -1
    fi
}

# ============================================================
# 安全写入 Token 到 openclaw 配置
# 通过 stdin 管道传值，Token 不出现在进程参数列表 (ps)
# ============================================================
oc_set_token() {
    local token="$1"
    # 优先尝试通过 stdin 传入
    if echo -n "$token" | openclaw config set gateway.auth.token --stdin >> "$LOG_FILE" 2>&1; then
        return 0
    fi
    # 若 openclaw 不支持 --stdin，回退到临时文件（权限 600）
    # 注意：此时 Token 仍不会出现在命令行参数中
    local tmpf
    tmpf=$(mktemp) || error "无法创建临时文件"
    # trap 保证任何退出路径都清理临时文件
    trap 'rm -f "$tmpf"' RETURN
    chmod 600 "$tmpf"
    printf '%s' "$token" > "$tmpf"
    # 通过文件重定向传入；若也不支持，最后才用命令行参数
    openclaw config set gateway.auth.token --file "$tmpf" >> "$LOG_FILE" 2>&1 || \
    openclaw config set gateway.auth.token "$(cat "$tmpf")" >> "$LOG_FILE" 2>&1 || \
        error "无法写入 OpenClaw Token，请检查 openclaw 版本"
}

oc_config_set() {
    local key="$1" value="$2"
    if [ "$key" = "gateway.auth.token" ]; then
        oc_set_token "$value"
    else
        openclaw config set "$key" "$value" >> "$LOG_FILE" 2>&1
    fi
}

# ============================================================
# OS 检测
# ============================================================
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
            ubuntu|debian|linuxmint|pop)
                OS_FAMILY="debian"; PKG_MANAGER="apt" ;;
            centos|rhel|rocky|almalinux|ol|amzn)
                OS_FAMILY="rhel";   PKG_MANAGER="yum" ;;
            fedora)
                OS_FAMILY="fedora"; PKG_MANAGER="dnf" ;;
            arch|manjaro)
                OS_FAMILY="arch";   PKG_MANAGER="pacman" ;;
            *)
                OS_FAMILY="unknown" ;;
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
        brew)   brew install "$pkg"                   >> "$LOG_FILE" 2>&1 ;;
        apt)    sudo apt-get install -y "$pkg"        >> "$LOG_FILE" 2>&1 ;;
        yum)    sudo yum install -y "$pkg"            >> "$LOG_FILE" 2>&1 ;;
        dnf)    sudo dnf install -y "$pkg"            >> "$LOG_FILE" 2>&1 ;;
        pacman) sudo pacman -S --noconfirm "$pkg"     >> "$LOG_FILE" 2>&1 ;;
        *)      error "不支持的包管理器: $PKG_MANAGER" ;;
    esac
}

check_system_compat() {
    info "系统: $OS_NAME $OS_VERSION ($OS_FAMILY) | 包管理: $PKG_MANAGER"
    case "$OS_FAMILY" in
        macos)
            version_gte "$OS_VERSION" "11.0" || warn "⚠️  建议 macOS 11.0+"
            ;;
        unknown)
            warn "⚠️  未知 Linux 发行版，部分功能可能不可用"
            command -v sudo &>/dev/null || error "需要 sudo"
            ;;
        *)
            command -v sudo &>/dev/null || error "Linux 部署需要 sudo"
            ;;
    esac
}

# ============================================================
# 依赖安装
# ============================================================
install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        local ver
        ver=$(cloudflared --version 2>/dev/null | awk '{print $2}')
        success "✓ cloudflared $ver 已安装"
        return 0
    fi
    info "安装 cloudflared..."
    case "$OS_FAMILY" in
        macos)
            pkg_install "cloudflare/cloudflare/cloudflared"
            ;;
        debian)
            curl -fsSL https://pkg.cloudflare.com/cloudflared/gpg-key \
                | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg 2>> "$LOG_FILE"
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
https://pkg.cloudflare.com/cloudflared \
$(lsb_release -cs 2>/dev/null || echo focal) main" \
                | sudo tee /etc/apt/sources.list.d/cloudflared.list >> "$LOG_FILE" 2>&1
            sudo apt-get update  >> "$LOG_FILE" 2>&1
            sudo apt-get install -y cloudflared >> "$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            local arch
            arch=$(uname -m)
            local rpm_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.rpm"
            sudo rpm -i "$rpm_url" >> "$LOG_FILE" 2>&1 \
                || sudo yum install -y "$rpm_url" >> "$LOG_FILE" 2>&1
            ;;
        *)
            local arch
            arch=$(uname -m)
            case "$arch" in
                x86_64|amd64)   arch="amd64" ;;
                aarch64|arm64)  arch="arm64" ;;
                armv7l)         arch="arm"   ;;
                *) error "不支持的 CPU 架构: $arch" ;;
            esac
            sudo curl -fsSL \
                "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" \
                -o /usr/local/bin/cloudflared
            sudo chmod +x /usr/local/bin/cloudflared
            ;;
    esac
    command -v cloudflared &>/dev/null || error "cloudflared 安装失败，请查看日志: $LOG_FILE"
    local ver
    ver=$(cloudflared --version 2>/dev/null | awk '{print $2}')
    success "✓ cloudflared $ver 安装成功"
}

install_nodejs() {
    if command -v node &>/dev/null; then
        local ver
        ver=$(node --version 2>/dev/null | cut -c2-)  # 去掉 'v' 前缀
        if version_gte "$ver" "18"; then
            success "✓ Node.js $ver 已安装"
            return 0
        fi
        warn "⚠️  Node.js $ver < 18，需要升级"
    fi
    info "安装 Node.js 20..."
    case "$OS_FAMILY" in
        macos)
            pkg_install "node"
            ;;
        debian)
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >> "$LOG_FILE" 2>&1
            sudo apt-get install -y nodejs >> "$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash - >> "$LOG_FILE" 2>&1
            sudo yum install -y nodejs >> "$LOG_FILE" 2>&1
            ;;
        *)
            warn "⚠️  请手动安装 Node.js 18+"
            return 1
            ;;
    esac
    command -v node &>/dev/null || error "Node.js 安装失败，请查看日志: $LOG_FILE"
    local ver
    ver=$(node --version 2>/dev/null | cut -c2-)
    success "✓ Node.js $ver 安装成功"
}

install_openclaw() {
    info "安装 OpenClaw CLI..."
    if command -v openclaw &>/dev/null; then
        local ver
        ver=$(openclaw --version 2>/dev/null | head -n1)
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
    command -v openclaw &>/dev/null || error "OpenClaw 安装失败，请查看日志: $LOG_FILE"
    local ver
    ver=$(openclaw --version 2>/dev/null | head -n1)
    success "✓ OpenClaw $ver 安装成功"
}

check_dependencies() {
    info "检查依赖..."
    detect_os
    check_system_compat
    if [[ "$OS_FAMILY" == "macos" ]]; then
        command -v brew &>/dev/null || error "需要 Homebrew: https://brew.sh"
        success "✓ Homebrew"
    fi
    install_nodejs
    install_cloudflared
    success "依赖检查完成"
}

# ============================================================
# 服务管理（launchd / systemd 抽象）
# ============================================================
find_openclaw_bin() {
    command -v openclaw 2>/dev/null || echo "/usr/local/bin/openclaw"
}

_install_launchd() {
    local oc_bin="$1"
    local cf_bin
    # 动态获取路径，兼容 Intel (/usr/local/bin) 和 Apple Silicon (/opt/homebrew/bin)
    cf_bin=$(command -v cloudflared 2>/dev/null || echo "/opt/homebrew/bin/cloudflared")
    local dir="$HOME/Library/LaunchAgents"
    mkdir -p "$dir"

    cat > "$dir/ai.openclaw.gateway.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>ai.openclaw.gateway</string>
    <key>ProgramArguments</key>
    <array>
        <string>$oc_bin</string>
        <string>gateway</string><string>start</string><string>--force</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict><key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>NetworkState</key><true/>
        <key>SuccessfulExit</key><false/>
    </dict>
    <key>StandardOutPath</key><string>/tmp/openclaw-gateway.log</string>
    <key>StandardErrorPath</key><string>/tmp/openclaw-gateway.err.log</string>
    <key>ThrottleInterval</key><integer>30</integer>
</dict></plist>
EOF

    cat > "$dir/com.cloudflare.cloudflared.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>com.cloudflare.cloudflared</string>
    <key>ProgramArguments</key>
    <array>
        <string>$cf_bin</string>
        <string>tunnel</string>
        <string>--config</string><string>$CF_CONFIG_DIR/config.yml</string>
        <string>run</string><string>$TUNNEL_NAME</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict><key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>NetworkState</key><true/>
        <key>SuccessfulExit</key><false/>
        <key>Crashed</key><true/>
    </dict>
    <key>StandardOutPath</key><string>/tmp/cloudflared.log</string>
    <key>StandardErrorPath</key><string>/tmp/cloudflared.err.log</string>
    <key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
EOF

    launchctl unload "$dir/ai.openclaw.gateway.plist"          2>/dev/null || true
    launchctl load   "$dir/ai.openclaw.gateway.plist"
    launchctl unload "$dir/com.cloudflare.cloudflared.plist"   2>/dev/null || true
    launchctl load   "$dir/com.cloudflare.cloudflared.plist"
}

_uninstall_launchd() {
    local dir="$HOME/Library/LaunchAgents"
    launchctl unload "$dir/ai.openclaw.gateway.plist"         2>/dev/null || true
    launchctl unload "$dir/com.cloudflare.cloudflared.plist"  2>/dev/null || true
    rm -f "$dir/ai.openclaw.gateway.plist"
    rm -f "$dir/com.cloudflare.cloudflared.plist"
}

_install_systemd() {
    local oc_bin="$1"
    local cf_bin
    cf_bin=$(command -v cloudflared 2>/dev/null || echo "/usr/local/bin/cloudflared")

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
    sudo systemctl enable openclaw-gateway
    sudo systemctl enable cloudflared-tunnel
}

_uninstall_systemd() {
    sudo systemctl stop    openclaw-gateway    2>/dev/null || true
    sudo systemctl stop    cloudflared-tunnel  2>/dev/null || true
    sudo systemctl disable openclaw-gateway    2>/dev/null || true
    sudo systemctl disable cloudflared-tunnel  2>/dev/null || true
    sudo rm -f /etc/systemd/system/openclaw-gateway.service
    sudo rm -f /etc/systemd/system/cloudflared-tunnel.service
    sudo systemctl daemon-reload 2>/dev/null || true
}

service_install() {
    local oc_bin
    oc_bin=$(find_openclaw_bin)
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
            launchctl start ai.openclaw.gateway         2>/dev/null || true
            launchctl start com.cloudflare.cloudflared  2>/dev/null || true
            ;;
        *)
            sudo systemctl start openclaw-gateway   2>/dev/null || true
            sudo systemctl start cloudflared-tunnel 2>/dev/null || true
            ;;
    esac
}

service_stop() {
    case "$OS_FAMILY" in
        macos)
            launchctl stop   ai.openclaw.gateway         2>/dev/null || true
            launchctl stop   com.cloudflare.cloudflared  2>/dev/null || true
            launchctl unload "$HOME/Library/LaunchAgents/ai.openclaw.gateway.plist"        2>/dev/null || true
            launchctl unload "$HOME/Library/LaunchAgents/com.cloudflare.cloudflared.plist" 2>/dev/null || true
            ;;
        *)
            sudo systemctl stop    openclaw-gateway   2>/dev/null || true
            sudo systemctl stop    cloudflared-tunnel 2>/dev/null || true
            sudo systemctl disable openclaw-gateway   2>/dev/null || true
            sudo systemctl disable cloudflared-tunnel 2>/dev/null || true
            ;;
    esac
}

# ============================================================
# DNS 备份 / 设置 / 恢复
# ============================================================

# 获取 macOS 活跃网卡的 networksetup 服务名
_macos_active_iface_name() {
    local default_dev
    default_dev=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
    [ -z "$default_dev" ] && return 1
    # 从 networksetup -listnetworkserviceorder 找到对应服务名
    networksetup -listnetworkserviceorder 2>/dev/null \
        | grep -B1 "Device: ${default_dev})" \
        | head -1 \
        | sed 's/^([0-9]*) //'
}

dns_backup() {
    local backup_file="$OC_CONFIG_DIR/.dns_backup"
    case "$OS_FAMILY" in
        macos)
            local iface
            iface=$(_macos_active_iface_name 2>/dev/null) || {
                warn "⚠️  无法检测网络接口，跳过 DNS 备份"
                return 0
            }
            {
                echo "macos"
                echo "$iface"
                networksetup -getdnsservers "$iface" 2>/dev/null || echo "Empty"
            } > "$backup_file"
            chmod 600 "$backup_file"
            info "DNS 已备份 (接口: $iface)"
            ;;
        *)
            if [ -f /etc/resolv.conf ]; then
                {
                    echo "linux"
                    cat /etc/resolv.conf
                } > "$backup_file"
                chmod 600 "$backup_file"
                info "DNS 已备份 (/etc/resolv.conf)"
            fi
            ;;
    esac
}

dns_set() {
    info "配置 DNS → 1.1.1.1 / 1.0.0.1 ..."
    case "$OS_FAMILY" in
        macos)
            local iface
            iface=$(_macos_active_iface_name 2>/dev/null) || {
                warn "⚠️  无法检测网络接口，跳过 DNS 设置"
                return 0
            }
            networksetup -setdnsservers "$iface" 1.1.1.1 1.0.0.1 2>/dev/null \
                && success "✓ DNS 已设置 (接口: $iface)" \
                || warn "⚠️  DNS 设置失败"
            ;;
        *)
            if command -v resolvectl &>/dev/null; then
                local iface
                iface=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
                if [ -n "$iface" ]; then
                    sudo resolvectl dns "$iface" 1.1.1.1 1.0.0.1 2>/dev/null \
                        && success "✓ DNS 已设置 (resolvectl, 接口: $iface)" \
                        || warn "⚠️  resolvectl 失败"
                else
                    warn "⚠️  无法检测默认网卡，跳过 DNS 设置"
                fi
            else
                sudo tee /etc/resolv.conf > /dev/null <<'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
options edns0
EOF
                success "✓ DNS 已设置 (/etc/resolv.conf)"
                warn "⚠️  注意: NetworkManager 可能在下次连接时覆盖此配置"
            fi
            ;;
    esac
}

dns_restore() {
    local backup_file="$OC_CONFIG_DIR/.dns_backup"
    [ ! -f "$backup_file" ] && return 0

    local platform
    platform=$(sed -n '1p' "$backup_file")
    case "$platform" in
        macos)
            local iface
            iface=$(sed -n '2p' "$backup_file")
            if [ -z "$iface" ]; then
                warn "⚠️  DNS 备份文件损坏（无接口信息），跳过恢复"
                rm -f "$backup_file"
                return 0
            fi
            # 第 3 行起是原 DNS 服务器列表
            local dns_servers
            dns_servers=$(sed -n '3,$p' "$backup_file" | tr '\n' ' ' | sed 's/ $//')
            if [ -z "$dns_servers" ] || echo "$dns_servers" | grep -qi "empty\|There aren't"; then
                networksetup -setdnsservers "$iface" "Empty" 2>/dev/null \
                    && success "✓ DNS 已恢复 → DHCP (接口: $iface)"
            else
                # shellcheck disable=SC2086
                networksetup -setdnsservers "$iface" $dns_servers 2>/dev/null \
                    && success "✓ DNS 已恢复 → $dns_servers (接口: $iface)"
            fi
            ;;
        linux)
            # 重建 resolv.conf（跳过第一行 "linux" 标记）
            sudo tee /etc/resolv.conf > /dev/null < <(sed -n '2,$p' "$backup_file")
            success "✓ DNS 已恢复 (/etc/resolv.conf)"
            ;;
        *)
            warn "⚠️  未知 DNS 备份格式，跳过恢复"
            ;;
    esac
    rm -f "$backup_file"
}

# ============================================================
# 输入验证
# ============================================================
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || error "端口 '$port' 不是有效数字"
    if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
        error "端口必须在 1024–65535 之间，当前: $port"
    fi
    if port_in_use "$port"; then
        error "端口 $port 已被占用，请选择其他端口"
    fi
    success "✓ 端口 $port 可用"
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]] \
        || error "域名格式无效: $domain"
    success "✓ 域名 $domain 有效"
}

# ============================================================
# 用户配置收集
# ============================================================
get_user_config() {
    echo ""
    echo -e "${GREEN}===== 配置向导 =====${NC}"
    echo ""

    # 域名
    if [ -z "${DOMAIN:-}" ]; then
        while true; do
            read -rp "▶ 域名 (如 claw.example.com): " DOMAIN
            [ -z "$DOMAIN" ] && continue
            validate_domain "$DOMAIN" && break
        done
    else
        validate_domain "$DOMAIN"
    fi

    # 端口
    if [ -z "${PORT:-}" ]; then
        read -rp "▶ 端口 (默认 $DEFAULT_PORT): " PORT
        PORT="${PORT:-$DEFAULT_PORT}"
    fi
    validate_port "$PORT"

    # Token
    if [ -n "${OPENCLAW_TOKEN:-}" ]; then
        TOKEN="$OPENCLAW_TOKEN"
        info "使用环境变量 OPENCLAW_TOKEN"
    else
        TOKEN=$(openssl rand -hex 32 2>/dev/null) \
            || error "openssl 不可用，无法生成 Token，请安装 openssl"
    fi

    mkdir -p "$OC_CONFIG_DIR"
    printf '%s' "$TOKEN" > "$OC_CONFIG_DIR/.auth_token"
    chmod 600 "$OC_CONFIG_DIR/.auth_token"
    success "✓ Token 已保存 → $OC_CONFIG_DIR/.auth_token (权限 600)"

    echo ""
    read -rp "按 Enter 继续..."
    echo ""
}

# ============================================================
# 配置并启动 OpenClaw
# ============================================================
configure_openclaw() {
    info "配置 OpenClaw..."
    mkdir -p "$OC_CONFIG_DIR"
    oc_config_set gateway.port      "$PORT"
    oc_config_set gateway.bind      "loopback"
    oc_config_set gateway.mode      "local"
    oc_config_set gateway.auth.mode "token"
    oc_config_set gateway.auth.token "$TOKEN"
    success "✓ 配置已写入"

    openclaw config validate >> "$LOG_FILE" 2>&1 || error "OpenClaw 配置验证失败，请查看日志: $LOG_FILE"
    success "✓ 配置验证通过"

    # 停止可能残留的旧进程
    openclaw gateway stop 2>/dev/null || true
    pkill -f "openclaw.*gateway" 2>/dev/null || true
    sleep 2

    info "启动 OpenClaw Gateway..."
    openclaw gateway start --force >> "$LOG_FILE" 2>&1 || error "OpenClaw 启动失败，请查看日志: $LOG_FILE"
    sleep 5

    if port_in_use "$PORT"; then
        success "✓ OpenClaw 运行中 (127.0.0.1:$PORT)"
    else
        error "OpenClaw 启动后未监听 127.0.0.1:$PORT，请查看日志: $LOG_FILE"
    fi
}

# ============================================================
# 配置 Cloudflare Tunnel
# ============================================================
configure_tunnel() {
    info "配置 Cloudflare Tunnel..."

    # 检查认证凭据
    if [ ! -f "$CF_CONFIG_DIR/cert.pem" ]; then
        echo -e "${YELLOW}⚠️  需要先完成 Cloudflare 登录认证${NC}"
        read -rp "按 Enter 打开浏览器认证..."
        cloudflared tunnel login >> "$LOG_FILE" 2>&1 || error "Cloudflare 认证失败，请查看日志: $LOG_FILE"
        success "✓ 认证成功"
    else
        success "✓ 已有认证凭据"
    fi

    # 创建或复用隧道
    local tunnel_id=""
    if cloudflared tunnel list 2>/dev/null | grep -qw "$TUNNEL_NAME"; then
        tunnel_id=$(cloudflared tunnel list 2>/dev/null | awk -v name="$TUNNEL_NAME" '$0 ~ name {print $1; exit}')
        warn "⚠️  检测到同名隧道，复用: $tunnel_id"
        # 凭据文件必须存在，否则隧道无法启动
        if [ ! -f "$CF_CONFIG_DIR/${tunnel_id}.json" ]; then
            error "凭据文件 $CF_CONFIG_DIR/${tunnel_id}.json 不存在。
  请先手动删除旧隧道: cloudflared tunnel delete $TUNNEL_NAME
  然后重新运行本脚本。"
        fi
    else
        local create_out
        create_out=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1) \
            || error "创建隧道失败: $create_out"
        tunnel_id=$(echo "$create_out" | sed -n 's/.*Tunnel ID: *\([0-9a-f-]*\).*/\1/p')
        [ -z "$tunnel_id" ] && error "无法从输出中解析 Tunnel ID: $create_out"
        success "✓ 隧道创建成功: $tunnel_id"
    fi

    # 写入 TUNNEL_ID 供后续函数使用
    TUNNEL_ID="$tunnel_id"

    # 生成 config.yml
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
    success "✓ Tunnel 配置已生成 ($CF_CONFIG_DIR/config.yml)"

    # 配置 DNS 路由，明确区分成功/失败/已存在
    info "配置 DNS 路由 ($DOMAIN → 隧道)..."
    local dns_out dns_exit=0
    dns_out=$(cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" 2>&1) || dns_exit=$?
    if [ "$dns_exit" -ne 0 ]; then
        if echo "$dns_out" | grep -qi "already\|exists"; then
            warn "⚠️  DNS 记录已存在，跳过创建"
        else
            warn "⚠️  DNS 路由配置失败: $dns_out"
            warn "    请手动执行: cloudflared tunnel route dns $TUNNEL_NAME $DOMAIN"
        fi
    else
        success "✓ DNS 路由配置成功"
    fi
}

# ============================================================
# 配置 Cloudflare Access（Zero Trust）
# ============================================================
configure_cf_access() {
    if [ "${NO_ACCESS:-false}" = "true" ]; then
        info "跳过 Cloudflare Access (--no-access)"
        return 0
    fi

    echo -e "${GREEN}===== Cloudflare Access (Zero Trust) =====${NC}"

    # 收集必要参数
    if [ -z "${CF_API_TOKEN:-}" ]; then
        read -rsp "▶ CF API Token: " CF_API_TOKEN; echo ""
    fi
    [ -z "${CF_ACCOUNT_ID:-}" ] && read -rp  "▶ CF Account ID: "                  CF_ACCOUNT_ID
    [ -z "${ACCESS_EMAIL:-}" ]  && read -rp  "▶ 允许访问的邮箱: "                  ACCESS_EMAIL
    [ -z "${CF_TEAM_NAME:-}" ]  && read -rp  "▶ Zero Trust Team Name (如 myteam): " CF_TEAM_NAME

    local api="https://api.cloudflare.com/client/v4"

    # ---- 创建 Access Application ----
    info "创建 Access Application..."
    local resp app_id app_aud

    # _sensitive_begin/end 在父 shell 中临时关闭 set -x，防止 Token 进日志
    _sensitive_begin
    resp=$(curl -sf -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"OpenClaw\",\"domain\":\"$DOMAIN\",\"type\":\"self_hosted\",
             \"session_duration\":\"24h\",\"auto_redirect_to_identity\":false}" \
        2>> "$LOG_FILE") || resp=""
    _sensitive_end

    app_id=$(json_field "$resp" '.result.id')
    app_aud=$(json_field "$resp" '.result.aud')

    # 若创建失败（可能已存在），则按 domain 查找已有 Application
    if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
        warn "创建失败或已存在，尝试查找已有 Application..."
        local existing_resp

        _sensitive_begin
        existing_resp=$(curl -sf "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            2>> "$LOG_FILE") || existing_resp=""
        _sensitive_end

        if command -v jq &>/dev/null; then
            app_id=$(echo "$existing_resp"  | jq -r ".result[] | select(.domain==\"$DOMAIN\") | .id"  2>/dev/null | head -1)
            app_aud=$(echo "$existing_resp" | jq -r ".result[] | select(.domain==\"$DOMAIN\") | .aud" 2>/dev/null | head -1)
        else
            # sed fallback：在 JSON 里找到 domain 匹配的对象，取其 id 和 aud
            app_id=$(echo "$existing_resp"  | sed -n "s/.*\"domain\":\"$DOMAIN\".*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
            app_aud=$(echo "$existing_resp" | sed -n "s/.*\"domain\":\"$DOMAIN\".*\"aud\":\"\([^\"]*\)\".*/\1/p" | head -1)
        fi
    fi

    [ -z "$app_id" ] || [ "$app_id" = "null" ] \
        && error "无法创建或找到 Access Application (domain: $DOMAIN)，请检查 CF API Token 权限"
    success "✓ Application: $app_id  AUD: $app_aud"

    # ---- 创建访问策略 ----
    _sensitive_begin
    curl -sf -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps/$app_id/policies" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"Whitelist\",\"decision\":\"allow\",
             \"include\":[{\"email\":{\"email\":\"$ACCESS_EMAIL\"}}]}" \
        >> "$LOG_FILE" 2>&1 || warn "⚠️  Policy 创建失败，请在 Cloudflare Dashboard 手动添加"
    _sensitive_end
    success "✓ 访问策略已创建 (邮箱: $ACCESS_EMAIL)"

    # ---- 更新 config.yml，启用 Origin JWT 验证 ----
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
        audTag:
          - "$app_aud"
  - service: http_status:404

logfile: $CF_CONFIG_DIR/tunnel.log
loglevel: info
EOF
    success "✓ Origin JWT 验证已启用"
    info "安全层级: Cloudflare Edge → Access JWT → cloudflared → OpenClaw Token"
}

# ============================================================
# 部署验证
# ============================================================
verify_deployment() {
    echo -e "${GREEN}===== 部署验证 =====${NC}"
    local all_ok=true

    # 1. OpenClaw 进程
    info "检查 OpenClaw..."
    if port_in_use "$PORT"; then
        success "✓ OpenClaw 监听 127.0.0.1:$PORT"
    else
        warn "⚠️  OpenClaw 未监听 $PORT"
        all_ok=false
    fi

    # 2. Cloudflare Tunnel 进程 + 连通状态
    info "检查 Cloudflare Tunnel..."
    local waited=0
    while ! pgrep -f "cloudflared.*tunnel" &>/dev/null; do
        sleep 5; waited=$((waited + 5))
        [ "$waited" -ge 30 ] && break
    done

    if pgrep -f "cloudflared.*tunnel" &>/dev/null; then
        success "✓ cloudflared 进程运行中"
        # 检查隧道是否真正建连（而非仅进程存在）
        if cloudflared tunnel info "$TUNNEL_NAME" 2>/dev/null \
                | grep -qiE "HEALTHY|active connection|ACTIVE"; then
            success "✓ Tunnel 已连通"
        else
            warn "⚠️  Tunnel 进程在，但尚未连通（握手可能需要更多时间）"
        fi
    else
        warn "⚠️  未检测到 cloudflared 进程"
        all_ok=false
    fi

    # 3. 域名 HTTP 可达性
    info "检查域名可达性 ($DOMAIN)..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$DOMAIN" 2>/dev/null || echo "000")
    if [[ "$http_code" =~ ^(200|301|302|401|403)$ ]]; then
        success "✓ 域名可访问 (HTTP $http_code)"
    else
        warn "⚠️  域名返回 HTTP $http_code（DNS 传播可能需要几分钟）"
    fi

    echo ""
    if [ "$all_ok" = true ]; then
        success "✅ 部署验证通过"
    else
        warn "⚠️  部分检查未通过，请查看日志: $LOG_FILE"
    fi
}

# ============================================================
# 卸载
# ============================================================
uninstall() {
    echo -e "${RED}===== 卸载 ClawHole =====${NC}"
    read -rp "确认卸载所有组件? (y/n): " -n 1; echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0

    # 停止并移除服务
    openclaw gateway stop 2>/dev/null || true
    service_stop
    service_uninstall

    # 清理 OpenClaw 配置
    openclaw config unset gateway.port       2>/dev/null || true
    openclaw config unset gateway.bind       2>/dev/null || true
    openclaw config unset gateway.auth.mode  2>/dev/null || true
    openclaw config unset gateway.auth.token 2>/dev/null || true
    rm -f "$OC_CONFIG_DIR/.auth_token"

    # 恢复 DNS
    dns_restore

    # 可选：卸载 OpenClaw CLI
    read -rp "卸载 OpenClaw CLI? (y/n): " -n 1; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local npm_root
        npm_root=$(npm root -g 2>/dev/null) || npm_root=""
        if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then
            sudo npm uninstall -g openclaw 2>/dev/null || true
        else
            npm uninstall -g openclaw 2>/dev/null || true
        fi
        success "✓ OpenClaw CLI 已卸载"
    fi

    # 可选：删除 Cloudflare Tunnel（必须在删除 ~/.cloudflared 之前）
    read -rp "删除 Cloudflare Tunnel '$TUNNEL_NAME'? (y/n): " -n 1; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local tid
        tid=$(cloudflared tunnel list 2>/dev/null | awk -v name="$TUNNEL_NAME" '$0 ~ name {print $1; exit}')
        if [ -n "$tid" ]; then
            if cloudflared tunnel delete "$tid" 2>/dev/null; then
                success "✓ 隧道已删除"
                rm -rf "$CF_CONFIG_DIR"
                success "✓ ~/.cloudflared 已清理"
            else
                warn "⚠️  隧道删除失败，保留 $CF_CONFIG_DIR（可手动清理）"
            fi
        else
            warn "⚠️  未找到隧道 '$TUNNEL_NAME'"
        fi
    fi

    # 可选：删除 Cloudflare DNS 记录
    if [ -n "${DOMAIN:-}" ]; then
        read -rp "删除 Cloudflare DNS 记录 ($DOMAIN)? (y/n): " -n 1; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cloudflared tunnel route dns delete "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null \
                && success "✓ DNS 记录已删除" \
                || warn "⚠️  DNS 记录删除失败，请在 Cloudflare Dashboard 手动操作"
        fi
    else
        warn "⚠️  未指定域名，跳过 DNS 记录删除"
    fi

    rm -f "$LOG_FILE"
    success "✅ 卸载完成"
    exit 0
}

# ============================================================
# Banner 和帮助
# ============================================================
banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗"
    echo -e "║                                                          ║"
    echo -e "║  ${GREEN}ClawHole v${SCRIPT_VERSION} — OpenClaw 隐私部署${CYAN}              ║"
    echo -e "║                                                          ║"
    echo -e "║  ${YELLOW}${OS_NAME} ${OS_VERSION} (${OS_FAMILY}) | ${PKG_MANAGER}${CYAN}                  ║"
    echo -e "║                                                          ║"
    echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    cat <<EOF
ClawHole v${SCRIPT_VERSION} — OpenClaw + Cloudflare Tunnel 隐私部署

用法: ./$SCRIPT_NAME [选项]

选项:
  --domain <域名>           访问域名 (必须已托管到 Cloudflare)
  --port <端口>             本地监听端口 (默认: $DEFAULT_PORT)
  --no-access               跳过 Cloudflare Access Zero Trust (不推荐)
  --cf-api-token <token>    Cloudflare API Token
  --cf-account-id <id>      Cloudflare Account ID
  --cf-team-name <name>     Zero Trust Team Name (如 myteam)
  --access-email <email>    允许访问的邮箱
  --uninstall               卸载所有已部署组件
  --debug                   调试模式 (set -x，敏感命令自动屏蔽)
  --help                    显示此帮助

环境变量:
  OPENCLAW_TOKEN            预设 Token（不通过交互输入）
  CF_API_TOKEN              预设 CF API Token

支持系统:
  macOS 11.0+ (Intel / Apple Silicon)
  Ubuntu 20.04+ / Debian 11+
  CentOS 7+ / RHEL 8+ / Rocky Linux / AlmaLinux
  Fedora 36+
  Arch Linux / Manjaro

部署流程:
  1. 安装依赖 (Node.js, cloudflared, openclaw)
  2. 配置 OpenClaw Gateway（仅监听 loopback）
  3. 创建 Cloudflare Tunnel（零公网端口暴露）
  4. 可选：启用 Cloudflare Access Zero Trust（邮箱白名单）
  5. 注册系统服务（开机自启）
  6. 验证部署状态
EOF
    exit 0
}

# ============================================================
# 主流程
# ============================================================
main() {
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)        DOMAIN="$2";        shift 2 ;;
            --port)          PORT="$2";           shift 2 ;;
            --no-access)     NO_ACCESS=true;      shift   ;;
            --cf-api-token)  CF_API_TOKEN="$2";   shift 2 ;;
            --cf-account-id) CF_ACCOUNT_ID="$2";  shift 2 ;;
            --cf-team-name)  CF_TEAM_NAME="$2";   shift 2 ;;
            --access-email)  ACCESS_EMAIL="$2";   shift 2 ;;
            --uninstall)     UNINSTALL=true;       shift   ;;
            --debug)         DEBUG=1;              shift   ;;
            --help)          show_help ;;
            *) echo "未知参数: $1"; show_help ;;
        esac
    done

    # debug 模式在路径初始化前开启（敏感命令由 _sensitive_begin/end 屏蔽）
    [ "${DEBUG:-0}" = "1" ] && set -x

    # OS 检测（卸载流程也需要）
    detect_os

    # 初始化路径（必须在任何 log/info 调用之前完成）
    OC_CONFIG_DIR="$HOME/.openclaw"
    CF_CONFIG_DIR="$HOME/.cloudflared"
    LOG_FILE="$OC_CONFIG_DIR/deploy-${TIMESTAMP}.log"
    mkdir -p "$OC_CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    # 卸载流程
    [ "${UNINSTALL:-false}" = "true" ] && uninstall

    # 部署流程
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
    echo -e "   🌐 访问地址: https://$DOMAIN"
    echo -e "   🔑 查看 Token: cat $OC_CONFIG_DIR/.auth_token"
    echo -e "   📋 部署日志: $LOG_FILE"
    echo ""
}

# ============================================================
# 入口
# ============================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Bash 版本检查（需要 3.2+ 支持 read -ra）
    if [ "${BASH_VERSINFO[0]}" -lt 3 ] || \
       { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
        echo "错误: 需要 Bash 3.2 或更高版本（当前: $BASH_VERSION）"
        exit 1
    fi

    # root 警告（Linux）
    if [[ $EUID -eq 0 ]] && [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${YELLOW}⚠️  不建议以 root 身份运行，脚本会在需要时自动使用 sudo${NC}"
        read -rp "仍要继续? (y/n): " -n 1; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi

    main "$@"
fi
    main "$@"
fi
