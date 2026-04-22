#!/bin/bash
# ClawHole — OpenClaw + Cloudflare Tunnel 隐私部署脚本 v4.2
# 支持 macOS + Linux (Ubuntu/Debian/CentOS/RHEL/Fedora/Arch)
#
# 用法: ./clawhole.sh [选项]
#   --domain <域名>         访问域名
#   --port <端口>           监听端口 (默认 10371)
#   --no-access             跳过 Cloudflare Access
#   --cf-api-token <token>  CF API Token
#   --cf-account-id <id>    CF Account ID
#   --cf-team-name <n>      Zero Trust Team Name
#   --access-email <email>  Access 白名单邮箱
#   --uninstall             卸载所有组件
#   --yes                   非交互模式（CI/CD 用，跳过所有确认）
#   --debug                 调试模式 (set -x，敏感命令除外)
#   --help                  显示帮助
#
# 环境变量:
#   OPENCLAW_TOKEN          预设 Token（避免交互输入）
#   CF_API_TOKEN            预设 CF API Token
#
# v4.0 改动摘要（相对 v3.5）:
#   FIX-1  : cloudflared tunnel create 改用 --output json，不再 sed 解析 CLI 输出
#   FIX-2  : 二进制下载后 SHA256 校验，防止中间人 / 缓存污染
#   FIX-3  : 完全移除 DNS 修改逻辑（Tunnel 是 outbound，不需要改本机 DNS）
#   FIX-4  : oc_set_token 错误信息包含所需 openclaw 最低版本提示
#   FIX-5  : configure_openclaw 停旧进程改用 PID 文件 + openclaw gateway stop
#   FIX-6  : 服务安装前检测是否已存在，避免重复注册（幂等）
#   FIX-7  : 新增 cf_api_call 带 3 次自动重试的 API 封装
#   FIX-8  : verify_deployment 新增 /health endpoint 检查
#   FIX-9  : 日志 rotation，保留最近 5 份，自动清理旧日志
#   FIX-10 : --debug 模式启动时输出完整环境快照
#   FIX-11 : 修正子函数内 set -e + || 混用导致的潜在意外退出
#
# v4.3 改动摘要（相对 v4.2）:
#   FIX-K  : watchdog 健康阈值改为 MIN_HA_CONN（默认 2），检测静默掉连，
#             原逻辑只在 ha_connections=0 时重启，无法发现 4→2 的部分失联；
#             重启用 launchctl kickstart -k / systemctl restart，更干净
#   FIX-L  : 新增每日 04:00 保底重启 cloudflared（launchd StartCalendarInterval /
#             systemd OnCalendar），兜底长跑静默故障
#
# v4.2 改动摘要（相对 v4.1）:
#   FIX-I  : config.yml 新增 metrics: 127.0.0.1:2000，暴露 cloudflared 健康指标
#   FIX-J  : 新增 tunnel watchdog（launchd StartInterval=300 / systemd timer），
#             每 5 分钟检查 ha_connections，发现 tunnel 僵死自动重启 cloudflared；
#             同时检测 gateway 未 load 时自动重载
#
# v4.1 改动摘要（相对 v4.0）:
#   FIX-A  : CF API cf_api_call 区分 2xx(成功) / 4xx(不重试报错) / 5xx(重试)
#   FIX-B  : cloudflared tunnel list 改用 --output json + json_field 解析
#   FIX-C  : OpenClaw 进程控制交给 systemd/launchd，不再自己 fork + pgrep
#   FIX-D  : systemd unit 补全安全加固项（PrivateTmp/ProtectSystem/ProtectHome）
#   FIX-E  : /health 降为辅助检查，端口连通性为主检查
#   FIX-F  : TUNNEL_NAME 改为 openclaw-<domain> 支持多实例
#   FIX-G  : --yes / NON_INTERACTIVE 模式，CI/CD 可无人值守运行
#   FIX-H  : 部署状态机（STATE_FILE），支持断点恢复

set -e
set -o pipefail

# ============================================================
# 全局常量
# ============================================================
readonly SCRIPT_VERSION="4.3.0"
readonly SCRIPT_NAME="clawhole.sh"
readonly DEFAULT_PORT=10371
# FIX-F: TUNNEL_NAME 在 main() 中根据 DOMAIN 动态设置，支持多实例
# 此处保留占位，main() 会覆盖
TUNNEL_NAME=""
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_ROTATE_KEEP=5          # FIX-9: 保留最近 N 份日志
readonly CF_API_RETRY=3             # FIX-7: API 最大重试次数
readonly CF_API_RETRY_DELAY=3       # FIX-7: 重试间隔（秒）

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
TUNNEL_ID=""
OC_PID_FILE=""   # FIX-5: PID 文件路径（卸载时使用，启动已交给服务管理器）
STATE_FILE=""    # FIX-H: 部署状态机文件
NON_INTERACTIVE=false  # FIX-G: --yes 模式

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
# FIX-9: 日志 rotation — 保留最近 LOG_ROTATE_KEEP 份，删除旧的
# ============================================================
rotate_logs() {
    local log_dir="$1"
    [ -d "$log_dir" ] || return 0
    # 列出所有 deploy-*.log，按时间排序，删除超出保留数量的旧日志
    local logs
    logs=$(ls -t "$log_dir"/deploy-*.log 2>/dev/null) || return 0
    local count
    count=$(echo "$logs" | wc -l | tr -d ' ')
    if [ "$count" -gt "$LOG_ROTATE_KEEP" ]; then
        echo "$logs" | tail -n +"$((LOG_ROTATE_KEEP + 1))" | xargs rm -f
        info "日志 rotation: 保留最近 $LOG_ROTATE_KEEP 份，已清理 $((count - LOG_ROTATE_KEEP)) 份旧日志"
    fi
}

# ============================================================
# FIX-G: 交互确认（--yes 模式下自动确认）
# 用法: confirm "提示文字" || return
# ============================================================
confirm() {
    local prompt="${1:-确认? (y/n)}"
    if [ "$NON_INTERACTIVE" = "true" ]; then
        info "[非交互] 自动确认: $prompt"
        return 0
    fi
    read -rp "$prompt (y/n): " -n 1; echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ============================================================
# FIX-H: 部署状态机
# 每步完成后写入 STATE_FILE，重复运行时跳过已完成步骤
# 步骤: deps → openclaw_install → openclaw_config →
#        tunnel → access → service → done
# ============================================================
STATE_STEPS=(deps openclaw_install openclaw_config tunnel access service done)

state_get() {
    [ -f "$STATE_FILE" ] && cat "$STATE_FILE" 2>/dev/null || echo ""
}

state_set() {
    local step="$1"
    printf '%s\n' "$step" > "$STATE_FILE"
    chmod 600 "$STATE_FILE"
}

state_done() {
    local step="$1"
    local current
    current=$(state_get)
    [ -z "$current" ] && return 1   # 没有状态 = 未开始
    local i j
    for i in "${!STATE_STEPS[@]}"; do
        [ "${STATE_STEPS[$i]}" = "$current" ] && break
    done
    for j in "${!STATE_STEPS[@]}"; do
        [ "${STATE_STEPS[$j]}" = "$step" ] && break
    done
    # current 的索引 >= step 的索引 → 该步骤已完成
    [ "$i" -ge "$j" ]
}

state_reset() {
    rm -f "$STATE_FILE"
    info "部署状态已重置"
}


_sensitive_begin() {
    case "$-" in *x*) _TRACE_WAS_ON=1 ;; *) _TRACE_WAS_ON=0 ;; esac
    { set +x; } 2>/dev/null
}
_sensitive_end() {
    [ "${_TRACE_WAS_ON:-0}" = "1" ] && set -x
    _TRACE_WAS_ON=0
}

# ============================================================
# 版本比较（纯 bash，兼容 Bash 3.2+）
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
# JSON 字段提取（jq → python3 → sed 三重回退）
# ============================================================
json_field() {
    local json="$1" field="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$field" 2>/dev/null
    elif command -v python3 &>/dev/null; then
        local py_keys
        py_keys=$(echo "$field" | sed 's/^\.//' | sed "s/\./']['/g")
        echo "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '${py_keys}'.split(\"']['\")
    for k in keys:
        d = d[k]
    print(d if d is not None else '')
except Exception:
    print('')
" 2>/dev/null
    else
        warn "⚠️  未安装 jq 或 python3，使用 sed 解析（不稳定，强烈建议安装 jq）"
        local key
        key=$(echo "$field" | sed 's/.*\.\([^.]*\)$/\1/')
        echo "$json" | sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" | head -1
    fi
}

# ============================================================
# FIX-7 + FIX-A: Cloudflare API 封装
# 2xx → 成功返回响应体
# 4xx → 客户端错误（权限/参数），不重试，直接返回 1
# 5xx/网络错误 → 服务端错误，最多重试 CF_API_RETRY 次
# ============================================================
cf_api_call() {
    local desc="$1"; shift
    local attempt resp http_code body

    for attempt in $(seq 1 $CF_API_RETRY); do
        _sensitive_begin
        # -w 在响应体末尾追加 HTTP 状态码标记
        resp=$(curl -s -w "\n__HTTP_CODE__:%{http_code}" "$@" 2>>"$LOG_FILE") || resp=""
        _sensitive_end

        http_code=$(echo "$resp" | grep '__HTTP_CODE__:' | sed 's/__HTTP_CODE__://')
        body=$(echo "$resp" | grep -v '__HTTP_CODE__:')

        if [[ "$http_code" =~ ^2 ]]; then
            # 2xx: 成功
            echo "$body"
            return 0
        elif [[ "$http_code" =~ ^4 ]]; then
            # 4xx: 客户端错误，重试无意义，直接失败
            warn "⚠️  CF API [$desc] 客户端错误 HTTP $http_code（权限或参数问题，不重试）"
            warn "    响应: $(echo "$body" | head -c 300)"
            return 1
        else
            # 5xx 或网络错误: 可重试
            if [ "$attempt" -lt "$CF_API_RETRY" ]; then
                warn "⚠️  CF API [$desc] 第 $attempt 次失败 (HTTP ${http_code:-网络错误})，${CF_API_RETRY_DELAY}s 后重试..."
                sleep "$CF_API_RETRY_DELAY"
            else
                warn "⚠️  CF API [$desc] 连续失败 $CF_API_RETRY 次，放弃"
                warn "    最后响应: $(echo "$body" | head -c 300)"
                return 1
            fi
        fi
    done
    return 1
}

# ============================================================
# FIX-4: 安全写入 Token（错误信息含版本提示）
# ============================================================
oc_set_token() {
    local token="$1"
    if echo -n "$token" | openclaw config set gateway.auth.token --stdin >> "$LOG_FILE" 2>&1; then
        return 0
    fi
    local tmpf
    tmpf=$(mktemp) || error "无法创建临时文件"
    trap 'rm -f "$tmpf"' RETURN
    chmod 600 "$tmpf"
    printf '%s' "$token" > "$tmpf"
    if openclaw config set gateway.auth.token --file "$tmpf" >> "$LOG_FILE" 2>&1; then
        return 0
    fi
    # FIX-4: 明确告知用户需要的版本，而不是只说"请升级"
    error "无法安全写入 OpenClaw Token。
  --stdin 和 --file 两种方式均不支持，说明当前 openclaw 版本过旧。
  请升级到 openclaw >= 1.4.0:
    npm install -g openclaw@latest
  当前版本: $(openclaw --version 2>/dev/null | head -n1 || echo '未知')"
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

# FIX-10: debug 模式下输出完整环境快照
dump_debug_env() {
    echo "======== ClawHole v${SCRIPT_VERSION} 环境快照 [$(date)] ========"
    echo "OS       : $OS_NAME $OS_VERSION ($OS_FAMILY)"
    echo "PKG_MGR  : $PKG_MANAGER"
    echo "BASH     : $BASH_VERSION"
    echo "ARCH     : $(uname -m)"
    echo "USER     : $(id)"
    echo "PATH     : $PATH"
    echo "jq       : $(command -v jq 2>/dev/null || echo '未安装')"
    echo "python3  : $(command -v python3 2>/dev/null || echo '未安装')"
    echo "node     : $(node --version 2>/dev/null || echo '未安装')"
    echo "cloudflared: $(cloudflared --version 2>/dev/null | head -n1 || echo '未安装')"
    echo "openclaw : $(openclaw --version 2>/dev/null | head -n1 || echo '未安装')"
    echo "DOMAIN   : ${DOMAIN:-'(未设置)'}"
    echo "PORT     : ${PORT:-'(未设置)'}"
    echo "NO_ACCESS: ${NO_ACCESS:-false}"
    echo "LOG_FILE : $LOG_FILE"
    echo "========================================================"
}

# ============================================================
# 架构映射
# ============================================================
_map_arch() {
    local raw
    raw=$(uname -m)
    case "$raw" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "arm"   ;;
        *) error "不支持的 CPU 架构: $raw" ;;
    esac
}

# ============================================================
# FIX-2: SHA256 校验函数
# 用法: verify_sha256 <文件路径> <预期哈希>
# ============================================================
verify_sha256() {
    local filepath="$1" expected="$2"
    local actual
    if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "$filepath" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        actual=$(shasum -a 256 "$filepath" | awk '{print $1}')
    else
        warn "⚠️  sha256sum / shasum 均不可用，跳过校验（建议安装 coreutils）"
        return 0
    fi
    if [ "$actual" != "$expected" ]; then
        error "SHA256 校验失败！文件可能被篡改或下载损坏。
  期望: $expected
  实际: $actual
  请删除文件后重试: rm -f $filepath"
    fi
    success "✓ SHA256 校验通过"
}

# FIX-2: 获取 cloudflared 最新版本的 SHA256（从 GitHub Releases 下载 checksums 文件）
_get_cloudflared_checksum() {
    local arch="$1" os_type="$2"
    local filename="cloudflared-${os_type}-${arch}"
    local checksum_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-checksums.txt"
    local checksums
    checksums=$(curl -fsSL "$checksum_url" 2>>"$LOG_FILE") || {
        warn "⚠️  无法获取 cloudflared checksums，跳过 SHA256 校验"
        echo ""
        return 0
    }
    echo "$checksums" | awk -v fn="$filename" '$2 == fn || $2 == ("*" fn) {print $1; exit}'
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
                | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg 2>>"$LOG_FILE"
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
https://pkg.cloudflare.com/cloudflared \
$(lsb_release -cs 2>/dev/null || echo focal) main" \
                | sudo tee /etc/apt/sources.list.d/cloudflared.list >>"$LOG_FILE" 2>&1
            sudo apt-get update  >>"$LOG_FILE" 2>&1
            sudo apt-get install -y cloudflared >>"$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            local arch
            arch=$(_map_arch)
            local rpm_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.rpm"
            sudo rpm -i "$rpm_url" >>"$LOG_FILE" 2>&1 \
                || sudo yum install -y "$rpm_url" >>"$LOG_FILE" 2>&1 || true
            ;;
        *)
            # FIX-2: 通用二进制下载后做 SHA256 校验
            local arch
            arch=$(_map_arch)
            local bin_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"
            local tmp_bin
            tmp_bin=$(mktemp)
            info "下载 cloudflared ($arch)..."
            curl -fsSL "$bin_url" -o "$tmp_bin" || error "下载 cloudflared 失败，请检查网络"
            local expected_hash
            expected_hash=$(_get_cloudflared_checksum "$arch" "linux")
            if [ -n "$expected_hash" ]; then
                verify_sha256 "$tmp_bin" "$expected_hash"
            fi
            sudo mv "$tmp_bin" /usr/local/bin/cloudflared
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
        ver=$(node --version 2>/dev/null | cut -c2-)
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
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >>"$LOG_FILE" 2>&1
            sudo apt-get install -y nodejs >>"$LOG_FILE" 2>&1
            ;;
        rhel|fedora)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash - >>"$LOG_FILE" 2>&1
            sudo yum install -y nodejs >>"$LOG_FILE" 2>&1
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
        read -rp "更新到最新版? (y/n): " -n 1; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 0
    fi
    local npm_root
    npm_root=$(npm root -g 2>/dev/null) || npm_root=""
    if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then
        sudo npm install -g openclaw@latest >>"$LOG_FILE" 2>&1
    else
        npm install -g openclaw@latest >>"$LOG_FILE" 2>&1
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
    if ! command -v jq &>/dev/null; then
        warn "⚠️  未检测到 jq，建议安装以确保 Cloudflare API 解析可靠"
        warn "    macOS: brew install jq  |  Ubuntu/Debian: sudo apt-get install jq"
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

_launchctl_load() {
    local plist="$1"
    local macos_major
    macos_major=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
    if [ "${macos_major:-0}" -ge 13 ]; then
        launchctl bootstrap "gui/$(id -u)" "$plist" 2>/dev/null || true
    else
        launchctl load "$plist" 2>/dev/null || true
    fi
}

_launchctl_unload() {
    local plist="$1"
    local macos_major
    macos_major=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
    if [ "${macos_major:-0}" -ge 13 ]; then
        launchctl bootout "gui/$(id -u)" "$plist" 2>/dev/null || true
    else
        launchctl unload "$plist" 2>/dev/null || true
    fi
}

_install_launchd() {
    local oc_bin="$1"
    local cf_bin
    cf_bin=$(command -v cloudflared 2>/dev/null || echo "/opt/homebrew/bin/cloudflared")
    local dir="$HOME/Library/LaunchAgents"
    mkdir -p "$dir"

    # FIX-6: 检测是否已安装，避免重复注册
    local oc_plist="$dir/ai.openclaw.gateway.plist"
    local cf_plist="$dir/com.cloudflare.cloudflared.plist"

    cat > "$oc_plist" <<EOF
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

    cat > "$cf_plist" <<EOF
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

    local watchdog_script="$OC_CONFIG_DIR/tunnel-watchdog.sh"
    local watchdog_plist="$dir/ai.openclaw.tunnel-watchdog.plist"

    cat > "$watchdog_script" <<'WATCHDOG'
#!/bin/bash
# ClawHole tunnel watchdog — checks cloudflared ha_connections every 5 min
# MIN_HA_CONN: 最小可接受 HA 连接数；本机开 WARP 时 cloudflared 最多只能建 2 路，
# 无 WARP 时可达 4；默认 2 兼容两种场景，必要时可在 plist 里 override。
MIN_HA_CONN=${MIN_HA_CONN:-2}
GATEWAY_PLIST="$HOME/Library/LaunchAgents/ai.openclaw.gateway.plist"

HA_CONN=$(curl -sf --max-time 5 http://127.0.0.1:2000/metrics 2>/dev/null \
  | grep '^cloudflared_tunnel_ha_connections ' | awk '{print $2}')

if [ -z "$HA_CONN" ] || ! [[ "$HA_CONN" =~ ^[0-9]+$ ]] || [ "$HA_CONN" -lt "$MIN_HA_CONN" ]; then
  echo "[$(date)] cloudflared unhealthy (ha_connections=${HA_CONN:-unreachable}, min=$MIN_HA_CONN), kickstart..."
  launchctl kickstart -k "gui/$(id -u)/com.cloudflare.cloudflared"
fi

if ! launchctl list 2>/dev/null | grep -q "ai.openclaw.gateway"; then
  echo "[$(date)] gateway not loaded, loading..."
  launchctl load "$GATEWAY_PLIST"
fi
WATCHDOG
    chmod +x "$watchdog_script"

    cat > "$watchdog_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>ai.openclaw.tunnel-watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$watchdog_script</string>
    </array>
    <key>StartInterval</key><integer>300</integer>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>$OC_CONFIG_DIR/logs/tunnel-watchdog.log</string>
    <key>StandardErrorPath</key><string>$OC_CONFIG_DIR/logs/tunnel-watchdog.log</string>
</dict></plist>
EOF

    # 每日保底重启 cloudflared（04:00），防止 HA 连接静默掉线
    local daily_plist="$dir/ai.openclaw.tunnel-daily-restart.plist"
    cat > "$daily_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>ai.openclaw.tunnel-daily-restart</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/launchctl</string>
        <string>kickstart</string>
        <string>-k</string>
        <string>gui/$(id -u)/com.cloudflare.cloudflared</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key><integer>4</integer>
        <key>Minute</key><integer>0</integer>
    </dict>
    <key>StandardOutPath</key><string>$OC_CONFIG_DIR/logs/tunnel-daily-restart.log</string>
    <key>StandardErrorPath</key><string>$OC_CONFIG_DIR/logs/tunnel-daily-restart.log</string>
</dict></plist>
EOF

    mkdir -p "$OC_CONFIG_DIR/logs"

    # FIX-6: 先 unload 再 load，保证幂等（已注册的先卸掉再重注册）
    _launchctl_unload "$oc_plist"
    _launchctl_load   "$oc_plist"
    _launchctl_unload "$cf_plist"
    _launchctl_load   "$cf_plist"
    _launchctl_unload "$watchdog_plist"
    _launchctl_load   "$watchdog_plist"
    _launchctl_unload "$daily_plist"
    _launchctl_load   "$daily_plist"
    success "✓ launchd 服务已注册（watchdog 每 5 分钟健康检查 + 每日 04:00 保底重启）"
}

_uninstall_launchd() {
    local dir="$HOME/Library/LaunchAgents"
    _launchctl_unload "$dir/ai.openclaw.gateway.plist"
    _launchctl_unload "$dir/com.cloudflare.cloudflared.plist"
    _launchctl_unload "$dir/ai.openclaw.tunnel-watchdog.plist"
    _launchctl_unload "$dir/ai.openclaw.tunnel-daily-restart.plist"
    rm -f "$dir/ai.openclaw.gateway.plist"
    rm -f "$dir/com.cloudflare.cloudflared.plist"
    rm -f "$dir/ai.openclaw.tunnel-watchdog.plist"
    rm -f "$dir/ai.openclaw.tunnel-daily-restart.plist"
    rm -f "$OC_CONFIG_DIR/tunnel-watchdog.sh"
}

_install_systemd() {
    local oc_bin="$1"
    local cf_bin
    cf_bin=$(command -v cloudflared 2>/dev/null || echo "/usr/local/bin/cloudflared")

    # FIX-C: ExecStart 使用 --no-daemon（前台模式），让 systemd 管理进程生命周期
    # FIX-D: 补全 systemd 安全加固项
    sudo tee /etc/systemd/system/openclaw-gateway.service > /dev/null <<EOF
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$oc_bin gateway start --force --no-daemon
Restart=on-failure
RestartSec=10
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$OC_CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # FIX-D: cloudflared 同样补全安全加固
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

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$CF_CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    local watchdog_script="$OC_CONFIG_DIR/tunnel-watchdog.sh"
    cat > "$watchdog_script" <<'WATCHDOG'
#!/bin/bash
# ClawHole tunnel watchdog — checks cloudflared ha_connections
# MIN_HA_CONN: 最小可接受 HA 连接数；默认 2（WARP 场景上限）
MIN_HA_CONN=${MIN_HA_CONN:-2}
CLOUDFLARED_SERVICE="cloudflared-tunnel"

HA_CONN=$(curl -sf --max-time 5 http://127.0.0.1:2000/metrics 2>/dev/null \
  | grep '^cloudflared_tunnel_ha_connections ' | awk '{print $2}')

if [ -z "$HA_CONN" ] || ! [[ "$HA_CONN" =~ ^[0-9]+$ ]] || [ "$HA_CONN" -lt "$MIN_HA_CONN" ]; then
  echo "[$(date)] cloudflared unhealthy (ha_connections=${HA_CONN:-unreachable}, min=$MIN_HA_CONN), restarting..."
  systemctl restart "$CLOUDFLARED_SERVICE"
fi

if ! systemctl is-active --quiet openclaw-gateway; then
  echo "[$(date)] gateway not running, starting..."
  systemctl start openclaw-gateway
fi
WATCHDOG
    chmod +x "$watchdog_script"

    sudo tee /etc/systemd/system/clawhole-watchdog.service > /dev/null <<EOF
[Unit]
Description=ClawHole Tunnel Watchdog
After=network-online.target

[Service]
Type=oneshot
ExecStart=$watchdog_script
EOF

    sudo tee /etc/systemd/system/clawhole-watchdog.timer > /dev/null <<EOF
[Unit]
Description=ClawHole Tunnel Watchdog Timer

[Timer]
OnBootSec=60
OnUnitActiveSec=300

[Install]
WantedBy=timers.target
EOF

    # 每日保底重启 cloudflared（04:00），防止 HA 连接静默掉线
    sudo tee /etc/systemd/system/clawhole-daily-restart.service > /dev/null <<EOF
[Unit]
Description=ClawHole Daily cloudflared Restart

[Service]
Type=oneshot
ExecStart=/bin/systemctl restart cloudflared-tunnel
EOF

    sudo tee /etc/systemd/system/clawhole-daily-restart.timer > /dev/null <<EOF
[Unit]
Description=ClawHole Daily cloudflared Restart Timer

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload

    # FIX-6: enable 幂等（已 enable 的不会报错）
    sudo systemctl enable openclaw-gateway  >>"$LOG_FILE" 2>&1 || true
    sudo systemctl enable cloudflared-tunnel >>"$LOG_FILE" 2>&1 || true
    sudo systemctl enable --now clawhole-watchdog.timer >>"$LOG_FILE" 2>&1 || true
    sudo systemctl enable --now clawhole-daily-restart.timer >>"$LOG_FILE" 2>&1 || true
    success "✓ systemd 服务已注册（watchdog 每 5 分钟健康检查 + 每日 04:00 保底重启）"
}

_uninstall_systemd() {
    sudo systemctl stop    openclaw-gateway    2>/dev/null || true
    sudo systemctl stop    cloudflared-tunnel  2>/dev/null || true
    sudo systemctl stop    clawhole-watchdog.timer 2>/dev/null || true
    sudo systemctl stop    clawhole-daily-restart.timer 2>/dev/null || true
    sudo systemctl disable openclaw-gateway    2>/dev/null || true
    sudo systemctl disable cloudflared-tunnel  2>/dev/null || true
    sudo systemctl disable clawhole-watchdog.timer 2>/dev/null || true
    sudo systemctl disable clawhole-daily-restart.timer 2>/dev/null || true
    sudo rm -f /etc/systemd/system/openclaw-gateway.service
    sudo rm -f /etc/systemd/system/cloudflared-tunnel.service
    sudo rm -f /etc/systemd/system/clawhole-watchdog.service
    sudo rm -f /etc/systemd/system/clawhole-watchdog.timer
    sudo rm -f /etc/systemd/system/clawhole-daily-restart.service
    sudo rm -f /etc/systemd/system/clawhole-daily-restart.timer
    rm -f "$OC_CONFIG_DIR/tunnel-watchdog.sh"
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
            local dir="$HOME/Library/LaunchAgents"
            _launchctl_load "$dir/ai.openclaw.gateway.plist"
            _launchctl_load "$dir/com.cloudflare.cloudflared.plist"
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
            local dir="$HOME/Library/LaunchAgents"
            _launchctl_unload "$dir/ai.openclaw.gateway.plist"
            _launchctl_unload "$dir/com.cloudflare.cloudflared.plist"
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

    if [ -z "${DOMAIN:-}" ]; then
        [ "$NON_INTERACTIVE" = "true" ] && error "--yes 模式下必须通过 --domain 指定域名"
        while true; do
            read -rp "▶ 域名 (如 claw.example.com): " DOMAIN
            [ -z "$DOMAIN" ] && continue
            validate_domain "$DOMAIN" && break
        done
    else
        validate_domain "$DOMAIN"
    fi

    # FIX-F: TUNNEL_NAME 绑定到域名，支持多实例
    TUNNEL_NAME="openclaw-$(echo "$DOMAIN" | tr '.' '-')"
    info "Tunnel 名称: $TUNNEL_NAME"

    if [ -z "${PORT:-}" ]; then
        if [ "$NON_INTERACTIVE" = "true" ]; then
            PORT="$DEFAULT_PORT"
            info "[非交互] 使用默认端口 $PORT"
        else
            read -rp "▶ 端口 (默认 $DEFAULT_PORT): " PORT
            PORT="${PORT:-$DEFAULT_PORT}"
        fi
    fi
    validate_port "$PORT"

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

    if [ "$NON_INTERACTIVE" != "true" ]; then
        echo ""
        read -rp "按 Enter 继续..."
        echo ""
    fi
}

# ============================================================
# 配置 OpenClaw（只写配置，不自己 fork 进程）
# FIX-C: 进程生命周期完全交给 systemd / launchd
#         这里只做：停旧服务 → 写配置 → 验证配置
#         实际启动在 service_start() 之后
# ============================================================
configure_openclaw() {
    info "配置 OpenClaw..."
    mkdir -p "$OC_CONFIG_DIR"

    # 停旧服务（通过服务管理器，不用 pgrep / pkill）
    # FIX-C: 此时服务管理器可能还没注册，用 openclaw 自己的 stop 命令兜底
    openclaw gateway stop >>"$LOG_FILE" 2>&1 || true
    sleep 1

    oc_config_set gateway.port       "$PORT"
    oc_config_set gateway.bind       "loopback"
    oc_config_set gateway.mode       "local"
    oc_config_set gateway.auth.mode  "token"
    oc_config_set gateway.auth.token "$TOKEN"
    success "✓ 配置已写入"

    openclaw config validate >>"$LOG_FILE" 2>&1 \
        || error "OpenClaw 配置验证失败，请查看日志: $LOG_FILE"
    success "✓ 配置验证通过"
    # 注意：不在这里启动进程，由 service_start() 通过 systemd/launchd 统一启动
}

# ============================================================
# 配置 Cloudflare Tunnel
# ============================================================
configure_tunnel() {
    info "配置 Cloudflare Tunnel..."

    if [ ! -f "$CF_CONFIG_DIR/cert.pem" ]; then
        echo -e "${YELLOW}⚠️  需要先完成 Cloudflare 登录认证${NC}"
        confirm "按 Enter 打开浏览器认证" || true
        cloudflared tunnel login >>"$LOG_FILE" 2>&1 || error "Cloudflare 认证失败，请查看日志: $LOG_FILE"
        success "✓ 认证成功"
    else
        success "✓ 已有认证凭据"
    fi

    # FIX-B: 用 --output json 解析 tunnel list，不再文本 grep
    local tunnel_id=""
    local list_json
    list_json=$(cloudflared tunnel list --output json 2>>"$LOG_FILE") || list_json="[]"

    if command -v jq &>/dev/null; then
        tunnel_id=$(echo "$list_json" | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id" 2>/dev/null | head -1)
    elif command -v python3 &>/dev/null; then
        tunnel_id=$(echo "$list_json" | python3 -c "
import sys, json
try:
    for t in json.load(sys.stdin):
        if t.get('name') == '$TUNNEL_NAME':
            print(t.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null)
    else
        # sed 回退：有字段顺序风险，输出警告
        warn "⚠️  未安装 jq/python3，使用 sed 解析 tunnel list（不稳定）"
        tunnel_id=$(echo "$list_json" | sed -n "s/.*\"name\":\"${TUNNEL_NAME}\".*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
    fi

    if [ -n "$tunnel_id" ] && [ "$tunnel_id" != "null" ]; then
        warn "⚠️  检测到同名隧道，复用: $tunnel_id"
        if [ ! -f "$CF_CONFIG_DIR/${tunnel_id}.json" ]; then
            error "凭据文件 $CF_CONFIG_DIR/${tunnel_id}.json 不存在。
  请先手动删除旧隧道: cloudflared tunnel delete $TUNNEL_NAME
  然后重新运行本脚本。"
        fi
    else
        # FIX-1: --output json 获取结构化输出
        local create_out
        create_out=$(cloudflared tunnel create --output json "$TUNNEL_NAME" 2>>"$LOG_FILE") \
            || error "创建隧道失败，请查看日志: $LOG_FILE"
        tunnel_id=$(json_field "$create_out" '.id')
        [ -z "$tunnel_id" ] || [ "$tunnel_id" = "null" ] \
            && error "无法从 JSON 输出解析 Tunnel ID，原始输出: $create_out"
        success "✓ 隧道创建成功: $tunnel_id"
    fi

    TUNNEL_ID="$tunnel_id"

    # 生成 config.yml
    mkdir -p "$CF_CONFIG_DIR"
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $tunnel_id
credentials-file: $CF_CONFIG_DIR/$tunnel_id.json
protocol: http2
metrics: 127.0.0.1:2000

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

    # FIX-6: DNS 路由幂等——already exists 不视为错误
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

    [ -z "$TUNNEL_ID" ] && error "TUNNEL_ID 未设置，请确保 configure_tunnel 已成功执行"

    echo -e "${GREEN}===== Cloudflare Access (Zero Trust) =====${NC}"

    if [ -z "${CF_API_TOKEN:-}" ]; then
        read -rsp "▶ CF API Token: " CF_API_TOKEN; echo ""
    fi
    [ -z "${CF_ACCOUNT_ID:-}" ] && read -rp  "▶ CF Account ID: "                   CF_ACCOUNT_ID
    [ -z "${ACCESS_EMAIL:-}" ]  && read -rp  "▶ 允许访问的邮箱: "                   ACCESS_EMAIL
    [ -z "${CF_TEAM_NAME:-}" ]  && read -rp  "▶ Zero Trust Team Name (如 myteam): " CF_TEAM_NAME

    local api="https://api.cloudflare.com/client/v4"
    local resp app_id app_aud

    # FIX-7: 创建 Access Application（带重试）
    info "创建 Access Application..."
    _sensitive_begin
    resp=$(cf_api_call "创建 Access App" \
        -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"OpenClaw\",\"domain\":\"$DOMAIN\",\"type\":\"self_hosted\",
             \"session_duration\":\"24h\",\"auto_redirect_to_identity\":false}") || resp=""
    _sensitive_end

    app_id=$(json_field "$resp" '.result.id')
    app_aud=$(json_field "$resp" '.result.aud')

    if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
        warn "创建失败或已存在，尝试查找已有 Application..."
        local existing_resp

        _sensitive_begin
        # FIX-7: 查询也带重试
        existing_resp=$(cf_api_call "查询 Access Apps" \
            "$api/accounts/$CF_ACCOUNT_ID/access/apps" \
            -H "Authorization: Bearer $CF_API_TOKEN") || existing_resp=""
        _sensitive_end

        if command -v jq &>/dev/null; then
            app_id=$(echo "$existing_resp"  | jq -r ".result[] | select(.domain==\"$DOMAIN\") | .id"  2>/dev/null | head -1)
            app_aud=$(echo "$existing_resp" | jq -r ".result[] | select(.domain==\"$DOMAIN\") | .aud" 2>/dev/null | head -1)
        elif command -v python3 &>/dev/null; then
            app_id=$(echo "$existing_resp" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for app in data.get('result', []):
        if app.get('domain') == '$DOMAIN':
            print(app.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null)
            app_aud=$(echo "$existing_resp" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for app in data.get('result', []):
        if app.get('domain') == '$DOMAIN':
            print(app.get('aud', ''))
            break
except Exception:
    pass
" 2>/dev/null)
        else
            warn "⚠️  未安装 jq 或 python3，使用 sed 解析（不可靠）"
            app_id=$(echo "$existing_resp"  | sed -n "s/.*\"domain\":\"$DOMAIN\".*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1)
            app_aud=$(echo "$existing_resp" | sed -n "s/.*\"domain\":\"$DOMAIN\".*\"aud\":\"\([^\"]*\)\".*/\1/p" | head -1)
        fi
    fi

    [ -z "$app_id" ] || [ "$app_id" = "null" ] \
        && error "无法创建或找到 Access Application (domain: $DOMAIN)，请检查 CF API Token 权限"
    success "✓ Application: $app_id  AUD: $app_aud"

    # FIX-7: 创建策略带重试
    _sensitive_begin
    cf_api_call "创建 Access Policy" \
        -X POST "$api/accounts/$CF_ACCOUNT_ID/access/apps/$app_id/policies" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"Whitelist\",\"decision\":\"allow\",
             \"include\":[{\"email\":{\"email\":\"$ACCESS_EMAIL\"}}]}" \
        >>"$LOG_FILE" 2>&1 || warn "⚠️  Policy 创建失败，请在 Cloudflare Dashboard 手动添加"
    _sensitive_end
    success "✓ 访问策略已创建 (邮箱: $ACCESS_EMAIL)"

    # 更新 config.yml 启用 Origin JWT 验证
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $TUNNEL_ID
credentials-file: $CF_CONFIG_DIR/$TUNNEL_ID.json
protocol: http2
metrics: 127.0.0.1:2000

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
# FIX-E: 端口连通性为主检查，/health 为辅助增强检查
# ============================================================
verify_deployment() {
    echo -e "${GREEN}===== 部署验证 =====${NC}"
    local all_ok=true

    # 1. 主检查：端口连通性（最可靠）
    info "检查 OpenClaw 端口 (主检查)..."
    local waited=0
    until port_in_use "$PORT"; do
        sleep 3; waited=$((waited + 3))
        [ "$waited" -ge 30 ] && break
    done

    if port_in_use "$PORT"; then
        success "✓ OpenClaw 监听 127.0.0.1:$PORT"
    else
        warn "⚠️  OpenClaw 未监听 $PORT（服务可能启动慢，稍后再试）"
        all_ok=false
    fi

    # 2. 辅助检查：/health endpoint（不强依赖，版本兼容问题跳过）
    # FIX-E: /health 不存在时不视为错误，仅作增强信息
    info "检查 /health endpoint（辅助）..."
    local health_code
    health_code=$(curl -sf -o /dev/null -w "%{http_code}" \
        --max-time 5 "http://127.0.0.1:${PORT}/health" 2>/dev/null || echo "000")
    if [[ "$health_code" =~ ^(200|204)$ ]]; then
        success "✓ /health 返回 HTTP $health_code"
    elif [ "$health_code" = "404" ]; then
        info "  /health 返回 404（此版本 OpenClaw 不支持该 endpoint，正常）"
    elif [ "$health_code" = "000" ]; then
        info "  /health 无响应（可能服务仍在启动，端口已通则不影响使用）"
    else
        info "  /health 返回 HTTP $health_code（不影响主服务）"
    fi

    # 3. Cloudflare Tunnel 进程
    info "检查 Cloudflare Tunnel..."
    local cf_waited=0
    until pgrep -f "cloudflared.*tunnel" &>/dev/null; do
        sleep 5; cf_waited=$((cf_waited + 5))
        [ "$cf_waited" -ge 30 ] && break
    done

    if pgrep -f "cloudflared.*tunnel" &>/dev/null; then
        success "✓ cloudflared 进程运行中"
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

    # 4. 域名可达性
    info "检查域名可达性 ($DOMAIN)..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 10 "https://$DOMAIN" 2>/dev/null || echo "000")
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
    # FIX-G: --yes 模式下自动确认
    confirm "确认卸载所有组件?" || exit 0

    # FIX-C: 通过服务管理器停服务，不再手动 kill 进程
    service_stop
    service_uninstall

    openclaw gateway stop 2>/dev/null || true
    openclaw config unset gateway.port       2>/dev/null || true
    openclaw config unset gateway.bind       2>/dev/null || true
    openclaw config unset gateway.auth.mode  2>/dev/null || true
    openclaw config unset gateway.auth.token 2>/dev/null || true
    rm -f "$OC_CONFIG_DIR/.auth_token"
    state_reset

    confirm "卸载 OpenClaw CLI?" && {
        local npm_root
        npm_root=$(npm root -g 2>/dev/null) || npm_root=""
        if [[ "$OS_FAMILY" != "macos" ]] && [[ -n "$npm_root" ]] && [[ ! -w "$npm_root" ]]; then
            sudo npm uninstall -g openclaw 2>/dev/null || true
        else
            npm uninstall -g openclaw 2>/dev/null || true
        fi
        success "✓ OpenClaw CLI 已卸载"
    }

    confirm "删除 Cloudflare Tunnel '$TUNNEL_NAME'?" && {
        local list_json tid
        list_json=$(cloudflared tunnel list --output json 2>/dev/null) || list_json="[]"
        if command -v jq &>/dev/null; then
            tid=$(echo "$list_json" | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id" 2>/dev/null | head -1)
        else
            tid=$(echo "$list_json" | python3 -c "
import sys,json
try:
    for t in json.load(sys.stdin):
        if t.get('name')=='$TUNNEL_NAME': print(t['id']); break
except: pass
" 2>/dev/null)
        fi
        if [ -n "$tid" ] && [ "$tid" != "null" ]; then
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
    }

    if [ -n "${DOMAIN:-}" ]; then
        confirm "删除 Cloudflare DNS 记录 ($DOMAIN)?" && {
            cloudflared tunnel route dns delete "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null \
                && success "✓ DNS 记录已删除" \
                || warn "⚠️  DNS 记录删除失败，请在 Cloudflare Dashboard 手动操作"
        }
    fi

    rm -f "$OC_CONFIG_DIR"/deploy-*.log
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
  --cf-team-name <n>        Zero Trust Team Name (如 myteam)
  --access-email <email>    允许访问的邮箱
  --uninstall               卸载所有已部署组件
  --yes                     非交互模式，跳过所有确认（CI/CD 用）
  --reset-state             重置部署状态机，强制全流程重新执行
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

CI/CD 用法示例:
  OPENCLAW_TOKEN=xxx CF_API_TOKEN=yyy \\
    ./$SCRIPT_NAME \\
      --domain claw.example.com \\
      --cf-account-id <id> \\
      --cf-team-name myteam \\
      --access-email admin@example.com \\
      --yes

部署流程:
  1. 安装依赖 (Node.js, cloudflared, openclaw)
  2. 配置 OpenClaw Gateway（仅监听 loopback）
  3. 创建 Cloudflare Tunnel（零公网端口暴露）
  4. 可选：启用 Cloudflare Access Zero Trust（邮箱白名单）
  5. 注册系统服务（systemd/launchd 托管，开机自启）
  6. 验证部署状态
EOF
    exit 0
}

# ============================================================
# 主流程
# ============================================================
main() {
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
            --yes)           NON_INTERACTIVE=true; shift   ;;
            --debug)         DEBUG=1;              shift   ;;
            --reset-state)   RESET_STATE=true;     shift   ;;
            --help)          show_help ;;
            *) echo "未知参数: $1"; show_help ;;
        esac
    done

    [ "${DEBUG:-0}" = "1" ] && set -x

    detect_os

    OC_CONFIG_DIR="$HOME/.openclaw"
    CF_CONFIG_DIR="$HOME/.cloudflared"
    LOG_FILE="$OC_CONFIG_DIR/deploy-${TIMESTAMP}.log"
    STATE_FILE="$OC_CONFIG_DIR/.deploy_state"
    OC_PID_FILE="$OC_CONFIG_DIR/gateway.pid"
    mkdir -p "$OC_CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    # FIX-9: 启动时 rotate 旧日志
    rotate_logs "$OC_CONFIG_DIR"

    # FIX-10: debug 模式输出环境快照
    if [ "${DEBUG:-0}" = "1" ]; then
        dump_debug_env | tee -a "$LOG_FILE"
    fi

    [ "${UNINSTALL:-false}" = "true" ] && uninstall

    # FIX-H: 支持手动重置状态机
    [ "${RESET_STATE:-false}" = "true" ] && state_reset

    # FIX-H: 恢复提示
    local current_state
    current_state=$(state_get)
    if [ -n "$current_state" ] && [ "$current_state" != "done" ]; then
        warn "⚠️  检测到未完成的部署（当前进度: $current_state），将从断点继续"
        warn "    如需全新部署，请先运行: $SCRIPT_NAME --reset-state"
    fi

    banner
    # FIX-H: 每步执行前检查状态机，跳过已完成步骤

    if ! state_done "deps"; then
        check_dependencies
        state_set "deps"
    else
        info "跳过依赖安装（已完成）"
    fi

    # get_user_config 每次都执行（TOKEN/DOMAIN 可能需要重新收集）
    get_user_config

    if ! state_done "openclaw_install"; then
        install_openclaw
        state_set "openclaw_install"
    else
        info "跳过 OpenClaw 安装（已完成）"
    fi

    if ! state_done "openclaw_config"; then
        configure_openclaw
        state_set "openclaw_config"
    else
        info "跳过 OpenClaw 配置（已完成）"
    fi

    if ! state_done "tunnel"; then
        configure_tunnel
        state_set "tunnel"
    else
        info "跳过 Tunnel 配置（已完成）"
        # 恢复 TUNNEL_ID（tunnel 已完成时需要从 config.yml 中读取）
        if [ -f "$CF_CONFIG_DIR/config.yml" ]; then
            TUNNEL_ID=$(grep '^tunnel:' "$CF_CONFIG_DIR/config.yml" | awk '{print $2}')
        fi
    fi

    if ! state_done "access"; then
        configure_cf_access
        state_set "access"
    else
        info "跳过 CF Access 配置（已完成）"
    fi

    if ! state_done "service"; then
        service_install
        service_start
        state_set "service"
    else
        info "跳过服务注册（已完成），重启服务..."
        service_start
    fi

    sleep 10
    verify_deployment
    state_set "done"

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
    if [ "${BASH_VERSINFO[0]}" -lt 3 ] || \
       { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
        echo "错误: 需要 Bash 3.2 或更高版本（当前: $BASH_VERSION）"
        exit 1
    fi

    if [[ $EUID -eq 0 ]] && [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${YELLOW}⚠️  不建议以 root 身份运行，脚本会在需要时自动使用 sudo${NC}"
        read -rp "仍要继续? (y/n): " -n 1; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi

    main "$@"
fi
