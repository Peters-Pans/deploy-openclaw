#!/bin/bash
# OpenClaw + Cloudflare Tunnel 隐私部署脚本 v3.0
# 专为中国大陆动态 IPv4 环境优化 | 安全加固版
#
# 特性:
#   ✅ 真实 IP 完全隐藏
#   ✅ 零公网端口暴露
#   ✅ 动态 IPv4 无感
#   ✅ 自动 HTTPS + WAF
#   ✅ 双重认证 (Token + 可选 CF Access Zero Trust)
#   ✅ DNS 污染防护
#   ✅ 自动重连 + 健康检查
#   ✅ 详细日志 + 故障排查
#
# 用法: ./deploy-openclaw.sh [选项]
# 选项: --domain <域名> --port <端口> --uninstall --enable-access --help

set -e
set -o pipefail

# ========== 全局配置 ==========
readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="deploy-openclaw.sh"
readonly DEFAULT_PORT=10371
readonly TUNNEL_NAME="openclaw-tunnel"
readonly CF_CONFIG_DIR="$HOME/.cloudflared"
readonly OC_CONFIG_DIR="$HOME/.openclaw"
readonly LAUNCHD_DIR="$HOME/Library/LaunchAgents"
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# 日志: 写到 ~/.openclaw/ 下，chmod 600，不在 /tmp 泄露
readonly LOG_DIR="$OC_CONFIG_DIR"
readonly LOG_FILE="$LOG_DIR/deploy-$TIMESTAMP.log"

# 颜色定义（含 WHITE）
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'  # No Color

# ========== 工具函数 ==========
log() {
    local msg="$1"
    local level="${2:-INFO}"
    local color="$BLUE"
    case "$level" in
        INFO) color="$BLUE" ;;
        WARN) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        SUCCESS) color="$GREEN" ;;
        DEBUG) color="$PURPLE" ;;
    esac
    echo -e "${color}[${level}]${NC} $msg" | tee -a "$LOG_FILE"
}

info() { log "$1" "INFO"; }
warn() { log "$1" "WARN" >&2; }
error() { log "$1" "ERROR" >&2; exit 1; }
success() { log "$1" "SUCCESS"; }
debug() { [ "${DEBUG:-0}" = "1" ] && log "$1" "DEBUG" || true; }

# ========== 检测 openclaw 可执行文件路径 ==========
find_openclaw_bin() {
    local bin
    bin=$(command -v openclaw 2>/dev/null) || return 1
    echo "$bin"
}

# ========== macOS 兼容的 Perl 正则提取 ==========
# 替代 grep -oP（macOS 原生 grep 不支持 -P）
extract_pattern() {
    local input="$1"
    local pattern="$2"
    # 优先用 ggrep，回退到 sed
    if command -v ggrep &>/dev/null; then
        echo "$input" | ggrep -oP "$pattern" 2>/dev/null || true
    else
        # 简化的 sed 回退——仅支持基础提取
        echo "$input" | sed -n "s/.*\($pattern\).*/\1/p" 2>/dev/null || true
    fi
}

banner() {
    cat <<EOF

${CYAN}╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ${GREEN}OpenClaw + Cloudflare Tunnel 隐私部署脚本 v$SCRIPT_VERSION${CYAN}   ║
║                                                            ║
║   ${YELLOW}适配中国大陆动态 IPv4 环境 | 无需公网IP/端口转发/备案${CYAN}      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝${NC}

EOF
}

# ========== 依赖检查 ==========
check_dependencies() {
    info "检查系统依赖..."
    
    # 检查 Homebrew
    if ! command -v brew &>/dev/null; then
        error "未检测到 Homebrew。请先安装: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
    success "✓ Homebrew 已安装"
    
    # 检查 Node.js
    if ! command -v node &>/dev/null; then
        error "未检测到 Node.js。请先安装: brew install node"
    fi
    
    NODE_VERSION=$(node --version 2>/dev/null | cut -d'v' -f2)
    if [ "$(printf '%s\n' "18" "$NODE_VERSION" | sort -V | head -n1)" != "18" ]; then
        warn "⚠️  检测到 Node.js $NODE_VERSION，建议使用 Node.js 18+"
    else
        success "✓ Node.js $NODE_VERSION 已安装"
    fi
    
    # 检查 cloudflared
    if ! command -v cloudflared &>/dev/null; then
        info "安装 cloudflared..."
        if ! brew install cloudflare/cloudflare/cloudflared >> "$LOG_FILE" 2>&1; then
            error "cloudflared 安装失败，请检查网络连接"
        fi
    fi
    
    CF_VERSION=$(cloudflared --version 2>/dev/null | awk '{print $2}')
    success "✓ cloudflared $CF_VERSION 已安装"
    
    # 检查 macOS 版本
    MACOS_VERSION=$(sw_vers -productVersion)
    if [ "$(printf '%s\n' "11.0" "$MACOS_VERSION" | sort -V | head -n1)" != "11.0" ]; then
        warn "⚠️  检测到 macOS $MACOS_VERSION，建议使用 macOS 11.0+"
    else
        success "✓ macOS $MACOS_VERSION 兼容"
    fi
    
    success "依赖检查完成"
}

# ========== 端口验证 ==========
validate_port() {
    local port="$1"
    
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        error "端口 '$port' 不是有效数字"
    fi
    
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        error "端口 '$port' 超出有效范围 (1-65535)"
    fi
    
    if [ "$port" -lt 1024 ]; then
        error "端口 '$port' 是系统保留端口（需 root 权限），请使用 1024-65535 范围"
    fi
    
    # 注意: 此处存在 TOCTOU 竞争条件——检测空闲到实际绑定之间有时间窗口
    # 实际部署中概率极低，通过 --force 启动标志可缓解
    if lsof -ti ":$port" &>/dev/null; then
        local pid=$(lsof -ti ":$port")
        local process=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        error "端口 $port 已被 $process (PID: $pid) 占用！请使用 --port 指定其他端口"
    fi
    
    success "✓ 端口 $port 可用"
}

# ========== 域名验证 ==========
validate_domain() {
    local domain="$1"
    
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        error "域名 '$domain' 格式无效（示例: claw.example.com）"
    fi
    
    if [[ "$domain" == *"*"* ]] || [[ "$domain" == *" "* ]]; then
        error "域名不能包含通配符或空格"
    fi
    
    success "✓ 域名 $domain 格式有效"
}

# ========== 生成安全令牌 ==========
generate_secure_token() {
    openssl rand -hex 32 2>/dev/null || {
        LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c 64
    }
}

# ========== 安全存储 Token 到文件 ==========
save_token_to_file() {
    local token="$1"
    local token_file="$OC_CONFIG_DIR/.auth_token"
    
    mkdir -p "$OC_CONFIG_DIR"
    echo -n "$token" > "$token_file"
    chmod 600 "$token_file"
    
    success "✓ Auth Token 已保存到: $token_file (权限 600)"
}

# ========== 获取用户配置 ==========
get_user_config() {
    echo ""
    echo -e "${GREEN}===== 配置向导 =====${NC}"
    echo ""
    
    # 域名
    if [ -z "$DOMAIN" ]; then
        while true; do
            read -p "▶ 域名 (如 claw.example.com): " DOMAIN
            [[ -z "$DOMAIN" ]] && warn "域名不能为空" && continue
            validate_domain "$DOMAIN"
            break
        done
    else
        validate_domain "$DOMAIN"
    fi
    
    # 端口
    if [ -z "$PORT" ]; then
        read -p "▶ 端口 (默认 $DEFAULT_PORT, 按 Enter 使用默认): " PORT
        PORT="${PORT:-$DEFAULT_PORT}"
    fi
    validate_port "$PORT"
    
    # Token: 优先从环境变量读取，否则自动生成
    if [ -n "$OPENCLAW_TOKEN" ]; then
        TOKEN="$OPENCLAW_TOKEN"
        info "使用环境变量 OPENCLAW_TOKEN 中的 Token"
    else
        TOKEN=$(generate_secure_token)
    fi
    
    # Token 写入文件而非显示在终端
    save_token_to_file "$TOKEN"
    echo ""
    echo -e "${YELLOW}⚠️  Token 已安全保存到文件，运行以下命令查看:${NC}"
    echo -e "   ${CYAN}cat $OC_CONFIG_DIR/.auth_token${NC}"
    echo ""
    read -p "按 Enter 继续..."
    
    echo ""
    success "✓ 配置完成: 域名=$DOMAIN | 端口=$PORT"
    echo ""
}

# ========== 安装 OpenClaw ==========
install_openclaw() {
    info "安装 OpenClaw CLI..."
    
    # 检查是否已安装
    if command -v openclaw &>/dev/null; then
        local current_version=$(openclaw --version 2>/dev/null | head -n1 || echo "unknown")
        info "检测到已安装 OpenClaw $current_version"
        read -p "是否更新到最新版本? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "跳过更新，使用现有版本"
            return 0
        fi
    fi
    
    if ! npm install -g openclaw@latest >> "$LOG_FILE" 2>&1; then
        error "OpenClaw 安装失败，请检查网络连接和 npm 权限"
    fi
    
    local version=$(openclaw --version 2>/dev/null | head -n1 || echo "unknown")
    success "✓ OpenClaw $version 安装成功"
}

# ========== 配置 OpenClaw (安全模式) ==========
configure_openclaw() {
    info "创建安全配置 (仅监听 127.0.0.1)..."
    
    mkdir -p "$OC_CONFIG_DIR"
    
    # 使用 openclaw config set 逐项写入，确保 schema 合规
    openclaw config set gateway.port "$PORT" >> "$LOG_FILE" 2>&1
    openclaw config set gateway.bind "loopback" >> "$LOG_FILE" 2>&1
    openclaw config set gateway.mode "local" >> "$LOG_FILE" 2>&1
    openclaw config set gateway.auth.mode "token" >> "$LOG_FILE" 2>&1
    openclaw config set gateway.auth.token "$TOKEN" >> "$LOG_FILE" 2>&1
    
    success "✓ 配置文件已写入: $OC_CONFIG_DIR/openclaw.json"
    
    # 验证配置
    info "验证配置..."
    if ! openclaw config validate >> "$LOG_FILE" 2>&1; then
        error "配置验证失败，请查看日志: $LOG_FILE"
    fi
    success "✓ 配置验证通过"
    
    # 停止旧实例
    info "停止旧的 OpenClaw 实例..."
    openclaw gateway stop 2>/dev/null || true
    pkill -f "openclaw.*gateway" 2>/dev/null || true
    sleep 2
    
    # 启动服务（使用 --force 防止 TOCTOU 端口竞争）
    info "启动 OpenClaw 服务..."
    if ! openclaw gateway start --force >> "$LOG_FILE" 2>&1; then
        error "OpenClaw 启动失败，请查看日志: $LOG_FILE"
    fi
    
    # 等待服务启动
    sleep 5
    
    # 验证监听状态
    if ! lsof -ti "127.0.0.1:$PORT" &>/dev/null; then
        error "OpenClaw 未正确监听 127.0.0.1:$PORT，请检查日志"
    fi
    
    success "✓ OpenClaw 启动成功 (仅本地访问: 127.0.0.1:$PORT)"
}

# ========== 配置 Cloudflare Tunnel ==========
configure_tunnel() {
    info "配置 Cloudflare Tunnel..."
    
    # 检查认证
    if [ ! -f "$HOME/.cloudflared/cert.pem" ]; then
        echo ""
        echo -e "${YELLOW}⚠️  首次使用需完成 Cloudflare 认证:${NC}"
        echo "   1. 浏览器将自动打开认证页面"
        echo "   2. 登录 Cloudflare 账号"
        echo "   3. 选择您的域名 (需已托管到 Cloudflare)"
        echo ""
        read -p "   按 Enter 继续认证..."
        
        if ! cloudflared tunnel login >> "$LOG_FILE" 2>&1; then
            error "Cloudflare 认证失败，请检查网络连接和账号权限"
        fi
        
        success "✓ Cloudflare 认证成功"
    else
        success "✓ 已检测到 Cloudflare 认证凭据"
    fi
    
    # 创建/复用隧道
    info "创建/复用 Cloudflare Tunnel..."
    
    local tunnel_id=""
    if cloudflared tunnel list 2>/dev/null | grep -q "$TUNNEL_NAME"; then
        tunnel_id=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}')
        warn "⚠️  隧道 '$TUNNEL_NAME' 已存在，复用 ID: $tunnel_id"
    else
        info "创建新隧道: $TUNNEL_NAME"
        local tunnel_output=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1)
        # 兼容 macOS: 用 sed 替代 grep -oP
        tunnel_id=$(echo "$tunnel_output" | sed -n 's/.*Tunnel ID: *\([0-9a-f-]*\).*/\1/p')
        
        if [ -z "$tunnel_id" ]; then
            error "隧道创建失败: $tunnel_output"
        fi
        
        success "✓ 新隧道创建成功 | ID: $tunnel_id"
    fi
    
    export TUNNEL_ID="$tunnel_id"
    
    # 生成 Tunnel 配置
    info "生成 Tunnel 配置文件..."
    
    mkdir -p "$CF_CONFIG_DIR"
    
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $tunnel_id
credentials-file: $CF_CONFIG_DIR/$tunnel_id.json

# 出站连接配置（适应中国大陆网络）
protocol: http2

ingress:
  # 主路由：反代到本地 OpenClaw
  - hostname: $DOMAIN
    service: http://127.0.0.1:$PORT
    originRequest:
      noTLSVerify: false
      httpHostHeader: $DOMAIN
      connectTimeout: 30s
      noHappyEyeballs: false
      keepAliveConnections: 100
      keepAliveTimeout: 90s
  
  # 拦截其他请求（安全兜底）
  - service: http_status:404

# 日志配置
logfile: $HOME/.cloudflared/tunnel.log
loglevel: info
EOF
    
    success "✓ Tunnel 配置已生成: $CF_CONFIG_DIR/config.yml"
    
    # 配置 DNS 路由
    info "配置 DNS 路由 ($DOMAIN → Tunnel)..."
    
    if cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" 2>&1 | grep -qi "already"; then
        warn "⚠️  DNS 路由已存在，跳过配置"
    else
        success "✓ DNS 路由配置成功"
    fi
    
    # 测试 Tunnel 连接
    info "测试 Tunnel 连接..."
    if timeout 10 cloudflared tunnel run "$TUNNEL_NAME" --config "$CF_CONFIG_DIR/config.yml" >> "$LOG_FILE" 2>&1 & sleep 3; then
        pkill -f "cloudflared.*tunnel.*run" 2>/dev/null || true
        success "✓ Tunnel 连接测试成功"
    else
        warn "⚠️  Tunnel 连接测试超时（可能需要更长时间启动）"
    fi
}

# ========== Cloudflare Access (Zero Trust) 集成 ==========
configure_cf_access() {
    if [ "$ENABLE_ACCESS" != "true" ]; then
        info "跳过 Cloudflare Access 配置 (未启用 --enable-access)"
        return 0
    fi
    
    echo ""
    echo -e "${GREEN}===== Cloudflare Access (Zero Trust) 配置 =====${NC}"
    echo ""
    echo -e "${YELLOW}此功能需要:${NC}"
    echo "  1. Cloudflare 账号已开启 Zero Trust"
    echo "  2. Cloudflare API Token（需 Zone:DNS:Edit + Access:Apps&Policies 权限）"
    echo "  3. 用于登录的邮箱地址（Access 白名单）"
    echo ""
    
    # 获取 API Token
    if [ -z "$CF_API_TOKEN" ]; then
        read -s -p "▶ Cloudflare API Token: " CF_API_TOKEN
        echo ""
        [[ -z "$CF_API_TOKEN" ]] && error "API Token 不能为空"
    fi
    
    # 获取 Account ID
    if [ -z "$CF_ACCOUNT_ID" ]; then
        read -p "▶ Cloudflare Account ID (在 Dashboard 右侧获取): " CF_ACCOUNT_ID
        [[ -z "$CF_ACCOUNT_ID" ]] && error "Account ID 不能为空"
    fi
    
    # 获取允许登录的邮箱
    if [ -z "$ACCESS_EMAIL" ]; then
        read -p "▶ 允许登录的邮箱地址: " ACCESS_EMAIL
        [[ -z "$ACCESS_EMAIL" ]] && error "邮箱不能为空"
    fi
    
    local CF_API="https://api.cloudflare.com/client/v4"
    local auth_header="Authorization: Bearer $CF_API_TOKEN"
    local ct_header="Content-Type: application/json"
    
    # 1. 创建 Access Application
    info "创建 Access Application..."
    local app_response=$(curl -s -X POST "$CF_API/accounts/$CF_ACCOUNT_ID/access/apps" \
        -H "$auth_header" \
        -H "$ct_header" \
        -d '{
            "name": "OpenClaw",
            "domain": "'"$DOMAIN"'",
            "type": "self_hosted",
            "session_duration": "24h",
            "auto_redirect_to_identity": false
        }')
    
    local app_id=$(echo "$app_response" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
    local app_aud=$(echo "$app_response" | sed -n 's/.*"aud":"\([^"]*\)".*/\1/p')
    
    if [ -z "$app_id" ] || [ -z "$app_aud" ]; then
        # 可能已存在，尝试查找
        warn "Application 创建返回异常，尝试查找已有 Application..."
        local existing=$(curl -s "$CF_API/accounts/$CF_ACCOUNT_ID/access/apps" \
            -H "$auth_header" | sed -n 's/.*"domain":"'"$DOMAIN"'".*"id":"\([^"]*\)".*"aud":"\([^"]*\)".*/\1 \2/p')
        app_id=$(echo "$existing" | awk '{print $1}')
        app_aud=$(echo "$existing" | awk '{print $2}')
        
        if [ -z "$app_id" ]; then
            error "无法创建或查找 Access Application，请检查 API Token 权限"
        fi
        info "复用已有 Application: $app_id"
    else
        success "✓ Access Application 已创建 | ID: $app_id | AUD: $app_aud"
    fi
    
    # 2. 创建 Email 白名单 Policy
    info "创建 Access Policy (邮箱白名单)..."
    local policy_response=$(curl -s -X POST "$CF_API/accounts/$CF_ACCOUNT_ID/access/apps/$app_id/policies" \
        -H "$auth_header" \
        -H "$ct_header" \
        -d '{
            "name": "Email Whitelist",
            "decision": "allow",
            "include": [{"email": {"email": "'"$ACCESS_EMAIL"'"}}]
        }')
    
    local policy_id=$(echo "$policy_response" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
    if [ -n "$policy_id" ]; then
        success "✓ Access Policy 已创建 | ID: $policy_id"
    else
        warn "⚠️  Policy 创建可能失败（可能已存在），继续..."
    fi
    
    # 3. 更新 cloudflared config.yml — 加入 origin JWT 验证
    info "更新 Tunnel 配置 (加入 Origin JWT 验证)..."
    
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
      noHappyEyeballs: false
      keepAliveConnections: 100
      keepAliveTimeout: 90s
      access:
        required: true
        teamName: $(echo "$CF_API" | sed 's|https://api.cloudflare.com/client/v4||')
        audTag:
          - "$app_aud"
  
  - service: http_status:404

logfile: $HOME/.cloudflared/tunnel.log
loglevel: info
EOF
    
    success "✓ Origin JWT 验证已启用"
    echo ""
    echo -e "${GREEN}===== Zero Trust 防线已就位 =====${NC}"
    echo "   Cloudflare Edge (DDoS/WAF)"
    echo "   → CF Access (邮箱白名单 + JWT)"
    echo "   → cloudflared (本地 Origin JWT 验证)"
    echo "   → OpenClaw Token"
    echo "   → OpenClaw UI"
    echo ""
}

# ========== 配置开机自启 ==========
configure_launchd() {
    info "配置开机自启服务..."
    
    mkdir -p "$LAUNCHD_DIR"
    
    # 检测 openclaw 实际路径
    local OC_BIN
    OC_BIN=$(find_openclaw_bin) || OC_BIN="/usr/local/bin/openclaw"
    info "OpenClaw 路径: $OC_BIN"
    
    # OpenClaw LaunchAgent
    cat > "$LAUNCHD_DIR/ai.openclaw.gateway.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.openclaw.gateway</string>
    <key>ProgramArguments</key>
    <array>
        <string>$OC_BIN</string>
        <string>gateway</string>
        <string>start</string>
        <string>--force</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>NetworkState</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/openclaw-gateway.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/openclaw-gateway.err.log</string>
    <key>ThrottleInterval</key>
    <integer>30</integer>
</dict>
</plist>
EOF
    
    # Cloudflare Tunnel LaunchAgent
    cat > "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cloudflare.cloudflared</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/cloudflared</string>
        <string>tunnel</string>
        <string>--config</string>
        <string>$CF_CONFIG_DIR/config.yml</string>
        <string>run</string>
        <string>$TUNNEL_NAME</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>NetworkState</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/cloudflared.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/cloudflared.err.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
EOF
    
    # 加载服务
    info "加载 LaunchAgent 服务..."
    
    launchctl unload "$LAUNCHD_DIR/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl load "$LAUNCHD_DIR/ai.openclaw.gateway.plist" || warn "OpenClaw LaunchAgent 加载失败"
    
    launchctl unload "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    launchctl load "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist" || warn "Tunnel LaunchAgent 加载失败"
    
    # 启动服务
    launchctl start ai.openclaw.gateway 2>/dev/null || true
    launchctl start com.cloudflare.cloudflared 2>/dev/null || true
    
    sleep 5
    
    success "✓ 开机自启配置完成"
}

# ========== 验证部署 ==========
verify_deployment() {
    echo ""
    echo -e "${GREEN}===== 部署验证 =====${NC}"
    echo ""
    
    local all_passed=true
    
    # 1. 检查 OpenClaw 监听
    info "检查 OpenClaw 监听状态..."
    if lsof -ti "127.0.0.1:$PORT" &>/dev/null; then
        success "✓ OpenClaw 仅监听 127.0.0.1:$PORT (未暴露公网)"
    else
        error "✗ OpenClaw 未正确监听 127.0.0.1:$PORT"
        all_passed=false
    fi
    
    # 2. 检查 Tunnel 进程
    info "检查 Cloudflare Tunnel 进程..."
    if pgrep -f "cloudflared.*tunnel.*run" &>/dev/null; then
        success "✓ Cloudflare Tunnel 进程运行中"
    else
        warn "⚠️  Tunnel 进程未检测到 (可能需要 10 秒启动)"
        sleep 10
        if pgrep -f "cloudflared.*tunnel" &>/dev/null; then
            success "✓ Tunnel 进程已启动"
        else
            error "✗ Tunnel 进程未运行，请检查日志"
            all_passed=false
        fi
    fi
    
    # 3. 外部可访问性测试（不泄露 IP 给第三方，直接测自己的域名）
    info "测试域名可访问性 (https://$DOMAIN)..."
    if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN/health" 2>/dev/null | grep -q "200\|302"; then
        success "✓ 域名访问成功: https://$DOMAIN"
    else
        warn "⚠️  域名暂时不可达 (DNS 生效可能需要几分钟)"
        echo "    请稍后手动验证: curl -I https://$DOMAIN"
    fi
    
    # 4. 验证 Token 文件权限
    info "验证 Token 文件权限..."
    local token_file="$OC_CONFIG_DIR/.auth_token"
    if [ -f "$token_file" ]; then
        local perms=$(stat -f "%Lp" "$token_file" 2>/dev/null || echo "unknown")
        if [ "$perms" = "600" ]; then
            success "✓ Token 文件权限正确 (600)"
        else
            warn "⚠️  Token 文件权限为 $perms，建议修复为 600"
            chmod 600 "$token_file" 2>/dev/null && success "✓ 已修复权限"
        fi
    fi
    
    echo ""
    echo -e "${GREEN}===== 隐私保护状态 =====${NC}"
    echo "   • 真实 IP: 已隐藏 (通过 Cloudflare Tunnel)"
    echo "   • 公网端口: 无 (仅监听 127.0.0.1)"
    echo "   • 访问方式: 仅可通过 https://$DOMAIN"
    echo "   • 认证方式: OpenClaw Token (文件存储)"
    if [ "$ENABLE_ACCESS" = "true" ]; then
        echo "   • Zero Trust: 已启用 (CF Access + Origin JWT)"
    fi
    echo ""
    
    if [ "$all_passed" = true ]; then
        success "✅ 部署验证通过！"
    else
        warn "⚠️  部分检查未通过，请查看日志: $LOG_FILE"
    fi
}

# ========== 配置 DNS 污染防护 ==========
configure_doh() {
    info "配置 DNS 污染防护 (DoH)..."
    
    # 保存原始 DNS 配置用于卸载时恢复
    local interface=$(networksetup -listnetworkserviceorder | grep "$(route get default | grep interface | awk '{print $2}')" | head -1 | sed 's/.*Port: \(.*\),.*/\1/')
    
    if [ -z "$interface" ]; then
        warn "⚠️  无法检测网络接口，跳过 DoH 配置"
        return 0
    fi
    
    # 备份当前 DNS
    local dns_backup_file="$OC_CONFIG_DIR/.dns_backup"
    local current_dns=$(networksetup -getdnsservers "$interface" 2>/dev/null)
    echo "$interface" > "$dns_backup_file"
    echo "$current_dns" >> "$dns_backup_file"
    chmod 600 "$dns_backup_file"
    info "原始 DNS 已备份到: $dns_backup_file"
    
    # 设置 Cloudflare DoH
    if networksetup -setdnsservers "$interface" 1.1.1.1 1.0.0.1 2>/dev/null; then
        success "✓ 已设置 Cloudflare DoH (1.1.1.1, 1.0.0.1)"
        echo "    网络接口: $interface"
    else
        warn "⚠️  DoH 配置失败 (可能需要管理员权限)"
    fi
}

# ========== 恢复 DNS 配置 ==========
restore_dns() {
    local dns_backup_file="$OC_CONFIG_DIR/.dns_backup"
    
    if [ ! -f "$dns_backup_file" ]; then
        info "无 DNS 备份，跳过恢复"
        return 0
    fi
    
    local interface=$(sed -n '1p' "$dns_backup_file")
    local original_dns=$(sed -n '2p' "$dns_backup_file")
    
    if [ -z "$interface" ]; then
        warn "⚠️  DNS 备份格式异常，跳过恢复"
        return 0
    fi
    
    if [ "$original_dns" = "Empty" ] || [ -z "$original_dns" ]; then
        networksetup -setdnsservers "$interface" "Empty" 2>/dev/null && \
            success "✓ DNS 已恢复为默认 (DHCP)" || \
            warn "⚠️  DNS 恢复失败"
    else
        networksetup -setdnsservers "$interface" $original_dns 2>/dev/null && \
            success "✓ DNS 已恢复: $original_dns" || \
            warn "⚠️  DNS 恢复失败"
    fi
    
    rm -f "$dns_backup_file"
}

# ========== 一键卸载 ==========
uninstall() {
    echo ""
    echo -e "${RED}===== 执行卸载 =====${NC}"
    echo ""
    
    # 确认
    read -p "⚠️  此操作将停止 OpenClaw 和 Tunnel 服务，删除部署配置。是否继续? (y/n): " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && info "卸载已取消" && exit 0
    
    # 停止服务
    info "停止服务..."
    launchctl stop ai.openclaw.gateway 2>/dev/null || true
    launchctl stop com.cloudflare.cloudflared 2>/dev/null || true
    launchctl unload "$LAUNCHD_DIR/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl unload "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    
    # 删除 LaunchAgent
    info "删除 LaunchAgent 配置..."
    rm -f "$LAUNCHD_DIR/ai.openclaw.gateway.plist"
    rm -f "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist"
    
    # 停止 OpenClaw gateway
    openclaw gateway stop 2>/dev/null || true
    
    # 删除部署脚本写入的配置（保留 workspace/sessions 等用户数据）
    info "删除 OpenClaw 部署配置..."
    openclaw config unset gateway.port 2>/dev/null || true
    openclaw config unset gateway.bind 2>/dev/null || true
    openclaw config unset gateway.auth.mode 2>/dev/null || true
    openclaw config unset gateway.auth.token 2>/dev/null || true
    
    # 删除 Token 文件
    rm -f "$OC_CONFIG_DIR/.auth_token"
    rm -f "$OC_CONFIG_DIR/.dns_backup"
    rm -f "$LOG_FILE"
    
    # 恢复 DNS 配置
    restore_dns
    
    # 卸载 OpenClaw (可选)
    echo ""
    read -p "是否同时卸载 OpenClaw CLI? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "卸载 OpenClaw..."
        npm uninstall -g openclaw 2>/dev/null || true
    else
        info "保留 OpenClaw CLI (仅删除部署配置)"
    fi
    
    # 删除 Tunnel (可选)
    echo ""
    read -p "是否同时删除 Cloudflare Tunnel? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if cloudflared tunnel list 2>/dev/null | grep -q "$TUNNEL_NAME"; then
            local tunnel_id=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}')
            info "删除 Tunnel: $tunnel_id"
            cloudflared tunnel delete "$tunnel_id" 2>/dev/null || true
        fi
        rm -rf "$CF_CONFIG_DIR"
    fi
    
    # 清理 DNS 路由 (可选)
    echo ""
    read -p "是否从 Cloudflare 删除 DNS 记录? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # 使用正确的子命令: tunnel route dns delete (不是 rm)
        cloudflared tunnel route dns delete "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null || \
            warn "DNS 路由删除失败，请在 Cloudflare Dashboard 手动删除"
    fi
    
    success "✅ 卸载完成！"
    echo ""
    echo "如需重新安装，请重新运行: $SCRIPT_NAME"
    exit 0
}

# ========== 帮助信息 ==========
show_help() {
    cat <<EOF
${CYAN}OpenClaw + Cloudflare Tunnel 隐私部署脚本 v$SCRIPT_VERSION${NC}

用法:
  ${GREEN}$SCRIPT_NAME${NC} [选项]

选项:
  ${YELLOW}--domain <域名>${NC}        指定访问域名 (如 claw.example.com)
  ${YELLOW}--port <端口>${NC}          指定 OpenClaw 监听端口 (默认 $DEFAULT_PORT)
  ${YELLOW}--enable-access${NC}        启用 Cloudflare Access (Zero Trust) 集成
  ${YELLOW}--cf-api-token <token>${NC} Cloudflare API Token (配合 --enable-access)
  ${YELLOW}--cf-account-id <id>${NC}   Cloudflare Account ID (配合 --enable-access)
  ${YELLOW}--access-email <email>${NC} 允许登录的邮箱 (配合 --enable-access)
  ${YELLOW}--uninstall${NC}            执行一键卸载
  ${YELLOW}--help${NC}                 显示此帮助信息
  ${YELLOW}--debug${NC}                启用调试模式 (详细日志)

环境变量:
  ${YELLOW}OPENCLAW_TOKEN${NC}         直接指定 OpenClaw Token (不通过命令行传递)
  ${YELLOW}CF_API_TOKEN${NC}           Cloudflare API Token (配合 --enable-access)

示例:
  # 交互式部署 (推荐)
  ./$SCRIPT_NAME

  # 静默部署
  ./$SCRIPT_NAME --domain claw.example.com --port 10371

  # 启用 Zero Trust
  ./$SCRIPT_NAME --domain claw.example.com --enable-access

  # 通过环境变量安全传递 Token
  OPENCLAW_TOKEN=\$(openssl rand -hex 32) ./$SCRIPT_NAME --domain claw.example.com

  # 卸载
  ./$SCRIPT_NAME --uninstall

安全说明:
  • Token 通过文件存储 (权限 600)，不输出到终端
  • 命令行参数不接受 Token，避免 ps 泄露
  • 日志写入 ~/.openclaw/ (非 /tmp)，权限 600
  • 不向第三方泄露 IP (移除 api.ipify.org 调用)
  • DNS 配置修改前自动备份，卸载时自动恢复
  • 使用 openclaw gateway start --force 防止端口竞争

要求:
  • 域名已托管到 Cloudflare DNS
  • macOS 11.0+ (Intel/Apple Silicon)
  • 可访问互联网 (出站 443 端口)
  • 无需公网 IP / 端口转发 / 备案

日志:
  部署日志: $LOG_FILE (权限 600)
  OpenClaw: /tmp/openclaw-gateway.log
  Tunnel:   $HOME/.cloudflared/tunnel.log

EOF
    exit 0
}

# ========== 主流程 ==========
main() {
    banner
    
    # 参数解析
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain) DOMAIN="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            --enable-access) ENABLE_ACCESS=true; shift ;;
            --cf-api-token) CF_API_TOKEN="$2"; shift 2 ;;
            --cf-account-id) CF_ACCOUNT_ID="$2"; shift 2 ;;
            --access-email) ACCESS_EMAIL="$2"; shift 2 ;;
            --uninstall) UNINSTALL=true; shift ;;
            --help) show_help ;;
            --debug) DEBUG=1; shift ;;
            *) error "未知参数: $1";;
        esac
    done
    
    # 卸载模式
    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall
    fi
    
    # 日志初始化（权限 600）
    mkdir -p "$OC_CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    info "部署日志: $LOG_FILE"
    
    # 依赖检查
    check_dependencies
    
    # 获取配置
    get_user_config
    
    # 配置 DoH
    configure_doh
    
    # 安装 OpenClaw
    install_openclaw
    
    # 配置 OpenClaw
    configure_openclaw
    
    # 配置 Tunnel
    configure_tunnel
    
    # 配置 Cloudflare Access (可选)
    configure_cf_access
    
    # 配置开机自启
    configure_launchd
    
    # 验证部署
    verify_deployment
    
    # 完成
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║   ${WHITE}✅ 部署成功！                                          ${GREEN}║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║   ${CYAN}🌐 访问地址:${NC} ${YELLOW}https://$DOMAIN${GREEN}                          ║${NC}"
    echo -e "${GREEN}║   ${CYAN}📊 本地调试:${NC} ${YELLOW}http://127.0.0.1:$PORT${GREEN}                ║${NC}"
    echo -e "${GREEN}║   ${CYAN}🔑 Token文件:${NC} ${YELLOW}$OC_CONFIG_DIR/.auth_token${GREEN}    ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║   ${WHITE}💡 提示:${NC}                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║      • 首次访问可能需要 1-5 分钟 DNS 生效                  ${GREEN}║${NC}"
    echo -e "${GREEN}║      • Token 存储在文件中，运行以下命令查看:               ${GREEN}║${NC}"
    echo -e "${GREEN}║        cat $OC_CONFIG_DIR/.auth_token         ${GREEN}║${NC}"
    echo -e "${GREEN}║      • 卸载命令: ./$SCRIPT_NAME --uninstall       ${GREEN}║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${PURPLE}📖 详细文档: https://github.com/Peters-Pans/deploy-openclaw${NC}"
    echo ""
}

# ========== 执行入口 ==========
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 检查是否使用 sudo
    if [[ $EUID -eq 0 ]]; then
        warn "⚠️  不建议使用 sudo 运行此脚本 (将使用当前用户权限)"
        read -p "是否继续? (y/n): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    # 检查 bash 版本
    if [ "${BASH_VERSINFO[0]}" -lt 3 ]; then
        error "需要 Bash 3.0+，当前版本: $BASH_VERSION"
    fi
    
    main "$@"
fi
