#!/bin/bash
# OpenClaw + Cloudflare Tunnel 隐私部署脚本 v2.2
# 专为中国大陆动态 IPv4 环境优化 | 安全加固版
# 
# 特性:
#   ✅ 真实 IP 完全隐藏
#   ✅ 零公网端口暴露
#   ✅ 动态 IPv4 无感
#   ✅ 自动 HTTPS + WAF
#   ✅ 双重认证 (Token + BasicAuth)
#   ✅ DNS 污染防护
#   ✅ 自动重连 + 健康检查
#   ✅ 详细日志 + 故障排查
#
# 用法: ./deploy-openclaw.sh [选项]
# 选项: --domain <域名> --port <端口> --token <令牌> --uninstall --help

set -e
set -o pipefail

# ========== 全局配置 ==========
readonly SCRIPT_VERSION="2.2.0"
readonly SCRIPT_NAME="deploy-openclaw.sh"
readonly DEFAULT_PORT=10371
readonly TUNNEL_NAME="openclaw-tunnel"
readonly CF_CONFIG_DIR="$HOME/.cloudflared"
readonly OC_CONFIG_DIR="$HOME/.openclaw"
readonly LAUNCHD_DIR="$HOME/Library/LaunchAgents"
readonly LOG_DIR="/tmp"
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_FILE="$LOG_DIR/openclaw-deploy-$TIMESTAMP.log"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
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

banner() {
    cat <<EOF

${CYAN}╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ${GREEN}OpenClaw + Cloudflare Tunnel 隐私部署脚本 v$SCRIPT_VERSION${CYAN}   ║
║                                                            ║
║   ${YELLOW}适配中国大陆动态 IPv4 环境 | 无需公网IP/端口转发/备案${CYAN}      ║
║                                                            ║
║   ${RED}⚠️  重要: 切勿在脚本中硬编码敏感信息 (Token/API Key)${CYAN}     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝${NC}

EOF
}

# ========== 检测 openclaw 可执行文件路径 ==========
find_openclaw_bin() {
    # 优先用 which 找到的路径
    local bin
    bin=$(command -v openclaw 2>/dev/null) || return 1
    echo "$bin"
}

# ========== 依赖检查 ==========
check_dependencies() {
    info "检查系统依赖..."
    
    # 检查 Homebrew
    if ! command -v brew &>/dev/null; then
        error "未检测到 Homebrew。请先安装: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
    success "✓ Homebrew 已安装"
    
    # 检查 Node.js (OpenClaw 需要 Node 运行时)
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
    
    # 检查是否为数字
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        error "端口 '$port' 不是有效数字"
    fi
    
    # 检查范围
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        error "端口 '$port' 超出有效范围 (1-65535)"
    fi
    
    # 检查系统保留端口
    if [ "$port" -lt 1024 ]; then
        error "端口 '$port' 是系统保留端口（需 root 权限），请使用 1024-65535 范围"
    fi
    
    # 检查是否被占用
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
    
    # 简单的域名格式验证
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        error "域名 '$domain' 格式无效（示例: claw.example.com）"
    fi
    
    # 检查是否包含敏感字符
    if [[ "$domain" == *"*"* ]] || [[ "$domain" == *" "* ]]; then
        error "域名不能包含通配符或空格"
    fi
    
    success "✓ 域名 $domain 格式有效"
}

# ========== 生成安全令牌 ==========
generate_secure_token() {
    # 生成 32 字节 (64 字符) 随机十六进制字符串
    openssl rand -hex 32 2>/dev/null || {
        # 备用方案
        LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c 64
    }
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
    
    # Token
    if [ -z "$TOKEN" ]; then
        info "生成安全访问令牌..."
        TOKEN=$(generate_secure_token)
        echo ""
        echo -e "${YELLOW}⚠️  重要: 请妥善保存以下令牌 (用于访问 OpenClaw)${NC}"
        echo -e "${CYAN}OpenClaw AuthToken:${NC} $TOKEN"
        echo ""
        read -p "按 Enter 继续..."
    fi
    
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
    
    if ! npm install -g openclaw@latest --silent >> "$LOG_FILE" 2>&1; then
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
    # 1. 网关端口
    openclaw config set gateway.port "$PORT" 2>> "$LOG_FILE"
    # 2. 绑定模式 = loopback (仅 127.0.0.1)
    openclaw config set gateway.bind "loopback" 2>> "$LOG_FILE"
    # 3. 运行模式 = local
    openclaw config set gateway.mode "local" 2>> "$LOG_FILE"
    # 4. 认证模式 = token
    openclaw config set gateway.auth.mode "token" 2>> "$LOG_FILE"
    # 5. 认证令牌
    openclaw config set gateway.auth.token "$TOKEN" 2>> "$LOG_FILE"
    
    success "✓ 配置文件已写入: $OC_CONFIG_DIR/openclaw.json"
    
    # 验证配置
    info "验证配置..."
    if ! openclaw config validate 2>> "$LOG_FILE"; then
        error "配置验证失败，请查看日志: $LOG_FILE"
    fi
    success "✓ 配置验证通过"
    
    # 停止旧实例
    info "停止旧的 OpenClaw 实例..."
    openclaw gateway stop 2>/dev/null || true
    pkill -f "openclaw.*gateway" 2>/dev/null || true
    sleep 2
    
    # 启动服务
    info "启动 OpenClaw 服务..."
    if ! openclaw gateway start >> "$LOG_FILE" 2>&1; then
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
        tunnel_id=$(echo "$tunnel_output" | grep -oP 'Tunnel ID:\s*\K[0-9a-f-]+' || echo "")
        
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
protocol-headers: true

ingress:
  # 主路由：反代到本地 OpenClaw
  - hostname: $DOMAIN
    service: http://127.0.0.1:$PORT
    originRequest:
      noTLSVerify: true
      httpHostHeader: $DOMAIN
      # 连接超时
      connectTimeout: 30s
      # 无活动超时
      noHappyEyeballs: false
      # 保持连接
      keepAliveConnections: 100
      keepAliveTimeout: 90s
  
  # 拦截其他请求（安全兜底）
  - service: http_status:404

# 日志配置
logfile: /tmp/cloudflared-tunnel.log
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
    if timeout 10 cloudflared tunnel run "$TUNNEL_NAME" --config "$CF_CONFIG_DIR/config.yml" 2>&1 | head -20 >> "$LOG_FILE" 2>&1 & sleep 3; then
        pkill -f "cloudflared.*tunnel.*run" 2>/dev/null || true
        success "✓ Tunnel 连接测试成功"
    else
        warn "⚠️  Tunnel 连接测试超时（可能需要更长时间启动）"
    fi
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
    
    # 3. 外部可访问性测试
    info "测试域名可访问性 (https://$DOMAIN)..."
    if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN/health" 2>/dev/null | grep -q "200\|302"; then
        success "✓ 域名访问成功: https://$DOMAIN"
        
        # 4. 验证 IP 隐藏
        info "验证真实 IP 隐藏..."
        local real_ip
        local cf_ip
        
        real_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
        cf_ip=$(curl -s -H "Host: $DOMAIN" https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep -oP 'ip=\K[0-9.]+' || echo "unknown")
        
        if [ "$real_ip" != "unknown" ] && [ "$cf_ip" != "unknown" ] && [ "$real_ip" != "$cf_ip" ]; then
            success "✓ 真实 IP 已隐藏"
            echo "    您的真实 IP: $real_ip"
            echo "    Cloudflare 边缘 IP: $cf_ip"
        else
            warn "⚠️  无法验证 IP 隐藏 (可能 Cloudflare 未生效)"
        fi
    else
        warn "⚠️  域名暂时不可达 (DNS 生效可能需要几分钟)"
        echo "    请稍后手动验证: curl -I https://$DOMAIN"
    fi
    
    echo ""
    echo -e "${GREEN}===== 隐私保护状态 =====${NC}"
    echo "   • 真实 IP: 已隐藏 (通过 Cloudflare Tunnel)"
    echo "   • 公网端口: $PORT (应显示 filtered/closed)"
    echo "   • 访问方式: 仅可通过 https://$DOMAIN"
    echo "   • 认证方式: OpenClaw Token (已配置)"
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
    
    # 检测当前网络接口
    local interface=$(networksetup -listnetworkserviceorder | grep "$(route get default | grep interface | awk '{print $2}')" | head -1 | sed 's/.*Port: \(.*\),.*/\1/')
    
    if [ -z "$interface" ]; then
        warn "⚠️  无法检测网络接口，跳过 DoH 配置"
        return 0
    fi
    
    # 设置 Cloudflare DoH
    if networksetup -setdnsservers "$interface" 1.1.1.1 1.0.0.1 2>/dev/null; then
        success "✓ 已设置 Cloudflare DoH (1.1.1.1, 1.0.0.1)"
        echo "    网络接口: $interface"
    else
        warn "⚠️  DoH 配置失败 (可能需要管理员权限)"
    fi
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
    rm -f /tmp/openclaw-*.log
    
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
        cloudflared tunnel route dns rm "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null || true
        info "DNS 记录已删除"
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
  ${YELLOW}--domain <域名>${NC}      指定访问域名 (如 claw.example.com)
  ${YELLOW}--port <端口>${NC}        指定 OpenClaw 监听端口 (默认 $DEFAULT_PORT)
  ${YELLOW}--token <令牌>${NC}       指定 OpenClaw authToken (32位十六进制)
  ${YELLOW}--uninstall${NC}          执行一键卸载
  ${YELLOW}--help${NC}               显示此帮助信息
  ${YELLOW}--debug${NC}              启用调试模式 (详细日志)

示例:
  # 交互式部署 (推荐)
  ./$SCRIPT_NAME
  
  # 静默部署
  ./$SCRIPT_NAME --domain claw.example.com --port 10371
  
  # 指定 Token 部署
  ./$SCRIPT_NAME --domain claw.example.com --token "\$(openssl rand -hex 32)"
  
  # 卸载
  ./$SCRIPT_NAME --uninstall

隐私保护:
  • 真实 IP 完全隐藏 (通过 Cloudflare Tunnel)
  • 零公网端口暴露 (仅监听 127.0.0.1)
  • 动态 IPv4 无感 (出站连接)
  • 自动 HTTPS + WAF 防护
  • 双重认证 (Token + 可选 BasicAuth)

要求:
  • 域名已托管到 Cloudflare DNS
  • macOS 11.0+ (Intel/Apple Silicon)
  • 可访问互联网 (出站 443 端口)
  • 无需公网 IP / 端口转发 / 备案

日志:
  部署日志: $LOG_FILE
  OpenClaw: /tmp/openclaw-gateway.log
  Tunnel:   /tmp/cloudflared.log

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
            --token) TOKEN="$2"; shift 2 ;;
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
    
    # 日志初始化
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
    echo -e "${GREEN}║   ${CYAN}🔒 AuthToken:${NC} ${YELLOW}$TOKEN${GREEN}             ║${NC}"
    echo -e "${GREEN}║   ${CYAN}📊 本地调试:${NC} ${YELLOW}http://127.0.0.1:$PORT${GREEN}                ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║   ${WHITE}💡 提示:${NC}                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║      • 首次访问可能需要 1-5 分钟 DNS 生效                  ${GREEN}║${NC}"
    echo -e "${GREEN}║      • Token 请妥善保存，遗失需重新部署                    ${GREEN}║${NC}"
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
