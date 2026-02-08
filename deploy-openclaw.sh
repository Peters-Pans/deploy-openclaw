#!/bin/bash
# OpenClaw + Cloudflare Tunnel 一体化部署脚本
# 适配中国大陆动态 IPv4 环境 | 隐私优先设计
# 作者: Panomia | 日期: 2026-02-08

set -e  # 遇错即停

# ========== 全局配置 ==========
SCRIPT_VERSION="1.2.0"
LOG_FILE="/tmp/openclaw-deploy-$(date +%Y%m%d-%H%M%S).log"
OPENCLAW_PORT=10371
TUNNEL_NAME="openclaw-tunnel"
CF_CONFIG_DIR="$HOME/.cloudflared"
OC_CONFIG_DIR="$HOME/.openclaw"
LAUNCHD_DIR="$HOME/Library/LaunchAgents"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}
warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}
error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}
success() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"
}

# ========== 依赖检查 ==========
check_dependencies() {
    log "检查系统依赖..."
    
    # Homebrew
    if ! command -v brew &>/dev/null; then
        error "未检测到 Homebrew。请先安装: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
    
    # Node.js/npm
    if ! command -v npm &>/dev/null; then
        error "未检测到 npm。请先安装 Node.js: brew install node"
    fi
    
    # cloudflared
    if ! command -v cloudflared &>/dev/null; then
        log "安装 cloudflared..."
        brew install cloudflare/cloudflare/cloudflared || error "cloudflared 安装失败"
    fi
    
    success "依赖检查通过"
}

# ========== 交互式配置 ==========
get_user_config() {
    echo ""
    echo -e "${GREEN}===== OpenClaw 隐私部署配置 =====${NC}"
    
    # 域名
    if [ -z "$DOMAIN" ]; then
        read -p "▶ 请输入您的域名 (如 claw.example.com): " DOMAIN
        [[ -z "$DOMAIN" ]] && error "域名不能为空"
    fi
    
    # Cloudflare 认证
    if [ ! -f "$HOME/.cloudflared/cert.pem" ]; then
        echo ""
        echo -e "${YELLOW}⚠️  首次使用需完成 Cloudflare 认证:${NC}"
        echo "   1. 浏览器将自动打开认证页面"
        echo "   2. 登录 Cloudflare 账号"
        echo "   3. 选择您的域名 (需已托管到 Cloudflare)"
        echo ""
        read -p "   按 Enter 继续..."
        cloudflared tunnel login || error "Cloudflare 认证失败"
    else
        success "已检测到 Cloudflare 认证凭据"
    fi
    
    # 生成 OpenClaw Token
    if [ -z "$OC_TOKEN" ]; then
        OC_TOKEN=$(openssl rand -hex 16)
        success "已生成 OpenClaw 访问令牌 (请妥善保存): $OC_TOKEN"
    fi
    
    echo ""
    success "配置完成: 域名=$DOMAIN | 端口=$OPENCLAW_PORT"
}

# ========== 安装 OpenClaw (安全模式) ==========
install_openclaw() {
    log "安装 OpenClaw CLI..."
    npm install -g openclaw@latest --silent || error "OpenClaw 安装失败"
    
    log "创建安全配置 (仅监听 127.0.0.1)..."
    mkdir -p "$OC_CONFIG_DIR"
    
    cat > "$OC_CONFIG_DIR/config.json" <<EOF
{
  "gateway": {
    "host": "127.0.0.1",
    "port": $OPENCLAW_PORT,
    "public": false,
    "authToken": "$OC_TOKEN"
  },
  "privacy": {
    "disableTelemetry": true,
    "hideFromLocalNetwork": true
  }
}
EOF
    
    log "启动 OpenClaw 服务..."
    openclaw stop 2>/dev/null || true  # 停止可能存在的旧实例
    openclaw start --no-browser || error "OpenClaw 启动失败"
    
    # 验证监听状态
    sleep 3
    if ! lsof -i "127.0.0.1:$OPENCLAW_PORT" -sTCP:LISTEN &>/dev/null; then
        error "OpenClaw 未正确监听 127.0.0.1:$OPENCLAW_PORT"
    fi
    
    success "OpenClaw 安全模式启动成功 (仅本地访问)"
}

# ========== 配置 Cloudflare Tunnel ==========
configure_tunnel() {
    log "创建 Cloudflare Tunnel: $TUNNEL_NAME..."
    
    # 检查隧道是否已存在
    if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
        TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
        warn "隧道 '$TUNNEL_NAME' 已存在，复用 ID: $TUNNEL_ID"
    else
        # 创建新隧道
        TUNNEL_OUTPUT=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1)
        TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | grep -oP 'Tunnel ID:\s*\K[0-9a-f-]+' || echo "")
        
        if [ -z "$TUNNEL_ID" ]; then
            error "隧道创建失败: $TUNNEL_OUTPUT"
        fi
        
        success "新隧道创建成功 | ID: $TUNNEL_ID"
    fi
    
    # 生成配置文件
    mkdir -p "$CF_CONFIG_DIR"
    CRED_FILE="$CF_CONFIG_DIR/$TUNNEL_ID.json"
    
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $TUNNEL_ID
credentials-file: $CRED_FILE

ingress:
  - hostname: $DOMAIN
    service: http://127.0.0.1:$OPENCLAW_PORT
    originRequest:
      noTLSVerify: true
      httpHostHeader: $DOMAIN
  
  # 拦截其他请求
  - service: http_status:404
EOF
    
    success "Tunnel 配置生成: $CF_CONFIG_DIR/config.yml"
    
    # 配置 DNS 路由
    log "配置 DNS 路由 ($DOMAIN → Tunnel)..."
    if ! cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN" 2>&1 | grep -q "already"; then
        success "DNS 路由配置成功"
    else
        warn "DNS 路由已存在，跳过配置"
    fi
}

# ========== 配置开机自启 ==========
setup_launchd() {
    log "配置开机自启服务..."
    mkdir -p "$LAUNCHD_DIR"
    
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
        <string>/opt/homebrew/bin/openclaw</string>
        <string>start</string>
        <string>--no-browser</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/openclaw-gateway.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/openclaw-gateway.err.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>NODE_ENV</key>
        <string>production</string>
    </dict>
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
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/cloudflared.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/cloudflared.err.log</string>
</dict>
</plist>
EOF
    
    # 加载服务
    launchctl unload "$LAUNCHD_DIR/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl load "$LAUNCHD_DIR/ai.openclaw.gateway.plist"
    
    launchctl unload "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    launchctl load "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist"
    
    # 启动服务
    launchctl start ai.openclaw.gateway
    launchctl start com.cloudflare.cloudflared
    
    sleep 5
    
    success "开机自启配置完成"
}

# ========== 验证部署 ==========
verify_deployment() {
    echo ""
    echo -e "${GREEN}===== 部署验证 =====${NC}"
    
    # 1. 检查 OpenClaw 监听
    if lsof -i "127.0.0.1:$OPENCLAW_PORT" -sTCP:LISTEN &>/dev/null; then
        success "✓ OpenClaw 仅监听 127.0.0.1:$OPENCLAW_PORT (未暴露公网)"
    else
        error "✗ OpenClaw 未正确监听"
    fi
    
    # 2. 检查 Tunnel 进程
    if pgrep -f "cloudflared.*tunnel.*run" &>/dev/null; then
        success "✓ Cloudflare Tunnel 进程运行中"
    else
        warn "⚠️  Tunnel 进程未检测到 (可能需要 10 秒启动)"
        sleep 10
    fi
    
    # 3. 外部可访问性测试 (需联网)
    if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN/health" | grep -q "200\|302"; then
        success "✓ 域名访问成功: https://$DOMAIN"
        
        # 4. 验证 IP 隐藏
        REAL_IP=$(curl -s https://api.ipify.org)
        CF_IP=$(curl -s -H "Host: $DOMAIN" https://1.1.1.1/cdn-cgi/trace | grep -oP 'ip=\K[0-9.]+')
        
        if [ "$REAL_IP" != "$CF_IP" ]; then
            success "✓ 真实 IP 已隐藏 (您的IP: $REAL_IP → Cloudflare边缘: $CF_IP)"
        else
            warn "⚠️  无法验证 IP 隐藏 (可能 Cloudflare 未生效)"
        fi
    else
        warn "⚠️  域名暂时不可达 (DNS 生效可能需要几分钟)"
        echo "   请稍后手动验证: curl -I https://$DOMAIN"
    fi
    
    echo ""
    echo -e "${GREEN}===== 隐私保护状态 =====${NC}"
    echo "   • 真实 IP: $REAL_IP"
    echo "   • 公网端口扫描: 10371 端口应显示 filtered/closed"
    echo "   • 访问方式: 仅可通过 https://$DOMAIN (经 Cloudflare 加密隧道)"
    echo ""
    success "部署完成！日志已保存至: $LOG_FILE"
}

# ========== 一键卸载 ==========
uninstall() {
    echo -e "${RED}===== 执行卸载 =====${NC}"
    
    # 停止服务
    launchctl stop ai.openclaw.gateway 2>/dev/null || true
    launchctl stop com.cloudflare.cloudflared 2>/dev/null || true
    launchctl unload "$LAUNCHD_DIR/ai.openclaw.gateway.plist" 2>/dev/null || true
    launchctl unload "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist" 2>/dev/null || true
    
    # 删除 LaunchAgent
    rm -f "$LAUNCHD_DIR/ai.openclaw.gateway.plist"
    rm -f "$LAUNCHD_DIR/com.cloudflare.cloudflared.plist"
    
    # 卸载 OpenClaw
    npm uninstall -g openclaw 2>/dev/null || true
    rm -rf "$OC_CONFIG_DIR"
    rm -rf "$HOME/.openclaw.workspace"
    
    # 删除 Tunnel (可选)
    read -p "是否同时删除 Cloudflare Tunnel? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
            TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
            cloudflared tunnel delete "$TUNNEL_ID" 2>/dev/null || true
            cloudflared tunnel route dns rm "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null || true
        fi
        rm -rf "$CF_CONFIG_DIR"
    fi
    
    # 清理 DNS 路由 (可选)
    read -p "是否从 Cloudflare 删除 DNS 记录 $DOMAIN? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cloudflared tunnel route dns rm "$TUNNEL_NAME" "$DOMAIN" 2>/dev/null || true
    fi
    
    success "卸载完成！残留文件已清理"
    exit 0
}

# ========== 帮助信息 ==========
show_help() {
    cat <<EOF
OpenClaw + Cloudflare Tunnel 一体化部署脚本 v$SCRIPT_VERSION

用法:
  ./deploy-openclaw.sh [选项]

选项:
  --domain <域名>      指定访问域名 (如 claw.example.com)
  --token <令牌>       指定 OpenClaw authToken (32位十六进制)
  --uninstall          执行一键卸载
  --help               显示此帮助信息

示例:
  ./deploy-openclaw.sh --domain claw.example.com
  ./deploy-openclaw.sh --uninstall

要求:
  • 域名已托管到 Cloudflare
  • Mac Mini 可访问互联网 (出站 443)
  • 无需公网 IP / 端口转发 / 备案

隐私保护:
  • OpenClaw 仅监听 127.0.0.1
  • 真实 IP 通过 Cloudflare Tunnel 完全隐藏
  • 动态 IPv4 变化无感
EOF
    exit 0
}

# ========== 主流程 ==========
main() {
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN} OpenClaw 隐私部署脚本 v$SCRIPT_VERSION${NC}"
    echo -e "${GREEN} 适配中国大陆动态 IPv4 环境${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    
    # 参数解析
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain) DOMAIN="$2"; shift 2 ;;
            --token) OC_TOKEN="$2"; shift 2 ;;
            --uninstall) uninstall ;;
            --help) show_help ;;
            *) error "未知参数: $1";;
        esac
    done
    
    # 日志初始化
    exec &> >(tee -a "$LOG_FILE")
    log "部署日志: $LOG_FILE"
    
    # 依赖检查
    check_dependencies
    
    # 获取配置
    get_user_config
    
    # 安装 OpenClaw
    install_openclaw
    
    # 配置 Tunnel
    configure_tunnel
    
    # 开机自启
    setup_launchd
    
    # 验证
    verify_deployment
    
    echo ""
    echo -e "${GREEN}✅ 部署成功！${NC}"
    echo ""
    echo "  访问地址: https://$DOMAIN"
    echo "  本地调试: http://127.0.0.1:$OPENCLAW_PORT (需携带 authToken)"
    echo "  卸载命令: ./deploy-openclaw.sh --uninstall"
    echo ""
}

# ========== 执行入口 ==========
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 检查 sudo (本脚本无需 root)
    if [[ $EUID -eq 0 ]]; then
        warn "不建议使用 sudo 运行此脚本 (将使用当前用户权限)"
        read -p "是否继续? (y/n): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    main "$@"
fi