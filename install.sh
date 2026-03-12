#!/bin/bash
set -e

# ─────────────────────────────────────────────
#  Vane 一键安装脚本
#  https://github.com/evecus/Vane
# ─────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

REPO="evecus/Vane"
SERVICE_NAME="vane"
BINARY_NAME="vane"

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 权限检查 ──────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  error "请使用 root 权限运行此脚本：sudo bash install.sh"
fi

# ── 欢迎横幅 ──────────────────────────────────
echo ""
echo -e "${BOLD}  🌀 Vane 一键安装脚本${NC}"
echo -e "  ${BLUE}https://github.com/${REPO}${NC}"
echo "  ─────────────────────────────────────"
echo ""

# ── 检测系统架构 ──────────────────────────────
detect_arch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *)              error "不支持的架构：$arch（仅支持 x86_64 / aarch64）" ;;
  esac
}

# ── 检测依赖 ──────────────────────────────────
check_deps() {
  local missing=()
  for cmd in curl tar systemctl; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    error "缺少依赖：${missing[*]}，请先安装后重试"
  fi
}

# ── 获取最新版本号 ─────────────────────────────
get_latest_version() {
  local version
  version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ -z "$version" ]; then
    error "无法获取最新版本，请检查网络连接或稍后重试"
  fi
  echo "$version"
}

# ── 询问安装目录 ──────────────────────────────
ask_install_dir() {
  local default_dir="/opt"
  echo -ne "${BOLD}请输入安装目录${NC} [默认: ${default_dir}]: "
  read -r user_dir
  user_dir="${user_dir:-$default_dir}"

  # 去掉末尾斜杠
  user_dir="${user_dir%/}"

  if [ ! -d "$user_dir" ]; then
    error "目录 $user_dir 不存在，请先创建或输入已存在的目录"
  fi

  echo "$user_dir"
}

# ── 主流程 ────────────────────────────────────
check_deps

ARCH=$(detect_arch)
info "检测到系统架构：${BOLD}$ARCH${NC}"

info "正在获取最新版本信息..."
VERSION=$(get_latest_version)
info "最新版本：${BOLD}$VERSION${NC}"

INSTALL_BASE=$(ask_install_dir)
INSTALL_DIR="${INSTALL_BASE}/vane"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/vane-linux-${ARCH}"

echo ""
info "安装目录：${BOLD}${INSTALL_DIR}${NC}"
info "下载地址：${BOLD}${DOWNLOAD_URL}${NC}"
echo ""

# 如果已安装，提示升级
if [ -f "$BINARY_PATH" ]; then
  current_ver=$("$BINARY_PATH" --version 2>/dev/null || echo "未知")
  warn "检测到已安装的 Vane（${current_ver}），将升级到 ${VERSION}"
  # 停止旧服务（如果在运行）
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "停止旧服务..."
    systemctl stop "$SERVICE_NAME"
  fi
fi

# ── 创建安装目录 ──────────────────────────────
info "创建安装目录 ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

# ── 下载二进制 ────────────────────────────────
info "正在下载 vane-linux-${ARCH}..."
TMP_FILE=$(mktemp)
if ! curl -fL --progress-bar "$DOWNLOAD_URL" -o "$TMP_FILE"; then
  rm -f "$TMP_FILE"
  error "下载失败，请检查网络连接或访问 https://github.com/${REPO}/releases 手动下载"
fi

# ── 安装二进制 ────────────────────────────────
mv "$TMP_FILE" "$BINARY_PATH"
chmod +x "$BINARY_PATH"
success "二进制文件已安装到 ${BINARY_PATH}"

# ── 验证可执行 ────────────────────────────────
if ! "$BINARY_PATH" --help &>/dev/null && ! "$BINARY_PATH" -help &>/dev/null; then
  # 有些程序没有 --help，只要文件存在且有执行权限就认为 OK
  if [ ! -x "$BINARY_PATH" ]; then
    error "文件无法执行，安装可能失败"
  fi
fi

# ── 创建 systemd 服务 ─────────────────────────
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "创建 systemd 服务文件 ${SERVICE_FILE}..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Vane - 轻量级网络管理面板
Documentation=https://github.com/${REPO}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BINARY_PATH}
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# 安全加固
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

success "systemd 服务文件已创建"

# ── 启用并启动服务 ────────────────────────────
info "重载 systemd 配置..."
systemctl daemon-reload

info "设置开机自启..."
systemctl enable "$SERVICE_NAME"

info "启动 Vane 服务..."
systemctl start "$SERVICE_NAME"

# 等待片刻确认启动
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
  success "Vane 服务已成功启动"
else
  warn "服务启动异常，请查看日志：journalctl -u ${SERVICE_NAME} -n 50"
fi

# ── 完成提示 ──────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✅ 安装完成！${NC}"
echo "  ─────────────────────────────────────"
echo -e "  版本        ${BOLD}${VERSION}${NC}"
echo -e "  安装目录    ${BOLD}${INSTALL_DIR}${NC}"
echo -e "  服务名称    ${BOLD}${SERVICE_NAME}${NC}"
echo ""
echo -e "  ${BOLD}首次运行会在日志中打印临时密码，请执行：${NC}"
echo -e "  ${YELLOW}journalctl -u ${SERVICE_NAME} -n 30${NC}"
echo ""
echo -e "  ${BOLD}常用命令：${NC}"
echo -e "  启动服务    ${YELLOW}systemctl start ${SERVICE_NAME}${NC}"
echo -e "  停止服务    ${YELLOW}systemctl stop ${SERVICE_NAME}${NC}"
echo -e "  重启服务    ${YELLOW}systemctl restart ${SERVICE_NAME}${NC}"
echo -e "  查看日志    ${YELLOW}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "  卸载服务    ${YELLOW}systemctl disable --now ${SERVICE_NAME} && rm -rf ${INSTALL_DIR} ${SERVICE_FILE}${NC}"
echo ""
