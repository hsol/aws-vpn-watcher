#!/bin/bash
# ─────────────────────────────────────────────────────────────
# AWS VPN Watcher 설치 스크립트
# 실행: bash install.sh
# ─────────────────────────────────────────────────────────────

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

p() { printf "%b\n" "$@"; }  # echo -e 대신 printf 사용 (macOS 호환)

p "${BOLD}🔧 AWS VPN Watcher 설치 시작${NC}"
p "────────────────────────────────────"

INSTALL_DIR="$HOME/.local/bin"
LOG_DIR="$HOME/.local/log"
PLIST_DIR="$HOME/Library/LaunchAgents"
SCRIPT_NAME="aws-vpn-watcher.py"          # 실제 파이썬 파일명
PLIST_NAME="com.user.aws-vpn-watcher.plist"
MANAGE_NAME="manage.sh"
CMD_NAME="avwatcher"                       # 터미널 커맨드 이름

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_DEST="$INSTALL_DIR/$SCRIPT_NAME"
MANAGE_DEST="$INSTALL_DIR/$CMD_NAME"
PLIST_DEST="$PLIST_DIR/$PLIST_NAME"

SHELL_RC="$HOME/.zshrc"
MARKER_BEGIN="# >>> aws-vpn-watcher >>>"
MARKER_END="# <<< aws-vpn-watcher <<<"

# ── 1. 디렉토리 ────────────────────────────────
p "📁 디렉토리 생성 중..."
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$PLIST_DIR"

# ── 2. Python3 확인 ────────────────────────────
p "🐍 Python3 확인 중..."
PYTHON3=$(which python3 2>/dev/null || echo "")
if [ -z "$PYTHON3" ]; then
    p "${RED}❌ python3를 찾을 수 없습니다. Homebrew로 설치하세요:${NC}"
    p "   brew install python3"
    exit 1
fi
p "   ${GREEN}✓${NC} $PYTHON3"

# ── 3. terminal-notifier 확인 / 설치 ──────────
p "🔔 terminal-notifier 확인 중..."
if ! command -v terminal-notifier &>/dev/null; then
    if command -v brew &>/dev/null; then
        p "   설치 중 (brew install terminal-notifier)..."
        brew install terminal-notifier
        p "   ${GREEN}✓${NC} terminal-notifier 설치 완료"
    else
        p "   ${YELLOW}⚠️  Homebrew가 없어 terminal-notifier를 자동 설치할 수 없습니다.${NC}"
        p "   알림 아이콘 없이 동작합니다. (직접 설치: brew install terminal-notifier)"
    fi
else
    p "   ${GREEN}✓${NC} $(which terminal-notifier)"
fi

# ── 4. 파일 복사 ───────────────────────────────
p "📋 파일 복사 중..."

cp "$SRC_DIR/$SCRIPT_NAME" "$SCRIPT_DEST"
chmod +x "$SCRIPT_DEST"
p "   ${GREEN}✓${NC} $SCRIPT_DEST"

sed \
    -e "s|__REPO_DIR__|$SRC_DIR|g" \
    "$SRC_DIR/$MANAGE_NAME" > "$MANAGE_DEST"
chmod +x "$MANAGE_DEST"
p "   ${GREEN}✓${NC} $MANAGE_DEST  (→ $CMD_NAME 커맨드)"

# ── 5. plist 생성 (경로 치환) ──────────────────
p "⚙️  LaunchAgent plist 생성 중..."
STDOUT_LOG="$LOG_DIR/aws-vpn-watcher.stdout.log"
STDERR_LOG="$LOG_DIR/aws-vpn-watcher.stderr.log"

sed \
    -e "s|SCRIPT_PATH_PLACEHOLDER|$SCRIPT_DEST|g" \
    -e "s|STDOUT_LOG_PLACEHOLDER|$STDOUT_LOG|g" \
    -e "s|STDERR_LOG_PLACEHOLDER|$STDERR_LOG|g" \
    -e "s|HOME_PLACEHOLDER|$HOME|g" \
    "$SRC_DIR/$PLIST_NAME" > "$PLIST_DEST"
p "   ${GREEN}✓${NC} $PLIST_DEST"

# ── 6. LaunchAgent 등록 ────────────────────────
if launchctl list 2>/dev/null | grep -q "com.user.aws-vpn-watcher"; then
    p "🔄 기존 서비스 언로드 중..."
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
fi
p "🚀 LaunchAgent 등록 중..."
launchctl load "$PLIST_DEST"
p "   ${GREEN}✓${NC} 등록 완료 (부팅 시 자동 시작)"

# ── 7. PATH 등록 (~/.zshrc) ────────────────────
p "🔗 PATH 등록 중 ($SHELL_RC)..."

if grep -q "$MARKER_BEGIN" "$SHELL_RC" 2>/dev/null; then
    p "   ${YELLOW}이미 등록됨 — 스킵${NC}"
else
    cat >> "$SHELL_RC" <<EOF

$MARKER_BEGIN
export PATH="\$HOME/.local/bin:\$PATH"
$MARKER_END
EOF
    p "   ${GREEN}✓${NC} PATH 블록 추가됨"
fi

# ── 완료 ───────────────────────────────────────
p ""
p "────────────────────────────────────"
p "${GREEN}${BOLD}✅ 설치 완료!${NC}"
p ""
p "새 터미널 탭을 열거나 아래를 실행하면 즉시 사용 가능합니다:"
p "   ${BOLD}source $SHELL_RC${NC}"
p ""
p "이후 어디서든 아래 커맨드를 사용하세요:"
p "   ${BOLD}avwatcher status${NC}     — 상태 확인"
p "   ${BOLD}avwatcher stop${NC}       — 서비스 중지"
p "   ${BOLD}avwatcher start${NC}      — 서비스 시작"
p "   ${BOLD}avwatcher restart${NC}    — 서비스 재시작"
p "   ${BOLD}avwatcher logs${NC}       — 실시간 로그"
p "   ${BOLD}avwatcher uninstall${NC}  — 완전 제거"
p "   ${BOLD}avwatcher update${NC}     — 최신 release 확인 후 필요 시 업데이트"
