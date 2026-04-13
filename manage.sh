#!/bin/bash
# ─────────────────────────────────────────────────────────────
# avwatcher — AWS VPN Watcher 관리 도구
#
#   avwatcher start      서비스 시작
#   avwatcher stop       서비스 중지
#   avwatcher restart    서비스 재시작
#   avwatcher status     실행 상태 확인
#   avwatcher logs       실시간 로그 보기
#   avwatcher uninstall  완전 제거
#   avwatcher update     최신 release 확인 후 필요 시 업데이트
# ─────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

p() { printf "%b\n" "$@"; }  # macOS 호환 출력

PLIST_NAME="com.user.aws-vpn-watcher"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
SCRIPT_PATH="$HOME/.local/bin/aws-vpn-watcher.py"
CMD_PATH="$HOME/.local/bin/avwatcher"
LOG_FILE="$HOME/.local/log/aws-vpn-watcher.log"
SHELL_RC="$HOME/.zshrc"
MARKER_BEGIN="# >>> aws-vpn-watcher >>>"
MARKER_END="# <<< aws-vpn-watcher <<<"
REPO_DIR="__REPO_DIR__"

if [ ! -d "$REPO_DIR/.git" ]; then
    REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
REPO_INSTALL_SCRIPT="$REPO_DIR/install.sh"

get_repo_slug() {
    local remote_url slug
    remote_url="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || echo "")"
    if [ -z "$remote_url" ]; then
        echo ""
        return
    fi

    # https://github.com/owner/repo(.git)
    if [[ "$remote_url" =~ github\.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
        slug="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
        echo "$slug"
        return
    fi

    echo ""
}

get_latest_release_tag() {
    local repo_slug latest_tag
    repo_slug="$1"
    latest_tag=""

    # gh가 있으면 우선 사용
    if command -v gh >/dev/null 2>&1; then
        latest_tag="$(gh release view --repo "$repo_slug" --json tagName -q '.tagName' 2>/dev/null || echo "")"
    fi

    # gh가 없거나 실패하면 GitHub API fallback
    if [ -z "$latest_tag" ]; then
        latest_tag="$(curl -fsSL "https://api.github.com/repos/$repo_slug/releases/latest" 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))' 2>/dev/null || echo "")"
    fi

    echo "$latest_tag"
}

check_installed() {
    if [ ! -f "$PLIST_PATH" ]; then
        p "${RED}❌ 서비스가 설치되지 않았습니다. 먼저 install.sh를 실행하세요.${NC}"
        exit 1
    fi
}

cmd_start() {
    check_installed
    if launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
        p "${YELLOW}⚠️  이미 실행 중입니다.${NC}"
        cmd_status
        return
    fi
    launchctl load "$PLIST_PATH"
    p "${GREEN}✅ AWS VPN Watcher 시작됨${NC}"
}

cmd_stop() {
    check_installed
    if ! launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
        p "${YELLOW}⚠️  현재 실행 중이지 않습니다.${NC}"
        return
    fi
    launchctl unload "$PLIST_PATH"
    p "${GREEN}⏹️  AWS VPN Watcher 중지됨${NC}"
    p "   다시 시작: ${BOLD}avwatcher start${NC}"
}

cmd_restart() {
    check_installed
    p "🔄 재시작 중..."
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    sleep 1
    launchctl load "$PLIST_PATH"
    p "${GREEN}✅ AWS VPN Watcher 재시작됨${NC}"
}

cmd_status() {
    check_installed
    p "${BOLD}── AWS VPN Watcher 상태 ──${NC}"

    if launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
        INFO=$(launchctl list "$PLIST_NAME" 2>/dev/null || echo "")
        PID=$(echo "$INFO" | grep '"PID"' | grep -o '[0-9]*' || echo "")
        if [ -n "$PID" ]; then
            p "   상태: ${GREEN}● 실행 중${NC} (PID: $PID)"
        else
            p "   상태: ${GREEN}● 등록됨${NC} (대기 중)"
        fi
    else
        p "   상태: ${RED}● 중지됨${NC}"
    fi

    p "   plist: $PLIST_PATH"
    p "   로그:  $LOG_FILE"

    if [ -f "$LOG_FILE" ]; then
        printf "\n"
        p "${BOLD}── 최근 로그 (5줄) ──${NC}"
        tail -5 "$LOG_FILE" | sed 's/^/   /'
    fi
}

cmd_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        p "${YELLOW}⚠️  로그 파일이 아직 없습니다. 서비스가 시작된 후 생성됩니다.${NC}"
        exit 1
    fi
    p "${BOLD}실시간 로그 (Ctrl+C로 종료)${NC}"
    printf "────────────────────────────────────\n"
    tail -f "$LOG_FILE"
}

cmd_uninstall() {
    p "${BOLD}🗑️  AWS VPN Watcher 제거 시작${NC}"
    printf "────────────────────────────────────\n"

    if launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
        p "⏹️  서비스 중지 중..."
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        p "   ${GREEN}✓${NC} 서비스 중지됨"
    fi

    if [ -f "$PLIST_PATH" ]; then
        rm "$PLIST_PATH"
        p "   ${GREEN}✓${NC} plist 삭제: $PLIST_PATH"
    fi

    if [ -f "$SCRIPT_PATH" ]; then
        rm "$SCRIPT_PATH"
        p "   ${GREEN}✓${NC} 스크립트 삭제: $SCRIPT_PATH"
    fi

    if [ -f "$CMD_PATH" ]; then
        rm "$CMD_PATH"
        p "   ${GREEN}✓${NC} 커맨드 삭제: $CMD_PATH"
    fi

    if grep -q "$MARKER_BEGIN" "$SHELL_RC" 2>/dev/null; then
        sed -i '' "/^$/{ N; /\n$MARKER_BEGIN/d; }" "$SHELL_RC" 2>/dev/null || true
        sed -i '' "/$MARKER_BEGIN/,/$MARKER_END/d" "$SHELL_RC"
        p "   ${GREEN}✓${NC} $SHELL_RC 에서 PATH 블록 제거됨"
    fi

    printf "\n"
    p "${GREEN}${BOLD}✅ 제거 완료!${NC}"
    p "   로그 파일은 남아있습니다: $HOME/.local/log/aws-vpn-watcher*.log"
    p "   삭제하려면: ${BOLD}rm $HOME/.local/log/aws-vpn-watcher*.log${NC}"
    printf "\n"
    p "현재 터미널 세션에서 PATH를 업데이트하려면:"
    p "   ${BOLD}source $SHELL_RC${NC}"
}

cmd_update() {
    p "${BOLD}🔄 AWS VPN Watcher 업데이트 시작${NC}"
    printf "────────────────────────────────────\n"

    if [ ! -d "$REPO_DIR/.git" ]; then
        p "${RED}❌ Git 저장소를 찾을 수 없습니다: $REPO_DIR${NC}"
        p "   저장소 루트에서 수동 업데이트 후 install.sh를 실행하세요."
        exit 1
    fi

    if [ ! -f "$REPO_INSTALL_SCRIPT" ]; then
        p "${RED}❌ 설치 스크립트를 찾을 수 없습니다: $REPO_INSTALL_SCRIPT${NC}"
        p "   저장소 상태를 확인한 뒤 수동으로 bash install.sh를 실행하세요."
        exit 1
    fi

    p "1) 최신 release 확인..."
    REPO_SLUG="$(get_repo_slug)"
    if [ -z "$REPO_SLUG" ]; then
        p "${YELLOW}⚠️  origin 원격에서 GitHub 저장소 정보를 파싱하지 못했습니다.${NC}"
        p "   release 확인 없이 기존 방식(git pull)으로 진행합니다."
    else
        LATEST_RELEASE_TAG="$(get_latest_release_tag "$REPO_SLUG")"
        CURRENT_RELEASE_TAG="$(git -C "$REPO_DIR" describe --tags --abbrev=0 2>/dev/null || echo "")"

        if [ -n "$LATEST_RELEASE_TAG" ]; then
            p "   최신 release: $LATEST_RELEASE_TAG"
            if [ -n "$CURRENT_RELEASE_TAG" ]; then
                p "   현재 버전:   $CURRENT_RELEASE_TAG"
            else
                p "   현재 버전:   (태그 없음)"
            fi

            if [ "$LATEST_RELEASE_TAG" = "$CURRENT_RELEASE_TAG" ]; then
                p "${GREEN}✅ 이미 최신 release 입니다. 업데이트를 건너뜁니다.${NC}"
                return 0
            fi
        else
            p "${YELLOW}⚠️  최신 release 정보를 가져오지 못했습니다.${NC}"
            p "   release 확인 없이 기존 방식(git pull)으로 진행합니다."
        fi
    fi

    p "2) 최신 코드 가져오기 (git pull)..."
    if ! git -C "$REPO_DIR" pull; then
        p "${RED}❌ git pull 실패 — 충돌/권한 문제를 확인하세요.${NC}"
        exit 1
    fi
    p "   ${GREEN}✓${NC} git pull 완료"

    p "3) 실행 중 서비스 중지 시도..."
    if launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        p "   ${GREEN}✓${NC} 서비스 중지 완료"
    else
        p "   ${YELLOW}이미 중지 상태 — 스킵${NC}"
    fi

    p "4) 기존 설치 제거..."
    cmd_uninstall

    p "5) 재설치 진행..."
    bash "$REPO_INSTALL_SCRIPT"

    printf "\n"
    p "${GREEN}${BOLD}✅ 업데이트 완료!${NC}"
    p "   상태 확인: ${BOLD}avwatcher status${NC}"
}

# ── 커맨드 라우팅 ──────────────────────────────
case "${1:-}" in
    start)     cmd_start     ;;
    stop)      cmd_stop      ;;
    restart)   cmd_restart   ;;
    status)    cmd_status    ;;
    logs)      cmd_logs      ;;
    uninstall) cmd_uninstall ;;
    update)    cmd_update    ;;
    *)
        p "${BOLD}avwatcher${NC} — AWS VPN 연결을 감지하여 SSO 로그인을 자동으로 실행합니다."
        printf "\n"
        printf "Usage: avwatcher <command>\n"
        printf "\n"
        printf "Commands:\n"
        printf "  start      서비스 시작\n"
        printf "  stop       서비스 중지\n"
        printf "  restart    서비스 재시작\n"
        printf "  status     실행 상태 및 최근 로그 확인\n"
        printf "  logs       실시간 로그 스트리밍\n"
        printf "  uninstall  완전 제거 (파일, plist, PATH 블록 모두)\n"
        printf "  update     최신 release 확인 후 필요 시 업데이트 실행\n"
        ;;
esac
