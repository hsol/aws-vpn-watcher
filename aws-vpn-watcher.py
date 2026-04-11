#!/usr/bin/env python3
"""
AWS VPN Watcher
---------------
AWS VPN Client 연결을 감지하면 macOS 다이얼로그로 프로필을 선택하고
자동으로 aws sso login을 실행합니다.
"""

import configparser
import hashlib
import json
import subprocess
import time
import logging
import os
import re
import sys
import threading
from datetime import datetime, timezone

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
POLL_INTERVAL   = 5   # VPN 감지 주기 (초)
STABILIZE_DELAY = 2   # VPN 연결 후 다이얼로그 표시 전 대기 (초)
LOG_FILE = os.path.expanduser("~/.local/log/aws-vpn-watcher.log")

# ── 시스템 명령어 절대경로 (LaunchAgent는 PATH가 제한적) ──
CMD_PGREP     = "/usr/bin/pgrep"
CMD_IFCONFIG  = "/sbin/ifconfig"
CMD_OSASCRIPT = "/usr/bin/osascript"
CMD_AWS       = next(
    (p for p in [
        "/usr/local/bin/aws",
        "/opt/homebrew/bin/aws",
        "/usr/bin/aws",
    ] if os.path.isfile(p)),
    "aws",  # 못 찾으면 그냥 aws (fallback)
)

# ──────────────────────────────────────────────
# 로깅 설정
# ──────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# SSO 프로필 자동 탐색
# ──────────────────────────────────────────────
def discover_sso_profiles() -> list[str]:
    """
    ~/.aws/config 를 파싱해 SSO 설정이 있는 프로필 목록을 반환합니다.
    sso_session 또는 sso_start_url 키를 가진 [profile xxx] 섹션을 SSO 프로필로 판단합니다.
    """
    config_file = os.path.join(os.path.expanduser("~"), ".aws", "config")
    if not os.path.isfile(config_file):
        log.warning(f"AWS config 파일 없음: {config_file}")
        return []

    config = configparser.ConfigParser()
    config.read(config_file)

    sso_profiles = []
    for section in config.sections():
        if section.startswith("profile "):
            name = section[len("profile "):]
        elif section == "default":
            name = "default"
        else:
            continue  # [sso-session ...] 등 프로필 아닌 섹션 스킵

        opts = dict(config[section])
        if any(k in opts for k in ("sso_session", "sso_start_url", "sso_account_id")):
            sso_profiles.append(name)

    log.info(f"탐색된 SSO 프로필: {sso_profiles}")
    return sorted(sso_profiles)


# ──────────────────────────────────────────────
# SSO 세션 유효성 확인
# ──────────────────────────────────────────────
def get_sso_start_url(profile: str) -> str | None:
    """~/.aws/config 에서 프로필의 sso_start_url을 반환합니다."""
    config_file = os.path.join(os.path.expanduser("~"), ".aws", "config")
    config = configparser.ConfigParser()
    config.read(config_file)

    section = f"profile {profile}" if profile != "default" else "default"
    if section not in config:
        return None

    opts = dict(config[section])

    # 직접 sso_start_url이 있는 경우
    if "sso_start_url" in opts:
        return opts["sso_start_url"]

    # sso_session을 통한 간접 참조인 경우
    if "sso_session" in opts:
        session_section = f"sso-session {opts['sso_session']}"
        if session_section in config:
            return config[session_section].get("sso_start_url")

    return None


def _check_cache_file(path: str, profile: str) -> bool | None:
    """
    캐시 파일 하나를 읽어 유효성을 반환합니다.
    유효 → True, 만료 → False, 파일 없음/읽기 실패 → None
    """
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        expires_at = data.get("expiresAt", "")
        if not expires_at:
            return None
        expires_at = expires_at.replace("UTC", "+00:00").replace("Z", "+00:00")
        expiry = datetime.fromisoformat(expires_at)
        now = datetime.now(timezone.utc)
        if expiry > now:
            remaining_h = int((expiry - now).total_seconds() // 3600)
            log.info(f"[{profile}] SSO 세션 유효 (잔여 약 {remaining_h}시간)")
            return True
        else:
            log.info(f"[{profile}] SSO 세션 만료됨")
            return False
    except Exception as e:
        log.warning(f"[{profile}] 캐시 파일 읽기 실패 ({path}): {e}")
        return None


def is_sso_session_valid(profile: str) -> bool:
    """
    ~/.aws/sso/cache/ 의 토큰 캐시를 확인해 SSO 세션이 유효한지 반환합니다.
    네트워크 호출 없이 로컬 파일만으로 판단합니다.

    AWS CLI 버전에 따라 캐시 파일명 규칙이 다릅니다:
      - 구버전: SHA1(sso_start_url)
      - 신버전(sso-session): SHA1(sso_session_name)
    두 방식 모두 확인하고, 없으면 캐시 디렉토리 전체를 스캔합니다.
    """
    cache_dir = os.path.join(os.path.expanduser("~"), ".aws", "sso", "cache")
    if not os.path.isdir(cache_dir):
        log.info(f"[{profile}] SSO 캐시 디렉토리 없음 → 로그인 필요")
        return False

    config_file = os.path.join(os.path.expanduser("~"), ".aws", "config")
    config = configparser.ConfigParser()
    config.read(config_file)

    section = f"profile {profile}" if profile != "default" else "default"
    opts = dict(config[section]) if section in config else {}

    # ── 후보 캐시 키 목록 생성 ──────────────────
    candidates: list[str] = []

    # 1) 신버전: SHA1(sso_session_name)
    if "sso_session" in opts:
        session_name = opts["sso_session"]
        candidates.append(hashlib.sha1(session_name.encode()).hexdigest())

    # 2) 구버전: SHA1(sso_start_url)
    start_url = get_sso_start_url(profile)
    if start_url:
        candidates.append(hashlib.sha1(start_url.encode()).hexdigest())

    # ── 후보 파일 직접 확인 ─────────────────────
    for key in candidates:
        result = _check_cache_file(os.path.join(cache_dir, f"{key}.json"), profile)
        if result is True:
            return True
        if result is False:
            return False  # 파일은 있는데 만료됨

    # ── fallback: 캐시 디렉토리 전체 스캔 ────────
    # 후보 키로 파일을 찾지 못한 경우, start_url이 일치하는 캐시를 찾습니다.
    log.info(f"[{profile}] 후보 캐시 없음 → 전체 스캔")
    try:
        for fname in os.listdir(cache_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(cache_dir, fname)
            try:
                with open(fpath) as f:
                    data = json.load(f)
                # start_url이 일치하는 파일인지 확인
                if start_url and data.get("startUrl") != start_url:
                    continue
                result = _check_cache_file(fpath, profile)
                if result is True:
                    return True
            except Exception:
                continue
    except Exception as e:
        log.warning(f"[{profile}] 캐시 스캔 실패: {e}")

    log.info(f"[{profile}] 유효한 SSO 캐시 없음 → 로그인 필요")
    return False


# ──────────────────────────────────────────────
# VPN 감지 로직
# ──────────────────────────────────────────────
def is_openvpn_running() -> bool:
    """AWS VPN Client가 사용하는 openvpn 프로세스가 실행 중인지 확인"""
    result = subprocess.run([CMD_PGREP, "-f", "openvpn"], capture_output=True)
    return result.returncode == 0


def get_active_vpn_interfaces() -> list[str]:
    """
    POINTOPOINT 플래그가 있고 RUNNING 상태인 utun 인터페이스 목록 반환.
    AWS VPN Client는 연결 시 이런 형태의 utun 인터페이스를 생성합니다.
    """
    result = subprocess.run([CMD_IFCONFIG], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    vpn_ifaces = []
    current_iface = None
    current_flags = ""

    for line in lines:
        if line and not line.startswith(("\t", " ")):
            current_iface = line.split(":")[0]
            current_flags = line
        elif (
            current_iface
            and current_iface.startswith("utun")
            and "POINTOPOINT" in current_flags
            and "RUNNING" in current_flags
        ):
            if "inet" in line and "-->" in line:
                vpn_ifaces.append(current_iface)

    return vpn_ifaces


def is_vpn_connected() -> bool:
    """
    두 가지 조건을 모두 만족할 때 VPN 연결로 판단:
    1. openvpn 프로세스가 실행 중
    2. POINTOPOINT utun 인터페이스에 IP가 할당됨
    """
    if not is_openvpn_running():
        return False
    return len(get_active_vpn_interfaces()) > 0


# ──────────────────────────────────────────────
# 프로필 선택 다이얼로그
# ──────────────────────────────────────────────
def ask_profiles_via_dialog(profiles: list[str]) -> list[str]:
    """
    macOS 다이얼로그로 로그인할 프로필을 선택합니다.
    여러 항목 선택 가능. 취소 시 빈 리스트 반환.
    """
    # AppleScript용 리스트 문자열 생성 (예: {"ppb-prod", "ppb-dev"})
    items_str = "{" + ", ".join(f'"{p}"' for p in profiles) + "}"

    apple_script = f"""
set profileList to {items_str}
set chosen to choose from list profileList ¬
    with prompt "AWS VPN 연결됨 🔐\n로그인할 프로필을 선택하세요:" ¬
    with multiple selections allowed ¬
    default items {items_str} ¬
    with empty selection allowed
if chosen is false then
    return ""
end if
set output to ""
repeat with i from 1 to count of chosen
    if i > 1 then set output to output & ","
    set output to output & (item i of chosen)
end repeat
return output
"""
    try:
        result = subprocess.run(
            [CMD_OSASCRIPT, "-e", apple_script],
            capture_output=True,
            text=True,
            timeout=60,  # 60초 내에 선택 안 하면 취소 처리
        )
        output = result.stdout.strip()
        if not output:
            log.info("프로필 선택이 취소됐습니다.")
            return []
        selected = [p.strip() for p in output.split(",") if p.strip()]
        log.info(f"선택된 프로필: {selected}")
        return selected
    except subprocess.TimeoutExpired:
        log.warning("다이얼로그 응답 시간 초과 - 취소 처리")
        return []
    except Exception as e:
        log.error(f"다이얼로그 실행 실패: {e}")
        # 폴백: 모든 프로필 사용
        return profiles


# ──────────────────────────────────────────────
# 알림 및 SSO 로그인 실행
# ──────────────────────────────────────────────

# terminal-notifier 경로 탐색 (설치된 경우 아이콘 포함 알림 사용)
CMD_TERMINAL_NOTIFIER = next(
    (p for p in [
        "/usr/local/bin/terminal-notifier",
        "/opt/homebrew/bin/terminal-notifier",
    ] if os.path.isfile(p)),
    None,
)

AWS_VPN_ICON = "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/AppIcon.icns"


def notify(title: str, message: str):
    """
    macOS 알림 센터에 알림 표시.
    terminal-notifier가 설치된 경우 AWS VPN Client 아이콘과 함께 표시하고,
    없으면 osascript로 fallback합니다.
    """
    try:
        if CMD_TERMINAL_NOTIFIER and os.path.isfile(AWS_VPN_ICON):
            subprocess.run(
                [
                    CMD_TERMINAL_NOTIFIER,
                    "-title",   title,
                    "-message", message,
                    "-appIcon", AWS_VPN_ICON,
                    "-sound",   "Glass",
                ],
                check=False,
                capture_output=True,
            )
        else:
            # fallback: osascript 기본 알림
            script = f'display notification "{message}" with title "{title}" sound name "Glass"'
            subprocess.run([CMD_OSASCRIPT, "-e", script], check=False)
    except Exception:
        pass


def open_browser(url: str):
    """/usr/bin/open 으로 브라우저를 직접 엽니다."""
    try:
        subprocess.run(["/usr/bin/open", url], check=False)
        log.info(f"브라우저 열기: {url}")
    except Exception as e:
        log.error(f"브라우저 열기 실패: {e}")


def run_sso_login(profiles: list[str]):
    """
    aws sso login을 Python subprocess로 직접 실행합니다.
    stdout을 실시간으로 읽어 authorization URL이 나오면
    /usr/bin/open 으로 브라우저를 직접 엽니다.
    프로필은 순서대로 하나씩 처리합니다.
    """
    if not profiles:
        log.info("선택된 프로필 없음 - 로그인 생략")
        return

    # plist EnvironmentVariables 에 HOME / AWS_CONFIG_FILE 등이 이미 설정돼 있으므로
    # os.environ 을 그대로 사용합니다.
    for profile in profiles:
        log.info(f"─── SSO 로그인 시작: {profile} ───")
        notify("AWS SSO Login 🔐", f"{profile} 로그인 중... 브라우저를 확인하세요.")

        try:
            proc = subprocess.Popen(
                [CMD_AWS, "sso", "login", "--profile", profile],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,   # stderr를 stdout으로 합침
                text=True,
            )

            aws_cli_opening_browser = False  # aws cli 자체 브라우저 오픈 시도 여부
            fallback_url = None              # aws cli가 출력한 fallback URL

            # stdout을 한 줄씩 읽으며 진행 로그 기록
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip()
                log.info(f"[{profile}] {line}")

                # aws cli가 자체적으로 브라우저를 열려는 경우 → 우리는 열지 않음
                if "Attempting to automatically open" in line:
                    aws_cli_opening_browser = True

                # fallback URL 수집 (aws cli 자체 오픈 실패 대비)
                if not aws_cli_opening_browser and not fallback_url:
                    urls = re.findall(r"https://\S+", line)
                    if urls:
                        fallback_url = urls[0]

            # aws cli가 브라우저를 열지 못했을 때만 우리가 직접 열기
            if not aws_cli_opening_browser and fallback_url:
                log.info("aws cli 자체 브라우저 오픈 없음 → 직접 열기")
                threading.Thread(
                    target=open_browser, args=(fallback_url,), daemon=True
                ).start()

            proc.wait()

            if proc.returncode == 0:
                log.info(f"✅ {profile} 로그인 완료")
                notify("AWS SSO Login ✅", f"{profile} 로그인 완료!")
            else:
                log.error(f"❌ {profile} 로그인 실패 (returncode={proc.returncode})")
                notify("AWS SSO Login ❌", f"{profile} 로그인 실패")

        except Exception as e:
            log.error(f"{profile} 로그인 중 오류: {e}", exc_info=True)
            notify("AWS SSO Login ❌", f"{profile} 오류 발생")


# ──────────────────────────────────────────────
# 메인 루프
# ──────────────────────────────────────────────
def main():
    log.info("=" * 50)
    log.info("AWS VPN Watcher 시작")
    log.info(f"감지 주기: {POLL_INTERVAL}초")
    log.info("=" * 50)

    was_connected = False

    while True:
        try:
            connected = is_vpn_connected()

            if connected and not was_connected:
                ifaces = get_active_vpn_interfaces()
                log.info(f"✅ VPN 연결 감지! 인터페이스: {ifaces}")
                notify("AWS VPN 연결됨 🔐", "프로필을 선택해주세요...")

                # 연결 안정화 대기
                time.sleep(STABILIZE_DELAY)

                # ~/.aws/config 에서 SSO 프로필 실시간 탐색
                available = discover_sso_profiles()
                if not available:
                    log.warning("SSO 프로필을 찾을 수 없습니다. ~/.aws/config 를 확인하세요.")
                    notify("AWS VPN Watcher ⚠️", "SSO 프로필을 찾을 수 없습니다.")
                    was_connected = connected
                    continue

                # 세션이 이미 유효한 프로필은 제외
                expired = [p for p in available if not is_sso_session_valid(p)]

                if not expired:
                    log.info("모든 프로필 세션이 유효합니다. 로그인 생략.")
                    notify("AWS VPN 연결됨 ✅", "SSO 세션이 유효합니다. 로그인 생략.")
                    was_connected = connected
                    continue

                # 만료된 프로필만 다이얼로그에 표시
                selected = ask_profiles_via_dialog(expired)

                if selected:
                    run_sso_login(selected)
                else:
                    log.info("프로필 미선택 - SSO 로그인 건너뜀")
                    notify("AWS VPN Watcher", "SSO 로그인을 건너뛰었습니다.")

            elif not connected and was_connected:
                log.info("⚠️  VPN 연결 해제됨")
                notify("AWS VPN 연결 해제", "VPN 연결이 끊겼습니다.")

            was_connected = connected

        except Exception as e:
            log.error(f"오류 발생: {e}", exc_info=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
