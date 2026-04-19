#!/usr/bin/env python3
"""
AWS VPN Watcher
---------------
AWS VPN Client 연결을 감지하면 macOS 다이얼로그로 프로필을 선택하고
자동으로 aws sso login을 실행합니다.

SSO 자동 로그인을 끄려면 환경변수 AWS_VPN_WATCHER_SKIP_SSO_LOGIN=1 이거나
실행 인자 --no-sso-login 을 사용하세요 (LaunchAgent plist 의 EnvironmentVariables 등).
"""

import argparse
import configparser
import hashlib
import json
import select
import subprocess
import time
import logging
import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
POLL_INTERVAL   = 5   # VPN 감지 주기 (초)
STABILIZE_DELAY = 2   # VPN 연결 후 다이얼로그 표시 전 대기 (초)
# VPN을 켠 채로 두었을 때 SSO 만료를 잡기 위한 주기 점검 (초)
SSO_RECHECK_WHILE_CONNECTED_SEC = 60
# 연결 유지 중 만료가 계속일 때 알림만 주기적으로 (다이얼로그 없음, 초)
STILL_EXPIRED_NOTIFY_INTERVAL_SEC = 900
# 자동 업데이트 체크 주기 (초, 기본 24시간)
AUTO_UPDATE_CHECK_INTERVAL_SEC = 24 * 60 * 60
# SSO 로그인 1회 최대 대기 시간 (초)
SSO_LOGIN_TIMEOUT_SEC = 180
HOME_DIR = os.path.expanduser("~")
AUTO_UPDATE_STATE_CANDIDATES = [
    os.path.join(HOME_DIR, ".local", "log", "aws-vpn-watcher-update.json"),
    os.path.join(HOME_DIR, ".aws-vpn-watcher-update.json"),
]
LOG_FILE = os.path.expanduser("~/.local/log/aws-vpn-watcher.log")
AWS_VPN_CLIENT_APP = "/Applications/AWS VPN Client/AWS VPN Client.app"
# macOS AWS VPN Client 가 커넥션 목록을 저장하는 경로 (ProfileName 기준으로 AWS CLI 프로필과 맞추는 전제)
AWS_VPN_CLIENT_CONNECTION_PROFILES_FILE = os.path.join(
    HOME_DIR, ".config", "AWSVPNClient", "ConnectionProfiles"
)
# VPN 클라이언트 ProfileName → ~/.aws/config SSO 프로필 이름 (이름이 다를 때 사용자가 한 번 지정)
VPN_SSO_MAPPINGS_DIR = os.path.join(HOME_DIR, ".config", "aws-vpn-watcher")
VPN_SSO_MAPPINGS_FILE = os.path.join(VPN_SSO_MAPPINGS_DIR, "vpn-sso-mappings.json")


def _env_truthy(name: str) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    return v in ("1", "true", "yes", "on")


# ── 시스템 명령어 절대경로 (LaunchAgent는 PATH가 제한적) ──
CMD_PGREP     = "/usr/bin/pgrep"
CMD_IFCONFIG  = "/sbin/ifconfig"
CMD_OSASCRIPT = "/usr/bin/osascript"
CMD_AVWATCHER = os.path.expanduser("~/.local/bin/avwatcher")
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


def _resolve_auto_update_state_file() -> str:
    for path in AUTO_UPDATE_STATE_CANDIDATES:
        parent = os.path.dirname(path)
        try:
            os.makedirs(parent, exist_ok=True)
        except Exception:
            continue
        if os.path.isdir(parent) and os.access(parent, os.W_OK):
            return path
    # 마지막 fallback: 사용자 홈 루트 파일
    return os.path.join(HOME_DIR, ".aws-vpn-watcher-update.json")


AUTO_UPDATE_STATE_FILE = _resolve_auto_update_state_file()


def _load_auto_update_state() -> dict:
    try:
        if not os.path.isfile(AUTO_UPDATE_STATE_FILE):
            return {}
        with open(AUTO_UPDATE_STATE_FILE) as f:
            return json.load(f)
    except Exception as e:
        log.warning(f"자동 업데이트 상태 읽기 실패: {e}")
        return {}


def _save_auto_update_state(state: dict):
    try:
        with open(AUTO_UPDATE_STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        log.warning(f"자동 업데이트 상태 저장 실패: {e}")


_auto_update_lock = threading.Lock()
_auto_update_running = False
_sso_login_lock = threading.Lock()
_sso_login_running = False


def _run_auto_update():
    global _auto_update_running
    with _auto_update_lock:
        if _auto_update_running:
            return
        _auto_update_running = True

    try:
        if not os.path.isfile(CMD_AVWATCHER):
            log.warning(f"자동 업데이트 실패: avwatcher 커맨드 없음 ({CMD_AVWATCHER})")
            return

        log.info("자동 업데이트 점검 시작 (avwatcher update)")
        proc = subprocess.Popen(
            [CMD_AVWATCHER, "update"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip()
            if line:
                log.info(f"[auto-update] {line}")
        proc.wait()

        if proc.returncode == 0:
            log.info("자동 업데이트 점검 완료")
        else:
            log.error(f"자동 업데이트 실패 (returncode={proc.returncode})")
    except Exception as e:
        log.error(f"자동 업데이트 실행 중 오류: {e}", exc_info=True)
    finally:
        with _auto_update_lock:
            _auto_update_running = False


def maybe_trigger_daily_auto_update(now_ts: float):
    state = _load_auto_update_state()
    last_check_ts = float(state.get("last_check_ts", 0.0))
    if now_ts - last_check_ts < AUTO_UPDATE_CHECK_INTERVAL_SEC:
        return

    # 점검 시각을 먼저 저장해, 실패 시에도 과도한 반복 실행을 방지
    state["last_check_ts"] = now_ts
    _save_auto_update_state(state)

    threading.Thread(target=_run_auto_update, daemon=True).start()


# ──────────────────────────────────────────────
# SSO 프로필 자동 탐색
# ──────────────────────────────────────────────
def discover_sso_profiles(*, verbose: bool = True) -> List[str]:
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

    if verbose:
        log.info(f"탐색된 SSO 프로필: {sso_profiles}")
    return sorted(sso_profiles)


def load_aws_vpn_client_connection_profile_names() -> Optional[Set[str]]:
    """
    AWS VPN Client 에 등록된 커넥션의 ProfileName 집합을 반환합니다.
    ConnectionProfiles 파일이 없으면 None (레거시 동작: config 의 전체 SSO 프로필 사용).
    파일은 있으나 읽기 실패·형식 오류면 빈 set.
    """
    path = AWS_VPN_CLIENT_CONNECTION_PROFILES_FILE
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning(f"AWS VPN Client ConnectionProfiles 읽기 실패 ({path}): {e}")
        return set()

    raw = data.get("ConnectionProfiles")
    if not isinstance(raw, list):
        log.warning("ConnectionProfiles JSON 에 ConnectionProfiles 배열이 없습니다.")
        return set()

    names: Set[str] = set()
    for item in raw:
        if isinstance(item, dict):
            pn = item.get("ProfileName")
            if pn:
                names.add(str(pn))
    return names


def load_vpn_sso_mappings() -> dict[str, str]:
    """VPN ProfileName → AWS CLI SSO 프로필 이름."""
    if not os.path.isfile(VPN_SSO_MAPPINGS_FILE):
        return {}
    try:
        with open(VPN_SSO_MAPPINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning(f"VPN↔SSO 매핑 파일 읽기 실패 ({VPN_SSO_MAPPINGS_FILE}): {e}")
        return {}
    raw = data.get("vpn_to_sso_profile")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, str) and k.strip() and v.strip():
            out[k.strip()] = v.strip()
    return out


def save_vpn_sso_mappings(mappings: dict[str, str]):
    try:
        os.makedirs(VPN_SSO_MAPPINGS_DIR, exist_ok=True)
        payload = {
            "version": 1,
            "vpn_to_sso_profile": dict(sorted(mappings.items())),
        }
        with open(VPN_SSO_MAPPINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write("\n")
        log.info(f"VPN↔SSO 매핑 저장: {VPN_SSO_MAPPINGS_FILE}")
    except Exception as e:
        log.warning(f"VPN↔SSO 매핑 저장 실패: {e}")


def _mapping_sso_for_vpn(mappings: dict[str, str], vpn_profile_name: str) -> Optional[str]:
    """저장된 매핑에서 VPN ProfileName 에 대응하는 SSO 프로필 이름 (정확히 또는 대소문자 무시)."""
    if vpn_profile_name in mappings:
        return mappings[vpn_profile_name]
    lk = vpn_profile_name.lower()
    for k, v in mappings.items():
        if k.lower() == lk:
            return v
    return None


def _vpn_names_needing_user_mapping(
    all_sso: List[str], vpn_names: Set[str], mappings: dict[str, str]
) -> List[str]:
    """
    (1) 이름이 같은 SSO 프로필이 없고
    (2) 유효한 저장 매핑도 없는
    VPN ProfileName 목록.
    """
    need: List[str] = []
    for vpn in sorted(vpn_names):
        if any(p.lower() == vpn.lower() for p in all_sso):
            continue
        mapped = _mapping_sso_for_vpn(mappings, vpn)
        if mapped and mapped in all_sso:
            continue
        need.append(vpn)
    return need


def _applescript_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def ask_sso_profile_for_vpn_mapping_dialog(
    vpn_profile_name: str, sso_profiles: List[str]
) -> Optional[str]:
    """
    이름이 맞지 않는 VPN 커넥션 하나에 대해, 연결할 SSO 프로필을 한 개 고릅니다.
    취소·빈 선택 → None.
    """
    if not sso_profiles:
        return None
    safe_vpn = _applescript_escape(vpn_profile_name)
    items_str = "{" + ", ".join(f'"{_applescript_escape(p)}"' for p in sso_profiles) + "}"
    apple_script = f"""
set profileList to {items_str}
set chosen to choose from list profileList ¬
    with prompt "VPN 커넥션과 AWS SSO 프로필 이름이 다릅니다.\\n\\nVPN: \\"{safe_vpn}\\"\\n\\n이 VPN에 쓸 ~/.aws/config 의 SSO 프로필을 한 개 고르세요. (건너뛰려면 선택 해제 후 확인)" ¬
    without multiple selections allowed ¬
    with empty selection allowed
if chosen is false then
    return ""
end if
if (count of chosen) is 0 then
    return ""
end if
return item 1 of chosen
"""
    try:
        result = subprocess.run(
            [CMD_OSASCRIPT, "-e", apple_script],
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = result.stdout.strip()
        if not out:
            log.info(f"VPN↔SSO 매핑 건너뜀 또는 취소: VPN={vpn_profile_name!r}")
            return None
        if out in sso_profiles:
            return out
        log.warning(f"다이얼로그 결과가 목록에 없음: {out!r}")
        return None
    except subprocess.TimeoutExpired:
        log.warning("VPN↔SSO 매핑 다이얼로그 시간 초과")
        return None
    except Exception as e:
        log.error(f"VPN↔SSO 매핑 다이얼로그 실패: {e}")
        return None


def prompt_and_save_vpn_sso_mappings(unresolved_vpns: List[str], all_sso: List[str]) -> dict[str, str]:
    """미해결 VPN 각각에 대해 다이얼로그로 매핑을 받아 파일에 병합 저장합니다."""
    before = load_vpn_sso_mappings()
    current = dict(before)
    for vpn in unresolved_vpns:
        chosen = ask_sso_profile_for_vpn_mapping_dialog(vpn, all_sso)
        if chosen:
            current[vpn] = chosen
    if current != before:
        save_vpn_sso_mappings(current)
    return current


def resolve_watched_sso_profiles(
    all_sso: List[str],
    vpn_names: Optional[Set[str]],
    mappings: dict[str, str],
    *,
    verbose: bool = False,
) -> List[str]:
    """
    감시할 SSO 프로필 목록.
    - VPN ProfileName 과 동일한 이름의 SSO 프로필
    - 또는 vpn-sso-mappings 에 저장된 대응
    """
    if vpn_names is None:
        if verbose:
            log.info(
                "AWS VPN Client ConnectionProfiles 가 없습니다. "
                "~/.aws/config 의 모든 SSO 프로필을 감시합니다 (레거시 모드)."
            )
        return list(all_sso)

    if not vpn_names:
        if verbose:
            log.info(
                "AWS VPN Client 에 등록된 커넥션이 없습니다. "
                "이번 점검에서는 SSO 프로필을 감시하지 않습니다."
            )
        return []

    watched: Set[str] = set()
    vpn_by_lower = {n.lower(): n for n in vpn_names}

    for p in all_sso:
        if p.lower() in vpn_by_lower:
            watched.add(p)

    for vpn in vpn_names:
        if any(p.lower() == vpn.lower() for p in all_sso):
            continue
        mapped = _mapping_sso_for_vpn(mappings, vpn)
        if mapped and mapped in all_sso:
            watched.add(mapped)

    by_name = sorted(p for p in all_sso if p.lower() in vpn_by_lower)
    by_map = sorted(watched - set(by_name))

    unresolved = _vpn_names_needing_user_mapping(all_sso, vpn_names, mappings)
    if unresolved:
        msg = (
            "이름·매핑으로 아직 SSO 가 연결되지 않은 VPN 커넥션: "
            + ", ".join(unresolved)
        )
        if verbose:
            log.warning(msg)
        else:
            log.debug(msg)

    if not watched and all_sso:
        msg = (
            "등록된 VPN 커넥션에 대응하는 SSO 프로필이 없습니다. "
            f"VPN: {sorted(vpn_names)}, SSO: {all_sso} — "
            f"이름을 맞추거나 매핑 파일을 편집하세요: {VPN_SSO_MAPPINGS_FILE}"
        )
        if verbose:
            log.warning(msg)
        else:
            log.debug(msg)
    elif verbose:
        parts = []
        if by_name:
            parts.append(f"이름 일치 {len(by_name)}개: {by_name}")
        if by_map:
            parts.append(f"저장 매핑 {len(by_map)}개: {by_map}")
        log.info(
            "VPN 기준 감시 SSO 프로필 "
            f"({len(watched)}개): "
            + ("; ".join(parts) if parts else str(sorted(watched)))
        )

    return sorted(watched)


def get_watched_sso_profiles(
    all_sso: List[str], *, verbose: bool = False, offer_mapping_ui: bool = False
) -> List[str]:
    """
    ConnectionProfiles + (이름 일치 | vpn-sso-mappings.json) 으로 감시 대상 SSO 목록.
    offer_mapping_ui=True 이면, VPN 연결 직후 등에서 미매칭 커넥션에 대해 매핑 다이얼로그를 띄웁니다.
    """
    vpn_names = load_aws_vpn_client_connection_profile_names()
    if vpn_names is None:
        return resolve_watched_sso_profiles(all_sso, None, {}, verbose=verbose)

    mappings = load_vpn_sso_mappings()
    unresolved = _vpn_names_needing_user_mapping(all_sso, vpn_names, mappings)

    if offer_mapping_ui and unresolved and all_sso:
        try:
            os.makedirs(VPN_SSO_MAPPINGS_DIR, exist_ok=True)
        except Exception:
            pass
        notify(
            "AWS VPN Watcher — VPN↔SSO 매핑",
            "이름이 다른 커넥션이 있습니다. 다음 창에서 SSO 프로필을 골라 주세요. "
            f"(저장: {VPN_SSO_MAPPINGS_FILE})",
            on_click=VPN_SSO_MAPPINGS_DIR,
        )
        mappings = prompt_and_save_vpn_sso_mappings(unresolved, all_sso)

    return resolve_watched_sso_profiles(all_sso, vpn_names, mappings, verbose=verbose)


# ──────────────────────────────────────────────
# SSO 세션 유효성 확인
# ──────────────────────────────────────────────
def get_sso_start_url(profile: str) -> Optional[str]:
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


def _check_cache_file(path: str, profile: str) -> Optional[bool]:
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


def get_active_vpn_interfaces() -> List[str]:
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
def ask_profiles_via_dialog(profiles: List[str]) -> List[str]:
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

AWS_VPN_ICON = (
    "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/AppIcon.icns"
)


def _notify_open_url(on_click: Optional[str]) -> Optional[str]:
    """
    terminal-notifier -open 에 넣을 URL.
    None → -open 생략(클릭 시 별도 동작 없음).
    """
    if on_click is None:
        return None
    if on_click == "log":
        p = Path(LOG_FILE)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return p.as_uri()
    if on_click == "aws_vpn":
        app = Path(AWS_VPN_CLIENT_APP)
        if app.is_dir():
            return app.as_uri()
        return _notify_open_url("log")
    if on_click.startswith(("http://", "https://", "file:")):
        return on_click
    p = Path(on_click).expanduser()
    if p.exists():
        return p.as_uri()
    return _notify_open_url("log")


def notify(title: str, message: str, *, on_click: Optional[str] = "log"):
    """
    macOS 알림 센터에 알림 표시.
    terminal-notifier 사용 시 -open 으로 클릭(보기) 동작을 연결합니다.
    on_click=None 이면 -open 을 넣지 않습니다.
    osascript fallback 은 시스템 제약으로 클릭 URL을 붙이지 못합니다.
    """
    try:
        open_url = _notify_open_url(on_click)
        if CMD_TERMINAL_NOTIFIER:
            cmd: List[str] = [
                CMD_TERMINAL_NOTIFIER,
                "-title",
                title,
                "-message",
                message,
                "-sound",
                "Glass",
            ]
            if os.path.isfile(AWS_VPN_ICON):
                cmd.extend(["-appIcon", AWS_VPN_ICON])
            if open_url:
                cmd.extend(["-open", open_url])
            subprocess.run(cmd, check=False, capture_output=True)
        else:
            # fallback: 클릭 시 동작 없음(시스템이 보기 버튼을 보여줄 수 있음)
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


def run_sso_login(profiles: List[str]):
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
            started_at = time.time()
            timed_out = False

            # stdout을 비차단에 가깝게 읽으면서 타임아웃을 강제합니다.
            while True:
                if proc.poll() is not None:
                    break

                if time.time() - started_at >= SSO_LOGIN_TIMEOUT_SEC:
                    timed_out = True
                    log.warning(
                        f"[{profile}] SSO 로그인 시간 초과 "
                        f"({SSO_LOGIN_TIMEOUT_SEC}초) — 프로세스 종료"
                    )
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    break

                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if not ready:
                    continue

                line = proc.stdout.readline()
                if not line:
                    continue
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

            if timed_out:
                notify(
                    "AWS SSO Login 시간 초과",
                    f"{profile} 인증이 {SSO_LOGIN_TIMEOUT_SEC}초 내 완료되지 않아 중단했습니다.",
                )
                log.warning(
                    f"[{profile}] 인증 창이 닫혔거나 브라우저 인증이 완료되지 않아 중단됨"
                )
            elif proc.returncode == 0:
                log.info(f"✅ {profile} 로그인 완료")
                notify("AWS SSO Login ✅", f"{profile} 로그인 완료!")
            else:
                log.error(f"❌ {profile} 로그인 실패 (returncode={proc.returncode})")
                notify("AWS SSO Login ❌", f"{profile} 로그인 실패")

        except Exception as e:
            log.error(f"{profile} 로그인 중 오류: {e}", exc_info=True)
            notify("AWS SSO Login ❌", f"{profile} 오류 발생")


def run_sso_login_async(profiles: List[str], reason: str = ""):
    global _sso_login_running
    if not profiles:
        return

    with _sso_login_lock:
        if _sso_login_running:
            log.info("이미 SSO 로그인이 진행 중이어서 새 요청을 건너뜁니다.")
            return
        _sso_login_running = True

    def _worker():
        global _sso_login_running
        try:
            if reason:
                log.info(f"SSO 로그인 비동기 실행 시작 — 이유: {reason}")
            run_sso_login(profiles)
        finally:
            with _sso_login_lock:
                _sso_login_running = False

    threading.Thread(target=_worker, daemon=True).start()


# ──────────────────────────────────────────────
# 메인 루프
# ──────────────────────────────────────────────
def main(*, skip_sso_login: bool = False):
    log.info("=" * 50)
    log.info("AWS VPN Watcher 시작")
    log.info(f"감지 주기: {POLL_INTERVAL}초")
    if skip_sso_login:
        log.info(
            "SSO 자동 로그인 비활성: 만료 시 프로필 다이얼로그·aws sso login 을 실행하지 않습니다 "
            "(--no-sso-login 또는 AWS_VPN_WATCHER_SKIP_SSO_LOGIN)"
        )
    log.info(
        f"연결 유지 중 SSO 재점검: {SSO_RECHECK_WHILE_CONNECTED_SEC}초마다 "
        f"(만료 전환 시 알림·다이얼로그)"
    )
    log.info(
        f"자동 업데이트 점검: {AUTO_UPDATE_CHECK_INTERVAL_SEC // 3600}시간마다 "
        "(release 기준 필요 시 업데이트)"
    )
    log.info("=" * 50)

    was_connected = False
    # 직전 VPN 연결 유지 점검에서 SSO가 전부 유효했는지 (만료 전환 감지용)
    connected_sso_all_valid_prev: Optional[bool] = None
    last_mid_sso_check_ts = 0.0
    last_still_expired_notify_ts = 0.0

    while True:
        try:
            now_ts = time.time()
            maybe_trigger_daily_auto_update(now_ts)

            connected = is_vpn_connected()

            if connected and not was_connected:
                ifaces = get_active_vpn_interfaces()
                log.info(f"✅ VPN 연결 감지! 인터페이스: {ifaces}")
                notify(
                    "AWS VPN 연결됨 🔐",
                    "프로필을 선택해주세요...",
                    on_click="aws_vpn",
                )

                # 연결 안정화 대기
                time.sleep(STABILIZE_DELAY)

                # VPN 클라이언트 등록 커넥션에 해당하는 SSO 만 (이름 일치 또는 저장된 매핑; 미매칭 시 다이얼로그)
                all_sso = discover_sso_profiles()
                available = get_watched_sso_profiles(
                    all_sso, verbose=True, offer_mapping_ui=True
                )
                if not available:
                    if not all_sso:
                        log.warning("SSO 프로필을 찾을 수 없습니다. ~/.aws/config 를 확인하세요.")
                        notify(
                            "AWS VPN Watcher ⚠️",
                            "SSO 프로필을 찾을 수 없습니다.",
                            on_click=os.path.expanduser("~/.aws/config"),
                        )
                    else:
                        log.warning(
                            "VPN 에서 감시할 SSO 프로필을 정하지 못했습니다. "
                            f"이름을 맞추거나 매핑을 확인하세요: {VPN_SSO_MAPPINGS_FILE}"
                        )
                        notify(
                            "AWS VPN Watcher ⚠️",
                            "VPN에 대응하는 SSO 프로필이 없습니다. 이름 일치 또는 매핑을 설정하세요.",
                            on_click=VPN_SSO_MAPPINGS_DIR,
                        )
                    connected_sso_all_valid_prev = None
                    last_mid_sso_check_ts = time.time()
                    was_connected = connected
                    continue

                # 세션이 이미 유효한 프로필은 제외
                valid   = [p for p in available if is_sso_session_valid(p)]
                expired = [p for p in available if p not in valid]

                if valid:
                    log.info(
                        f"로그인 생략 프로필 ({len(valid)}개) — 이유: SSO 세션 유효 | "
                        + ", ".join(valid)
                    )

                if not expired:
                    log.info("로그인 불필요 — 모든 프로필의 SSO 세션이 유효합니다. 건너뜁니다.")
                    notify(
                        "AWS VPN 연결됨 ✅",
                        "SSO 세션이 유효합니다. 로그인 생략.",
                        on_click="aws_vpn",
                    )
                    connected_sso_all_valid_prev = True
                    last_mid_sso_check_ts = time.time()
                    was_connected = connected
                    continue

                if skip_sso_login:
                    log.info(
                        "만료된 SSO 가 있으나 자동 로그인 비활성 옵션으로 "
                        f"다이얼로그·aws sso login 을 건너뜁니다: {', '.join(expired)}"
                    )
                    notify(
                        "AWS SSO 만료 (로그인 안 함 모드)",
                        "만료된 프로필이 있습니다. 필요 시 터미널에서 aws sso login 하세요.",
                        on_click="log",
                    )
                    connected_sso_all_valid_prev = False
                    last_mid_sso_check_ts = time.time()
                    was_connected = connected
                    continue

                # 만료된 프로필만 다이얼로그에 표시
                selected = ask_profiles_via_dialog(expired)

                if selected:
                    run_sso_login_async(selected, reason="VPN 연결 직후 만료 프로필")
                    all_sso = discover_sso_profiles(verbose=False)
                    available = get_watched_sso_profiles(
                        all_sso, verbose=False, offer_mapping_ui=False
                    )
                    valid_after = [p for p in available if is_sso_session_valid(p)]
                    expired_after = [p for p in available if p not in valid_after]
                    connected_sso_all_valid_prev = len(expired_after) == 0
                else:
                    log.info(
                        f"로그인 생략 — 이유: 사용자가 다이얼로그에서 취소 | "
                        f"대상 프로필: {expired}"
                    )
                    notify("AWS VPN Watcher", "SSO 로그인을 건너뛰었습니다.")
                    connected_sso_all_valid_prev = False
                last_mid_sso_check_ts = time.time()

            elif not connected and was_connected:
                log.info("⚠️  VPN 연결 해제됨")
                notify(
                    "AWS VPN 연결 해제",
                    "VPN 연결이 끊겼습니다.",
                    on_click="aws_vpn",
                )
                connected_sso_all_valid_prev = None
                last_still_expired_notify_ts = 0.0

            elif connected and was_connected:
                now_ts = time.time()
                if now_ts - last_mid_sso_check_ts >= SSO_RECHECK_WHILE_CONNECTED_SEC:
                    last_mid_sso_check_ts = now_ts
                    all_sso = discover_sso_profiles(verbose=False)
                    available = get_watched_sso_profiles(
                        all_sso, verbose=False, offer_mapping_ui=False
                    )
                    if available:
                        valid = [p for p in available if is_sso_session_valid(p)]
                        expired = [p for p in available if p not in valid]
                        if expired:
                            if skip_sso_login:
                                if connected_sso_all_valid_prev is True:
                                    log.info(
                                        "VPN 유지 중 SSO 만료 — 자동 로그인 비활성로 "
                                        "다이얼로그·aws sso login 생략: "
                                        + ", ".join(expired)
                                    )
                                    notify(
                                        "AWS SSO 만료 (로그인 안 함 모드)",
                                        "SSO가 만료됐습니다. 필요 시 터미널에서 로그인하세요.",
                                        on_click="log",
                                    )
                                else:
                                    log.debug(
                                        "VPN 유지 중 SSO 여전히 만료 (로그인 안 함 모드, 알림 생략): "
                                        + ", ".join(expired)
                                    )
                                connected_sso_all_valid_prev = False
                            elif connected_sso_all_valid_prev is True:
                                log.info(
                                    "VPN 연결 유지 중 SSO 만료 감지 "
                                    "(직전 점검까지 모든 프로필 유효)"
                                )
                                notify(
                                    "AWS SSO 만료 🔐",
                                    "VPN은 연결됐지만 SSO가 만료됐습니다. 재로그인할 프로필을 고르세요.",
                                    on_click="log",
                                )
                                selected = ask_profiles_via_dialog(expired)
                                if selected:
                                    run_sso_login_async(
                                        selected,
                                        reason="VPN 연결 유지 중 SSO 만료",
                                    )
                                    all_sso = discover_sso_profiles(verbose=False)
                                    available = get_watched_sso_profiles(
                                        all_sso, verbose=False, offer_mapping_ui=False
                                    )
                                    valid_after = [
                                        p for p in available if is_sso_session_valid(p)
                                    ]
                                    expired_after = [
                                        p for p in available if p not in valid_after
                                    ]
                                    connected_sso_all_valid_prev = (
                                        len(expired_after) == 0
                                    )
                                else:
                                    log.info(
                                        "연결 유지 중 만료 — 사용자가 재로그인 다이얼로그 취소"
                                    )
                                    connected_sso_all_valid_prev = False
                            elif connected_sso_all_valid_prev is False:
                                if (
                                    not skip_sso_login
                                    and now_ts - last_still_expired_notify_ts
                                    >= STILL_EXPIRED_NOTIFY_INTERVAL_SEC
                                ):
                                    notify(
                                        "AWS SSO 만료 — 자동 재로그인",
                                        "세션이 아직 만료 상태여서 자동으로 재로그인을 시도합니다.",
                                        on_click="log",
                                    )
                                    log.info(
                                        "만료 상태 지속 감지 — 만료 프로필 자동 재로그인 시도: "
                                        + ", ".join(expired)
                                    )
                                    run_sso_login_async(expired, reason="만료 상태 지속")
                                    last_still_expired_notify_ts = now_ts
                            else:
                                connected_sso_all_valid_prev = False
                        else:
                            connected_sso_all_valid_prev = True
                            last_still_expired_notify_ts = 0.0

            was_connected = connected

        except Exception as e:
            log.error(f"오류 발생: {e}", exc_info=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(
        description="AWS VPN Client 연결 시 AWS SSO 로그인을 돕는 macOS watcher",
    )
    _parser.add_argument(
        "--no-sso-login",
        action="store_true",
        help="만료 시 프로필 선택 다이얼로그와 aws sso login 을 실행하지 않습니다.",
    )
    _args = _parser.parse_args()
    main(
        skip_sso_login=_args.no_sso_login
        or _env_truthy("AWS_VPN_WATCHER_SKIP_SSO_LOGIN"),
    )
