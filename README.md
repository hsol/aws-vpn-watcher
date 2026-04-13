# aws-vpn-watcher

AWS VPN Client에 연결될 때 `aws sso login`을 자동으로 실행해주는 macOS 백그라운드 유틸리티입니다. 이제 VPN 연결 후 로그인을 깜빡하는 일은 없습니다.

## 동작 방식

aws-vpn-watcher는 macOS LaunchAgent로 백그라운드에서 상시 실행됩니다. `openvpn` 프로세스와 `utun` 네트워크 인터페이스를 감시하다가 AWS VPN 연결이 감지되면 프로필 선택 다이얼로그를 띄우고, 선택한 프로필에 대해 브라우저를 자동으로 열어 SSO 인증을 진행합니다.

SSO 세션이 아직 유효한 경우에는 로그인을 건너뛰고 이유를 로그로 남깁니다.
또한 백그라운드 실행 중 하루에 한 번 최신 GitHub release를 확인하고, 새 버전이 있으면 자동 업데이트를 진행합니다. 업데이트는 전체 제거 없이 파일만 갱신한 뒤 LaunchAgent를 다시 등록하며, 등록 실패 시 이전 plist로 복구를 시도합니다.

```text
AWS VPN 연결됨
    → 로그인이 필요한 프로필 선택 다이얼로그 표시
        → 브라우저 열림 (SSO 인증)
            → 완료 ✅
```

## 요구사항

- macOS
- Python 3
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [AWS VPN Client](https://aws.amazon.com/vpn/client-vpn-download/)
- [terminal-notifier](https://github.com/julienXX/terminal-notifier) *(선택 사항 — 앱 아이콘이 포함된 알림 표시)*

## 설치

```bash
git clone https://github.com/hsol/aws-vpn-watcher.git
cd aws-vpn-watcher
bash install.sh
```

설치 후 쉘을 다시 불러옵니다:

```bash
source ~/.zshrc
```

서비스는 설치 즉시 시작되며, 부팅 시 자동으로 실행됩니다.

## 사용법

```bash
avwatcher start      # 서비스 시작
avwatcher stop       # 서비스 중지
avwatcher restart    # 서비스 재시작
avwatcher status     # 상태 및 최근 로그 확인
avwatcher logs       # 실시간 로그 스트리밍
avwatcher uninstall  # 완전 제거
avwatcher update     # 최신 release 확인 후 필요 시 업데이트
```

## 프로필 자동 탐색

aws-vpn-watcher는 `~/.aws/config`를 자동으로 읽어 SSO가 설정된 프로필(`sso_session`, `sso_start_url`, `sso_account_id` 중 하나를 포함하는 프로필)을 탐색합니다. 별도 설정 없이 AWS config에 프로필을 추가하거나 제거하면 다이얼로그에 즉시 반영됩니다.

## 로그

```bash
tail -f ~/.local/log/aws-vpn-watcher.log
```

또는:

```bash
avwatcher logs
```

## 제거

```bash
avwatcher uninstall
```

LaunchAgent, 설치된 바이너리, `~/.zshrc`의 PATH 항목이 모두 제거됩니다. 로그 파일은 보존됩니다.

## 라이선스

MIT
