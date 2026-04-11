# aws-vpn-watcher

Automatically runs `aws sso login` when AWS VPN Client connects — so you never forget again.

## How it works

aws-vpn-watcher runs as a macOS LaunchAgent in the background. When it detects an AWS VPN connection (by monitoring the `openvpn` process and `utun` network interfaces), it prompts you to select which AWS SSO profiles to log into and opens the browser for authentication automatically.

```
AWS VPN connects
    → Profile selection dialog appears
        → Browser opens for SSO authentication
            → Done ✅
```

## Requirements

- macOS
- Python 3
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [AWS VPN Client](https://aws.amazon.com/vpn/client-vpn-download/)
- [terminal-notifier](https://github.com/julienXX/terminal-notifier) *(optional — for notifications with icon)*

## Installation

```bash
git clone https://github.com/ppbstudios/aws-vpn-watcher.git
cd aws-vpn-watcher
bash install.sh
```

Then reload your shell:

```bash
source ~/.zshrc
```

The service starts immediately and auto-starts on every boot.

## Usage

```bash
avwatcher start      # Start the service
avwatcher stop       # Stop the service
avwatcher restart    # Restart the service
avwatcher status     # Show status and recent logs
avwatcher logs       # Stream live logs
avwatcher uninstall  # Remove everything
```

## Profile detection

aws-vpn-watcher automatically reads `~/.aws/config` and discovers SSO-enabled profiles (those with `sso_session`, `sso_start_url`, or `sso_account_id`). No manual configuration needed — add or remove profiles from your AWS config and they'll appear in the dialog automatically.

## Logs

```bash
tail -f ~/.local/log/aws-vpn-watcher.log
```

## Uninstall

```bash
avwatcher uninstall
```

This removes the LaunchAgent, installed binaries, and the PATH entry from `~/.zshrc`. Log files are preserved.

## License

MIT
