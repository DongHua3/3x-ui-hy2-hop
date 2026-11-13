# 3x-ui Hysteria2 Port Hopping Tool (`hy2`)

Zero-dependency single-file Linux tool (Bash + Python 3 standard library) to audit **3x-ui / Xray Hysteria2** port hopping, configure idempotent IPv4/IPv6 NAT forwarding (`systemd`), and perform live bidirectional CLI verification across PC and mobile clients.

## Features

1. **Full Audit (`--check` / `--json`)**
   - Dynamically locates `x-ui` (`XUI_DB_FOLDER`, `XUI_BIN_FOLDER`, `xray` args), reads `x-ui.db` safely in WAL read-only mode, and cross-checks against `config.json` and live `ss -4/-6 -ulpne` UDP sockets.
   - Detects IPv6 dual-stack blackholes (`listen: 0.0.0.0` while global IPv6 / `AAAA` is active), `v6only` mismatches, overlapping UDP services, and `INPUT` firewall blocks.
   - Provides concise PC (`v2rayN`) and mobile (`v2rayNG` / `SFA` / `NekoBox`) port-hopping guidance without exposing plaintext passwords in terminal summaries.

2. **Idempotent Dual-Stack NAT Persistence (`--apply` / `--dry-run` / `--uninstall`)**
   - Creates an isolated `HY2_PORT_HOP` chain hooked at the top of `nat PREROUTING` without touching `filter` or `fail2ban` rules.
   - Applies `-m addrtype --dst-type LOCAL` to avoid hijacking ephemeral outbound ports, switches to `DNAT` automatically when bound to non-primary secondary IPs, and persists via `/usr/local/sbin/hy2-port-hop-ctl`, `/etc/hy2-port-hop.conf`, and `hy2-port-hop.service`.

3. **Live Bidirectional Verification (`--monitor`)**
   - Uses kernel `AF_PACKET (SOCK_DGRAM)` + classic BPF (`SO_ATTACH_FILTER`) to drop high-throughput TCP traffic in kernel space while capturing UDP, IPv6 extension headers/fragments, and ICMP/ICMPv6 Port Unreachable replies.
   - Aggregates per `(client_ip, family)` and matches outbound `sport == hopped_port` (conntrack reverse-SNAT) to confirm true bidirectional hopping and client source-port rotation, filtering out VPS outbound DNS/NTP ephemeral noise.

## Quick Install & Usage

```bash
# Install globally as `hy2`
sudo curl -fsSL https://raw.githubusercontent.com/DongHua3/3x-ui-hy2-hop/main/hy2_hop_tool.sh -o /usr/local/sbin/hy2 && sudo chmod +x /usr/local/sbin/hy2

# Interactive menu
sudo hy2

# Read-only audit
sudo hy2 --check

# Preview / apply dual-stack NAT rules
sudo hy2 --apply --dry-run
sudo hy2 --apply

# Live bidirectional CLI monitor
sudo hy2 --monitor

# Uninstall rules and systemd service
sudo hy2 --uninstall
```
