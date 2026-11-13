#!/usr/bin/env bash
# ==============================================================================
# 3x-ui Hysteria2 端口跳跃体检 / NAT 转发持久化 / 双栈实时双向验证工具
# 单文件零第三方依赖（Bash + Python3 标准库），支持 Ubuntu / Debian 主流 VPS
# ==============================================================================
set -euo pipefail

APP_NAME="hy2_hop_tool"
LOCK_FILE="/run/hy2-port-hop-tool.lock"
CTL_BIN="/usr/local/sbin/hy2-port-hop-ctl"
CONF_FILE="/etc/hy2-port-hop.conf"
SERVICE_NAME="hy2-port-hop.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

TMP_DIR=""

cleanup() {
    local rc=$?
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
        rm -rf "${TMP_DIR}"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

msg_err() {
    printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2
}

msg_warn() {
    printf '\033[33m[WARN]\033[0m %s\n' "$*" >&2
}

msg_info() {
    printf '\033[36m[INFO]\033[0m %s\n' "$*"
}

check_prereqs() {
    if ! command -v python3 >/dev/null 2>&1; then
        msg_err "未找到 python3，请先安装 python3。"
        exit 1
    fi

    local missing_mods
    missing_mods="$(python3 - <<'PY' 2>&1 || true
missing = []
for m in ("sqlite3", "http.server", "ctypes", "socket", "json", "secrets", "ipaddress", "threading"):
    try:
        __import__(m)
    except Exception as e:
        missing.append(f"{m}({e})")
if missing:
    print(",".join(missing))
PY
)"
    if [[ -n "$missing_mods" ]]; then
        msg_err "当前 python3 缺少标准库模块（常见于极简 python3-minimal 镜像）: $missing_mods"
        msg_err "请执行: apt-get update && apt-get install -y python3 libpython3-stdlib"
        exit 1
    fi

    if ! command -v ss >/dev/null 2>&1; then
        msg_warn "未找到 ss 命令（iproute2），部分端口监听探测将受限。"
    fi
}

extract_payload() {
    TMP_DIR="$(mktemp -d /tmp/hy2_hop_tool.XXXXXX)"
    chmod 0700 "${TMP_DIR}"
    cat <<'__PYTHON_PAYLOAD__' > "${TMP_DIR}/tool.py"
#!/usr/bin/env python3
import argparse
import ctypes
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import deque

CHAIN_NAME = "HY2_PORT_HOP"
CTL_BIN = "/usr/local/sbin/hy2-port-hop-ctl"
CONF_FILE = "/etc/hy2-port-hop.conf"
SERVICE_NAME = "hy2-port-hop.service"
SERVICE_FILE = f"/etc/systemd/system/{SERVICE_NAME}"

# ------------------------------------------------------------------------------
# Shell & System Helpers
# ------------------------------------------------------------------------------

def run_cmd(cmd, check=False, timeout=8):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        if check:
            raise
        return 1, "", str(e)


def is_root():
    return os.geteuid() == 0


def read_sysctl(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return default


def strip_jsonc(text):
    out = []
    i = 0
    n = len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
        else:
            if c == '"':
                in_str = True
                out.append(c)
                i += 1
            elif c == "/" and i + 1 < n and text[i + 1] == "/":
                while i < n and text[i] != "\n":
                    i += 1
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
            else:
                out.append(c)
                i += 1
    return "".join(out)


def load_json_lenient(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(strip_jsonc(raw))


def parse_port_spec(spec):
    """Parse '47000-50000,51000' -> normalized list of (start, end) tuples."""
    if not spec or not str(spec).strip():
        return []
    ranges = []
    for token in str(spec).split(","):
        token = token.strip()
        if not token:
            continue
        sep = "-" if "-" in token else (":" if ":" in token else None)
        if sep:
            parts = token.split(sep, 1)
            a, b = int(parts[0].strip()), int(parts[1].strip())
            if a < 1 or b > 65535 or a > b:
                raise ValueError(f"非法端口范围: {token}")
            ranges.append((a, b))
        else:
            p = int(token)
            if p < 1 or p > 65535:
                raise ValueError(f"非法端口: {token}")
            ranges.append((p, p))
    if not ranges:
        return []
    ranges.sort()
    merged = [ranges[0]]
    for a, b in ranges[1:]:
        la, lb = merged[-1]
        if a <= lb + 1:
            merged[-1] = (la, max(lb, b))
        else:
            merged.append((a, b))
    return merged


def format_ranges_dash(ranges):
    return ",".join(f"{a}-{b}" if a != b else str(a) for a, b in ranges)


def format_ranges_colon(ranges):
    return [f"{a}:{b}" if a != b else f"{a}:{a}" for a, b in ranges]


def port_in_ranges(port, ranges):
    for a, b in ranges:
        if a <= port <= b:
            return True
    return False


# ------------------------------------------------------------------------------
# Network, Interface & Dual-stack Detection
# ------------------------------------------------------------------------------

def detect_network_state():
    state = {
        "wan_v4_iface": None,
        "wan_v6_iface": None,
        "has_public_v4": False,
        "has_global_v6": False,
        "v4_addrs": [],
        "v6_addrs": [],
        "v6_default_route": False,
        "bindv6only": read_sysctl("/proc/sys/net/ipv6/bindv6only", "0"),
        "conntrack_udp_timeout": read_sysctl("/proc/sys/net/netfilter/nf_conntrack_udp_timeout", "?"),
        "conntrack_udp_stream_timeout": read_sysctl("/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream", "?"),
        "ip_local_port_range": read_sysctl("/proc/sys/net/ipv4/ip_local_port_range", "32768 60999"),
        "rp_filter_all": read_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "?"),
        "iptables_bin": shutil.which("iptables"),
        "ip6tables_bin": shutil.which("ip6tables"),
        "iptables_ver": "",
        "ip6tables_nat_ok": False,
        "xt_addrtype_v4_ok": False,
        "xt_addrtype_v6_ok": False,
        "in_container": False,
    }

    # Container check
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        state["in_container"] = True
    else:
        try:
            with open("/proc/1/cgroup", "r", encoding="utf-8") as f:
                cg = f.read()
            if any(k in cg for k in ("docker", "lxc", "kubepods")):
                state["in_container"] = True
        except Exception:
            pass

    rc, out, _ = run_cmd(["ip", "-4", "route", "show", "default"])
    if rc == 0 and out:
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            state["wan_v4_iface"] = m.group(1)

    rc, out, _ = run_cmd(["ip", "-6", "route", "show", "default"])
    if rc == 0 and out:
        state["v6_default_route"] = True
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            state["wan_v6_iface"] = m.group(1)

    rc, out, _ = run_cmd(["ip", "-j", "addr", "show"])
    if rc == 0 and out:
        try:
            ifaces = json.loads(out)
            for iface in ifaces:
                ifname = iface.get("ifname", "")
                if ifname == "lo":
                    continue
                for addr in iface.get("addr_info", []):
                    fam = addr.get("family")
                    local = addr.get("local")
                    scope = addr.get("scope")
                    if not local or scope != "global":
                        continue
                    if fam == "inet":
                        ip_obj = ipaddress.IPv4Address(local)
                        state["v4_addrs"].append({
                            "iface": ifname,
                            "ip": local,
                            "private": ip_obj.is_private,
                            "primary": not addr.get("secondary", False),
                        })
                        state["has_public_v4"] = True
                    elif fam == "inet6":
                        if addr.get("deprecated") or addr.get("tentative"):
                            continue
                        ip_obj = ipaddress.IPv6Address(local)
                        # Exclude ULA fc00::/7
                        if ip_obj.is_private or ip_obj.is_link_local:
                            continue
                        dis_all = read_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0")
                        dis_if = read_sysctl(f"/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6", "0")
                        if dis_all == "0" and dis_if == "0":
                            state["v6_addrs"].append({
                                "iface": ifname,
                                "ip": local,
                                "primary": not addr.get("secondary", False),
                            })
            if state["v6_addrs"] and state["v6_default_route"]:
                state["has_global_v6"] = True
        except Exception:
            pass

    if state["iptables_bin"]:
        rc, out, _ = run_cmd([state["iptables_bin"], "-V"])
        if rc == 0:
            state["iptables_ver"] = out
        if is_root():
            rc, _, _ = run_cmd([state["iptables_bin"], "-t", "nat", "-C", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "ACCEPT"])
            # rc==1 means rule not matched, rc==2 means invalid syntax/missing xt_addrtype
            rc2, _, err2 = run_cmd([state["iptables_bin"], "-t", "nat", "-C", "PREROUTING", "-p", "udp", "--dport", "65534", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"])
            if rc2 in (0, 1) and "No chain/target/match" not in err2:
                state["xt_addrtype_v4_ok"] = True

    if state["ip6tables_bin"] and is_root():
        rc, _, _ = run_cmd([state["ip6tables_bin"], "-t", "nat", "-S"])
        state["ip6tables_nat_ok"] = (rc == 0)
        if state["ip6tables_nat_ok"]:
            rc2, _, err2 = run_cmd([state["ip6tables_bin"], "-t", "nat", "-C", "PREROUTING", "-p", "udp", "--dport", "65534", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"])
            if rc2 in (0, 1) and "No chain/target/match" not in err2:
                state["xt_addrtype_v6_ok"] = True

    return state


# ------------------------------------------------------------------------------
# 3x-ui & Xray Inspection
# ------------------------------------------------------------------------------

def detect_xui_paths():
    info = {
        "xui_service_active": False,
        "xray_running": False,
        "xray_pids": [],
        "xray_bin": None,
        "xray_version": None,
        "config_path": "/usr/local/x-ui/bin/config.json",
        "confdir": None,
        "db_type": "sqlite",
        "db_path": "/etc/x-ui/x-ui.db",
        "docker_isolated": False,
    }

    rc, out, _ = run_cmd(["systemctl", "is-active", "x-ui"])
    info["xui_service_active"] = (rc == 0 and out == "active")

    rc, out, _ = run_cmd(["systemctl", "show", "x-ui", "-p", "Environment", "-p", "ExecStart"])
    if rc == 0 and out:
        for line in out.splitlines():
            m_db = re.search(r"XUI_DB_FOLDER=(\S+)", line)
            if m_db:
                info["db_path"] = os.path.join(m_db.group(1).strip('"\''), "x-ui.db")
            m_bin = re.search(r"XUI_BIN_FOLDER=(\S+)", line)
            if m_bin:
                info["config_path"] = os.path.join(m_bin.group(1).strip('"\''), "config.json")
            m_dbt = re.search(r"XUI_DB_TYPE=(\S+)", line)
            if m_dbt:
                info["db_type"] = m_dbt.group(1).strip('"\'').lower()

    # Inspect running xray processes
    rc, out, _ = run_cmd(["pgrep", "-af", "xray"])
    if rc == 0 and out:
        host_net_ns = None
        try:
            host_net_ns = os.readlink("/proc/1/ns/net")
        except Exception:
            pass
        for line in out.splitlines():
            parts = line.split(None, 1)
            if not parts:
                continue
            pid_str = parts[0]
            cmd = parts[1] if len(parts) > 1 else ""
            if "xray" not in cmd or "hy2_hop_tool" in cmd:
                continue
            info["xray_running"] = True
            info["xray_pids"].append(int(pid_str))
            bin_tok = cmd.split()[0]
            if os.path.isfile(bin_tok):
                info["xray_bin"] = bin_tok
            m_c = re.search(r"(?:-c|--config)\s+(\S+)", cmd)
            if m_c:
                cand = m_c.group(1)
                if not os.path.isabs(cand):
                    try:
                        cwd = os.readlink(f"/proc/{pid_str}/cwd")
                        cand = os.path.normpath(os.path.join(cwd, cand))
                    except Exception:
                        pass
                if os.path.isfile(cand):
                    info["config_path"] = cand
            m_cd = re.search(r"(?:-confdir)\s+(\S+)", cmd)
            if m_cd:
                info["confdir"] = m_cd.group(1)
            if host_net_ns:
                try:
                    p_ns = os.readlink(f"/proc/{pid_str}/ns/net")
                    if p_ns != host_net_ns:
                        info["docker_isolated"] = True
                except Exception:
                    pass

    if not info["xray_bin"]:
        for cand in ("/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray-linux-arm64", shutil.which("xray") or ""):
            if cand and os.path.isfile(cand):
                info["xray_bin"] = cand
                break

    if info["xray_bin"]:
        rc, out, _ = run_cmd([info["xray_bin"], "version"])
        if rc == 0 and out:
            info["xray_version"] = out.splitlines()[0].strip()

    return info


def read_sqlite_inbounds_ro(db_path):
    if not os.path.isfile(db_path):
        return None, f"未找到数据库文件: {db_path}"
    tmp_db_dir = tempfile.mkdtemp(prefix="xui_db_ro_")
    try:
        for suffix in ("", "-wal", "-shm"):
            src = db_path + suffix
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(tmp_db_dir, os.path.basename(src)))
        snap = os.path.join(tmp_db_dir, os.path.basename(db_path))
        conn = sqlite3.connect(f"file:{snap}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, remark, enable, listen, port, protocol, settings, stream_settings, tag FROM inbounds"
        ).fetchall()
        result = []
        for r in rows:
            result.append({k: r[k] for k in r.keys()})
        conn.close()
        return result, None
    except Exception as e:
        return None, str(e)
    finally:
        shutil.rmtree(tmp_db_dir, ignore_errors=True)


def parse_ss_udp_sockets():
    sockets = []
    # Combine ss -ulpne with family context
    for fam, flag in (("4", "-4"), ("6", "-6"), ("all", "")):
        cmd = ["ss", "-ulpne"]
        if flag:
            cmd.insert(1, flag)
        rc, out, _ = run_cmd(cmd)
        if rc != 0 or not out:
            continue
        if fam == "all" and sockets:
            break
        for line in out.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 5:
                continue
            local_addr = cols[3]
            if ":" not in local_addr:
                continue
            host, port_s = local_addr.rsplit(":", 1)
            if not port_s.isdigit():
                continue
            port = int(port_s)
            v6only = None
            m_v6 = re.search(r"v6only:([01])", line)
            if m_v6:
                v6only = int(m_v6.group(1))
            proc = ""
            m_p = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if m_p:
                proc = f"{m_p.group(1)}({m_p.group(2)})"
            sockets.append({
                "query_fam": fam,
                "local": local_addr,
                "host": host.strip("[]"),
                "port": port,
                "v6only": v6only,
                "proc": proc,
                "raw": line,
            })
    return sockets


def analyze_hy2_inbound(ib, source_name):
    stream = ib.get("streamSettings") or ib.get("stream_settings") or {}
    if isinstance(stream, str):
        try:
            stream = json.loads(stream)
        except Exception:
            stream = {}
    settings = ib.get("settings") or {}
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except Exception:
            settings = {}

    fm = stream.get("finalmask") or {}
    qp = fm.get("quicParams") or {}
    legacy_hop = qp.get("udpHop") or {}
    udp_masks = fm.get("udp") or []

    salamander = None
    udp_hop_new = None
    for m in udp_masks:
        t = (m.get("type") or "").lower()
        if t == "salamander":
            salamander = m.get("settings") or {}
        elif t == "udphop":
            udp_hop_new = m.get("settings") or {}

    hop_ports = legacy_hop.get("ports") or (udp_hop_new or {}).get("remotePorts") or (udp_hop_new or {}).get("ports") or ""
    hop_interval = legacy_hop.get("interval") or (udp_hop_new or {}).get("interval") or ""

    tls = stream.get("tlsSettings") or {}
    sni = tls.get("serverName") or ""
    if not sni:
        certs = tls.get("certificates") or []
        if certs:
            # try domain from cert path
            cpath = certs[0].get("certificateFile", "")
            m_dom = re.search(r"/cert/([^/]+)/", cpath)
            if m_dom:
                sni = m_dom.group(1)

    clients = settings.get("clients") or []
    passwords = [c.get("auth") for c in clients if c.get("auth")]

    sockopt = stream.get("sockopt") or {}
    listen = ib.get("listen")
    if listen is None or listen == "":
        # 3x-ui GenXrayInboundConfig converts empty listen to 0.0.0.0
        effective_listen = "0.0.0.0"
        listen_was_empty = True
    else:
        effective_listen = str(listen)
        listen_was_empty = False

    return {
        "source": source_name,
        "tag": ib.get("tag", ""),
        "remark": ib.get("remark", ""),
        "port": int(ib.get("port", 0)),
        "listen_raw": listen if listen is not None else "",
        "effective_listen": effective_listen,
        "listen_was_empty": listen_was_empty,
        "v6only": bool(sockopt.get("V6Only", sockopt.get("v6only", False))),
        "hop_ports": str(hop_ports).strip(),
        "hop_interval": str(hop_interval).strip(),
        "has_legacy_udphop": bool(legacy_hop.get("ports")),
        "has_new_udphop_on_inbound": bool(udp_hop_new),
        "salamander": salamander,
        "quic_params": qp,
        "sni": sni,
        "passwords": passwords,
        "raw_finalmask": fm,
    }


def check_dns_records(domain):
    if not domain:
        return {"v4": [], "v6": []}
    res = {"v4": [], "v6": []}
    rc, out, _ = run_cmd(["getent", "ahosts", domain])
    if rc == 0 and out:
        for line in out.splitlines():
            ip = line.split()[0]
            try:
                obj = ipaddress.ip_address(ip)
                if obj.version == 4 and ip not in res["v4"]:
                    res["v4"].append(ip)
                elif obj.version == 6 and ip not in res["v6"]:
                    res["v6"].append(ip)
            except Exception:
                pass
    return res


def inspect_iptables_state(net_state):
    res = {
        "v4_chain_exists": False,
        "v4_prerouting_hooked": False,
        "v4_rules": [],
        "v4_conflicts": [],
        "v4_input_drops": [],
        "v6_chain_exists": False,
        "v6_prerouting_hooked": False,
        "v6_rules": [],
        "v6_conflicts": [],
        "v6_input_drops": [],
        "service_enabled": False,
        "service_active": False,
        "conf_exists": os.path.isfile(CONF_FILE),
        "conf_data": None,
    }

    if os.path.isfile(CONF_FILE):
        try:
            with open(CONF_FILE, "r", encoding="utf-8") as f:
                res["conf_data"] = json.load(f)
        except Exception:
            pass

    rc, out, _ = run_cmd(["systemctl", "is-enabled", SERVICE_NAME])
    res["service_enabled"] = (rc == 0 and out == "enabled")
    rc, out, _ = run_cmd(["systemctl", "is-active", SERVICE_NAME])
    res["service_active"] = (rc == 0 and out == "active")

    if net_state["iptables_bin"] and is_root():
        rc, out, _ = run_cmd([net_state["iptables_bin"], "-t", "nat", "-S", CHAIN_NAME])
        if rc == 0:
            res["v4_chain_exists"] = True
            res["v4_rules"] = out.splitlines()
        rc, out, _ = run_cmd([net_state["iptables_bin"], "-t", "nat", "-S", "PREROUTING"])
        if rc == 0:
            for line in out.splitlines():
                if f"-j {CHAIN_NAME}" in line:
                    res["v4_prerouting_hooked"] = True
                elif ("REDIRECT" in line or "DNAT" in line) and "-p udp" in line:
                    res["v4_conflicts"].append(line)
        rc, out, _ = run_cmd([net_state["iptables_bin"], "-S", "INPUT"])
        if rc == 0:
            for line in out.splitlines():
                if ("-j DROP" in line or "-j REJECT" in line) and ("udp" in line or "-P INPUT DROP" in line or "-P INPUT REJECT" in line or not " -p " in line):
                    res["v4_input_drops"].append(line)

    if net_state["ip6tables_bin"] and net_state["ip6tables_nat_ok"] and is_root():
        rc, out, _ = run_cmd([net_state["ip6tables_bin"], "-t", "nat", "-S", CHAIN_NAME])
        if rc == 0:
            res["v6_chain_exists"] = True
            res["v6_rules"] = out.splitlines()
        rc, out, _ = run_cmd([net_state["ip6tables_bin"], "-t", "nat", "-S", "PREROUTING"])
        if rc == 0:
            for line in out.splitlines():
                if f"-j {CHAIN_NAME}" in line:
                    res["v6_prerouting_hooked"] = True
                elif ("REDIRECT" in line or "DNAT" in line) and "-p udp" in line:
                    res["v6_conflicts"].append(line)
        rc, out, _ = run_cmd([net_state["ip6tables_bin"], "-S", "INPUT"])
        if rc == 0:
            for line in out.splitlines():
                if ("-j DROP" in line or "-j REJECT" in line) and ("udp" in line or "-P INPUT DROP" in line or "-P INPUT REJECT" in line or not " -p " in line):
                    res["v6_input_drops"].append(line)

    return res


def build_client_snippets(ib):
    hop_ports = ib["hop_ports"] or "47000-50000"
    hop_int = ib["hop_interval"] or "15-20"
    # Normalize minimum interval >= 5 for Xray
    try:
        first_num = int(str(hop_int).split("-")[0].strip())
    except Exception:
        first_num = 15
    safe_xray_int = hop_int if first_num >= 5 else "15-20"
    sing_int = f"{max(first_num, 5)}s"

    # Build complete client FinalMask preserving salamander & quicParams; udphop MUST be last!
    qp_clean = {k: v for k, v in (ib["quic_params"] or {}).items() if k != "udpHop"}
    udp_list = []
    if ib["salamander"]:
        sal_entry = {"type": "salamander", "settings": dict(ib["salamander"])}
        udp_list.append(sal_entry)
    udp_list.append({
        "type": "udphop",
        "settings": {
            "remotePorts": hop_ports,
            "interval": safe_xray_int,
            "mode": "intervalLocal,intervalRemote",
        },
    })
    xray_finalmask = {}
    if qp_clean:
        xray_finalmask["quicParams"] = qp_clean
    xray_finalmask["udp"] = udp_list

    ranges = parse_port_spec(hop_ports) if hop_ports else [(47000, 50000)]
    sb_outbound = {
        "type": "hysteria2",
        "tag": "hy2-out",
        "server": ib["sni"] or "YOUR_VPS_DOMAIN_OR_IP",
        "server_ports": format_ranges_colon(ranges),
        "hop_interval": sing_int,
        "password": ib["passwords"][0] if ib["passwords"] else "YOUR_PASSWORD",
        "tls": {
            "enabled": True,
            "server_name": ib["sni"] or "YOUR_VPS_DOMAIN_OR_IP",
        },
    }
    if ib["salamander"] and ib["salamander"].get("password"):
        sb_outbound["obfs"] = {
            "type": "salamander",
            "password": ib["salamander"]["password"],
        }

    return {
        "xray_finalmask_client_only": xray_finalmask,
        "singbox_outbound": sb_outbound,
    }


def run_audit():
    net = detect_network_state()
    xui = detect_xui_paths()
    ss_udp = parse_ss_udp_sockets()
    ipt = inspect_iptables_state(net)

    cfg_hy2 = []
    cfg_err = None
    if os.path.isfile(xui["config_path"]):
        try:
            cfg = load_json_lenient(xui["config_path"])
            for ib in cfg.get("inbounds", []):
                if (ib.get("protocol") or "").lower() in ("hysteria", "hysteria2"):
                    cfg_hy2.append(analyze_hy2_inbound(ib, "config.json"))
        except Exception as e:
            cfg_err = str(e)
    else:
        cfg_err = f"未找到配置文件: {xui['config_path']}"

    db_hy2 = []
    db_err = None
    if xui["db_type"] == "postgres":
        db_err = "检测到 XUI_DB_TYPE=postgres，跳过本地 SQLite 读取"
    else:
        rows, err = read_sqlite_inbounds_ro(xui["db_path"])
        if err:
            db_err = err
        elif rows:
            for r in rows:
                if (r.get("protocol") or "").lower() in ("hysteria", "hysteria2") and r.get("enable"):
                    db_hy2.append(analyze_hy2_inbound(r, "x-ui.db"))

    findings = []
    blockers = []

    if xui["docker_isolated"]:
        blockers.append("检测到 Xray 运行在独立容器网络命名空间中，宿主机 PREROUTING REDIRECT 无法直接作用于容器内部网络！")

    if not cfg_hy2:
        findings.append("未在运行配置中发现 Hysteria2 入站")

    for ib in cfg_hy2:
        port = ib["port"]
        # Socket verification
        matched_socks = [s for s in ss_udp if s["port"] == port]
        dns = check_dns_records(ib["sni"])
        ib["dns"] = dns
        ib["matched_sockets"] = matched_socks

        # Check listen vs dual-stack: NEVER treat ss -4 '*:port' as IPv6!
        v4_ok = any(
            s["query_fam"] == "4"
            or (s["query_fam"] == "6" and s["v6only"] == 0)
            or s["host"] == "0.0.0.0"
            for s in matched_socks
        )
        v6_ok = any(
            s["query_fam"] == "6" and (s["host"] in ("*", "::") or ":" in s["host"])
            for s in matched_socks
        )
        if not matched_socks and ib["effective_listen"] in ("0.0.0.0",):
            v6_ok = False
        ib["listen_v4_actual"] = v4_ok
        ib["listen_v6_actual"] = v6_ok

        if (net["has_global_v6"] or dns["v6"]) and not v6_ok:
            blockers.append(
                f"[BLOCKER] 入站端口 {port} 当前仅监听 IPv4 ({ib['effective_listen']})，但 VPS 具备公网 IPv6"
                + (f" 且域名 {ib['sni']} 存在 AAAA 记录 ({','.join(dns['v6'])})" if dns["v6"] else "")
                + "！若此时启用 IPv6 REDIRECT，手机 4G/5G 优先走 IPv6 连入会被内核直接回 ICMPv6 Port Unreachable 断网！"
                + "\n    -> 修复方法: 请在 3x-ui 面板编辑该入站，将 Listen IP 显式填写为 ::（不要留空，3x-ui 留空会强转 0.0.0.0；也不要手改 config.json，重启会被覆盖；且勿勾选 V6Only）。"
            )

        if ib["has_new_udphop_on_inbound"]:
            blockers.append(f"[BLOCKER] 检测到入站 {port} 的 finalmask.udp 中包含 'udphop'，Xray 26.9.9+ 服务端会报 'udphop: client only' 启动失败！")

        if ib["salamander"] is not None:
            pw = ib["salamander"].get("password", "")
            if len(pw.encode("utf-8")) < 4:
                findings.append(f"入站 {port} Salamander 混淆密码长度不足 4 字节，可能导致异常")

        if ib["hop_ports"]:
            try:
                hr = parse_port_spec(ib["hop_ports"])
                if port_in_ranges(port, hr):
                    findings.append(f"警告: 主端口 {port} 落在跳跃范围 {ib['hop_ports']} 内部")
                # Check overlapping UDP listeners on host
                for s in ss_udp:
                    if s["port"] != port and port_in_ranges(s["port"], hr):
                        findings.append(f"警告: 本机已有其他 UDP 服务 {s['proc']} 监听在跳跃端口 {s['port']}，配置 REDIRECT 后将被抢占拦截！")
            except Exception as e:
                findings.append(f"跳跃端口范围解析失败: {e}")

        # DB vs config.json consistency
        for dib in db_hy2:
            if dib["port"] == port:
                if dib["effective_listen"] != ib["effective_listen"] or dib["hop_ports"] != ib["hop_ports"]:
                    findings.append(f"入站 {port} 在 x-ui.db 与 config.json 之间存在差异（可能修改面板后未重启 Xray，或手动改过 config.json）")

        ib["client_snippets"] = build_client_snippets(ib)

    # Check IPv6 redirect without IPv6 listener
    if ipt["v6_prerouting_hooked"] and cfg_hy2 and not any(ib.get("listen_v6_actual") for ib in cfg_hy2):
        blockers.append("[BLOCKER] 检测到当前系统已挂接 IPv6 PREROUTING NAT 转发，但 Xray 根本未监听 IPv6，这会造成 IPv6 流量黑洞！")

    return {
        "network": net,
        "xui": xui,
        "config_error": cfg_err,
        "db_error": db_err,
        "hy2_inbounds": cfg_hy2,
        "db_hy2_inbounds": db_hy2,
        "iptables": ipt,
        "blockers": blockers,
        "findings": findings,
    }


def print_audit_report(report):
    net = report["network"]
    xui = report["xui"]
    ipt = report["iptables"]

    print("\n" + "=" * 72)
    print("  3x-ui Hysteria2 端口跳跃体检报告")
    print("=" * 72)
    print(f"Xray 运行状态 : {'运行中' if xui['xray_running'] else '未运行'} | 版本: {xui['xray_version'] or '未知'}")
    print(f"配置路径      : {xui['config_path']}")
    print(f"数据库路径    : {xui['db_path']} ({xui['db_type']})")
    print(f"WAN 网卡      : v4={net['wan_v4_iface'] or '无'} | v6={net['wan_v6_iface'] or '无'} | 容器环境={'是' if net['in_container'] else '否'}")
    print(f"本机 IPv4     : {', '.join(a['ip'] + ('(主)' if a['primary'] else '(副)') for a in net['v4_addrs']) or '无'}")
    print(f"全局 IPv6     : {', '.join(a['ip'] for a in net['v6_addrs']) or '无'} (默认路由={'有' if net['v6_default_route'] else '无'})")
    print(f"防火墙后端    : {net['iptables_ver'] or '未检测到 iptables'} | ip6table_nat={'可用' if net['ip6tables_nat_ok'] else '不可用/未检测'}")
    print(f"持久化服务    : {SERVICE_NAME} (enabled={ipt['service_enabled']}, active={ipt['service_active']})")

    if report["config_error"]:
        print(f"\n[!] 配置读取异常: {report['config_error']}")
    if report["db_error"]:
        print(f"[!] 数据库说明  : {report['db_error']}")

    for idx, ib in enumerate(report["hy2_inbounds"], 1):
        print(f"\n--- Hy2 入站 #{idx}: 端口 {ib['port']} (tag={ib['tag']}) ---")
        print(f"  面板配置 Listen : {ib['effective_listen']} {'(面板留空，3x-ui 自动转为 0.0.0.0)' if ib['listen_was_empty'] else ''}")
        print(f"  实际 UDP 监听   : v4={'是' if ib['listen_v4_actual'] else '否'} | v6={'是' if ib['listen_v6_actual'] else '否'} | sockets={[s['local'] for s in ib['matched_sockets']]}")
        print(f"  UDP Hop 配置    : ports={ib['hop_ports'] or '未设置'} | interval={ib['hop_interval'] or '未设置'}")
        print(f"  Salamander 混淆 : {'开启' if ib['salamander'] else '未开启'} | SNI={ib['sni'] or '未设置'} | DNS(v4={ib['dns']['v4']}, v6={ib['dns']['v6']})")

    print("\n--- NAT PREROUTING 状态 ---")
    print(f"  IPv4 自定义链 {CHAIN_NAME}: 存在={ipt['v4_chain_exists']}, 已挂载={ipt['v4_prerouting_hooked']}")
    for r in ipt["v4_rules"]:
        print(f"    {r}")
    print(f"  IPv6 自定义链 {CHAIN_NAME}: 存在={ipt['v6_chain_exists']}, 已挂载={ipt['v6_prerouting_hooked']}")
    for r in ipt["v6_rules"]:
        print(f"    {r}")
    if ipt["v4_conflicts"] or ipt["v6_conflicts"]:
        print("  [!] 发现 PREROUTING 中存在其他 UDP 转发规则:")
        for c in ipt["v4_conflicts"] + ipt["v6_conflicts"]:
            print(f"      {c}")
    if ipt["v4_input_drops"] or ipt["v6_input_drops"]:
        print("  [!] 检测到 INPUT 链存在 DROP/REJECT 规则，请确认未误拦主端口或已放行:")
        for d in ipt["v4_input_drops"][:4] + ipt["v6_input_drops"][:4]:
            print(f"      {d}")

    if report["blockers"]:
        print("\n" + "!" * 72)
        for b in report["blockers"]:
            print(f"\033[31m{b}\033[0m")
        print("!" * 72)

    if report["findings"]:
        print("\n[提醒事项]")
        for f in report["findings"]:
            print(f"  - {f}")

    for idx, ib in enumerate(report["hy2_inbounds"], 1):
        sn = ib["client_snippets"]
        print(f"\n--- 客户端适配指引 (对应入站 #{idx} 端口 {ib['port']}) ---")
        print("  * PC 端 (v2rayN): 默认 Hysteria2 走 sing-box 内核；由于 3x-ui 通用链接不带跳跃间隔，")
        print(f"    更新订阅后需在节点中手动补填间隔（如 {ib['hop_interval'] or '15-20'}）并复制到独立分组保存；若切 Xray 内核请升级含 PR #10550 版本。")
        print("  * 手机端 (v2rayNG): 2.3.8–2.3.15 存在 Issue #6224 导致填了间隔仍锁死主端口，建议升级 >= 2.4.0；")
        print("    若使用 NekoBox / sing-box (SFA)，端口范围必须用冒号分隔且间隔带单位 's'。")
        print("\n  \033[31m[警告] 下方 FinalMask JSON 仅限填入【客户端 Outbound】，严禁填入 3x-ui 服务端 Inbound（否则报 udphop: client only）！\033[0m")
        print("  [Xray >= 26.9.9 / v2rayNG 客户端完整 FinalMask JSON（已保留原有混淆与参数，udphop 置末位）]:")
        print(json.dumps(sn["xray_finalmask_client_only"], ensure_ascii=False, indent=2))
        print("\n  [sing-box / SFA 客户端 Outbound 参考片段]:")
        print(json.dumps(sn["singbox_outbound"], ensure_ascii=False, indent=2))
    print("=" * 72 + "\n")


# ------------------------------------------------------------------------------
# Module 2: Idempotent NAT Configuration & Persistence
# ------------------------------------------------------------------------------

CTL_SCRIPT_CONTENT = r'''#!/usr/bin/env bash
set -euo pipefail
CONF_FILE="/etc/hy2-port-hop.conf"
CHAIN_NAME="HY2_PORT_HOP"

if [[ ! -f "$CONF_FILE" ]]; then
    echo "Config not found: $CONF_FILE" >&2
    exit 1
fi

apply_family() {
    local bin="$1"
    local iface="$2"
    local target_mode="$3"
    local dest_ip="$4"
    local main_port="$5"
    local ranges_csv="$6"
    local use_addrtype="$7"

    "$bin" -t nat -N "$CHAIN_NAME" 2>/dev/null || true
    "$bin" -t nat -F "$CHAIN_NAME"

    local match_args=()
    if [[ "$use_addrtype" == "1" ]]; then
        match_args=(-m addrtype --dst-type LOCAL)
    elif [[ -n "$iface" ]]; then
        match_args=(-i "$iface")
    fi

    local action_args=()
    if [[ "$target_mode" == "DNAT" && -n "$dest_ip" ]]; then
        if [[ "$bin" == *"ip6tables"* ]]; then
            action_args=(-j DNAT --to-destination "[${dest_ip}]:${main_port}")
        else
            action_args=(-j DNAT --to-destination "${dest_ip}:${main_port}")
        fi
    else
        action_args=(-j REDIRECT --to-ports "$main_port")
    fi

    IFS=',' read -ra RLIST <<< "$ranges_csv"
    for r in "${RLIST[@]}"; do
        [[ -z "$r" ]] && continue
        "$bin" -t nat -A "$CHAIN_NAME" "${match_args[@]}" -p udp --dport "$r" \
            -m comment --comment "hy2-port-hop" "${action_args[@]}"
    done

    if ! "$bin" -t nat -C PREROUTING -j "$CHAIN_NAME" 2>/dev/null; then
        "$bin" -t nat -I PREROUTING 1 -j "$CHAIN_NAME"
    fi
}

clear_family() {
    local bin="$1"
    while "$bin" -t nat -C PREROUTING -j "$CHAIN_NAME" 2>/dev/null; do
        "$bin" -t nat -D PREROUTING -j "$CHAIN_NAME"
    done
    "$bin" -t nat -F "$CHAIN_NAME" 2>/dev/null || true
    "$bin" -t nat -X "$CHAIN_NAME" 2>/dev/null || true
}

ACTION="${1:-start}"
eval "$(python3 - <<'PY'
import json, shlex
with open("/etc/hy2-port-hop.conf", "r", encoding="utf-8") as f:
    c = json.load(f)
for k in ("enable_v4", "enable_v6", "iface_v4", "iface_v6", "mode_v4", "mode_v6", "dest_ip_v4", "dest_ip_v6", "main_port", "ranges_colon_csv", "use_addrtype_v4", "use_addrtype_v6"):
    v = c.get(k, "")
    if isinstance(v, bool):
        v = "1" if v else "0"
    print(f"CFG_{k.upper()}={shlex.quote(str(v))}")
PY
)"

case "$ACTION" in
    start)
        if [[ "$CFG_ENABLE_V4" == "1" ]] && command -v iptables >/dev/null 2>&1; then
            apply_family "iptables" "$CFG_IFACE_V4" "$CFG_MODE_V4" "$CFG_DEST_IP_V4" "$CFG_MAIN_PORT" "$CFG_RANGES_COLON_CSV" "$CFG_USE_ADDRTYPE_V4"
        else
            command -v iptables >/dev/null 2>&1 && clear_family "iptables"
        fi
        if [[ "$CFG_ENABLE_V6" == "1" ]] && command -v ip6tables >/dev/null 2>&1; then
            apply_family "ip6tables" "$CFG_IFACE_V6" "$CFG_MODE_V6" "$CFG_DEST_IP_V6" "$CFG_MAIN_PORT" "$CFG_RANGES_COLON_CSV" "$CFG_USE_ADDRTYPE_V6"
        else
            command -v ip6tables >/dev/null 2>&1 && clear_family "ip6tables"
        fi
        ;;
    stop)
        command -v iptables >/dev/null 2>&1 && clear_family "iptables"
        command -v ip6tables >/dev/null 2>&1 && clear_family "ip6tables"
        ;;
    *)
        echo "Usage: $0 {start|stop}" >&2
        exit 1
        ;;
esac
'''

SERVICE_CONTENT = f"""[Unit]
Description=Hysteria2 UDP Port Hopping NAT Redirect
After=network-online.target netfilter-persistent.service ufw.service docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={CTL_BIN} start
ExecStop={CTL_BIN} stop

[Install]
WantedBy=multi-user.target
"""


def build_nat_plan(report, main_port, hop_ports_str, force_v6=None):
    net = report["network"]
    ranges = parse_port_spec(hop_ports_str)
    if not ranges:
        raise ValueError("跳跃端口范围不能为空")
    ranges_colon_csv = ",".join(f"{a}:{b}" if a != b else str(a) for a, b in ranges)

    target_ib = None
    for ib in report["hy2_inbounds"]:
        if ib["port"] == main_port:
            target_ib = ib
            break

    enable_v4 = bool(net["iptables_bin"] and (net["has_public_v4"] or net["wan_v4_iface"]))
    v6_listener_ok = target_ib["listen_v6_actual"] if target_ib else False
    if force_v6 is not None:
        enable_v6 = bool(force_v6 and net["ip6tables_bin"] and net["ip6tables_nat_ok"])
    else:
        # Guard against IPv6 blackhole if Xray is only listening on 0.0.0.0
        enable_v6 = bool(net["has_global_v6"] and net["ip6tables_bin"] and net["ip6tables_nat_ok"] and v6_listener_ok)

    # Determine REDIRECT vs DNAT when bound to a non-primary specific IP
    mode_v4 = "REDIRECT"
    dest_ip_v4 = ""
    mode_v6 = "REDIRECT"
    dest_ip_v6 = ""
    if target_ib and target_ib["effective_listen"] not in ("0.0.0.0", "::", "*"):
        lip = target_ib["effective_listen"]
        try:
            ip_obj = ipaddress.ip_address(lip)
            if ip_obj.version == 4:
                is_primary = any(a["ip"] == lip and a["primary"] for a in net["v4_addrs"])
                if not is_primary:
                    mode_v4 = "DNAT"
                    dest_ip_v4 = lip
            elif ip_obj.version == 6:
                is_primary = any(a["ip"] == lip and a["primary"] for a in net["v6_addrs"])
                if not is_primary:
                    mode_v6 = "DNAT"
                    dest_ip_v6 = lip
        except Exception:
            pass

    plan = {
        "enable_v4": enable_v4,
        "enable_v6": enable_v6,
        "v6_skipped_due_to_listener": bool(net["has_global_v6"] and not v6_listener_ok and force_v6 is None),
        "iface_v4": net["wan_v4_iface"] or "",
        "iface_v6": net["wan_v6_iface"] or "",
        "mode_v4": mode_v4,
        "mode_v6": mode_v6,
        "dest_ip_v4": dest_ip_v4,
        "dest_ip_v6": dest_ip_v6,
        "main_port": int(main_port),
        "ranges_dash": format_ranges_dash(ranges),
        "ranges_colon_csv": ranges_colon_csv,
        "use_addrtype_v4": net["xt_addrtype_v4_ok"],
        "use_addrtype_v6": net["xt_addrtype_v6_ok"],
    }
    return plan


def apply_nat_plan(plan, dry_run=False):
    print("\n--- NAT 转发执行计划 ---")
    print(f"  目标主端口 : {plan['main_port']}/udp")
    print(f"  跳跃端口段 : {plan['ranges_dash']}")
    print(f"  IPv4 规则  : {'启用' if plan['enable_v4'] else '跳过'} (mode={plan['mode_v4']}, match={'addrtype LOCAL' if plan['use_addrtype_v4'] else 'iface ' + plan['iface_v4']})")
    print(f"  IPv6 规则  : {'启用' if plan['enable_v6'] else '跳过'} (mode={plan['mode_v6']}, match={'addrtype LOCAL' if plan['use_addrtype_v6'] else 'iface ' + plan['iface_v6']})")
    if plan["v6_skipped_due_to_listener"]:
        print("  \033[33m[安全跳过 IPv6]\033[0m 检测到 Xray 未监听 IPv6，已自动跳过写入 ip6tables 规则以防断网；请先在 3x-ui 面板把 Listen IP 改为 :: 后重跑。")

    if dry_run:
        print("\n[dry-run] 仅预览以上计划，未改动系统文件或防火墙。")
        return True

    if not is_root():
        print("[ERROR] 写入防火墙规则与 systemd 服务需要 root 权限！", file=sys.stderr)
        return False

    with open(CONF_FILE, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    os.chmod(CONF_FILE, 0o600)

    with open(CTL_BIN, "w", encoding="utf-8") as f:
        f.write(CTL_SCRIPT_CONTENT)
    os.chmod(CTL_BIN, 0o700)

    with open(SERVICE_FILE, "w", encoding="utf-8") as f:
        f.write(SERVICE_CONTENT)
    os.chmod(SERVICE_FILE, 0o644)

    run_cmd(["systemctl", "daemon-reload"])
    rc, out, err = run_cmd(["systemctl", "enable", "--now", SERVICE_NAME])
    if rc != 0:
        print(f"[ERROR] 启动 {SERVICE_NAME} 失败: {err or out}", file=sys.stderr)
        return False
    # Force restart so updated conf takes effect immediately if already active
    rc2, out2, err2 = run_cmd(["systemctl", "restart", SERVICE_NAME])
    if rc2 != 0:
        print(f"[ERROR] 重启 {SERVICE_NAME} 失败: {err2 or out2}", file=sys.stderr)
        return False

    print(f"\n[OK] 转发规则已通过 {SERVICE_NAME} 生效并持久化！")
    print("[重要提醒]")
    print("  1. 请确保云厂商安全组（如 AWS/阿里云/GCP）已分别放行 IPv4 与 IPv6 的 UDP " + plan["ranges_dash"] + "。")
    print("  2. 若你在配置前刚刚测试过跳跃端口，内核 nf_conntrack 可能保留旧连接粘滞状态（默认约 30~120 秒），请断开重连客户端（更换本地源端口）后再测。")
    return True


def uninstall_nat(dry_run=False):
    if dry_run:
        print(f"[dry-run] 将停用并删除 {SERVICE_FILE}, {CTL_BIN}, {CONF_FILE} 并清理链 {CHAIN_NAME}。")
        return True
    if not is_root():
        print("[ERROR] 卸载需要 root 权限！", file=sys.stderr)
        return False
    run_cmd(["systemctl", "disable", "--now", SERVICE_NAME])
    if os.path.isfile(CTL_BIN):
        run_cmd([CTL_BIN, "stop"])
    for p in (SERVICE_FILE, CTL_BIN, CONF_FILE):
        if os.path.exists(p):
            os.remove(p)
    run_cmd(["systemctl", "daemon-reload"])
    print(f"[OK] 已完整清理 {CHAIN_NAME} 防火墙链及持久化服务。")
    return True


# ------------------------------------------------------------------------------
# Module 3: AF_PACKET (SOCK_DGRAM) + cBPF Bidirectional Real-Time Monitor
# ------------------------------------------------------------------------------

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


class TpacketStats(ctypes.Structure):
    _fields_ = [
        ("tp_packets", ctypes.c_uint),
        ("tp_drops", ctypes.c_uint),
    ]


def attach_l3_cbpf(sock):
    """Attach classic BPF on AF_PACKET SOCK_DGRAM (offset 0 = L3 IP header).
    Drops all TCP/non-UDP/non-ICMP traffic in kernel space so high-throughput
    TCP proxy traffic causes zero Python wakeups, while passing IPv4 UDP/ICMP
    and IPv6 UDP/Fragment/Routing/HopOpt/DestOpt/ICMPv6 for exact L4 parsing.
    """
    BPF_LD = 0x00
    BPF_B = 0x10
    BPF_ABS = 0x20
    BPF_JMP = 0x05
    BPF_JEQ = 0x10
    BPF_K = 0x00
    BPF_ALU = 0x04
    BPF_AND = 0x50
    BPF_RET = 0x06

    insns = [
        # 0: A = byte[0] & 0xF0 (IP version)
        (BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
        (BPF_ALU | BPF_AND | BPF_K, 0, 0, 0xF0),
        # 2: if A == 0x40 goto 4 (IPv4), else check IPv6 at 3
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x40),
        # 3: if A == 0x60 goto 8 (IPv6), else drop (16)
        (BPF_JMP | BPF_JEQ | BPF_K, 4, 12, 0x60),
        # IPv4: 4: A = byte[9] (protocol)
        (BPF_LD | BPF_B | BPF_ABS, 0, 0, 9),
        # 5: if UDP (17) -> accept (15)
        (BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 17),
        # 6: if ICMP (1) -> accept (15)
        (BPF_JMP | BPF_JEQ | BPF_K, 8, 9, 1),
        # 7: pad/drop
        (BPF_RET | BPF_K, 0, 0, 0),
        # IPv6: 8: A = byte[6] (next header)
        (BPF_LD | BPF_B | BPF_ABS, 0, 0, 6),
        # 9..14: accept UDP(17), Fragment(44), ICMPv6(58), Hop(0), Routing(43), Dest(60)
        (BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 17),
        (BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 44),
        (BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 58),
        (BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 0),
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 43),
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 60),
        # 15: ACCEPT
        (BPF_RET | BPF_K, 0, 0, 0x00040000),
        # 16: DROP
        (BPF_RET | BPF_K, 0, 0, 0),
    ]
    arr = (SockFilter * len(insns))(*(SockFilter(c, jt, jf, k) for c, jt, jf, k in insns))
    prog = SockFprog(len(insns), arr)
    SOL_SOCKET = 1
    SO_ATTACH_FILTER = 26
    sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, bytes(prog))


def parse_l3_packet(data):
    """Parse L3 IPv4/IPv6 packet from AF_PACKET SOCK_DGRAM. Returns dict or None."""
    if len(data) < 20:
        return None
    ver = data[0] >> 4
    if ver == 4:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        frag_off = struct.unpack("!H", data[6:8])[0] & 0x1FFF
        proto = data[9]
        src_ip = socket.inet_ntop(socket.AF_INET, data[12:16])
        dst_ip = socket.inet_ntop(socket.AF_INET, data[16:20])
        if frag_off != 0:
            return None
        payload = data[ihl:]
        if proto == 17 and len(payload) >= 8:
            sport, dport = struct.unpack("!HH", payload[:4])
            return {"fam": 4, "proto": "udp", "src": src_ip, "dst": dst_ip, "sport": sport, "dport": dport}
        if proto == 1 and len(payload) >= 8:
            icmp_type, icmp_code = payload[0], payload[1]
            if icmp_type == 3 and icmp_code == 3 and len(payload) >= 28:
                inner = payload[8:]
                if len(inner) >= 20 and (inner[0] >> 4) == 4:
                    i_ihl = (inner[0] & 0x0F) * 4
                    if len(inner) >= i_ihl + 4 and inner[9] == 17:
                        i_dst = socket.inet_ntop(socket.AF_INET, inner[16:20])
                        i_sport, i_dport = struct.unpack("!HH", inner[i_ihl:i_ihl + 4])
                        return {
                            "fam": 4, "proto": "icmp_unreach", "src": src_ip, "dst": dst_ip,
                            "inner_dst": i_dst, "inner_sport": i_sport, "inner_dport": i_dport,
                        }
        return None

    if ver == 6 and len(data) >= 40:
        nh = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        offset = 40
        # Walk IPv6 extension headers
        for _ in range(6):
            if nh in (17, 58):
                break
            if nh == 44:  # Fragment header (8 bytes)
                if len(data) < offset + 8:
                    return None
                next_nh = data[offset]
                frag_field = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                frag_off = (frag_field >> 3) & 0x1FFF
                if frag_off != 0:
                    return None
                nh = next_nh
                offset += 8
            elif nh in (0, 43, 60):
                if len(data) < offset + 8:
                    return None
                next_nh = data[offset]
                hdr_len = (data[offset + 1] + 1) * 8
                nh = next_nh
                offset += hdr_len
            else:
                return None

        payload = data[offset:]
        if nh == 17 and len(payload) >= 8:
            sport, dport = struct.unpack("!HH", payload[:4])
            return {"fam": 6, "proto": "udp", "src": src_ip, "dst": dst_ip, "sport": sport, "dport": dport}
        if nh == 58 and len(payload) >= 8:
            icmp_type, icmp_code = payload[0], payload[1]
            if icmp_type == 1 and icmp_code == 4 and len(payload) >= 48:
                inner = payload[8:]
                if len(inner) >= 48 and (inner[0] >> 4) == 6 and inner[6] == 17:
                    i_dst = socket.inet_ntop(socket.AF_INET6, inner[24:40])
                    i_sport, i_dport = struct.unpack("!HH", inner[40:44])
                    return {
                        "fam": 6, "proto": "icmp_unreach", "src": src_ip, "dst": dst_ip,
                        "inner_dst": i_dst, "inner_sport": i_sport, "inner_dport": i_dport,
                    }
    return None


class HopMonitor:
    def __init__(self, main_port, hop_ranges, net_state):
        self.main_port = int(main_port)
        self.hop_ranges = hop_ranges
        self.net_state = net_state
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.clients = {}  # (client_ip, fam) -> stats
        self.events = deque(maxlen=60)
        self.nat_counters = {"v4_pkts": 0, "v4_bytes": 0, "v6_pkts": 0, "v6_bytes": 0}
        self.kernel_drops = 0
        self.kernel_packets = 0
        self.started_at = time.time()
        self.error = None

    def _get_client(self, ip, fam):
        key = (ip, fam)
        if key not in self.clients:
            self.clients[key] = {
                "ip": ip,
                "family": f"IPv{fam}",
                "main_in_pkts": 0,
                "main_out_pkts": 0,
                "hop_in_pkts": 0,
                "hop_out_pkts": 0,
                "hop_ports_seen": [],
                "hop_ports_bidir": [],
                "client_sports_seen": [],
                "icmp_unreach_hits": 0,
                "pending_hops": set(),  # (client_sport, hop_port)
                "last_seen": 0.0,
            }
        return self.clients[key]

    def _evaluate_status(self, c):
        if c["icmp_unreach_hits"] > 0 and c["hop_out_pkts"] == 0 and c["main_out_pkts"] == 0:
            return "ICMP_UNREACHABLE (疑似服务未监听该协议族或端口不可达)"
        if len(c["hop_ports_bidir"]) >= 2:
            if len(c["client_sports_seen"]) <= 1 and len(c["hop_ports_bidir"]) >= 2:
                return "BIDIR_OK_WARN (已双向跳跃，但客户端源端口未同步变化，注意 conntrack 碰撞风险)"
            return "BIDIR_OK (端口跳跃双向真实生效)"
        if len(c["hop_ports_bidir"]) == 1:
            return "HOP_SINGLE_PORT (已通过跳跃端口双向通信，等待下一周期观察是否轮换)"
        if c["hop_in_pkts"] > 0 and c["hop_out_pkts"] == 0:
            return "INBOUND_ONLY (仅收到入站包无回包：可能是公网扫描/密码错误/后端未响应)"
        if c["main_in_pkts"] > 0 or c["main_out_pkts"] > 0:
            return f"STUCK_MAIN_PORT (流量全部停留在主端口 {self.main_port}，未触发端口跳跃)"
        return "IDLE"

    def _poll_nat_loop(self):
        while not self.stop_event.is_set():
            v4_p, v4_b = 0, 0
            v6_p, v6_b = 0, 0
            if self.net_state["iptables_bin"]:
                rc, out, _ = run_cmd([self.net_state["iptables_bin"], "-t", "nat", "-L", CHAIN_NAME, "-n", "-v", "-x"])
                if rc == 0:
                    for line in out.splitlines()[2:]:
                        cols = line.split()
                        if len(cols) >= 2 and cols[0].isdigit() and cols[1].isdigit():
                            v4_p += int(cols[0])
                            v4_b += int(cols[1])
            if self.net_state["ip6tables_bin"] and self.net_state["ip6tables_nat_ok"]:
                rc, out, _ = run_cmd([self.net_state["ip6tables_bin"], "-t", "nat", "-L", CHAIN_NAME, "-n", "-v", "-x"])
                if rc == 0:
                    for line in out.splitlines()[2:]:
                        cols = line.split()
                        if len(cols) >= 2 and cols[0].isdigit() and cols[1].isdigit():
                            v6_p += int(cols[0])
                            v6_b += int(cols[1])
            with self.lock:
                self.nat_counters = {"v4_pkts": v4_p, "v4_bytes": v4_b, "v6_pkts": v6_p, "v6_bytes": v6_b}
            self.stop_event.wait(1.0)

    def _packet_loop(self):
        PACKET_OUTGOING = 4
        PACKET_STATISTICS = 6
        SOL_PACKET = 263
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            attach_l3_cbpf(sock)
            sock.settimeout(0.5)
        except Exception as e:
            self.error = f"AF_PACKET 初始化失败: {e}"
            return

        last_stat_check = time.time()
        try:
            while not self.stop_event.is_set():
                now = time.time()
                if now - last_stat_check >= 1.0:
                    try:
                        raw_stats = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, ctypes.sizeof(TpacketStats))
                        st = TpacketStats.from_buffer_copy(raw_stats)
                        with self.lock:
                            self.kernel_packets += st.tp_packets
                            self.kernel_drops += st.tp_drops
                    except Exception:
                        pass
                    last_stat_check = now

                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception:
                    continue

                ifname, _, pkttype, _, _ = addr
                if ifname == "lo":
                    continue

                pkt = parse_l3_packet(data)
                if not pkt:
                    continue

                if pkt["proto"] == "icmp_unreach":
                    idport = pkt["inner_dport"]
                    if idport != self.main_port and not port_in_ranges(idport, self.hop_ranges):
                        continue
                    with self.lock:
                        # Match client ip = pkt["dst"]
                        key = (pkt["dst"], pkt["fam"])
                        if key in self.clients:
                            c = self.clients[key]
                            c["icmp_unreach_hits"] += 1
                            c["last_seen"] = now
                            self.events.appendleft({
                                "ts": time.strftime("%H:%M:%S"),
                                "dir": "ICMP_ERR",
                                "ip": pkt["dst"],
                                "fam": f"IPv{pkt['fam']}",
                                "detail": f"Port Unreachable for dport {idport}",
                            })
                    continue

                # UDP packet
                sport, dport = pkt["sport"], pkt["dport"]
                is_out = (pkttype == PACKET_OUTGOING)

                if not is_out:
                    # Inbound: client(src:sport) -> vps(dst:dport)
                    in_hop = port_in_ranges(dport, self.hop_ranges)
                    in_main = (dport == self.main_port)
                    if not (in_hop or in_main):
                        continue
                    with self.lock:
                        c = self._get_client(pkt["src"], pkt["fam"])
                        c["last_seen"] = now
                        if in_main:
                            c["main_in_pkts"] += 1
                        else:
                            c["hop_in_pkts"] += 1
                            c["pending_hops"].add((sport, dport))
                            if dport not in c["hop_ports_seen"]:
                                c["hop_ports_seen"].append(dport)
                                if len(c["hop_ports_seen"]) > 30:
                                    c["hop_ports_seen"].pop(0)
                                self.events.appendleft({
                                    "ts": time.strftime("%H:%M:%S"),
                                    "dir": "HOP_IN",
                                    "ip": pkt["src"],
                                    "fam": f"IPv{pkt['fam']}",
                                    "detail": f":{sport} -> :{dport}",
                                })
                            if sport not in c["client_sports_seen"]:
                                c["client_sports_seen"].append(sport)
                                if len(c["client_sports_seen"]) > 20:
                                    c["client_sports_seen"].pop(0)
                else:
                    # Outbound: vps(src:sport) -> client(dst:dport)
                    out_hop = port_in_ranges(sport, self.hop_ranges)
                    out_main = (sport == self.main_port)
                    if not (out_hop or out_main):
                        continue
                    with self.lock:
                        c = self._get_client(pkt["dst"], pkt["fam"])
                        c["last_seen"] = now
                        if out_main:
                            c["main_out_pkts"] += 1
                        else:
                            c["hop_out_pkts"] += 1
                            if (dport, sport) in c["pending_hops"] and sport not in c["hop_ports_bidir"]:
                                c["hop_ports_bidir"].append(sport)
                                if len(c["hop_ports_bidir"]) > 30:
                                    c["hop_ports_bidir"].pop(0)
                                self.events.appendleft({
                                    "ts": time.strftime("%H:%M:%S"),
                                    "dir": "BIDIR_OK",
                                    "ip": pkt["dst"],
                                    "fam": f"IPv{pkt['fam']}",
                                    "detail": f"双向确认 :{sport} <-> :{dport}",
                                })
        finally:
            sock.close()

    def start(self):
        t1 = threading.Thread(target=self._packet_loop, daemon=True)
        t2 = threading.Thread(target=self._poll_nat_loop, daemon=True)
        t1.start()
        t2.start()

    def stop(self):
        self.stop_event.set()

    def snapshot(self):
        with self.lock:
            clist = []
            for c in sorted(self.clients.values(), key=lambda x: x["last_seen"], reverse=True):
                clist.append({
                    "ip": c["ip"],
                    "family": c["family"],
                    "main_in_pkts": c["main_in_pkts"],
                    "main_out_pkts": c["main_out_pkts"],
                    "hop_in_pkts": c["hop_in_pkts"],
                    "hop_out_pkts": c["hop_out_pkts"],
                    "hop_ports_seen": list(c["hop_ports_seen"]),
                    "hop_ports_bidir": list(c["hop_ports_bidir"]),
                    "client_sports_count": len(c["client_sports_seen"]),
                    "icmp_unreach_hits": c["icmp_unreach_hits"],
                    "status": self._evaluate_status(c),
                    "idle_sec": round(time.time() - c["last_seen"], 1),
                })
            return {
                "uptime_sec": round(time.time() - self.started_at, 1),
                "main_port": self.main_port,
                "hop_ranges": format_ranges_dash(self.hop_ranges),
                "nat_counters": dict(self.nat_counters),
                "kernel_packets": self.kernel_packets,
                "kernel_drops": self.kernel_drops,
                "error": self.error,
                "clients": clist,
                "events": list(self.events)[:25],
            }


# ------------------------------------------------------------------------------
# Temporary Web Dashboard (127.0.0.1 default; Bearer token session)
# ------------------------------------------------------------------------------

WEB_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hy2 端口跳跃实时验证</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 16px; }
  .wrap { max-width: 1000px; margin: 0 auto; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; margin-bottom: 14px; }
  h2 { margin: 0 0 10px; font-size: 18px; color: #38bdf8; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
  .metric { background: #0f172a; padding: 10px; border-radius: 8px; }
  .metric .k { font-size: 12px; color: #94a3b8; }
  .metric .v { font-size: 20px; font-weight: 700; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { border-bottom: 1px solid #334155; padding: 8px; text-align: left; word-break: break-all; }
  th { color: #94a3b8; }
  .ok { color: #4ade80; font-weight: 600; }
  .warn { color: #fbbf24; font-weight: 600; }
  .err { color: #f87171; font-weight: 600; }
  input, button { padding: 8px 12px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; }
  button { background: #0284c7; border-color: #0284c7; cursor: pointer; font-weight: 600; }
  .mono { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <div id="authBox" class="card">
    <h2>Hy2 端口跳跃实时监测看板</h2>
    <p style="font-size:13px;color:#94a3b8;">请输入终端展示的一次性访问口令以兑换会话密钥（不走 URL 参数或 Cookie）：</p>
    <input id="otpInput" type="password" placeholder="输入一次性口令" />
    <button onclick="doAuth()">验证进入</button>
    <span id="authMsg" class="err" style="margin-left:10px;"></span>
  </div>

  <div id="dash" style="display:none;">
    <div class="card">
      <h2>全局转发状态 <span id="meta" style="font-size:12px;color:#94a3b8;font-weight:400;"></span></h2>
      <div class="grid">
        <div class="metric"><div class="k">IPv4 NAT PREROUTING</div><div class="v" id="v4nat">-</div></div>
        <div class="metric"><div class="k">IPv6 NAT PREROUTING</div><div class="v" id="v6nat">-</div></div>
        <div class="metric"><div class="k">内核捕获 / 丢包</div><div class="v" id="kstats">-</div></div>
      </div>
    </div>

    <div class="card">
      <h2>客户端实时判定（按来源 IP 与协议族聚合）</h2>
      <table>
        <thead>
          <tr><th>来源 IP</th><th>协议</th><th>主端口包 (入/出)</th><th>跳跃包 (入/出)</th><th>双向确认端口</th><th>源端口数</th><th>状态判定</th></tr>
        </thead>
        <tbody id="clientRows"></tbody>
      </table>
    </div>

    <div class="card">
      <h2>最近端口跳跃事件</h2>
      <div id="events" class="mono" style="max-height:220px;overflow:auto;"></div>
    </div>
  </div>
</div>
<script>
let sessionToken = "";
async function doAuth() {
  const otp = document.getElementById("otpInput").value.trim();
  const r = await fetch("/api/auth", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({otp})
  });
  const j = await r.json();
  if (!r.ok) {
    document.getElementById("authMsg").textContent = j.error || "验证失败";
    return;
  }
  sessionToken = j.token;
  document.getElementById("authBox").style.display = "none";
  document.getElementById("dash").style.display = "block";
  poll();
  setInterval(poll, 1200);
}
function statusCls(s) {
  if (s.startsWith("BIDIR_OK (")) return "ok";
  if (s.startsWith("BIDIR_OK_WARN") || s.startsWith("HOP_SINGLE")) return "warn";
  return "err";
}
async function poll() {
  if (!sessionToken) return;
  try {
    const r = await fetch("/api/stats", {headers: {"Authorization": "Bearer " + sessionToken}});
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById("meta").textContent = `主端口 ${d.main_port} | 跳跃段 ${d.hop_ranges} | 已运行 ${d.uptime_sec}s`;
    document.getElementById("v4nat").textContent = `${d.nat_counters.v4_pkts} pkts / ${d.nat_counters.v4_bytes} B`;
    document.getElementById("v6nat").textContent = `${d.nat_counters.v6_pkts} pkts / ${d.nat_counters.v6_bytes} B`;
    document.getElementById("kstats").textContent = `${d.kernel_packets} / ${d.kernel_drops}`;
    const tb = document.getElementById("clientRows");
    tb.innerHTML = d.clients.map(c => `<tr>
      <td class="mono">${c.ip}</td>
      <td>${c.family}</td>
      <td>${c.main_in_pkts} / ${c.main_out_pkts}</td>
      <td>${c.hop_in_pkts} / ${c.hop_out_pkts}</td>
      <td class="mono">${c.hop_ports_bidir.slice(-6).join(", ") || "-"}</td>
      <td>${c.client_sports_count}</td>
      <td class="${statusCls(c.status)}">${c.status}</td>
    </tr>`).join("") || `<tr><td colspan="7" style="color:#94a3b8;">等待客户端发包... 请在 PC 或手机连上节点并访问海外网站</td></tr>`;
    document.getElementById("events").innerHTML = d.events.map(e =>
      `<div>[${e.ts}] [${e.dir}] ${e.ip} (${e.fam}) ${e.detail}</div>`
    ).join("");
  } catch (e) {}
}
</script>
</body>
</html>
"""


class BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_web_server(monitor, host, port):
    otp = secrets.token_urlsafe(12)
    session_tokens = set()
    fail_state = {"count": 0, "locked_until": 0.0}
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.request.settimeout(5.0)

        def log_message(self, format, *args):
            return

        def _send_json(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/":
                body = WEB_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/api/stats":
                auth = self.headers.get("Authorization", "")
                tok = auth[7:].strip() if auth.startswith("Bearer ") else ""
                with lock:
                    ok = tok in session_tokens
                if not ok:
                    self._send_json(401, {"error": "Unauthorized"})
                    return
                self._send_json(200, monitor.snapshot())
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            if path != "/api/auth":
                self._send_json(404, {"error": "Not found"})
                return
            now = time.time()
            with lock:
                if now < fail_state["locked_until"]:
                    self._send_json(429, {"error": "尝试次数过多，请稍后再试"})
                    return
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 4096)
                raw = self.rfile.read(length)
                data = json.loads(raw.decode("utf-8"))
                user_otp = str(data.get("otp", "")).strip()
            except Exception:
                self._send_json(400, {"error": "Bad request"})
                return
            if secrets.compare_digest(user_otp, otp):
                tok = secrets.token_urlsafe(24)
                with lock:
                    session_tokens.add(tok)
                    fail_state["count"] = 0
                self._send_json(200, {"token": tok})
            else:
                with lock:
                    fail_state["count"] += 1
                    if fail_state["count"] >= 5:
                        fail_state["locked_until"] = now + 30.0
                self._send_json(403, {"error": "口令错误"})

    srv = BoundedThreadingHTTPServer((host, port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, otp


def run_monitor_loop(report, main_port, hop_ports_str, enable_web=False, public_web=False, web_port=18080):
    if not is_root():
        print("[ERROR] 实时 AF_PACKET 抓包检测需要 root 权限！", file=sys.stderr)
        return
    ranges = parse_port_spec(hop_ports_str)
    mon = HopMonitor(main_port, ranges, report["network"])
    mon.start()

    srv = None
    otp = ""
    if enable_web:
        bind_host = "0.0.0.0" if public_web else "127.0.0.1"
        try:
            srv, otp = start_web_server(mon, bind_host, web_port)
        except Exception as e:
            print(f"[WARN] 启动临时监控网页失败: {e}")

    stop_flag = threading.Event()

    def _sig_handler(signum, frame):
        stop_flag.set()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    v4_ips = [a["ip"] for a in report["network"]["v4_addrs"] if not a["private"]]
    dns_v4 = [ip for ib in report.get("hy2_inbounds", []) for ip in ib.get("dns", {}).get("v4", [])]
    ext_ip = v4_ips[0] if v4_ips else (dns_v4[0] if dns_v4 else "<VPS_IP>")
    probe_port = ranges[0][0] + 123 if ranges[0][1] - ranges[0][0] >= 200 else ranges[0][0]

    try:
        while not stop_flag.is_set():
            snap = mon.snapshot()
            sys.stdout.write("\033[2J\033[H")
            print(f"=== Hy2 端口跳跃实时双向验证 (主端口={main_port}, 跳跃段={snap['hop_ranges']}, 运行={snap['uptime_sec']}s) ===")
            nc = snap["nat_counters"]
            print(f"NAT PREROUTING: IPv4={nc['v4_pkts']} pkts/{nc['v4_bytes']}B | IPv6={nc['v6_pkts']} pkts/{nc['v6_bytes']}B | 内核抓包/丢包={snap['kernel_packets']}/{snap['kernel_drops']}")
            if snap["error"]:
                print(f"\033[31m[错误] {snap['error']}\033[0m")

            if srv:
                print("\n--- 临时监控网页（退出即自动关闭）---")
                print(f"  一次性口令 : \033[33m{otp}\033[0m")
                print(f"  SSH 隧道访问(推荐): ssh -N -L {web_port}:127.0.0.1:{web_port} root@{ext_ip}  然后打开 http://127.0.0.1:{web_port}/")
                if public_web:
                    print(f"  \033[31m[公网明文模式已开启]\033[0m 直连地址: http://{ext_ip}:{web_port}/ （注意 HTTP 明文风险与云安全组需放行 {web_port}/tcp）")

            print("\n--- 客户端实时判定（首包即跳：正常时主端口命中应为 0）---")
            if not snap["clients"]:
                print("  等待客户端数据包... 请在 PC / 手机连上该节点并访问海外网站（连续使用 20s 观察端口轮换）")
            else:
                print(f"  {'来源 IP':<32} {'族':<5} {'主端口(入/出)':<14} {'跳跃(入/出)':<14} {'源端口数':<8} {'已确认跳转端口'}")
                for c in snap["clients"][:10]:
                    ports_str = ",".join(str(p) for p in c["hop_ports_bidir"][-5:]) or "-"
                    print(f"  {c['ip']:<32} {c['family']:<5} {c['main_in_pkts']}/{c['main_out_pkts']:<11} {c['hop_in_pkts']}/{c['hop_out_pkts']:<11} {c['client_sports_count']:<8} {ports_str}")
                    print(f"     -> 判定: {c['status']}")

            print("\n--- 最近事件 ---")
            for ev in snap["events"][:6]:
                print(f"  [{ev['ts']}] [{ev['dir']}] {ev['ip']} ({ev['fam']}) {ev['detail']}")

            print(f"\n[定界提示] 若跳跃包持续为 0，可在本地执行以下探针区分“云安全组拦截”与“客户端未跳”:")
            print(f"  python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'hy2probe',('{ext_ip}',{probe_port}))\"")
            print("按 Ctrl+C 停止监测并自动关闭临时端口。")
            sys.stdout.flush()
            stop_flag.wait(1.0)
    finally:
        mon.stop()
        if srv:
            srv.shutdown()
            srv.server_close()


# ------------------------------------------------------------------------------
# Interactive Menu & CLI Entrypoint
# ------------------------------------------------------------------------------

def tty_input(prompt_text, default=""):
    try:
        with open("/dev/tty", "r", encoding="utf-8") as tty_in, open("/dev/tty", "w", encoding="utf-8") as tty_out:
            tty_out.write(prompt_text)
            tty_out.flush()
            line = tty_in.readline()
            if not line:
                return default
            val = line.strip()
            return val if val else default
    except Exception:
        return default


def choose_hy2_params(report):
    ibs = report["hy2_inbounds"]
    if ibs:
        if len(ibs) == 1:
            ib = ibs[0]
        else:
            print("\n检测到多个 Hysteria2 入站，请选择:")
            for i, item in enumerate(ibs, 1):
                print(f"  {i}) 端口 {item['port']} | 跳跃 {item['hop_ports'] or '未设置'} | 备注 {item['remark']}")
            sel = tty_input("选择序号 [1]: ", "1")
            idx = max(0, min(len(ibs) - 1, int(sel) - 1)) if sel.isdigit() else 0
            ib = ibs[idx]
        default_port = str(ib["port"])
        default_hop = ib["hop_ports"] or "47000-50000"
    else:
        default_port = "443"
        default_hop = "47000-50000"
    p_str = tty_input(f"Hysteria2 主端口 [{default_port}]: ", default_port)
    h_str = tty_input(f"跳跃端口范围 [{default_hop}]: ", default_hop)
    return int(p_str), h_str


def interactive_menu(args):
    while True:
        report = run_audit()
        print("\n================ 3x-ui Hy2 端口跳跃助手 ================")
        print("  1) 全面体检（3x-ui / 双栈监听 / 防火墙 / PC与手机端指引）")
        print("  2) 一键配置并持久化端口转发（IPv4 + IPv6 systemd）")
        print("  3) 实时检测端口跳跃是否生效（CLI 双向监测）")
        print("  4) 实时检测 + 启动临时 Web 监控看板（默认 127.0.0.1 安全隧道）")
        print("  5) 卸载并清理端口转发规则与持久化服务")
        print("  0) 退出")
        choice = tty_input("请选择操作 [1]: ", "0")

        if choice == "1":
            print_audit_report(report)
            tty_input("按回车继续...", "")
        elif choice == "2":
            print_audit_report(report)
            main_port, hop_str = choose_hy2_params(report)
            plan = build_nat_plan(report, main_port, hop_str)
            if plan["v6_skipped_due_to_listener"]:
                ans = tty_input("检测到 IPv6 未监听，已默认跳过 IPv6 转发。是否仍强制写入 IPv6 规则？(y/N) [N]: ", "N")
                if ans.lower() == "y":
                    plan = build_nat_plan(report, main_port, hop_str, force_v6=True)
            apply_nat_plan(plan, dry_run=args.dry_run)
            tty_input("按回车继续...", "")
        elif choice == "3":
            main_port, hop_str = choose_hy2_params(report)
            run_monitor_loop(report, main_port, hop_str, enable_web=False)
        elif choice == "4":
            main_port, hop_str = choose_hy2_params(report)
            wp = tty_input(f"临时网页端口 [{args.port}]: ", str(args.port))
            pub = tty_input("是否公网监听 0.0.0.0（默认仅 127.0.0.1 走 ssh -L）？(y/N) [N]: ", "N")
            run_monitor_loop(
                report, main_port, hop_str,
                enable_web=True,
                public_web=(pub.lower() == "y" or args.public_web),
                web_port=int(wp),
            )
        elif choice == "5":
            ans = tty_input(f"确认卸载 {SERVICE_NAME} 并清除 {CHAIN_NAME} 规则？(y/N) [N]: ", "N")
            if ans.lower() == "y":
                uninstall_nat(dry_run=args.dry_run)
            tty_input("按回车继续...", "")
        elif choice == "0":
            break


def main():
    parser = argparse.ArgumentParser(description="3x-ui Hysteria2 端口跳跃检测与转发工具")
    parser.add_argument("--check", action="store_true", help="只读全面体检")
    parser.add_argument("--json", action="store_true", help="与 --check 联用输出 JSON 报告")
    parser.add_argument("--apply", action="store_true", help="配置并持久化 NAT 转发")
    parser.add_argument("--dry-run", action="store_true", help="仅预览变更不写入系统")
    parser.add_argument("--uninstall", action="store_true", help="清理 NAT 规则与持久化服务")
    parser.add_argument("--monitor", action="store_true", help="启动 CLI 实时双向抓包检测")
    parser.add_argument("--web", action="store_true", help="与 --monitor 联用，开启临时 Web 看板")
    parser.add_argument("--public-web", action="store_true", help="允许临时 Web 看板绑定 0.0.0.0（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=18080, help="临时 Web 看板端口（默认 18080）")
    parser.add_argument("--main-port", type=int, default=0, help="手动指定 Hysteria2 主端口")
    parser.add_argument("--hop-ports", type=str, default="", help="手动指定跳跃端口范围，如 47000-50000")
    parser.add_argument("--force-v6", action="store_true", help="强制同时写入 IPv6 转发规则")
    args = parser.parse_args()

    if args.uninstall:
        sys.exit(0 if uninstall_nat(dry_run=args.dry_run) else 1)

    if args.check:
        report = run_audit()
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print_audit_report(report)
        sys.exit(0)

    if args.apply:
        report = run_audit()
        ib = report["hy2_inbounds"][0] if report["hy2_inbounds"] else None
        mp = args.main_port or (ib["port"] if ib else 443)
        hp = args.hop_ports or (ib["hop_ports"] if ib and ib["hop_ports"] else "47000-50000")
        plan = build_nat_plan(report, mp, hp, force_v6=True if args.force_v6 else None)
        sys.exit(0 if apply_nat_plan(plan, dry_run=args.dry_run) else 1)

    if args.monitor:
        report = run_audit()
        ib = report["hy2_inbounds"][0] if report["hy2_inbounds"] else None
        mp = args.main_port or (ib["port"] if ib else 443)
        hp = args.hop_ports or (ib["hop_ports"] if ib and ib["hop_ports"] else "47000-50000")
        run_monitor_loop(report, mp, hp, enable_web=args.web, public_web=args.public_web, web_port=args.port)
        sys.exit(0)

    # Interactive mode
    if not os.path.exists("/dev/tty"):
        print("无可用交互终端，请使用 --check / --apply / --monitor 等命令行参数。", file=sys.stderr)
        sys.exit(1)
    interactive_menu(args)


if __name__ == "__main__":
    main()
__PYTHON_PAYLOAD__
}

main() {
    check_prereqs
    extract_payload

    # Acquire file lock only for mutating or monitoring operations (if flock exists & writable /run)
    local need_lock=1
    for arg in "$@"; do
        if [[ "$arg" == "--check" || "$arg" == "--help" || "$arg" == "-h" ]]; then
            need_lock=0
        fi
    done

    if [[ "$need_lock" == "1" && -w "/run" ]] && command -v flock >/dev/null 2>&1; then
        exec 9>"$LOCK_FILE"
        if ! flock -n 9; then
            msg_err "已有另一个 ${APP_NAME} 实例正在运行（锁文件: ${LOCK_FILE}）。"
            exit 1
        fi
    fi

    python3 "${TMP_DIR}/tool.py" "$@"
}

main "$@"
