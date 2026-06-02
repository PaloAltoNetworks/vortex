"""
Network shaper using Linux tc/netem for latency, packet loss, and bandwidth control.
Requires NET_ADMIN capability.
"""
import os
import re
import random
import socket
import subprocess
import logging
import threading
import time

logger = logging.getLogger(__name__)

_random_bw_running = False
_random_bw_thread = None
_random_bw_lock = threading.Lock()

# Track last applied settings so the API can return them accurately
_last_shaping = {"latency_ms": 0, "jitter_ms": 0, "packet_loss_pct": 0, "bandwidth_mbps": 0}

# Sudo authentication state (NOPASSWD configured in container)
_sudo_authenticated = True  # Auto-authenticated with NOPASSWD
_sudo_lock = threading.Lock()
# Commands that require sudo
_SUDO_COMMANDS = {'tc', 'iptables', 'ip'}


def get_sudo_authenticated():
    """Check if sudo is available. Always True with NOPASSWD."""
    return True


def _detect_interface():
    """Auto-detect the network interface used to reach SERVER_HOST.

    Uses 'ip route get <server_ip>' to find the outgoing interface.
    Falls back to SHAPER_INTERFACE env var, then 'eth0'.
    """
    env_iface = os.environ.get('SHAPER_INTERFACE')
    if env_iface:
        logger.info(f"Using interface from SHAPER_INTERFACE env: {env_iface}")
        return env_iface

    server_host = os.environ.get('SERVER_HOST', '')
    if server_host:
        try:
            # Resolve hostname to IP first if needed
            try:
                server_ip = socket.gethostbyname(server_host)
            except socket.gaierror:
                server_ip = server_host

            result = subprocess.run(
                ['ip', 'route', 'get', server_ip],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Output like: "10.0.0.2 dev eth1 src 10.0.0.1 uid 0"
                match = re.search(r'dev\s+(\S+)', result.stdout)
                if match:
                    iface = match.group(1)
                    logger.info(f"Auto-detected interface '{iface}' for server {server_host} ({server_ip})")
                    return iface
        except Exception as e:
            logger.warning(f"Interface auto-detection failed: {e}")

    # Fallback: find default route interface
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                iface = match.group(1)
                logger.info(f"Using default route interface: {iface}")
                return iface
    except Exception as e:
        logger.warning(f"Default route detection failed: {e}")

    logger.info("Falling back to eth0")
    return 'eth0'


INTERFACE = _detect_interface()


def _validate_ip(ip):
    """Validate an IPv4 address string."""
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        raise ValueError(f"Invalid IP address: {ip}")
    parts = ip.split('.')
    for p in parts:
        if int(p) > 255:
            raise ValueError(f"Invalid IP address: {ip}")
    return ip


def _needs_sudo(cmd):
    """Check if a command needs sudo. Read-only commands don't need sudo."""
    if cmd[0] not in _SUDO_COMMANDS:
        return False
    # ip route get/show and ip addr show are read-only
    if cmd[0] == 'ip' and len(cmd) >= 2:
        if cmd[1] == 'route':
            return False
        if cmd[1:3] == ['-4', 'addr'] or (cmd[1] == 'addr' and 'show' in cmd):
            return False
    # tc qdisc show is read-only
    if cmd[0] == 'tc' and 'show' in cmd:
        return False
    return True


def _run(cmd):
    """Run a command as a list (no shell). Uses sudo (NOPASSWD) for privileged commands."""
    needs_sudo = _needs_sudo(cmd)
    if needs_sudo:
        sudo_cmd = ['sudo'] + cmd
        logger.info(f"cmd: sudo {cmd}")
        try:
            result = subprocess.run(sudo_cmd, capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            logger.warning(f"cmd not found: {cmd[0]}")
            return False, f"{cmd[0]}: command not found"
        except subprocess.TimeoutExpired:
            logger.warning(f"cmd timeout: {cmd}")
            return False, "Command timed out"
    else:
        logger.info(f"cmd: {cmd}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            logger.warning(f"cmd not found: {cmd[0]}")
            return False, f"{cmd[0]}: command not found"
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if stderr:
            logger.warning(f"cmd failed: {stderr}")
    return result.returncode == 0, result.stdout + result.stderr


def get_current_settings():
    ok, output = _run(['tc', 'qdisc', 'show', 'dev', INTERFACE])
    return output if ok else "No settings applied"


def clear_all():
    _run(['tc', 'qdisc', 'del', 'dev', INTERFACE, 'root'])
    _last_shaping.update({"latency_ms": 0, "jitter_ms": 0, "packet_loss_pct": 0, "bandwidth_mbps": 0})
    logger.info("Cleared all shaping rules")
    return True


def apply_shaping(latency_ms=0, jitter_ms=0, packet_loss_pct=0, bandwidth_mbps=0):
    """Apply network impairment on egress."""
    clear_all()

    netem_args = []
    if latency_ms > 0:
        netem_args.extend(['delay', f'{int(latency_ms)}ms'])
        if jitter_ms > 0:
            netem_args.extend([f'{int(jitter_ms)}ms', 'distribution', 'normal'])
    if packet_loss_pct > 0:
        netem_args.extend(['loss', f'{float(packet_loss_pct)}%'])

    has_netem = len(netem_args) > 0
    has_bw = bandwidth_mbps > 0

    if has_bw and has_netem:
        _run(['tc', 'qdisc', 'add', 'dev', INTERFACE, 'root', 'handle', '1:', 'htb', 'default', '10'])
        _run(['tc', 'class', 'add', 'dev', INTERFACE, 'parent', '1:', 'classid', '1:10', 'htb',
              'rate', f'{int(bandwidth_mbps)}mbit', 'ceil', f'{int(bandwidth_mbps)}mbit'])
        _run(['tc', 'qdisc', 'add', 'dev', INTERFACE, 'parent', '1:10', 'handle', '10:', 'netem'] + netem_args)
    elif has_bw:
        _run(['tc', 'qdisc', 'add', 'dev', INTERFACE, 'root', 'handle', '1:', 'htb', 'default', '10'])
        _run(['tc', 'class', 'add', 'dev', INTERFACE, 'parent', '1:', 'classid', '1:10', 'htb',
              'rate', f'{int(bandwidth_mbps)}mbit', 'ceil', f'{int(bandwidth_mbps)}mbit'])
    elif has_netem:
        _run(['tc', 'qdisc', 'add', 'dev', INTERFACE, 'root', 'netem'] + netem_args)
    else:
        logger.info("No shaping parameters — traffic unimpaired")
        return True

    _last_shaping.update({"latency_ms": latency_ms, "jitter_ms": jitter_ms,
                          "packet_loss_pct": packet_loss_pct, "bandwidth_mbps": bandwidth_mbps})
    logger.info(f"Applied: latency={latency_ms}ms jitter={jitter_ms}ms "
                f"loss={packet_loss_pct}% bw={bandwidth_mbps}Mbps")
    return True


def start_random_bandwidth(min_mbps=20, max_mbps=1000, interval=10):
    """Cycle bandwidth randomly between min and max every interval seconds."""
    global _random_bw_running, _random_bw_thread
    with _random_bw_lock:
        if _random_bw_running:
            return False
        _random_bw_running = True

    def _loop():
        global _random_bw_running
        logger.info(f"Random bandwidth started: {min_mbps}-{max_mbps} Mbps every {interval}s")
        while _random_bw_running:
            bw = random.randint(min_mbps, max_mbps)
            clear_all()
            _run(['tc', 'qdisc', 'add', 'dev', INTERFACE, 'root', 'handle', '1:', 'htb', 'default', '10'])
            _run(['tc', 'class', 'add', 'dev', INTERFACE, 'parent', '1:', 'classid', '1:10', 'htb',
                  'rate', f'{bw}mbit', 'ceil', f'{bw}mbit'])
            logger.info(f"Random bandwidth set to {bw} Mbps")
            time.sleep(interval)
        clear_all()
        logger.info("Random bandwidth stopped")

    _random_bw_thread = threading.Thread(target=_loop, daemon=True)
    _random_bw_thread.start()
    return True


def stop_random_bandwidth():
    global _random_bw_running
    with _random_bw_lock:
        _random_bw_running = False
    return True


def is_random_bandwidth_running():
    return _random_bw_running


def get_last_shaping():
    """Return last applied shaping settings as a dict."""
    return dict(_last_shaping)




# ─── Source IP Aliases ──────────────────────────────────────

_alias_ips = []
_alias_lock = threading.Lock()


def _get_subnet_prefix():
    """Detect the subnet prefix length from the interface."""
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show', 'dev', INTERFACE],
            capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                parts = line.strip().split()
                addr_cidr = parts[1]
                return addr_cidr.split('/')[1]
    except Exception:
        pass
    return '24'


def add_ip_aliases(base_ip, count):
    """Add IP aliases to the interface.

    base_ip: starting IP, e.g. '172.18.0.100'
    count: number of aliases to add (max 50)
    """
    global _alias_ips
    _validate_ip(base_ip)
    count = min(int(count), 50)
    remove_ip_aliases()

    prefix = _get_subnet_prefix()
    parts = base_ip.split('.')
    base_last = int(parts[3])
    base_prefix = '.'.join(parts[:3])
    added = []

    for i in range(count):
        last_octet = base_last + i
        if last_octet > 254:
            break
        ip = f'{base_prefix}.{last_octet}'
        ok, _ = _run(['ip', 'addr', 'add', f'{ip}/{prefix}', 'dev', INTERFACE])
        if ok:
            added.append(ip)
            logger.info(f"Added alias IP {ip}/{prefix}")

    with _alias_lock:
        _alias_ips = added

    logger.info(f"Added {len(added)} IP aliases ({added[0]}-{added[-1]})" if added else "No aliases added")
    return added


def remove_ip_aliases():
    """Remove all previously added IP aliases."""
    global _alias_ips
    prefix = _get_subnet_prefix()
    with _alias_lock:
        for ip in _alias_ips:
            _run(['ip', 'addr', 'del', f'{ip}/{prefix}', 'dev', INTERFACE])
            logger.info(f"Removed alias IP {ip}")
        _alias_ips = []


def get_alias_ips():
    """Return list of active alias IPs."""
    with _alias_lock:
        return list(_alias_ips)


def get_random_source_ip():
    """Return a random alias IP, or None if no aliases configured."""
    with _alias_lock:
        if _alias_ips:
            return random.choice(_alias_ips)
    return None
