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


# ─── ISP Scenario Simulator ──────────────────────────────────

ISP_SCENARIOS = {
    'peak_hours': {
        'name': 'Peak Hours Congestion',
        'description': 'Simulates ISP congestion during peak evening hours — bandwidth drops, latency climbs',
        'phases': [
            {'name': 'Normal',          'duration_sec': 60, 'latency_ms': 15,  'jitter_ms': 3,  'packet_loss_pct': 0,   'bandwidth_mbps': 100},
            {'name': 'Building',        'duration_sec': 60, 'latency_ms': 45,  'jitter_ms': 15, 'packet_loss_pct': 0.5, 'bandwidth_mbps': 50},
            {'name': 'Peak Congestion', 'duration_sec': 90, 'latency_ms': 120, 'jitter_ms': 40, 'packet_loss_pct': 3,   'bandwidth_mbps': 15},
            {'name': 'Recovery',        'duration_sec': 60, 'latency_ms': 35,  'jitter_ms': 10, 'packet_loss_pct': 0.3, 'bandwidth_mbps': 70},
            {'name': 'Normal',          'duration_sec': 30, 'latency_ms': 15,  'jitter_ms': 3,  'packet_loss_pct': 0,   'bandwidth_mbps': 100},
        ]
    },
    'intermittent_loss': {
        'name': 'Intermittent Loss Bursts',
        'description': 'Random packet loss bursts followed by clean periods — common on congested links',
        'phases': [
            {'name': 'Clean',       'duration_sec': 40, 'latency_ms': 10, 'jitter_ms': 2,  'packet_loss_pct': 0,  'bandwidth_mbps': 0},
            {'name': 'Loss Burst',  'duration_sec': 20, 'latency_ms': 25, 'jitter_ms': 10, 'packet_loss_pct': 10, 'bandwidth_mbps': 0},
            {'name': 'Clean',       'duration_sec': 30, 'latency_ms': 10, 'jitter_ms': 2,  'packet_loss_pct': 0,  'bandwidth_mbps': 0},
            {'name': 'Heavy Burst', 'duration_sec': 25, 'latency_ms': 40, 'jitter_ms': 20, 'packet_loss_pct': 15, 'bandwidth_mbps': 0},
            {'name': 'Clean',       'duration_sec': 45, 'latency_ms': 10, 'jitter_ms': 2,  'packet_loss_pct': 0,  'bandwidth_mbps': 0},
        ]
    },
    'isp_throttling': {
        'name': 'ISP Throttling',
        'description': 'ISP gradually reduces bandwidth then restores — typical throttling pattern',
        'phases': [
            {'name': 'Full Speed',     'duration_sec': 45, 'latency_ms': 12, 'jitter_ms': 2,  'packet_loss_pct': 0,   'bandwidth_mbps': 100},
            {'name': 'Slight Drop',    'duration_sec': 40, 'latency_ms': 15, 'jitter_ms': 5,  'packet_loss_pct': 0,   'bandwidth_mbps': 50},
            {'name': 'Heavy Throttle', 'duration_sec': 60, 'latency_ms': 30, 'jitter_ms': 10, 'packet_loss_pct': 0.5, 'bandwidth_mbps': 5},
            {'name': 'Throttled',      'duration_sec': 50, 'latency_ms': 25, 'jitter_ms': 8,  'packet_loss_pct': 0.2, 'bandwidth_mbps': 2},
            {'name': 'Restored',       'duration_sec': 45, 'latency_ms': 12, 'jitter_ms': 2,  'packet_loss_pct': 0,   'bandwidth_mbps': 100},
        ]
    },
    'fiber_cut': {
        'name': 'Fiber Cut Failover',
        'description': 'Primary fiber cut with failover to backup path — tests path redundancy',
        'phases': [
            {'name': 'Primary Path',   'duration_sec': 40, 'latency_ms': 8,   'jitter_ms': 1,  'packet_loss_pct': 0,   'bandwidth_mbps': 200},
            {'name': 'Fiber Cut',       'duration_sec': 15, 'latency_ms': 500, 'jitter_ms': 200,'packet_loss_pct': 80,  'bandwidth_mbps': 0},
            {'name': 'Total Outage',    'duration_sec': 20, 'latency_ms': 0,   'jitter_ms': 0,  'packet_loss_pct': 100, 'bandwidth_mbps': 0},
            {'name': 'Failover Path',   'duration_sec': 60, 'latency_ms': 85,  'jitter_ms': 20, 'packet_loss_pct': 1,   'bandwidth_mbps': 50},
            {'name': 'Stabilized',      'duration_sec': 45, 'latency_ms': 60,  'jitter_ms': 10, 'packet_loss_pct': 0.2, 'bandwidth_mbps': 80},
        ]
    },
    'cable_degradation': {
        'name': 'Cable/DSL Degradation',
        'description': 'Progressive cable quality degradation with jitter spikes — aging infrastructure',
        'phases': [
            {'name': 'Good',                'duration_sec': 50, 'latency_ms': 20,  'jitter_ms': 5,  'packet_loss_pct': 0,   'bandwidth_mbps': 50},
            {'name': 'Jitter Spikes',       'duration_sec': 40, 'latency_ms': 35,  'jitter_ms': 40, 'packet_loss_pct': 0.5, 'bandwidth_mbps': 40},
            {'name': 'Degraded',            'duration_sec': 60, 'latency_ms': 60,  'jitter_ms': 50, 'packet_loss_pct': 3,   'bandwidth_mbps': 20},
            {'name': 'Partial Recovery',    'duration_sec': 50, 'latency_ms': 30,  'jitter_ms': 15, 'packet_loss_pct': 0.5, 'bandwidth_mbps': 35},
        ]
    },
    'mobile_lte': {
        'name': 'Mobile/LTE Variability',
        'description': 'Mobile network with tower handoffs, congested cells, and edge fallback',
        'phases': [
            {'name': 'Good LTE',       'duration_sec': 40, 'latency_ms': 30,  'jitter_ms': 10, 'packet_loss_pct': 0,   'bandwidth_mbps': 50},
            {'name': 'Tower Handoff',   'duration_sec': 10, 'latency_ms': 200, 'jitter_ms': 100,'packet_loss_pct': 5,   'bandwidth_mbps': 10},
            {'name': 'Congested Cell',  'duration_sec': 50, 'latency_ms': 80,  'jitter_ms': 30, 'packet_loss_pct': 2,   'bandwidth_mbps': 15},
            {'name': 'Good LTE',        'duration_sec': 40, 'latency_ms': 30,  'jitter_ms': 10, 'packet_loss_pct': 0,   'bandwidth_mbps': 50},
            {'name': 'Edge Fallback',   'duration_sec': 60, 'latency_ms': 150, 'jitter_ms': 50, 'packet_loss_pct': 3,   'bandwidth_mbps': 3},
            {'name': 'LTE Restored',    'duration_sec': 30, 'latency_ms': 35,  'jitter_ms': 10, 'packet_loss_pct': 0,   'bandwidth_mbps': 45},
        ]
    },
}

_isp_running = False
_isp_thread = None
_isp_lock = threading.Lock()
_isp_status = {
    'running': False,
    'scenario_id': '',
    'scenario_name': '',
    'current_phase': 0,
    'phase_name': '',
    'phase_elapsed_sec': 0,
    'phase_duration_sec': 0,
    'total_elapsed_sec': 0,
    'total_duration_sec': 0,
    'loop': False,
    'impairment': {},
}


def get_isp_scenarios():
    """Return scenario catalog for UI."""
    result = {}
    for sid, s in ISP_SCENARIOS.items():
        total_sec = sum(p['duration_sec'] for p in s['phases'])
        result[sid] = {
            'name': s['name'],
            'description': s['description'],
            'total_duration_sec': total_sec,
            'phase_count': len(s['phases']),
            'phases': s['phases'],
        }
    return result


def start_isp_scenario(scenario_id, loop=False):
    """Start an ISP scenario. Returns False if already running or invalid ID."""
    global _isp_running, _isp_thread
    if scenario_id not in ISP_SCENARIOS:
        return False, f"Unknown scenario: {scenario_id}"
    with _isp_lock:
        if _isp_running:
            return False, "A scenario is already running"
        _isp_running = True

    scenario = ISP_SCENARIOS[scenario_id]
    total_sec = sum(p['duration_sec'] for p in scenario['phases'])

    def _run_scenario():
        global _isp_running
        logger.info(f"ISP scenario started: {scenario['name']} (loop={loop})")
        iteration = 0
        while _isp_running:
            elapsed_total = 0
            for phase_idx, phase in enumerate(scenario['phases']):
                if not _isp_running:
                    break
                with _isp_lock:
                    _isp_status.update({
                        'running': True,
                        'scenario_id': scenario_id,
                        'scenario_name': scenario['name'],
                        'current_phase': phase_idx,
                        'phase_name': phase['name'],
                        'phase_elapsed_sec': 0,
                        'phase_duration_sec': phase['duration_sec'],
                        'total_elapsed_sec': elapsed_total,
                        'total_duration_sec': total_sec,
                        'loop': loop,
                        'impairment': {
                            'latency_ms': phase['latency_ms'],
                            'jitter_ms': phase['jitter_ms'],
                            'packet_loss_pct': phase['packet_loss_pct'],
                            'bandwidth_mbps': phase['bandwidth_mbps'],
                        },
                    })
                logger.info(f"ISP phase: {phase['name']} — latency={phase['latency_ms']}ms "
                            f"jitter={phase['jitter_ms']}ms loss={phase['packet_loss_pct']}% "
                            f"bw={phase['bandwidth_mbps']}Mbps ({phase['duration_sec']}s)")
                apply_shaping(
                    latency_ms=phase['latency_ms'],
                    jitter_ms=phase['jitter_ms'],
                    packet_loss_pct=phase['packet_loss_pct'],
                    bandwidth_mbps=phase['bandwidth_mbps'],
                )
                # Sleep in 1-second ticks to allow responsive shutdown
                for sec in range(phase['duration_sec']):
                    if not _isp_running:
                        break
                    time.sleep(1)
                    with _isp_lock:
                        _isp_status['phase_elapsed_sec'] = sec + 1
                        _isp_status['total_elapsed_sec'] = elapsed_total + sec + 1
                elapsed_total += phase['duration_sec']
            iteration += 1
            if not loop:
                break
        clear_all()
        with _isp_lock:
            _isp_running = False
            _isp_status.update({'running': False, 'phase_name': '', 'scenario_id': '', 'impairment': {}})
        logger.info("ISP scenario stopped")

    _isp_thread = threading.Thread(target=_run_scenario, daemon=True)
    _isp_thread.start()
    return True, f"Started: {scenario['name']}"


def stop_isp_scenario():
    """Stop the running ISP scenario."""
    global _isp_running
    with _isp_lock:
        if not _isp_running:
            return False, "No scenario running"
        _isp_running = False
    return True, "Stopping scenario"


def get_isp_scenario_status():
    """Return current ISP scenario state."""
    with _isp_lock:
        return dict(_isp_status)
