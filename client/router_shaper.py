"""
Router-based link simulation via SSH.

Connects to Linux routers via SSH and applies tc/netem impairment rules
on selected interfaces. Supports multiple routers independently.
"""
import re
import time
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import paramiko

logger = logging.getLogger(__name__)

ROUTER_PRESETS = {
    'degraded_wan': {'latency_ms': 300, 'jitter_ms': 50, 'packet_loss_pct': 5, 'bandwidth_mbps': 0},
    'voice_sla': {'latency_ms': 200, 'jitter_ms': 40, 'packet_loss_pct': 2, 'bandwidth_mbps': 0},
    'video_sla': {'latency_ms': 150, 'jitter_ms': 30, 'packet_loss_pct': 3, 'bandwidth_mbps': 0},
}


def _slugify(name):
    """Convert a display name to a URL-safe ID."""
    return re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')


@dataclass
class RouterConnection:
    router_id: str
    name: str
    ip: str
    username: str
    password: str
    ssh_client: Optional[paramiko.SSHClient] = field(default=None, repr=False)
    connected: bool = False
    interfaces: list = field(default_factory=list)
    selected_interface: Optional[str] = None
    current_mode: str = 'idle'  # idle, healthy, impaired, link_down
    impairment_config: dict = field(default_factory=lambda: {
        'latency_ms': 0, 'jitter_ms': 0, 'packet_loss_pct': 0, 'bandwidth_mbps': 0})
    logs: deque = field(default_factory=lambda: deque(maxlen=100))

    def log(self, msg):
        ts = time.strftime('%H:%M:%S')
        entry = f"[{ts}] {msg}"
        self.logs.append(entry)
        logger.info(f"[Router:{self.name}] {msg}")

    def to_dict(self):
        return {
            'router_id': self.router_id,
            'name': self.name,
            'ip': self.ip,
            'username': self.username,
            'connected': self.connected,
            'interfaces': list(self.interfaces),
            'selected_interface': self.selected_interface,
            'current_mode': self.current_mode,
            'impairment_config': dict(self.impairment_config),
            'logs': list(self.logs)[-50:],
        }


class RouterManager:
    """Manages multiple SSH router connections for link simulation."""

    def __init__(self):
        self._routers: dict[str, RouterConnection] = {}
        self._lock = threading.Lock()

    # ─── Router Registry ─────────────────────────────────────

    def add_router(self, name, ip, username, password):
        """Add a router, connect via SSH, and discover interfaces."""
        name = name.strip()
        ip = ip.strip()
        if not name or not ip or not username:
            return False, "Name, IP, and username are required", {}

        router_id = _slugify(name)
        with self._lock:
            if router_id in self._routers:
                return False, f"Router '{name}' already exists", {}

        router = RouterConnection(
            router_id=router_id, name=name, ip=ip,
            username=username.strip(), password=password,
        )

        # Attempt connection
        ok, msg = self._connect(router)
        if not ok:
            return False, msg, {}

        # Discover interfaces
        self._discover_interfaces(router)

        with self._lock:
            self._routers[router_id] = router

        return True, f"Connected to {name} ({ip})", router.to_dict()

    def remove_router(self, router_id):
        """Disconnect and remove a router."""
        with self._lock:
            router = self._routers.pop(router_id, None)
        if not router:
            return False, f"Router '{router_id}' not found"

        # Clean up: restore healthy state before disconnecting
        if router.connected and router.selected_interface and router.current_mode != 'idle':
            self._apply_healthy(router)

        self._disconnect(router)
        return True, f"Router '{router.name}' removed"

    def get_router(self, router_id):
        with self._lock:
            return self._routers.get(router_id)

    def list_routers(self):
        with self._lock:
            return [r.to_dict() for r in self._routers.values()]

    # ─── Connection Management ───────────────────────────────

    def connect(self, router_id):
        router = self.get_router(router_id)
        if not router:
            return False, "Router not found"
        if router.connected:
            return True, "Already connected"
        ok, msg = self._connect(router)
        if ok:
            self._discover_interfaces(router)
        return ok, msg

    def disconnect(self, router_id):
        router = self.get_router(router_id)
        if not router:
            return False, "Router not found"
        self._disconnect(router)
        return True, f"Disconnected from {router.name}"

    def _connect(self, router):
        """Establish SSH connection to a router."""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=router.ip,
                username=router.username,
                password=router.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            router.ssh_client = client
            router.connected = True
            router.log(f"Connected to {router.ip}")
            return True, f"Connected to {router.ip}"
        except paramiko.AuthenticationException:
            msg = "Authentication failed: invalid username or password"
            router.log(f"Connection failed: {msg}")
            return False, msg
        except paramiko.SSHException as e:
            msg = f"SSH error: {e}"
            router.log(f"Connection failed: {msg}")
            return False, msg
        except Exception as e:
            msg = f"Cannot connect to {router.ip}: {e}"
            router.log(f"Connection failed: {msg}")
            return False, msg

    def _disconnect(self, router):
        """Close SSH connection."""
        if router.ssh_client:
            try:
                router.ssh_client.close()
            except Exception:
                pass
            router.ssh_client = None
        router.connected = False
        router.current_mode = 'idle'
        router.log("Disconnected")

    def _ensure_connected(self, router):
        """Check SSH connection is alive; attempt one reconnect if dead."""
        if router.ssh_client:
            transport = router.ssh_client.get_transport()
            if transport and transport.is_active():
                return True
        # Connection lost — attempt reconnect
        router.log("SSH connection lost, attempting reconnect...")
        router.connected = False
        ok, msg = self._connect(router)
        if not ok:
            router.log(f"Reconnect failed: {msg}")
        return ok

    def _ssh_exec(self, router, cmd):
        """Execute a command on the router via SSH.

        Returns (success: bool, output: str).
        """
        if not self._ensure_connected(router):
            return False, "SSH connection lost. Please reconnect."

        try:
            router.log(f"exec: {cmd}")
            stdin, stdout, stderr = router.ssh_client.exec_command(cmd, timeout=15)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()

            if exit_code != 0:
                # Ignore "RTNETLINK answers: No such file or directory" (no qdisc to delete)
                if 'No such file' in err or 'Cannot delete' in err:
                    return True, out
                router.log(f"cmd failed (exit {exit_code}): {err}")
                return False, err or f"Command failed with exit code {exit_code}"

            return True, out
        except Exception as e:
            router.connected = False
            msg = f"SSH exec error: {e}"
            router.log(msg)
            return False, msg

    # ─── Interface Discovery ─────────────────────────────────

    def discover_interfaces(self, router_id):
        router = self.get_router(router_id)
        if not router:
            return []
        self._discover_interfaces(router)
        return router.interfaces

    def _discover_interfaces(self, router):
        """Discover interfaces on the router via SSH."""
        interfaces = {}

        # Get link info
        ok, link_output = self._ssh_exec(router, 'ip -o link show')
        if not ok:
            router.log(f"Interface discovery failed: {link_output}")
            return

        # Parse link output: "2: eth0: <BROADCAST,...> ... state UP ..."
        for line in link_output.split('\n'):
            if not line.strip():
                continue
            match = re.match(r'\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]*)>.*?state\s+(\S+)', line)
            if match:
                name = match.group(1)
                state = match.group(3).lower()
                if name == 'lo':
                    continue
                interfaces[name] = {
                    'name': name,
                    'ip_address': '',
                    'subnet': '',
                    'description': '',
                    'state': state,
                }

        # Get address info
        ok, addr_output = self._ssh_exec(router, 'ip -o -4 addr show')
        if ok:
            for line in addr_output.split('\n'):
                if not line.strip():
                    continue
                match = re.match(r'\d+:\s+(\S+)\s+inet\s+(\S+)', line)
                if match:
                    name = match.group(1)
                    cidr = match.group(2)
                    if name in interfaces:
                        parts = cidr.split('/')
                        interfaces[name]['ip_address'] = parts[0]
                        interfaces[name]['subnet'] = '/' + parts[1] if len(parts) > 1 else ''

        # Read interface descriptions from ifalias files
        ok, desc_output = self._ssh_exec(router,
            'for iface in /sys/class/net/*/ifalias; do '
            'name=$(basename $(dirname "$iface")); '
            'desc=$(cat "$iface" 2>/dev/null); '
            '[ -n "$desc" ] && echo "$name:$desc"; '
            'done')
        if ok:
            for line in desc_output.split('\n'):
                if ':' in line:
                    name, desc = line.split(':', 1)
                    if name.strip() in interfaces:
                        interfaces[name.strip()]['description'] = desc.strip()

        router.interfaces = list(interfaces.values())
        router.log(f"Discovered {len(router.interfaces)} interfaces")

    # ─── Interface Selection ─────────────────────────────────

    def select_interface(self, router_id, interface_name):
        router = self.get_router(router_id)
        if not router:
            return False, "Router not found"
        if not any(i['name'] == interface_name for i in router.interfaces):
            return False, f"Interface '{interface_name}' not found on router"
        router.selected_interface = interface_name
        router.log(f"Selected interface: {interface_name}")
        return True, f"Interface '{interface_name}' selected"

    # ─── Mode Application ────────────────────────────────────

    def apply_mode(self, router_id, mode, config=None):
        """Apply a mode to the router's selected interface.

        mode: 'healthy', 'impaired', or 'link_down'
        config: dict with latency_ms, jitter_ms, packet_loss_pct, bandwidth_mbps (for impaired mode)
        """
        router = self.get_router(router_id)
        if not router:
            return False, "Router not found"
        if not router.connected:
            return False, "Router not connected"
        if not router.selected_interface:
            return False, "No interface selected"

        if mode == 'healthy':
            return self._apply_healthy(router)
        elif mode == 'impaired':
            return self._apply_impaired(router, config or {})
        elif mode == 'link_down':
            return self._apply_link_down(router)
        else:
            return False, f"Unknown mode: {mode}"

    def _apply_healthy(self, router):
        """Clear all impairment and ensure interface is up."""
        iface = router.selected_interface
        # Clear tc rules (ignore errors if none exist)
        self._ssh_exec(router, f'sudo tc qdisc del dev {iface} root')
        # Bring interface up
        ok, msg = self._ssh_exec(router, f'sudo ip link set {iface} up')
        if not ok:
            return False, f"Failed to bring up {iface}: {msg}"

        router.current_mode = 'healthy'
        router.impairment_config = {'latency_ms': 0, 'jitter_ms': 0,
                                     'packet_loss_pct': 0, 'bandwidth_mbps': 0}
        router.log(f"Mode: HEALTHY — {iface} up, no impairment")
        return True, f"{iface} healthy — no impairment"

    def _apply_impaired(self, router, config):
        """Apply tc/netem impairment on the selected interface."""
        iface = router.selected_interface
        latency_ms = int(config.get('latency_ms', 0))
        jitter_ms = int(config.get('jitter_ms', 0))
        packet_loss_pct = float(config.get('packet_loss_pct', 0))
        bandwidth_mbps = int(config.get('bandwidth_mbps', 0))

        # Ensure interface is up first
        self._ssh_exec(router, f'sudo ip link set {iface} up')
        # Clear existing rules
        self._ssh_exec(router, f'sudo tc qdisc del dev {iface} root')

        # Build netem args
        netem_args = self._build_netem_args(latency_ms, jitter_ms, packet_loss_pct)
        has_netem = len(netem_args) > 0
        has_bw = bandwidth_mbps > 0

        if not has_netem and not has_bw:
            router.current_mode = 'healthy'
            router.log("No impairment values set — mode remains healthy")
            return True, "No impairment values — interface is healthy"

        if has_bw and has_netem:
            self._ssh_exec(router,
                f'sudo tc qdisc add dev {iface} root handle 1: htb default 10')
            self._ssh_exec(router,
                f'sudo tc class add dev {iface} parent 1: classid 1:10 htb '
                f'rate {bandwidth_mbps}mbit ceil {bandwidth_mbps}mbit')
            ok, msg = self._ssh_exec(router,
                f'sudo tc qdisc add dev {iface} parent 1:10 handle 10: netem {netem_args}')
        elif has_bw:
            self._ssh_exec(router,
                f'sudo tc qdisc add dev {iface} root handle 1: htb default 10')
            ok, msg = self._ssh_exec(router,
                f'sudo tc class add dev {iface} parent 1: classid 1:10 htb '
                f'rate {bandwidth_mbps}mbit ceil {bandwidth_mbps}mbit')
        else:
            ok, msg = self._ssh_exec(router,
                f'sudo tc qdisc add dev {iface} root netem {netem_args}')

        if not ok:
            return False, f"Failed to apply impairment: {msg}"

        router.current_mode = 'impaired'
        router.impairment_config = {
            'latency_ms': latency_ms, 'jitter_ms': jitter_ms,
            'packet_loss_pct': packet_loss_pct, 'bandwidth_mbps': bandwidth_mbps,
        }
        desc = self._fmt_impairment(router.impairment_config)
        router.log(f"Mode: IMPAIRED — {iface} | {desc}")
        return True, f"{iface} impaired — {desc}"

    def _apply_link_down(self, router):
        """Shut down the selected interface."""
        iface = router.selected_interface
        # Clear tc rules first
        self._ssh_exec(router, f'sudo tc qdisc del dev {iface} root')
        # Bring interface down
        ok, msg = self._ssh_exec(router, f'sudo ip link set {iface} down')
        if not ok:
            return False, f"Failed to bring down {iface}: {msg}"

        router.current_mode = 'link_down'
        router.impairment_config = {'latency_ms': 0, 'jitter_ms': 0,
                                     'packet_loss_pct': 0, 'bandwidth_mbps': 0}
        router.log(f"Mode: LINK DOWN — {iface} shut down")
        return True, f"{iface} is DOWN"

    # ─── Command Helpers ─────────────────────────────────────

    @staticmethod
    def _build_netem_args(latency_ms, jitter_ms, packet_loss_pct):
        """Build netem argument string. Designed to be overridden for other vendors."""
        parts = []
        if latency_ms > 0:
            parts.append(f'delay {int(latency_ms)}ms')
            if jitter_ms > 0:
                parts.append(f'{int(jitter_ms)}ms distribution normal')
        if packet_loss_pct > 0:
            parts.append(f'loss {float(packet_loss_pct)}%')
        return ' '.join(parts)

    @staticmethod
    def _fmt_impairment(config):
        """Format impairment values for display."""
        parts = []
        if config.get('latency_ms'):
            parts.append(f"latency={config['latency_ms']}ms")
        if config.get('jitter_ms'):
            parts.append(f"jitter={config['jitter_ms']}ms")
        if config.get('packet_loss_pct'):
            parts.append(f"loss={config['packet_loss_pct']}%")
        if config.get('bandwidth_mbps'):
            parts.append(f"bw={config['bandwidth_mbps']}Mbps")
        return ' '.join(parts) if parts else 'none'

    # ─── Status ──────────────────────────────────────────────

    def get_status(self, router_id):
        router = self.get_router(router_id)
        if not router:
            return {'error': 'Router not found'}
        # Refresh connected state
        if router.ssh_client:
            transport = router.ssh_client.get_transport()
            if not transport or not transport.is_active():
                router.connected = False
                router.current_mode = 'idle'
        return router.to_dict()

    def get_all_status(self):
        with self._lock:
            return {rid: r.to_dict() for rid, r in self._routers.items()}


    # ─── ISP Scenario Simulator ─────────────────────────────

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

    def get_isp_scenarios(self):
        """Return scenario catalog for UI."""
        result = {}
        for sid, s in self.ISP_SCENARIOS.items():
            total_sec = sum(p['duration_sec'] for p in s['phases'])
            result[sid] = {
                'name': s['name'],
                'description': s['description'],
                'total_duration_sec': total_sec,
                'phase_count': len(s['phases']),
                'phases': s['phases'],
            }
        return result

    def start_isp_scenario(self, router_id, scenario_id, loop=False):
        """Start an ISP scenario on a router's selected interface."""
        if scenario_id not in self.ISP_SCENARIOS:
            return False, f"Unknown scenario: {scenario_id}"

        router = self.get_router(router_id)
        if not router:
            return False, "Router not found"
        if not router.connected:
            return False, "Router not connected"
        if not router.selected_interface:
            return False, "No interface selected on this router"

        # Check if this router already has a running scenario
        with self._lock:
            if hasattr(router, '_isp_running') and router._isp_running:
                return False, "A scenario is already running on this router"

        scenario = self.ISP_SCENARIOS[scenario_id]
        total_sec = sum(p['duration_sec'] for p in scenario['phases'])

        router._isp_running = True
        router._isp_status = {
            'running': True,
            'scenario_id': scenario_id,
            'scenario_name': scenario['name'],
            'current_phase': 0,
            'phase_name': '',
            'phase_elapsed_sec': 0,
            'phase_duration_sec': 0,
            'total_elapsed_sec': 0,
            'total_duration_sec': total_sec,
            'loop': loop,
            'impairment': {},
        }

        def _run_scenario():
            router.log(f"ISP scenario started: {scenario['name']} (loop={loop})")
            while router._isp_running:
                elapsed_total = 0
                for phase_idx, phase in enumerate(scenario['phases']):
                    if not router._isp_running:
                        break
                    router._isp_status.update({
                        'running': True,
                        'current_phase': phase_idx,
                        'phase_name': phase['name'],
                        'phase_elapsed_sec': 0,
                        'phase_duration_sec': phase['duration_sec'],
                        'total_elapsed_sec': elapsed_total,
                        'impairment': {
                            'latency_ms': phase['latency_ms'],
                            'jitter_ms': phase['jitter_ms'],
                            'packet_loss_pct': phase['packet_loss_pct'],
                            'bandwidth_mbps': phase['bandwidth_mbps'],
                        },
                    })
                    router.log(f"ISP phase: {phase['name']} — latency={phase['latency_ms']}ms "
                               f"jitter={phase['jitter_ms']}ms loss={phase['packet_loss_pct']}% "
                               f"bw={phase['bandwidth_mbps']}Mbps ({phase['duration_sec']}s)")
                    # Apply impairment via SSH to router interface
                    config = {
                        'latency_ms': phase['latency_ms'],
                        'jitter_ms': phase['jitter_ms'],
                        'packet_loss_pct': phase['packet_loss_pct'],
                        'bandwidth_mbps': phase['bandwidth_mbps'],
                    }
                    self._apply_impaired(router, config)
                    # Sleep in 1-second ticks for responsive shutdown
                    for sec in range(phase['duration_sec']):
                        if not router._isp_running:
                            break
                        time.sleep(1)
                        router._isp_status['phase_elapsed_sec'] = sec + 1
                        router._isp_status['total_elapsed_sec'] = elapsed_total + sec + 1
                    elapsed_total += phase['duration_sec']
                if not loop:
                    break
            # Restore healthy state
            self._apply_healthy(router)
            router._isp_running = False
            router._isp_status.update({
                'running': False, 'phase_name': '', 'scenario_id': '', 'impairment': {}
            })
            router.log("ISP scenario stopped")

        t = threading.Thread(target=_run_scenario, daemon=True)
        t.start()
        return True, f"Started: {scenario['name']} on {router.name} ({router.selected_interface})"

    def stop_isp_scenario(self, router_id):
        """Stop the running ISP scenario on a router."""
        router = self.get_router(router_id)
        if not router:
            return False, "Router not found"
        if not hasattr(router, '_isp_running') or not router._isp_running:
            return False, "No scenario running on this router"
        router._isp_running = False
        return True, "Stopping scenario"

    def get_isp_scenario_status(self, router_id):
        """Return current ISP scenario state for a router."""
        router = self.get_router(router_id)
        if not router:
            return {'running': False}
        if not hasattr(router, '_isp_status'):
            return {'running': False}
        return dict(router._isp_status)


# Module-level singleton
router_manager = RouterManager()
