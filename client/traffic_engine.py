"""
Traffic engine — protocol handlers for HTTP/HTTPS, TCP, UDP, FTP, SSH, ICMP.
Each job runs in a background thread with a configurable duration.
"""
import os
import time
import random
import socket
import struct
import ftplib
import logging
import threading
import subprocess
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
import httpx
import paramiko
import socks
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger('paramiko.transport').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# DSCP name → value mapping
DSCP_VALUES = {
    'BE': 0, 'CS1': 8, 'AF11': 10, 'AF12': 12, 'AF13': 14,
    'CS2': 16, 'AF21': 18, 'AF22': 20, 'AF23': 22,
    'CS3': 24, 'AF31': 26, 'AF32': 28, 'AF33': 30,
    'CS4': 32, 'AF41': 34, 'AF42': 36, 'AF43': 38,
    'CS5': 40, 'VA': 44, 'EF': 46, 'CS6': 48, 'CS7': 56,
}


REALWORLD_PROFILES = {
    'office_worker': {
        'name': 'Office Worker',
        'description': 'Typical office: browser-based web browsing, SaaS apps (O365, Google), DNS, SSH',
        'protocols': [
            {'protocol': 'https', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 3, 'ignore_ssl': True,
                'random_size': True, 'ramp_enabled': True,
                'dscp': 'AF21'}},
            {'protocol': 'ext_https', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 5, 'ignore_ssl': True,
                'urls': 'https://www.google.com\nhttps://www.microsoft.com\nhttps://www.github.com\nhttps://www.wikipedia.org',
                'dscp': 'AF21'}},
            {'protocol': 'http_plain', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 5,
                'random_size': True, 'ramp_enabled': True,
                'dscp': 'BE'}},
            {'protocol': 'dns', 'flow_id': 'rw', 'config': {
                'interval': 0.5, 'dscp': 'CS6',
                'domains': 'google.com\namazon.com\nmicrosoft.com\ngithub.com\ncloudflare.com\noffice365.com\nslack.com\nzoom.us'}},
            {'protocol': 'ssh', 'flow_id': 'rw', 'config': {
                'interval': 10, 'command': 'uptime', 'dscp': 'CS2'}},
        ],
    },
    'remote_worker': {
        'name': 'Remote Worker',
        'description': 'VPN-heavy: browser HTTPS, video-call RTP (EF/AF41), SaaS apps, SSH tunnels',
        'protocols': [
            {'protocol': 'https', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 3, 'ignore_ssl': True,
                'random_size': True, 'ramp_enabled': True,
                'dscp': 'AF21'}},
            {'protocol': 'ext_https', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 5, 'ignore_ssl': True,
                'urls': 'https://www.google.com\nhttps://www.microsoft.com\nhttps://www.github.com\nhttps://www.amazon.com',
                'dscp': 'AF21'}},
            {'protocol': 'dns', 'flow_id': 'rw', 'config': {
                'interval': 0.3, 'dscp': 'CS6',
                'domains': 'google.com\nmicrosoft.com\nzoom.us\nteams.microsoft.com\nslack.com\ngithub.com'}},
            {'protocol': 'rtp', 'flow_id': 'rw', 'config': {
                'mode': 'Video Call', 'video_bitrate': '500k',
                'audio_bitrate': '64k', 'resolution': '640x480',
                'dscp_video': 'AF41', 'dscp_audio': 'EF'}},
            {'protocol': 'ssh', 'flow_id': 'rw', 'config': {
                'interval': 5, 'command': 'ls -la /tmp', 'dscp': 'CS2'}},
        ],
    },
    'branch_office': {
        'name': 'Branch Office',
        'description': 'Multi-user branch: browser web, SaaS apps, bulk FTP (AF11), video RTP (AF41), multicast, DNS',
        'protocols': [
            {'protocol': 'https', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 2, 'ignore_ssl': True,
                'random_size': True, 'ramp_enabled': True,
                'dscp': 'AF21'}},
            {'protocol': 'ext_https', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 4, 'ignore_ssl': True,
                'urls': 'https://www.google.com\nhttps://www.microsoft.com\nhttps://www.github.com\nhttps://www.wikipedia.org\nhttps://www.amazon.com',
                'dscp': 'AF21'}},
            {'protocol': 'http_plain', 'flow_id': 'rw', 'config': {
                'browser_mode': True, 'interval': 5,
                'random_size': True, 'ramp_enabled': True,
                'dscp': 'BE'}},
            {'protocol': 'dns', 'flow_id': 'rw', 'config': {
                'interval': 0.2, 'dscp': 'CS6',
                'domains': 'google.com\namazon.com\nmicrosoft.com\ngithub.com\ncloudflare.com\noffice365.com\naws.amazon.com\nazure.microsoft.com'}},
            {'protocol': 'ftp', 'flow_id': 'rw', 'config': {
                'filename': 'testfile_100mb.bin', 'random_size': True,
                'dscp': 'AF11'}},
            {'protocol': 'ssh', 'flow_id': 'rw', 'config': {
                'interval': 8, 'command': 'uptime', 'dscp': 'CS2'}},
            {'protocol': 'rtp', 'flow_id': 'rw', 'config': {
                'mode': 'Streaming', 'video_bitrate': '2M',
                'resolution': '1280x720', 'dscp_video': 'AF41'}},
            {'protocol': 'multicast', 'flow_id': 'rw', 'config': {
                'group': '239.1.1.1', 'port': 5004, 'packet_size': 1200,
                'target_pps': 50, 'dscp': 'AF41'}},
        ],
    },
}


def _dscp_to_tos(dscp):
    """Convert DSCP value or name to TOS byte. DSCP occupies upper 6 bits."""
    if isinstance(dscp, str):
        dscp = DSCP_VALUES.get(dscp.upper(), int(dscp) if dscp.isdigit() else 0)
    return int(dscp) << 2


def _set_tos(sock, tos):
    """Set IP_TOS on a socket."""
    if tos > 0:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)


class DscpHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that sets IP_TOS/DSCP and source IP binding on the underlying socket."""

    def __init__(self, tos=0, source_address=None, **kwargs):
        self.tos = tos
        self.source_address = source_address  # (ip, 0) tuple to bind to
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        socket_options = [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]
        if self.tos > 0:
            socket_options.append((socket.IPPROTO_IP, socket.IP_TOS, self.tos))
        kwargs['socket_options'] = socket_options
        if self.source_address:
            kwargs['source_address'] = self.source_address
        super().init_poolmanager(*args, **kwargs)


def _random_xff():
    """Return an alias source IP if configured, otherwise a random IP."""
    import network_shaper
    alias_ip = network_shaper.get_random_source_ip()
    if alias_ip:
        return alias_ip
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# Realistic browser User-Agent strings for App-ID classification
_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
]


def _get_source_address():
    """Return a (ip, 0) tuple for socket binding if aliases are configured, else None."""
    import network_shaper
    ip = network_shaper.get_random_source_ip()
    return (ip, 0) if ip else None


def _browser_headers(url=''):
    """Generate realistic browser headers for Palo Alto App-ID classification."""
    ua = random.choice(_USER_AGENTS)
    headers = {
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'X-Forwarded-For': _random_xff(),
    }
    # Add Sec-CH-UA for Chrome/Edge user agents
    if 'Chrome/' in ua:
        headers['Sec-CH-UA'] = '"Chromium";v="131", "Not_A Brand";v="24"'
        headers['Sec-CH-UA-Mobile'] = '?0'
        headers['Sec-CH-UA-Platform'] = '"Windows"' if 'Windows' in ua else '"macOS"'
    return headers


@dataclass
class TrafficJob:
    protocol: str
    thread: Optional[threading.Thread] = None
    running: bool = False
    start_time: float = 0
    duration: int = 0  # seconds, 0 = indefinite
    stats: dict = field(default_factory=lambda: {
        "bytes_sent": 0, "bytes_recv": 0, "requests": 0, "errors": 0})
    config: dict = field(default_factory=dict)
    logs: deque = field(default_factory=lambda: deque(maxlen=1000))
    _log_lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, msg):
        ts = time.strftime('%H:%M:%S')
        entry = f"[{ts}] {msg}"
        with self._log_lock:
            self.logs.append(entry)
        logger.info(f"[{self.protocol}] {msg}")

    def get_recent_logs(self, n=100):
        """Return last N log entries safely without holding the lock long."""
        with self._log_lock:
            return list(self.logs)[-n:]

    def should_stop(self):
        if not self.running:
            return True
        if self.duration > 0 and (time.time() - self.start_time) >= self.duration:
            self.running = False
            self.log(f"Duration {self.duration}s reached — stopping")
            return True
        return False

    def elapsed(self):
        return int(time.time() - self.start_time) if self.start_time else 0

    def remaining(self):
        if self.duration <= 0:
            return -1  # indefinite
        left = self.duration - self.elapsed()
        return max(0, left)


class TrafficEngine:
    def __init__(self):
        self.jobs: dict[str, TrafficJob] = {}
        self._lock = threading.Lock()

    def get_status(self):
        # Snapshot job references under lock, serialize outside to avoid contention
        with self._lock:
            jobs_snapshot = list(self.jobs.items())

        result = {}
        for proto, job in jobs_snapshot:
            result[proto] = {
                "running": job.running,
                "stats": dict(job.stats),
                "config": dict(job.config),
                "logs": job.get_recent_logs(100),
                "elapsed": job.elapsed(),
                "remaining": job.remaining(),
                "duration": job.duration,
            }
        return result

    def start_job(self, protocol, config):
        # Support flow IDs: "http_2" → handler "_run_http", job key "http_2"
        flow_id = config.pop('flow_id', None)
        job_key = f"{protocol}_{flow_id}" if flow_id else protocol

        with self._lock:
            if job_key in self.jobs and self.jobs[job_key].running:
                return False, f"{job_key} already running"

            duration = int(config.pop('duration', 0))
            job = TrafficJob(protocol=job_key, config=config,
                             duration=duration, start_time=time.time())
            job.running = True
            self.jobs[job_key] = job

        # Look up handler by base protocol name (strip _N suffix)
        handler = getattr(self, f'_run_{protocol}', None)
        if not handler:
            job.running = False
            return False, f"Unknown protocol: {protocol}"

        thread = threading.Thread(target=self._wrapped_run,
                                  args=(handler, job), daemon=True, name=f"traffic-{job_key}")
        job.thread = thread
        thread.start()
        dur_str = f" for {duration}s" if duration > 0 else " (indefinite)"
        label = f"{protocol} (flow {flow_id})" if flow_id else protocol
        return True, f"{label} started{dur_str}"

    def _get_timing(self, cfg):
        """Return (interval, burst_count, burst_pause) from config."""
        rate_pps = float(cfg.get('rate_pps', 0))
        if rate_pps > 0:
            interval = 1.0 / rate_pps
        else:
            interval = float(cfg.get('interval', 1))
        burst_enabled = cfg.get('burst_enabled', False)
        burst_count = int(cfg.get('burst_count', 5)) if burst_enabled else 1
        burst_pause = float(cfg.get('burst_pause', 2)) if burst_enabled else interval
        return interval, burst_count, burst_pause

    def _wrapped_run(self, handler, job):
        try:
            handler(job)
        except Exception as e:
            job.log(f"Fatal error: {e}")
            job.stats['errors'] += 1
        finally:
            job.running = False

    def stop_job(self, protocol):
        with self._lock:
            # Direct match (e.g., "http" or "http_2")
            if protocol in self.jobs and self.jobs[protocol].running:
                self.jobs[protocol].running = False
                return True, f"{protocol} stopping"
            # Stop all flows of a base protocol (e.g., "http" stops "http_1", "http_2")
            stopped = []
            for key, job in self.jobs.items():
                if key.startswith(protocol + '_') and job.running:
                    job.running = False
                    stopped.append(key)
            if stopped:
                return True, f"Stopping {', '.join(stopped)}"
            return False, f"{protocol} not running"

    def stop_all(self):
        with self._lock:
            for job in self.jobs.values():
                job.running = False

    def clear_stats(self):
        with self._lock:
            for job in self.jobs.values():
                job.stats = {"bytes_sent": 0, "bytes_recv": 0, "requests": 0, "errors": 0}

    @staticmethod
    def _get_proxy_url(cfg):
        """Build proxy URL from config if proxy is enabled."""
        proxy = cfg.get('_proxy')
        if not proxy or not proxy.get('enabled'):
            return None
        ptype = proxy.get('type', 'http')
        host = proxy.get('host', '')
        port = proxy.get('port', 8080)
        user = proxy.get('username', '')
        pwd = proxy.get('password', '')
        if not host:
            return None
        auth = f"{user}:{pwd}@" if user else ""
        if ptype == 'socks5':
            return f"socks5h://{auth}{host}:{port}"
        return f"http://{auth}{host}:{port}"

    @staticmethod
    def _get_proxy_socks_params(cfg):
        """Return (type, host, port, username, password) for SOCKS proxy, or None."""
        proxy = cfg.get('_proxy')
        if not proxy or not proxy.get('enabled'):
            return None
        if proxy.get('type') != 'socks5':
            return None
        return (socks.SOCKS5, proxy['host'], int(proxy.get('port', 1080)),
                proxy.get('username') or None, proxy.get('password') or None)

    # ─── HTTP / HTTPS ───────────────────────────────────────

    def _run_https(self, job: TrafficJob):
        cfg = job.config
        if cfg.get('highcps_mode', True):
            return self._run_ab(job, 'https')
        if cfg.get('browser_mode'):
            url = cfg.get('url', 'https://server/')
            if not url.startswith('https'):
                url = url.replace('http://', 'https://')
            return self._run_browser_mode(job, [url], ignore_ssl=cfg.get('ignore_ssl', False))

        url = cfg.get('url', 'https://server/')
        if not url.startswith('https'):
            url = url.replace('http://', 'https://')
        method = cfg.get('method', 'GET').upper()
        interval, burst_count, burst_pause = self._get_timing(cfg)
        verify_ssl = not cfg.get('ignore_ssl', False)
        data_size_kb = int(cfg.get('data_size_kb', 0))
        upload = cfg.get('upload', False)
        random_size = cfg.get('random_size', False)
        use_http2 = cfg.get('http2', False)
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)

        proxy_url = self._get_proxy_url(cfg)
        proto_label = "HTTP/2" if use_http2 else "HTTPS"
        burst_str = f" burst={burst_count}x pause={burst_pause}s" if burst_count > 1 else ""
        proxy_str = f" proxy={proxy_url}" if proxy_url else ""
        job.log(f"{proto_label} {method} {url} interval={interval:.3f}s{burst_str} DSCP={dscp}(TOS={tos}){proxy_str}")

        if use_http2:
            sock_opts = []
            if tos > 0:
                sock_opts = [(socket.IPPROTO_IP, socket.IP_TOS, tos)]
            _cur_src_h2 = None

            def _make_h2_client(src_ip=None):
                t_kwargs = {}
                if sock_opts:
                    t_kwargs['socket_options'] = sock_opts
                if proxy_url:
                    t_kwargs['proxy'] = proxy_url
                if src_ip:
                    t_kwargs['local_address'] = src_ip
                transport = httpx.HTTPTransport(**t_kwargs) if t_kwargs else None
                return httpx.Client(http2=True, verify=verify_ssl, timeout=60,
                                    transport=transport, proxy=proxy_url if (proxy_url and not t_kwargs.get('proxy')) else None)

            src_addr = _get_source_address()
            client = _make_h2_client(src_addr[0] if src_addr else None)
            try:
                while not job.should_stop():
                    for _ in range(burst_count):
                        if job.should_stop():
                            break
                        # Rotate source IP each request
                        new_src = _get_source_address()
                        if new_src != _cur_src_h2:
                            _cur_src_h2 = new_src
                            client.close()
                            client = _make_h2_client(new_src[0] if new_src else None)
                        sent_bytes = 0
                        recv_bytes = 0
                        req_url = url
                        try:
                            cur_size_kb = random.randint(1, max(data_size_kb, 1024)) if random_size else data_size_kb
                            headers = _browser_headers(url)

                            if upload and cur_size_kb > 0:
                                data = os.urandom(cur_size_kb * 1024)
                                resp = client.post(url, content=data, headers=headers)
                                sent_bytes = len(data)
                                recv_bytes = len(resp.content)
                                job.stats['bytes_sent'] += sent_bytes
                            elif method == 'GET':
                                if random_size:
                                    rand_mb = random.randint(1, 100)
                                    base = url.rsplit('/generate/', 1)[0] if '/generate/' in url else url.rstrip('/')
                                    req_url = f"{base}/generate/{rand_mb}"
                                resp = client.get(req_url, headers=headers)
                                recv_bytes = len(resp.content)
                                job.stats['bytes_recv'] += recv_bytes
                            else:
                                data = os.urandom(cur_size_kb * 1024) if cur_size_kb > 0 else b''
                                resp = client.request(method, url, content=data, headers=headers)
                                sent_bytes = len(data)
                                recv_bytes = len(resp.content)
                                job.stats['bytes_sent'] += sent_bytes
                                job.stats['bytes_recv'] += recv_bytes

                            job.stats['requests'] += 1
                            job.log(f"{method} {req_url} → {resp.status_code} ({resp.http_version}) | sent={sent_bytes}B recv={recv_bytes}B")
                        except Exception as e:
                            job.stats['errors'] += 1
                            job.log(f"Error: {req_url} — {e}")

                        if burst_count == 1:
                            time.sleep(interval)
                    if burst_count > 1:
                        job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                        time.sleep(burst_pause)
            finally:
                client.close()
        else:
            _cur_src = None  # track current source IP for rotation

            def _make_session(src_addr=None):
                s = requests.Session()
                adapter = DscpHTTPAdapter(tos=tos, source_address=src_addr)
                s.mount('https://', adapter)
                s.mount('http://', adapter)
                if proxy_url:
                    s.proxies = {'https': proxy_url, 'http': proxy_url}
                return s

            session = _make_session(_get_source_address())

            while not job.should_stop():
                for _ in range(burst_count):
                    if job.should_stop():
                        break
                    # Rotate source IP each request
                    new_src = _get_source_address()
                    if new_src != _cur_src:
                        _cur_src = new_src
                        session.close()
                        session = _make_session(new_src)
                    sent_bytes = 0
                    recv_bytes = 0
                    req_url = url
                    try:
                        cur_size_kb = random.randint(1, max(data_size_kb, 1024)) if random_size else data_size_kb
                        headers = _browser_headers(url)

                        if upload and cur_size_kb > 0:
                            data = os.urandom(cur_size_kb * 1024)
                            resp = session.post(url, data=data, headers=headers, verify=verify_ssl, timeout=30)
                            sent_bytes = len(data)
                            recv_bytes = len(resp.content)
                            job.stats['bytes_sent'] += sent_bytes
                        elif method == 'GET':
                            if random_size:
                                rand_mb = random.randint(1, 100)
                                base = url.rsplit('/generate/', 1)[0] if '/generate/' in url else url.rstrip('/')
                                req_url = f"{base}/generate/{rand_mb}"
                            resp = session.get(req_url, headers=headers, verify=verify_ssl, timeout=60, stream=True)
                            recv_bytes = len(resp.content)
                            job.stats['bytes_recv'] += recv_bytes
                        else:
                            data = os.urandom(cur_size_kb * 1024) if cur_size_kb > 0 else b''
                            resp = session.request(method, url, data=data, headers=headers, verify=verify_ssl, timeout=30)
                            sent_bytes = len(data)
                            recv_bytes = len(resp.content)
                            job.stats['bytes_sent'] += sent_bytes
                            job.stats['bytes_recv'] += recv_bytes

                        job.stats['requests'] += 1
                        job.log(f"{method} {req_url} → {resp.status_code} | sent={sent_bytes}B recv={recv_bytes}B")
                    except Exception as e:
                        job.stats['errors'] += 1
                        job.log(f"Error: {req_url} — {e}")

                    if burst_count == 1:
                        time.sleep(interval)
                if burst_count > 1:
                    job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                    time.sleep(burst_pause)
        job.log("Stopped")

    # ─── HTTP Plain (port 9999) ────────────────────────────

    def _run_http_plain(self, job: TrafficJob):
        """HTTP requests to the plain HTTP server on port 9999 (App-ID: web-browsing)."""
        cfg = job.config
        if cfg.get('highcps_mode', True):
            return self._run_ab(job, 'http')
        if cfg.get('browser_mode'):
            host = cfg.get('host', 'server')
            port = int(cfg.get('port', 9999))
            return self._run_browser_mode(job, [f"http://{host}:{port}"], ignore_ssl=False)

        host = cfg.get('host', 'server')
        port = int(cfg.get('port', 9999))
        method = cfg.get('method', 'GET').upper()
        data_size_kb = int(cfg.get('data_size_kb', 1))
        interval, burst_count, burst_pause = self._get_timing(cfg)
        random_size = cfg.get('random_size', False)
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)

        proxy_url = self._get_proxy_url(cfg)
        base_url = f"http://{host}:{port}"
        burst_str = f" burst={burst_count}x pause={burst_pause}s" if burst_count > 1 else ""
        proxy_str = f" proxy={proxy_url}" if proxy_url else ""
        job.log(f"HTTP {method} {base_url} data_size={data_size_kb}KB interval={interval:.3f}s{burst_str} DSCP={dscp}(TOS={tos}){proxy_str}")

        _cur_src = None

        def _make_session(src_addr=None):
            s = requests.Session()
            adapter = DscpHTTPAdapter(tos=tos, source_address=src_addr, max_retries=3)
            s.mount('http://', adapter)
            s.mount('https://', adapter)
            if proxy_url:
                s.proxies = {'http': proxy_url, 'https': proxy_url}
            return s

        session = _make_session(_get_source_address())

        while not job.should_stop():
            for _ in range(burst_count):
                if job.should_stop():
                    break
                new_src = _get_source_address()
                if new_src != _cur_src:
                    _cur_src = new_src
                    session.close()
                    session = _make_session(new_src)
                sent_bytes = 0
                recv_bytes = 0
                try:
                    cur_size_kb = random.randint(1, max(data_size_kb, 100)) if random_size else data_size_kb
                    headers = _browser_headers(base_url)

                    if method == 'POST':
                        data = os.urandom(cur_size_kb * 1024)
                        resp = session.post(f"{base_url}/upload", data=data, headers=headers, timeout=30)
                        sent_bytes = len(data)
                        recv_bytes = len(resp.content)
                        job.stats['bytes_sent'] += sent_bytes
                    elif method == 'GET' and cur_size_kb > 0:
                        resp = session.get(f"{base_url}/download?size={cur_size_kb}", headers=headers, timeout=60)
                        recv_bytes = len(resp.content)
                    else:
                        resp = session.get(base_url, headers=headers, timeout=30)
                        recv_bytes = len(resp.content)

                    job.stats['bytes_recv'] += recv_bytes
                    job.stats['requests'] += 1
                    job.log(f"HTTP {method} {base_url} → {resp.status_code} | sent={sent_bytes}B recv={recv_bytes}B")
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"HTTP error: {base_url} — {e}")
                    time.sleep(5)  # back off on errors

                if burst_count == 1:
                    time.sleep(max(interval, 1))
            if burst_count > 1:
                job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                time.sleep(burst_pause)
        job.log("Stopped")

    # ─── DNS (port 9998) ────────────────────────────────────

    def _run_dns(self, job: TrafficJob):
        """Send DNS queries using dig (App-ID: dns)."""
        cfg = job.config
        host = cfg.get('host', 'server')
        port = int(cfg.get('port', 53))
        domains_raw = cfg.get('domains', 'google.com\namazon.com\nmicrosoft.com\ngithub.com\ncloudflare.com')
        domains_raw = domains_raw.replace('\\n', '\n').replace(',', '\n')
        domains = [d.strip() for d in domains_raw.split('\n') if d.strip()]
        if not domains:
            domains = ['google.com']
        interval, burst_count, burst_pause = self._get_timing(cfg)
        dscp = cfg.get('dscp', 'BE')
        burst_str = f" burst={burst_count}x pause={burst_pause}s" if burst_count > 1 else ""
        job.log(f"DNS (dig) → @{host}:{port} domains={len(domains)} interval={interval:.3f}s{burst_str} DSCP={dscp}")

        domain_idx = 0
        while not job.should_stop():
            for _ in range(burst_count):
                if job.should_stop():
                    break
                domain = domains[domain_idx % len(domains)]
                domain_idx += 1
                try:
                    cmd = ['dig', f'@{host}', '-p', str(port), domain, 'A',
                           '+noedns', '+timeout=3', '+tries=1', '+noall', '+answer', '+stats']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    output = result.stdout.strip()
                    job.stats['requests'] += 1
                    # Parse answer lines and stats
                    lines = output.split('\n') if output else []
                    answer_lines = [l for l in lines if l and not l.startswith(';;')]
                    stat_lines = [l for l in lines if l.startswith(';;')]
                    # Extract msg size from stats (;; MSG SIZE  rcvd: 56)
                    query_size = 40 + len(domain)
                    resp_size = 0
                    for sl in stat_lines:
                        if 'rcvd' in sl:
                            try:
                                resp_size = int(sl.split('rcvd:')[1].strip())
                            except (ValueError, IndexError):
                                resp_size = len(output)
                    job.stats['bytes_sent'] += query_size
                    job.stats['bytes_recv'] += max(resp_size, len(output))
                    if result.returncode == 0 and answer_lines:
                        # Extract IPs from answer lines (last field)
                        ips = [l.split()[-1] for l in answer_lines if len(l.split()) >= 5]
                        job.log(f"DNS {domain} → @{host}:{port} | answers={len(answer_lines)} [{', '.join(ips[:3])}]")
                    elif result.returncode == 0:
                        job.stats['errors'] += 1
                        job.log(f"DNS {domain} → @{host}:{port} | no answer")
                    else:
                        job.stats['errors'] += 1
                        err = result.stderr.strip().split('\n')[0] if result.stderr.strip() else 'failed'
                        job.log(f"DNS {domain} → @{host}:{port} | {err}")
                except subprocess.TimeoutExpired:
                    job.stats['errors'] += 1
                    job.log(f"DNS {domain} → @{host}:{port} | timeout")
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"DNS error: {domain} — {e}")
                if burst_count == 1:
                    time.sleep(interval)
            if burst_count > 1:
                job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                time.sleep(burst_pause)

        job.log("Stopped")

    # ─── iperf3 ───────────────────────────────────────────

    def _run_iperf(self, job: TrafficJob):
        cfg = job.config
        host = cfg.get('host', 'server')
        port = int(cfg.get('port', 5201))
        proto = cfg.get('protocol', 'TCP').lower()
        bandwidth = cfg.get('bandwidth', '100M')
        parallel = int(cfg.get('parallel', 1))
        reverse = cfg.get('reverse', False)
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)
        duration = job.duration if job.duration > 0 else 3600

        cmd = ['iperf3', '-c', host, '-p', str(port), '-b', bandwidth,
               '-t', str(duration), '-P', str(parallel)]
        if proto == 'udp':
            cmd.append('-u')
        if reverse:
            cmd.append('-R')
        if tos > 0:
            cmd.extend(['-S', str(tos)])

        job.log(f"iperf3 {proto.upper()} → {host}:{port} bw={bandwidth} "
                f"parallel={parallel} reverse={reverse} duration={duration}s")

        retries = 0
        max_retries = 5
        while not job.should_stop():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                # Stream stdout lines in real-time for live activity logs
                while not job.should_stop() and proc.poll() is None:
                    line = proc.stdout.readline()
                    if line:
                        stripped = line.strip()
                        # Log interval lines (contain transfer stats) and summary
                        if stripped and ('sec' in stripped or 'sender' in stripped or 'receiver' in stripped):
                            job.log(f"iperf3 :{port} | {stripped}")
                            retries = 0  # reset on successful data
                    else:
                        time.sleep(0.5)
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=5)
                # Read any remaining output
                remaining = proc.stdout.read()
                stderr = proc.stderr.read()

                if remaining:
                    for line in remaining.split('\n'):
                        stripped = line.strip()
                        if stripped and ('sec' in stripped or 'sender' in stripped or 'receiver' in stripped):
                            job.log(f"iperf3 :{port} | {stripped}")

                # On transient errors, retry same port after brief wait
                if proc.returncode != 0 and stderr:
                    err_lower = stderr.lower()
                    if any(s in err_lower for s in ['server is busy', 'control socket has closed',
                            'unable to receive parameters', 'server side protocol']):
                        retries += 1
                        if retries > max_retries:
                            job.log(f"iperf3 :{port} — too many retries, giving up")
                            break
                        job.log(f"iperf3 :{port} — server busy, retrying in 3s ({retries}/{max_retries})")
                        time.sleep(3)
                        continue
                    elif any(s in err_lower for s in ['connection refused', 'unable to connect', 'no route to host']):
                        job.log(f"iperf3 :{port} — cannot reach server ({stderr.strip()[:80]})")
                        break
                    job.log(f"iperf3 :{port} error: {stderr[:300]}")

                job.log(f"iperf3 done on port {port} (exit={proc.returncode})")
                break
            except Exception as e:
                job.stats['errors'] += 1
                job.log(f"iperf3 error on port {port}: {e}")
                break

        job.log("Stopped")


    # ─── FTP ────────────────────────────────────────────────

    def _run_ftp(self, job: TrafficJob):
        cfg = job.config
        host = cfg.get('host', 'server')
        port = int(cfg.get('port', 21))
        username = cfg.get('username', 'anonymous')
        password = cfg.get('password', '')
        filename = cfg.get('filename', 'testfile_100mb.bin')
        random_size = cfg.get('random_size', False)
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)
        ftp_files = ['testfile_100mb.bin']

        socks_params = self._get_proxy_socks_params(cfg)
        proxy_url = self._get_proxy_url(cfg)
        proxy_str = f" proxy={proxy_url}" if proxy_url else ""
        job.log(f"FTP continuous download from {host}:{port} random_size={random_size} DSCP={dscp}(TOS={tos}){proxy_str}")

        if proxy_url and not socks_params:
            job.log("Note: HTTP proxy not supported for FTP — use SOCKS5 proxy instead")

        while not job.should_stop():
            try:
                ftp = ftplib.FTP()
                if socks_params:
                    # Create SOCKS5-wrapped socket for FTP
                    sock = socks.socksocket()
                    sock.set_proxy(*socks_params)
                    sock.connect((host, port))
                    sock.settimeout(30)
                    ftp.sock = sock
                    ftp.af = sock.family
                    ftp.file = sock.makefile('r', encoding=ftp.encoding)
                    ftp.welcome = ftp.getresp()
                else:
                    ftp.connect(host, port, timeout=30)
                if tos > 0:
                    _set_tos(ftp.sock, tos)
                ftp.login(username, password)
                ftp.set_pasv(True)

                cur_file = random.choice(ftp_files) if random_size else filename
                size = ftp.size(cur_file) or 0
                job.log(f"Connected — downloading {cur_file} ({size} bytes)")

                bytes_recv = 0
                last_log_bytes = 0
                LOG_INTERVAL = 1024 * 1024  # log every 1MB

                def callback(data):
                    nonlocal bytes_recv, last_log_bytes
                    if job.should_stop():
                        raise StopIteration("Duration reached")
                    bytes_recv += len(data)
                    job.stats['bytes_recv'] += len(data)
                    if bytes_recv - last_log_bytes >= LOG_INTERVAL:
                        pct = f" ({bytes_recv * 100 // size}%)" if size > 0 else ""
                        job.log(f"FTP {cur_file} ← recv={bytes_recv}B{pct}")
                        last_log_bytes = bytes_recv

                try:
                    ftp.retrbinary(f'RETR {cur_file}', callback, blocksize=65536)
                except StopIteration:
                    pass

                job.stats['requests'] += 1
                job.log(f"FTP {cur_file} ← download complete: {bytes_recv}B")
                ftp.quit()
            except StopIteration:
                break
            except Exception as e:
                job.stats['errors'] += 1
                job.log(f"FTP error: {e}")
                time.sleep(2)

            if not job.should_stop():
                job.log("Restarting download (continuous)")
                time.sleep(0.5)

        job.log("Stopped")

    # ─── SSH ────────────────────────────────────────────────

    def _run_ssh(self, job: TrafficJob):
        """SSH via sshpass + native ssh command — avoids paramiko issues."""
        cfg = job.config
        host = cfg.get('host', 'server')
        port = int(cfg.get('port', 2222))
        username = cfg.get('username', 'testuser')
        password = cfg.get('password', 'testpass')
        command = cfg.get('command', 'uptime')
        interval, burst_count, burst_pause = self._get_timing(cfg)
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)

        socks_params = self._get_proxy_socks_params(cfg)
        proxy_url = self._get_proxy_url(cfg)
        burst_str = f" burst={burst_count}x pause={burst_pause}s" if burst_count > 1 else ""
        proxy_str = f" proxy={proxy_url}" if proxy_url else ""
        job.log(f"SSH {username}@{host}:{port} cmd='{command}' interval={interval:.3f}s{burst_str} DSCP={dscp}(TOS={tos}){proxy_str}")

        ssh_opts = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'ConnectTimeout=10',
            '-o', f'ServerAliveInterval=15',
            '-p', str(port),
        ]

        # Add proxy command for SSH tunneling
        proxy_cfg = cfg.get('_proxy')
        if proxy_cfg and proxy_cfg.get('enabled') and proxy_cfg.get('host'):
            p_host = proxy_cfg['host']
            p_port = proxy_cfg.get('port', 1080)
            if proxy_cfg.get('type') == 'socks5':
                # Use nc with SOCKS5 proxy (netcat-openbsd supports -X 5 -x)
                proxy_cmd = f"nc -X 5 -x {p_host}:{p_port} %h %p"
                ssh_opts.extend(['-o', f'ProxyCommand={proxy_cmd}'])
            else:
                # HTTP CONNECT proxy
                proxy_cmd = f"nc -X connect -x {p_host}:{p_port} %h %p"
                ssh_opts.extend(['-o', f'ProxyCommand={proxy_cmd}'])

        while not job.should_stop():
            for _ in range(burst_count):
                if job.should_stop():
                    break
                try:
                    cmd = ['sshpass', '-p', password, 'ssh'] + ssh_opts + [
                        f'{username}@{host}', command
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    out = result.stdout.strip()
                    err = result.stderr.strip()
                    job.stats['requests'] += 1
                    job.stats['bytes_recv'] += len(out)
                    job.log(f"SSH {username}@{host} $ {command} → exit={result.returncode} | recv={len(out)}B | {out[:150]}")
                    if err and result.returncode != 0:
                        job.log(f"SSH stderr: {err[:200]}")
                        job.stats['errors'] += 1
                except subprocess.TimeoutExpired:
                    job.stats['errors'] += 1
                    job.log(f"SSH timeout: {username}@{host}:{port}")
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"SSH error: {username}@{host}:{port} — {e}")
                if burst_count == 1:
                    time.sleep(interval)
            if burst_count > 1:
                job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                time.sleep(burst_pause)

        job.log("Stopped")

    # ─── External HTTPS ────────────────────────────────────

    def _run_ext_https(self, job: TrafficJob):
        cfg = job.config
        # Support multi-URL: 'urls' textarea (newline/comma separated) or legacy 'url' field
        raw = cfg.get('urls', cfg.get('url', 'https://www.google.com'))
        urls = [u.strip() for u in raw.replace(',', '\n').split('\n') if u.strip()]
        if cfg.get('browser_mode') and urls:
            return self._run_browser_mode(job, urls, ignore_ssl=cfg.get('ignore_ssl', False))
        if not urls:
            job.log("No URLs configured")
            return
        method = cfg.get('method', 'GET').upper()
        interval, burst_count, burst_pause = self._get_timing(cfg)
        verify_ssl = not cfg.get('ignore_ssl', False)
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)

        proxy_url = self._get_proxy_url(cfg)
        burst_str = f" burst={burst_count}x pause={burst_pause}s" if burst_count > 1 else ""
        proxy_str = f" proxy={proxy_url}" if proxy_url else ""
        job.log(f"External HTTPS {method} → {len(urls)} URL(s) interval={interval:.3f}s{burst_str} DSCP={dscp}(TOS={tos}){proxy_str}")
        for i, u in enumerate(urls):
            job.log(f"  URL[{i}]: {u}")

        _cur_src = None

        def _make_session(src_addr=None):
            s = requests.Session()
            adapter = DscpHTTPAdapter(tos=tos, source_address=src_addr)
            s.mount('http://', adapter)
            s.mount('https://', adapter)
            if proxy_url:
                s.proxies = {'https': proxy_url, 'http': proxy_url}
            return s

        session = _make_session(_get_source_address())

        url_index = 0
        while not job.should_stop():
            for _ in range(burst_count):
                if job.should_stop():
                    break
                # Rotate source IP each request
                new_src = _get_source_address()
                if new_src != _cur_src:
                    _cur_src = new_src
                    session.close()
                    session = _make_session(new_src)
                url = urls[url_index % len(urls)]
                url_index += 1
                try:
                    headers = _browser_headers(url)
                    if method == 'GET':
                        resp = session.get(url, headers=headers, verify=verify_ssl, timeout=30)
                    else:
                        resp = session.request(method, url, headers=headers, verify=verify_ssl, timeout=30)
                    job.stats['bytes_recv'] += len(resp.content)
                    job.stats['requests'] += 1
                    job.log(f"{method} {resp.status_code} — {len(resp.content)}B ({url})")
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"Error: {url} — {e}")
                if burst_count == 1:
                    time.sleep(interval)
            if burst_count > 1:
                job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                time.sleep(burst_pause)
        job.log("Stopped")

    # ─── Browser Mode (Playwright) ────────────────────────

    def _run_browser_mode(self, job, urls, ignore_ssl=True):
        """Shared Playwright browser mode — real browser with authentic L7 headers/TLS."""
        from playwright.sync_api import sync_playwright

        cfg = job.config
        browser_choice = cfg.get('browser_type', 'Random')
        interval, burst_count, burst_pause = self._get_timing(cfg)

        proxy_url = self._get_proxy_url(cfg)
        proxy_cfg = None
        if proxy_url:
            proxy_cfg = {"server": proxy_url}
            proxy_data = cfg.get('_proxy', {})
            if proxy_data.get('username'):
                proxy_cfg["username"] = proxy_data["username"]
                proxy_cfg["password"] = proxy_data.get("password", "")

        burst_str = f" burst={burst_count}x pause={burst_pause}s" if burst_count > 1 else ""
        proxy_str = f" proxy={proxy_url}" if proxy_url else ""
        job.log(f"Browser mode: {browser_choice} → {len(urls)} URL(s) interval={interval:.1f}s{burst_str}{proxy_str}")

        with sync_playwright() as p:
            browser_map = {'Chromium': p.chromium, 'Firefox': p.firefox, 'WebKit': p.webkit}
            if browser_choice == 'Random':
                browser_list = list(browser_map.items())
            else:
                browser_list = [(browser_choice, browser_map.get(browser_choice, p.chromium))]

            url_index = 0
            while not job.should_stop():
                # Pick browser — rotate on each cycle when Random
                b_name, b_type = random.choice(browser_list)
                try:
                    launch_args = {'headless': True}
                    if b_name == 'Chromium':
                        launch_args['args'] = ['--no-sandbox', '--disable-setuid-sandbox']
                    elif b_name == 'Firefox':
                        launch_args['firefox_user_prefs'] = {'security.sandbox.content.level': 0}
                    browser = b_type.launch(**launch_args)
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"Failed to launch {b_name}: {e}")
                    time.sleep(5)
                    continue

                try:
                    ctx_kwargs = {"ignore_https_errors": ignore_ssl}
                    if proxy_cfg:
                        ctx_kwargs["proxy"] = proxy_cfg
                    context = browser.new_context(**ctx_kwargs)
                    page = context.new_page()

                    for _ in range(burst_count):
                        if job.should_stop():
                            break
                        url = urls[url_index % len(urls)]
                        url_index += 1
                        try:
                            resp = page.goto(url, wait_until='load', timeout=30000)
                            status = resp.status if resp else 0
                            content = page.content()
                            recv_bytes = len(content.encode('utf-8'))
                            job.stats['bytes_recv'] += recv_bytes
                            job.stats['requests'] += 1
                            job.log(f"{b_name} {url} → {status} | recv={recv_bytes}B")
                        except Exception as e:
                            job.stats['errors'] += 1
                            job.log(f"{b_name} error: {url} — {e}")

                        if burst_count == 1:
                            time.sleep(interval)

                    if burst_count > 1:
                        job.log(f"Burst of {burst_count} complete, pausing {burst_pause}s")
                        time.sleep(burst_pause)
                finally:
                    try:
                        browser.close()
                    except Exception:
                        pass

        job.log("Browser mode stopped")

    # ─── Multicast ─────────────────────────────────────────

    def _run_multicast(self, job: TrafficJob):
        """Multicast traffic: IGMP join + receive UDP multicast from server."""
        cfg = job.config
        group = cfg.get('group', '239.1.1.1')
        port = int(cfg.get('port', 5004))
        ttl = int(cfg.get('ttl', 32))
        packet_size = int(cfg.get('packet_size', 1200))
        target_pps = int(cfg.get('target_pps', 100))
        dscp = cfg.get('dscp', 'AF41')
        server = cfg.get('host', os.environ.get('SERVER_HOST', 'server'))

        # Extended stats
        job.stats['pps'] = 0
        job.stats['loss_pct'] = 0.0

        # Step 1: Tell the server to start sending multicast
        try:
            resp = requests.post(f'http://{server}:5000/api/multicast/start', json={
                'group': group, 'port': port, 'ttl': ttl,
                'packet_size': packet_size, 'pps': target_pps, 'dscp': dscp
            }, timeout=10)
            result = resp.json()
            job.log(f"Server multicast sender: {result.get('message', 'started')}")
        except Exception as e:
            job.log(f"WARNING: Could not start server multicast sender: {e}")
            job.log("Continuing — server may need manual multicast configuration")

        # Step 2: Create multicast receiver socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))

        # IGMP join
        mreq = struct.pack('4sl', socket.inet_aton(group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(2.0)

        job.log(f"Multicast IGMP JOIN {group}:{port} TTL={ttl} target_pps={target_pps} DSCP={dscp}")
        job.log(f"NOTE: Firewall must have PIM/IGMP configured for multicast routing")

        # Step 3: Receive loop with per-second stats
        window_start = time.time()
        window_count = 0
        last_seq = -1

        try:
            while not job.should_stop():
                try:
                    data, addr = sock.recvfrom(65535)
                    job.stats['bytes_recv'] += len(data)
                    job.stats['requests'] += 1
                    window_count += 1

                    # Parse sequence number from first 4 bytes for loss detection
                    if len(data) >= 4:
                        seq = struct.unpack('!I', data[:4])[0]
                        if last_seq >= 0 and seq > last_seq + 1:
                            lost = seq - last_seq - 1
                            job.stats['errors'] += lost
                        last_seq = seq

                except socket.timeout:
                    pass

                now = time.time()
                if now - window_start >= 1.0:
                    elapsed = now - window_start
                    pps = window_count / elapsed
                    total = job.stats['requests'] + job.stats['errors']
                    loss = (job.stats['errors'] / total * 100) if total > 0 else 0
                    job.stats['pps'] = round(pps, 1)
                    job.stats['loss_pct'] = round(loss, 2)
                    job.log(f"Multicast {group}:{port} | {pps:.0f} pps, "
                            f"recv={job.stats['requests']} loss={loss:.1f}%")
                    window_start = now
                    window_count = 0
        finally:
            # Cleanup: leave group, stop server sender
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except Exception:
                pass
            sock.close()
            try:
                requests.post(f'http://{server}:5000/api/multicast/stop', timeout=5)
            except Exception:
                pass

        job.log("Stopped")

    # ─── RTP Audio/Video ─────────────────────────────────────

    def _run_rtp(self, job: TrafficJob):
        """RTP Audio/Video via ffmpeg — generates real RTP streams for firewall App-ID testing."""
        cfg = job.config
        server = cfg.get('host', os.environ.get('SERVER_HOST', 'server'))
        mode = cfg.get('mode', 'Video Call')
        audio_codec = cfg.get('audio_codec', 'opus')
        resolution = cfg.get('resolution', '640x480')
        video_bitrate = cfg.get('video_bitrate', '1M')
        audio_bitrate = cfg.get('audio_bitrate', '64k')
        video_port = int(cfg.get('video_port', 5004))
        audio_port = int(cfg.get('audio_port', 5006))
        dscp_video = cfg.get('dscp_video', 'AF41')
        dscp_audio = cfg.get('dscp_audio', 'EF')

        running_procs = []
        iptables_rules = []

        try:
            # Set DSCP marking via iptables (ffmpeg can't set TOS on RTP output)
            if mode in ('Video Call', 'Streaming'):
                tos_v = _dscp_to_tos(dscp_video)
                if tos_v > 0:
                    rule_v = ['sudo', 'iptables', '-t', 'mangle', '-A', 'OUTPUT',
                              '-p', 'udp', '--dport', str(video_port),
                              '-j', 'TOS', '--set-tos', str(tos_v)]
                    try:
                        subprocess.run(rule_v, capture_output=True, timeout=5)
                        iptables_rules.append(rule_v)
                        job.log(f"DSCP marking: port {video_port} → {dscp_video} (TOS={tos_v})")
                    except Exception as e:
                        job.log(f"WARNING: Could not set DSCP for video: {e}")

            if mode in ('Video Call', 'Audio Only'):
                tos_a = _dscp_to_tos(dscp_audio)
                if tos_a > 0:
                    rule_a = ['sudo', 'iptables', '-t', 'mangle', '-A', 'OUTPUT',
                              '-p', 'udp', '--dport', str(audio_port),
                              '-j', 'TOS', '--set-tos', str(tos_a)]
                    try:
                        subprocess.run(rule_a, capture_output=True, timeout=5)
                        iptables_rules.append(rule_a)
                        job.log(f"DSCP marking: port {audio_port} → {dscp_audio} (TOS={tos_a})")
                    except Exception as e:
                        job.log(f"WARNING: Could not set DSCP for audio: {e}")

            # Tell server to start RTP receiver
            try:
                resp = requests.post(f'http://{server}:5000/api/rtp/receive', json={
                    'video_port': video_port, 'audio_port': audio_port, 'mode': mode
                }, timeout=10)
                result = resp.json()
                job.log(f"Server RTP receiver: {result.get('message', 'started')}")
            except Exception as e:
                job.log(f"WARNING: Could not start server RTP receiver: {e}")

            # For Video Call mode, also have the server send RTP back to us
            if mode == 'Video Call':
                try:
                    # Detect our own IP as seen by the server
                    client_ip = self._get_client_ip(server)
                    resp = requests.post(f'http://{server}:5000/api/rtp/start', json={
                        'client_ip': client_ip,
                        'video_port': video_port + 10,  # offset to avoid port conflict
                        'audio_port': audio_port + 10,
                        'resolution': resolution,
                        'video_bitrate': video_bitrate,
                        'audio_codec': audio_codec,
                        'audio_bitrate': audio_bitrate,
                    }, timeout=10)
                    result = resp.json()
                    job.log(f"Server RTP sender (bidirectional): {result.get('message', 'started')}")
                except Exception as e:
                    job.log(f"WARNING: Could not start server RTP sender: {e}")

            # Launch ffmpeg processes
            if mode in ('Video Call', 'Streaming'):
                video_cmd = [
                    'ffmpeg', '-re', '-nostdin',
                    '-f', 'lavfi', '-i', f'testsrc=size={resolution}:rate=30',
                    '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
                    '-b:v', video_bitrate, '-g', '30',
                    '-f', 'rtp', f'rtp://{server}:{video_port}?pkt_size=1200'
                ]
                try:
                    proc = subprocess.Popen(video_cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True)
                    running_procs.append(('video', proc))
                    job.log(f"RTP Video: H.264 {resolution} {video_bitrate} → "
                            f"{server}:{video_port} DSCP={dscp_video} (PID {proc.pid})")
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"ffmpeg video failed to start: {e}")

            if mode in ('Video Call', 'Audio Only'):
                if audio_codec == 'opus':
                    audio_cmd = [
                        'ffmpeg', '-re', '-nostdin',
                        '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=48000',
                        '-c:a', 'libopus', '-b:a', audio_bitrate,
                        '-f', 'rtp', f'rtp://{server}:{audio_port}?pkt_size=160'
                    ]
                else:  # g711 / pcm_alaw
                    audio_cmd = [
                        'ffmpeg', '-re', '-nostdin',
                        '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=8000',
                        '-c:a', 'pcm_alaw', '-ar', '8000', '-ac', '1',
                        '-f', 'rtp', f'rtp://{server}:{audio_port}?pkt_size=160'
                    ]
                try:
                    proc = subprocess.Popen(audio_cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True)
                    running_procs.append(('audio', proc))
                    job.log(f"RTP Audio: {audio_codec} {audio_bitrate} → "
                            f"{server}:{audio_port} DSCP={dscp_audio} (PID {proc.pid})")
                except Exception as e:
                    job.stats['errors'] += 1
                    job.log(f"ffmpeg audio failed to start: {e}")

            if not running_procs:
                job.log("ERROR: No ffmpeg processes started")
                return

            # Monitor loop — parse ffmpeg stderr for progress
            import re as _re
            last_log = time.time()
            while not job.should_stop():
                all_exited = True
                for label, proc in running_procs:
                    if proc.poll() is not None:
                        continue
                    all_exited = False

                if all_exited:
                    job.log("All ffmpeg processes exited")
                    break

                # Parse ffmpeg stderr for stats every 2 seconds
                now = time.time()
                if now - last_log >= 2.0:
                    for label, proc in running_procs:
                        if proc.poll() is not None:
                            continue
                        # Non-blocking read of stderr
                        import select
                        readable, _, _ = select.select([proc.stderr], [], [], 0)
                        lines = []
                        for stream in readable:
                            while True:
                                line = stream.readline()
                                if not line:
                                    break
                                lines.append(line.strip())

                        for line in lines:
                            # Parse: frame= 120 fps= 30 ... size= 456kB ...
                            size_match = _re.search(r'size=\s*([\d.]+)(\w+)', line)
                            if size_match:
                                size_val = float(size_match.group(1))
                                unit = size_match.group(2).lower()
                                if 'kb' in unit:
                                    size_bytes = int(size_val * 1024)
                                elif 'mb' in unit:
                                    size_bytes = int(size_val * 1024 * 1024)
                                else:
                                    size_bytes = int(size_val)
                                job.stats['bytes_sent'] = max(job.stats['bytes_sent'], size_bytes)

                            frame_match = _re.search(r'frame=\s*(\d+)', line)
                            if frame_match:
                                job.stats['requests'] = max(job.stats['requests'],
                                                            int(frame_match.group(1)))

                            bitrate_match = _re.search(r'bitrate=\s*([\d.]+)(\w+)', line)
                            if bitrate_match:
                                job.log(f"RTP {label}: {line}")

                    last_log = now

                time.sleep(0.5)

        finally:
            # Cleanup: terminate ffmpeg processes
            for label, proc in running_procs:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    job.log(f"ffmpeg {label} terminated")

            # Clean up iptables DSCP rules
            for rule in iptables_rules:
                cleanup = list(rule)
                cleanup[cleanup.index('-A')] = '-D'
                try:
                    subprocess.run(cleanup, capture_output=True, timeout=5)
                except Exception:
                    pass

            # Stop server RTP processes
            try:
                requests.post(f'http://{server}:5000/api/rtp/stop', timeout=5)
            except Exception:
                pass

        job.log("Stopped")

    @staticmethod
    def _get_client_ip(server_host):
        """Detect our IP address as seen when connecting to the server."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((server_host, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '0.0.0.0'

    # ─── PCAP Replay ───────────────────────────────────────────

    def _run_pcap_replay(self, job: TrafficJob):
        """Replay a PCAP file using tcpreplay for zero-day attack testing."""
        cfg = job.config
        pcap_file = cfg.get('pcap_file', '')
        replay_rate = float(cfg.get('replay_rate', 1.0))
        loop = cfg.get('loop', False)
        interface = cfg.get('interface', '').strip()

        if not pcap_file:
            job.log("No PCAP file specified")
            return

        pcap_path = os.path.join('/tmp/pcap_uploads', pcap_file)
        if not os.path.exists(pcap_path):
            job.log(f"PCAP file not found: {pcap_path}")
            return

        # Auto-detect interface if not specified
        if not interface:
            try:
                server = os.environ.get('SERVER_HOST', 'server')
                out = subprocess.check_output(
                    ['ip', 'route', 'get', server],
                    text=True, timeout=5)
                for part in out.split():
                    if part == 'dev':
                        idx = out.split().index('dev')
                        interface = out.split()[idx + 1]
                        break
            except Exception:
                pass
            if not interface:
                interface = 'eth0'

        file_size = os.path.getsize(pcap_path)
        job.log(f"PCAP replay: {pcap_file} ({file_size} bytes) on {interface} "
                f"rate={replay_rate}x loop={loop}")

        cmd = ['sudo', 'tcpreplay', '-i', interface]

        if replay_rate == 0:
            cmd.append('--topspeed')
        elif replay_rate != 1.0:
            cmd.extend(['--multiplier', str(replay_rate)])

        if loop:
            cmd.append('--loop=0')

        cmd.append(pcap_path)
        job.log(f"cmd: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            import select
            while not job.should_stop() and proc.poll() is None:
                readable, _, _ = select.select([proc.stdout], [], [], 0.5)
                for stream in readable:
                    line = stream.readline()
                    if line:
                        stripped = line.strip()
                        if stripped:
                            job.log(f"tcpreplay: {stripped}")
                            # Parse stats from tcpreplay output
                            if 'packets' in stripped.lower():
                                try:
                                    for word in stripped.split():
                                        if word.isdigit():
                                            job.stats['requests'] += int(word)
                                            break
                                except Exception:
                                    pass
                            if 'bytes' in stripped.lower():
                                try:
                                    for word in stripped.split():
                                        if word.isdigit():
                                            job.stats['bytes_sent'] += int(word)
                                            break
                                except Exception:
                                    pass

            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

            # Read remaining output
            remaining = proc.stdout.read()
            if remaining:
                for line in remaining.strip().split('\n'):
                    if line.strip():
                        job.log(f"tcpreplay: {line.strip()}")
                        # Parse final summary stats
                        if 'Actual' in line and 'packets' in line:
                            try:
                                parts = line.split()
                                for i, p in enumerate(parts):
                                    if 'packets' in p.lower() and i > 0:
                                        job.stats['requests'] = int(parts[i - 1].strip('()'))
                                        break
                            except Exception:
                                pass

            rc = proc.returncode
            if rc and rc not in (-15, -9):
                job.log(f"tcpreplay exited with code {rc}")
                job.stats['errors'] += 1
        except Exception as e:
            job.stats['errors'] += 1
            job.log(f"PCAP replay error: {e}")

        job.log("Stopped")

    # ─── UDP Traffic Generator ─────────────────────────────────

    def _run_udp(self, job: TrafficJob):
        """UDP traffic generator using Python sockets with per-second logging."""
        cfg = job.config
        host = cfg.get('host', os.environ.get('SERVER_HOST', 'server'))
        port = int(cfg.get('port', 5201))
        packet_size = int(cfg.get('packet_size', 512))
        target_pps = int(cfg.get('target_pps', 100))
        dscp = cfg.get('dscp', 'BE')
        tos = _dscp_to_tos(dscp)
        ramp_enabled = cfg.get('ramp_enabled', False)
        ramp_start_pps = int(cfg.get('ramp_start_pps', 10))
        ramp_steps = int(cfg.get('ramp_steps', 5))
        duration = job.duration or 60

        # Extended stats
        job.stats['pps'] = 0
        job.stats['peak_pps'] = 0
        job.stats['mbps'] = 0

        # Resolve host to verify DNS works
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
            job.log(f"Resolved {host}:{port} → {addr[0]}:{addr[1]}")
        except Exception as e:
            job.log(f"ERROR: Cannot resolve {host}:{port} — {e}")
            job.stats['errors'] += 1
            return

        ramp_str = f" ramp={ramp_start_pps}→{target_pps} in {ramp_steps} steps" if ramp_enabled else ""
        job.log(f"UDP → {host}:{port} | size={packet_size}B pps={target_pps} "
                f"DSCP={dscp}(TOS={tos}){ramp_str}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if tos > 0:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
            sock.setblocking(False)

            payload = os.urandom(packet_size)
            interval = 1.0 / max(target_pps, 1)
            window_start = time.time()
            window_count = 0
            current_pps = target_pps
            step_start = time.time()

            while not job.should_stop():
                # Ramping: recalculate current PPS based on elapsed time
                if ramp_enabled:
                    elapsed = time.time() - step_start
                    progress = min(elapsed / max(duration, 1), 1.0)
                    step_index = min(int(progress * ramp_steps), ramp_steps - 1)
                    new_pps = int(ramp_start_pps + (target_pps - ramp_start_pps) * (step_index + 1) / ramp_steps)
                    if new_pps != current_pps:
                        current_pps = new_pps
                        interval = 1.0 / max(current_pps, 1)
                        job.log(f"Ramp step {step_index + 1}/{ramp_steps}: {current_pps} PPS")

                # Send packet
                try:
                    sock.sendto(payload, (host, port))
                    job.stats['requests'] += 1
                    job.stats['bytes_sent'] += packet_size
                    window_count += 1
                except Exception as e:
                    job.stats['errors'] += 1

                # Log stats every second
                now = time.time()
                window_elapsed = now - window_start
                if window_elapsed >= 1.0:
                    pps = window_count / window_elapsed
                    mbps = (window_count * packet_size * 8) / (window_elapsed * 1_000_000)
                    job.stats['pps'] = round(pps, 1)
                    job.stats['peak_pps'] = max(job.stats.get('peak_pps', 0), pps)
                    job.stats['mbps'] = round(mbps, 2)
                    job.log(f"UDP {host}:{port} | {pps:.0f} pps, {mbps:.2f} Mbps, "
                            f"total={job.stats['requests']} errors={job.stats['errors']}")
                    window_start = now
                    window_count = 0

                # Pace to target PPS
                time.sleep(max(0, interval - 0.0001))

            sock.close()
        except Exception as e:
            job.stats['errors'] += 1
            job.log(f"UDP error: {e}")

        job.log("Stopped")

    # ─── High-CPS Engine (ab-based) ───────────────────────────

    def _run_ab(self, job: TrafficJob, proto: str):
        """High CPS testing using ab (Apache Bench). Called from _run_https and _run_http_plain."""
        cfg = job.config
        server = os.environ.get('SERVER_HOST', 'server')
        target_cps = int(cfg.get('target_cps', 100))
        concurrency = int(cfg.get('concurrency', 50))
        duration = job.duration or 60
        method = cfg.get('method', 'GET').upper()

        # Ramping config
        ramp_enabled = cfg.get('ramp_enabled', False)
        ramp_start = int(cfg.get('ramp_start_cps', 10))
        ramp_steps = int(cfg.get('ramp_steps', 5))

        # Extended stats
        job.stats['cps'] = 0
        job.stats['peak_cps'] = 0
        job.stats['avg_latency_ms'] = 0
        job.stats['p99_latency_ms'] = 0
        job.stats['connections_total'] = 0
        job.stats['connections_failed'] = 0

        if proto == 'https':
            url = cfg.get('url', f'https://{server}/')
            if not url.startswith('https'):
                url = url.replace('http://', 'https://')
        else:
            host = cfg.get('host', server)
            port = int(cfg.get('port', 9999))
            url = f"http://{host}:{port}/"

        # Run ab in 5s chunks for frequent log updates
        chunk_duration = min(5, duration)
        remaining = duration
        elapsed = 0

        if ramp_enabled:
            job.log(f"High-CPS {proto.upper()} RAMP → {url} | {ramp_start}→{target_cps} cps "
                    f"in {ramp_steps} steps, concurrency={concurrency}, duration={duration}s")
        else:
            job.log(f"High-CPS {proto.upper()} → {url} | target={target_cps} cps, "
                    f"concurrency={concurrency}, method={method}, duration={duration}s")

        while not job.should_stop() and remaining > 0:
            run_for = min(chunk_duration, remaining)

            # Calculate current CPS (ramping or fixed)
            if ramp_enabled:
                progress = min(elapsed / max(duration - chunk_duration, 1), 1.0)
                step_index = min(int(progress * ramp_steps), ramp_steps - 1)
                current_cps = int(ramp_start + (target_cps - ramp_start) * (step_index + 1) / ramp_steps)
                job.log(f"Ramp step {step_index + 1}/{ramp_steps}: {current_cps} CPS")
            else:
                current_cps = target_cps

            # ab uses -n (total requests) not rate — estimate from CPS * duration
            total_requests = current_cps * run_for
            conc = min(concurrency, total_requests)

            cmd = ['ab', '-n', str(total_requests), '-c', str(conc),
                   '-s', '30']  # 30s socket timeout
            # No -k flag = new connection per request (CPS mode)
            if method != 'GET':
                cmd.extend(['-m', method])
            if proto == 'https':
                cmd.extend(['-f', 'TLS1.2'])
            cmd.append(url)
            job.log(f"ab -n {total_requests} -c {conc} {url}")

            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                while not job.should_stop() and proc.poll() is None:
                    time.sleep(0.5)

                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=5)
                    break

                output = proc.stdout.read()
                if output:
                    chunk_stats = self._parse_ab_output(job, output)
                    cps = job.stats.get('cps', 0)
                    avg_lat = job.stats.get('avg_latency_ms', 0)
                    p99_lat = job.stats.get('p99_latency_ms', 0)
                    reqs = chunk_stats.get('chunk_requests', 0)
                    errs = chunk_stats.get('chunk_errors', 0)
                    job.log(f"{proto.upper()} {url} | {cps:.0f} cps, "
                            f"avg={avg_lat:.1f}ms p99={p99_lat:.1f}ms, "
                            f"reqs={reqs} errs={errs}")

            except Exception as e:
                job.stats['errors'] += 1
                job.log(f"ab error: {e}")

            remaining -= run_for
            elapsed += run_for

        job.log("Stopped")

    def _parse_ab_output(self, job, output):
        """Parse ab (Apache Bench) output for CPS and latency metrics. Returns chunk stats."""
        import re as _re

        chunk_requests = 0
        chunk_errors = 0

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Requests per second: 95.23 [#/sec] (mean)
            m = _re.match(r'Requests per second:\s+([\d.]+)', line)
            if m:
                cps = float(m.group(1))
                job.stats['cps'] = round(cps, 1)
                job.stats['peak_cps'] = max(job.stats.get('peak_cps', 0), cps)

            # Time per request: 10.501 [ms] (mean)
            m = _re.match(r'Time per request:\s+([\d.]+)\s+\[ms\]\s+\(mean\)$', line)
            if m:
                job.stats['avg_latency_ms'] = round(float(m.group(1)), 2)

            # Complete requests: 475
            m = _re.match(r'Complete requests:\s+(\d+)', line)
            if m:
                count = int(m.group(1))
                job.stats['requests'] += count
                job.stats['connections_total'] += count
                chunk_requests = count

            # Failed requests: 0
            m = _re.match(r'Failed requests:\s+(\d+)', line)
            if m:
                errs = int(m.group(1))
                job.stats['errors'] += errs
                job.stats['connections_failed'] += errs
                chunk_errors = errs

            # Total transferred: 48000 bytes
            m = _re.match(r'Total transferred:\s+(\d+)\s+bytes', line)
            if m:
                job.stats['bytes_recv'] += int(m.group(1))

            # Non-2xx responses: 5
            m = _re.match(r'Non-2xx responses:\s+(\d+)', line)
            if m:
                non2xx = int(m.group(1))
                job.stats['errors'] += non2xx
                job.stats['connections_failed'] += non2xx
                chunk_errors += non2xx

            # Percentile latencies: 99%    45
            m = _re.match(r'\s*99%\s+(\d+)', line)
            if m:
                job.stats['p99_latency_ms'] = float(m.group(1))

        return {'chunk_requests': chunk_requests, 'chunk_errors': chunk_errors}
