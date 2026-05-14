"""Traffic Generator Client — Flask Web UI + REST API."""
import os
import time
import socket
import logging
import subprocess
from flask import Flask, render_template, jsonify, request

from traffic_engine import TrafficEngine
from security_engine import SecurityTestEngine, CustomPatternStore
import network_shaper
from router_shaper import router_manager

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)s %(levelname)s %(message)s')

app = Flask(__name__)
engine = TrafficEngine()
custom_pattern_store = CustomPatternStore()
security_engine = SecurityTestEngine(custom_store=custom_pattern_store)

SERVER_HOST = os.environ.get('SERVER_HOST', 'server')

# Global proxy configuration
_proxy_config = {
    'enabled': False,
    'type': 'http',        # 'http' or 'socks5'
    'host': '',
    'port': 8080,
    'username': '',
    'password': '',
}


def _get_json():
    """Safely get JSON from request, returning empty dict on None."""
    return request.json or {}


@app.route('/')
def dashboard():
    return render_template('dashboard.html', server_host=SERVER_HOST)


@app.route('/api/server_host')
def get_server_host():
    return jsonify({"server_host": SERVER_HOST})


@app.route('/api/status')
def status():
    return jsonify({
        "jobs": engine.get_status(),
        "shaping": network_shaper.get_current_settings(),
    })


@app.route('/api/start', methods=['POST'])
def start_traffic():
    data = _get_json()
    protocol = data.get('protocol')
    config = data.get('config', {})
    if not protocol:
        return jsonify({"error": "protocol required"}), 400

    # Resolve proxy: per-protocol override vs global
    proxy_mode = config.pop('proxy', 'Global')
    if proxy_mode == 'Custom':
        # Per-protocol custom proxy
        custom_host = config.pop('proxy_host', '')
        if custom_host:
            config['_proxy'] = {
                'enabled': True,
                'type': config.pop('proxy_type', 'http'),
                'host': custom_host,
                'port': int(config.pop('proxy_port', 8080)),
                'username': config.pop('proxy_user', ''),
                'password': config.pop('proxy_pass', ''),
            }
        else:
            # Custom selected but no host — remove stale keys
            for k in ('proxy_type', 'proxy_port', 'proxy_user', 'proxy_pass'):
                config.pop(k, None)
    elif proxy_mode == 'Global':
        use_proxy = _proxy_config.get('enabled', False)
        if use_proxy and _proxy_config.get('host'):
            config['_proxy'] = dict(_proxy_config)
    elif proxy_mode == 'On':
        if _proxy_config.get('host'):
            config['_proxy'] = dict(_proxy_config)
    # 'Off' — no proxy

    ok, msg = engine.start_job(protocol, config)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 409


@app.route('/api/stop', methods=['POST'])
def stop_traffic():
    data = _get_json()
    protocol = data.get('protocol')
    if not protocol:
        return jsonify({"error": "protocol required"}), 400
    if protocol == 'all':
        engine.stop_all()
        return jsonify({"ok": True, "message": "Stopping all"})
    ok, msg = engine.stop_job(protocol)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 404


@app.route('/api/sudo', methods=['GET'])
def sudo_auth():
    return jsonify({"authenticated": True})


@app.route('/api/clear_stats', methods=['POST'])
def clear_stats():
    engine.clear_stats()
    return jsonify({"ok": True, "message": "Stats cleared"})


# ─── Proxy Configuration ─────────────────────────────────

@app.route('/api/proxy', methods=['GET', 'POST'])
def proxy_config():
    if request.method == 'GET':
        return jsonify(_proxy_config)
    data = _get_json()
    _proxy_config['enabled'] = bool(data.get('enabled', False))
    _proxy_config['type'] = data.get('type', 'http')
    _proxy_config['host'] = data.get('host', '')
    _proxy_config['port'] = int(data.get('port', 8080))
    _proxy_config['username'] = data.get('username', '')
    _proxy_config['password'] = data.get('password', '')
    return jsonify({"ok": True, "message": "Proxy config updated", "config": _proxy_config})


@app.route('/api/proxy/test', methods=['POST'])
def proxy_test():
    """Test proxy connectivity by making a request through the configured proxy."""
    import requests as req
    data = _get_json()
    ptype = data.get('type', _proxy_config.get('type', 'http'))
    host = data.get('host', _proxy_config.get('host', ''))
    port = int(data.get('port', _proxy_config.get('port', 8080)))
    username = data.get('username', _proxy_config.get('username', ''))
    password = data.get('password', _proxy_config.get('password', ''))

    if not host:
        return jsonify({"ok": False, "message": "Proxy host not configured"}), 400

    auth = f"{username}:{password}@" if username else ""
    if ptype == 'socks5':
        proxy_url = f"socks5h://{auth}{host}:{port}"
    else:
        proxy_url = f"http://{auth}{host}:{port}"

    try:
        resp = req.get('https://www.google.com', proxies={'https': proxy_url, 'http': proxy_url},
                       timeout=10, verify=False)
        return jsonify({"ok": True, "message": f"Proxy working — {resp.status_code} from google.com"})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Proxy test failed: {e}"}), 502


# ─── Router Link Simulation ──────────────────────────────

@app.route('/api/routers', methods=['GET'])
def list_routers():
    return jsonify(router_manager.list_routers())


@app.route('/api/routers', methods=['POST'])
def add_router():
    d = _get_json()
    name = d.get('name', '')
    ip = d.get('ip', '')
    username = d.get('username', '')
    password = d.get('password', '')
    ok, msg, data = router_manager.add_router(name, ip, username, password)
    if ok:
        return jsonify({"ok": True, "message": msg, "router": data})
    return jsonify({"ok": False, "error": msg}), 400


@app.route('/api/routers/<router_id>', methods=['DELETE'])
def remove_router(router_id):
    ok, msg = router_manager.remove_router(router_id)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 404


@app.route('/api/routers/<router_id>/connect', methods=['POST'])
def connect_router(router_id):
    ok, msg = router_manager.connect(router_id)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 400


@app.route('/api/routers/<router_id>/disconnect', methods=['POST'])
def disconnect_router(router_id):
    ok, msg = router_manager.disconnect(router_id)
    return jsonify({"ok": ok, "message": msg})


@app.route('/api/routers/<router_id>/interfaces')
def router_interfaces(router_id):
    interfaces = router_manager.discover_interfaces(router_id)
    return jsonify({"interfaces": interfaces})


@app.route('/api/routers/<router_id>/select-interface', methods=['POST'])
def router_select_interface(router_id):
    d = _get_json()
    iface = d.get('interface', '')
    ok, msg = router_manager.select_interface(router_id, iface)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 400


@app.route('/api/routers/<router_id>/mode', methods=['POST'])
def router_set_mode(router_id):
    d = _get_json()
    mode = d.get('mode', '')
    config = {
        'latency_ms': int(d.get('latency_ms', 0)),
        'jitter_ms': int(d.get('jitter_ms', 0)),
        'packet_loss_pct': float(d.get('packet_loss_pct', 0)),
        'bandwidth_mbps': int(d.get('bandwidth_mbps', 0)),
    }
    ok, msg = router_manager.apply_mode(router_id, mode, config)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 400


@app.route('/api/routers/<router_id>/status')
def router_status(router_id):
    return jsonify(router_manager.get_status(router_id))


import concurrent.futures

# Per-protocol traceroute config: args for traceroute + which config key holds the dest host
PROTO_TRACEROUTE = {
    'https':      {'args': ['-T', '-p', '443'],  'label': 'HTTPS',       'port': 443,  'host_key': 'url'},
    'iperf':      {'args': ['-T', '-p', '5201'], 'label': 'iperf3',      'port': 5201, 'host_key': 'host'},
    'http_plain': {'args': ['-T', '-p', '9999'], 'label': 'HTTP',        'port': 9999, 'host_key': 'host'},
    'dns':        {'args': ['-U', '-p', '53'],   'label': 'DNS',         'port': 53,   'host_key': 'host'},
    'ftp':        {'args': ['-T', '-p', '21'],   'label': 'FTP',         'port': 21,   'host_key': 'host'},
    'ssh':        {'args': ['-T', '-p', '2222'], 'label': 'SSH',         'port': 2222, 'host_key': 'host'},
    'hping3':     {'args': ['-I'],                'label': 'hping3',      'port': 0,    'host_key': 'host'},
    'ext_https':  {'args': ['-T', '-p', '443'],  'label': 'Ext HTTPS',   'port': 443,  'host_key': 'urls'},
}

# Cache: keyed by "proto:dest" → {'hops': [...], 'time': float}
_topo_path_cache = {}
_TOPO_CACHE_TTL = 30


def _run_traceroute(dest, extra_args=None):
    """Run traceroute to dest with optional extra args, return list of hop dicts."""
    cmd = ['sudo', 'traceroute', '-n', '-q', '1', '-w', '2', '-m', '15']
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(dest)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        hops = []
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1] if parts[1] != '*' else '*'
                rtt = parts[2] if len(parts) >= 3 and parts[1] != '*' else '--'
                hops.append({'hop': int(parts[0]), 'ip': ip, 'rtt': rtt})
        # Remove trailing timeout hops (keep at most 1 consecutive timeout)
        filtered = []
        consecutive_timeouts = 0
        for h in hops:
            if h['ip'] == '*':
                consecutive_timeouts += 1
                if consecutive_timeouts <= 1:
                    filtered.append(h)
            else:
                consecutive_timeouts = 0
                filtered.append(h)
        return filtered
    except Exception:
        return []


def _get_dest_for_proto(proto_key, job_config):
    """Extract destination host from a running job's config."""
    tc = PROTO_TRACEROUTE.get(proto_key, {})
    host_key = tc.get('host_key', 'host')

    if host_key == 'url':
        url = job_config.get('url', '')
        # Extract hostname from URL
        try:
            from urllib.parse import urlparse
            return urlparse(url).hostname or SERVER_HOST
        except Exception:
            return SERVER_HOST
    elif host_key == 'urls':
        raw = job_config.get('urls', job_config.get('url', ''))
        urls = [u.strip() for u in raw.replace(',', '\n').split('\n') if u.strip()]
        if urls:
            try:
                from urllib.parse import urlparse
                return urlparse(urls[0]).hostname or SERVER_HOST
            except Exception:
                return SERVER_HOST
        return SERVER_HOST
    else:
        return job_config.get('host', SERVER_HOST)


@app.route('/api/topology')
def topology():
    """Return topology with per-protocol traceroute paths and router state."""
    client_ip = '--'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((SERVER_HOST, 80))
        client_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Get running protocols
    status = engine.get_status()

    # Aggregate flows by base protocol
    proto_agg = {}
    for job_key, info in status.items():
        parts = job_key.split('_')
        if len(parts) >= 3 and parts[-1].isdigit():
            base = '_'.join(parts[:-1])
        elif len(parts) == 2 and parts[-1].isdigit():
            base = parts[0]
        else:
            base = job_key
        if base not in proto_agg:
            proto_agg[base] = {'running': False, 'stats': {'bytes_sent': 0, 'bytes_recv': 0, 'requests': 0, 'errors': 0}, 'config': {}}
        agg = proto_agg[base]
        if info.get('running'):
            agg['running'] = True
            if not agg['config']:
                agg['config'] = info.get('config', {})
        for k in ('bytes_sent', 'bytes_recv', 'requests', 'errors'):
            agg['stats'][k] += info.get('stats', {}).get(k, 0)

    now = time.time()
    paths = {}

    # Per-protocol traceroute for running protocols only (no default path)
    def trace_proto(proto_key, agg):
        tc = PROTO_TRACEROUTE.get(proto_key)
        if not tc:
            return None
        dest = _get_dest_for_proto(proto_key, agg['config'])
        ck = proto_key + ':' + dest
        cached = _topo_path_cache.get(ck)
        if cached and now - cached['time'] <= _TOPO_CACHE_TTL:
            proto_hops = cached['hops']
        else:
            args = tc['args'] if tc['args'] else []
            proto_hops = _run_traceroute(dest, args)
            _topo_path_cache[ck] = {'hops': proto_hops, 'time': now}
        return {
            'key': proto_key,
            'label': tc['label'],
            'dest': dest,
            'port': tc['port'],
            'hops': proto_hops,
            'running': agg['running'],
            'stats': agg['stats'],
        }

    # Run traceroutes in parallel for all running protocols
    running_protos = [(k, v) for k, v in proto_agg.items() if v['running'] and k in PROTO_TRACEROUTE]
    if running_protos:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(trace_proto, k, v): k for k, v in running_protos}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    paths[result['key']] = result

    # Routers for impairment overlay
    routers = router_manager.list_routers()

    return jsonify({
        'client_ip': client_ip,
        'server_host': SERVER_HOST,
        'paths': paths,
        'routers': routers,
    })


@app.route('/api/shaping/random_bandwidth', methods=['POST'])
def toggle_random_bandwidth():
    d = _get_json()
    enabled = d.get('enabled', False)
    try:
        min_mbps = int(d.get('min_mbps', 20))
        max_mbps = int(d.get('max_mbps', 1000))
        interval = int(d.get('interval', 10))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid parameters"}), 400
    if enabled:
        network_shaper.start_random_bandwidth(min_mbps, max_mbps, interval)
        return jsonify({"ok": True, "message": f"Random bandwidth {min_mbps}-{max_mbps} Mbps every {interval}s"})
    else:
        network_shaper.stop_random_bandwidth()
        return jsonify({"ok": True, "message": "Random bandwidth stopped"})


@app.route('/api/interface', methods=['GET', 'POST'])
def interface():
    if request.method == 'POST':
        d = _get_json()
        iface = d.get('interface', '').strip()
        if not iface:
            return jsonify({"error": "interface required"}), 400
        # Validate interface exists inside the container
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', iface],
                capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return jsonify({"error": f"Interface '{iface}' not found in container. Use 'ip link' inside the container to see available interfaces."}), 400
        except Exception:
            pass
        network_shaper.INTERFACE = iface
        return jsonify({"ok": True, "interface": iface,
                        "message": f"Interface changed to {iface}"})
    return jsonify({"interface": network_shaper.INTERFACE})


@app.route('/api/source_ips', methods=['GET', 'POST'])
def source_ips():
    if request.method == 'POST':
        d = _get_json()
        enabled = d.get('enabled', False)
        if enabled:
            base_ip = d.get('base_ip', '172.18.0.100')
            count = int(d.get('count', 5))
            try:
                added = network_shaper.add_ip_aliases(base_ip, count)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            return jsonify({"ok": True, "message": f"Added {len(added)} source IPs",
                            "ips": added})
        else:
            network_shaper.remove_ip_aliases()
            return jsonify({"ok": True, "message": "Source IPs removed", "ips": []})
    else:
        ips = network_shaper.get_alias_ips()
        return jsonify({"enabled": len(ips) > 0, "ips": ips})


# ─── Security Testing ─────────────────────────────────────

@app.route('/api/security/catalog')
def security_catalog():
    return jsonify(security_engine.get_catalog())


@app.route('/api/security/start', methods=['POST'])
def security_start():
    data = _get_json()
    test_ids = data.get('tests', [])
    config = data.get('config', {})
    config.setdefault('host', SERVER_HOST)
    ok, msg = security_engine.start(test_ids, config)
    return jsonify({"ok": ok, "message": msg}), 200 if ok else 409


@app.route('/api/security/stop', methods=['POST'])
def security_stop():
    ok, msg = security_engine.stop()
    return jsonify({"ok": ok, "message": msg})


@app.route('/api/security/status')
def security_status():
    return jsonify(security_engine.get_status())


@app.route('/api/security/clear', methods=['POST'])
def security_clear():
    security_engine.clear()
    return jsonify({"ok": True, "message": "Security results cleared"})


# ─── Custom Attack Patterns ──────────────────────────────

@app.route('/api/security/patterns', methods=['GET'])
def list_patterns():
    return jsonify(custom_pattern_store.list())


@app.route('/api/security/patterns', methods=['POST'])
def add_pattern():
    data = _get_json()
    required = ['name', 'category', 'payload']
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400
    pattern = {
        'name': data['name'],
        'category': data.get('category', 'web_attacks'),
        'description': data.get('description', ''),
        'payload': data['payload'],
        'method': data.get('method', 'GET'),
        'headers': data.get('headers', {}),
        'target_path': data.get('target_path', '/echo'),
        'expected_action': data.get('expected_action', 'block'),
        'panos_feature': data.get('panos_feature', 'Vulnerability Protection'),
    }
    result = custom_pattern_store.add(pattern)
    security_engine.reload_catalog()
    return jsonify({"ok": True, "pattern": result})


@app.route('/api/security/patterns/<pattern_id>', methods=['PUT'])
def update_pattern(pattern_id):
    data = _get_json()
    result = custom_pattern_store.update(pattern_id, data)
    if result is None:
        return jsonify({"error": "Pattern not found"}), 404
    security_engine.reload_catalog()
    return jsonify({"ok": True, "pattern": result})


@app.route('/api/security/patterns/<pattern_id>', methods=['DELETE'])
def delete_pattern(pattern_id):
    if custom_pattern_store.delete(pattern_id):
        security_engine.reload_catalog()
        return jsonify({"ok": True, "message": "Pattern deleted"})
    return jsonify({"error": "Pattern not found"}), 404


# ─── Built-in Test Overrides ─────────────────────────────

@app.route('/api/security/builtin/<test_id>', methods=['PUT'])
def override_builtin(test_id):
    """Save an override for a built-in test."""
    data = _get_json()
    result = security_engine.save_override(test_id, data)
    if result is None:
        return jsonify({"error": "Built-in test not found"}), 404
    security_engine.reload_catalog()
    return jsonify({"ok": True, "pattern": result})


@app.route('/api/security/builtin/<test_id>', methods=['DELETE'])
def reset_builtin(test_id):
    """Remove override for a built-in test (reset to default)."""
    if security_engine.delete_override(test_id):
        security_engine.reload_catalog()
        return jsonify({"ok": True, "message": "Reset to default"})
    return jsonify({"error": "No override found for this test"}), 404


@app.route('/api/security/builtin/<test_id>', methods=['GET'])
def get_builtin(test_id):
    """Get the original unmodified built-in test."""
    test = security_engine.get_builtin_test(test_id)
    if test is None:
        return jsonify({"error": "Built-in test not found"}), 404
    return jsonify(test)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
