import io
import os
import json
import time
import socket
import struct
import signal
import subprocess
import threading
import zipfile
from flask import Flask, request, jsonify, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = '/data/uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

STATS_FILE = '/tmp/http_stats.json'
stats_lock = threading.Lock()

# Load stats from disk on startup to survive restarts
def _load_stats():
    try:
        with open(STATS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            'requests': 0, 'bytes_recv': 0, 'bytes_sent': 0,
            'errors': 0, 'uploads': 0, 'downloads': 0,
        }

http_stats = _load_stats()

# Batch stats saves on a timer instead of per-request
_stats_dirty = False

RESET_SIGNAL = '/tmp/stats_reset_http'


def _stats_save_loop():
    global _stats_dirty
    while True:
        time.sleep(2)
        # Check for reset signal
        if os.path.exists(RESET_SIGNAL):
            with stats_lock:
                for k in http_stats:
                    http_stats[k] = 0
                _stats_dirty = True
            try:
                os.remove(RESET_SIGNAL)
            except OSError:
                pass
        if _stats_dirty:
            with stats_lock:
                _stats_dirty = False
                with open(STATS_FILE, 'w') as f:
                    json.dump(http_stats, f)

_save_thread = threading.Thread(target=_stats_save_loop, daemon=True)
_save_thread.start()


def _mark_dirty():
    global _stats_dirty
    _stats_dirty = True


def _safe_path(base_dir, filename):
    """Resolve a safe file path within base_dir, preventing path traversal."""
    name = secure_filename(filename)
    if not name:
        return None
    resolved = os.path.realpath(os.path.join(base_dir, name))
    if not resolved.startswith(os.path.realpath(base_dir)):
        return None
    return resolved


@app.before_request
def track_request():
    with stats_lock:
        http_stats['requests'] += 1
        http_stats['bytes_recv'] += request.content_length or 0
    _mark_dirty()


@app.after_request
def track_response(response):
    with stats_lock:
        content_length = response.content_length or 0
        http_stats['bytes_sent'] += content_length
    _mark_dirty()
    return response


@app.route('/')
def index():
    return jsonify({"status": "ok", "service": "vortex-server",
                    "protocols": ["http", "https", "tcp", "udp", "ftp", "ssh", "icmp"]})


@app.route('/health')
def health():
    return jsonify({"status": "healthy"})


FTP_DATA_DIR = '/data'


@app.route('/upload', methods=['POST'])
def upload():
    with stats_lock:
        http_stats['uploads'] += 1
    _mark_dirty()

    if 'file' in request.files:
        f = request.files['file']
        path = _safe_path(UPLOAD_DIR, f.filename)
        if not path:
            return jsonify({"error": "Invalid filename"}), 400
        f.save(path)
        return jsonify({"status": "ok", "filename": os.path.basename(path), "size": os.path.getsize(path)})

    data = request.get_data()
    path = os.path.join(UPLOAD_DIR, 'raw_upload.bin')
    with open(path, 'wb') as f:
        f.write(data)
    return jsonify({"status": "ok", "size": len(data)})


@app.route('/api/files/upload', methods=['POST'])
def upload_ftp_file():
    """Upload a file to the FTP data directory."""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({"error": "No filename"}), 400
    path = _safe_path(FTP_DATA_DIR, f.filename)
    if not path:
        return jsonify({"error": "Invalid filename"}), 400
    f.save(path)
    os.chmod(path, 0o644)
    return jsonify({"ok": True, "filename": os.path.basename(path), "size": os.path.getsize(path)})


@app.route('/api/files')
def list_ftp_files():
    """List files available for FTP download."""
    files = []
    try:
        for name in sorted(os.listdir(FTP_DATA_DIR)):
            path = os.path.join(FTP_DATA_DIR, name)
            if os.path.isfile(path):
                size = os.path.getsize(path)
                files.append({"name": name, "size": size})
    except FileNotFoundError:
        pass
    return jsonify({"files": files})


@app.route('/api/files/<name>', methods=['DELETE'])
def delete_ftp_file(name):
    """Delete a file from the FTP data directory."""
    path = _safe_path(FTP_DATA_DIR, name)
    if not path or not os.path.isfile(path):
        return jsonify({"error": "File not found"}), 404
    os.remove(path)
    return jsonify({"ok": True, "message": f"Deleted {os.path.basename(path)}"})


@app.route('/generate/<int:size_mb>')
def generate_data(size_mb):
    """Stream zeroed data of specified size in MB for bandwidth testing."""
    size_mb = min(size_mb, 1024)

    with stats_lock:
        http_stats['downloads'] += 1
    _mark_dirty()

    def generate():
        chunk = b'\x00' * (1024 * 1024)
        sent = 0
        for _ in range(size_mb):
            yield chunk
            sent += len(chunk)
        with stats_lock:
            http_stats['bytes_sent'] += sent
        _mark_dirty()

    return app.response_class(
        generate(), mimetype='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename=testdata_{size_mb}mb.bin'})


# ─── EICAR Anti-Malware Test (HTTPS via nginx) ─────────────

EICAR_STRING = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

_eicar_zip_buf = io.BytesIO()
with zipfile.ZipFile(_eicar_zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('eicar.com', EICAR_STRING.decode())
EICAR_ZIP_BYTES = _eicar_zip_buf.getvalue()


@app.route('/eicar')
def eicar():
    """Serve EICAR test file over HTTPS (through nginx SSL termination)."""
    with stats_lock:
        http_stats['downloads'] += 1
    _mark_dirty()
    return Response(
        EICAR_STRING,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': 'attachment; filename="eicar.com"'})


@app.route('/eicar.zip')
def eicar_zip():
    """Serve EICAR inside a ZIP archive over HTTPS."""
    with stats_lock:
        http_stats['downloads'] += 1
    _mark_dirty()
    return Response(
        EICAR_ZIP_BYTES,
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment; filename="eicar.zip"'})


# ─── DSCP helper ──────────────────────────────────────────

DSCP_VALUES = {
    'BE': 0, 'CS1': 8, 'AF11': 10, 'AF12': 12, 'AF13': 14,
    'CS2': 16, 'AF21': 18, 'AF22': 20, 'AF23': 22,
    'CS3': 24, 'AF31': 26, 'AF32': 28, 'AF33': 30,
    'CS4': 32, 'AF41': 34, 'AF42': 36, 'AF43': 38,
    'CS5': 40, 'VA': 44, 'EF': 46, 'CS6': 48, 'CS7': 56,
}


def _dscp_to_tos(name):
    return DSCP_VALUES.get(name, 0) << 2


# ─── Multicast Sender ────────────────────────────────────

_mcast_thread = None
_mcast_running = False
_mcast_stats = {'packets_sent': 0, 'bytes_sent': 0}


def _multicast_sender(group, port, ttl, packet_size, pps, dscp):
    global _mcast_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    tos = _dscp_to_tos(dscp)
    if tos > 0:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)

    interval = 1.0 / max(pps, 1)
    seq = 0
    payload_size = max(packet_size - 4, 0)
    filler = os.urandom(payload_size) if payload_size > 0 else b''

    while _mcast_running:
        packet = struct.pack('!I', seq) + filler
        try:
            sock.sendto(packet, (group, port))
            _mcast_stats['packets_sent'] += 1
            _mcast_stats['bytes_sent'] += len(packet)
        except Exception:
            pass
        seq += 1
        time.sleep(interval)

    sock.close()


@app.route('/api/multicast/start', methods=['POST'])
def multicast_start():
    global _mcast_thread, _mcast_running, _mcast_stats
    if _mcast_running:
        return jsonify({"ok": False, "message": "Multicast sender already running"}), 409

    data = request.json or {}
    group = data.get('group', '239.1.1.1')
    port = int(data.get('port', 5004))
    ttl = int(data.get('ttl', 32))
    packet_size = int(data.get('packet_size', 1200))
    pps = int(data.get('pps', 100))
    dscp = data.get('dscp', 'AF41')

    _mcast_stats = {'packets_sent': 0, 'bytes_sent': 0}
    _mcast_running = True
    _mcast_thread = threading.Thread(
        target=_multicast_sender,
        args=(group, port, ttl, packet_size, pps, dscp),
        daemon=True)
    _mcast_thread.start()
    return jsonify({"ok": True, "message": f"Multicast sender started: {group}:{port} {pps}pps"})


@app.route('/api/multicast/stop', methods=['POST'])
def multicast_stop():
    global _mcast_running
    if not _mcast_running:
        return jsonify({"ok": False, "message": "Multicast sender not running"}), 404
    _mcast_running = False
    return jsonify({"ok": True, "message": "Multicast sender stopped",
                    "stats": dict(_mcast_stats)})


@app.route('/api/multicast/status')
def multicast_status():
    return jsonify({"running": _mcast_running, "stats": dict(_mcast_stats)})


# ─── RTP Receiver / Sender (ffmpeg) ──────────────────────

_rtp_procs = []
_rtp_running = False


def _kill_rtp_procs():
    global _rtp_running
    _rtp_running = False
    for label, proc in _rtp_procs:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    _rtp_procs.clear()


@app.route('/api/rtp/receive', methods=['POST'])
def rtp_receive():
    """Start ffmpeg RTP receiver to accept streams and send RTCP back."""
    global _rtp_running
    if _rtp_running:
        return jsonify({"ok": False, "message": "RTP already running"}), 409

    data = request.json or {}
    video_port = int(data.get('video_port', 5004))
    audio_port = int(data.get('audio_port', 5006))
    mode = data.get('mode', 'Video Call')

    _rtp_running = True
    started = []

    if mode in ('Video Call', 'Streaming'):
        # SDP content for receiving video RTP
        sdp_video = (
            f"v=0\n"
            f"o=- 0 0 IN IP4 0.0.0.0\n"
            f"s=Vortex RTP\n"
            f"c=IN IP4 0.0.0.0\n"
            f"t=0 0\n"
            f"m=video {video_port} RTP/AVP 96\n"
            f"a=rtpmap:96 H264/90000\n"
        )
        sdp_path = f'/tmp/rtp_video_{video_port}.sdp'
        with open(sdp_path, 'w') as f:
            f.write(sdp_video)

        cmd = ['ffmpeg', '-protocol_whitelist', 'file,rtp,udp',
               '-i', sdp_path, '-f', 'null', '-']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            _rtp_procs.append(('video_recv', proc))
            started.append(f'video receiver on port {video_port}')
        except Exception as e:
            return jsonify({"ok": False, "message": f"ffmpeg video error: {e}"}), 500

    if mode in ('Video Call', 'Audio Only'):
        sdp_audio = (
            f"v=0\n"
            f"o=- 0 0 IN IP4 0.0.0.0\n"
            f"s=Vortex RTP\n"
            f"c=IN IP4 0.0.0.0\n"
            f"t=0 0\n"
            f"m=audio {audio_port} RTP/AVP 111\n"
            f"a=rtpmap:111 opus/48000/2\n"
        )
        sdp_path = f'/tmp/rtp_audio_{audio_port}.sdp'
        with open(sdp_path, 'w') as f:
            f.write(sdp_audio)

        cmd = ['ffmpeg', '-protocol_whitelist', 'file,rtp,udp',
               '-i', sdp_path, '-f', 'null', '-']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            _rtp_procs.append(('audio_recv', proc))
            started.append(f'audio receiver on port {audio_port}')
        except Exception as e:
            return jsonify({"ok": False, "message": f"ffmpeg audio error: {e}"}), 500

    return jsonify({"ok": True, "message": f"RTP started: {', '.join(started)}"})


@app.route('/api/rtp/start', methods=['POST'])
def rtp_start_sender():
    """Start ffmpeg RTP sender for bidirectional Video Call mode."""
    data = request.json or {}
    client_ip = data.get('client_ip', '127.0.0.1')
    video_port = int(data.get('video_port', 5004))
    audio_port = int(data.get('audio_port', 5006))
    resolution = data.get('resolution', '640x480')
    video_bitrate = data.get('video_bitrate', '1M')
    audio_codec = data.get('audio_codec', 'opus')
    audio_bitrate = data.get('audio_bitrate', '64k')

    started = []

    # Video sender
    video_cmd = [
        'ffmpeg', '-re',
        '-f', 'lavfi', '-i', f'testsrc=size={resolution}:rate=30',
        '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
        '-b:v', video_bitrate, '-pkt_size', '1200',
        '-f', 'rtp', f'rtp://{client_ip}:{video_port}?pkt_size=1200'
    ]
    try:
        proc = subprocess.Popen(video_cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        _rtp_procs.append(('video_send', proc))
        started.append(f'video sender to {client_ip}:{video_port}')
    except Exception as e:
        return jsonify({"ok": False, "message": f"ffmpeg video send error: {e}"}), 500

    # Audio sender
    if audio_codec == 'opus':
        audio_cmd = [
            'ffmpeg', '-re',
            '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=48000',
            '-c:a', 'libopus', '-b:a', audio_bitrate,
            '-f', 'rtp', f'rtp://{client_ip}:{audio_port}?pkt_size=160'
        ]
    else:
        audio_cmd = [
            'ffmpeg', '-re',
            '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=8000',
            '-c:a', 'pcm_alaw', '-ar', '8000', '-ac', '1',
            '-f', 'rtp', f'rtp://{client_ip}:{audio_port}?pkt_size=160'
        ]
    try:
        proc = subprocess.Popen(audio_cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        _rtp_procs.append(('audio_send', proc))
        started.append(f'audio sender to {client_ip}:{audio_port}')
    except Exception as e:
        return jsonify({"ok": False, "message": f"ffmpeg audio send error: {e}"}), 500

    return jsonify({"ok": True, "message": f"RTP sender started: {', '.join(started)}"})


@app.route('/api/rtp/stop', methods=['POST'])
def rtp_stop():
    if not _rtp_procs:
        return jsonify({"ok": False, "message": "No RTP processes running"}), 404
    _kill_rtp_procs()
    return jsonify({"ok": True, "message": "RTP processes stopped"})


@app.route('/api/rtp/status')
def rtp_status():
    active = [(label, proc.pid) for label, proc in _rtp_procs if proc.poll() is None]
    return jsonify({"running": _rtp_running, "processes": active})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
