import io
import os
import json
import time
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
