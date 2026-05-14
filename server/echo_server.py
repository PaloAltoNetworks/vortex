"""
Network services: HTTP server (port 9999) and DNS forwarder (port 9998).
Replaces raw echo with recognizable App-ID protocols for Palo Alto firewalls.
"""
import io
import json
import os
import socket
import struct
import threading
import signal
import sys
import time
import zipfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, unquote

# EICAR anti-malware test string (standard, universally recognized — NOT actual malware)
EICAR_STRING = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Pre-build EICAR zip in memory
_eicar_zip_buf = io.BytesIO()
with zipfile.ZipFile(_eicar_zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('eicar.com', EICAR_STRING.decode())
EICAR_ZIP_BYTES = _eicar_zip_buf.getvalue()

# ─── Test file payloads for file-based threat detection ──────
# Minimal valid PE (MZ header + PE signature) — not executable, just triggers file type detection
PE_TEST_BYTES = (
    b'MZ' + b'\x90' * 58 +                    # DOS header (64 bytes)
    struct.pack('<I', 64) +                     # e_lfanew at offset 60 → PE header at 64
    b'PE\x00\x00' +                            # PE signature
    struct.pack('<HH', 0x14C, 1) +             # Machine: i386, 1 section
    b'\x00' * 12 +                             # Timestamp, symbol table, etc.
    struct.pack('<HH', 0x00E0, 0x0102) +       # Optional header size, characteristics (EXECUTABLE)
    b'\x00' * 224 +                            # Minimal optional header
    b'This is a test PE file for anti-malware detection testing.\x00'
)

# Minimal PDF with embedded JavaScript annotation
PDF_JS_TEST_BYTES = (
    b'%PDF-1.4\n'
    b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n'
    b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
    b'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n'
    b'4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert\\("Security Test"\\);) >>\nendobj\n'
    b'xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n'
    b'0000000127 00000 n \n0000000206 00000 n \n'
    b'trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n296\n%%EOF\n'
)

# Bytes mimicking a file with OLE/VBA macro signatures
OFFICE_MACRO_TEST_BYTES = (
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # OLE2 compound file magic
    + b'\x00' * 20
    + b'Attribute VB_Name = "ThisDocument"\r\n'
    + b'Sub AutoOpen()\r\n'
    + b'    MsgBox "Security Test Macro"\r\n'
    + b'End Sub\r\n'
    + b'\x00' * 100
)

STATS_FILE = '/tmp/echo_stats.json'
stats_lock = threading.Lock()
stats = {
    'http': {'requests': 0, 'bytes_recv': 0, 'bytes_sent': 0, 'active': 0,
             'gets': 0, 'posts': 0},
    'dns': {'queries': 0, 'bytes_recv': 0, 'bytes_sent': 0, 'last_active': 0,
            'forwarded': 0, 'errors': 0},
}

# ─── HTTP Server (port 9999) ─────────────────────────────────

class TrafficHTTPHandler(BaseHTTPRequestHandler):
    """Simple HTTP server for generating web-browsing App-ID traffic."""

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass  # Client disconnected mid-request — normal during link simulation

    def do_GET(self):
        with stats_lock:
            stats['http']['requests'] += 1
            stats['http']['gets'] += 1
            stats['http']['active'] += 1
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            if path == '/echo':
                # Echo query parameter back as HTML — firewall inspects both request URL and response
                params = parse_qs(parsed.query)
                payload = params.get('payload', [''])[0]
                body = (
                    f'<html><head><title>Echo</title></head>'
                    f'<body><h1>Echo Response</h1>'
                    f'<div id="payload">{payload}</div>'
                    f'</body></html>'
                ).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(body)

            elif path == '/eicar':
                # Serve EICAR anti-malware test file
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', 'attachment; filename="eicar.com"')
                self.send_header('Content-Length', str(len(EICAR_STRING)))
                self.end_headers()
                self.wfile.write(EICAR_STRING)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(EICAR_STRING)

            elif path == '/eicar.zip':
                # Serve EICAR inside a zip archive
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="eicar.zip"')
                self.send_header('Content-Length', str(len(EICAR_ZIP_BYTES)))
                self.end_headers()
                self.wfile.write(EICAR_ZIP_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(EICAR_ZIP_BYTES)

            elif path == '/test-file/pe':
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-dosexec')
                self.send_header('Content-Disposition', 'attachment; filename="testfile.exe"')
                self.send_header('Content-Length', str(len(PE_TEST_BYTES)))
                self.end_headers()
                self.wfile.write(PE_TEST_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(PE_TEST_BYTES)

            elif path == '/test-file/pdf-js':
                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Disposition', 'attachment; filename="testfile.pdf"')
                self.send_header('Content-Length', str(len(PDF_JS_TEST_BYTES)))
                self.end_headers()
                self.wfile.write(PDF_JS_TEST_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(PDF_JS_TEST_BYTES)

            elif path == '/test-file/office-macro':
                self.send_response(200)
                self.send_header('Content-Type', 'application/vnd.ms-word')
                self.send_header('Content-Disposition', 'attachment; filename="testfile.doc"')
                self.send_header('Content-Length', str(len(OFFICE_MACRO_TEST_BYTES)))
                self.end_headers()
                self.wfile.write(OFFICE_MACRO_TEST_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(OFFICE_MACRO_TEST_BYTES)

            elif path.startswith('/download'):
                # Parse size parameter (KB)
                size_kb = 1
                if '?' in self.path:
                    params = dict(p.split('=') for p in self.path.split('?')[1].split('&') if '=' in p)
                    size_kb = int(params.get('size', 1))
                size_kb = max(1, min(size_kb, 102400))  # Cap at 100MB
                data = os.urandom(size_kb * 1024)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(data)
            else:
                body = (
                    '<html><head><title>Traffic Generator</title></head>'
                    '<body><h1>Traffic Generator HTTP Server</h1>'
                    '<p>Port 9999 — App-ID: web-browsing</p>'
                    f'<p>Requests served: {stats["http"]["requests"]}</p>'
                    '</body></html>'
                ).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(body)
        finally:
            with stats_lock:
                stats['http']['active'] -= 1

    def do_POST(self):
        with stats_lock:
            stats['http']['requests'] += 1
            stats['http']['posts'] += 1
            stats['http']['active'] += 1
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            with stats_lock:
                stats['http']['bytes_recv'] += len(body)

            parsed = urlparse(self.path)
            if parsed.path == '/echo':
                # Echo POST body back as HTML — firewall inspects request body and response
                payload = body.decode('utf-8', errors='replace')
                response = (
                    f'<html><head><title>Echo</title></head>'
                    f'<body><h1>Echo Response</h1>'
                    f'<div id="payload">{payload}</div>'
                    f'</body></html>'
                ).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                response = json.dumps({
                    'status': 'ok',
                    'bytes_received': len(body),
                }).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            with stats_lock:
                stats['http']['bytes_sent'] += len(response)
        finally:
            with stats_lock:
                stats['http']['active'] -= 1


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def http_server(port=9999):
    server = ThreadedHTTPServer(('0.0.0.0', port), TrafficHTTPHandler)
    print(f"[HTTP] Server on port {port}")
    server.serve_forever()


# ─── DNS Server (port 9998) ──────────────────────────────────

# Static DNS records — resolved locally without external connectivity
STATIC_DNS = {
    'google.com': '142.250.80.46',
    'www.google.com': '142.250.80.46',
    'amazon.com': '205.251.242.103',
    'www.amazon.com': '205.251.242.103',
    'microsoft.com': '20.70.246.20',
    'www.microsoft.com': '20.70.246.20',
    'github.com': '140.82.121.3',
    'www.github.com': '140.82.121.3',
    'cloudflare.com': '104.16.132.229',
    'www.cloudflare.com': '104.16.132.229',
    'facebook.com': '157.240.1.35',
    'www.facebook.com': '157.240.1.35',
    'apple.com': '17.253.144.10',
    'www.apple.com': '17.253.144.10',
    'netflix.com': '54.74.73.31',
    'www.netflix.com': '54.74.73.31',
    'twitter.com': '104.244.42.193',
    'www.twitter.com': '104.244.42.193',
    'linkedin.com': '13.107.42.14',
    'www.linkedin.com': '13.107.42.14',
    'yahoo.com': '74.6.231.21',
    'www.yahoo.com': '74.6.231.21',
    'wikipedia.org': '208.80.154.224',
    'www.wikipedia.org': '208.80.154.224',
    'reddit.com': '151.101.1.140',
    'www.reddit.com': '151.101.1.140',
    'stackoverflow.com': '151.101.1.69',
    'www.stackoverflow.com': '151.101.1.69',
    'traffic-server': '127.0.0.1',
    'server': '127.0.0.1',
}

# Default IP for unknown domains
DEFAULT_IP = '10.0.0.1'


def _parse_dns_name(data, offset):
    """Parse a DNS name from a packet, handling compression pointers."""
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            sub_name, _ = _parse_dns_name(data, ptr)
            labels.append(sub_name)
            offset += 2
            return '.'.join(labels), offset
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii', errors='ignore'))
        offset += length
    return '.'.join(labels), offset


def _build_dns_response(query, _domain, ip):
    """Build a DNS A-record response for the given query."""
    # Copy transaction ID from original query
    txn_id = query[:2]
    flags = struct.pack('!H', 0x8180)  # response, authoritative, recursion available
    qdcount = struct.pack('!H', 1)
    ancount = struct.pack('!H', 1)
    nscount = struct.pack('!H', 0)
    arcount = struct.pack('!H', 0)
    header = txn_id + flags + qdcount + ancount + nscount + arcount

    # Copy the question section directly from the original query (byte 12 onward)
    # Find end of QNAME (null terminator) then skip QTYPE(2) + QCLASS(2)
    offset = 12
    while offset < len(query) and query[offset] != 0:
        offset += 1 + query[offset]
    offset += 1  # skip null terminator
    offset += 4  # skip QTYPE + QCLASS
    question = query[12:offset]

    # Answer section — pointer to qname at offset 12 + A record
    answer = struct.pack('!HHHLH', 0xC00C, 1, 1, 300, 4)  # name pointer, A, IN, TTL=300, RDLENGTH=4
    answer += socket.inet_aton(ip)

    return header + question + answer


def dns_server(port=9998):
    """Local DNS server with static records.
    Resolves queries from static table — no external connectivity needed.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    print(f"[DNS] Server on port {port} — {len(STATIC_DNS)} static records")

    while True:
        try:
            data, client_addr = srv.recvfrom(4096)
            with stats_lock:
                stats['dns']['queries'] += 1
                stats['dns']['bytes_recv'] += len(data)
                stats['dns']['last_active'] = time.time()

            # Parse query — extract domain name
            if len(data) < 12:
                continue
            domain, _ = _parse_dns_name(data, 12)
            domain_lower = domain.lower()

            # Look up in static records
            ip = STATIC_DNS.get(domain_lower, DEFAULT_IP)

            # Build and send response
            response = _build_dns_response(data, domain, ip)
            srv.sendto(response, client_addr)

            with stats_lock:
                stats['dns']['bytes_sent'] += len(response)
                stats['dns']['forwarded'] += 1

        except Exception as e:
            print(f"[DNS] Error: {e}")
            with stats_lock:
                stats['dns']['errors'] += 1


# ─── Stats & Main ────────────────────────────────────────────

RESET_SIGNAL = '/tmp/stats_reset_echo'


def save_stats():
    while True:
        # Check for reset signal
        if os.path.exists(RESET_SIGNAL):
            with stats_lock:
                for svc in stats.values():
                    for k in svc:
                        svc[k] = 0
            try:
                os.remove(RESET_SIGNAL)
            except OSError:
                pass
        with stats_lock:
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f)
        time.sleep(1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    threading.Thread(target=save_stats, daemon=True).start()
    threading.Thread(target=http_server, daemon=True).start()
    threading.Thread(target=lambda: dns_server(port=53), daemon=True).start()
    print("[NET] HTTP + DNS servers started")
    threading.Event().wait()
