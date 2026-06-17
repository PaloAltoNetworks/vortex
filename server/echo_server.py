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

# PDF with embedded JavaScript — proper structure with correct xref offsets
def _build_pdf_js():
    objs = []
    # Object 1: Catalog with OpenAction pointing to JS action
    objs.append(b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /AcroForm << /Fields [] /DR << >> /DA (/Helv 0 Tf 0 g) >> >>\nendobj\n')
    # Object 2: Pages
    objs.append(b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n')
    # Object 3: Page with minimal content
    objs.append(b'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> >> >>\nendobj\n')
    # Object 4: JavaScript action (this is what the firewall should detect)
    objs.append(b'4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert\\({cMsg: "Security Test", cTitle: "Alert"}\\); var x = this.getField\\("test"\\); app.execMenuItem\\("Print"\\);) >>\nendobj\n')
    # Object 5: Page content stream
    stream_data = b'BT /F1 24 Tf 100 700 Td (Security Test Document) Tj ET'
    objs.append(b'5 0 obj\n<< /Length ' + str(len(stream_data)).encode() + b' >>\nstream\n' + stream_data + b'\nendstream\nendobj\n')
    # Object 6: Font
    objs.append(b'6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n')

    body = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    offsets = []
    for obj in objs:
        offsets.append(len(body))
        body += obj
    xref_offset = len(body)
    xref = b'xref\n0 7\n0000000000 65535 f \n'
    for off in offsets:
        xref += f'{off:010d} 00000 n \n'.encode()
    xref += b'trailer\n<< /Size 7 /Root 1 0 R >>\n'
    xref += b'startxref\n' + str(xref_offset).encode() + b'\n%%EOF\n'
    return body + xref

PDF_JS_TEST_BYTES = _build_pdf_js()

# OLE2 Compound Document with VBA macro — proper 512-byte sector structure
def _build_ole2_macro():
    # OLE2 header (512 bytes)
    header = bytearray(512)
    # Magic number
    header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    # Minor version: 0x003E, Major version: 0x0003
    struct.pack_into('<HH', header, 24, 0x003E, 0x0003)
    # Byte order: little-endian
    struct.pack_into('<H', header, 28, 0xFFFE)
    # Sector size power: 9 (512 bytes)
    struct.pack_into('<H', header, 30, 0x0009)
    # Mini sector size power: 6 (64 bytes)
    struct.pack_into('<H', header, 32, 0x0006)
    # Total sectors in FAT: 1
    struct.pack_into('<I', header, 44, 1)
    # First directory sector SECID: 0
    struct.pack_into('<I', header, 48, 0)
    # First mini FAT sector: none
    struct.pack_into('<i', header, 60, -2)
    # Total mini FAT sectors: 0
    struct.pack_into('<I', header, 64, 0)
    # First DIFAT sector: none
    struct.pack_into('<i', header, 68, -2)
    # Total DIFAT sectors: 0
    struct.pack_into('<I', header, 72, 0)
    # DIFAT array: sector 0 is FAT, rest are free
    struct.pack_into('<i', header, 76, 1)
    for i in range(1, 109):
        struct.pack_into('<i', header, 76 + i * 4, -1)

    # Sector 0: Directory entries (512 bytes, 4 entries of 128 bytes each)
    directory = bytearray(512)

    # Entry 0: Root Entry
    name = 'Root Entry'.encode('utf-16-le')
    directory[0:len(name)] = name
    struct.pack_into('<H', directory, 64, len(name) + 2)  # name size
    directory[66] = 5  # type: root
    directory[67] = 1  # color: black
    struct.pack_into('<i', directory, 68, -1)  # left sibling
    struct.pack_into('<i', directory, 72, -1)  # right sibling
    struct.pack_into('<i', directory, 76, 1)   # child: entry 1

    # Entry 1: VBA directory (Macros)
    off1 = 128
    name1 = 'VBA'.encode('utf-16-le')
    directory[off1:off1+len(name1)] = name1
    struct.pack_into('<H', directory, off1+64, len(name1) + 2)
    directory[off1+66] = 1  # type: storage
    directory[off1+67] = 1
    struct.pack_into('<i', directory, off1+68, -1)
    struct.pack_into('<i', directory, off1+72, 2)  # right sibling: entry 2
    struct.pack_into('<i', directory, off1+76, -1)

    # Entry 2: ThisDocument stream with VBA macro content
    off2 = 256
    name2 = 'ThisDocument'.encode('utf-16-le')
    directory[off2:off2+len(name2)] = name2
    struct.pack_into('<H', directory, off2+64, len(name2) + 2)
    directory[off2+66] = 2  # type: stream
    directory[off2+67] = 0
    struct.pack_into('<i', directory, off2+68, -1)
    struct.pack_into('<i', directory, off2+72, -1)
    struct.pack_into('<i', directory, off2+76, -1)
    struct.pack_into('<i', directory, off2+116, 2)  # start sector
    struct.pack_into('<I', directory, off2+120, 512)  # size

    # Sector 1: FAT (sector allocation table)
    fat = bytearray(512)
    # Sector 0: directory (end of chain)
    struct.pack_into('<i', fat, 0, -2)
    # Sector 1: FAT sector itself
    struct.pack_into('<i', fat, 4, -3)
    # Sector 2: VBA content (end of chain)
    struct.pack_into('<i', fat, 8, -2)
    # Rest: free
    for i in range(3, 128):
        struct.pack_into('<i', fat, i * 4, -1)

    # Sector 2: VBA macro content
    vba_content = bytearray(512)
    macro_code = (
        b'Attribute VB_Name = "ThisDocument"\r\n'
        b'Attribute VB_Base = "1Normal.ThisDocument"\r\n'
        b'Attribute VB_GlobalNameSpace = False\r\n'
        b'Attribute VB_Creatable = False\r\n'
        b'Sub AutoOpen()\r\n'
        b'    Dim objShell As Object\r\n'
        b'    Set objShell = CreateObject("WScript.Shell")\r\n'
        b'    objShell.Run "cmd.exe /c echo Security Test"\r\n'
        b'End Sub\r\n'
        b'Sub Document_Open()\r\n'
        b'    AutoOpen\r\n'
        b'End Sub\r\n'
    )
    vba_content[0:len(macro_code)] = macro_code

    return bytes(header) + bytes(directory) + bytes(fat) + bytes(vba_content)

OFFICE_MACRO_TEST_BYTES = _build_ole2_macro()

# ─── File Blocking test payloads ──────────────────────────────
SCRIPT_FILES = {
    'bat': (
        b'@echo off\r\necho Security Test - File Blocking Validation\r\n'
        b'echo This file tests BAT file type detection\r\npause\r\n',
        'application/x-msdos-program', 'test.bat'
    ),
    'ps1': (
        b'# PowerShell Security Test - File Blocking Validation\r\n'
        b'Write-Host "Testing file blocking policy"\r\n'
        b'Invoke-WebRequest -Uri "http://example.com/test" -OutFile "test.txt"\r\n'
        b'Get-Process | Select-Object -First 5\r\n',
        'application/x-powershell', 'test.ps1'
    ),
    'vbs': (
        b'Dim objShell\r\nSet objShell = CreateObject("WScript.Shell")\r\n'
        b'Dim s : s = Chr(83) & Chr(101) & Chr(99) & Chr(117) & Chr(114) '
        b'& Chr(105) & Chr(116) & Chr(121) & Chr(32) & Chr(84) & Chr(101) '
        b'& Chr(115) & Chr(116)\r\n'
        b'WScript.Echo s\r\nobjShell.Run "cmd.exe /c echo " & s\r\n',
        'application/x-vbs', 'test.vbs'
    ),
}

HTA_TEST_BYTES = (
    b'<html>\r\n<head>\r\n<title>Security Test</title>\r\n'
    b'<HTA:APPLICATION ID="SecurityTest" APPLICATIONNAME="Test" '
    b'BORDER="thin" BORDERSTYLE="normal" SCROLL="yes">\r\n'
    b'</head>\r\n<body>\r\n'
    b'<script language="VBScript">\r\n'
    b'Sub RunTest\r\n'
    b'  Set objShell = CreateObject("WScript.Shell")\r\n'
    b'  objShell.Run "cmd.exe /c echo Security Test"\r\n'
    b'End Sub\r\n'
    b'</script>\r\n'
    b'<button onclick="RunTest">Run</button>\r\n'
    b'</body>\r\n</html>\r\n'
)

# Minimal valid JAR (ZIP with manifest)
def _build_jar():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('META-INF/MANIFEST.MF',
            'Manifest-Version: 1.0\r\n'
            'Main-Class: SecurityTest\r\n'
            'Created-By: Vortex Security Testing\r\n')
        zf.writestr('SecurityTest.class',
            # Minimal class file magic + version (not real bytecode, just triggers file type detection)
            b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + b'\x00' * 50 +
            b'SecurityTest - File Blocking Validation')
    return buf.getvalue()

JAR_TEST_BYTES = _build_jar()

# Novel PE for WildFire testing — PE with suspicious import names
def _build_wildfire_pe():
    """Build a PE with suspicious Windows API imports in its string table.
    This is NOT actual malware — just a file with suspicious characteristics
    that should trigger WildFire sandbox analysis."""
    suspicious_strings = (
        b'VirtualAllocEx\x00CreateRemoteThread\x00WriteProcessMemory\x00'
        b'NtUnmapViewOfSection\x00RtlCreateUserThread\x00'
        b'LoadLibraryA\x00GetProcAddress\x00'
        b'InternetOpenA\x00InternetConnectA\x00HttpOpenRequestA\x00'
        b'URLDownloadToFileA\x00WinExec\x00ShellExecuteA\x00'
    )
    # Build on top of existing PE structure but with different content
    pe = bytearray(PE_TEST_BYTES)
    # Replace the trailing text with suspicious import strings
    trail_start = pe.find(b'This is a test PE')
    if trail_start > 0:
        pe[trail_start:trail_start + len(suspicious_strings)] = suspicious_strings
    else:
        pe += suspicious_strings
    return bytes(pe)

WILDFIRE_PE_BYTES = _build_wildfire_pe()

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

            elif path.startswith('/test-file/script'):
                # Serve script files for file blocking tests
                params = parse_qs(parsed.query)
                script_type = params.get('type', ['bat'])[0]
                if script_type in SCRIPT_FILES:
                    content, ctype, fname = SCRIPT_FILES[script_type]
                else:
                    content, ctype, fname = SCRIPT_FILES['bat']
                self.send_response(200)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(content)

            elif path == '/test-file/hta':
                self.send_response(200)
                self.send_header('Content-Type', 'application/hta')
                self.send_header('Content-Disposition', 'attachment; filename="test.hta"')
                self.send_header('Content-Length', str(len(HTA_TEST_BYTES)))
                self.end_headers()
                self.wfile.write(HTA_TEST_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(HTA_TEST_BYTES)

            elif path == '/test-file/jar':
                self.send_response(200)
                self.send_header('Content-Type', 'application/java-archive')
                self.send_header('Content-Disposition', 'attachment; filename="test.jar"')
                self.send_header('Content-Length', str(len(JAR_TEST_BYTES)))
                self.end_headers()
                self.wfile.write(JAR_TEST_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(JAR_TEST_BYTES)

            elif path == '/test-file/wildfire-pe':
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-dosexec')
                self.send_header('Content-Disposition', 'attachment; filename="suspicious.exe"')
                self.send_header('Content-Length', str(len(WILDFIRE_PE_BYTES)))
                self.end_headers()
                self.wfile.write(WILDFIRE_PE_BYTES)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(WILDFIRE_PE_BYTES)

            elif path == '/login':
                # Credential phishing test — realistic login form
                body = (
                    '<html><head><title>Sign In - Corporate Portal</title>'
                    '<style>'
                    'body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}'
                    '.login-box{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.15);width:360px}'
                    'h2{margin:0 0 24px;color:#1a1a2e;text-align:center}'
                    'input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;font-size:14px}'
                    'button{width:100%;padding:10px;background:#0066cc;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;margin-top:12px}'
                    'button:hover{background:#0052a3}'
                    '.footer{text-align:center;margin-top:16px;font-size:12px;color:#888}'
                    '</style></head>'
                    '<body><div class="login-box">'
                    '<h2>Corporate Portal</h2>'
                    '<form method="POST" action="/login">'
                    '<input type="text" name="username" placeholder="Email or Username" required>'
                    '<input type="password" name="password" placeholder="Password" required>'
                    '<input type="hidden" name="csrf_token" value="abc123">'
                    '<button type="submit">Sign In</button>'
                    '</form>'
                    '<div class="footer">Secure Login &copy; 2024</div>'
                    '</div></body></html>'
                ).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                with stats_lock:
                    stats['http']['bytes_sent'] += len(body)

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
                    '<html><head><title>Vortex</title></head>'
                    '<body><h1>Vortex HTTP Server</h1>'
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
            if parsed.path == '/login':
                # Credential phishing test — accept form submission
                response = json.dumps({
                    'status': 'authenticated',
                    'message': 'Login successful',
                    'token': 'fake-session-token-abc123',
                }).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            elif parsed.path == '/echo':
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
    'vortex-server': '127.0.0.1',
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
