# CLAUDE.md

## Project Overview

Traffic Generator — a Docker-based network traffic generation and testing tool with a Flask web UI. Two containers (client + server) generate multi-protocol traffic with real-time monitoring, per-protocol topology visualization via traceroute + vis.js, SSH-based router link simulation, source IP rotation, DSCP marking, proxy support, and browser mode (Playwright). Designed for SD-WAN demos and network testing.

## Architecture

- **Client container** (`client/`): Flask web UI (port 8080/8443) + traffic engine + network shaper + router shaper
- **Server container** (`server/`): nginx (HTTP/HTTPS with HTTP/2) + iperf3 (3 instances) + DNS server + vsftpd (FTP) + openssh (SSH) + echo server (HTTP port 9999) + server dashboard (port 8082)
- **Network**: Docker bridge `traffic-net` (172.20.0.0/24) for single-host, or separate VMs with `SERVER_HOST` env var
- **Process management**: supervisord in both containers

## Key Files

### Client
- `client/app.py` — Flask routes: `/api/start`, `/api/stop`, `/api/status`, `/api/topology`, `/api/routers`, `/api/shaping`, `/api/source_ips`, `/api/proxy`, `/api/security/*`
- `client/traffic_engine.py` — Protocol handlers: HTTPS, HTTP, DNS, iperf3, FTP, SSH, hping3, External HTTPS. `TrafficJob` dataclass, `TrafficEngine` class with start/stop/status
- `client/security_engine.py` — Security testing engine: OWASP web attacks, malware/threat patterns, URL filtering. `SecurityTestEngine` class with test catalog, sequential execution, firewall detection heuristics
- `client/network_shaper.py` — Linux tc/netem for local impairment (latency, jitter, loss, bandwidth). Auto-detects interface via `ip route get`. Source IP aliases for multi-client simulation
- `client/router_shaper.py` — SSH-based remote router impairment. `RouterConnection` dataclass, `RouterManager` class. Modes: healthy, impaired, link_down. Presets: degraded_wan, voice_sla, video_sla
- `client/static/app.js` — Dashboard JS: protocol cards, topology rendering (vis.js), router controls, source IP config, logs
- `client/templates/dashboard.html` — Web UI template with collapsible sections
- `client/static/style.css` — Blue/corporate theme CSS
- `client/Dockerfile` — Python 3.11 + iperf3 + hping3 + traceroute + iproute2 + playwright browsers
- `client/nginx.conf` — HTTPS reverse proxy (port 8443 → gunicorn 8080)
- `client/supervisord.conf` — gunicorn + nginx process management

### Server
- `server/dashboard.py` — Server dashboard (port 8082): server stats tab + multi-client control tabs. Client registry with add/remove. Proxies API calls to registered clients
- `server/echo_server.py` — HTTP server (port 9999) + DNS server (port 53). Echo endpoint for web attack reflection, EICAR test file endpoints, download endpoint
- `server/stats_collector.py` — Collects FTP/SSH stats from logs, writes to JSON files for dashboard consumption
- `server/app.py` — nginx backend serving test content + EICAR endpoints for HTTPS-based anti-malware testing
- `server/Dockerfile` — nginx + iperf3 + dnsmasq + vsftpd + openssh + Python 3.11
- `server/nginx.conf` — HTTP (80) + HTTPS (443) with HTTP/2, self-signed cert
- `server/vsftpd.conf` — FTP server config (anonymous + ftpuser)
- `server/supervisord.conf` — All services managed by supervisord

### Root
- `docker-compose.yml` — Both containers on same host (local testing)
- `docker-compose.client.yml` — Client standalone with `SERVER_HOST` env var
- `docker-compose.server.yml` — Server standalone with all ports exposed
- `topology.md` — Detailed topology visualization documentation

## Protocols

| Protocol | Client Tool | Server Service | Port | Key Config |
|----------|------------|----------------|------|------------|
| HTTPS | requests/httpx/Playwright | nginx | 443 | HTTP/2, upload mode, browser mode |
| HTTP Plain | requests/Playwright | echo_server | 9999 | Random data sizes, browser mode |
| iperf3 | iperf3 CLI | iperf3 x3 | 5201-5203 | TCP/UDP, bandwidth, parallel streams, reverse |
| DNS | dig | dnsmasq | 53 | Configurable domain list |
| FTP | ftplib | vsftpd | 21 | File download/upload, progress logging |
| SSH | paramiko | openssh | 2222 | Command execution (testuser/testpass) |
| hping3 | hping3 CLI | — | ICMP/TCP/UDP | SYN/ACK/FIN, flood, traceroute, custom TTL |
| Ext HTTPS | requests/Playwright | external sites | 443 | Multi-URL round-robin, browser mode |

## Build & Deploy

```bash
# Build and push (amd64)
docker buildx build --platform linux/amd64 -t ajaymare/traffic-client:latest -f client/Dockerfile ./client --push
docker buildx build --platform linux/amd64 -t ajaymare/traffic-server:latest -f server/Dockerfile ./server --push

# Run locally (same host)
docker compose up -d

# Run on separate VMs
# Server VM:
docker compose -f docker-compose.server.yml up -d
# Client VM:
SERVER_HOST=<server-ip> docker compose -f docker-compose.client.yml up -d
```

### URLs
- Client dashboard: `https://<client-ip>:8443` or `http://<client-ip>:8080`
- Server dashboard: `https://<server-ip>:8443` or `http://<server-ip>:8082`

## Development Notes

### Traffic Engine (`traffic_engine.py`)
- `TrafficJob` dataclass: per-flow state (thread, stats, logs, config, duration)
- `TrafficEngine` class: manages jobs dict, start/stop, status reporting
- Each protocol runs in a background thread with configurable duration (default 15 min)
- Multiple flows per protocol: up to 20 parallel flows (keyed as `{proto}_{n}`)
- DSCP marking via `DscpHTTPAdapter` (custom HTTPAdapter setting IP_TOS on sockets)
- Source IP binding: `_get_source_address()` returns alias IP for socket-level binding
- Browser headers: `_browser_headers()` generates realistic User-Agent, Sec-CH-UA, Sec-Fetch-* headers
- Burst mode: send N requests, pause X seconds, repeat
- Rate control: target packets-per-second with adaptive sleep

### Browser Mode (Playwright)
- Toggle on HTTPS, HTTP Plain, or External HTTPS protocol cards
- Uses Playwright headless browsers (Chromium, Firefox, WebKit — all installed in container)
- Generates real TLS fingerprints and L7 headers
- Browser rotation: specific engine or random rotation each burst cycle
- Proxy support: works with global, per-protocol, and custom proxy configs

### Network Shaping (`network_shaper.py`)
- Auto-detects outgoing interface via `ip route get <SERVER_HOST>`
- Applies tc/netem: `sudo tc qdisc add/change dev <iface> root netem delay Xms Yms loss Z%`
- Bandwidth limiting via `tc qdisc add ... root tbf rate Xmbit`
- Source IP aliases: `sudo ip addr add <ip>/32 dev <iface>` for multi-client simulation
- Random bandwidth mode: periodically changes bandwidth limit
- Requires `NET_ADMIN` capability

### Router Shaper (`router_shaper.py`)
- `RouterConnection` dataclass: SSH client, interface list, current mode, impairment config
- `RouterManager` class: manages multiple routers independently
- SSH via paramiko, discovers interfaces with `ip -j addr show`
- Three modes:
  - **Healthy**: clears tc qdisc rules
  - **Impaired**: applies tc/netem (latency, jitter, loss, bandwidth) on selected interface
  - **Link Down**: `sudo ip link set <iface> down`
- Presets: degraded_wan (300ms/5%), voice_sla (200ms/2%), video_sla (150ms/3%)

### Topology Visualization
- Backend: `/api/topology` runs per-protocol `traceroute` (TCP/UDP) in parallel via ThreadPoolExecutor
- Frontend: vis.js hierarchical graph (left-to-right) with custom SVG icons
- Node types: client (laptop), server (rack), router (circle with status color), hop (numbered), timeout (red X)
- Animated dashes on active edges, latency labels on edges, path merging for identical hops
- Router status overlay: green (healthy), amber (impaired), red (link down)
- 30-second traceroute cache, 10-second auto-refresh
- See `topology.md` for full details

### Server Dashboard (`dashboard.py`)
- Server tab: aggregate stats (nginx, iperf3, DNS, FTP, SSH), per-service status, active connections
- Client tabs: register clients by name + URL, full proxy to client API (GET/POST/PUT/DELETE)
- FTP file management: upload/delete files via dashboard
- Service restart: individual or all services via supervisord
- Security testing integration: proxies security API calls to registered clients, full UI with expandable details and custom patterns
- CSS: uses `.modal-overlay` with `.show` class toggle — avoid adding duplicate `.modal-overlay` rules that override `display: none`

### Proxy Configuration
- Global proxy: HTTP or SOCKS5 with optional auth
- Per-protocol override: Global, On, Off, or Custom
- Custom proxy: independent type/host/port/credentials per protocol
- Applied at socket level for requests/httpx, passed to Playwright for browser mode

### DSCP Marking
- Full DSCP table: BE, CS1-CS7, AF11-AF43, VA, EF
- `_dscp_to_tos(dscp)` converts name/value to TOS byte (DSCP << 2)
- Applied on all protocols via `DscpHTTPAdapter` or raw socket `setsockopt`

### Multi-Client Control
- Server dashboard registers clients by name + URL
- Each client tab proxies all API calls (`/api/client/<name>/...`) through server to client
- Enables centralized control of multiple traffic generators

### Security Testing (`security_engine.py`)
- Separate engine from TrafficEngine — tests run once per case with pass/fail verdicts vs continuous traffic
- Six categories: Web Attacks (SQL injection, XSS, command injection, path traversal, Log4Shell), Malware/Threats (EICAR HTTP/HTTPS/ZIP, C2 callback, malicious User-Agent), URL Filtering (PAN-DB test URLs), DNS-Based Attacks (tunneling, DGA, rebinding), Protocol Abuse (SSH brute force, FTP bounce, HTTP smuggling, Slowloris), File-Based Threats (PDF with JS, Office macros, PE download)
- Detection heuristics: ConnectionReset/timeout = blocked by firewall (PASS), HTTP 200 with echoed payload = passed through (FAIL), block page markers = blocked (PASS)
- EICAR over HTTPS only detected if firewall has SSL Decryption enabled
- URL Filtering test URLs use PAN-DB test URLs (`urlfiltering.paloaltonetworks.com/test-*`), configurable at runtime
- Enriched results: each `SecurityTestResult` includes payload, URL, method, response body snippet, response headers, verdict explanation, expected behavior
- `EXPECTED_BEHAVIOR` dict maps test IDs to human-readable firewall behavior descriptions
- Expandable detail view: clicking a test row shows full payload, response, PAN-OS guidance
- Per-test Run button (▶): runs a single test independently without needing to select/deselect checkboxes
- Edit any test: all tests (built-in and custom) have an edit button (✏). Built-in test edits are saved as overrides via `save_override()` / `PUT /api/security/builtin/<id>`
- Override store: modified built-in tests are stored in `CustomPatternStore` with `override_of` field, replacing the original in the catalog. Reset to default via `DELETE /api/security/builtin/<id>`
- Custom attack patterns: `CustomPatternStore` with JSON persistence (`/data/custom_patterns.json` or `/tmp/custom_patterns.json`), CRUD via `/api/security/patterns` endpoints
- Custom patterns support: name, category, payload, method, headers, target path, expected action, PAN-OS feature
- `reload_catalog()` must be called after any custom pattern CRUD to refresh the test catalog
- API: `/api/security/catalog`, `/api/security/start`, `/api/security/stop`, `/api/security/status`, `/api/security/clear`, `/api/security/patterns` (GET/POST), `/api/security/patterns/<id>` (PUT/DELETE), `/api/security/builtin/<id>` (GET/PUT/DELETE)
- Echo server endpoints: `GET/POST /echo` (reflects payloads for web attack testing), `GET /eicar`, `GET /eicar.zip`, `GET /test-file/pe`, `GET /test-file/pdf-js`, `GET /test-file/office-macro`
- Server dashboard proxies all security API via `/api/client/<name>/security/*` routes

### Container Capabilities
- `NET_ADMIN`: required for tc/netem, ip addr, iptables
- `NET_RAW`: required for hping3, raw sockets
- Both set in docker-compose files and documented in docker run commands

### Key Files Added/Modified
- `client/security_engine.py` — `SecurityTestEngine` + `CustomPatternStore` classes
- `client/app.py` — Security + custom pattern API endpoints
- `client/static/app.js` — Expandable details, custom pattern modal, enriched result storage (`_securityResults` dict)
- `client/templates/dashboard.html` — Custom pattern modal HTML
- `server/dashboard.py` — Security proxy routes + full security UI in client tabs (JS functions prefixed `client*`)
- `SECURITY_TESTING.md` — User guide for security testing feature

## Git

- Remote origin: https://github.com/ajaymare/traffic-gen.git
- Remote gitlab: https://code.pan.run/netsec/netsec-tme/traffic-tool.git
- Docker images: `ajaymare/traffic-client:latest`, `ajaymare/traffic-server:latest` (amd64)
- Author: Ajay Mare (ajaymaray@gmail.com)
