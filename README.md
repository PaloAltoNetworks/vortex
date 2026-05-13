# Traffic Generator

Docker-based network traffic generation and testing tool with a blue/corporate-themed web UI. Supports multiple protocols with real-time monitoring, per-protocol topology visualization, router-based link simulation via SSH, and multi-client control.

## Protocols

| Protocol | Description |
|----------|-------------|
| HTTPS | GET/POST with optional HTTP/2, SSL bypass, upload mode, browser mode |
| iperf3 | TCP/UDP bandwidth testing with parallel streams, reverse mode |
| hping3 | ICMP, TCP SYN/ACK/FIN, UDP, Traceroute with flood mode |
| HTTP (Plain) | Plain HTTP on port 9999 with configurable data sizes, browser mode |
| DNS | DNS queries to configurable domains via local DNS server |
| FTP | Continuous file download with progress logging |
| SSH | Repeated command execution over SSH |
| External HTTPS | Multi-URL round-robin to external sites, browser mode |

## Architecture

- **Server**: Single container running nginx (HTTP/HTTPS with HTTP/2), iperf3 (3 instances), DNS server (port 53), vsftpd (FTP), openssh (SSH on port 2222), server dashboard — managed by supervisord
- **Client**: Web UI (Flask) with traffic engine, SSH-based router link simulation, and source IP simulation
- **Server Dashboard**: Unified multi-client control panel with tabs — monitor server stats and control multiple clients from a single UI

## Deployment

### Separate VMs (Recommended)

**Server VM:**

```bash
docker compose -f docker-compose.server.yml up -d
```

**Client VM:**

```bash
SERVER_HOST=<server-vm-ip> docker compose -f docker-compose.client.yml up -d
```

- Client dashboard: `https://<client-vm-ip>:8443` (or `http://<client-vm-ip>:8080`)
- Server dashboard: `https://<server-vm-ip>:8443` (or `http://<server-vm-ip>:8082`)

### Same Server

Run both containers on a single machine for local testing:

```bash
docker compose up -d
```

- Client dashboard: `https://<server-ip>:8443` (or `http://<server-ip>:8080`)
- Server dashboard: `https://<server-ip>:18443` (or `http://<server-ip>:8082`)

## Features

### Security Testing (NGFW Validation)
- **Web Attack Tests**: SQL Injection (UNION, OR 1=1, DROP TABLE), XSS (script tag, IMG onerror, SVG onload), Command Injection (cat, pipe, backtick), Path Traversal, Log4Shell (JNDI)
- **Malware/Threat Tests**: EICAR anti-malware download over HTTP and HTTPS, EICAR in ZIP archive, C2 callback pattern, malicious User-Agent strings
- **URL Filtering Tests**: PAN-DB category test URLs — malware, phishing, hacking, proxy/anonymizer
- **Firewall detection**: Automatic pass/fail verdicts based on connection resets, timeouts, block pages, and response analysis
- **Real-time results**: Live verdict updates with color-coded PASS (blocked by firewall) / FAIL (passed through) indicators
- **SSL Decryption validation**: EICAR over HTTPS tests whether the firewall's SSL Decryption policy is working
- **Configurable test URLs**: URL Filtering test URLs can be changed at runtime
- **See [Security Testing Guide](SECURITY_TESTING.md)** for detailed usage instructions

### Traffic Control
- **Duration control**: Default 15-minute test duration, configurable per protocol
- **Rate control (pps)**: Set target packets-per-second instead of manual interval
- **Burst mode**: Send N requests rapidly, pause for X seconds, repeat
- **Multiple flows**: Run up to 20 parallel flows per protocol
- **DSCP marking**: Set QoS markings (EF, AF, CS classes) on all protocols
- **Random data sizes**: Toggle random packet/file sizes for HTTPS, HTTP, FTP
- **Select all / bulk actions**: Start or stop multiple protocols at once
- **Collapsible protocol cards**: Click to expand, advanced fields (DSCP, burst, rate) hidden behind toggle

### Browser Mode (Playwright)
- **Real browser traffic**: Toggle Browser Mode on HTTPS, HTTP Plain, or External HTTPS to use Playwright headless browsers instead of Python HTTP clients
- **Authentic fingerprints**: Generates real TLS fingerprints, User-Agent strings, and L7 headers (Sec-CH-UA, Sec-Fetch-*, Accept-Language) indistinguishable from real browsers
- **3 browser engines**: Chromium (Chrome/Edge/Brave), Firefox (Gecko), WebKit (Safari) — all installed in the container
- **Browser rotation**: Choose a specific browser or Random to rotate between all 3 engines each burst cycle
- **Full page loads**: Loads JS, CSS, images, fonts — triggers all sub-requests a real browser would make
- **Proxy support**: Works with global, per-protocol, and custom proxy configurations

### Proxy Configuration
- **Global proxy**: Configure HTTP or SOCKS5 proxy with optional authentication for all protocols
- **Per-protocol override**: Each protocol can use Global proxy, force On/Off, or specify a Custom proxy
- **Custom proxy**: Per-protocol custom proxy with independent type, host, port, and credentials

### Router-Based Link Simulation
- **SSH-based**: Connect to Linux routers via SSH, apply tc/netem impairment on real interfaces
- **Multiple routers**: Add and manage multiple routers independently
- **Interface discovery**: Auto-discover interfaces with IP addresses and state
- **Three modes**: Healthy (clear impairment), Impaired (latency/jitter/loss/bandwidth), Link Down (interface down)
- **Presets**: Degraded WAN (300ms/5%), Voice SLA (200ms/2%), Video SLA (150ms/3%)
- **Independent control**: Each router has its own interface selection and impairment state

### Source IP Simulation
- **Random source IPs**: Simulate multiple clients from a single container using IP aliases
- **Socket-level binding**: TCP sockets bound to alias IPs via `source_address` for authentic multi-client simulation
- **Session rotation**: HTTP sessions recreated on IP change to maintain clean keep-alive connections

### Traffic Topology
- **Per-protocol traceroute**: Each protocol runs its own TCP/UDP traceroute (e.g., TCP port 443 for HTTPS, UDP port 53 for DNS) to reveal SD-WAN policy routing differences
- **Multi-path visualization**: vis.js network graph shows all discovered paths with color-coded edges per protocol
- **Enterprise-grade SVG icons**: Laptop with status LED (client), server rack with drive bays and LEDs (server), router with directional arrows and status ring, numbered hop circles, red X timeout markers
- **IP subtitle labels**: Each node displays its IP address as a subtitle below the name
- **Edge latency labels**: RTT latency displayed directly on edges (e.g., "2.3 ms") for at-a-glance visibility
- **Path merging**: Paths with identical hops automatically merge to reduce clutter, with protocol labels combined
- **Smooth 8-phase animation**: Animated dash flow with opacity cycling on active traffic edges (300ms interval)
- **Structured tooltips**: Card-style tooltips with colored left border and color-coded latency (green <20ms, yellow 20-100ms, red >100ms)
- **Pulsing legend**: Active protocol dots pulse with CSS animation; line segments show edge colors
- **Stats bar mini cards**: Per-protocol stat cards with colored accent borders showing bytes, requests, and errors
- **Dot-grid canvas**: Subtle radial-gradient dot pattern background for professional diagram feel
- **Empty state**: SVG placeholder with "Start a protocol to see topology" when no flows are active
- **30-second cache**: Traceroute results cached per protocol to avoid excessive probing

### Monitoring
- **Live stats**: Real-time bytes sent/received, request count, error tracking with 2-second auto-refresh
- **Clear stats**: Reset all accumulated counters to zero on both client and server dashboards
- **Activity logs**: Detailed per-request logs for every protocol (up to 200 entries, chronologically sorted)
- **Countdown timer**: Shows remaining time for each running traffic flow
- **Blue/corporate theme**: Enterprise-grade interface with collapsible sections and white cards
- **Inline notifications**: Toast-style notifications for service restarts instead of browser popups
- **Docker healthchecks**: Both containers report health status via `docker ps`

### Protocol-Specific
- **HTTPS with HTTP/2**: Toggle HTTP/2 for true HTTP/2 traffic using httpx with h2 (App-ID: web-browsing)
- **iperf3**: TCP/UDP with configurable bandwidth, parallel streams, reverse mode; 3 server instances (ports 5201-5203)
- **hping3**: ICMP ping, TCP SYN/ACK/FIN scans, UDP probes, traceroute with flood mode, custom TTL and DSCP
- **DNS**: Queries configurable domain list via built-in DNS server on port 53
- **FTP file management**: Upload custom files to server via dashboard, download with progress logging
- **Multi-client control**: Server dashboard (port 8082) with tabs to manage multiple clients

## Server Ports

| Port | Service |
|------|---------|
| 80 | HTTP (nginx) |
| 443 | HTTPS (self-signed cert, HTTP/2 enabled) |
| 5201-5203 | iperf3 (3 instances for concurrent clients) |
| 9999 | HTTP echo server (+ security test endpoints) |
| 53 | DNS server |
| 21 | FTP |
| 21100-21110 | FTP passive |
| 2222 | SSH (testuser/testpass) |
| 8082 | Server Dashboard (HTTP) |
| 8443 | Dashboard HTTPS (self-signed cert) |

## Default Credentials

- **SSH**: `testuser` / `testpass`
- **FTP**: `anonymous` (no password) or `ftpuser` / `ftppass`

## Run from Docker Hub (No Build Required)

Images (amd64) are available on Docker Hub.

### Separate VMs (Recommended)

**Server VM:**

```bash
docker run -d --name traffic-server \
  -p 80:80 -p 443:443 \
  -p 5201:5201 -p 5201:5201/udp \
  -p 5202:5202 -p 5202:5202/udp \
  -p 5203:5203 -p 5203:5203/udp \
  -p 9999:9999 -p 53:53/udp \
  -p 21:21 -p 21100-21110:21100-21110 \
  -p 2222:2222 \
  -p 8082:8082 \
  -p 8443:8443 \
  --restart unless-stopped \
  ajaymare/traffic-server:latest
```

**Client VM:**

```bash
docker run -d --name traffic-client \
  --cap-add NET_ADMIN \
  -p 8080:8080 \
  -p 8443:8443 \
  -e SERVER_HOST=<server-vm-ip> \
  --restart unless-stopped \
  ajaymare/traffic-client:latest
```

- Client dashboard: `https://<client-vm-ip>:8443` (or `http://<client-vm-ip>:8080`)
- Server dashboard: `https://<server-vm-ip>:8443` (or `http://<server-vm-ip>:8082`)

### Same Server

```bash
# Create a docker network
docker network create traffic-net

# Start server
docker run -d --name traffic-server \
  --network traffic-net \
  -p 80:80 -p 443:443 \
  -p 5201:5201 -p 5201:5201/udp \
  -p 5202:5202 -p 5202:5202/udp \
  -p 5203:5203 -p 5203:5203/udp \
  -p 9999:9999 -p 53:53/udp \
  -p 21:21 -p 21100-21110:21100-21110 \
  -p 2222:2222 \
  -p 8082:8082 \
  -p 18443:8443 \
  --restart unless-stopped \
  ajaymare/traffic-server:latest

# Start client (points to server container by name)
docker run -d --name traffic-client \
  --network traffic-net \
  --cap-add NET_ADMIN \
  -p 8080:8080 \
  -p 8443:8443 \
  -e SERVER_HOST=traffic-server \
  --restart unless-stopped \
  ajaymare/traffic-client:latest
```

- Client dashboard: `https://<server-ip>:8443` (or `http://<server-ip>:8080`)
- Server dashboard: `https://<server-ip>:18443` (or `http://<server-ip>:8082`)

### Stop and Remove

```bash
docker stop traffic-client traffic-server
docker rm traffic-client traffic-server
docker network rm traffic-net  # if using same-server setup
```

## Server Dashboard — Multi-Client Control

The server dashboard (`http://<server>:8082`) provides a unified control panel:

1. **Server tab**: Aggregate traffic stats, per-service status, active connections, FTP file management (upload/delete)
2. **Client tabs**: Click "+" to register clients by name and URL. Each tab provides full protocol controls, router link simulation, source IP configuration, and live activity logs — all proxied through the server.

## Router Link Simulation

Simulate WAN impairment on upstream Linux routers for SD-WAN demos:

1. Open dashboard → Link Simulation — Routers
2. Add a router (name, IP, SSH username/password) → auto-connects and discovers interfaces
3. Select an interface → choose a preset or set custom impairment values
4. Click **Healthy**, **Apply Impaired**, or **Link Down** to change the link state
5. Each router operates independently — impair one WAN link while keeping another healthy

Requires SSH access to the router with sudo privileges for `tc` and `ip` commands.

## Random Source IPs

Simulate traffic from multiple clients using a single container:

1. Open client dashboard → Source IP Simulation (click to expand)
2. Check **Random Source IPs**, set Base IP and Count → click **Apply**
3. Each connection binds its TCP socket to a random alias IP at the OS level
4. Sessions are automatically recreated when the source IP rotates to maintain clean connections

Requires `NET_ADMIN` capability (already included in docker run commands above).
