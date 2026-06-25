# Vortex

Docker-based network traffic generation, security validation, and performance testing tool with a web UI. Designed for NGFW PoCs, SD-WAN demos, and network testing. Two containers — client and server — deploy in minutes.

## Quick Start

### Separate VMs (Recommended)

**Server VM:**

```bash
docker run -d --name vortex-server \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 80:80 -p 443:443 \
  -p 5201:5201 -p 5201:5201/udp \
  -p 5202:5202 -p 5202:5202/udp \
  -p 5203:5203 -p 5203:5203/udp \
  -p 5000:5000 \
  -p 5004-5007:5004-5007/udp \
  -p 9999:9999 -p 53:53/udp \
  -p 21:21 -p 21100-21110:21100-21110 \
  -p 2222:2222 \
  -p 8082:8082 -p 8443:8443 \
  --restart unless-stopped \
  ajaymare/vortex-server:latest
```

**Client VM:**

```bash
docker run -d --name vortex-client \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 8080:8080 -p 8443:8443 \
  -e SERVER_HOST=<server-vm-ip> \
  --restart unless-stopped \
  ajaymare/vortex-client:latest
```

**Access:**
- Client dashboard: `https://<client-ip>:8443` or `http://<client-ip>:8080`
- Server dashboard: `https://<server-ip>:8443` or `http://<server-ip>:8082`

### Using Docker Compose

**Separate VMs:**

```bash
# Server VM
docker compose -f docker-compose.server.yml up -d

# Client VM
SERVER_HOST=<server-ip> docker compose -f docker-compose.client.yml up -d
```

**Same host (local testing):**

```bash
docker compose up -d
```

- Client: `https://localhost:8443` or `http://localhost:8080`
- Server: `https://localhost:18443` or `http://localhost:8082`

## Protocols

| Protocol | Tool | Description |
|----------|------|-------------|
| HTTPS | ab / requests / Playwright | High-CPS mode (default), standard requests, or browser mode with HTTP/2 support |
| HTTP (Plain) | ab / requests / Playwright | High-CPS mode (default) on port 9999, standard requests, or browser mode |
| RTP Audio/Video | ffmpeg | Real-time H.264 video + Opus/G.711 audio RTP streams for App-ID classification and QoS testing |
| Multicast | Python sockets / IGMP | IGMP join + UDP multicast receive — validates PIM, IGMP snooping, multicast routing |
| iperf3 | iperf3 CLI | TCP/UDP bandwidth testing with parallel streams and reverse mode |
| DNS | dig | DNS queries to configurable domains via built-in DNS server |
| FTP | ftplib | Continuous file download/upload with progress logging |
| SSH | sshpass + ssh | Repeated command execution over SSH |
| External HTTPS | requests / Playwright | Multi-URL round-robin to external sites |

## Key Features

### High-CPS Engine
- **Connections-per-second testing** using Apache Bench (`ab`) for HTTP and HTTPS
- New TCP connection per request (no keepalive) — measures real connection setup rate
- **Ramping**: Gradually increase CPS from start value to target in configurable steps (enabled by default)
- **Random packet sizes** enabled by default for realistic traffic patterns
- Per-chunk stats every 5 seconds: CPS, avg latency, P99 latency, request count, errors
- Configurable concurrency (parallel workers)

### RTP Audio/Video
- Real RTP streams via **ffmpeg** with proper codec headers (H.264 video, Opus/G.711 audio)
- Firewalls see authentic `rtp` and `rtcp` App-IDs
- Three modes: **Video Call** (bidirectional), **Streaming** (unidirectional), **Audio Only**
- DSCP marking: Video = AF41, Audio = EF (configurable)
- Configurable resolution (320x240 to 1920x1080), bitrate, and codec
- Server receives streams and sends RTCP feedback; bidirectional mode sends RTP both ways

### Multicast Traffic
- Server sends sequenced UDP multicast, client joins via **IGMP** and receives
- Tests IGMP snooping, PIM routing, and multicast forwarding on firewalls
- Per-second stats: PPS, packet loss percentage (via sequence number tracking)
- Configurable multicast group (default 239.1.1.1), TTL, packet size, target PPS
- Note: Firewall must have PIM/IGMP configured for multicast routing between subnets

### Security Testing (NGFW Validation)
- **30+ attack simulations** across 6 categories:
  - Web Attacks: SQLi, XSS, Command Injection, Path Traversal, Log4Shell, XXE, SSRF, and more
  - Malware/Threats: EICAR download (HTTP/HTTPS/ZIP), C2 callback, malicious User-Agent
  - URL Filtering: PAN-DB category test URLs (malware, phishing, hacking, proxy)
  - DNS Attacks: DNS tunneling, DGA detection, DNS rebinding
  - Protocol Abuse: SSH brute force, FTP bounce, HTTP smuggling, Slowloris
  - File-Based Threats: PDF with JS, Office macros, PE executable download
- Automated pass/fail verdicts based on connection resets, block pages, and response analysis
- Edit any test (built-in or custom), add custom attack patterns
- See [Security Testing Guide](SECURITY_TESTING.md) for details

### Browser Mode (Playwright)
- Real browser traffic using Chromium, Firefox, or WebKit (all pre-installed)
- Authentic TLS fingerprints and L7 headers
- Available on HTTPS, HTTP Plain, and External HTTPS cards
- Browser rotation: specific engine or random per burst cycle

### Traffic Topology Visualization
- Per-protocol traceroute (TCP/UDP) showing SD-WAN path differences
- vis.js network graph with animated traffic flow, latency labels, and router health status
- Enterprise SVG icons: client, server, router, hops, timeout markers

### Router Link Simulation (SSH)
- Connect to Linux routers via SSH — apply tc/netem impairment on real interfaces
- Three modes: Healthy, Impaired (latency/jitter/loss/bandwidth), Link Down
- Presets: Degraded WAN (300ms/5%), Voice SLA (200ms/2%), Video SLA (150ms/3%)
- Multiple routers, independent control per router

### Multi-Client Control
- Server dashboard (`http://<server>:8082`) manages multiple client instances
- Add clients by name + URL — each gets a full control tab
- All API calls proxied through server for centralized management

### Traffic Control
- Duration control (default 15 min), rate control (PPS), burst mode
- Up to 20 parallel flows per protocol
- DSCP marking on all protocols (EF, AF, CS classes)
- Random data sizes, select-all / bulk start-stop

### Proxy Configuration
- Global HTTP/SOCKS5 proxy with optional auth
- Per-protocol override: Global, On, Off, or Custom
- Works with all modes including Playwright browser mode

### Source IP Simulation
- Simulate multiple clients using IP aliases on a single container
- Socket-level binding for authentic multi-client traffic
- Requires `NET_ADMIN` capability

## Server Ports

| Port | Service |
|------|---------|
| 80 | HTTP (nginx) |
| 5000 | Flask API (multicast/RTP coordination) |
| 443 | HTTPS (self-signed cert, HTTP/2) |
| 5201-5203 | iperf3 (3 instances) |
| 5004-5007/udp | RTP video/audio + RTCP, multicast |
| 9999 | HTTP echo server + security test endpoints |
| 53 | DNS server |
| 21 | FTP (passive: 21100-21110) |
| 2222 | SSH |
| 8082 | Server Dashboard |
| 8443 | Dashboard HTTPS |

## Default Credentials

- **SSH**: `testuser` / `testpass`
- **FTP**: `anonymous` (no password) or `ftpuser` / `ftppass`

## Docker Images

Pre-built images (linux/amd64) on Docker Hub:

- `ajaymare/vortex-client:latest`
- `ajaymare/vortex-server:latest`

## Stop and Remove

```bash
docker stop vortex-client vortex-server
docker rm vortex-client vortex-server
```
