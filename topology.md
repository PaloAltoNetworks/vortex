# Topology Visualization

Live, auto-discovering network map built from real `traceroute` data, rendered with [vis.js Network](https://visjs.org/). No static topology definition — the path is discovered dynamically as traffic flows.

## Architecture

```
Browser (10s poll)          Client Container                    Network
      │                          │                                │
      │  GET /api/topology       │                                │
      ├─────────────────────────>│                                │
      │                          │  traceroute -T -p 443 server   │
      │                          ├───────────────────────────────>│
      │                          │  hop1: 10.0.0.1 (2.5ms)       │
      │                          │  hop2: 10.0.0.2 (5.1ms)       │
      │                          │<───────────────────────────────┤
      │  { paths, routers }      │                                │
      │<─────────────────────────┤                                │
      │                          │                                │
  renderTopology()               │                                │
  vis.js graph                   │                                │
```

## Data Collection (Backend)

### `/api/topology` endpoint (`client/app.py`)

Polled every 10 seconds by the browser. For each **running** protocol, it:

1. Runs `traceroute` with protocol-specific flags
2. Parses output into hop objects: `{hop: 1, ip: "10.0.0.1", rtt: "2.5"}`
3. Caches results for 30 seconds to avoid excessive traceroute calls
4. Overlays router state from `router_shaper.py` (healthy/impaired/link_down)

### Per-Protocol Traceroute Flags

| Protocol | Command | Method |
|----------|---------|--------|
| HTTPS | `traceroute -T -p 443` | TCP SYN |
| HTTP | `traceroute -T -p 9999` | TCP SYN |
| DNS | `traceroute -U -p 53` | UDP |
| iperf3 | `traceroute -T -p 5201` | TCP SYN |
| FTP | `traceroute -T -p 21` | TCP SYN |
| SSH | `traceroute -T -p 2222` | TCP SYN |
| hping3 | `traceroute -I` | ICMP |
| Ext HTTPS | `traceroute -T -p 443` | TCP SYN |

Different protocols may take different network paths (e.g., SD-WAN policy-based routing), so each gets its own traceroute.

### Traceroute Parsing (`_run_traceroute()`)

```
sudo traceroute -n -q 1 -w 2 -m 15 [-T -p PORT] <dest>
```

- `-n`: no DNS resolution (faster)
- `-q 1`: single query per hop (faster)
- `-w 2`: 2-second timeout per hop
- `-m 15`: max 15 hops
- Trailing consecutive timeouts are trimmed (keeps at most 1)

### Parallel Execution

Running protocols are traced in parallel using `ThreadPoolExecutor(max_workers=4)` to avoid serial delays when multiple protocols are active.

### Response Format

```json
{
  "client_ip": "172.20.0.10",
  "server_host": "172.20.0.20",
  "paths": {
    "https": {
      "label": "HTTPS",
      "dest": "172.20.0.20",
      "port": 443,
      "hops": [
        {"hop": 1, "ip": "10.0.0.1", "rtt": "2.5"},
        {"hop": 2, "ip": "172.20.0.20", "rtt": "5.1"}
      ],
      "running": true,
      "stats": {"bytes_sent": 1024, "bytes_recv": 2048, "requests": 10, "errors": 0}
    }
  },
  "routers": [
    {"ip": "10.0.0.1", "name": "WAN-Router", "current_mode": "healthy"}
  ]
}
```

## Rendering (Frontend)

### vis.js Hierarchical Graph (`client/static/app.js`)

`renderTopology()` builds a left-to-right directed graph:

```
[Client] ──hop1──> [Router] ──hop2──> [Hop 2] ──hop3──> [Server]
   💻                 🔵                  ⭕                🖥️
```

### Node Types

| Type | Icon | When Used |
|------|------|-----------|
| **Client** | Green laptop | Always present, shows client IP |
| **Server** | Blue server rack | Always present, shows server host |
| **Router** | Circle, color-coded | Hop IP matches a configured router |
| **Hop** | Numbered circle | Unknown intermediate device |
| **Timeout** | Red X with dashed border | Hop returned `*` (no response) |

Each node type has a custom inline SVG icon defined in `TOPO_ICONS`.

### Router Status Colors

Routers discovered via traceroute that match configured routers (from `router_shaper.py`) are color-coded:

| Status | Fill | Stroke | Meaning |
|--------|------|--------|---------|
| Healthy | `#ecfdf5` | `#059669` (green) | No impairment applied |
| Impaired | `#fffbeb` | `#d97706` (amber) | tc/netem shaping active |
| Link Down | `#fef2f2` | `#dc2626` (red) | Interface brought down |

### Edge Rendering

- **Color-coded per protocol** — 10-color palette (`TOPO_COLORS`), each protocol gets a unique color
- **Animated dashes** for active traffic — `animateTopology()` cycles dash patterns and width every 300ms
- **Latency labels** on edges showing RTT in ms
- **Arrow heads** (vee type) showing traffic direction
- **Curved paths** — alternating `curvedCW`/`curvedCCW` so overlapping routes don't stack

### Path Merging

Protocols that traverse identical hops are merged into a single visual path with combined labels. This prevents visual clutter when multiple protocols share the same route. The merge key is the comma-joined hop IPs.

### Animation (`animateTopology()`)

Active edges pulse with cycling dash patterns and width:
- 8-frame cycle at 300ms intervals
- Dash patterns shift: `[12,4] → [10,5] → [8,6] → ...`
- Width pulses: `3.5 → 3.8 → 4.0 → 4.2 → ...`
- Opacity varies: `1.0 → 0.95 → 0.9 → ...`

Creates a visual "flowing traffic" effect on active protocol paths.

### Interactive Features

- **Tooltips on hover** — IP address, latency, router impairment details (delay, jitter, loss, bandwidth)
- **Latency color coding** in tooltips: green (<20ms), amber (20-100ms), red (>100ms)
- **Protocol legend** — colored dots showing which protocol maps to which path, active/inactive state
- **Stats bar** — live bytes/requests per running protocol
- **Draggable nodes** — reposition nodes for better viewing
- **Zoomable** — scroll to zoom in/out

### Empty State

When no protocols are running, the topology container shows a placeholder with three gray circles connected by dashed lines and the message "Start a protocol to see network topology."

## Example Topology Scenarios

### Single Host (Docker Bridge)

```
[Client 172.20.0.10] ────────────> [Server 172.20.0.20]
```

Direct connection, no intermediate hops (same Docker bridge network).

### Split Deployment (Through SD-WAN Routers)

```
                              ┌─ [Router-1 10.0.0.1] ─────┐
[Client 192.168.1.10] ───────┤  (impaired: 50ms, 5% loss) ├───> [Server 10.10.0.20]
                              └─ [Router-2 10.0.0.2] ─────┘
                                 (healthy)
```

Different protocols may take different paths based on SD-WAN policy-based routing, each shown in a different color with its own latency labels.

## Key Files

| File | Role |
|------|------|
| `client/app.py` | `/api/topology` endpoint, `_run_traceroute()`, `PROTO_TRACEROUTE` config |
| `client/static/app.js` | `renderTopology()`, `animateTopology()`, `TOPO_ICONS`, vis.js graph |
| `client/templates/dashboard.html` | `#topology-container` div, card layout |
| `client/static/style.css` | `.topo-*` CSS classes for legend, stats, tooltips |
