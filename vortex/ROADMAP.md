# Vortex Enterprise Feature Roadmap

## Context

The Vortex tool currently has 8 protocols, 45 security tests, network impairment, topology visualization, and multi-client control. To differentiate from commercial tools (Ixia BreakingPoint $50K+, Spirent, Keysight) and become the go-to NGFW PoC tool, we need features that are visually impressive for demos, practically useful for testing, and free.

---

## Phase 1 — P0: Immediate High Impact

### 1. Application Mix Profiles (One-Click Scenarios)
**What:** Pre-built traffic profiles — "Branch Office" (70% web, 10% VoIP, 10% SaaS, 5% video, 5% FTP/SSH), "Data Center", "Remote Worker". One click starts multiple protocols with correct DSCP markings, flow counts, and timing.

**Why wow:** Ixia charges $50K+ for app mixes. SE says "let me simulate your branch office" and clicks one button. Biggest demo impact feature.

**Files:** `client/app.py` (new `/api/profiles` endpoints), `client/static/app.js` (profile selector UI). No engine changes — already supports concurrent multi-protocol jobs.

**Complexity:** Medium

---

### 2. MITRE ATT&CK Mapped Security Tests
**What:** Map all 45 tests to ATT&CK technique IDs. Add a heat-map matrix view (14 tactic columns, colored cells by verdict). Click any cell to see test details.

**Why wow:** Transforms "a list of tests" into "ATT&CK coverage validator." CISOs and security architects judge tools by ATT&CK coverage. No Docker-based tool does this.

**Files:** `client/security_engine.py` (add `attack_id`, `attack_tactic` fields to `SecurityTestCase`), `client/static/app.js` (new ATT&CK matrix view)

**Complexity:** Low-Medium

---

### 3. SSL/TLS Decryption Validation Suite
**What:** Dedicated test suite for SSL decryption: EICAR over TLS 1.2 vs 1.3 with different ciphers, certificate pinning detection, decryption exemption validation (financial/health sites), PFS cipher negotiation. Shows "SSL Decryption Scorecard."

**Why wow:** SSL decryption is #1 anxiety in every NGFW PoC. Answers "does it break things?" and "can it decrypt?" systematically. SEs currently test ad-hoc with curl.

**Files:** `client/security_engine.py` (new `_test_ssl_decryption` method, `SSL_DECRYPTION_TESTS` list)

**Complexity:** Medium

---

### 4. Automated Security Posture Report (PDF/HTML)
**What:** One-click downloadable report: executive summary with risk score, per-category pie charts, individual test details with PAN-OS remediation, ATT&CK coverage matrix, pass/fail breakdown. Professional format.

**Why wow:** This is the deliverable the SE leaves behind after a PoC. Turns a demo tool into a PoC validation artifact. Commercial tools charge per-report licenses.

**Files:** `client/security_engine.py` (new `generate_report`), `client/app.py` (`/api/security/report`), new Jinja2 HTML template

**Complexity:** Medium

---

### 5. Real-Time Traffic Analytics Charts
**What:** Live updating charts: throughput over time per protocol (line chart), latency histogram, error rate sparklines, DSCP distribution pie, active flow table. Chart.js via CDN.

**Why wow:** Current UI shows raw numbers. When SE applies impairment, the throughput chart dips visually — that IS the demo moment. Ixia has charts; this brings it to a free tool.

**Files:** `client/traffic_engine.py` (add time-series `deque` to `TrafficJob`), `client/app.py` (`/api/timeseries`), `client/static/app.js` (Chart.js charts)

**Complexity:** Medium

---

## Phase 2 — P1: High Value Differentiation

### 6. Evasion Technique Testing
**What:** Tests if firewall catches attacks with evasion: double URL encoding, Unicode obfuscation, chunked transfer with split payloads, HTTP parameter pollution, case variation (SeLeCt), comment insertion (SE/\*\*/LECT), IP fragmentation.

**Why wow:** "Your firewall caught plain SQLi — but can it catch double-encoded SQLi?" This is what separates NGFW from basic IPS. What Ixia BreakingPoint's "evasion profiles" do.

**Files:** `client/security_engine.py` (evasion wrapper functions around existing payloads)

**Complexity:** Low

---

### 7. Data Exfiltration / DLP Tests
**What:** Tests outbound data loss: credit card patterns in HTTP POST, SSN/PII in body, base64-encoded data in DNS, encrypted archive upload. Synthetic sensitive data that DLP signatures should catch.

**Why wow:** DLP is a key NGFW differentiator that's hard to demo. "Your firewall caught someone exfiltrating credit card numbers" — compelling for compliance-focused customers.

**Files:** `client/security_engine.py` (new payloads in `ATTACK_PAYLOADS`, new test entries)

**Complexity:** Low

---

### 8. WAN Scenario Playbooks with Timeline
**What:** Automated network impairment sequences: "Fiber Cut Failover" (link down at T+30s, recover at T+120s), "Progressive Degradation" (50ms→500ms over 5 min), "Brown-out Pattern" (random 5s outages). Visual timeline showing events.

**Why wow:** SD-WAN demos always involve link failover. Automates the entire scenario so SE focuses on explaining, not clicking. Timeline visualization makes it visually compelling.

**Files:** `client/router_shaper.py` (new `ScenarioEngine`), `client/app.py` (`/api/scenarios`), `client/static/app.js` (timeline chart)

**Complexity:** Medium

---

### 9. Packet Capture Integration
**What:** Start/stop tcpdump from dashboard with protocol-specific BPF filters. Download PCAP from browser. Live summary (top talkers, protocol distribution) without Wireshark.

**Why wow:** Every PoC, someone asks "can I see the packets?" Currently SE must SSH into container. One-click capture with download eliminates this friction.

**Files:** `client/app.py` (`/api/capture`), new `client/capture_engine.py`

**Complexity:** Medium

---

### 10. PAN-OS Configuration Pre-Flight Validator
**What:** Connects to PAN-OS XML API, pulls running config, validates before testing: Is Vuln Protection attached? Anti-Virus configured? SSL Decryption present? URL Filtering applied? Shows checklist with remediation steps.

**Why wow:** #1 reason tests fail during PoC is misconfigured policy. Pre-flight catches issues before test runs, saving 30 min of debugging. No other tool offers this.

**Files:** New `client/panos_integration.py`, `client/app.py` (`/api/panos/validate`)

**Complexity:** Medium

---

### 11. Firewall Log Correlation View
**What:** Connects to PAN-OS XML API to pull threat/traffic/URL logs. Correlates with test results by timestamp: "Test X at T1 → PAN-OS threat log at T1+0.2s, signature Y, action: reset-both." Unified proof view.

**Why wow:** Instead of PASS/FAIL, show the exact PAN-OS log entry. Irrefutable proof. Eliminates "now let me switch to Panorama" step. Uses same `panos_integration.py` as #10.

**Files:** `client/panos_integration.py` (shared), `client/security_engine.py` (correlation)

**Complexity:** High

---

### 12. SD-WAN Policy Validation Dashboard
**What:** Compares expected path ("HTTPS via MPLS, DNS via Internet") against actual traceroute path. Shows green/red for compliance. When SD-WAN fails over, shows path change in real time.

**Why wow:** Core SD-WAN PoC value. Existing topology shows paths but doesn't validate against policy. Adds "expected vs actual" comparison.

**Files:** `client/app.py` (`/api/sdwan-policy`), `client/static/app.js` (extend topology)

**Complexity:** Low-Medium

---

### 13. SaaS Application Simulation
**What:** Playwright-driven multi-step SaaS journeys: O365 (OneDrive, SharePoint, Outlook), Salesforce, Google Workspace. Real browser generates authentic App-ID signatures.

**Why wow:** When PAN-OS ACC shows real app names (office365-base, google-drive) instead of "web-browsing," the demo is 10x more credible. Impossible with Scapy/locust.

**Files:** `client/traffic_engine.py` (extend `_run_browser_mode` with URL sequences)

**Complexity:** Medium

---

### 14. OpenAPI Spec + CLI Mode
**What:** Formal OpenAPI 3.0 spec with Swagger UI. CLI: `cli.py start-profile "Branch Office"`. Enables CI/CD integration: "every firewall config change → run 45 tests → fail pipeline if attacks pass."

**Why wow:** NetDevOps gold. Turns the tool from "demo helper" to "automated regression testing for firewall policy."

**Files:** `client/app.py` (OpenAPI decorators), new `client/cli.py`

**Complexity:** Low

---

## Phase 3 — P2: Polish

### 15. RTP/Voice/Video Traffic Simulation
Proper RTP streams with SIP signaling, DSCP EF/AF41 marking. SD-WAN QoS demos.

### 16. TLS 1.3 / QUIC/HTTP3 Traffic
Test firewall decryption capabilities and QUIC blocking/fallback.

### 17. Config Import/Export
Export/import entire PoC setup as JSON. Share between SEs.

### 18. Guided PoC Wizard
Step-by-step wizard: connect → validate firewall → select scenario → run → report.

### 19. Dark Mode / Presentation Mode
Projector-optimized dark theme. Presentation mode hides clutter, enlarges charts.

### 20. Topology Annotations
Click to label hops ("MPLS link", "Firewall"), draw zone rectangles, export as PNG.

---

## Recommended Implementation Order

| # | Feature | Complexity | Impact | Est. |
|---|---------|-----------|--------|------|
| 1 | Application Mix Profiles | Medium | Highest | 2-3 days |
| 2 | Real-Time Charts (Chart.js) | Medium | High | 2-3 days |
| 3 | MITRE ATT&CK Matrix | Low-Med | High | 1-2 days |
| 4 | Evasion Techniques | Low | High | 1 day |
| 5 | DLP / Data Exfil Tests | Low | High | 1 day |
| 6 | Security Report (HTML) | Medium | High | 2 days |
| 7 | SSL Decryption Suite | Medium | High | 2 days |
| 8 | PAN-OS Pre-Flight | Medium | High | 2 days |
| 9 | WAN Scenario Playbooks | Medium | High | 2-3 days |
| 10 | Packet Capture | Medium | Medium | 2 days |
| 11 | SD-WAN Policy Validation | Low-Med | High | 1-2 days |
| 12 | Firewall Log Correlation | High | Highest | 3-4 days |
| 13 | SaaS Simulation | Medium | High | 2-3 days |
| 14 | OpenAPI + CLI | Low | Medium | 1 day |
