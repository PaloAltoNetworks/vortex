const SRV = (typeof SERVER_HOST !== 'undefined') ? SERVER_HOST : 'server';

const DSCP_OPTIONS = ['BE','CS1','AF11','AF12','AF13','CS2','AF21','AF22','AF23','CS3','AF31','AF32','AF33','CS4','AF41','AF42','AF43','CS5','VA','EF','CS6','CS7'];
const ADVANCED_KEYS = ['browser_mode', 'browser_type', 'proxy', 'dscp', 'rate_pps', 'burst_enabled', 'burst_count', 'burst_pause'];

const PROTOCOLS = {
    https: {
        name: 'HTTPS',
        appId: 'web-browsing',
        fields: [
            { key: 'url', label: 'URL', type: 'text', get default() { return `https://${SRV}/`; } },
            { key: 'method', label: 'Method', type: 'select', options: ['GET', 'POST'], default: 'GET' },
            { key: 'data_size_kb', label: 'Data KB', type: 'number', default: 0 },
            { key: 'interval', label: 'Interval (s)', type: 'number', default: 1, step: 0.1 },
            { key: 'http2', label: 'HTTP/2', type: 'checkbox', default: false },
            { key: 'ignore_ssl', label: 'Ignore SSL', type: 'checkbox', default: true },
            { key: 'upload', label: 'Upload Mode', type: 'checkbox', default: false },
            { key: 'random_size', label: 'Random Size', type: 'checkbox', default: false },
            { key: 'browser_mode', label: 'Browser Mode', type: 'checkbox', default: false },
            { key: 'browser_type', label: 'Browser', type: 'select', options: ['Random', 'Chromium', 'Firefox', 'WebKit'], default: 'Random' },
            { key: 'proxy', label: 'Proxy', type: 'select', options: ['Global', 'On', 'Off', 'Custom'], default: 'Global' },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'rate_pps', label: 'Rate (pps)', type: 'number', default: 0, step: 1 },
            { key: 'burst_enabled', label: 'Burst Mode', type: 'checkbox', default: false },
            { key: 'burst_count', label: 'Burst Size', type: 'number', default: 5 },
            { key: 'burst_pause', label: 'Burst Pause (s)', type: 'number', default: 2, step: 0.5 },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    iperf: {
        name: 'iperf3',
        appId: 'iperf',
        fields: [
            { key: 'host', label: 'Host', type: 'text', get default() { return SRV; } },
            { key: 'port', label: 'Port', type: 'number', default: 5201 },
            { key: 'protocol', label: 'Protocol', type: 'select', options: ['TCP', 'UDP'], default: 'TCP' },
            { key: 'bandwidth', label: 'Bandwidth', type: 'text', default: '100M' },
            { key: 'parallel', label: 'Parallel Streams', type: 'number', default: 1 },
            { key: 'reverse', label: 'Reverse (download)', type: 'checkbox', default: false },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    hping3: {
        name: 'hping3',
        appId: 'ping, ip-protocol-custom',
        fields: [
            { key: 'host', label: 'Host', type: 'text', get default() { return SRV; } },
            { key: 'mode', label: 'Mode', type: 'select', options: ['ICMP', 'TCP SYN', 'TCP ACK', 'TCP FIN', 'UDP', 'Traceroute'], default: 'ICMP' },
            { key: 'port', label: 'Dest Port', type: 'number', default: 0 },
            { key: 'packet_size', label: 'Data Size (B)', type: 'number', default: 64 },
            { key: 'count', label: 'Count (0=cont)', type: 'number', default: 0 },
            { key: 'interval', label: 'Interval (s)', type: 'number', default: 1, step: 0.1 },
            { key: 'flood', label: 'Flood Mode', type: 'checkbox', default: false },
            { key: 'ttl', label: 'TTL', type: 'number', default: 64 },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    http_plain: {
        name: 'HTTP (Plain)',
        appId: 'web-browsing',
        fields: [
            { key: 'host', label: 'Host', type: 'text', get default() { return SRV; } },
            { key: 'port', label: 'Port', type: 'number', default: 9999 },
            { key: 'method', label: 'Method', type: 'select', options: ['GET', 'POST'], default: 'GET' },
            { key: 'data_size_kb', label: 'Data Size (KB)', type: 'number', default: 1 },
            { key: 'interval', label: 'Interval (s)', type: 'number', default: 1, step: 0.1 },
            { key: 'random_size', label: 'Random Size', type: 'checkbox', default: false },
            { key: 'browser_mode', label: 'Browser Mode', type: 'checkbox', default: false },
            { key: 'browser_type', label: 'Browser', type: 'select', options: ['Random', 'Chromium', 'Firefox', 'WebKit'], default: 'Random' },
            { key: 'proxy', label: 'Proxy', type: 'select', options: ['Global', 'On', 'Off', 'Custom'], default: 'Global' },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'rate_pps', label: 'Rate (pps)', type: 'number', default: 0, step: 1 },
            { key: 'burst_enabled', label: 'Burst Mode', type: 'checkbox', default: false },
            { key: 'burst_count', label: 'Burst Size', type: 'number', default: 5 },
            { key: 'burst_pause', label: 'Burst Pause (s)', type: 'number', default: 2, step: 0.5 },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    dns: {
        name: 'DNS',
        appId: 'dns',
        fields: [
            { key: 'host', label: 'Host', type: 'text', get default() { return SRV; } },
            { key: 'port', label: 'Port', type: 'number', default: 53 },
            { key: 'domains', label: 'Domains (one per line)', type: 'textarea', default: 'google.com\namazon.com\nmicrosoft.com\ngithub.com\ncloudflare.com' },
            { key: 'interval', label: 'Interval (s)', type: 'number', default: 1, step: 0.1 },
            { key: 'proxy', label: 'Proxy', type: 'select', options: ['Global', 'On', 'Off', 'Custom'], default: 'Global' },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'rate_pps', label: 'Rate (pps)', type: 'number', default: 0, step: 1 },
            { key: 'burst_enabled', label: 'Burst Mode', type: 'checkbox', default: false },
            { key: 'burst_count', label: 'Burst Size', type: 'number', default: 5 },
            { key: 'burst_pause', label: 'Burst Pause (s)', type: 'number', default: 2, step: 0.5 },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    ftp: {
        name: 'FTP',
        appId: 'ftp',
        maxFlows: 1,
        fields: [
            { key: 'host', label: 'Host', type: 'text', get default() { return SRV; } },
            { key: 'port', label: 'Port', type: 'number', default: 21 },
            { key: 'username', label: 'Username', type: 'text', default: 'anonymous' },
            { key: 'password', label: 'Password', type: 'password', default: '' },
            { key: 'filename', label: 'Filename', type: 'select', options: ['testfile_100mb.bin'], default: 'testfile_100mb.bin' },
            { key: 'random_size', label: 'Random File', type: 'checkbox', default: false },
            { key: 'proxy', label: 'Proxy', type: 'select', options: ['Global', 'On', 'Off', 'Custom'], default: 'Global' },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    ssh: {
        name: 'SSH',
        appId: 'ssh',
        fields: [
            { key: 'host', label: 'Host', type: 'text', get default() { return SRV; } },
            { key: 'port', label: 'Port', type: 'number', default: 2222 },
            { key: 'username', label: 'Username', type: 'text', default: 'testuser' },
            { key: 'password', label: 'Password', type: 'password', default: 'testpass' },
            { key: 'command', label: 'Command', type: 'text', default: 'uptime' },
            { key: 'interval', label: 'Interval (s)', type: 'number', default: 5 },
            { key: 'proxy', label: 'Proxy', type: 'select', options: ['Global', 'On', 'Off', 'Custom'], default: 'Global' },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'rate_pps', label: 'Rate (pps)', type: 'number', default: 0, step: 1 },
            { key: 'burst_enabled', label: 'Burst Mode', type: 'checkbox', default: false },
            { key: 'burst_count', label: 'Burst Size', type: 'number', default: 5 },
            { key: 'burst_pause', label: 'Burst Pause (s)', type: 'number', default: 2, step: 0.5 },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
    ext_https: {
        name: 'External HTTPS',
        appId: 'ssl, web-browsing',
        fields: [
            { key: 'urls', label: 'Target URLs (one per line)', type: 'textarea', default: 'https://www.google.com' },
            { key: 'method', label: 'Method', type: 'select', options: ['GET', 'POST', 'HEAD'], default: 'GET' },
            { key: 'interval', label: 'Interval (s)', type: 'number', default: 1, step: 0.1 },
            { key: 'ignore_ssl', label: 'Ignore SSL', type: 'checkbox', default: false },
            { key: 'browser_mode', label: 'Browser Mode', type: 'checkbox', default: false },
            { key: 'browser_type', label: 'Browser', type: 'select', options: ['Random', 'Chromium', 'Firefox', 'WebKit'], default: 'Random' },
            { key: 'proxy', label: 'Proxy', type: 'select', options: ['Global', 'On', 'Off', 'Custom'], default: 'Global' },
            { key: 'dscp', label: 'DSCP', type: 'select', options: DSCP_OPTIONS, default: 'BE' },
            { key: 'rate_pps', label: 'Rate (pps)', type: 'number', default: 0, step: 1 },
            { key: 'burst_enabled', label: 'Burst Mode', type: 'checkbox', default: false },
            { key: 'burst_count', label: 'Burst Size', type: 'number', default: 5 },
            { key: 'burst_pause', label: 'Burst Pause (s)', type: 'number', default: 2, step: 0.5 },
            { key: 'flows', label: 'Flows', type: 'number', default: 1 },
            { key: 'duration', label: 'Duration (s)', type: 'number', default: 900 },
        ]
    },
};

// ─── Section Toggle ─────────────────────────────────────────

function toggleSection(name) {
    const body = document.getElementById('section-' + name);
    const chevron = document.getElementById('chevron-' + name);
    if (!body) return;
    body.classList.toggle('collapsed');
    if (chevron) chevron.classList.toggle('collapsed');
}

// ─── Protocol Card Toggle ───────────────────────────────────

function toggleProtoDetails(proto) {
    const el = document.getElementById('details-' + proto);
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function toggleCustomProxy(proto) {
    const sel = document.getElementById('cfg-' + proto + '-proxy');
    const custom = document.getElementById('cfg-' + proto + '-proxy-custom');
    if (sel && custom) custom.style.display = sel.value === 'Custom' ? 'block' : 'none';
}

function toggleAdvanced(proto) {
    const el = document.getElementById('adv-' + proto);
    const toggle = document.getElementById('adv-toggle-' + proto);
    if (el) {
        const show = el.style.display === 'none';
        el.style.display = show ? 'block' : 'none';
        if (toggle) toggle.textContent = show ? 'Advanced Settings \u25BE' : 'Advanced Settings \u25B8';
    }
}

// ─── Render ────────────────────────────────────────────────

function renderProtocolCards() {
    const grid = document.getElementById('protocol-grid');
    grid.innerHTML = '';

    for (const [proto, def] of Object.entries(PROTOCOLS)) {
        // Basic fields
        let basicHtml = '';
        let advancedHtml = '';
        let hasAdvanced = false;

        for (const f of def.fields) {
            if (f.key === 'flows') continue;
            const isAdv = ADVANCED_KEYS.includes(f.key);
            let input;
            if (f.key === 'proxy') {
                const opts = f.options.map(o =>
                    `<option value="${o}" ${o === f.default ? 'selected' : ''}>${o}</option>`).join('');
                input = `<select id="cfg-${proto}-${f.key}" onchange="toggleCustomProxy('${proto}')">${opts}</select>`;
                const customFields = `<div id="cfg-${proto}-proxy-custom" style="display:none;margin-top:4px;padding:6px;background:var(--bg-sub);border:1px solid var(--border);border-radius:4px">` +
                    `<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 6px;align-items:center;font-size:11px">` +
                    `<label style="color:var(--text-secondary)">Type</label>` +
                    `<select id="cfg-${proto}-proxy_type" style="padding:2px 6px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px"><option value="http">HTTP</option><option value="socks5">SOCKS5</option></select>` +
                    `<label style="color:var(--text-secondary)">Host</label>` +
                    `<input type="text" id="cfg-${proto}-proxy_host" placeholder="proxy.example.com" style="padding:2px 6px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px">` +
                    `<label style="color:var(--text-secondary)">Port</label>` +
                    `<input type="number" id="cfg-${proto}-proxy_port" value="8080" style="padding:2px 6px;font-size:11px;width:80px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px">` +
                    `<label style="color:var(--text-secondary)">User</label>` +
                    `<input type="text" id="cfg-${proto}-proxy_user" placeholder="(optional)" style="padding:2px 6px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px">` +
                    `<label style="color:var(--text-secondary)">Pass</label>` +
                    `<input type="password" id="cfg-${proto}-proxy_pass" placeholder="(optional)" style="padding:2px 6px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px">` +
                    `</div></div>`;
                const row = `<div class="field-row"><label>${f.label}</label>${input}</div>${customFields}`;
                advancedHtml += row; hasAdvanced = true;
                continue;
            } else if (f.type === 'select') {
                const opts = f.options.map(o =>
                    `<option value="${o}" ${o === f.default ? 'selected' : ''}>${o}</option>`).join('');
                input = `<select id="cfg-${proto}-${f.key}">${opts}</select>`;
            } else if (f.type === 'textarea') {
                input = `<textarea id="cfg-${proto}-${f.key}" rows="3" style="width:100%;padding:6px 8px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:4px;resize:vertical;font-family:inherit">${f.default}</textarea>`;
            } else if (f.type === 'checkbox') {
                input = `<input type="checkbox" id="cfg-${proto}-${f.key}" ${f.default ? 'checked' : ''}>`;
            } else {
                const step = f.step ? `step="${f.step}"` : '';
                input = `<input type="${f.type}" id="cfg-${proto}-${f.key}" value="${f.default}" ${step}>`;
            }
            const row = `<div class="field-row"><label>${f.label}</label>${input}</div>`;
            if (isAdv) { advancedHtml += row; hasAdvanced = true; }
            else basicHtml += row;
        }

        const appIdHtml = def.appId ? `<div class="proto-appid">App-ID: ${def.appId}</div>` : '';

        let advSection = '';
        if (hasAdvanced) {
            advSection = `<div class="advanced-toggle" id="adv-toggle-${proto}" onclick="event.stopPropagation();toggleAdvanced('${proto}')">Advanced Settings \u25B8</div>
                <div class="advanced-fields" id="adv-${proto}" style="display:none">${advancedHtml}</div>`;
        }

        grid.innerHTML += `
            <div class="proto-card" id="proto-${proto}">
                <div class="proto-header" onclick="toggleProtoDetails('${proto}')">
                    <span class="proto-select" onclick="event.stopPropagation()">
                        <input type="checkbox" id="select-${proto}" class="proto-checkbox">
                        <span class="proto-name">${def.name}</span>
                    </span>
                    <span class="proto-header-right">
                        <span class="proto-badge" id="status-${proto}">Stopped</span>
                        <span class="proto-badge countdown" id="timer-${proto}" style="display:none"></span>
                        <button class="btn btn-start" onclick="event.stopPropagation();startProto('${proto}')" style="padding:3px 10px;font-size:10px">Start</button>
                        <button class="btn btn-stop" onclick="event.stopPropagation();stopProto('${proto}')" style="padding:3px 10px;font-size:10px">Stop</button>
                    </span>
                </div>
                <div class="proto-details" id="details-${proto}" style="display:none">
                    ${appIdHtml}
                    <div class="proto-fields">${basicHtml}</div>
                    ${advSection}
                    <div class="proto-actions" style="margin-top:6px">
                        <label style="font-size:10px;color:var(--text-secondary);display:flex;align-items:center;gap:4px">
                            Flows <input type="number" id="cfg-${proto}-flows" value="1" min="1" max="20" style="width:42px;padding:2px 4px;font-size:10px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px">
                        </label>
                    </div>
                </div>
            </div>`;
    }
}

// ─── API ───────────────────────────────────────────────────

async function apiPost(url, body) {
    const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return r.json();
}

function getConfig(proto) {
    const cfg = {};
    for (const f of PROTOCOLS[proto].fields) {
        if (f.key === 'flows') continue;
        const el = document.getElementById(`cfg-${proto}-${f.key}`);
        if (f.type === 'checkbox') cfg[f.key] = el.checked;
        else if (f.type === 'number') cfg[f.key] = parseFloat(el.value);
        else cfg[f.key] = el.value;
    }
    // Custom proxy override: include custom proxy fields
    if (cfg.proxy === 'Custom') {
        const g = id => document.getElementById(`cfg-${proto}-${id}`);
        cfg.proxy_type = g('proxy_type')?.value || 'http';
        cfg.proxy_host = g('proxy_host')?.value || '';
        cfg.proxy_port = parseInt(g('proxy_port')?.value || 8080);
        cfg.proxy_user = g('proxy_user')?.value || '';
        cfg.proxy_pass = g('proxy_pass')?.value || '';
    }
    return cfg;
}

function getFlowCount(proto) {
    const el = document.getElementById(`cfg-${proto}-flows`);
    return el ? Math.max(1, Math.min(20, parseInt(el.value) || 1)) : 1;
}

async function startProto(proto) {
    const config = getConfig(proto);
    const maxFlows = PROTOCOLS[proto].maxFlows || 20;
    const flows = Math.min(getFlowCount(proto), maxFlows);
    if (flows === 1) {
        const res = await apiPost('/api/start', { protocol: proto, config });
        addLog(`[${proto.toUpperCase()}] ${res.message}`);
    } else {
        for (let i = 1; i <= flows; i++) {
            const cfg = {...config, flow_id: String(i)};
            const res = await apiPost('/api/start', { protocol: proto, config: cfg });
            addLog(`[${proto.toUpperCase()}] ${res.message}`);
        }
    }
}

async function stopProto(proto) {
    const res = await apiPost('/api/stop', { protocol: proto });
    addLog(`[${proto.toUpperCase()}] ${res.message}`);
}

async function stopAll() {
    await apiPost('/api/stop', { protocol: 'all' });
    addLog('[ALL] Stopping all traffic');
}

async function clearStats() {
    await apiPost('/api/clear_stats', {});
    addLog('[STATS] Stats cleared');
}

function getSelectedProtos() {
    return Object.keys(PROTOCOLS).filter(p =>
        document.getElementById(`select-${p}`).checked
    );
}

function selectAll() {
    Object.keys(PROTOCOLS).forEach(p =>
        document.getElementById(`select-${p}`).checked = true
    );
}

function deselectAll() {
    Object.keys(PROTOCOLS).forEach(p =>
        document.getElementById(`select-${p}`).checked = false
    );
}

async function startSelected() {
    const selected = getSelectedProtos();
    if (selected.length === 0) { addLog('[WARN] No protocols selected'); return; }
    for (const proto of selected) {
        await startProto(proto);
    }
}

async function stopSelected() {
    const selected = getSelectedProtos();
    if (selected.length === 0) { addLog('[WARN] No protocols selected'); return; }
    for (const proto of selected) {
        const res = await apiPost('/api/stop', { protocol: proto });
        addLog(`[${proto.toUpperCase()}] ${res.message}`);
    }
}

// ─── Router Link Simulation ─────────────────────────────────

const ROUTER_PRESETS = {
    degraded_wan: { latency_ms: 300, jitter_ms: 50, packet_loss_pct: 5, bandwidth_mbps: 0 },
    voice_sla: { latency_ms: 200, jitter_ms: 40, packet_loss_pct: 2, bandwidth_mbps: 0 },
    video_sla: { latency_ms: 150, jitter_ms: 30, packet_loss_pct: 3, bandwidth_mbps: 0 },
};

async function addRouter() {
    const name = document.getElementById('router-add-name').value.trim();
    const ip = document.getElementById('router-add-ip').value.trim();
    const username = document.getElementById('router-add-user').value.trim();
    const password = document.getElementById('router-add-pass').value;
    const errEl = document.getElementById('router-add-error');
    if (!name || !ip || !username) {
        errEl.textContent = 'Name, IP, and username are required';
        errEl.style.display = 'block';
        return;
    }
    errEl.style.display = 'none';
    const res = await apiPost('/api/routers', { name, ip, username, password });
    if (res.ok) {
        document.getElementById('router-add-name').value = '';
        document.getElementById('router-add-ip').value = '';
        document.getElementById('router-add-user').value = '';
        document.getElementById('router-add-pass').value = '';
        addLog(`[ROUTER] ${res.message}`);
        loadRouters();
    } else {
        errEl.textContent = res.error || 'Failed to add router';
        errEl.style.display = 'block';
        addLog(`[ROUTER] Error: ${res.error}`);
    }
}

async function removeRouter(id) {
    if (!confirm('Remove this router?')) return;
    const res = await fetch('/api/routers/' + id, { method: 'DELETE' });
    const data = await res.json();
    addLog(`[ROUTER] ${data.message}`);
    loadRouters();
}

async function reconnectRouter(id) {
    const res = await apiPost('/api/routers/' + id + '/connect', {});
    addLog(`[ROUTER] ${res.message}`);
    loadRouters();
}

async function refreshInterfaces(id) {
    const resp = await fetch('/api/routers/' + id + '/interfaces');
    const data = await resp.json();
    addLog(`[ROUTER] Refreshed interfaces`);
    loadRouters();
}

async function selectInterface(id, iface) {
    const res = await apiPost('/api/routers/' + id + '/select-interface', { interface: iface });
    if (!res.ok) addLog(`[ROUTER] ${res.error || res.message}`);
}

function applyRouterPreset(id, presetName) {
    const p = ROUTER_PRESETS[presetName];
    if (!p) return;
    const el = (field) => document.getElementById('rtr-' + id + '-' + field);
    if (el('latency')) el('latency').value = p.latency_ms;
    if (el('jitter')) el('jitter').value = p.jitter_ms;
    if (el('loss')) el('loss').value = p.packet_loss_pct;
    if (el('bw')) el('bw').value = p.bandwidth_mbps;
}

async function applyRouterMode(id, mode) {
    const body = { mode };
    if (mode === 'impaired') {
        const el = (field) => document.getElementById('rtr-' + id + '-' + field);
        body.latency_ms = parseInt(el('latency')?.value) || 0;
        body.jitter_ms = parseInt(el('jitter')?.value) || 0;
        body.packet_loss_pct = parseFloat(el('loss')?.value) || 0;
        body.bandwidth_mbps = parseInt(el('bw')?.value) || 0;
    }
    const res = await apiPost('/api/routers/' + id + '/mode', body);
    addLog(`[ROUTER] ${res.message || res.error}`);
    loadRouters();
}

function toggleRouterInterfaces(id) {
    const el = document.getElementById('rtr-ifaces-' + id);
    const toggle = document.getElementById('rtr-ifaces-toggle-' + id);
    if (el) {
        const show = el.style.display === 'none';
        el.style.display = show ? 'block' : 'none';
        if (toggle) toggle.textContent = show ? 'Hide Interfaces' : 'Show Interfaces';
    }
}

function renderRouterCard(r) {
    const id = r.router_id;
    const connColor = r.connected ? 'var(--success)' : 'var(--danger)';
    const connText = r.connected ? 'Connected' : 'Disconnected';

    let ifaceRows = '';
    let selectedIfaceDisplay = r.selected_interface || 'None';
    if (r.interfaces && r.interfaces.length) {
        for (const iface of r.interfaces) {
            const checked = iface.name === r.selected_interface ? 'checked' : '';
            const stateColor = iface.state === 'up' ? 'var(--success)' : 'var(--danger)';
            const ipStr = iface.ip_address ? iface.ip_address + (iface.subnet || '') : '--';
            const descStr = iface.description ? ` — ${iface.description}` : '';
            ifaceRows += `<label style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:11px;cursor:pointer;color:var(--text-primary)">
                <input type="radio" name="rtr-${id}-iface" value="${iface.name}" ${checked}
                    onchange="selectInterface('${id}','${iface.name}')">
                <strong>${iface.name}</strong>
                <span style="color:var(--text-secondary);font-style:italic">${descStr}</span>
                <span style="color:var(--text-secondary)">${ipStr}</span>
                <span style="color:${stateColor};font-weight:600;font-size:10px">${iface.state.toUpperCase()}</span>
            </label>`;
        }
    } else {
        ifaceRows = '<div style="color:var(--text-secondary);font-size:11px">No interfaces discovered</div>';
    }

    // Mode indicator
    let modeHtml = '';
    if (r.current_mode === 'healthy') {
        modeHtml = `<div style="padding:6px 10px;background:rgba(39,174,96,0.1);border:1px solid rgba(39,174,96,0.3);border-radius:6px;font-size:12px;margin-bottom:8px;color:var(--success)">
            <strong>HEALTHY</strong> — ${r.selected_interface || '?'} up, no impairment</div>`;
    } else if (r.current_mode === 'impaired') {
        const cfg = r.impairment_config || {};
        const parts = [];
        if (cfg.latency_ms) parts.push(cfg.latency_ms + 'ms latency');
        if (cfg.jitter_ms) parts.push(cfg.jitter_ms + 'ms jitter');
        if (cfg.packet_loss_pct) parts.push(cfg.packet_loss_pct + '% loss');
        if (cfg.bandwidth_mbps) parts.push(cfg.bandwidth_mbps + ' Mbps');
        modeHtml = `<div style="padding:6px 10px;background:rgba(231,76,60,0.1);border:1px solid rgba(231,76,60,0.3);border-radius:6px;font-size:12px;margin-bottom:8px;color:var(--danger)">
            <strong>IMPAIRED</strong> — ${r.selected_interface || '?'} | ${parts.join(', ') || 'custom'}</div>`;
    } else if (r.current_mode === 'link_down') {
        modeHtml = `<div style="padding:6px 10px;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.4);border-radius:6px;font-size:12px;margin-bottom:8px;color:#ff6b6b">
            <strong>LINK DOWN</strong> — ${r.selected_interface || '?'} is shut down</div>`;
    }

    const inputStyle = 'width:60px;padding:3px 6px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px';

    return `<div style="background:var(--bg-sub);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:8px">
                <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${connColor}"></span>
                <strong style="font-size:13px;color:var(--text-primary)">${r.name}</strong>
                <span style="color:var(--text-secondary);font-size:11px">${r.ip}</span>
                <span style="color:${connColor};font-size:10px;font-weight:600">${connText}</span>
            </div>
            <div style="display:flex;gap:4px">
                ${!r.connected ? '<button class="btn btn-start" onclick="reconnectRouter(\'' + id + '\')" style="padding:2px 8px;font-size:10px">Reconnect</button>' : ''}
                <button class="btn btn-danger" onclick="removeRouter('${id}')" style="padding:2px 8px;font-size:10px">Remove</button>
            </div>
        </div>
        ${r.connected ? `
        ${modeHtml}
        <!-- Interface toggle -->
        <div style="margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                <span style="font-size:11px;color:var(--text-secondary)">Interface: <strong style="color:var(--text-primary)">${selectedIfaceDisplay}</strong></span>
                <button class="btn btn-secondary" id="rtr-ifaces-toggle-${id}" onclick="toggleRouterInterfaces('${id}')" style="padding:2px 8px;font-size:10px">Show Interfaces</button>
                <button class="btn btn-secondary" onclick="refreshInterfaces('${id}')" style="padding:2px 8px;font-size:10px">Refresh</button>
            </div>
            <div id="rtr-ifaces-${id}" style="display:none;padding:6px 8px;background:var(--bg-card);border:1px solid var(--border);border-radius:4px;margin-top:4px">
                ${ifaceRows}
            </div>
        </div>
        <!-- Presets + Impairment in compact row -->
        <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:8px">
            <span style="font-size:10px;color:var(--text-secondary)">Presets:</span>
            <button class="btn btn-secondary" onclick="applyRouterPreset('${id}','degraded_wan')" style="padding:2px 8px;font-size:10px">Degraded WAN</button>
            <button class="btn btn-secondary" onclick="applyRouterPreset('${id}','voice_sla')" style="padding:2px 8px;font-size:10px">Voice SLA</button>
            <button class="btn btn-secondary" onclick="applyRouterPreset('${id}','video_sla')" style="padding:2px 8px;font-size:10px">Video SLA</button>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:8px">
            <label style="font-size:10px;color:var(--text-secondary)">Latency</label>
            <input type="number" id="rtr-${id}-latency" value="${(r.impairment_config||{}).latency_ms||0}" min="0" max="5000" style="${inputStyle}"><span style="font-size:10px;color:var(--text-secondary)">ms</span>
            <label style="font-size:10px;color:var(--text-secondary);margin-left:4px">Jitter</label>
            <input type="number" id="rtr-${id}-jitter" value="${(r.impairment_config||{}).jitter_ms||0}" min="0" max="2000" style="${inputStyle}"><span style="font-size:10px;color:var(--text-secondary)">ms</span>
            <label style="font-size:10px;color:var(--text-secondary);margin-left:4px">Loss</label>
            <input type="number" id="rtr-${id}-loss" value="${(r.impairment_config||{}).packet_loss_pct||0}" min="0" max="100" step="0.5" style="${inputStyle}"><span style="font-size:10px;color:var(--text-secondary)">%</span>
            <label style="font-size:10px;color:var(--text-secondary);margin-left:4px">BW</label>
            <input type="number" id="rtr-${id}-bw" value="${(r.impairment_config||{}).bandwidth_mbps||0}" min="0" max="10000" step="10" style="width:70px;padding:3px 6px;font-size:11px;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:3px"><span style="font-size:10px;color:var(--text-secondary)">Mbps</span>
        </div>
        <!-- Mode Buttons -->
        <div style="display:flex;gap:6px">
            <button class="btn btn-start" onclick="applyRouterMode('${id}','healthy')" style="padding:4px 12px;font-size:11px">Healthy</button>
            <button class="btn btn-primary" onclick="applyRouterMode('${id}','impaired')" style="padding:4px 12px;font-size:11px">Apply Impaired</button>
            <button class="btn btn-danger" onclick="applyRouterMode('${id}','link_down')" style="padding:4px 12px;font-size:11px">Link Down</button>
        </div>
        ` : '<div style="color:var(--text-secondary);font-size:11px;padding:6px 0">Router disconnected. Click Reconnect to restore.</div>'}
    </div>`;
}

async function loadRouters() {
    try {
        const resp = await fetch('/api/routers');
        const routers = await resp.json();
        const container = document.getElementById('router-cards-container');
        if (!container) return;
        if (!routers.length) {
            container.innerHTML = '<div style="color:var(--text-secondary);font-size:12px;text-align:center;padding:12px">No routers added. Add a router above to start link simulation.</div>';
            return;
        }
        container.innerHTML = routers.map(r => renderRouterCard(r)).join('');
    } catch(e) {}
}

async function pollRouterStatus() {
    try {
        const resp = await fetch('/api/routers');
        const routers = await resp.json();
        const container = document.getElementById('router-cards-container');
        if (!container) return;
        if (!routers.length) {
            container.innerHTML = '<div style="color:var(--text-secondary);font-size:12px;text-align:center;padding:12px">No routers added. Add a router above to start link simulation.</div>';
            return;
        }
        const savedValues = {};
        const expandedIfaces = {};
        for (const r of routers) {
            const rid = r.router_id;
            for (const f of ['latency','jitter','loss','bw']) {
                const el = document.getElementById('rtr-' + rid + '-' + f);
                if (el) savedValues[rid + '-' + f] = el.value;
            }
            const ifaceEl = document.getElementById('rtr-ifaces-' + rid);
            if (ifaceEl && ifaceEl.style.display !== 'none') expandedIfaces[rid] = true;
        }
        container.innerHTML = routers.map(r => renderRouterCard(r)).join('');
        for (const [key, val] of Object.entries(savedValues)) {
            const el = document.getElementById('rtr-' + key);
            if (el) el.value = val;
        }
        for (const rid of Object.keys(expandedIfaces)) {
            const ifaceEl = document.getElementById('rtr-ifaces-' + rid);
            const toggleBtn = document.getElementById('rtr-ifaces-toggle-' + rid);
            if (ifaceEl) ifaceEl.style.display = 'block';
            if (toggleBtn) toggleBtn.textContent = 'Hide Interfaces';
        }
        for (const r of routers) {
            if (r.logs) {
                for (const line of r.logs) {
                    const key = 'rtr:' + r.router_id + ':' + line;
                    if (!_seenEngineLogs.has(key)) {
                        _seenEngineLogs.add(key);
                        logBuf.push('[ROUTER:' + r.name + '] ' + line);
                    }
                }
            }
        }
        renderLogPanel();
    } catch(e) {}
}

// ─── Status polling ────────────────────────────────────────

function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

function fmtTime(s) {
    if (s < 0) return '--';
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

async function pollStatus() {
    try {
        const resp = await fetch('/api/status');
        const data = await resp.json();
        let totSent = 0, totRecv = 0, totReqs = 0, totErrs = 0;

        const protoAgg = {};
        for (const [jobKey, info] of Object.entries(data.jobs)) {
            const baseParts = jobKey.split('_');
            let base;
            if (baseParts.length >= 3 && !isNaN(baseParts[baseParts.length - 1])) {
                base = baseParts.slice(0, -1).join('_');
            } else if (baseParts.length === 2 && !isNaN(baseParts[1])) {
                base = baseParts[0];
            } else {
                base = jobKey;
            }

            if (!protoAgg[base]) protoAgg[base] = { running: false, flows: 0, remaining: -1, elapsed: 0, stats: {bytes_sent:0,bytes_recv:0,requests:0,errors:0} };
            const agg = protoAgg[base];
            if (info.running) { agg.running = true; agg.flows++; }
            agg.stats.bytes_sent += info.stats.bytes_sent;
            agg.stats.bytes_recv += info.stats.bytes_recv;
            agg.stats.requests += info.stats.requests;
            agg.stats.errors += info.stats.errors;
            if (info.remaining >= 0) agg.remaining = Math.max(agg.remaining, info.remaining);
            agg.elapsed = Math.max(agg.elapsed, info.elapsed);

            totSent += info.stats.bytes_sent;
            totRecv += info.stats.bytes_recv;
            totReqs += info.stats.requests;
            totErrs += info.stats.errors;
        }

        for (const [proto, agg] of Object.entries(protoAgg)) {
            const card = document.getElementById(`proto-${proto}`);
            const badge = document.getElementById(`status-${proto}`);
            const timer = document.getElementById(`timer-${proto}`);
            if (!card) continue;

            if (agg.running) {
                card.classList.add('running');
                badge.classList.add('running');
                badge.textContent = agg.flows > 1 ? `${agg.flows} Flows` : 'Running';
                if (agg.remaining >= 0) {
                    timer.style.display = '';
                    timer.textContent = fmtTime(agg.remaining);
                } else {
                    timer.style.display = '';
                    timer.textContent = fmtTime(agg.elapsed);
                }
            } else {
                card.classList.remove('running');
                badge.classList.remove('running');
                badge.textContent = 'Stopped';
                timer.style.display = 'none';
            }
        }

        for (const proto of Object.keys(PROTOCOLS)) {
            if (!protoAgg[proto]) {
                const card = document.getElementById(`proto-${proto}`);
                const badge = document.getElementById(`status-${proto}`);
                const timer = document.getElementById(`timer-${proto}`);
                if (card) card.classList.remove('running');
                if (badge) { badge.classList.remove('running'); badge.textContent = 'Stopped'; }
                if (timer) timer.style.display = 'none';
            }
        }

        document.getElementById('stat-sent').textContent = fmtBytes(totSent);
        document.getElementById('stat-recv').textContent = fmtBytes(totRecv);
        document.getElementById('stat-reqs').textContent = totReqs.toLocaleString();
        document.getElementById('stat-errors').textContent = totErrs.toLocaleString();

        for (const [proto, info] of Object.entries(data.jobs)) {
            if (info.logs) {
                for (const line of info.logs) {
                    const key = proto + ':' + line;
                    if (!_seenEngineLogs.has(key)) {
                        _seenEngineLogs.add(key);
                        logBuf.push('[' + proto.toUpperCase() + '] ' + line);
                    }
                }
            }
        }
        if (_seenEngineLogs.size > 5000) {
            const arr = Array.from(_seenEngineLogs);
            _seenEngineLogs = new Set(arr.slice(arr.length - 2000));
        }
        renderLogPanel();
    } catch (e) { /* ignore */ }
}

// ─── Logs ──────────────────────────────────────────────────

const logBuf = [];
let autoRefreshInterval = null;
let _seenEngineLogs = new Set();

function renderLogPanel() {
    if (logBuf.length > 1000) logBuf.splice(0, logBuf.length - 500);
    const panel = document.getElementById('log-panel');
    const last150 = logBuf.slice(-150);
    panel.innerHTML = last150.map(l => {
        const cls = l.toLowerCase().includes('error') ? ' error' : '';
        const d = document.createElement('div');
        d.textContent = l;
        return `<div class="log-entry${cls}">${d.innerHTML}</div>`;
    }).join('');
    panel.scrollTop = panel.scrollHeight;
}

function addLog(msg) {
    logBuf.push(`[${new Date().toLocaleTimeString()}] ${msg}`);
    renderLogPanel();
}

function toggleAutoRefresh() {
    const enabled = document.getElementById('auto-refresh-toggle').checked;
    if (enabled) {
        if (!autoRefreshInterval) {
            autoRefreshInterval = setInterval(() => { pollStatus(); pollRouterStatus(); }, 2000);
            pollStatus();
            pollRouterStatus();
        }
    } else {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
    }
    addLog(enabled ? 'Auto-refresh enabled' : 'Auto-refresh paused');
}

// ─── Source IPs ─────────────────────────────────────────────

function toggleSourceIpConfig() {
    const enabled = document.getElementById('source-ip-toggle').checked;
    document.getElementById('source-ip-config').style.display = enabled ? 'block' : 'none';
    if (!enabled) {
        apiPost('/api/source_ips', { enabled: false });
        document.getElementById('source-ip-list').textContent = '';
        addLog('[SOURCE IP] Disabled');
    }
}

async function applySourceIps() {
    const base_ip = document.getElementById('source-ip-base').value.trim();
    const count = parseInt(document.getElementById('source-ip-count').value);
    const res = await apiPost('/api/source_ips', { enabled: true, base_ip, count });
    addLog('[SOURCE IP] ' + res.message);
    if (res.ips && res.ips.length) {
        document.getElementById('source-ip-list').textContent = 'Active: ' + res.ips.join(', ');
    }
}

async function loadSourceIps() {
    try {
        const resp = await fetch('/api/source_ips');
        const data = await resp.json();
        const toggle = document.getElementById('source-ip-toggle');
        if (toggle) toggle.checked = data.enabled;
        document.getElementById('source-ip-config').style.display = data.enabled ? 'block' : 'none';
        if (data.ips && data.ips.length) {
            document.getElementById('source-ip-list').textContent = 'Active: ' + data.ips.join(', ');
        }
    } catch(e) {}
}


// ─── Proxy Configuration ────────────────────────────────────

async function loadProxy() {
    try {
        const resp = await fetch('/api/proxy');
        const cfg = await resp.json();
        const el = id => document.getElementById('proxy-' + id);
        if (el('enabled')) el('enabled').checked = cfg.enabled;
        if (el('type')) el('type').value = cfg.type || 'http';
        if (el('host')) el('host').value = cfg.host || '';
        if (el('port')) el('port').value = cfg.port || 8080;
        if (el('username')) el('username').value = cfg.username || '';
        if (el('password')) el('password').value = cfg.password || '';
    } catch(e) {}
}

async function saveProxy() {
    const el = id => document.getElementById('proxy-' + id);
    const cfg = {
        enabled: el('enabled')?.checked || false,
        type: el('type')?.value || 'http',
        host: el('host')?.value || '',
        port: parseInt(el('port')?.value || 8080),
        username: el('username')?.value || '',
        password: el('password')?.value || '',
    };
    try {
        const resp = await fetch('/api/proxy', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(cfg)
        });
        const data = await resp.json();
        addLog(data.message || 'Proxy config updated');
    } catch(e) {
        addLog('Failed to save proxy config');
    }
}

async function testProxy() {
    const el = id => document.getElementById('proxy-' + id);
    const cfg = {
        type: el('type')?.value || 'http',
        host: el('host')?.value || '',
        port: parseInt(el('port')?.value || 8080),
        username: el('username')?.value || '',
        password: el('password')?.value || '',
    };
    const btn = document.getElementById('proxy-test-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Testing...'; }
    try {
        const resp = await fetch('/api/proxy/test', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(cfg)
        });
        const data = await resp.json();
        addLog(data.message);
    } catch(e) {
        addLog('Proxy test failed');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Test'; }
    }
}


// ─── FTP File List ──────────────────────────────────────────

async function loadFtpFileList() {
    try {
        const resp = await fetch('http://' + SRV + ':5000/api/files');
        const data = await resp.json();
        const sel = document.getElementById('cfg-ftp-filename');
        if (!sel || !data.files) return;
        const current = sel.value;
        const defaultFile = 'testfile_100mb.bin';
        sel.innerHTML = data.files.map(f => {
            const isSelected = current ? f.name === current : f.name === defaultFile;
            return '<option value="' + f.name + '"' + (isSelected ? ' selected' : '') + '>' +
                f.name + ' (' + fmtBytes(f.size) + ')</option>';
        }).join('');
    } catch(e) { /* server may not be reachable */ }
}

// ─── Topology ───────────────────────────────────────────────

let topoNetwork = null;
let topoAnimInterval = null;
let topoEdges = null;
let topoAnimState = 0;
let topoHasTraffic = false;
let topoActiveEdgeIds = [];  // edges belonging to running protocols (animated)

const TOPO_COLORS = [
    '#2563eb', '#059669', '#d97706', '#7c3aed', '#0891b2',
    '#dc2626', '#0d9488', '#ea580c', '#4f46e5', '#16a34a'
];

// SVG icon data URIs for topology nodes
const TOPO_ICONS = {
    client: (fill, stroke) => `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><defs><filter id="s"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.2"/></filter><linearGradient id="scr" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#e0f2fe"/><stop offset="100%" stop-color="#bae6fd"/></linearGradient></defs><rect x="10" y="14" width="44" height="30" rx="3" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#s)"/><rect x="15" y="18" width="34" height="22" rx="2" fill="url(#scr)"/><circle cx="32" cy="29" r="6" fill="${stroke}" opacity="0.15"/><path d="M22 48h20M32 44v4" stroke="${stroke}" stroke-width="2" stroke-linecap="round"/><rect x="20" y="48" width="24" height="3" rx="1.5" fill="${stroke}" opacity="0.4"/><circle cx="48" cy="18" r="3" fill="#22c55e" opacity="0.9"/></svg>`)}`,
    server: (fill, stroke) => `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><defs><filter id="s"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.2"/></filter></defs><rect x="12" y="6" width="40" height="52" rx="4" fill="${fill}" stroke="${stroke}" stroke-width="2" filter="url(#s)"/><rect x="17" y="12" width="30" height="10" rx="2" fill="#fff" opacity="0.5"/><rect x="20" y="15" width="14" height="2" rx="1" fill="${stroke}" opacity="0.3"/><rect x="20" y="18" width="8" height="2" rx="1" fill="${stroke}" opacity="0.2"/><circle cx="40" cy="17" r="2.5" fill="#22c55e"/><rect x="17" y="26" width="30" height="10" rx="2" fill="#fff" opacity="0.5"/><rect x="20" y="29" width="14" height="2" rx="1" fill="${stroke}" opacity="0.3"/><rect x="20" y="32" width="8" height="2" rx="1" fill="${stroke}" opacity="0.2"/><circle cx="40" cy="31" r="2.5" fill="#2563eb"/><rect x="17" y="40" width="30" height="10" rx="2" fill="#fff" opacity="0.5"/><rect x="20" y="43" width="14" height="2" rx="1" fill="${stroke}" opacity="0.3"/><rect x="20" y="46" width="8" height="2" rx="1" fill="${stroke}" opacity="0.2"/><circle cx="40" cy="45" r="2.5" fill="#d97706"/></svg>`)}`,
    router: (fill, stroke) => `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 56 56"><defs><filter id="s"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.2"/></filter></defs><circle cx="28" cy="28" r="22" fill="${fill}" stroke="${stroke}" stroke-width="2.5" filter="url(#s)"/><circle cx="28" cy="28" r="6" fill="${stroke}" opacity="0.8"/><path d="M28 10v10M28 36v10M10 28h10M36 28h10" stroke="${stroke}" stroke-width="2" stroke-linecap="round"/><path d="M16 16l7 7M33 33l7 7M40 16l-7 7M23 33l-7 7" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.4"/><polygon points="28,8 26,13 30,13" fill="${stroke}" opacity="0.7"/><polygon points="28,48 26,43 30,43" fill="${stroke}" opacity="0.7"/><polygon points="8,28 13,26 13,30" fill="${stroke}" opacity="0.7"/><polygon points="48,28 43,26 43,30" fill="${stroke}" opacity="0.7"/></svg>`)}`,
    hop: (fill, stroke, num) => `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 36 36"><defs><linearGradient id="hg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${fill}"/><stop offset="100%" stop-color="#dbeafe"/></linearGradient></defs><circle cx="18" cy="18" r="13" fill="url(#hg)" stroke="${stroke}" stroke-width="2"/><text x="18" y="22" text-anchor="middle" fill="${stroke}" font-size="12" font-weight="700" font-family="-apple-system,sans-serif">${num}</text></svg>`)}`,
    timeout: (num) => `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 36 36"><circle cx="18" cy="18" r="13" fill="#fef2f2" stroke="#ef4444" stroke-width="2" stroke-dasharray="4 3"/><line x1="13" y1="13" x2="23" y2="23" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round"/><line x1="23" y1="13" x2="13" y2="23" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round"/></svg>`)}`,
};

async function refreshTopology() {
    try {
        const resp = await fetch('/api/topology');
        const data = await resp.json();
        renderTopology(data);
    } catch(e) {
        const container = document.getElementById('topology-container');
        if (container) container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-secondary)">Failed to load topology</div>';
    }
}

function _topoTooltip(lines, borderColor) {
    const el = document.createElement('div');
    el.className = 'topo-tooltip';
    if (borderColor) el.style.borderLeftColor = borderColor;
    el.innerHTML = lines.join('<br>');
    return el;
}

function _latencyClass(rtt) {
    const ms = parseFloat(rtt);
    if (isNaN(ms)) return '';
    if (ms < 20) return 'topo-tip-latency-good';
    if (ms < 100) return 'topo-tip-latency-warn';
    return 'topo-tip-latency-bad';
}

function _latencyHtml(rtt) {
    if (!rtt || rtt === '--') return '';
    const cls = _latencyClass(rtt);
    return `<span class="topo-tip-row"><span class="topo-tip-label">Latency</span><span class="${cls}">${rtt} ms</span></span>`;
}

function renderTopology(data) {
    const container = document.getElementById('topology-container');
    if (!container) return;

    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();
    topoEdges = edges;
    topoActiveEdgeIds = [];

    const pathsObj = data.paths || {};
    const routers = data.routers || [];

    const routerByIp = {};
    routers.forEach(r => { routerByIp[r.ip] = r; });

    // Only show active (non-default) paths
    const pathKeys = Object.keys(pathsObj).filter(k => k !== 'default');
    const runningPaths = pathKeys.filter(k => pathsObj[k].running);
    topoHasTraffic = runningPaths.length > 0;

    // Group paths by hop signature for merging
    const hopSigMap = {};
    pathKeys.forEach(k => {
        const p = pathsObj[k];
        const sig = (p.hops || []).map(h => h.ip).join(',');
        if (!hopSigMap[sig]) hopSigMap[sig] = [];
        hopSigMap[sig].push(k);
    });

    // CLIENT node — laptop icon
    nodes.add({
        id: 'client', label: 'Client\n' + data.client_ip, shape: 'image', size: 36,
        image: TOPO_ICONS.client('#ecfdf5', '#059669'),
        font: { size: 11, face: '-apple-system, sans-serif', color: '#1e2a3a', vadjust: 10, multi: true },
        level: 0, shadow: { enabled: true, color: 'rgba(5,150,105,0.15)', size: 12 },
        title: _topoTooltip([
            '<div class="topo-tip-header">Client</div>',
            '<span class="topo-tip-row"><span class="topo-tip-label">IP Address</span><strong>' + data.client_ip + '</strong></span>',
            '<span class="topo-tip-row"><span class="topo-tip-label">Active Flows</span><strong>' + runningPaths.length + '</strong></span>'
        ], '#059669'),
    });

    // SERVER node — server rack icon
    const maxHops = Math.max(1, ...pathKeys.map(k => (pathsObj[k].hops || []).length));
    nodes.add({
        id: 'server', label: 'Server\n' + data.server_host, shape: 'image', size: 36,
        image: TOPO_ICONS.server('#eff6ff', '#2563eb'),
        font: { size: 11, face: '-apple-system, sans-serif', color: '#1e2a3a', vadjust: 10, multi: true },
        level: maxHops + 1, shadow: { enabled: true, color: 'rgba(37,99,235,0.15)', size: 12 },
        title: _topoTooltip([
            '<div class="topo-tip-header">Server</div>',
            '<span class="topo-tip-row"><span class="topo-tip-label">IP Address</span><strong>' + data.server_host + '</strong></span>'
        ], '#2563eb'),
    });

    const renderedSigs = new Set();
    let pathIndex = 0;
    const addedNodes = new Set(['client', 'server']);
    const legendItems = [];

    pathKeys.forEach(pathKey => {
        const path = pathsObj[pathKey];
        const hops = path.hops || [];
        const sig = hops.map(h => h.ip).join(',');

        if (renderedSigs.has(sig)) return;
        renderedSigs.add(sig);

        const mergedKeys = hopSigMap[sig] || [pathKey];
        const labels = mergedKeys.map(k => pathsObj[k].label);
        const isRunning = mergedKeys.some(k => k !== 'default' && pathsObj[k].running);
        const isDefaultOnly = mergedKeys.length === 1 && mergedKeys[0] === 'default';

        const color = isDefaultOnly ? '#94a3b8' : TOPO_COLORS[pathIndex % TOPO_COLORS.length];
        if (!isDefaultOnly) pathIndex++;

        legendItems.push({ labels, color, running: isRunning, defaultOnly: isDefaultOnly });

        const edgeWidth = isRunning ? 3.5 : 1.5;

        // Create hop nodes with appropriate icons
        const nodeChain = ['client'];
        hops.forEach((h, i) => {
            const isLast = i === hops.length - 1;
            const isTimeout = h.ip === '*';

            if (isLast && !isTimeout && (h.ip === data.server_host || h.ip === data.client_ip)) return;

            const sharedId = 'hop_shared_' + h.hop + '_' + h.ip;
            if (addedNodes.has(sharedId)) { nodeChain.push(sharedId); return; }

            const router = routerByIp[h.ip];
            let nodeImage, nodeLabel = '', nodeSize = 18, tipLines = [];

            let tipColor = color;
            if (isTimeout) {
                nodeImage = TOPO_ICONS.timeout(h.hop);
                nodeSize = 18;
                nodeLabel = '';
                tipColor = '#ef4444';
                tipLines = [
                    '<div class="topo-tip-header" style="color:#ef4444">Hop ' + h.hop + ' — Timeout</div>',
                    '<span style="color:#ef4444">Request timed out</span>'
                ];
            } else if (router) {
                const modeColors = {
                    healthy: { fill: '#ecfdf5', stroke: '#059669' },
                    impaired: { fill: '#fffbeb', stroke: '#d97706' },
                    link_down: { fill: '#fef2f2', stroke: '#dc2626' }
                };
                const mc = modeColors[router.current_mode] || { fill: '#eff6ff', stroke: color };
                nodeImage = TOPO_ICONS.router(mc.fill, mc.stroke);
                nodeLabel = router.name + '\n' + h.ip; nodeSize = 30;
                tipColor = mc.stroke;
                const mode = router.current_mode ? router.current_mode.replace('_', ' ') : 'unknown';
                const modeColor = { healthy: '#059669', impaired: '#d97706', link_down: '#dc2626' }[router.current_mode] || '#6b7a8d';
                tipLines = [
                    '<div class="topo-tip-header">' + router.name + '</div>',
                    '<span class="topo-tip-row"><span class="topo-tip-label">IP</span><strong>' + h.ip + '</strong></span>',
                    '<span class="topo-tip-row"><span class="topo-tip-label">Status</span><span style="color:' + modeColor + ';font-weight:600">' + mode + '</span></span>'
                ];
                if (h.rtt && h.rtt !== '--') tipLines.push(_latencyHtml(h.rtt));
                if (router.current_mode === 'impaired' && router.impairment_config) {
                    const ic = router.impairment_config;
                    const parts = [];
                    if (ic.latency_ms) parts.push(ic.latency_ms + 'ms delay');
                    if (ic.jitter_ms) parts.push(ic.jitter_ms + 'ms jitter');
                    if (ic.packet_loss_pct) parts.push(ic.packet_loss_pct + '% loss');
                    if (ic.bandwidth_mbps) parts.push(ic.bandwidth_mbps + ' Mbps');
                    if (parts.length) tipLines.push('<span style="color:#d97706;font-size:11px">' + parts.join(' &middot; ') + '</span>');
                }
            } else {
                nodeImage = TOPO_ICONS.hop('#eff6ff', color, h.hop);
                nodeSize = 20;
                nodeLabel = h.ip;
                tipLines = [
                    '<div class="topo-tip-header">Hop ' + h.hop + '</div>',
                    '<span class="topo-tip-row"><span class="topo-tip-label">IP</span><strong>' + h.ip + '</strong></span>'
                ];
                if (h.rtt && h.rtt !== '--') tipLines.push(_latencyHtml(h.rtt));
            }

            nodes.add({
                id: sharedId, label: nodeLabel, shape: 'image', size: nodeSize,
                image: nodeImage,
                font: { size: 9, face: '-apple-system, sans-serif', color: '#64748b', vadjust: 8, multi: true },
                level: i + 1,
                shadow: isRunning ? { enabled: true, color: color + '25', size: 8 } : false,
                title: _topoTooltip(tipLines, tipColor),
            });
            addedNodes.add(sharedId);
            nodeChain.push(sharedId);
        });
        nodeChain.push('server');

        // Edges — smooth curves with latency labels and arrows
        const curveDir = pathIndex % 2 === 0 ? 'curvedCW' : 'curvedCCW';
        const roundness = pathIndex > 1 ? 0.1 + (pathIndex * 0.08) : 0;
        for (let i = 0; i < nodeChain.length - 1; i++) {
            const edgeId = 'e_' + pathKey + '_' + i;
            // Get RTT for this hop segment as edge label
            let edgeLabel = '';
            if (isRunning && i < hops.length && hops[i] && hops[i].rtt && hops[i].rtt !== '--') {
                edgeLabel = hops[i].rtt + ' ms';
            }
            edges.add({
                id: edgeId, from: nodeChain[i], to: nodeChain[i + 1],
                arrows: { to: { enabled: true, scaleFactor: 0.5, type: 'vee' } },
                color: { color: isRunning ? color : '#cbd5e1', highlight: color, hover: color },
                width: edgeWidth,
                label: edgeLabel,
                font: { size: 8, color: color, strokeWidth: 3, strokeColor: '#ffffff', align: 'top' },
                dashes: isRunning ? [10, 5] : false,
                smooth: roundness > 0 ? { type: curveDir, roundness } : { type: 'cubicBezier' },
                hoverWidth: 1.5,
                selectionWidth: 2,
                shadow: isRunning ? { enabled: true, color: color + '20', size: 4 } : false,
            });
            if (isRunning) topoActiveEdgeIds.push({ id: edgeId, color });
        }
    });

    // If no active flows, show empty state with placeholder
    if (pathKeys.length === 0) {
        container.innerHTML = `<div class="topo-empty">
            <svg width="120" height="50" viewBox="0 0 120 50"><circle cx="15" cy="25" r="8" fill="#e2e8f0" stroke="#94a3b8" stroke-width="1.5"/><circle cx="60" cy="25" r="6" fill="#e2e8f0" stroke="#94a3b8" stroke-width="1.5"/><circle cx="105" cy="25" r="8" fill="#e2e8f0" stroke="#94a3b8" stroke-width="1.5"/><line x1="23" y1="25" x2="54" y2="25" stroke="#cbd5e1" stroke-width="1.5" stroke-dasharray="4 3"/><line x1="66" y1="25" x2="97" y2="25" stroke="#cbd5e1" stroke-width="1.5" stroke-dasharray="4 3"/></svg>
            <span>Start a protocol to see network topology</span></div>`;
        if (topoNetwork) { topoNetwork.destroy(); topoNetwork = null; }
        const legendEl = document.getElementById('topology-legend');
        if (legendEl) legendEl.innerHTML = '';
        const statsEl = document.getElementById('topology-stats');
        if (statsEl) statsEl.innerHTML = '';
        return;
    }

    const options = {
        layout: { hierarchical: { direction: 'LR', sortMethod: 'directed', levelSeparation: 160, nodeSpacing: 60 } },
        physics: false,
        interaction: { hover: true, tooltipDelay: 80, dragNodes: true, zoomView: true, dragView: true },
        edges: { chosen: { edge: function(values) { values.width = values.width * 1.3; } } },
    };

    // Protocol legend bar
    let legendEl = document.getElementById('topology-legend');
    if (!legendEl) {
        legendEl = document.createElement('div');
        legendEl.id = 'topology-legend';
        legendEl.className = 'topo-legend';
        container.parentNode.insertBefore(legendEl, container.nextSibling);
    }
    if (legendItems.length > 0) {
        legendEl.innerHTML = legendItems.map(li => {
            const names = li.labels.join(', ');
            const opacity = li.running ? '1' : '0.5';
            const activeClass = li.running ? ' active' : '';
            const dot = `<span class="topo-legend-dot${activeClass}" style="background:${li.color};color:${li.color}"></span>`;
            const line = `<span class="topo-legend-line" style="background:${li.color}"></span>`;
            return `<span class="topo-legend-item" style="opacity:${opacity}">${dot}${line}${names}</span>`;
        }).join('');
    } else {
        legendEl.innerHTML = '';
    }

    // Stats bar
    let statsEl = document.getElementById('topology-stats');
    if (!statsEl) {
        statsEl = document.createElement('div');
        statsEl.id = 'topology-stats';
        statsEl.className = 'topo-stats';
        container.parentNode.appendChild(statsEl);
    }
    if (topoHasTraffic) {
        const statCards = runningPaths.map((k, idx) => {
            const p = pathsObj[k];
            const s = p.stats || {};
            const c = TOPO_COLORS[idx % TOPO_COLORS.length];
            const metrics = [];
            if (s.bytes_recv) metrics.push(fmtBytes(s.bytes_recv) + ' recv');
            else if (s.bytes_sent) metrics.push(fmtBytes(s.bytes_sent) + ' sent');
            if (s.requests) metrics.push(s.requests + ' reqs');
            return `<span class="topo-stat-card"><span class="stat-accent" style="background:${c}"></span><span class="stat-proto">${p.label}</span>${metrics.join(' &middot; ')}</span>`;
        });
        statsEl.innerHTML = '<strong style="color:#059669;margin-right:6px">\u25CF</strong>' + statCards.join('');
    } else {
        statsEl.innerHTML = '';
    }

    if (topoNetwork) {
        topoNetwork.setData({ nodes, edges });
    } else {
        topoNetwork = new vis.Network(container, { nodes, edges }, options);
    }

    if (topoHasTraffic && !topoAnimInterval) {
        topoAnimInterval = setInterval(animateTopology, 300);
    } else if (!topoHasTraffic && topoAnimInterval) {
        clearInterval(topoAnimInterval);
        topoAnimInterval = null;
    }
}

function animateTopology() {
    if (!topoEdges || !topoHasTraffic) return;
    topoAnimState = (topoAnimState + 1) % 8;
    const dashPatterns = [[12,4],[10,5],[8,6],[6,7],[5,8],[6,7],[8,6],[10,5]];
    const widthPulse = [3.5, 3.8, 4, 4.2, 4, 3.8, 3.5, 3.2];
    const opacities = [1, 0.95, 0.9, 0.85, 0.9, 0.95, 1, 1];
    topoActiveEdgeIds.forEach(e => {
        const r = parseInt(e.color.slice(1,3),16);
        const g = parseInt(e.color.slice(3,5),16);
        const b = parseInt(e.color.slice(5,7),16);
        const a = opacities[topoAnimState];
        topoEdges.update({
            id: e.id,
            dashes: dashPatterns[topoAnimState],
            width: widthPulse[topoAnimState],
            color: { color: `rgba(${r},${g},${b},${a})` }
        });
    });
}

// ─── Security Testing ───────────────────────────────────────

const SEC_CATEGORY_META = {
    web_attacks: { label: 'Web Attacks (OWASP)', badge: 'vuln', icon: '\u26A0\uFE0F' },
    malware_threats: { label: 'Malware / Threat Prevention', badge: 'malware', icon: '\uD83D\uDEE1\uFE0F' },
    url_filtering: { label: 'URL Filtering', badge: 'url', icon: '\uD83C\uDF10' },
    dns_attacks: { label: 'DNS-Based Attacks', badge: 'dns', icon: '\uD83D\uDD0D' },
    protocol_abuse: { label: 'Protocol Abuse', badge: 'proto', icon: '\u26A1' },
    file_threats: { label: 'File-Based Threats', badge: 'file', icon: '\uD83D\uDCC4' },
};

let _securityCatalog = null;
let _securityPollActive = false;
let _securityResults = {};

async function loadSecurityCatalog() {
    try {
        const resp = await fetch('/api/security/catalog');
        _securityCatalog = await resp.json();
        renderSecurityPanel();
    } catch(e) {
        document.getElementById('security-panel').innerHTML =
            '<div style="color:var(--text-secondary);font-size:12px;padding:12px;text-align:center">Failed to load security test catalog</div>';
    }
}

function renderSecurityPanel() {
    const panel = document.getElementById('security-panel');
    if (!_securityCatalog) { panel.innerHTML = ''; return; }

    let html = '';
    for (const [cat, tests] of Object.entries(_securityCatalog)) {
        const meta = SEC_CATEGORY_META[cat] || { label: cat, badge: 'vuln', icon: '' };
        html += `<div class="security-category">
            <div class="security-category-header" onclick="toggleSecurityCategory('${cat}')">
                <div class="security-category-title">
                    <span>${meta.icon}</span>
                    <span>${meta.label}</span>
                    <span class="security-category-badge ${meta.badge}">${tests.length} tests</span>
                </div>
                <div style="display:flex;align-items:center;gap:6px">
                    <span class="security-select-all" onclick="event.stopPropagation();toggleSecCategorySelect('${cat}')">[Select All]</span>
                    <span class="chevron" id="chevron-sec-${cat}" style="font-size:10px;color:var(--text-secondary)">&#9660;</span>
                </div>
            </div>
            <div class="security-test-list" id="sec-list-${cat}">
                <div class="security-test-row header">
                    <span></span>
                    <span>Test</span>
                    <span>PAN-OS Feature</span>
                    <span>Expected</span>
                    <span>Result</span>
                    <span>Actions</span>
                </div>`;
        for (const t of tests) {
            const overrideBadge = t.overridden ? '<span class="sec-override-badge" title="Modified from default">modified</span>' : '';
            const editBtn = `<button class="sec-edit-btn" onclick="event.stopPropagation();editTestCase('${t.id}',${!!t.custom && !t.overridden})" title="Edit">&#9998;</button>`;
            const deleteBtn = (t.custom && !t.overridden) ? `<button class="sec-del-btn" onclick="event.stopPropagation();deleteCustomPattern('${t.id}')" title="Delete">&#10005;</button>` : '';
            const resetBtn = t.overridden ? `<button class="sec-reset-btn" onclick="event.stopPropagation();resetBuiltinTest('${t.id}')" title="Reset to default">&#8634;</button>` : '';
            html += `<div class="security-test-row clickable" id="sec-row-${t.id}" onclick="toggleSecDetail('${t.id}')">
                <input type="checkbox" class="sec-checkbox" data-cat="${cat}" data-id="${t.id}" checked style="width:14px;height:14px;accent-color:var(--accent)" onclick="event.stopPropagation()">
                <div>
                    <div class="security-test-name">${t.name}${overrideBadge}</div>
                    <div class="security-test-desc">${t.description || ''}</div>
                </div>
                <span class="security-test-feature">${t.panos_feature}</span>
                <span style="font-size:10px;color:var(--text-secondary);text-transform:uppercase">${t.expected_action}</span>
                <span id="sec-verdict-${t.id}"><span class="sec-verdict pending">--</span></span>
                <span class="sec-actions" onclick="event.stopPropagation()">
                    <button class="sec-run-btn" onclick="runSingleTest('${t.id}')" title="Run this test">&#9654;</button>
                    ${editBtn}${resetBtn}${deleteBtn}
                </span>
            </div>
            <div class="security-test-detail" id="sec-detail-${t.id}" style="display:none"></div>`;
        }
        html += '</div></div>';
    }
    panel.innerHTML = html;
}

function toggleSecDetail(testId) {
    const detail = document.getElementById('sec-detail-' + testId);
    if (!detail) return;
    if (detail.style.display === 'none') {
        detail.style.display = '';
        renderSecDetail(testId);
    } else {
        detail.style.display = 'none';
    }
}

function renderSecDetail(testId) {
    const detail = document.getElementById('sec-detail-' + testId);
    if (!detail) return;
    const r = _securityResults[testId];
    if (!r) {
        // No result yet — show catalog info
        let testInfo = null;
        if (_securityCatalog) {
            for (const tests of Object.values(_securityCatalog)) {
                for (const t of tests) {
                    if (t.id === testId) { testInfo = t; break; }
                }
                if (testInfo) break;
            }
        }
        if (testInfo) {
            detail.innerHTML = `<div class="security-detail-grid">
                <div class="detail-label">Description</div>
                <div class="detail-value">${testInfo.description || 'N/A'}</div>
                <div class="detail-label">PAN-OS Feature</div>
                <div class="detail-value">${testInfo.panos_feature}</div>
                <div class="detail-label">Expected Action</div>
                <div class="detail-value">${testInfo.expected_action}</div>
                <div class="detail-label">Status</div>
                <div class="detail-value" style="color:var(--text-secondary)">Not yet executed — run test to see results</div>
            </div>`;
        } else {
            detail.innerHTML = '<div style="padding:8px;font-size:11px;color:var(--text-secondary)">No results yet</div>';
        }
        return;
    }

    const ts = r.timestamp ? new Date(r.timestamp * 1000).toLocaleString() : 'N/A';
    const verdictClass = r.verdict === 'PASS' ? 'pass' : r.verdict === 'FAIL' ? 'fail' : r.verdict === 'ERROR' ? 'error' : 'pending';
    const payloadHtml = r.payload ? `<pre class="detail-pre">${escapeHtml(r.payload)}</pre>` : '<span style="color:var(--text-secondary)">N/A</span>';
    const respBodyHtml = r.response_body_snippet ? `<pre class="detail-pre">${escapeHtml(r.response_body_snippet)}</pre>` : '<span style="color:var(--text-secondary)">N/A</span>';
    const headersHtml = r.response_headers && Object.keys(r.response_headers).length > 0
        ? `<pre class="detail-pre">${escapeHtml(Object.entries(r.response_headers).map(([k,v]) => k + ': ' + v).join('\n'))}</pre>`
        : '<span style="color:var(--text-secondary)">N/A</span>';

    detail.innerHTML = `<div class="security-detail-grid">
        <div class="detail-label">Description</div>
        <div class="detail-value">${r.description || 'N/A'}</div>
        <div class="detail-label">Payload Sent</div>
        <div class="detail-value">${payloadHtml}</div>
        <div class="detail-label">Target URL</div>
        <div class="detail-value" style="word-break:break-all;font-family:monospace;font-size:10px">${escapeHtml(r.url || 'N/A')}</div>
        <div class="detail-label">HTTP Method</div>
        <div class="detail-value">${r.method || 'N/A'}</div>
        <div class="detail-label">Expected Behavior</div>
        <div class="detail-value">${r.expected_behavior || 'N/A'}</div>
        <div class="detail-label">Response Code</div>
        <div class="detail-value"><strong>${r.response_code || 'N/A'}</strong></div>
        <div class="detail-label">Response Body</div>
        <div class="detail-value">${respBodyHtml}</div>
        <div class="detail-label">Response Headers</div>
        <div class="detail-value">${headersHtml}</div>
        <div class="detail-label">PAN-OS Feature</div>
        <div class="detail-value">${r.panos_feature || 'N/A'}</div>
        <div class="detail-label">Timestamp</div>
        <div class="detail-value">${ts}</div>
        <div class="detail-label">Verdict</div>
        <div class="detail-value"><span class="sec-verdict ${verdictClass}" style="font-size:11px;padding:3px 10px">${r.verdict}</span>
            <span style="margin-left:8px;font-size:11px">${r.verdict_explanation || r.detail || ''}</span></div>
    </div>`;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function toggleSecurityCategory(cat) {
    const list = document.getElementById('sec-list-' + cat);
    const chevron = document.getElementById('chevron-sec-' + cat);
    if (list) list.classList.toggle('collapsed');
    if (chevron) chevron.classList.toggle('collapsed');
}

function toggleSecCategorySelect(cat) {
    const boxes = document.querySelectorAll(`.sec-checkbox[data-cat="${cat}"]`);
    const allChecked = Array.from(boxes).every(b => b.checked);
    boxes.forEach(b => b.checked = !allChecked);
}

function getSelectedSecurityTests() {
    return Array.from(document.querySelectorAll('.sec-checkbox:checked')).map(b => b.dataset.id);
}

async function runSingleTest(testId) {
    const config = {
        http_port: parseInt(document.getElementById('sec-http-port').value) || 9999,
        https_port: parseInt(document.getElementById('sec-https-port').value) || 443,
        interval: 0,
    };
    const res = await apiPost('/api/security/start', { tests: [testId], config });
    addLog('[SECURITY] Running: ' + testId);
    if (res.ok) startSecurityPolling();
}

async function startSecurityTests() {
    const tests = getSelectedSecurityTests();
    if (!tests.length) { addLog('[SECURITY] No tests selected'); return; }
    const config = {
        http_port: parseInt(document.getElementById('sec-http-port').value) || 9999,
        https_port: parseInt(document.getElementById('sec-https-port').value) || 443,
        interval: parseFloat(document.getElementById('sec-interval').value) || 2,
    };
    const res = await apiPost('/api/security/start', { tests, config });
    addLog('[SECURITY] ' + res.message);
    if (res.ok) startSecurityPolling();
}

async function stopSecurityTests() {
    const res = await apiPost('/api/security/stop', {});
    addLog('[SECURITY] ' + res.message);
}

async function clearSecurityResults() {
    await apiPost('/api/security/clear', {});
    _securityResults = {};
    document.querySelectorAll('[id^="sec-verdict-"]').forEach(el => {
        el.innerHTML = '<span class="sec-verdict pending">--</span>';
    });
    document.querySelectorAll('[id^="sec-detail-"]').forEach(el => {
        el.style.display = 'none';
        el.innerHTML = '';
    });
    document.getElementById('security-summary').style.display = 'none';
    addLog('[SECURITY] Results cleared');
}

function startSecurityPolling() {
    if (_securityPollActive) return;
    _securityPollActive = true;
    pollSecurityStatus();
}

async function pollSecurityStatus() {
    if (!_securityPollActive) return;
    try {
        const resp = await fetch('/api/security/status');
        const data = await resp.json();
        updateSecurityUI(data);
        if (!data.running && data.summary.pending === 0) {
            _securityPollActive = false;
            return;
        }
    } catch(e) {}
    setTimeout(pollSecurityStatus, 1500);
}

function updateSecurityUI(data) {
    for (const r of data.results) {
        _securityResults[r.test_id] = r;
        const el = document.getElementById('sec-verdict-' + r.test_id);
        if (!el) continue;
        let cls = 'pending', label = '--';
        if (r.verdict === 'PASS') { cls = 'pass'; label = 'PASS'; }
        else if (r.verdict === 'FAIL') { cls = 'fail'; label = 'FAIL'; }
        else if (r.verdict === 'ERROR') { cls = 'error'; label = 'ERROR'; }
        else if (r.verdict === 'PENDING') { cls = 'pending'; label = 'PENDING'; }
        el.innerHTML = `<span class="sec-verdict ${cls}" title="${escapeHtml(r.detail || '')}">${label}</span>`;
        // Update expanded detail if visible
        const detail = document.getElementById('sec-detail-' + r.test_id);
        if (detail && detail.style.display !== 'none') renderSecDetail(r.test_id);
    }

    const s = data.summary;
    const summaryEl = document.getElementById('security-summary');
    if (s.total > 0) {
        summaryEl.style.display = '';
        const runLabel = data.running ? '<span style="color:var(--accent);font-weight:600">Running...</span>' : '<span style="color:var(--text-secondary)">Complete</span>';
        summaryEl.innerHTML = `<div class="security-summary-bar">
            ${runLabel}
            <span style="color:var(--text-secondary);font-size:11px">Total: <strong>${s.total}</strong></span>
            <span class="security-summary-item"><span class="dot green"></span> Pass: ${s.passed}</span>
            <span class="security-summary-item"><span class="dot red"></span> Fail: ${s.failed}</span>
            ${s.errors > 0 ? `<span class="security-summary-item"><span class="dot yellow"></span> Error: ${s.errors}</span>` : ''}
            ${s.pending > 0 ? `<span class="security-summary-item"><span class="dot gray"></span> Pending: ${s.pending}</span>` : ''}
        </div>`;
    } else {
        summaryEl.style.display = 'none';
    }
}

// ─── Custom Attack Patterns ─────────────────────────────────

function showCustomPatternForm(editId) {
    const modal = document.getElementById('custom-pattern-modal');
    if (!modal) return;
    if (editId) {
        document.getElementById('custom-pattern-title').textContent = 'Edit Custom Pattern';
        document.getElementById('custom-pattern-edit-id').value = editId;
        // Load pattern data
        fetch('/api/security/patterns').then(r => r.json()).then(patterns => {
            const p = patterns.find(x => x.id === editId);
            if (p) {
                document.getElementById('cp-name').value = p.name || '';
                document.getElementById('cp-category').value = p.category || 'web_attacks';
                document.getElementById('cp-payload').value = p.payload || '';
                document.getElementById('cp-method').value = p.method || 'GET';
                document.getElementById('cp-target-path').value = p.target_path || '/echo';
                document.getElementById('cp-headers').value = p.headers ? JSON.stringify(p.headers, null, 2) : '';
                document.getElementById('cp-description').value = p.description || '';
                document.getElementById('cp-panos-feature').value = p.panos_feature || 'Vulnerability Protection';
            }
        });
    } else {
        document.getElementById('custom-pattern-title').textContent = 'Add Custom Attack Pattern';
        document.getElementById('custom-pattern-edit-id').value = '';
        document.getElementById('cp-name').value = '';
        document.getElementById('cp-category').value = 'web_attacks';
        document.getElementById('cp-payload').value = '';
        document.getElementById('cp-method').value = 'GET';
        document.getElementById('cp-target-path').value = '/echo';
        document.getElementById('cp-headers').value = '';
        document.getElementById('cp-description').value = '';
        document.getElementById('cp-panos-feature').value = 'Vulnerability Protection';
    }
    modal.style.display = 'flex';
}

function hideCustomPatternForm() {
    const modal = document.getElementById('custom-pattern-modal');
    if (modal) modal.style.display = 'none';
}

async function saveCustomPattern() {
    const editId = document.getElementById('custom-pattern-edit-id').value;
    const name = document.getElementById('cp-name').value.trim();
    const payload = document.getElementById('cp-payload').value.trim();
    if (!name || !payload) { alert('Name and payload are required'); return; }

    let headers = {};
    const headersStr = document.getElementById('cp-headers').value.trim();
    if (headersStr) {
        try { headers = JSON.parse(headersStr); } catch(e) { alert('Headers must be valid JSON'); return; }
    }

    const data = {
        name,
        category: document.getElementById('cp-category').value,
        payload,
        method: document.getElementById('cp-method').value,
        target_path: document.getElementById('cp-target-path').value || '/echo',
        headers,
        description: document.getElementById('cp-description').value.trim(),
        panos_feature: document.getElementById('cp-panos-feature').value,
        expected_action: 'block',
    };

    const modal = document.getElementById('custom-pattern-modal');
    const builtinEdit = modal ? modal.dataset.builtinEdit : '';

    if (builtinEdit && !editId.startsWith('custom_')) {
        // Saving override for a built-in test
        await fetch('/api/security/builtin/' + builtinEdit, {
            method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
        });
    } else if (editId) {
        await fetch('/api/security/patterns/' + editId, {
            method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
        });
    } else {
        await fetch('/api/security/patterns', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
        });
    }
    if (modal) modal.dataset.builtinEdit = '';
    hideCustomPatternForm();
    await loadSecurityCatalog();
    addLog('[SECURITY] Test saved: ' + name);
}

async function editCustomPattern(patternId) {
    showCustomPatternForm(patternId);
}

async function editTestCase(testId, isCustom) {
    if (isCustom) {
        // Pure custom pattern — use existing flow
        showCustomPatternForm(testId);
        return;
    }
    // Built-in test (or overridden) — load from catalog and use override API
    let testInfo = null;
    if (_securityCatalog) {
        for (const tests of Object.values(_securityCatalog)) {
            for (const t of tests) {
                if (t.id === testId) { testInfo = t; break; }
            }
            if (testInfo) break;
        }
    }
    if (!testInfo) { addLog('[SECURITY] Test not found: ' + testId); return; }

    const modal = document.getElementById('custom-pattern-modal');
    if (!modal) return;
    document.getElementById('custom-pattern-title').textContent = 'Edit Test: ' + testInfo.name;
    document.getElementById('custom-pattern-edit-id').value = testId;
    document.getElementById('cp-name').value = testInfo.name || '';
    document.getElementById('cp-category').value = testInfo.category || 'web_attacks';
    document.getElementById('cp-payload').value = testInfo.payload || '';
    document.getElementById('cp-method').value = testInfo.method || 'GET';
    document.getElementById('cp-target-path').value = testInfo.target_path || '/echo';
    document.getElementById('cp-headers').value = testInfo.headers && Object.keys(testInfo.headers).length > 0 ? JSON.stringify(testInfo.headers, null, 2) : '';
    document.getElementById('cp-description').value = testInfo.description || '';
    document.getElementById('cp-panos-feature').value = testInfo.panos_feature || 'Vulnerability Protection';
    // Tag this as a builtin edit
    modal.dataset.builtinEdit = testId;
    modal.style.display = 'flex';
}

async function resetBuiltinTest(testId) {
    if (!confirm('Reset this test to its default configuration?')) return;
    await fetch('/api/security/builtin/' + testId, { method: 'DELETE' });
    await loadSecurityCatalog();
    addLog('[SECURITY] Test reset to default: ' + testId);
}

async function deleteCustomPattern(patternId) {
    if (!confirm('Delete this custom pattern?')) return;
    await fetch('/api/security/patterns/' + patternId, { method: 'DELETE' });
    await loadSecurityCatalog();
    addLog('[SECURITY] Custom pattern deleted');
}

// ─── Init ──────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    renderProtocolCards();
    loadRouters();
    loadSourceIps();
    loadProxy();
    loadFtpFileList();
    loadSecurityCatalog();
    document.getElementById('source-ip-toggle').addEventListener('change', toggleSourceIpConfig);
    autoRefreshInterval = setInterval(() => { pollStatus(); pollRouterStatus(); }, 2000);
    setInterval(loadFtpFileList, 10000);
    setInterval(refreshTopology, 10000);
    pollStatus();
    refreshTopology();
    addLog('Dashboard ready.');
});
