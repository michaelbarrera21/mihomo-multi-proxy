const { createApp, ref, onMounted, watch, nextTick, computed } = Vue;

const nativeFetch = window.fetch.bind(window);
window.fetch = async (...args) => {
    const response = await nativeFetch(...args);
    const target = args[0];
    const url = typeof target === 'string' ? target : (target && target.url) || '';
    if (response.status === 401 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = `/login?next=${next}`;
    }
    return response;
};

// ===== Proxy Name Parsing Helpers =====

const FAKE_PROXY_KEYWORDS = [
    '剩余流量', '重置', '套餐到期', '距离下次', '建议',
    '流量预警', '额度', '用量', '已用', '过期', '到期',
    'expire', 'traffic', 'remaining', 'reset', 'subscription'
];

const SOURCE_TYPES = [
    { k: 'subscription', l: 'Sub' },
    { k: 'vless', l: 'URI' },
    { k: 'text', l: 'YAML' },
    { k: 'wireguard', l: 'WG' },
    { k: 'protonvpn', l: 'Proton' },
    { k: 'xray', l: 'Xray' },
    { k: 'http', l: 'HTTP/S' }
];

const LARGE_PREVIEW_SELECT_ALL_LIMIT = 1000;
const PREVIEW_PAGE_SIZE = 200;

function defaultSelection() {
    return { mode: 'all', node_keys: [] };
}

function cloneSelection(selection) {
    if (!selection || typeof selection !== 'object') return defaultSelection();
    const mode = ['all', 'include', 'exclude'].includes(selection.mode) ? selection.mode : 'all';
    const nodeKeys = Array.isArray(selection.node_keys) ? selection.node_keys.map(String) : [];
    return { mode, node_keys: nodeKeys };
}

function selectedCount(nodes) {
    return nodes.filter(n => n.selected).length;
}

function selectionSummary(nodes) {
    if (!nodes.length) return '';
    const count = selectedCount(nodes);
    const logicalTotal = nodes.reduce((sum, node) => {
        const logicalCount = Number((node.metadata || {}).logical_count || 1);
        return sum + Math.max(logicalCount || 1, 1);
    }, 0);
    const unit = logicalTotal > nodes.length ? 'endpoints' : '节点';
    const suffix = logicalTotal > nodes.length ? ` · 合并自 ${logicalTotal} 个 Proton 逻辑节点` : '';
    return count === nodes.length
        ? `将导入全部 ${nodes.length} 个 ${unit}${suffix}`
        : `将导入 ${count}/${nodes.length} 个 ${unit}${suffix}`;
}

function filterPreviewNodes(nodes, query) {
    const q = (query || '').trim().toLowerCase();
    if (!q) return nodes;

    return nodes.filter(node => {
        const metadata = node.metadata || {};
        return [
            node.name,
            node.server,
            node.type,
            metadata.exit_country,
            metadata.entry_country,
            metadata.city,
            metadata.state,
            metadata.domain,
            metadata.server_name,
            Array.isArray(metadata.features) ? metadata.features.join(' ') : ''
        ].some(value => String(value || '').toLowerCase().includes(q));
    });
}

function previewTotalPages(nodes) {
    return Math.max(1, Math.ceil(nodes.length / PREVIEW_PAGE_SIZE));
}

function previewPageItems(nodes, page) {
    const safePage = Math.min(Math.max(Number(page) || 1, 1), previewTotalPages(nodes));
    const start = (safePage - 1) * PREVIEW_PAGE_SIZE;
    return nodes.slice(start, start + PREVIEW_PAGE_SIZE);
}

function previewRangeText(nodes, page) {
    if (!nodes.length) return '0/0';
    const safePage = Math.min(Math.max(Number(page) || 1, 1), previewTotalPages(nodes));
    const start = (safePage - 1) * PREVIEW_PAGE_SIZE + 1;
    const end = Math.min(start + PREVIEW_PAGE_SIZE - 1, nodes.length);
    return `${start}-${end}/${nodes.length}`;
}

function contentSizeLabel(content) {
    const bytes = new Blob([content || '']).size;
    if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
}

function protonContentSummary(content) {
    if (new Blob([content || '']).size > 5 * 1024 * 1024) {
        return `Proton cache · ${contentSizeLabel(content)}`;
    }

    try {
        const data = JSON.parse(content || '{}');
        if (data && data.format === 'protonvpn.compact.v1') {
            const count = Array.isArray(data.servers) ? data.servers.length : 0;
            const stats = data.stats || {};
            const raw = Number(stats.raw_servers || 0);
            const unique = Number(stats.unique_endpoints || count);
            const auth = data.auth && data.auth.refresh_token ? ' · saved session' : '';
            if (raw && raw !== unique) {
                return `Proton compact cache · ${unique} endpoints · ${raw} logical nodes · ${contentSizeLabel(content)}${auth}`;
            }
            return `Proton compact cache · ${count} nodes · ${contentSizeLabel(content)}${auth}`;
        }
        if (data && Array.isArray(data.wireguard_configs)) {
            const auth = data.auth && data.auth.refresh_token ? ' · saved session' : '';
            return `Proton WireGuard cache · ${data.wireguard_configs.length} nodes · ${contentSizeLabel(content)}${auth}`;
        }
    } catch {}
    return `Proton content · ${contentSizeLabel(content)}`;
}

const storedProtonAuthCache = { content: null, result: false };

function hasStoredProtonAuth(content) {
    const value = content || '';
    if (storedProtonAuthCache.content === value) return storedProtonAuthCache.result;

    const head = value.slice(0, 12000);
    let result = head.includes('"protonvpn.compact.v1"')
        && head.includes('"auth"')
        && head.includes('"refresh_token"');

    if (!result && new Blob([value]).size <= 1024 * 1024) {
        try {
            const data = JSON.parse(value || '{}');
            result = !!(data && data.auth && data.auth.uid && data.auth.refresh_token);
        } catch {}
    }

    storedProtonAuthCache.content = value;
    storedProtonAuthCache.result = result;
    return result;
}

function protonKeepsDuplicates(content) {
    const value = content || '';
    if (value.slice(0, 20000).includes('"dedupe_endpoints":false')) return true;
    if (new Blob([value]).size > 1024 * 1024) return false;
    try {
        const data = JSON.parse(value || '{}');
        return data && data.filters && data.filters.dedupe_endpoints === false;
    } catch {}
    return false;
}

function defaultProtonCredentials() {
    return {
        auth_mode: 'password',
        username: '',
        password: '',
        twofa_code: '',
        auth_uid: '',
        auth_token: '',
        access_token: '',
        session_id: '',
        cookie_header: '',
        app_version: '',
        keep_duplicates: false
    };
}

function canFetchProton(credentials, source) {
    const c = credentials || {};
    const hasStoredAuth = hasStoredProtonAuth(source && source.content);
    if (c.auth_mode === 'session') {
        return !!(c.cookie_header || c.access_token || (c.auth_uid && c.auth_token) || hasStoredAuth);
    }
    return !!(c.username && c.password) || hasStoredAuth;
}

function isFakeProxy(name) {
    if (!name) return false;
    const lower = name.toLowerCase();
    return FAKE_PROXY_KEYWORDS.some(kw => lower.includes(kw.toLowerCase()));
}

function extractNameFromUri(uri) {
    try {
        const hashIdx = uri.lastIndexOf('#');
        if (hashIdx !== -1 && hashIdx < uri.length - 1) {
            return decodeURIComponent(uri.substring(hashIdx + 1).trim());
        }
    } catch {}
    return '';
}

function findYamlNameMatches(content) {
    const results = [];
    const regex = /(?<![a-zA-Z\-])name:\s*(?:'([^']*)'|"([^"]*)"|([^,}\r\n]+))\s*(?=[,}\r\n])/g;
    let match;
    let idx = 0;
    while ((match = regex.exec(content)) !== null) {
        const name = (match[1] ?? match[2] ?? match[3] ?? '').trim();
        const fullMatch = match[0];
        const colonIdx = fullMatch.indexOf(':');
        const afterColon = fullMatch.substring(colonIdx + 1);
        const valueOffset = afterColon.search(/\S/);
        let valueStart, valueLength, quoteStyle;
        if (match[1] !== undefined) {
            quoteStyle = "'";
            valueStart = match.index + colonIdx + 1 + valueOffset;
            valueLength = match[1].length + 2;
        } else if (match[2] !== undefined) {
            quoteStyle = '"';
            valueStart = match.index + colonIdx + 1 + valueOffset;
            valueLength = match[2].length + 2;
        } else {
            quoteStyle = '';
            valueStart = match.index + colonIdx + 1 + valueOffset;
            valueLength = match[3].length;
        }
        results.push({ name, index: idx, valueStart, valueLength, quoteStyle, isFake: isFakeProxy(name) });
        idx++;
    }
    return results;
}

function parseXrayProxies(content) {
    try {
        const lines = content.split('\n');
        const cleaned = lines.map(line => {
            if (line.includes('//') && !line.includes('://')) {
                return line.split('//')[0];
            }
            return line;
        }).join('\n');
        const data = JSON.parse(cleaned);
        const outbounds = data.outbounds || [];
        const proxyProtocols = ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria', 'hysteria2'];
        let idx = 0;
        return outbounds
            .filter(ob => proxyProtocols.includes(ob.protocol))
            .map(ob => ({ name: ob.tag || `proxy_${idx}`, index: idx++, isFake: isFakeProxy(ob.tag) }));
    } catch { return []; }
}

function parseContentProxies(content, type) {
    if (!content || !content.trim()) return [];
    if (type === 'subscription' || type === 'protonvpn') return [];
    const v = content.trim();

    if (type === 'vless' || type === 'http') {
        const lines = v.split('\n').map(l => l.trim()).filter(l => l);
        return lines.map((line, i) => {
            const name = extractNameFromUri(line);
            return { name: name || '', index: i, isFake: isFakeProxy(name) };
        });
    }
    if (type === 'text' || type === 'yaml') {
        // Use js-yaml for accurate proxy extraction
        try {
            const data = jsyaml.load(v);
            let proxies = [];
            if (data && typeof data === 'object' && Array.isArray(data.proxies)) {
                proxies = data.proxies;
            } else if (Array.isArray(data)) {
                proxies = data;
            }
            const parsed = proxies
                .filter(p => p && typeof p === 'object' && p.name)
                .map((p, i) => ({
                    name: String(p.name),
                    index: i,
                    isFake: isFakeProxy(String(p.name))
                }));
            if (parsed.length > 0) return parsed;
        } catch {}
        // Fallback: regex-based when js-yaml fails
        return findYamlNameMatches(v);
    }
    if (type === 'xray') {
        return parseXrayProxies(v);
    }
    if (type === 'wireguard') {
        const endpoint = (v.match(/Endpoint\s*=\s*([^\r\n]+)/i) || [])[1] || '';
        return [{ name: endpoint ? `WireGuard ${endpoint.trim()}` : 'WireGuard', index: 0, isFake: false }];
    }
    return [];
}

function updateUriProxyName(content, lineIndex, newName) {
    const lines = content.split('\n');
    const nonEmptyIndices = [];
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim()) nonEmptyIndices.push(i);
    }
    if (lineIndex >= 0 && lineIndex < nonEmptyIndices.length) {
        const actual = nonEmptyIndices[lineIndex];
        const line = lines[actual];
        const hashIdx = line.lastIndexOf('#');
        if (hashIdx !== -1) {
            lines[actual] = line.substring(0, hashIdx + 1) + newName;
        } else {
            lines[actual] = line.trimEnd() + '#' + newName;
        }
    }
    return lines.join('\n');
}

function getContentWarning(content, type, parsedProxies) {
    if (!content || !content.trim()) return '';
    if (type === 'text' || type === 'yaml') {
        try {
            const data = jsyaml.load(content);
            if (data && typeof data === 'object') {
                let proxies = [];
                if (Array.isArray(data.proxies)) {
                    proxies = data.proxies;
                } else if (Array.isArray(data)) {
                    proxies = data;
                }
                if (proxies.length === 0 && parsedProxies.length > 0) {
                    return 'YAML 解析未找到有效的 proxies 列表';
                }
                const validCount = proxies.filter(p => p && p.name && p.type && p.server).length;
                const nameOnlyCount = proxies.filter(p => p && p.name && (!p.type || !p.server)).length;
                if (validCount === 0 && nameOnlyCount > 0) {
                    return '解析出 name 字段但缺少 type 或 server，内容可能不是有效的代理配置';
                }
                if (nameOnlyCount > 0) {
                    return '有 ' + nameOnlyCount + ' 个条目缺少 type 或 server 字段';
                }
            } else if (parsedProxies.length > 0) {
                return 'YAML 解析结果不是有效的代理配置格式';
            }
        } catch (e) {
            const msg = e.message || String(e);
            const firstLine = msg.split('\n')[0];
            return 'YAML 语法错误: ' + firstLine;
        }
    }
    return '';
}

function buildNewValue(quoteStyle, newName) {
    if (quoteStyle === "'") return "'" + newName + "'";
    if (quoteStyle === '"') return '"' + newName + '"';
    return (newName.includes(',') || newName.includes('}') || newName.includes('{'))
        ? "'" + newName + "'" : newName;
}

function updateYamlProxyName(content, proxyIndex, newName) {
    // Use js-yaml to get the old name at proxyIndex, then find it in regex matches by value
    let oldName = null;
    let occurrencesBefore = 0;
    try {
        const data = jsyaml.load(content);
        let proxies;
        if (data && typeof data === 'object' && Array.isArray(data.proxies)) proxies = data.proxies;
        else if (Array.isArray(data)) proxies = data;
        else proxies = [];
        const valid = proxies.filter(p => p && p.name);
        if (proxyIndex >= 0 && proxyIndex < valid.length) {
            oldName = String(valid[proxyIndex].name);
            for (let i = 0; i < proxyIndex; i++) {
                if (String(valid[i].name) === oldName) occurrencesBefore++;
            }
        }
    } catch {
        // js-yaml failed, fall back to index-based regex
        const matches = findYamlNameMatches(content);
        if (proxyIndex < 0 || proxyIndex >= matches.length) return content;
        const m = matches[proxyIndex];
        return content.substring(0, m.valueStart) + buildNewValue(m.quoteStyle, newName) + content.substring(m.valueStart + m.valueLength);
    }

    if (oldName === null) return content;

    // Find the correct regex match by name value and occurrence
    const matches = findYamlNameMatches(content);
    let found = 0;
    for (const m of matches) {
        if (m.name.trim() === oldName.trim()) {
            if (found === occurrencesBefore) {
                return content.substring(0, m.valueStart) + buildNewValue(m.quoteStyle, newName) + content.substring(m.valueStart + m.valueLength);
            }
            found++;
        }
    }
    return content;
}

function updateXrayProxyName(content, proxyIndex, newName) {
    try {
        const lines = content.split('\n');
        const cleaned = lines.map(line => {
            if (line.includes('//') && !line.includes('://')) return line.split('//')[0];
            return line;
        }).join('\n');
        const data = JSON.parse(cleaned);
        const outbounds = data.outbounds || [];
        const proxyProtocols = ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria', 'hysteria2'];
        let idx = 0;
        for (let i = 0; i < outbounds.length; i++) {
            if (proxyProtocols.includes(outbounds[i].protocol)) {
                if (idx === proxyIndex) { outbounds[i].tag = newName; return JSON.stringify(data, null, 2); }
                idx++;
            }
        }
    } catch {}
    return content;
}

function updateProxyNameInContent(content, type, proxyIndex, newName) {
    if (type === 'vless' || type === 'http') return updateUriProxyName(content, proxyIndex, newName);
    if (type === 'text' || type === 'yaml') return updateYamlProxyName(content, proxyIndex, newName);
    if (type === 'xray') return updateXrayProxyName(content, proxyIndex, newName);
    return content;
}

function autoDetectType(val, currentType) {
    if (!val) return currentType;
    const v = val.trim();
    if (currentType === 'http') return currentType;
    if ((v.startsWith('http://') || v.startsWith('https://')) && v.includes('#') && !v.includes('proxies:')) {
        const hasProxyParams = v.includes('skip-cert-verify') || v.includes('sni=') || v.split('://')[1]?.split('/')?.[0]?.includes('@');
        if (hasProxyParams || v.match(/^https?:\/\/[^\/]+:\d+/)) return 'http';
    }
    if (v.startsWith('http://') || v.startsWith('https://')) return 'subscription';
    if (v.startsWith('vless://') || v.startsWith('ss://') || v.startsWith('trojan://') || v.startsWith('hysteria2://') || v.startsWith('vmess://')) return 'vless';
    if (v.includes('[Interface]') && v.includes('[Peer]')) return 'wireguard';
    if (v.includes('proxies:') || v.startsWith('proxies:')) return 'text';
    if (v.startsWith('{') && v.includes('"outbounds"')) return 'xray';
    return currentType;
}

// ===== Vue App =====

createApp({
    setup() {
        // ===== Theme =====
        const isDark = ref(localStorage.getItem('theme') !== 'light');
        function toggleTheme() {
            isDark.value = !isDark.value;
            document.documentElement.classList.toggle('dark', isDark.value);
            localStorage.setItem('theme', isDark.value ? 'dark' : 'light');
        }
        // Apply saved theme on load
        document.documentElement.classList.toggle('dark', isDark.value);

        const sources = ref([]);
        const mappings = ref([]);
        const duplicates = ref([]);
        const currentUser = ref('');

        const showAddModal = ref(false);
        const newSource = ref({
            name: '',
            type: 'subscription',
            content: '',
            selection: defaultSelection()
        });
        const parsedNewProxies = ref([]);
        const previewNewNodes = ref([]);
        const newPreviewFilter = ref('');
        const newPreviewPage = ref(1);
        const isPreviewingNew = ref(false);
        const newPreviewError = ref('');
        const newProtonCredentials = ref(defaultProtonCredentials());
        const isFetchingNewProton = ref(false);
        const newProtonError = ref('');
        let _addSyncLock = false;

        const restartService = ref(localStorage.getItem('restartService') === 'true');
        const serviceName = ref(localStorage.getItem('serviceName') || 'clash-meta');
        const outputPath = ref(localStorage.getItem('outputPath') || '/etc/mihomo/config.yaml');
        const isGenerating = ref(false);
        const isOpeningMihomoWeb = ref(false);
        const message = ref('');
        const success = ref(false);

        watch(restartService, (v) => localStorage.setItem('restartService', v ? 'true' : 'false'));
        watch(serviceName, (v) => localStorage.setItem('serviceName', v));
        watch(outputPath, (v) => localStorage.setItem('outputPath', v));

        // Auto-detect type + parse proxies + sync name
        watch(() => newSource.value.content, (val) => {
            if (_addSyncLock) return;
            _addSyncLock = true;

            // Auto-detect type
            if (val) {
                newSource.value.type = autoDetectType(val, newSource.value.type);
            }

            // Parse proxies
            const proxies = parseContentProxies(val, newSource.value.type);
            parsedNewProxies.value = proxies;
            newSource.value.selection = defaultSelection();
            previewNewNodes.value = [];
            newPreviewFilter.value = '';
            newPreviewPage.value = 1;
            newPreviewError.value = '';

            // Single proxy: sync name from content
            if (proxies.length === 1 && proxies[0].name) {
                newSource.value.name = proxies[0].name;
            }

            _addSyncLock = false;
        }, { flush: 'sync' });

        // Name → Content reverse sync (single proxy only)
        watch(() => newSource.value.name, (val) => {
            if (_addSyncLock) return;
            if (parsedNewProxies.value.length !== 1) return;
            _addSyncLock = true;
            newSource.value.content = updateProxyNameInContent(
                newSource.value.content, newSource.value.type, 0, val
            );
            parsedNewProxies.value = parseContentProxies(newSource.value.content, newSource.value.type);
            _addSyncLock = false;
        }, { flush: 'sync' });

        // Re-parse when type changes
        watch(() => newSource.value.type, () => {
            if (_addSyncLock) return;
            _addSyncLock = true;
            parsedNewProxies.value = parseContentProxies(newSource.value.content, newSource.value.type);
            newSource.value.selection = defaultSelection();
            previewNewNodes.value = [];
            newPreviewFilter.value = '';
            newPreviewPage.value = 1;
            newPreviewError.value = '';
            _addSyncLock = false;
        }, { flush: 'sync' });

        // Content warning for validation
        const newContentWarning = computed(() =>
            getContentWarning(newSource.value.content, newSource.value.type, parsedNewProxies.value)
        );

        // Multi-proxy name update
        const updateNewProxyName = (index, newName) => {
            _addSyncLock = true;
            newSource.value.content = updateProxyNameInContent(
                newSource.value.content, newSource.value.type, index, newName
            );
            const fresh = parseContentProxies(newSource.value.content, newSource.value.type);
            if (index < fresh.length) fresh[index].name = newName;
            parsedNewProxies.value = fresh;
            _addSyncLock = false;
        };

        const syncSelectionFromPreview = (sourceRef, nodes) => {
            const selectedKeys = nodes.filter(n => n.selected).map(n => n.node_key);
            sourceRef.value.selection = selectedKeys.length === nodes.length
                ? defaultSelection()
                : { mode: 'include', node_keys: selectedKeys };
        };

        const previewSourceNodes = async (sourceRef, nodesRef, loadingRef, errorRef) => {
            loadingRef.value = true;
            errorRef.value = '';
            try {
                const res = await fetch('/api/sources/preview', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: sourceRef.value.name,
                        type: sourceRef.value.type,
                        content: sourceRef.value.content,
                        selection: sourceRef.value.selection
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Preview failed');
                nodesRef.value = data.nodes || [];
                if (nodesRef === previewNewNodes) {
                    newPreviewPage.value = 1;
                } else if (nodesRef === previewEditNodes) {
                    editPreviewPage.value = 1;
                }
                syncSelectionFromPreview(sourceRef, nodesRef.value);
            } catch (e) {
                nodesRef.value = [];
                errorRef.value = e.message || String(e);
            } finally {
                loadingRef.value = false;
            }
        };

        const previewNewSource = () => previewSourceNodes(newSource, previewNewNodes, isPreviewingNew, newPreviewError);

        const togglePreviewNode = (sourceRef, nodesRef, node) => {
            node.selected = !node.selected;
            syncSelectionFromPreview(sourceRef, nodesRef.value);
        };

        const selectAllPreviewNodes = (sourceRef, nodesRef, selected) => {
            nodesRef.value.forEach(node => { node.selected = selected; });
            syncSelectionFromPreview(sourceRef, nodesRef.value);
        };

        const selectFilteredPreviewNodes = (sourceRef, nodesRef, filteredNodes, selected) => {
            const keys = new Set(filteredNodes.map(node => node.node_key));
            nodesRef.value.forEach(node => {
                if (keys.has(node.node_key)) node.selected = selected;
            });
            syncSelectionFromPreview(sourceRef, nodesRef.value);
        };

        const toggleNewPreviewNode = (node) => togglePreviewNode(newSource, previewNewNodes, node);
        const selectAllNewPreviewNodes = (selected) => selectAllPreviewNodes(newSource, previewNewNodes, selected);
        const selectFilteredNewPreviewNodes = (selected) =>
            selectFilteredPreviewNodes(newSource, previewNewNodes, newPreviewFilteredNodes.value, selected);

        const fetchProtonNodes = async (sourceRef, credentialsRef, nodesRef, loadingRef, errorRef) => {
            loadingRef.value = true;
            errorRef.value = '';
            try {
                const body = {
                    username: credentialsRef.value.username,
                    password: credentialsRef.value.password,
                    twofa_code: credentialsRef.value.twofa_code || null,
                    name: sourceRef.value.name || 'ProtonVPN',
                    existing_content: sourceRef.value.content || null,
                    auth_uid: credentialsRef.value.auth_uid || null,
                    auth_token: credentialsRef.value.auth_token || null,
                    access_token: credentialsRef.value.access_token || null,
                    session_id: credentialsRef.value.session_id || null,
                    cookie_header: credentialsRef.value.cookie_header || null,
                    app_version: credentialsRef.value.app_version || null,
                    dedupe_endpoints: !credentialsRef.value.keep_duplicates
                };
                const res = await fetch('/api/protonvpn/fetch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'ProtonVPN fetch failed');
                sourceRef.value.type = 'protonvpn';
                sourceRef.value.content = data.content;
                if (!sourceRef.value.name) sourceRef.value.name = 'ProtonVPN';
                const fetchedNodes = data.nodes || [];
                const selectAllByDefault = fetchedNodes.length <= LARGE_PREVIEW_SELECT_ALL_LIMIT;
                fetchedNodes.forEach(node => { node.selected = selectAllByDefault && node.selected !== false; });
                nodesRef.value = fetchedNodes;
                if (nodesRef === previewNewNodes) {
                    newPreviewFilter.value = '';
                    newPreviewPage.value = 1;
                } else if (nodesRef === previewEditNodes) {
                    editPreviewFilter.value = '';
                    editPreviewPage.value = 1;
                }
                syncSelectionFromPreview(sourceRef, nodesRef.value);
                credentialsRef.value.password = '';
                credentialsRef.value.twofa_code = '';
                credentialsRef.value.auth_token = '';
                credentialsRef.value.access_token = '';
                credentialsRef.value.session_id = '';
                credentialsRef.value.cookie_header = '';
            } catch (e) {
                nodesRef.value = [];
                errorRef.value = e.message || String(e);
            } finally {
                loadingRef.value = false;
            }
        };

        const fetchNewProton = () => fetchProtonNodes(
            newSource, newProtonCredentials, previewNewNodes, isFetchingNewProton, newProtonError
        );

        const closeAddModal = () => {
            showAddModal.value = false;
            _addSyncLock = true;
            newSource.value = { name: '', type: 'subscription', content: '', selection: defaultSelection() };
            newProtonCredentials.value = defaultProtonCredentials();
            parsedNewProxies.value = [];
            previewNewNodes.value = [];
            newPreviewFilter.value = '';
            newPreviewPage.value = 1;
            newPreviewError.value = '';
            newProtonError.value = '';
            _addSyncLock = false;
        };

        const fetchData = async () => {
            try {
                const s = await fetch('/api/sources').then(r => r.json());
                sources.value = s;
                const m = await fetch('/api/mappings').then(r => r.json());
                mappings.value = m;
                const d = await fetch('/api/mappings/duplicates').then(r => r.json());
                duplicates.value = d;
            } catch (e) {
                console.error(e);
            }
        };

        const loadAuthStatus = async () => {
            try {
                const data = await fetch('/api/auth/status').then(r => r.json());
                currentUser.value = data.username || '';
            } catch (e) {
                console.error(e);
            }
        };

        const logout = async () => {
            try {
                await fetch('/api/auth/logout', { method: 'POST' });
            } finally {
                window.location.href = '/login';
            }
        };

        const addSource = async () => {
            if (!newSource.value.name || !newSource.value.content) return;
            try {
                await fetch('/api/sources', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(newSource.value)
                });
                showAddModal.value = false;
                _addSyncLock = true;
                newSource.value = { name: '', type: 'subscription', content: '', selection: defaultSelection() };
                newProtonCredentials.value = defaultProtonCredentials();
                parsedNewProxies.value = [];
                previewNewNodes.value = [];
                newPreviewFilter.value = '';
                newPreviewPage.value = 1;
                newPreviewError.value = '';
                newProtonError.value = '';
                _addSyncLock = false;
                await fetchData();
            } catch (e) {
                alert('Error adding source');
            }
        };

        const deleteSource = async (id) => {
            if (!confirm('Are you sure?')) return;
            await fetch(`/api/sources/${id}`, { method: 'DELETE' });
            await fetchData();
        };

        const toggleSource = async (source) => {
            await fetch(`/api/sources/${source.id}/toggle`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !source.enabled })
            });
            await fetchData();
        };

        const deleteMapping = async (proxyName) => {
            if (!confirm(`删除映射: ${proxyName}?`)) return;
            await fetch(`/api/mappings/${encodeURIComponent(proxyName)}`, { method: 'DELETE' });
            await fetchData();
        };

        // Edit mapping
        const showEditModal = ref(false);
        const editMapping = ref({ proxy_name: '', port: 0 });
        let _editMappingOriginalName = '';

        const openEditModal = (map) => {
            _editMappingOriginalName = map.proxy_name;
            editMapping.value = { proxy_name: map.proxy_name, port: map.port };
            showEditModal.value = true;
        };

        const saveMapping = async () => {
            try {
                const body = { port: editMapping.value.port };
                if (editMapping.value.proxy_name !== _editMappingOriginalName) {
                    body.proxy_name = editMapping.value.proxy_name;
                }
                await fetch(`/api/mappings/${encodeURIComponent(_editMappingOriginalName)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                showEditModal.value = false;
                await fetchData();
            } catch (e) {
                alert('Error saving mapping');
            }
        };

        const generateConfig = async () => {
            isGenerating.value = true;
            message.value = '';
            try {
                const res = await fetch('/api/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        output_path: outputPath.value,
                        restart_service: restartService.value,
                        service_name: serviceName.value
                    })
                }).then(r => r.json());

                success.value = res.status === 'success';
                message.value = res.message;
                
                // Add issues details to message if any
                if (res.issues && res.issues.length > 0) {
                    const issuesList = res.issues.map(issue => 
                        `• ${issue.name} (${issue.type}): ${issue.reason}${issue.detail ? ' - ' + issue.detail : ''}`
                    ).join('\n');
                    message.value += `\n\n跳过的 Sources:\n${issuesList}`;
                }
                
                if (success.value) await fetchData();
            } catch (e) {
                success.value = false;
                message.value = 'Generation failed: ' + e;
            } finally {
                isGenerating.value = false;
            }
        };

        const openMihomoWeb = async () => {
            isOpeningMihomoWeb.value = true;
            message.value = '';
            const popup = window.open('about:blank', '_blank');
            if (popup) popup.opener = null;
            try {
                const res = await fetch(`/api/mihomo/webui?output_path=${encodeURIComponent(outputPath.value)}`);
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to read Mihomo config');
                if (popup) {
                    popup.location.href = data.url;
                } else {
                    window.location.href = data.url;
                }
                success.value = true;
                message.value = data.secret
                    ? `Mihomo Web: ${data.url}\nAPI Secret: ${data.secret}`
                    : `Mihomo Web: ${data.url}`;
            } catch (e) {
                if (popup) popup.close();
                success.value = false;
                message.value = 'Open Mihomo Web failed: ' + (e.message || e);
            } finally {
                isOpeningMihomoWeb.value = false;
            }
        };

        const uploadMappings = async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('file', file);

            try {
                const res = await fetch('/api/mappings/import', {
                    method: 'POST',
                    body: formData
                }).then(r => r.json());

                if (res.status === 'success') {
                    alert(res.message);
                    await fetchData();
                } else {
                    alert('Import failed: ' + (res.detail || res.message));
                }
            } catch (e) {
                alert('Error importing mappings: ' + e);
            } finally {
                // Reset input
                event.target.value = '';
            }
        };

        const sourceFileInput = ref(null);

        const loadSourceFile = () => {
            sourceFileInput.value.click();
        };

        const onSourceFileChange = (event) => {
            const file = event.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (e) => {
                // Set content to whichever modal is open
                if (showEditSourceModal.value) {
                    editSource.value.content = e.target.result;
                } else {
                    newSource.value.content = e.target.result;
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        };

        // Edit Source
        const showEditSourceModal = ref(false);
        const editSource = ref({ id: null, name: '', type: '', content: '', selection: defaultSelection() });
        const parsedEditProxies = ref([]);
        const previewEditNodes = ref([]);
        const editPreviewFilter = ref('');
        const editPreviewPage = ref(1);
        const isPreviewingEdit = ref(false);
        const editPreviewError = ref('');
        const editProtonCredentials = ref(defaultProtonCredentials());
        const isFetchingEditProton = ref(false);
        const editProtonError = ref('');
        let _editSyncLock = false;

        const newPreviewFilteredNodes = computed(() =>
            filterPreviewNodes(previewNewNodes.value, newPreviewFilter.value)
        );
        const newPreviewVisibleNodes = computed(() =>
            previewPageItems(newPreviewFilteredNodes.value, newPreviewPage.value)
        );
        const newPreviewTotalPages = computed(() =>
            previewTotalPages(newPreviewFilteredNodes.value)
        );
        const newPreviewRangeText = computed(() =>
            previewRangeText(newPreviewFilteredNodes.value, newPreviewPage.value)
        );
        const editPreviewFilteredNodes = computed(() =>
            filterPreviewNodes(previewEditNodes.value, editPreviewFilter.value)
        );
        const editPreviewVisibleNodes = computed(() =>
            previewPageItems(editPreviewFilteredNodes.value, editPreviewPage.value)
        );
        const editPreviewTotalPages = computed(() =>
            previewTotalPages(editPreviewFilteredNodes.value)
        );
        const editPreviewRangeText = computed(() =>
            previewRangeText(editPreviewFilteredNodes.value, editPreviewPage.value)
        );

        watch(newPreviewFilter, () => { newPreviewPage.value = 1; });
        watch(editPreviewFilter, () => { editPreviewPage.value = 1; });

        const openEditSourceModal = async (source) => {
            const fullSource = await fetch(`/api/sources/${source.id}`).then(r => r.json());
            _editSyncLock = true;
            editSource.value = { 
                id: fullSource.id,
                name: fullSource.name,
                type: fullSource.type,
                content: fullSource.content,
                selection: cloneSelection(fullSource.selection)
            };
            parsedEditProxies.value = parseContentProxies(fullSource.content, fullSource.type);
            previewEditNodes.value = [];
            editPreviewFilter.value = '';
            editPreviewPage.value = 1;
            editPreviewError.value = '';
            editProtonError.value = '';
            editProtonCredentials.value = defaultProtonCredentials();
            editProtonCredentials.value.keep_duplicates = protonKeepsDuplicates(fullSource.content);
            _editSyncLock = false;
            showEditSourceModal.value = true;
        };

        // Edit Source content watcher
        watch(() => editSource.value.content, (val) => {
            if (_editSyncLock) return;
            _editSyncLock = true;
            const proxies = parseContentProxies(val, editSource.value.type);
            parsedEditProxies.value = proxies;
            editSource.value.selection = defaultSelection();
            previewEditNodes.value = [];
            editPreviewFilter.value = '';
            editPreviewPage.value = 1;
            editPreviewError.value = '';
            if (proxies.length === 1 && proxies[0].name) {
                editSource.value.name = proxies[0].name;
            }
            _editSyncLock = false;
        }, { flush: 'sync' });

        // Edit Name → Content reverse sync (single proxy)
        watch(() => editSource.value.name, (val) => {
            if (_editSyncLock) return;
            if (parsedEditProxies.value.length !== 1) return;
            _editSyncLock = true;
            editSource.value.content = updateProxyNameInContent(
                editSource.value.content, editSource.value.type, 0, val
            );
            parsedEditProxies.value = parseContentProxies(editSource.value.content, editSource.value.type);
            _editSyncLock = false;
        }, { flush: 'sync' });

        // Edit type watcher
        watch(() => editSource.value.type, () => {
            if (_editSyncLock) return;
            _editSyncLock = true;
            parsedEditProxies.value = parseContentProxies(editSource.value.content, editSource.value.type);
            editSource.value.selection = defaultSelection();
            previewEditNodes.value = [];
            editPreviewFilter.value = '';
            editPreviewPage.value = 1;
            editPreviewError.value = '';
            _editSyncLock = false;
        }, { flush: 'sync' });

        // Content warning for edit validation
        const editContentWarning = computed(() =>
            getContentWarning(editSource.value.content, editSource.value.type, parsedEditProxies.value)
        );

        // Multi-proxy name update for edit modal
        const updateEditProxyName = (index, newName) => {
            _editSyncLock = true;
            editSource.value.content = updateProxyNameInContent(
                editSource.value.content, editSource.value.type, index, newName
            );
            const fresh = parseContentProxies(editSource.value.content, editSource.value.type);
            if (index < fresh.length) fresh[index].name = newName;
            parsedEditProxies.value = fresh;
            _editSyncLock = false;
        };

        const previewEditSource = () => previewSourceNodes(editSource, previewEditNodes, isPreviewingEdit, editPreviewError);
        const toggleEditPreviewNode = (node) => togglePreviewNode(editSource, previewEditNodes, node);
        const selectAllEditPreviewNodes = (selected) => selectAllPreviewNodes(editSource, previewEditNodes, selected);
        const selectFilteredEditPreviewNodes = (selected) =>
            selectFilteredPreviewNodes(editSource, previewEditNodes, editPreviewFilteredNodes.value, selected);
        const fetchEditProton = () => fetchProtonNodes(
            editSource, editProtonCredentials, previewEditNodes, isFetchingEditProton, editProtonError
        );

        const saveSourceEdit = async () => {
            if (!editSource.value.name || !editSource.value.content) return;
            try {
                await fetch(`/api/sources/${editSource.value.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: editSource.value.name,
                        type: editSource.value.type,
                        content: editSource.value.content,
                        selection: editSource.value.selection
                    })
                });
                showEditSourceModal.value = false;
                await fetchData();
            } catch (e) {
                alert('Error saving source');
            }
        };

        const formatContent = (c) => {
            if (!c) return '';
            if (c.trim().startsWith('{') && c.includes('"password"')) return c.replace(/"password"\s*:\s*"[^"]*"/g, '"password":"***"').substring(0, 50) + '...';
            if (c.startsWith('http')) return c;
            return c.substring(0, 50) + (c.length > 50 ? '...' : '');
        };

        const formatSourceContent = (source) => {
            if (source.content_preview) return source.content_preview;
            return formatContent(source.content || '');
        };

        onMounted(() => {
            loadAuthStatus();
            fetchData();
        });

        return {
            isDark,
            toggleTheme,
            currentUser,
            logout,
            sources,
            mappings,
            duplicates,
            showAddModal,
            newSource,
            SOURCE_TYPES,
            parsedNewProxies,
            previewNewNodes,
            newPreviewFilter,
            newPreviewPage,
            newPreviewFilteredNodes,
            newPreviewVisibleNodes,
            newPreviewTotalPages,
            newPreviewRangeText,
            isPreviewingNew,
            newPreviewError,
            newProtonCredentials,
            isFetchingNewProton,
            newProtonError,
            canFetchProton,
            fetchNewProton,
            previewNewSource,
            selectedCount,
            selectionSummary,
            toggleNewPreviewNode,
            selectAllNewPreviewNodes,
            selectFilteredNewPreviewNodes,
            updateNewProxyName,
            closeAddModal,
            restartService,
            outputPath,
            isGenerating,
            isOpeningMihomoWeb,
            message,
            success,
            showEditModal,
            editMapping,
            showEditSourceModal,
            editSource,
            parsedEditProxies,
            previewEditNodes,
            editPreviewFilter,
            editPreviewPage,
            editPreviewFilteredNodes,
            editPreviewVisibleNodes,
            editPreviewTotalPages,
            editPreviewRangeText,
            isPreviewingEdit,
            editPreviewError,
            editProtonCredentials,
            isFetchingEditProton,
            editProtonError,
            previewEditSource,
            toggleEditPreviewNode,
            selectAllEditPreviewNodes,
            selectFilteredEditPreviewNodes,
            fetchEditProton,
            updateEditProxyName,
            fetchData,
            addSource,
            deleteSource,
            toggleSource,
            deleteMapping,
            openEditModal,
            saveMapping,
            openEditSourceModal,
            saveSourceEdit,
            generateConfig,
            openMihomoWeb,
            formatContent,
            formatSourceContent,
            protonContentSummary,
            uploadMappings,
            sourceFileInput,
            loadSourceFile,
            onSourceFileChange,
            isFakeProxy,
            serviceName,
            newContentWarning,
            editContentWarning
        };
    }
}).mount('#app');
