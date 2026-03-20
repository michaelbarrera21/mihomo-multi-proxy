const { createApp, ref, onMounted, watch, nextTick, computed } = Vue;

// ===== Proxy Name Parsing Helpers =====

const FAKE_PROXY_KEYWORDS = [
    '剩余流量', '重置', '套餐到期', '距离下次', '建议',
    '流量预警', '额度', '用量', '已用', '过期', '到期',
    'expire', 'traffic', 'remaining', 'reset', 'subscription'
];

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
    if (type === 'subscription') return [];
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

        const showAddModal = ref(false);
        const newSource = ref({
            name: '',
            type: 'subscription',
            content: ''
        });
        const parsedNewProxies = ref([]);
        let _addSyncLock = false;

        const restartService = ref(false);
        const serviceName = ref(localStorage.getItem('serviceName') || 'clash-meta');
        const outputPath = ref(localStorage.getItem('outputPath') || '/etc/mihomo/config.yaml');
        const isGenerating = ref(false);
        const message = ref('');
        const success = ref(false);

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

        const closeAddModal = () => {
            showAddModal.value = false;
            _addSyncLock = true;
            newSource.value = { name: '', type: 'subscription', content: '' };
            parsedNewProxies.value = [];
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
                newSource.value = { name: '', type: 'subscription', content: '' };
                parsedNewProxies.value = [];
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

        const openEditModal = (map) => {
            editMapping.value = { proxy_name: map.proxy_name, port: map.port };
            showEditModal.value = true;
        };

        const saveMapping = async () => {
            try {
                await fetch(`/api/mappings/${encodeURIComponent(editMapping.value.proxy_name)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ port: editMapping.value.port })
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
        const editSource = ref({ id: null, name: '', type: '', content: '' });
        const parsedEditProxies = ref([]);
        let _editSyncLock = false;

        const openEditSourceModal = async (source) => {
            _editSyncLock = true;
            editSource.value = { 
                id: source.id, 
                name: source.name, 
                type: source.type, 
                content: source.content 
            };
            parsedEditProxies.value = parseContentProxies(source.content, source.type);
            _editSyncLock = false;
            showEditSourceModal.value = true;
        };

        // Edit Source content watcher
        watch(() => editSource.value.content, (val) => {
            if (_editSyncLock) return;
            _editSyncLock = true;
            const proxies = parseContentProxies(val, editSource.value.type);
            parsedEditProxies.value = proxies;
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

        const saveSourceEdit = async () => {
            if (!editSource.value.name || !editSource.value.content) return;
            try {
                await fetch(`/api/sources/${editSource.value.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: editSource.value.name,
                        type: editSource.value.type,
                        content: editSource.value.content
                    })
                });
                showEditSourceModal.value = false;
                await fetchData();
            } catch (e) {
                alert('Error saving source');
            }
        };

        const formatContent = (c) => {
            if (c.startsWith('http')) return c;
            return c.substring(0, 50) + (c.length > 50 ? '...' : '');
        };

        onMounted(() => {
            fetchData();
        });

        return {
            isDark,
            toggleTheme,
            sources,
            mappings,
            duplicates,
            showAddModal,
            newSource,
            parsedNewProxies,
            updateNewProxyName,
            closeAddModal,
            restartService,
            outputPath,
            isGenerating,
            message,
            success,
            showEditModal,
            editMapping,
            showEditSourceModal,
            editSource,
            parsedEditProxies,
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
            formatContent,
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
