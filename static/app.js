const { createApp, ref, onMounted, watch } = Vue;

createApp({
    setup() {
        const sources = ref([]);
        const mappings = ref([]);
        const duplicates = ref([]);

        const showAddModal = ref(false);
        const newSource = ref({
            name: '',
            type: 'subscription',
            content: ''
        });

        const restartService = ref(false);
        const serviceName = ref('clash-meta');
        const outputPath = ref('/etc/mihomo/config.yaml');
        const isGenerating = ref(false);
        const message = ref('');
        const success = ref(false);

        // Auto-detect type (only when user hasn't manually selected a specific type)
        watch(() => newSource.value.content, (val) => {
            if (!val) return;
            const v = val.trim();
            const currentType = newSource.value.type;
            
            // Don't auto-switch if user has already manually selected http type
            if (currentType === 'http') return;
            
            // HTTP/HTTPS proxy URI (check first, more specific pattern)
            if ((v.startsWith('http://') || v.startsWith('https://')) && v.includes('#') && !v.includes('proxies:')) {
                // Likely a single HTTP/HTTPS proxy URI with name fragment
                const hasProxyParams = v.includes('skip-cert-verify') || v.includes('sni=') || v.split('://')[1]?.split('/')?.[0]?.includes('@');
                if (hasProxyParams || v.match(/^https?:\/\/[^\/]+:\d+/)) {
                    newSource.value.type = 'http';
                    return;
                }
            }
            if (v.startsWith('http://') || v.startsWith('https://')) {
                newSource.value.type = 'subscription';
            } else if (v.startsWith('vless://') || v.startsWith('ss://') || v.startsWith('trojan://') || v.startsWith('hysteria2://') || v.startsWith('vmess://')) {
                newSource.value.type = 'vless';
            } else if (v.includes('proxies:') || v.startsWith('proxies:')) {
                newSource.value.type = 'text';
            } else if (v.trim().startsWith('{') && v.includes('"outbounds"')) {
                newSource.value.type = 'xray';
            }
        });

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
                newSource.value = { name: '', type: 'subscription', content: '' };
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

        const openEditSourceModal = async (source) => {
            editSource.value = { 
                id: source.id, 
                name: source.name, 
                type: source.type, 
                content: source.content 
            };
            showEditSourceModal.value = true;
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
            sources,
            mappings,
            duplicates,
            showAddModal,
            newSource,
            restartService,
            outputPath,
            isGenerating,
            message,
            success,
            showEditModal,
            editMapping,
            showEditSourceModal,
            editSource,
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
            onSourceFileChange
        };
    }
}).mount('#app');
