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

        // Auto-detect type
        watch(() => newSource.value.content, (val) => {
            if (!val) return;
            const v = val.trim();
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
                newSource.value.content = e.target.result;
            };
            reader.readAsText(file);
            event.target.value = '';
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
            fetchData,
            addSource,
            deleteSource,
            toggleSource,
            deleteMapping,
            openEditModal,
            saveMapping,
            generateConfig,
            formatContent,
            formatContent,
            uploadMappings,
            sourceFileInput,
            loadSourceFile,
            onSourceFileChange
        };
    }
}).mount('#app');
