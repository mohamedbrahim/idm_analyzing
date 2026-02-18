/**
 * IDM Permission Analyzer - Client Application
 * Interactive visualization and analysis of FreeIPA/IDM permissions
 */

class IDMAnalyzerApp {
    constructor() {
        this.users = [];
        this.hosts = [];
        this.currentUser = null;
        this.currentGraph = null;
        this.simulation = null;
        
        this.init();
    }
    
    async init() {
        // Load initial data
        await this.loadUsers();
        await this.loadHosts();
        
        // Setup event listeners
        this.setupNavigation();
        this.setupSearch();
        this.setupTabs();
        this.setupCompare();
        this.setupTrace();
        this.setupBrowse();
        this.setupModal();
        this.setupGraphControls();
    }
    
    // ==================== Data Loading ====================
    
    async loadUsers() {
        try {
            const response = await fetch('/api/users');
            this.users = await response.json();
        } catch (error) {
            console.error('Failed to load users:', error);
            this.users = [];
        }
    }
    
    async loadHosts() {
        try {
            const response = await fetch('/api/hosts');
            this.hosts = await response.json();
        } catch (error) {
            console.error('Failed to load hosts:', error);
            this.hosts = [];
        }
    }
    
    // ==================== Navigation ====================
    
    setupNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        
        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const viewId = item.dataset.view;
                this.switchView(viewId);
                
                // Update active state
                navItems.forEach(i => i.classList.remove('active'));
                item.classList.add('active');
            });
        });
    }
    
    switchView(viewId) {
        const views = document.querySelectorAll('.view');
        views.forEach(view => view.classList.remove('active'));
        
        const targetView = document.getElementById(`view-${viewId}`);
        if (targetView) {
            targetView.classList.add('active');
        }
    }
    
    // ==================== Search & Suggestions ====================
    
    setupSearch() {
        // Main user search
        const userSearch = document.getElementById('user-search');
        const userSuggestions = document.getElementById('user-suggestions');
        
        this.setupAutocomplete(userSearch, userSuggestions, this.users, 'uid', 'cn');
        
        userSearch.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.analyzeUser(userSearch.value.trim());
            }
        });
        
        document.getElementById('btn-analyze').addEventListener('click', () => {
            this.analyzeUser(userSearch.value.trim());
        });
    }
    
    setupAutocomplete(input, container, items, valueKey, labelKey) {
        let selectedIndex = -1;
        
        input.addEventListener('input', () => {
            const query = input.value.toLowerCase().trim();
            container.innerHTML = '';
            selectedIndex = -1;
            
            if (query.length < 1) {
                container.classList.remove('active');
                return;
            }
            
            const matches = items.filter(item => {
                const value = item[valueKey] || '';
                const label = item[labelKey] || '';
                return value.toLowerCase().includes(query) || 
                       label.toLowerCase().includes(query);
            }).slice(0, 10);
            
            if (matches.length === 0) {
                container.classList.remove('active');
                return;
            }
            
            matches.forEach((item, index) => {
                const div = document.createElement('div');
                div.className = 'suggestion-item';
                div.innerHTML = `
                    <div class="name">${item[valueKey]}</div>
                    ${item[labelKey] ? `<div class="detail">${item[labelKey]}</div>` : ''}
                `;
                div.addEventListener('click', () => {
                    input.value = item[valueKey];
                    container.classList.remove('active');
                });
                container.appendChild(div);
            });
            
            container.classList.add('active');
        });
        
        input.addEventListener('keydown', (e) => {
            const items = container.querySelectorAll('.suggestion-item');
            
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                selectedIndex = Math.min(selectedIndex + 1, items.length - 1);
                this.highlightSuggestion(items, selectedIndex);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                selectedIndex = Math.max(selectedIndex - 1, 0);
                this.highlightSuggestion(items, selectedIndex);
            } else if (e.key === 'Enter' && selectedIndex >= 0) {
                e.preventDefault();
                items[selectedIndex].click();
            } else if (e.key === 'Escape') {
                container.classList.remove('active');
            }
        });
        
        input.addEventListener('blur', () => {
            setTimeout(() => container.classList.remove('active'), 200);
        });
    }
    
    highlightSuggestion(items, index) {
        items.forEach((item, i) => {
            item.style.background = i === index ? 'var(--bg-hover)' : '';
        });
    }
    
    // ==================== User Analysis ====================
    
    async analyzeUser(username, filterMode = null) {
        if (!username) return;
        
        const resultsContainer = document.getElementById('analysis-results');
        resultsContainer.classList.remove('hidden');
        
        // Get filter mode from select if not provided
        if (!filterMode) {
            const filterSelect = document.getElementById('graph-filter');
            filterMode = filterSelect ? filterSelect.value : 'rules_only';
        }
        
        // Show loading state
        this.showLoading(resultsContainer);
        
        try {
            // Fetch analysis and graph data with filter
            const [analysis, graphData] = await Promise.all([
                fetch(`/api/user/${username}/analyze`).then(r => r.json()),
                fetch(`/api/user/${username}/graph?filter=${filterMode}`).then(r => r.json())
            ]);
            
            if (analysis.error || graphData.error) {
                this.showError(resultsContainer, analysis.error || graphData.error);
                return;
            }
            
            this.currentUser = username;
            this.currentGraph = graphData;
            this.analysisData = analysis;
            
            // Update UI
            this.updateUserInfo(analysis);
            this.updateStats(analysis, graphData.stats);
            this.renderGraph(graphData);
            this.updateDetailTabs(analysis);
            
        } catch (error) {
            console.error('Analysis failed:', error);
            this.showError(resultsContainer, 'Failed to analyze user');
        }
    }
    
    setupFilterChange() {
        const filterSelect = document.getElementById('graph-filter');
        if (filterSelect) {
            filterSelect.addEventListener('change', () => {
                if (this.currentUser) {
                    this.refreshGraph(filterSelect.value);
                }
            });
        }
    }
    
    async refreshGraph(filterMode) {
        if (!this.currentUser) return;
        
        try {
            const graphData = await fetch(`/api/user/${this.currentUser}/graph?filter=${filterMode}`).then(r => r.json());
            
            if (graphData.error) {
                console.error('Graph refresh failed:', graphData.error);
                return;
            }
            
            this.currentGraph = graphData;
            this.renderGraph(graphData);
            
            // Update stats to show filtered counts
            if (graphData.stats) {
                document.querySelector('#stat-groups .stat-value').textContent = graphData.stats.groups_shown;
            }
            
        } catch (error) {
            console.error('Graph refresh failed:', error);
        }
    }
    
    showLoading(container) {
        // Keep structure but show loading
    }
    
    showError(container, message) {
        container.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M12 8v4M12 16h.01"/>
                </svg>
                <p>${message}</p>
            </div>
        `;
    }
    
    updateUserInfo(analysis) {
        const container = document.getElementById('user-info-content');
        container.innerHTML = `
            <div class="info-row">
                <span class="info-label">Username</span>
                <span class="info-value">${analysis.user.uid}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Full Name</span>
                <span class="info-value">${analysis.user.cn || '-'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Email</span>
                <span class="info-value">${analysis.user.mail || '-'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Direct Groups</span>
                <span class="info-value">${analysis.direct_groups.length}</span>
            </div>
        `;
    }
    
    updateStats(analysis) {
        document.querySelector('#stat-groups .stat-value').textContent = analysis.all_groups.length;
        document.querySelector('#stat-hbac .stat-value').textContent = analysis.hbac_rules.length;
        document.querySelector('#stat-sudo .stat-value').textContent = analysis.sudo_rules.length;
    }
    
    // ==================== Graph Visualization ====================
    
    renderGraph(data) {
        const container = document.getElementById('graph-container');
        container.innerHTML = '';
        
        const width = container.clientWidth;
        const height = container.clientHeight;
        
        // Create SVG
        const svg = d3.select(container)
            .append('svg')
            .attr('width', width)
            .attr('height', height);
        
        // Create a group for zoom/pan
        const g = svg.append('g');
        
        // Setup zoom
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });
        
        svg.call(zoom);
        
        // Node colors
        const nodeColors = {
            user: '#4a90d9',
            group: '#34d399',
            hbac: '#f59e0b',
            sudo: '#ef4444'
        };
        
        // Node sizes
        const nodeSizes = {
            user: 25,
            group: 18,
            hbac: 20,
            sudo: 20
        };
        
        // Create simulation
        this.simulation = d3.forceSimulation(data.nodes)
            .force('link', d3.forceLink(data.edges)
                .id(d => d.id)
                .distance(120))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(40));
        
        // Create arrow markers
        svg.append('defs').selectAll('marker')
            .data(['member_of', 'has_hbac', 'has_sudo'])
            .join('marker')
            .attr('id', d => `arrow-${d}`)
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 25)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('fill', d => {
                if (d === 'member_of') return '#34d399';
                if (d === 'has_hbac') return '#f59e0b';
                return '#ef4444';
            })
            .attr('d', 'M0,-5L10,0L0,5');
        
        // Create links
        const link = g.append('g')
            .selectAll('line')
            .data(data.edges)
            .join('line')
            .attr('class', d => `link ${d.type}`)
            .attr('stroke-width', 2)
            .attr('marker-end', d => `url(#arrow-${d.type})`);
        
        // Create nodes
        const node = g.append('g')
            .selectAll('.node')
            .data(data.nodes)
            .join('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', (event, d) => {
                    if (!event.active) this.simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', (event, d) => {
                    d.fx = event.x;
                    d.fy = event.y;
                })
                .on('end', (event, d) => {
                    if (!event.active) this.simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }));
        
        // Add circles
        node.append('circle')
            .attr('r', d => nodeSizes[d.type] || 15)
            .attr('fill', d => nodeColors[d.type] || '#666');
        
        // Add labels
        node.append('text')
            .attr('dy', d => (nodeSizes[d.type] || 15) + 14)
            .attr('text-anchor', 'middle')
            .text(d => d.label.length > 20 ? d.label.substring(0, 18) + '...' : d.label);
        
        // Add click handler
        node.on('click', (event, d) => {
            this.showNodeDetails(d);
        });
        
        // Update positions on tick
        this.simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });
        
        // Store references for controls
        this.graphSvg = svg;
        this.graphZoom = zoom;
        this.graphGroup = g;
    }
    
    setupGraphControls() {
        document.getElementById('btn-zoom-in').addEventListener('click', () => {
            if (this.graphSvg && this.graphZoom) {
                this.graphSvg.transition().call(this.graphZoom.scaleBy, 1.3);
            }
        });
        
        document.getElementById('btn-zoom-out').addEventListener('click', () => {
            if (this.graphSvg && this.graphZoom) {
                this.graphSvg.transition().call(this.graphZoom.scaleBy, 0.7);
            }
        });
        
        document.getElementById('btn-fit').addEventListener('click', () => {
            if (this.graphSvg && this.graphZoom) {
                this.graphSvg.transition().call(
                    this.graphZoom.transform,
                    d3.zoomIdentity
                );
            }
        });
        
        document.getElementById('btn-export').addEventListener('click', () => {
            this.exportGraphAsPNG();
        });
    }
    
    exportGraphAsPNG() {
        const svg = document.querySelector('#graph-container svg');
        if (!svg) return;
        
        // Create canvas
        const canvas = document.createElement('canvas');
        const bbox = svg.getBoundingClientRect();
        canvas.width = bbox.width * 2;
        canvas.height = bbox.height * 2;
        
        const ctx = canvas.getContext('2d');
        ctx.scale(2, 2);
        ctx.fillStyle = '#0a0a0f';
        ctx.fillRect(0, 0, bbox.width, bbox.height);
        
        // Convert SVG to data URL
        const svgData = new XMLSerializer().serializeToString(svg);
        const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(svgBlob);
        
        const img = new Image();
        img.onload = () => {
            ctx.drawImage(img, 0, 0);
            URL.revokeObjectURL(url);
            
            // Download
            const link = document.createElement('a');
            link.download = `idm-permissions-${this.currentUser}.png`;
            link.href = canvas.toDataURL('image/png');
            link.click();
        };
        img.src = url;
    }
    
    showNodeDetails(node) {
        const modal = document.getElementById('node-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        
        title.textContent = `${node.type.toUpperCase()}: ${node.label}`;
        
        let content = '<div class="modal-info-grid">';
        
        // Basic info
        content += `
            <div class="modal-info-item">
                <span class="modal-info-label">Name</span>
                <span class="modal-info-value">${node.label}</span>
            </div>
            <div class="modal-info-item">
                <span class="modal-info-label">Type</span>
                <span class="modal-info-value">${node.type}</span>
            </div>
        `;
        
        // Additional metadata
        if (node.metadata) {
            for (const [key, value] of Object.entries(node.metadata)) {
                if (value && (typeof value !== 'object' || (Array.isArray(value) && value.length > 0))) {
                    const displayValue = Array.isArray(value) ? value.join(', ') : value;
                    content += `
                        <div class="modal-info-item">
                            <span class="modal-info-label">${this.formatLabel(key)}</span>
                            <span class="modal-info-value">${displayValue || '-'}</span>
                        </div>
                    `;
                }
            }
        }
        
        content += '</div>';
        body.innerHTML = content;
        modal.classList.remove('hidden');
    }
    
    formatLabel(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }
    
    // ==================== Detail Tabs ====================
    
    setupTabs() {
        const tabs = document.querySelectorAll('.tab');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                const tabName = tab.dataset.tab;
                this.showTabContent(tabName);
            });
        });
    }
    
    updateDetailTabs(analysis) {
        this.analysisData = analysis;
        this.showTabContent('groups');
    }
    
    showTabContent(tabName) {
        const container = document.getElementById('tab-content');
        
        if (!this.analysisData) {
            container.innerHTML = '<div class="empty-state"><p>No data available</p></div>';
            return;
        }
        
        if (tabName === 'groups') {
            this.renderGroupsTab(container);
        } else if (tabName === 'hbac') {
            this.renderHbacTab(container);
        } else if (tabName === 'sudo') {
            this.renderSudoTab(container);
        }
    }
    
    renderGroupsTab(container) {
        const groups = this.analysisData.direct_groups;
        const nested = this.analysisData.group_hierarchy;
        
        if (groups.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No groups found</p></div>';
            return;
        }
        
        let html = '<table class="detail-table"><thead><tr>';
        html += '<th>Group</th><th>Type</th><th>Parent Groups</th>';
        html += '</tr></thead><tbody>';
        
        groups.forEach(group => {
            const parents = nested
                .filter(n => n.child === group)
                .map(n => n.parent);
            
            html += `<tr>
                <td>${group}</td>
                <td><span class="badge badge-direct">Direct</span></td>
                <td>${parents.length > 0 ? parents.join(', ') : '-'}</td>
            </tr>`;
        });
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }
    
    renderHbacTab(container) {
        const rules = this.analysisData.hbac_rules;
        
        if (rules.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No HBAC rules found</p></div>';
            return;
        }
        
        let html = '<table class="detail-table"><thead><tr>';
        html += '<th>Rule</th><th>Match Type</th><th>Via</th><th>Hosts</th>';
        html += '</tr></thead><tbody>';
        
        rules.forEach(rule => {
            const matchBadge = this.getMatchBadge(rule.match_type);
            const hosts = rule.host_category === 'all' ? 'ALL' : 
                [...rule.hosts, ...rule.hostgroups.map(h => `[${h}]`)].join(', ') || '-';
            
            html += `<tr>
                <td>${rule.name}</td>
                <td>${matchBadge}</td>
                <td>${rule.via_groups.join(', ') || '-'}</td>
                <td>${hosts}</td>
            </tr>`;
        });
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }
    
    renderSudoTab(container) {
        const rules = this.analysisData.sudo_rules;
        
        if (rules.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No sudo rules found</p></div>';
            return;
        }
        
        let html = '<table class="detail-table"><thead><tr>';
        html += '<th>Rule</th><th>Match Type</th><th>Via</th><th>Hosts</th><th>Commands</th>';
        html += '</tr></thead><tbody>';
        
        rules.forEach(rule => {
            const matchBadge = this.getMatchBadge(rule.match_type);
            const hosts = rule.host_category === 'all' ? 'ALL' : 
                [...rule.hosts, ...rule.hostgroups.map(h => `[${h}]`)].join(', ') || '-';
            const commands = rule.commands.cmd_category === 'all' ? 'ALL' :
                [...rule.commands.allow, ...rule.commands.allow_groups.map(g => `[${g}]`)].join(', ') || '-';
            
            html += `<tr>
                <td>${rule.name}</td>
                <td>${matchBadge}</td>
                <td>${rule.via_groups.join(', ') || '-'}</td>
                <td>${hosts}</td>
                <td>${commands}</td>
            </tr>`;
        });
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }
    
    getMatchBadge(matchType) {
        if (matchType === 'direct') {
            return '<span class="badge badge-direct">Direct</span>';
        } else if (matchType === 'via_group') {
            return '<span class="badge badge-via-group">Via Group</span>';
        } else if (matchType === 'all_users') {
            return '<span class="badge badge-all">All Users</span>';
        }
        return matchType;
    }
    
    // ==================== Compare Users ====================
    
    setupCompare() {
        const user1Input = document.getElementById('compare-user1');
        const user2Input = document.getElementById('compare-user2');
        const suggestions1 = document.getElementById('suggestions-user1');
        const suggestions2 = document.getElementById('suggestions-user2');
        
        this.setupAutocomplete(user1Input, suggestions1, this.users, 'uid', 'cn');
        this.setupAutocomplete(user2Input, suggestions2, this.users, 'uid', 'cn');
        
        document.getElementById('btn-compare').addEventListener('click', () => {
            this.compareUsers(user1Input.value.trim(), user2Input.value.trim());
        });
    }
    
    async compareUsers(user1, user2) {
        if (!user1 || !user2) return;
        
        const container = document.getElementById('compare-results');
        container.classList.remove('hidden');
        
        try {
            const response = await fetch(`/api/compare?user1=${user1}&user2=${user2}`);
            const data = await response.json();
            
            if (data.error) {
                container.innerHTML = `<div class="empty-state"><p>${data.error}</p></div>`;
                return;
            }
            
            this.renderCompareResults(container, data);
            
        } catch (error) {
            console.error('Comparison failed:', error);
            container.innerHTML = '<div class="empty-state"><p>Comparison failed</p></div>';
        }
    }
    
    renderCompareResults(container, data) {
        const sections = [
            { key: 'groups', title: 'Groups' },
            { key: 'hbac_rules', title: 'HBAC Rules' },
            { key: 'sudo_rules', title: 'Sudo Rules' }
        ];
        
        let html = '';
        
        sections.forEach(section => {
            const sectionData = data[section.key];
            
            html += `
                <div class="compare-section">
                    <div class="compare-section-header">${section.title}</div>
                    <div class="compare-grid">
                        <div class="compare-column only-user1">
                            <h4>Only ${data.user1.uid}</h4>
                            <div class="compare-list">
                                ${sectionData.only_user1.length > 0 
                                    ? sectionData.only_user1.map(item => `<div class="compare-item">${item}</div>`).join('')
                                    : '<div class="compare-empty">None</div>'
                                }
                            </div>
                        </div>
                        <div class="compare-column common">
                            <h4>Common</h4>
                            <div class="compare-list">
                                ${sectionData.common.length > 0 
                                    ? sectionData.common.map(item => `<div class="compare-item">${item}</div>`).join('')
                                    : '<div class="compare-empty">None</div>'
                                }
                            </div>
                        </div>
                        <div class="compare-column only-user2">
                            <h4>Only ${data.user2.uid}</h4>
                            <div class="compare-list">
                                ${sectionData.only_user2.length > 0 
                                    ? sectionData.only_user2.map(item => `<div class="compare-item">${item}</div>`).join('')
                                    : '<div class="compare-empty">None</div>'
                                }
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        container.innerHTML = html;
    }
    
    // ==================== Trace Permission ====================
    
    setupTrace() {
        const userInput = document.getElementById('trace-user');
        const hostInput = document.getElementById('trace-host');
        const userSuggestions = document.getElementById('suggestions-trace');
        const hostSuggestions = document.getElementById('suggestions-host');
        
        this.setupAutocomplete(userInput, userSuggestions, this.users, 'uid', 'cn');
        this.setupAutocomplete(hostInput, hostSuggestions, this.hosts, 'fqdn', 'description');
        
        document.getElementById('btn-trace').addEventListener('click', () => {
            this.tracePermission(userInput.value.trim(), hostInput.value.trim());
        });
    }
    
    async tracePermission(username, hostname) {
        if (!username) return;
        
        const container = document.getElementById('trace-results');
        container.classList.remove('hidden');
        
        try {
            let url = `/api/user/${username}/trace-sudo`;
            if (hostname) {
                url += `?host=${hostname}`;
            }
            
            const response = await fetch(url);
            const traces = await response.json();
            
            if (traces.length === 0) {
                container.innerHTML = '<div class="empty-state"><p>No sudo rules found for this user' + 
                    (hostname ? ` on ${hostname}` : '') + '</p></div>';
                return;
            }
            
            this.renderTraceResults(container, traces);
            
        } catch (error) {
            console.error('Trace failed:', error);
            container.innerHTML = '<div class="empty-state"><p>Trace failed</p></div>';
        }
    }
    
    renderTraceResults(container, traces) {
        let html = '';
        
        traces.forEach(trace => {
            html += `
                <div class="trace-card">
                    <div class="trace-card-header">
                        <div class="trace-rule-name">
                            <span class="type-badge sudo">SUDO</span>
                            ${trace.rule}
                        </div>
                        ${this.getMatchBadge(trace.match_type)}
                    </div>
                    <div class="trace-card-body">
                        <div class="trace-path">
                            <div class="trace-path-label">Permission Path:</div>
                            <div class="path-display">
                                ${trace.path.map((item, i) => `
                                    <span class="path-item">${item.name}</span>
                                    ${i < trace.path.length - 1 ? '<span class="path-arrow">→</span>' : ''}
                                `).join('')}
                                <span class="path-arrow">→</span>
                                <span class="path-item">${trace.rule}</span>
                            </div>
                        </div>
                        <div class="trace-details">
                            <div class="trace-detail-item">
                                <h5>Hosts</h5>
                                <p>${trace.hosts.join(', ') || 'ALL'}</p>
                            </div>
                            <div class="trace-detail-item">
                                <h5>Commands</h5>
                                <p>${trace.commands.cmd_category === 'all' ? 'ALL' : 
                                    (trace.commands.allow.join(', ') || 'Specified commands')}</p>
                            </div>
                            <div class="trace-detail-item">
                                <h5>Run As</h5>
                                <p>${trace.runas.user_category === 'all' ? 'ANY USER' : 
                                    (trace.runas.users.join(', ') || 'root')}</p>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        container.innerHTML = html;
    }
    
    // ==================== Browse Rules ====================
    
    setupBrowse() {
        const tabs = document.querySelectorAll('.browse-tab');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                const browseType = tab.dataset.browse;
                this.loadBrowseContent(browseType);
            });
        });
        
        // Load initial content
        this.loadBrowseContent('hbac');
    }
    
    async loadBrowseContent(type) {
        const container = document.getElementById('browse-content');
        
        try {
            let url;
            if (type === 'hbac') {
                url = '/api/hbac-rules';
            } else if (type === 'sudo') {
                url = '/api/sudo-rules';
            } else {
                url = '/api/groups';
            }
            
            const response = await fetch(url);
            const data = await response.json();
            
            this.renderBrowseContent(container, data, type);
            
        } catch (error) {
            console.error('Browse load failed:', error);
            container.innerHTML = '<div class="empty-state"><p>Failed to load data</p></div>';
        }
    }
    
    renderBrowseContent(container, data, type) {
        if (!data || data.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No items found</p></div>';
            return;
        }
        
        let html = '<div class="browse-list">';
        
        if (type === 'hbac' || type === 'sudo') {
            data.forEach(rule => {
                const name = rule.cn ? rule.cn[0] : rule.cn;
                const enabled = (rule.ipaenabledflag && rule.ipaenabledflag[0] === 'TRUE');
                const desc = rule.description ? rule.description[0] : '';
                
                html += `
                    <div class="browse-item">
                        <div class="browse-item-header">
                            <span class="browse-item-name">${name}</span>
                            <span class="browse-item-status ${enabled ? 'enabled' : 'disabled'}">
                                ${enabled ? 'Enabled' : 'Disabled'}
                            </span>
                        </div>
                        <div class="browse-item-desc">${desc || 'No description'}</div>
                    </div>
                `;
            });
        } else {
            data.forEach(group => {
                html += `
                    <div class="browse-item">
                        <div class="browse-item-header">
                            <span class="browse-item-name">${group.cn}</span>
                        </div>
                        <div class="browse-item-desc">${group.description || 'No description'}</div>
                    </div>
                `;
            });
        }
        
        html += '</div>';
        container.innerHTML = html;
    }
    
    // ==================== Modal ====================
    
    setupModal() {
        const modal = document.getElementById('node-modal');
        const backdrop = modal.querySelector('.modal-backdrop');
        const closeBtn = modal.querySelector('.modal-close');
        
        backdrop.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
        
        closeBtn.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                modal.classList.add('hidden');
            }
        });
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new IDMAnalyzerApp();
});
