/**
 * GIAM-SAT Dashboard Builder v2.2 - Smart Field Matching
 * Auto-detects compatible widget types, default fields, and data aggregation.
 */
function showDetailModal(title, html) {
    var modalEl = document.getElementById('detailModal');
    var modal = bootstrap.Modal.getInstance(modalEl);
    if (!modal) modal = new bootstrap.Modal(modalEl);
    document.getElementById('detailModalTitle').textContent = title;
    document.getElementById('detailModalBody').innerHTML = html;
    modal.show();
}

// Internal columns to hide from table auto-detect
var HIDDEN_COLUMNS = ['id', 'raw_data', 'received_at', 'machine_id', 'email', 'employee_id', 'user_name', 'is_revoked', 'enrollment_token', 'notes'];

// Default field mappings per source + widget type
var DEFAULT_FIELDS = {
    stats:       { stat: { field: 'total_machines' } },
    machines:    { table: { columns: ['hostname', 'ip_address', 'platform', 'is_online', 'last_seen'] } },
    threats:     { table: { columns: ['hostname', 'rule_name', 'severity', 'description', 'timestamp'] },
                   bar_chart: { label_field: 'severity', value_field: 'severity' },
                   pie_chart: { label_field: 'severity', value_field: 'severity' } },
    events:      { table: { columns: ['hostname', 'subtype', 'event_id', 'description', 'time'] } },
    vulns:       { table: { columns: ['hostname', 'cve', 'severity', 'software', 'description', 'timestamp'] } },
    network:     { table: { columns: ['hostname', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'timestamp'] } },
    sysmon:      { table: { columns: ['hostname', 'sysmon_event_id', 'process_name', 'severity', 'description', 'timestamp'] },
                   bar_chart: { label_field: 'severity', value_field: 'severity' } },
    yara:        { table: { columns: ['hostname', 'rule_name', 'file', 'description', 'timestamp'] } }
};

var DbBuilder = {
    dashboardName: "",
    widgetCounter: 0,
    schema: null,
    chartInstances: {},
    refreshTimers: {},
    widgets: {},

    init: function () {
        try {
            var container = document.getElementById('dashboardBuilderContainer');
            if (!container) { console.error('[DbBuilder] Container not found'); return; }
            this.renderUI(container);
            fetch('/api/custom-dashboard/schema')
                .then(r => r.json())
                .then(d => { this.schema = d; })
                .catch(function(e) { console.error('[DbBuilder] Schema load error:', e); });
        } catch(e) { console.error('[DbBuilder] init error:', e); }
    },

    renderUI: function (container) {
        container.innerHTML = '' +
            '<div class="d-flex justify-content-between align-items-center mb-3">' +
            '<div>' +
            '<input class="search-box me-2" id="dbDashName" placeholder="' + t('db.dashName') + '" style="width:250px;" value="' + (this.dashboardName || '') + '">' +
            '<button class="btn btn-sm btn-success me-1" onclick="DbBuilder.save()"><i class="bi bi-check-lg"></i> ' + t('db.save') + '</button>' +
            '<button class="btn btn-sm btn-outline-info me-1" onclick="DbBuilder.loadList()"><i class="bi bi-folder2-open"></i> ' + t('db.open') + '</button>' +
            '<button class="btn btn-sm btn-outline-warning me-1" onclick="DbBuilder.addWidgetDialog()"><i class="bi bi-plus-circle"></i> ' + t('db.addWidget') + '</button>' +
            '<button class="btn btn-sm btn-outline-secondary" onclick="DbBuilder.clearAll()"><i class="bi bi-eraser"></i> ' + t('db.clearAll') + '</button>' +
            '</div>' +
            '<div><small class="text-muted" id="dbStatus"></small></div>' +
            '</div>' +
            '<div id="widgetGrid" style="display:grid;grid-template-columns:repeat(12,1fr);gap:12px;"></div>';
    },

    // ==== ADD WIDGET DIALOG ====
    addWidgetDialog: function () {
        if (!this.schema) { alert(t('db.loadingRetry')); return; }
        var self = this;

        var html = '';
        html += '<div class="mb-2"><label class="text-muted" style="font-size:11px;">' + t('db.dataSource') + '</label><select class="form-select form-select-sm" id="wizSource" onchange="DbBuilder._onSrcChange()" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);">';
        this.schema.sources.forEach(function (s) {
            html += '<option value="' + s.id + '">' + s.label + '</option>';
        });
        html += '</select></div>';

        // Loại widget - sẽ được fill động sau _onSrcChange
        html += '<div class="mb-2"><label class="text-muted" style="font-size:11px;">' + t('db.widgetType') + '</label><select class="form-select form-select-sm" id="wizType" onchange="DbBuilder._onTypeChange()" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);"></select></div>';

        html += '<div class="mb-2" id="wizFieldDiv"><label class="text-muted" style="font-size:11px;">' + t('db.dataField') + '</label><select class="form-select form-select-sm" id="wizField" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);"></select></div>';
        html += '<div class="mb-2" id="wizColsDiv" style="display:none;"><label class="text-muted" style="font-size:11px;">' + t('db.displayCols') + '</label><select class="form-select form-select-sm" id="wizCols" multiple style="height:100px;background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);"></select></div>';
        html += '<div class="mb-2" id="wizLabelDiv" style="display:none;"><label class="text-muted" style="font-size:11px;">' + t('db.labelField') + '</label><select class="form-select form-select-sm" id="wizLabel" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);"></select></div>';
        html += '<div class="mb-2" id="wizValueDiv" style="display:none;"><label class="text-muted" style="font-size:11px;">' + t('db.valueField') + '</label><select class="form-select form-select-sm" id="wizValue" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);"></select></div>';

        html += '<div class="mb-2"><label class="text-muted" style="font-size:11px;">' + t('db.title') + '</label><input class="search-box" id="wizTitle" placeholder="' + t('db.widgetTitle') + '" style="width:100%;"></div>';
        html += '<div class="mb-2"><label class="text-muted" style="font-size:11px;">' + t('db.width') + '</label><input class="search-box" id="wizWidth" type="number" value="3" min="1" max="12" style="width:80px;"></div>';
        html += '<div class="mb-2"><label class="text-muted" style="font-size:11px;">' + t('db.refresh') + '</label><input class="search-box" id="wizRefresh" type="number" value="60" min="0" style="width:80px;"></div>';
        html += '<button class="btn btn-sm btn-success" onclick="DbBuilder._addWidget()"><i class="bi bi-plus-circle"></i> ' + t('db.add') + '</button>';

        showDetailModal(t('db.addWidgetTitle'), html);
        setTimeout(function () { self._onSrcChange(); }, 50);
    },

    _getSource: function () {
        var sid = document.getElementById('wizSource')?.value;
        if (!this.schema) return null;
        return this.schema.sources.find(s => s.id === sid) || null;
    },

    _getAllowedTypes: function (src) {
        if (!src || !src.widget_types) return ['stat', 'table', 'bar_chart', 'line_chart', 'pie_chart'];
        return src.widget_types;
    },

    _onSrcChange: function () {
        var src = this._getSource();
        if (!src) return;

        // Fill field dropdowns
        var opts = src.fields.map(function (f) {
            return '<option value="' + escapeHtml(f.name) + '">' + escapeHtml(f.label) + ' (' + escapeHtml(f.type) + ')</option>';
        }).join('');
        ['wizField', 'wizCols', 'wizLabel', 'wizValue'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.innerHTML = opts;
        });

        // Fill widget type dropdown - ONLY allowed types
        var allowedTypes = this._getAllowedTypes(src);
        var typeLabels = {
            stat: 'Stat Card', table: 'Data Table', bar_chart: 'Bar Chart',
            line_chart: 'Line Chart', pie_chart: 'Pie Chart'
        };
        var typeOpts = allowedTypes.map(function (t) {
            return '<option value="' + t + '">' + (typeLabels[t] || t) + '</option>';
        }).join('');
        var typeEl = document.getElementById('wizType');
        if (typeEl) typeEl.innerHTML = typeOpts;

        // Set default fields based on type+source
        this._onTypeChange();
    },

    _onTypeChange: function () {
        var t = document.getElementById('wizType')?.value;
        var src = this._getSource();

        // Show/hide field groups
        var isStat = (t === 'stat' || t === 'number');
        var isTable = (t === 'table');
        var isChart = (t === 'bar_chart' || t === 'line_chart' || t === 'pie_chart');

        var fieldDiv = document.getElementById('wizFieldDiv');
        var colsDiv = document.getElementById('wizColsDiv');
        var labelDiv = document.getElementById('wizLabelDiv');
        var valueDiv = document.getElementById('wizValueDiv');

        if (fieldDiv) {
            // Stat on single_object: show field select; on array: hide and auto-count
            if (isStat && src && src.type === 'single_object') {
                fieldDiv.style.display = '';
            } else if (isStat) {
                fieldDiv.style.display = 'none';
                // Auto-set title hint
                var titleEl = document.getElementById('wizTitle');
                if (titleEl && !titleEl.value) titleEl.placeholder = t('db.exampleTotal', [src ? src.label : '', src ? src.endpoint.split('/').pop() : '']);
            } else {
                fieldDiv.style.display = 'none';
            }
        }
        if (colsDiv) colsDiv.style.display = isTable ? '' : 'none';
        if (labelDiv) labelDiv.style.display = isChart ? '' : 'none';
        if (valueDiv) valueDiv.style.display = isChart ? '' : 'none';

        // Set smart defaults
        if (src) {
            var defs = DEFAULT_FIELDS[src.id] || {};
            var typeDefs = defs[t] || defs['stat'] || {};

            // Default columns for table
            if (isTable && typeDefs.columns) {
                var colsEl = document.getElementById('wizCols');
                if (colsEl) {
                    Array.from(colsEl.options).forEach(function (o) {
                        o.selected = typeDefs.columns.indexOf(o.value) >= 0;
                    });
                }
            }

            // Default label/value for chart
            if (isChart) {
                setTimeout(function () {
                    var labelEl = document.getElementById('wizLabel');
                    var valueEl = document.getElementById('wizValue');
                    if (labelEl && typeDefs.label_field && labelEl.querySelector('option[value="' + typeDefs.label_field + '"]')) {
                        labelEl.value = typeDefs.label_field;
                    }
                    if (valueEl && typeDefs.value_field && valueEl.querySelector('option[value="' + typeDefs.value_field + '"]')) {
                        valueEl.value = typeDefs.value_field;
                    }
                }, 10);
            }

            // Default field for stat
            if (isStat && typeDefs.field) {
                setTimeout(function () {
                    var fieldEl = document.getElementById('wizField');
                    if (fieldEl && fieldEl.querySelector('option[value="' + typeDefs.field + '"]')) {
                        fieldEl.value = typeDefs.field;
                    }
                }, 10);
            }
        }
    },

    _addWidget: function () {
        var sid = document.getElementById('wizSource')?.value;
        var type = document.getElementById('wizType')?.value;
        var field = document.getElementById('wizField')?.value;
        var colsSel = document.getElementById('wizCols');
        var cols = colsSel ? Array.from(colsSel.selectedOptions).map(function (o) { return o.value; }) : [];
        var labelF = document.getElementById('wizLabel')?.value;
        var valueF = document.getElementById('wizValue')?.value;
        var title = (document.getElementById('wizTitle')?.value || 'Widget').trim();
        var width = parseInt(document.getElementById('wizWidth')?.value) || 3;
        var refresh = parseInt(document.getElementById('wizRefresh')?.value) || 0;
        var src = this._getSource();
        if (!src) return;

        this.widgetCounter++;
        var wid = 'w_' + this.widgetCounter + '_' + Date.now();
        var config = {
            id: wid,
            source_id: sid,
            source_type: src.type,
            type: type,
            title: title,
            endpoint: src.endpoint,
            field: field,
            columns: cols,
            label_field: labelF,
            value_field: valueF,
            refresh: refresh,
            width: width,
        };
        this.widgets[wid] = config;
        this._renderWidget(wid);
        this._loadData(wid);
        var modal = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
        if (modal) modal.hide();
    },

    // ==== RENDER WIDGET ====
    _renderWidget: function (wid) {
        var cfg = this.widgets[wid];
        if (!cfg) return;
        var grid = document.getElementById('widgetGrid');
        if (!grid) return;
        var existing = document.getElementById(wid);
        if (existing) existing.remove();
        var div = document.createElement('div');
        div.id = wid;
        div.className = 'dashboard-panel';
        div.style.gridColumn = 'span ' + (cfg.width || 3);
        div.innerHTML = '' +
            '<div class="panel-header" style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:rgba(0,0,0,0.2);border-bottom:1px solid #2a3a4a;font-size:12px;font-weight:600;color:#eef4f8;">' +
            '<span>' + escapeHtml(cfg.title || 'Widget') + '</span>' +
            '<div>' +
            '<button class="btn btn-sm btn-outline-info py-0 px-1 me-1" onclick="DbBuilder._loadData(\'' + wid + '\')" style="font-size:9px;" title="Refresh"><i class="bi bi-arrow-repeat"></i></button>' +
            '<button class="btn btn-sm btn-outline-danger py-0 px-1" onclick="DbBuilder.removeWidget(\'' + wid + '\')" style="font-size:9px;" title="' + t('db.remove') + '"><i class="bi bi-x"></i></button>' +
            '</div></div>' +
            '<div class="panel-body" id="' + wid + '_body" style="flex:1;padding:8px;overflow:auto;min-height:60px;">' +
            '<div style="display:flex;align-items:center;justify-content:center;color:#6a8aaa;font-size:12px;height:100%;"><div class="spinner-border spinner-border-sm text-secondary me-2"></div>' + t('common.loading') + '</div>' +
            '</div>';
        grid.appendChild(div);
    },

    // ==== LOAD DATA ====
    _loadData: function (wid) {
        var cfg = this.widgets[wid];
        if (!cfg) return;
        var body = document.getElementById(wid + '_body');
        if (!body) return;
        body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;color:#6a8aaa;font-size:12px;height:100%;"><div class="spinner-border spinner-border-sm text-secondary me-2"></div>' + t('common.loading') + '</div>';
        var url = cfg.endpoint;
        if (['threats', 'events', 'vulns', 'network', 'sysmon', 'yara'].indexOf(cfg.source_id) >= 0) url += '?limit=50';
        fetch(url)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                switch (cfg.type) {
                    case 'stat': case 'number': this._renderStat(wid, data, cfg); break;
                    case 'table': this._renderTable(wid, data, cfg); break;
                    default: this._renderChart(wid, data, cfg); break;
                }
            }.bind(this))
            .catch(function () { if (body) body.innerHTML = '<div class="error-placeholder">' + t('db.loadErr') + '</div>'; });
        if (cfg.refresh > 0) {
            if (this.refreshTimers[wid]) clearInterval(this.refreshTimers[wid]);
            this.refreshTimers[wid] = setInterval(function () { this._loadData(wid); }.bind(this), cfg.refresh * 1000);
        }
    },

    _renderStat: function (wid, data, cfg) {
        var body = document.getElementById(wid + '_body');
        if (!body) return;
        var val;
        if (cfg.source_type === 'single_object') {
            // Single object source (e.g. /api/stats) - extract field
            val = data;
            if (cfg.field) {
                val = (cfg.field || '').split('.').reduce(function (o, k) { return (o != null ? o[k] : null); }, data);
            }
        } else {
            // Array source - show count
            var items = Array.isArray(data) ? data : (data[cfg.field || 'data'] || data.results || [data]);
            if (Array.isArray(items)) {
                val = items.length;
            } else {
                val = 0;
            }
        }
        if (val == null) val = '0';
        if (typeof val === 'number') val = val.toLocaleString();
        body.innerHTML = '<div style="text-align:center;padding:16px;"><div style="font-size:32px;font-weight:700;color:#00d4aa;">' + val + '</div><div style="font-size:11px;color:#c8d8e8;">' + (cfg.title || '') + '</div></div>';
    },

    _renderTable: function (wid, data, cfg) {
        var body = document.getElementById(wid + '_body');
        if (!body) return;
        var items = Array.isArray(data) ? data : (data[cfg.field || 'data'] || data.results || [data]);
        if (!Array.isArray(items) || !items.length) {
            body.innerHTML = '<div style="color:#6a8aaa;font-size:12px;text-align:center;padding:20px;">' + t('db.noData') + '</div>';
            return;
        }
        // Use selected columns or auto-detect (filter internal cols)
        var cols;
        if (cfg.columns && cfg.columns.length > 0) {
            cols = cfg.columns;
        } else {
            cols = Object.keys(items[0] || {}).filter(function (c) { return HIDDEN_COLUMNS.indexOf(c) < 0; });
        }
        var html = '<table class="dashboard-table"><thead><tr>';
        cols.forEach(function (c) { html += '<th>' + c + '</th>'; });
        html += '</tr></thead><tbody>';
        items.slice(0, 20).forEach(function (row) {
            html += '<tr>';
            cols.forEach(function (c) {
                var v = row[c] !== undefined ? row[c] : '';
                if (c === 'is_online') v = (v == 1) ? '<span style="color:#00d4aa;">● Online</span>' : '<span style="color:#ff4444;">● Offline</span>';
                if (typeof v === 'object') v = JSON.stringify(v);
                html += '<td>' + String(v).substring(0, 200) + '</td>';
            });
            html += '</tr>';
        });
        html += '</tbody></table>';
        body.innerHTML = html;
    },

    /** Group array items by a field and count occurrences */
    _groupCount: function (items, field) {
        var counts = {};
        items.forEach(function (item) {
            var key = item[field] || t('db.unknown');
            counts[key] = (counts[key] || 0) + 1;
        });
        // Sort by count descending, but keep severity in logical order
        var keys = Object.keys(counts);
        var sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'FAIL', 'PASS', 'WARN'];
        keys.sort(function (a, b) {
            var ai = sevOrder.indexOf(a), bi = sevOrder.indexOf(b);
            if (ai >= 0 && bi >= 0) return ai - bi;
            if (ai >= 0) return -1;
            if (bi >= 0) return 1;
            return counts[b] - counts[a];
        });
        return { labels: keys, values: keys.map(function (k) { return counts[k]; }) };
    },

    _renderChart: function (wid, data, cfg) {
        var body = document.getElementById(wid + '_body');
        if (!body) return;
        var cid = wid + '_chart';
        if (!body.querySelector('#' + cid)) body.innerHTML = '<div class="dashboard-chart-wrapper" style="min-height:150px;"><canvas id="' + cid + '"></canvas></div>';
        var canvas = document.getElementById(cid);
        if (!canvas || typeof Chart === 'undefined') return;
        var ctx = canvas.getContext('2d');
        if (this.chartInstances[wid]) this.chartInstances[wid].destroy();

        var items = Array.isArray(data) ? data : (data[cfg.field || 'data'] || data.results || [data]);
        if (!Array.isArray(items)) items = [items];
        if (!items.length) { body.innerHTML = '<div style="color:#6a8aaa;font-size:12px;text-align:center;padding:20px;">' + t('db.noData') + '</div>'; return; }

        // Check if value_field is numeric or needs group-count
        var sampleVal = items[0][cfg.value_field];
        var needsGroupCount = !cfg.value_field || (typeof sampleVal !== 'number' && isNaN(Number(sampleVal)));

        var labels, values;
        if (needsGroupCount) {
            // Group by label_field (or value_field if label_field is empty) and count
            var groupField = cfg.label_field || cfg.value_field || Object.keys(items[0])[0];
            var grouped = this._groupCount(items, groupField);
            labels = grouped.labels;
            values = grouped.values;
        } else {
            labels = items.map(function (i) { return i[cfg.label_field || 'name'] || ''; });
            values = items.map(function (i) { return Number(i[cfg.value_field || 'value']) || 0; });
        }

        var cType = cfg.type === 'line_chart' ? 'line' : (cfg.type === 'pie_chart' ? 'doughnut' : 'bar');
        var colors = ["#00d4aa", "#3399ff", "#ffcc66", "#ff6b6b", "#a78bfa", "#34d399", "#60a5fa", "#f472b6", "#fbbf24", "#818cf8", "#ff8844", "#44ddff"];
        var datasets;
        if (cType === 'doughnut') {
            datasets = [{ data: values, backgroundColor: colors.slice(0, values.length), borderColor: '#0f1923', borderWidth: 2 }];
        } else {
            datasets = [{ label: cfg.title || t('db.count'), data: values, backgroundColor: colors[0] + '80', borderColor: colors[0], borderWidth: 2, tension: 0.3, fill: cType === 'line' }];
        }
        this.chartInstances[wid] = new Chart(ctx, {
            type: cType, data: { labels: labels, datasets: datasets },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: cType === 'doughnut', position: 'bottom', labels: { color: '#90a4c4', font: { size: 10 } } } },
                scales: cType === 'doughnut' ? {} : {
                    x: { ticks: { color: '#6a8aaa', font: { size: 10 }, maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#6a8aaa', font: { size: 10 }, precision: 0 }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
                }
            }
        });
    },

    removeWidget: function (wid) {
        if (this.refreshTimers[wid]) clearInterval(this.refreshTimers[wid]);
        if (this.chartInstances[wid]) { this.chartInstances[wid].destroy(); delete this.chartInstances[wid]; }
        delete this.widgets[wid];
        var el = document.getElementById(wid);
        if (el) el.remove();
    },

    clearAll: function (silent) {
        if (!silent && !confirm(t('db.confirmClear'))) return;
        var self = this;
        Object.keys(this.refreshTimers).forEach(function (k) { clearInterval(self.refreshTimers[k]); });
        this.refreshTimers = {};
        Object.keys(this.chartInstances).forEach(function (k) { self.chartInstances[k].destroy(); });
        this.chartInstances = {};
        this.widgets = {};
        var grid = document.getElementById('widgetGrid');
        if (grid) grid.innerHTML = '';
    },

    // ==== SAVE/LOAD ====
    save: function () {
        var name = (document.getElementById('dbDashName')?.value || '').trim();
        if (!name) { alert(t('db.enterName')); return; }
        this.dashboardName = name;
        var layout = [];
        Object.keys(this.widgets).forEach(function (wid) {
            layout.push({ id: wid, width: DbBuilder.widgets[wid].width || 3 });
        });
        fetch('/api/custom-dashboard/save', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, layout: layout, widgets: this.widgets })
        }).then(function (r) { return r.json(); }).then(function () {
            document.getElementById('dbStatus').textContent = t('db.saved', [name]);
        }).catch(function () { document.getElementById('dbStatus').textContent = t('db.error'); });
    },

    loadList: function () {
        var self = this;
        fetch('/api/custom-dashboard/list')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var ds = data.dashboards || [];
                if (!ds.length) { alert(t('db.noDashboards')); return; }
                var list = ds.map(function (d) {
                    return '<div class="p-2 d-flex justify-content-between align-items-center" style="border-bottom:1px solid #2a3a4a;">' +
                        '<span style="cursor:pointer;" onclick="DbBuilder._loadDashboard(\'' + d.name.replace(/'/g, "\\'") + '\')"><strong style="color:#eef4f8;">' + d.name + '</strong> <span style="font-size:10px;color:#6a8aaa;">' + (d.updated_at || '') + '</span></span>' +
                        '<button class="btn btn-sm btn-outline-danger" style="font-size:10px;padding:0 6px;" onclick="DbBuilder._deleteDashboard(\'' + d.name.replace(/'/g, "\\'") + '\')">' + t('btn.delete') + '</button></div>';
                }).join('');
                showDetailModal(t('db.openTitle'), '<div>' + list + '</div>');
            });
    },

    _deleteDashboard: function (name) {
        if (!confirm(t('db.confirmDelete', [name]))) return;
        fetch('/api/custom-dashboard/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name: name})})
            .then(function (r) { return r.json(); })
            .then(function () {
                showToast('✅ ' + t('db.deleted'));
                DbBuilder.loadList();
            })
            .catch(function () { showToast('❌ ' + t('ui.connErrShort')); });
    },

    _loadDashboard: function (name) {
        var self = this;
        fetch('/api/custom-dashboard/load', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name })
        }).then(function (r) { return r.json(); }).then(function (d) {
            if (d.error) { alert(d.error); return; }
            var modal = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
            if (modal) modal.hide();
            self.clearAll(true);
            self.dashboardName = d.name;
            var nameEl = document.getElementById('dbDashName');
            if (nameEl) nameEl.value = d.name;
            self.renderUI(document.getElementById('dashboardBuilderContainer'));
            document.getElementById('dbDashName').value = d.name;
            self.widgets = d.widgets || {};
            Object.keys(self.widgets).forEach(function (wid) { self._renderWidget(wid); });
            setTimeout(function () {
                Object.keys(self.widgets).forEach(function (wid) { self._loadData(wid); });
            }, 200);
            document.getElementById('dbStatus').textContent = t('db.opened', [d.name]);
        }).catch(function () { alert(t('db.loadDashErr')); });
    },
};