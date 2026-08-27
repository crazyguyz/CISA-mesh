/**
 * GIAM-SAT v4.4: Asset Management Frontend
 * Quản lý danh sách tài sản (máy tính, màn hình) và cảnh báo thay đổi.
 */
var Assets = {
    init: function() {
        document.querySelectorAll('[data-tab-as]').forEach(function(tab) {
            tab.addEventListener('click', function() {
                var tabName = this.getAttribute('data-tab-as');
                document.querySelectorAll('[data-tab-as]').forEach(function(t) { t.classList.remove('active'); });
                this.classList.add('active');
                document.querySelectorAll('.tab-as-content').forEach(function(c) { c.style.display = 'none'; });
                var target = document.getElementById('tabAs' + tabName.charAt(0).toUpperCase() + tabName.slice(1));
                if (target) target.style.display = 'block';
                if (tabName === 'computers') Assets.loadComputers();
                else if (tabName === 'monitors') Assets.loadMonitors();
                else if (tabName === 'printers') Assets.loadPrinters();
                else if (tabName === 'phones') Assets.loadPhones();
                else if (tabName === 'network') Assets.loadNetwork();
                else if (tabName === 'peripheral') Assets.loadPeripheral();
                else if (tabName === 'users') Assets.loadUsers();
                else if (tabName === 'kho') Assets.loadKho();
                else if (tabName === 'changes') Assets.loadChanges();
            });
        });
        Assets.initInvFilters();
        Assets.loadComputers();
        Assets.updateBadges();
        setInterval(Assets.updateBadges, 60000);
    },

    updateBadges: function() {
        fetch('/api/assets/unresolved_count')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var count = data.count || 0;
                var badge = document.getElementById('assetsBadge');
                var changeBadge = document.getElementById('assetChangeBadge');
                if (badge) {
                    badge.textContent = count;
                    badge.style.display = count > 0 ? 'inline' : 'none';
                }
                if (changeBadge) changeBadge.textContent = count;
            })
            .catch(function() {});
    },

    loadComputers: function() {
        var search = document.getElementById('assetComputerSearch');
        var q = search ? search.value.trim() : '';
        var container = document.getElementById('assetComputersTable');
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';

        fetch('/api/assets/computers?search=' + encodeURIComponent(q) + '&limit=200')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var computers = data.computers || [];
                if (computers.length === 0) {
                    container.innerHTML = '<div class="text-center text-muted py-4">' + t('assets.noComputers') + '</div>';
                    return;
                }
                var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                    '<th>' + t('assets.assetId') + '</th><th>' + t('assets.computer') + '</th><th>' + t('assets.user') + '</th><th>Mainboard</th>' +
                    '<th>CPU</th><th>RAM</th><th>' + t('assets.disk') + '</th><th>GPU</th>' +
                    '<th>' + t('assets.monitor') + '</th><th>Online</th><th>' + t('assets.updated') + '</th></tr></thead><tbody>';

                computers.forEach(function(c) {
                    var disks = c.disks_json;
                    if (typeof disks === 'string') { try { disks = JSON.parse(disks); } catch(e) { disks = []; } }
                    var gpus = c.gpu_json;
                    if (typeof gpus === 'string') { try { gpus = JSON.parse(gpus); } catch(e) { gpus = []; } }
                    var monitors = c.monitors_json;
                    if (typeof monitors === 'string') { try { monitors = JSON.parse(monitors); } catch(e) { monitors = []; } }

                    var diskInfo = disks.map(function(d) { return Assets.esc(d.model || '?') + ' (' + Assets.esc(d.size_gb || '?') + 'GB)'; }).join('<br>') || '-';
                    var gpuInfo = gpus.map(function(g) { return Assets.esc(g.name || '?') + ' (' + Assets.esc(g.ram_gb || '?') + 'GB)'; }).join('<br>') || '-';
                    var monitorInfo = monitors.map(function(m) { return Assets.esc(m.manufacturer || '') + ' ' + Assets.esc(m.name || ''); }).join('<br>') || '-';

                    var mbInfo = Assets.esc(c.motherboard_manufacturer || '') + ' ' + Assets.esc(c.motherboard_product || '');
                    if (!mbInfo.trim()) mbInfo = '-';
                    var displayId = c.display_id || c.asset_id || '-';
                    var onlineDot = c.is_online ? '<span class="online-dot online"></span>' : '<span class="online-dot offline"></span>';
                    var updated = c.updated_at ? c.updated_at.substring(0, 16) : '-';

                    html += '<tr>' +
                        '<td><code style="font-size:11px;font-weight:bold;color:#00d4aa;">' + Assets.esc(displayId) + '</code></td>' +
                        '<td><strong>' + Assets.esc(c.hostname || c.machine_id || '-') + '</strong><br><small class="text-muted">' + Assets.esc(c.os_name || '') + ' ' + Assets.esc(c.os_version || '') + '</small></td>' +
                        '<td><strong>' + Assets.esc(c.user_name || '-') + '</strong><br><small>' + Assets.esc(c.employee_id || '') + '</small></td>' +
                        '<td style="font-size:10px;">' + Assets.esc(mbInfo) + '</td>' +
                        '<td style="font-size:11px;">' + Assets.esc(c.cpu_name || '-') + '<br><small>' + (c.cpu_cores || 0) + ' cores, ' + (c.cpu_max_clock_mhz || 0) + ' MHz</small></td>' +
                        '<td>' + (c.ram_total_gb || 0) + ' GB</td>' +
                        '<td style="font-size:10px;">' + diskInfo + '</td>' +
                        '<td style="font-size:10px;">' + gpuInfo + '</td>' +
                        '<td style="font-size:10px;">' + monitorInfo + '</td>' +
                        '<td>' + onlineDot + '</td>' +
                        '<td><small>' + updated + '</small></td>' +
                        '</tr>';
                });

                html += '</tbody></table>';
                container.innerHTML = html;
            })
            .catch(function(err) {
                container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
            });
    },

    loadMonitors: function() {
        var search = document.getElementById('assetMonitorSearch');
        var q = search ? search.value.trim() : '';
        var container = document.getElementById('assetMonitorsTable');
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';

        fetch('/api/assets/monitors?search=' + encodeURIComponent(q) + '&limit=200')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var monitors = data.monitors || [];
                if (monitors.length === 0) {
                    container.innerHTML = '<div class="text-center text-muted py-4">' + t('assets.noMonitors') + '</div>';
                    return;
                }
                var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                    '<th>' + t('assets.assetId') + '</th><th>' + t('assets.monitorName') + '</th><th>' + t('assets.brand') + '</th><th>' + t('assets.resolution') + '</th>' +
                    '<th>' + t('assets.connectedComputer') + '</th><th>' + t('assets.user') + '</th><th>' + t('assets.updated') + '</th></tr></thead><tbody>';

                monitors.forEach(function(m) {
                    var updated = m.updated_at ? m.updated_at.substring(0, 16) : '-';
                    var displayId = m.display_id || m.asset_id || '-';
                    html += '<tr>' +
                        '<td><code style="font-size:11px;font-weight:bold;color:#00d4aa;">' + displayId + '</code></td>' +
                        '<td><strong>' + Assets.esc(m.name || '-') + '</strong><br><small class="text-muted">' + Assets.esc(m.model_type || 'Monitor') + '</small></td>' +
                        '<td>' + Assets.esc(m.manufacturer || '-') + '</td>' +
                        '<td>' + Assets.esc(m.resolution || '-') + '</td>' +
                        '<td>' + Assets.esc(m.computer_hostname || t('assets.unassigned')) + '</td>' +
                        '<td>' + Assets.esc(m.computer_user || '-') + '</td>' +
                        '<td><small>' + updated + '</small></td>' +
                        '</tr>';
                });

                html += '</tbody></table>';
                container.innerHTML = html;
            })
            .catch(function(err) {
                container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
            });
    },

    loadChanges: function() {
        var unresolvedOnly = document.getElementById('assetUnresolvedOnly');
        var unresolved = unresolvedOnly && unresolvedOnly.checked ? '1' : '0';
        var container = document.getElementById('assetChangesTable');
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';

        fetch('/api/assets/changes?limit=100&unresolved=' + unresolved)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var changes = data.changes || [];
                if (changes.length === 0) {
                    container.innerHTML = '<div class="text-center text-success py-4">' + t('assets.noChanges') + '</div>';
                    return;
                }
                var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                    '<th>' + t('assets.time') + '</th><th>' + t('assets.type') + '</th><th>' + t('assets.object') + '</th><th>' + t('assets.detail') + '</th>' +
                    '<th>' + t('assets.status') + '</th><th>' + t('assets.action') + '</th></tr></thead><tbody>';

                changes.forEach(function(ch) {
                    var details = ch.details;
                    if (typeof details === 'string') { try { details = JSON.parse(details); } catch(e) { details = {}; } }

                    var typeBadge = '';
                    var typeLabel = '';
                    if (ch.change_type === 'hardware_changed') { typeBadge = 'bg-danger'; typeLabel = t('assets.hwChanged'); }
                    else if (ch.change_type === 'monitor_reassigned') { typeBadge = 'bg-warning text-dark'; typeLabel = t('assets.monitorMoved'); }
                    else if (ch.change_type === 'monitor_disconnected') { typeBadge = 'bg-secondary'; typeLabel = t('assets.monitorRemoved'); }
                    else { typeBadge = 'bg-info'; typeLabel = ch.change_type || '-'; }

                    var desc = '';
                    if (ch.change_type === 'hardware_changed') {
                        var parts = [];
                        if (details.cpu_changed) parts.push('CPU: ' + details.cpu_changed);
                        if (details.ram_changed) parts.push('RAM: ' + details.ram_changed);
                        if (details.disks_changed) parts.push(t('assets.diskChanged'));
                        if (details.old_hash) parts.push('Hash: ' + details.old_hash + ' → ' + details.new_hash);
                        desc = parts.join('; ') || t('assets.hwChangedDesc');
                    } else if (ch.change_type === 'monitor_reassigned') {
                        desc = details.monitor + ': ' + details.from_computer + ' → ' + details.to_computer;
                    } else if (ch.change_type === 'monitor_disconnected') {
                        desc = t('assets.disconnected', [details.computer, details.monitor]);
                    }

                    var statusHtml = ch.is_resolved ? '<span class="badge bg-success">' + t('assets.resolved') + '</span>' : '<span class="badge bg-danger">' + t('assets.unresolved') + '</span>';
                    var actionHtml = ch.is_resolved ? '<small class="text-muted">' + (ch.resolved_by || '') + '</small>' : '<button class="btn btn-sm btn-success py-0 px-1" onclick="Assets.resolveChange(' + ch.id + ')">' + t('assets.confirm') + '</button>';

                    html += '<tr>' +
                        '<td><small>' + (ch.created_at || '').substring(0, 16) + '</small></td>' +
                        '<td><span class="badge ' + typeBadge + '">' + typeLabel + '</span></td>' +
                        '<td><code style="font-size:10px;">' + Assets.esc(ch.asset_id || '-') + '</code><br><small>' + Assets.esc(ch.asset_type || '') + '</small></td>' +
                        '<td style="font-size:11px;">' + Assets.esc(desc) + '</td>' +
                        '<td>' + statusHtml + '</td>' +
                        '<td>' + actionHtml + '</td>' +
                        '</tr>';
                });

                html += '</tbody></table>';
                container.innerHTML = html;

                var unresolvedC = changes.filter(function(c) { return !c.is_resolved; }).length;
                var badge = document.getElementById('assetsBadge');
                if (badge) { badge.textContent = unresolvedC; badge.style.display = unresolvedC > 0 ? 'inline' : 'none'; }
                var changeBadge = document.getElementById('assetChangeBadge');
                if (changeBadge) changeBadge.textContent = unresolvedC;
            })
            .catch(function(err) {
                container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
            });
    },

    resolveChange: function(changeId) {
        if (!confirm(t('assets.confirmResolve'))) return;
        fetch('/api/assets/changes/' + changeId + '/resolve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ resolved_by: 'admin' })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                Assets.loadChanges();
                Assets.updateBadges();
                if (typeof showToast === 'function') showToast(t('assets.resolvedToast'));
            }
        });
    },

    exportExcel: function() {
        window.open('/api/assets/export', '_blank');
        if (typeof showToast === 'function') showToast(t('assets.downloading'));
    },

    // =========================================================================
    // v4.7: IT asset inventory (Kho + auto-discovered)
    // =========================================================================
    CATALOG: [
        { v: 'printer', k: 'assets.catPrinter' },
        { v: 'phone', k: 'assets.catPhone' },
        { v: 'network_device', k: 'assets.catNetwork' },
        { v: 'peripheral', k: 'assets.catPeripheral' },
        { v: 'component', k: 'assets.catComponent' },
        { v: 'user', k: 'assets.catUser' },
        { v: 'other', k: 'assets.catOther' }
    ],
    STATUSES: [
        { v: 'in_stock', k: 'assets.stInStock' },
        { v: 'online', k: 'assets.stOnline' },
        { v: 'assigned', k: 'assets.stAssigned' },
        { v: 'in_repair', k: 'assets.stRepair' },
        { v: 'disposed', k: 'assets.stDisposed' },
        { v: 'active', k: 'assets.stActive' }
    ],
    _catLbl: function(v) { for (var i = 0; i < Assets.CATALOG.length; i++) { if (Assets.CATALOG[i].v === v) return t(Assets.CATALOG[i].k); } return v; },
    _stLbl: function(v) { for (var i = 0; i < Assets.STATUSES.length; i++) { if (Assets.STATUSES[i].v === v) return t(Assets.STATUSES[i].k); } return v; },
    _stCls: function(v) {
        return (v === 'in_stock' || v === 'active' || v === 'online') ? 'bg-success' : (v === 'assigned') ? 'bg-info' :
               (v === 'in_repair') ? 'bg-warning text-dark' : 'bg-secondary';
    },

    initInvFilters: function() {
        var catSel = document.getElementById('assetKhoCat');
        if (catSel && !catSel.options.length) {
            var h = '<option value="">' + t('assets.allCategories') + '</option>';
            Assets.CATALOG.forEach(function(c) { h += '<option value="' + c.v + '">' + t(c.k) + '</option>'; });
            catSel.innerHTML = h;
        }
        var stSel = document.getElementById('assetKhoStatus');
        if (stSel && !stSel.options.length) {
            var h2 = '<option value="">' + t('assets.allStatus') + '</option>';
            Assets.STATUSES.forEach(function(s) { h2 += '<option value="' + s.v + '">' + t(s.k) + '</option>'; });
            stSel.innerHTML = h2;
        }
        var fCat = document.getElementById('invCategory');
        if (fCat && !fCat.options.length) {
            Assets.CATALOG.forEach(function(c) {
                if (c.v === 'user') return; // users are added via the Người dùng tab, not via kho assets
                fCat.innerHTML += '<option value="' + c.v + '">' + t(c.k) + '</option>';
            });
        }
        var fSt = document.getElementById('invStatus');
        if (fSt && !fSt.options.length) {
            Assets.STATUSES.forEach(function(s) { fSt.innerHTML += '<option value="' + s.v + '">' + t(s.k) + '</option>'; });
        }
    },

    searchOf: function(id) { var el = document.getElementById(id); return el ? el.value.trim() : ''; },

    _loadInv: function(opts) {
        var container = document.getElementById(opts.container);
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';
        var url = '/api/assets/inventory?limit=500';
        if (opts.category) url += '&category=' + encodeURIComponent(opts.category);
        if (opts.status) url += '&status=' + encodeURIComponent(opts.status);
        if (opts.search) url += '&search=' + encodeURIComponent(opts.search);
        fetch(url).then(function(r) { return r.json(); }).then(function(data) {
            var items = data.assets || [];
            if (opts.preFilter) { items = items.filter(opts.preFilter); }
            if (!items.length) {
                container.innerHTML = '<div class="text-center text-muted py-4">' + t('assets.noInventory') + '</div>';
                return;
            }
            var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                '<th>' + t('assets.assetId') + '</th><th>' + t('assets.type') + '</th><th>' + t('assets.fieldName') + '</th>' +
                '<th>' + t('assets.fieldBrand') + '</th><th>' + t('assets.fieldModel') + '</th><th>' + t('assets.fieldSerial') + '</th>' +
                '<th>' + t('assets.status') + '</th><th>' + t('assets.colQty') + '</th><th>' + t('assets.fieldAssignedTo') + '</th><th>' + t('assets.fieldIp') + '</th><th>' + t('assets.colSrc') + '</th><th></th></tr></thead><tbody>';
            items.forEach(function(a) {
                var catLbl = Assets._catLbl(a.category);
                var stLbl = Assets._stLbl(a.status);
                var stCls = Assets._stCls(a.status);
                var srcBadge = a.source === 'auto'
                    ? '<span class="badge bg-primary">' + t('assets.sourceAuto') + '</span>'
                    : '<span class="badge bg-secondary">' + t('assets.sourceManual') + '</span>';
                var modelTxt = a.model || (a.name ? '' : '-');
                var assigned = a.assigned_to || (a.computer_asset_id ? 'PC' : '') || '-';
                var actions = '';
                if (opts.showActions) {
                    actions = '<button class="btn btn-sm py-0 px-1 me-1" style="background:none;border:none;color:#6ea8dc;font-size:11px;" onclick="Assets.editAsset(\'' + a.asset_id + '\')">✏️</button>' +
                        '<button class="btn btn-sm py-0 px-1" style="background:none;border:none;color:#e0836a;font-size:11px;" onclick="Assets.deleteAsset(\'' + a.asset_id + '\')">🗑</button>';
                    if (a.source === 'auto') {
                        actions = '<button class="btn btn-sm btn-success py-0 px-1 ms-1" onclick="Assets.adoptAsset(\'' + a.asset_id + '\')">' + t('assets.adopt') + '</button>' + actions;
                    }
                }
                html += '<tr><td><code style="font-size:10px;">' + Assets.esc(a.display_id || a.asset_id) + '</code></td>' +
                    '<td><span class="badge bg-dark">' + Assets.esc(catLbl) + '</span></td>' +
                    '<td>' + Assets.esc(a.name || modelTxt) + '</td>' +
                    '<td>' + Assets.esc(a.brand || '-') + '</td>' +
                    '<td>' + Assets.esc(modelTxt) + '</td>' +
                    '<td>' + Assets.esc(a.serial_number || '-') + '</td>' +
                    '<td><span class="badge ' + stCls + '">' + Assets.esc(stLbl) + '</span></td>' +
                    '<td>' + Assets.esc(a.quantity || 1) + '</td>' +
                    '<td>' + Assets.esc(assigned) + '</td>' +
                    '<td>' + Assets.esc(a.ip_address || '-') + '</td>' +
                    '<td>' + srcBadge + '</td>' +
                    '<td>' + actions + '</td></tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;
        }).catch(function(err) {
            container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
        });
    },

    loadPrinters: function() { Assets._loadInv({ category: 'printer', search: Assets.searchOf('assetPrinterSearch'), container: 'assetPrintersTable', showActions: true }); },
    loadPhones: function() { Assets._loadInv({ category: 'phone', search: Assets.searchOf('assetPhoneSearch'), container: 'assetPhonesTable', showActions: true }); },
    loadNetwork: function() { Assets._loadInv({ category: 'network_device', search: Assets.searchOf('assetNetworkSearch'), container: 'assetNetworkTable', showActions: true }); },
    loadPeripheral: function() { Assets._loadInv({ category: 'peripheral', search: Assets.searchOf('assetPeripheralSearch'), container: 'assetPeripheralTable', showActions: true }); },
    loadKho: function() {
        Assets._loadInv({
            search: Assets.searchOf('assetKhoSearch'),
            category: document.getElementById('assetKhoCat') ? document.getElementById('assetKhoCat').value : '',
            status: document.getElementById('assetKhoStatus') ? document.getElementById('assetKhoStatus').value : '',
            container: 'assetKhoTable', showActions: true,
            // Kho = chi tai san vat ly dang luu kho / cho cap phat.
            // Loai bo: nguoi dung (user), tai san dang hoat dong (online/active = thiet bi tu phat hien dang dung).
            preFilter: function(a) {
                if (a.category === 'user') return false;
                if (a.status === 'online' || a.status === 'active') return false;
                return true;
            }
        });
    },

    esc: function(s) {
        if (!s) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(s));
        return div.innerHTML;
    },

    loadUsers: function() {
        var container = document.getElementById('assetUsersTable');
        if (!container) return;
        var q = Assets.searchOf('assetUsersSearch');
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';
        var url = '/api/assets/inventory?category=user&limit=2000';
        if (q) url += '&search=' + encodeURIComponent(q);
        fetch(url).then(function(r) { return r.json(); }).then(function(data) {
            var items = data.assets || [];
            if (!items.length) {
                container.innerHTML = '<div class="text-center text-muted py-4">' + t('assets.noInventory') + '</div>';
                return;
            }
            var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                '<th>' + t('assets.fullName') + '</th><th>' + t('assets.employeeId') + '</th>' +
                '<th>' + t('assets.email') + '</th><th>' + t('assets.internalAccount') + '</th>' +
                '<th>' + t('assets.office') + '</th><th>' + t('assets.status') + '</th><th>' + t('assets.colSrc') + '</th><th></th></tr></thead><tbody>';
            items.forEach(function(a) {
                var email = a.email || '';
                var internal = email.split('@')[0] || '-';
                var srcBadge = a.source === 'auto'
                    ? '<span class="badge bg-primary">' + t('assets.sourceAuto') + '</span>'
                    : '<span class="badge bg-secondary">' + t('assets.sourceManual') + '</span>';
                var stLbl = Assets._stLbl(a.status);
                var stCls = Assets._stCls(a.status);
                html += '<tr>' +
                    '<td>' + Assets.esc(a.name || '-') + '</td>' +
                    '<td>' + Assets.esc(a.employee_id || '-') + '</td>' +
                    '<td>' + Assets.esc(email || '-') + '</td>' +
                    '<td><code>' + Assets.esc(internal) + '</code></td>' +
                    '<td>' + Assets.esc(a.location || '-') + '</td>' +
                    '<td><span class="badge ' + stCls + '">' + Assets.esc(stLbl) + '</span></td>' +
                    '<td>' + srcBadge + '</td>' +
                    '<td><button class="btn btn-sm py-0 px-1 me-1" style="background:none;border:none;color:#6ea8dc;font-size:11px;" onclick="Assets.editUser(\'' + a.asset_id + '\')">✏️</button>' +
                    '<button class="btn btn-sm py-0 px-1" style="background:none;border:none;color:#e0836a;font-size:11px;" onclick="Assets.deleteUser(\'' + a.asset_id + '\')">🗑</button></td></tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;
        }).catch(function(err) {
            container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
        });
    },

    syncUsers: function() {
        fetch('/api/assets/users/sync', { method: 'POST' })
            .then(function(r) { return r.json(); }).then(function(d) {
                if (d.success && typeof showToast === 'function') showToast(t('assets.syncedUsers', [d.created || 0]));
                Assets.loadUsers();
            }).catch(function(err) { if (typeof showToast === 'function') showToast(t('assets.loadErr', [err])); });
    },

    openUserForm: function(a) {
        var modal = document.getElementById('userModal');
        if (!modal) return;
        document.getElementById('userModalTitle').textContent = a ? t('assets.editUser') : t('assets.addUser');
        document.getElementById('userAssetId').value = a ? (a.asset_id || '') : '';
        document.getElementById('userName').value = a ? (a.name || '') : '';
        document.getElementById('userEmployeeId').value = a ? (a.employee_id || '') : '';
        document.getElementById('userEmail').value = a ? (a.email || '') : '';
        document.getElementById('userOffice').value = a ? (a.location || '') : '';
        modal.style.display = 'block';
    },
    closeUserForm: function() { var m = document.getElementById('userModal'); if (m) m.style.display = 'none'; },
    editUser: function(id) {
        fetch('/api/assets/inventory?category=user&limit=2000').then(function(r){return r.json();}).then(function(d){
            var found = null; (d.assets||[]).forEach(function(a){ if(a.asset_id===id) found=a; });
            if (found) Assets.openUserForm(found);
        });
    },
    deleteUser: function(id) {
        if (!confirm(t('assets.confirmDelete'))) return;
        fetch('/api/assets/inventory/' + encodeURIComponent(id), { method: 'DELETE' })
            .then(function(r){return r.json();}).then(function(){ Assets.loadUsers(); });
    },
    saveUser: function() {
        var el = function(id){ return document.getElementById(id); };
        var email = el('userEmail').value.trim();
        var payload = {
            category: 'user', status: 'active',
            name: el('userName').value.trim(),
            employee_id: el('userEmployeeId').value.trim(),
            email: email,
            location: el('userOffice').value.trim(),
            source: 'manual'
        };
        var id = el('userAssetId').value;
        var url = '/api/assets/inventory' + (id ? '/' + encodeURIComponent(id) : '');
        var method = id ? 'PUT' : 'POST';
        fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
            .then(function(r){return r.json();}).then(function(){
                if (typeof showToast === 'function') showToast(t('assets.savedToast'));
                Assets.closeUserForm();
                Assets.loadUsers();
            }).catch(function(err){ if (typeof showToast === 'function') showToast(t('assets.loadErr',[err])); });
    },

    openForm: function(asset) {
        Assets.initInvFilters();
        var modal = document.getElementById('invModal');
        if (!modal) return;
        document.getElementById('invModalTitle').textContent = asset ? t('assets.editTitle') : t('assets.addTitle');
        document.getElementById('invAssetId').value = asset ? (asset.asset_id || '') : '';
        document.getElementById('invSource').value = asset ? (asset.source || 'manual') : 'manual';
        document.getElementById('invCategory').value = asset ? (asset.category || 'other') : 'other';
        document.getElementById('invStatus').value = asset ? (asset.status || 'in_stock') : 'in_stock';
        document.getElementById('invName').value = asset ? (asset.name || '') : '';
        document.getElementById('invBrand').value = asset ? (asset.brand || '') : '';
        document.getElementById('invModel').value = asset ? (asset.model || '') : '';
        document.getElementById('invSerial').value = asset ? (asset.serial_number || '') : '';
        document.getElementById('invAssetTag').value = asset ? (asset.asset_tag || '') : '';
        document.getElementById('invAssignedTo').value = asset ? (asset.assigned_to || '') : '';
        document.getElementById('invIp').value = asset ? (asset.ip_address || '') : '';
        document.getElementById('invMac').value = asset ? (asset.mac_address || '') : '';
        document.getElementById('invLocation').value = asset ? (asset.location || '') : '';
        document.getElementById('invPurchaseDate').value = asset ? (asset.purchase_date || '') : '';
        document.getElementById('invWarranty').value = asset ? (asset.warranty_until || '') : '';
        document.getElementById('invCost').value = asset ? (asset.cost || '') : '';
        document.getElementById('invQuantity').value = asset ? (asset.quantity || 1) : 1;
        document.getElementById('invNotes').value = asset ? (asset.notes || '') : '';
        modal.style.display = 'block';
    },
    closeForm: function() { var m = document.getElementById('invModal'); if (m) m.style.display = 'none'; },

    _getObj: function(asset_id) {
        return new Promise(function(resolve) {
            var found = null;
            fetch('/api/assets/inventory?limit=1000').then(function(r) { return r.json(); }).then(function(d) {
                (d.assets || []).forEach(function(a) { if (a.asset_id === asset_id) found = a; });
                resolve(found);
            }).catch(function() { resolve(null); });
        });
    },
    editAsset: function(id) { Assets._getObj(id).then(function(a) { if (a) Assets.openForm(a); }); },
    deleteAsset: function(id) {
        if (!confirm(t('assets.confirmDelete'))) return;
        fetch('/api/assets/inventory/' + encodeURIComponent(id), { method: 'DELETE' })
            .then(function(r) { return r.json(); }).then(function() {
                if (typeof showToast === 'function') showToast(t('assets.deletedToast'));
                Assets.reloadVisible();
            }).catch(function(err) { if (typeof showToast === 'function') showToast(t('assets.loadErr', [err])); });
    },
    adoptAsset: function(id) {
        if (!confirm(t('assets.adopt'))) return;
        fetch('/api/assets/inventory/' + encodeURIComponent(id) + '/adopt', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
        }).then(function(r) { return r.json(); }).then(function(d) {
            if (typeof showToast === 'function') showToast(t('assets.adoptedToast'));
            Assets.reloadVisible();
        });
    },

    saveForm: function() {
        var el = function(id) { return document.getElementById(id); };
        var payload = {
            category: el('invCategory').value,
            status: el('invStatus').value,
            name: el('invName').value.trim(),
            brand: el('invBrand').value.trim(),
            model: el('invModel').value.trim(),
            serial_number: el('invSerial').value.trim(),
            asset_tag: el('invAssetTag').value.trim(),
            assigned_to: el('invAssignedTo').value.trim(),
            ip_address: el('invIp').value.trim(),
            mac_address: el('invMac').value.trim(),
            location: el('invLocation').value.trim(),
            purchase_date: el('invPurchaseDate').value,
            warranty_until: el('invWarranty').value,
            cost: parseFloat(el('invCost').value) || 0,
            quantity: parseInt(el('invQuantity').value) || 1,
            notes: el('invNotes').value.trim(),
            source: el('invSource').value || 'manual'
        };
        var id = el('invAssetId').value;
        var url = '/api/assets/inventory' + (id ? '/' + encodeURIComponent(id) : '');
        var method = id ? 'PUT' : 'POST';
        fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
            .then(function(r) { return r.json(); }).then(function(d) {
                if (typeof showToast === 'function') showToast(t('assets.savedToast'));
                Assets.closeForm();
                Assets.reloadVisible();
            }).catch(function(err) { if (typeof showToast === 'function') showToast(t('assets.loadErr', [err])); });
    },
    reloadVisible: function() {
        Assets.loadComputers(); Assets.loadMonitors(); Assets.loadChanges();
        Assets.loadPrinters(); Assets.loadPhones(); Assets.loadNetwork();
        Assets.loadPeripheral(); Assets.loadUsers(); Assets.loadKho();
    },

    openDiscover: function() { var m = document.getElementById('discoverModal'); if (m) m.style.display = 'block'; },
    closeDiscover: function() { var m = document.getElementById('discoverModal'); if (m) m.style.display = 'none'; },
    runDiscover: function() {
        var range = document.getElementById('discoverRange') ? document.getElementById('discoverRange').value.trim() : '';
        if (!range) range = '192.168.1.0/24';
        var statusEl = document.getElementById('discoverStatus');
        if (statusEl) statusEl.textContent = t('assets.discoverRun');
        fetch('/api/assets/discovery/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ range: range }) })
            .then(function(r) { return r.json(); }).then(function(d) {
                if (d.error) { if (statusEl) statusEl.textContent = t('assets.discoverErr', [d.error]); return; }
                if (statusEl) statusEl.textContent = t('assets.discovered', [d.found, d.printer, d.phone, d.network_device]);
                Assets.reloadVisible();
            }).catch(function(err) { if (statusEl) statusEl.textContent = t('assets.discoverErr', [err]); });
    },

};

function refreshAssetComputers() { Assets.loadComputers(); }
function refreshAssetMonitors() { Assets.loadMonitors(); }
function refreshAssetChanges() { Assets.loadChanges(); }
function refreshAssetPrinter() { Assets.loadPrinters(); }
function refreshAssetPhone() { Assets.loadPhones(); }
function refreshAssetNetwork() { Assets.loadNetwork(); }
function refreshAssetPeripheral() { Assets.loadPeripheral(); }
function refreshAssetUsers() { Assets.loadUsers(); }
function refreshAssetKho() { Assets.loadKho(); }

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { Assets.init(); });
} else {
    Assets.init();
}