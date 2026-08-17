/**
 * GIAM-SAT Group Policies UI v1.0.0 for v3.9.2
 * Tab "Group Policies" trong Groups view.
 * Quan ly chinh sach cho nhom may tram: chan website, chan USB, chan cai phan mem.
 */
(function() {
    var currentGroupId = null;

    function init() {
        // Setup on page load
        window.addEventListener('load', function() {
            setTimeout(setupGroupPoliciesTab, 600);
        });
    }

    function setupGroupPoliciesTab() {
        var groupsTabContainer = document.querySelector('#viewGroups');
        if (!groupsTabContainer) return;
        if (document.getElementById('tabGroupPolicies')) return;

        // Add tab button to the nav
        var tabNav = groupsTabContainer.querySelector('.nav-tabs');
        if (!tabNav) {
            tabNav = document.createElement('ul');
            tabNav.className = 'nav nav-tabs mb-2';
            tabNav.style.cssText = 'border-bottom:1px solid #2a3a4a';
            var existingCard = groupsTabContainer.querySelector('.card');
            if (existingCard) {
                groupsTabContainer.insertBefore(tabNav, existingCard);
            } else {
                groupsTabContainer.insertBefore(tabNav, groupsTabContainer.firstChild);
            }
        }

        var tabItem = document.createElement('li');
        tabItem.className = 'nav-item';
        tabItem.innerHTML = '<a class="nav-link" href="#" onclick="window.showPoliciesTab();return false;" id="tabPoliciesLink"><i class="bi bi-shield-lock"></i> Group Policies</a>';
        tabNav.appendChild(tabItem);

        // Create content panel
        var panel = document.createElement('div');
        panel.id = 'tabGroupPolicies';
        panel.style.display = 'none';
        panel.innerHTML = `
            <div class="card mb-2">
                <div class="card-header d-flex justify-content-between align-items-center" style="background:#13202e;">
                    <span><i class="bi bi-shield-lock"></i> Group Policies</span>
                    <div class="d-flex gap-2">
                        <select class="form-select form-select-sm" id="policiesGroupSelect" onchange="window.onPolicyGroupChange()" style="background:#0f1923;color:#c8d8e8;border:1px solid #2a3a4a;font-size:12px;width:200px;">
                            <option value="">' + t('gp.selectGroup') + '</option>
                        </select>
                        <button class="btn btn-sm btn-primary" onclick="window.addGroupPolicy()" id="btnAddPolicy" disabled>
                            <i class="bi bi-plus-circle"></i> ' + t('gp.addPolicy') + '
                        </button>
                    </div>
                </div>
                <div class="card-body p-2" id="groupPoliciesList">
                    <div class="text-muted text-center py-3">' + t('gp.selectGroupHint') + '</div>
                </div>
            </div>

            <!-- Add/Edit Policy Modal -->
            <div class="modal fade" id="policyModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content" style="background:#13202e;color:#c8d8e8;">
                        <div class="modal-header" style="border-bottom:1px solid #2a3a4a;">
                            <h6 class="modal-title" id="policyModalTitle">' + t('gp.addPolicyTitle') + '</h6>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="policyEditId" value="">
                            <div class="mb-2">
                                <label class="form-label small mb-1">Ten Policy</label>
                                <input class="form-control form-control-sm" id="policyName" placeholder="VD: Chan Facebook" style="background:#0f1923;color:#c8d8e8;border:1px solid #2a3a4a;">
                            </div>
                            <div class="mb-2">
                                <label class="form-label small mb-1">Loai Policy</label>
                                <select class="form-select form-select-sm" id="policyType" style="background:#0f1923;color:#c8d8e8;border:1px solid #2a3a4a;">
                                    <option value="block_usb">Chan USB</option>
                                    <option value="block_websites">Chan Website</option>
                                    <option value="block_software">Chan Cai Phan Mem</option>
                                </select>
                            </div>
                            <div class="mb-2">
                                <label class="form-label small mb-1">' + t('gp.configJson') + '</label>
                                <textarea class="form-control form-control-sm" id="policyConfig" rows="6" style="background:#0f1923;color:#c8d8e8;border:1px solid #2a3a4a;font-family:Consolas,monospace;font-size:11px;"></textarea>
                                <small class="text-muted" id="policyConfigHint"></small>
                            </div>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="policyEnabled" checked>
                                <label class="form-check-label small" for="policyEnabled">Kich hoat</label>
                            </div>
                        </div>
                        <div class="modal-footer" style="border-top:1px solid #2a3a4a;">
                            <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal">Huy</button>
                            <button type="button" class="btn btn-sm btn-primary" onclick="window.savePolicy()">Luu</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        groupsTabContainer.appendChild(panel);

        document.getElementById('policyType').addEventListener('change', updateConfigHint);
        updateConfigHint();

        // Load groups into dropdown
        loadPoliciesGroups();
    }

    function updateConfigHint() {
        var type = document.getElementById('policyType').value;
        var hints = {
            'block_usb': t('gp.blockUsbHint'),
            'block_websites': 'VD: {"domains":["facebook.com","youtube.com","tiktok.com"]}',
            'block_software': 'VD: {"blocked_paths":["%USERPROFILE%\\\\Downloads\\\\*.exe","%TEMP%\\\\*.exe"]}'
        };
        var hintEl = document.getElementById('policyConfigHint');
        if (hintEl) hintEl.textContent = hints[type] || '';
        if (type === 'block_usb') {
            document.getElementById('policyConfig').value = '{}';
        }
    }

    function loadPoliciesGroups() {
        fetch('/api/groups').then(function(r) { return r.json(); }).then(function(data) {
            var groups = data.groups || [];
            var sel = document.getElementById('policiesGroupSelect');
            if (!sel) return;
            var html = '<option value="">' + t('gp.selectGroup') + '</option>';
            groups.forEach(function(g) {
                html += '<option value="' + g.id + '">' + escapeHtml(g.name) + ' (' + (g.members ? g.members.length : 0) + ' may)</option>';
            });
            sel.innerHTML = html;
        });
    }

    window.showPoliciesTab = function() {
        // Hide other tabs
        var allTabs = document.querySelectorAll('#viewGroups > [id^="tab"]');
        allTabs.forEach(function(el) { el.style.display = 'none'; });
        document.querySelectorAll('#viewGroups .nav-link').forEach(function(el) { el.classList.remove('active'); });

        // Show policies tab
        var panel = document.getElementById('tabGroupPolicies');
        if (panel) panel.style.display = 'block';
        var link = document.getElementById('tabPoliciesLink');
        if (link) link.classList.add('active');

        // Refresh group dropdown
        loadPoliciesGroups();
        // If group already selected, reload
        if (currentGroupId) {
            loadGroupPolicies(currentGroupId);
        }
    };

    window.onPolicyGroupChange = function() {
        var sel = document.getElementById('policiesGroupSelect');
        var val = sel ? sel.value : '';
        currentGroupId = val ? parseInt(val) : null;
        var btn = document.getElementById('btnAddPolicy');
        if (btn) btn.disabled = !currentGroupId;
        if (currentGroupId) {
            loadGroupPolicies(currentGroupId);
        } else {
            var el = document.getElementById('groupPoliciesList');
            if (el) el.innerHTML = '<div class="text-muted text-center py-3">' + t('gp.selectGroupHint') + '</div>';
        }
    };

    window.addGroupPolicy = function() {
        if (!currentGroupId) {
            showToast(t('gp.selectGroupFirst'), 'warning');
            return;
        }
        document.getElementById('policyEditId').value = '';
        document.getElementById('policyModalTitle').textContent = t('gp.addPolicyTitle');
        document.getElementById('policyName').value = '';
        document.getElementById('policyType').value = 'block_usb';
        document.getElementById('policyConfig').value = '{}';
        document.getElementById('policyEnabled').checked = true;
        updateConfigHint();
        try {
            var modal = new bootstrap.Modal(document.getElementById('policyModal'));
            modal.show();
        } catch(e) {}
    };

    window.editPolicy = function(policyId) {
        fetch('/api/policies/get/' + policyId).then(function(r) { return r.json(); }).then(function(data) {
            if (!data.success) { showToast(data.error, 'danger'); return; }
            var p = data.policy;
            document.getElementById('policyEditId').value = p.id;
            document.getElementById('policyModalTitle').textContent = 'Sua Policy #' + p.id;
            document.getElementById('policyName').value = p.policy_name || '';
            document.getElementById('policyType').value = p.policy_type;
            document.getElementById('policyConfig').value = JSON.stringify(p.config, null, 2);
            document.getElementById('policyEnabled').checked = p.enabled == 1;
            updateConfigHint();
            try {
                var modal = new bootstrap.Modal(document.getElementById('policyModal'));
                modal.show();
            } catch(e) {}
        }).catch(function() { showToast(t('gp.loadErr'), 'danger'); });
    };

    window.savePolicy = function() {
        var editId = document.getElementById('policyEditId').value;
        var policyName = document.getElementById('policyName').value.trim();
        var policyType = document.getElementById('policyType').value;
        var configStr = document.getElementById('policyConfig').value;
        var enabled = document.getElementById('policyEnabled').checked;

        try {
            var config = JSON.parse(configStr || '{}');
        } catch(e) {
            showToast(t('gp.invalidJson', [e.message]), 'danger');
            return;
        }

        if (!policyName) policyName = policyType + ' - ' + new Date().toLocaleTimeString();

        if (editId) {
            fetch('/api/policies/update/' + editId, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({policy_name: policyName, config: config, enabled: enabled})
            }).then(function(r) { return r.json(); }).then(function(data) {
                if (data.success) {
                    showToast(t('gp.updated'), 'success');
                    try { bootstrap.Modal.getInstance(document.getElementById('policyModal')).hide(); } catch(e) {}
                    loadGroupPolicies(currentGroupId);
                } else { showToast(data.error, 'danger'); }
            });
        } else {
            fetch('/api/policies/add', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    group_id: currentGroupId,
                    policy_type: policyType,
                    policy_name: policyName,
                    config: config
                })
            }).then(function(r) { return r.json(); }).then(function(data) {
                if (data.success) {
                    showToast(t('gp.created'), 'success');
                    try { bootstrap.Modal.getInstance(document.getElementById('policyModal')).hide(); } catch(e) {}
                    loadGroupPolicies(currentGroupId);
                } else { showToast(data.error, 'danger'); }
            });
        }
    };

    window.deletePolicy = function(policyId) {
        if (!confirm(t('gp.confirmDelete'))) return;
        fetch('/api/policies/delete/' + policyId, {method: 'POST'}).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) {
                showToast(t('gp.deleted'), 'success');
                loadGroupPolicies(currentGroupId);
            }
        });
    };

    window.togglePolicy = function(policyId, enabled) {
        fetch('/api/policies/update/' + policyId, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled: enabled})
        }).then(function(r) { return r.json(); }).then(function(data) {
            if (data.success) {
                showToast(enabled ? t('gp.enabled') : t('gp.disabled'), 'success');
                loadGroupPolicies(currentGroupId);
            }
        });
    };

    function loadGroupPolicies(groupId) {
        currentGroupId = groupId;
        var el = document.getElementById('groupPoliciesList');
        if (!el) return;

        el.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-primary"></div> Dang tai...</div>';

        fetch('/api/policies/list?group_id=' + groupId).then(function(r) { return r.json(); }).then(function(data) {
            if (!data.success) { el.innerHTML = '<div class="text-danger p-2">Loi: ' + (data.error || 'Unknown') + '</div>'; return; }
            var policies = data.policies || [];
            if (policies.length === 0) {
                el.innerHTML = '<div class="text-muted text-center py-3">' + t('gp.noPolicies') + '</div>';
                return;
            }
            var typeLabels = {'block_usb': 'Chan USB', 'block_websites': 'Chan Website', 'block_software': 'Chan Phan Mem'};
            var typeIcons = {'block_usb': 'usb-plug', 'block_websites': 'globe2', 'block_software': 'file-earmark-x'};
            var statusBadges = {
                'pending': '<span class="badge bg-warning">cho ap dung</span>',
                'applied': '<span class="badge bg-success">' + t('gp.applied') + '</span>',
                'failed': '<span class="badge bg-danger">' + t('gp.failed') + '</span>'
            };

            var html = '';
            for (var i = 0; i < policies.length; i++) {
                var p = policies[i];
                var cfgPreview = JSON.stringify(p.config || {}).substring(0, 60);
                html += '<div class="card mb-1" style="background:#0f1923;border:1px solid #1e3040;">' +
                    '<div class="card-body p-2">' +
                    '<div class="d-flex justify-content-between align-items-start">' +
                    '<div>' +
                    '<i class="bi bi-' + (typeIcons[p.policy_type] || 'shield') + ' text-primary me-1"></i>' +
                    '<strong>' + escapeHtml(p.policy_name || typeLabels[p.policy_type] || p.policy_type) + '</strong> ' +
                    '<span class="text-muted small">[' + (typeLabels[p.policy_type] || p.policy_type) + ']</span> ' +
                    (statusBadges[p.apply_status] || '<span class="badge bg-secondary">' + (p.apply_status || 'unknown') + '</span>') +
                    '</div>' +
                    '<div class="btn-group btn-group-sm">' +
                    '<button class="btn btn-xs btn-outline-info" onclick="window.editPolicy(' + p.id + ')" title="Sua"><i class="bi bi-pencil"></i></button>' +
                    '<button class="btn btn-xs btn-outline-danger" onclick="window.deletePolicy(' + p.id + ')" title="Xoa"><i class="bi bi-trash"></i></button>' +
                    '</div>' +
                    '</div>' +
                    '<div class="small text-muted mt-1">' + escapeHtml(cfgPreview) + (cfgPreview.length >= 60 ? '...' : '') + '</div>' +
                    '<div class="small text-muted">' + t('gp.updatedAt', [p.updated_at || p.created_at || '-']) + ' | ' +
                    '<a href="#" class="text-decoration-none" onclick="window.togglePolicy(' + p.id + ',' + (p.enabled ? 'false' : 'true') + ');return false;">' +
                    (p.enabled ? '<span class="text-success">' + t('gp.on') + '</span>' : '<span class="text-danger">' + t('gp.off') + '</span>') + '</a>' +
                    '</div>' +
                    '</div></div>';
            }
            el.innerHTML = html;
        }).catch(function(e) {
            el.innerHTML = '<div class="text-danger p-2">' + t('gp.loadPoliciesErr', [e.message]) + '</div>';
        });
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function showToast(msg, type) {
        type = type || 'info';
        var toast = document.createElement('div');
        toast.className = 'alert alert-' + type + ' alert-dismissible fade show position-fixed bottom-0 end-0 m-3';
        toast.style.cssText = 'z-index:9999;max-width:400px;';
        toast.innerHTML = msg + '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
        document.body.appendChild(toast);
        setTimeout(function() { toast.remove(); }, 4000);
    }

    init();
})();