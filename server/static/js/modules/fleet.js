/**
 * GIAM-SAT fleet operations UI - v5.0.8 (Phase C)
 *
 * Renders into #fleetPanel (Log Coverage view): fleet health (silent agents,
 * version drift, log-source coverage), rejected-ingest counters and the rollout
 * wizard (plan -> canary -> advance when healthy -> rollback).
 *
 * Backed by /api/health/fleet, /api/fleet/rollout*, /api/policies/preview.
 */
(function () {
  'use strict';

  var state = { rolloutId: null, plan: null, policyWave: 0 };

  function T(key, fallback) {
    try { return (typeof t === 'function') ? t(key) : (fallback || key); } catch (e) { return fallback || key; }
  }

  function esc(v) {
    if (typeof escapeHtml === 'function') { return escapeHtml(v == null ? '' : String(v)); }
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function el(id) { return document.getElementById(id); }

  function getJson(url) {
    return fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.json(); });
  }

  function postJson(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {})
    }).then(function (r) { return r.json(); });
  }

  function badge(text, cls) {
    return '<span class="badge ' + (cls || 'bg-secondary') + '" style="font-size:9.5px;">' +
      esc(text) + '</span>';
  }

  function toast(msg) {
    if (typeof showToast === 'function') { showToast(msg); }
  }

  var FLAG_CLS = { silent: 'bg-danger', offline: 'bg-secondary', outdated: 'bg-warning text-dark',
                   no_sysmon: 'bg-info text-dark', no_auditpol: 'bg-info text-dark',
                   not_hardened: 'bg-dark' };

  function renderHealth(d) {
    var box = el('fleetHealth');
    if (!box || !d) { return; }
    var s = d.summary || {};
    var html = '<div class="mb-2">' +
      badge((s.machines || 0) + ' máy', 'bg-secondary') + ' ' +
      badge('online ' + (s.online || 0), 'bg-success') + ' ' +
      badge('im lặng ' + (s.silent || 0), s.silent ? 'bg-danger' : 'bg-secondary') + ' ' +
      badge('offline ' + (s.offline || 0), 'bg-secondary') + ' ' +
      badge('cũ ' + (s.outdated || 0), s.outdated ? 'bg-warning text-dark' : 'bg-secondary') + ' ' +
      badge('thiếu Sysmon ' + (s.no_sysmon || 0), 'bg-info text-dark') + '</div>';
    html += '<table class="table table-sm mb-2" style="font-size:11.5px;"><thead><tr>' +
      '<th>Máy</th><th>Phiên bản</th><th>Heartbeat</th><th>Cờ</th></tr></thead><tbody>';
    (d.machines || []).slice(0, 40).forEach(function (m) {
      html += '<tr><td>' + esc(m.hostname) + '</td><td>' + esc(m.version || '?') + '</td>' +
        '<td>' + esc(m.heartbeat_age_min == null ? '-' : m.heartbeat_age_min + "'") + '</td><td>' +
        (m.flags || []).map(function (f) { return badge(f, FLAG_CLS[f]); }).join(' ') +
        '</td></tr>';
    });
    html += '</tbody></table>';

    var ing = d.ingest || {};
    var rows = (ing.persisted || []).concat(ing.pending || []);
    if (rows.length) {
      html += '<div class="mt-2"><b>' + esc(T('fleet.ingest', 'Dữ liệu bị server từ chối')) +
        '</b> <span class="text-muted" style="font-size:10.5px;">' +
        esc(T('fleet.ingestHint', 'PSK sai / máy lạ / loại bản tin lạ - các nguồn này KHÔNG được ghi dữ liệu')) +
        '</span><table class="table table-sm" style="font-size:11.5px;"><thead><tr>' +
        '<th>Nguồn</th><th>Máy</th><th>Lý do</th><th>Loại</th><th>Số lần</th><th>Lần cuối</th>' +
        '<th></th></tr></thead><tbody>';
      rows.forEach(function (r) {
        html += '<tr><td>' + esc(r.source_ip) + '</td><td>' + esc(r.detail || '') + '</td><td>' +
          esc(r.reason) + '</td><td>' + esc(r.msg_type) + '</td><td>' + esc(String(r.count)) +
          '</td><td>' + esc(r.last_seen || '') + '</td><td>' +
          '<button class="btn btn-sm btn-outline-warning" onclick="fleet.ack(\'' +
          esc(r.source_ip) + '\')">' + esc(T('fleet.ack', 'Xử lý')) + '</button></td></tr>';
      });
      html += '</tbody></table></div>';
    }
    box.innerHTML = html;
  }

  function renderPlan(p) {
    if (!p || p.error) { toast((p && p.error) || 'Error'); return; }
    state.plan = p;
    var box = el('fleetPlan');
    if (!box) { return; }
    var html = '<div style="font-size:11.5px;">' +
      badge('đích ' + esc(p.target_version), 'bg-info text-dark') + ' ' +
      badge('cần cập nhật ' + esc(String(p.affected)), 'bg-warning text-dark') + ' ' +
      badge('đã đúng bản ' + esc(String(p.already_current)), 'bg-secondary') +
      (p.offline ? ' ' + badge('offline ' + esc(String(p.offline)), 'bg-danger') : '') + '</div>';
    if (p.warning) {
      html += '<div class="text-warning" style="font-size:11px;">⚠ ' + esc(p.warning) + '</div>';
    }
    html += '<table class="table table-sm mt-1" style="font-size:11.5px;"><thead><tr>' +
      '<th>Đợt</th><th>%</th><th>Số máy</th><th>Máy</th></tr></thead><tbody>';
    (p.waves || []).forEach(function (w) {
      html += '<tr><td>' + esc(String(w.index)) + (w.index === 0 ? ' (canary)' : '') + '</td><td>' +
        esc(String(w.pct)) + '%</td><td>' + esc(String((w.machines || []).length)) + '</td><td>' +
        esc((w.machines || []).slice(0, 8).join(', ')) +
        ((w.machines || []).length > 8 ? ' …' : '') + '</td></tr>';
    });
    html += '</tbody></table>';
    box.innerHTML = html;
  }

  function renderRollout(d) {
    var box = el('fleetRollout');
    if (!box) { return; }
    if (!d || !d.rollout) {
      box.innerHTML = '<div class="text-muted" style="font-size:11.5px;">' +
        esc(T('fleet.noRollout', 'Chưa có đợt triển khai nào')) + '</div>';
      return;
    }
    var r = d.rollout;
    state.rolloutId = r.id;
    var html = '<div style="font-size:11.5px;">' + badge('#' + r.id, 'bg-primary') + ' ' +
      badge('đích ' + esc(r.target_version), 'bg-info text-dark') + ' ' +
      badge('trạng thái ' + esc(r.state), r.state === 'rolled_back' ? 'bg-danger' : 'bg-secondary') +
      ' ' + badge('đợt ' + esc(String(d.current_wave)), 'bg-dark') + '</div>';
    html += '<table class="table table-sm mt-1" style="font-size:11.5px;"><thead><tr>' +
      '<th>Đợt</th><th>Trạng thái</th><th>Cập nhật</th><th>Lỗi</th><th>Chờ</th><th>Điều kiện</th>' +
      '</tr></thead><tbody>';
    (d.waves || []).forEach(function (w) {
      var c = w.counts || {};
      html += '<tr><td>' + esc(String(w.index)) + '</td><td>' +
        badge(w.state, w.state === 'current' ? 'bg-primary'
              : (w.state === 'done' ? 'bg-success' : 'bg-secondary')) + '</td><td>' +
        esc(String(c.updated || 0)) + '/' + esc(String(c.total || 0)) + ' (' +
        esc(String(c.updated_pct || 0)) + '%)</td><td>' + esc(String(c.failed || 0)) +
        '</td><td>' + esc(String((c.pending || 0) + (c.requested || 0))) + '</td><td>' +
        badge(w.healthy ? 'OK' : 'CHẶN', w.healthy ? 'bg-success' : 'bg-danger') +
        ' <span class="text-muted">' + esc(w.reason || '') + '</span></td></tr>';
    });
    html += '</tbody></table><div>' +
      '<button class="btn btn-sm btn-success me-1" onclick="fleet.advance(false)">▶ ' +
      esc(T('fleet.advance', 'Sang đợt tiếp')) + '</button>' +
      '<button class="btn btn-sm btn-outline-warning me-1" onclick="fleet.advance(true)">⏩ ' +
      esc(T('fleet.force', 'Bỏ qua điều kiện')) + '</button>' +
      '<button class="btn btn-sm btn-outline-danger" onclick="fleet.rollback()">⛔ ' +
      esc(T('fleet.rollback', 'Dừng / phục hồi')) + '</button></div>';
    box.innerHTML = html;
  }

  function loadHealth() {
    return getJson('/api/health/fleet').then(renderHealth).catch(function () {});
  }

  function renderStorage(d) {
    var box = el('fleetStorage');
    if (!box || !d) { return; }
    var need = d.partitions_needed || [];
    var html = '<div class="text-muted mb-1" style="font-size:11px;">' +
      esc(T('fleet.storageHint', 'Retention trên bảng lớn = DROP cả tháng (tức thì) thay vì DELETE từng dòng. Rollup giữ số liệu ngày/máy để hỏi dài hạn mà không quét bảng thô.')) +
      '</div><table class="table table-sm mb-1" style="font-size:11.5px;"><thead><tr>' +
      '<th>Bảng</th><th>Dung lượng</th><th>Dòng</th><th>Partition</th></tr></thead><tbody>';
    (d.tables || []).forEach(function (t) {
      html += '<tr><td>' + esc(t.table) + '</td><td>' + esc(t.size) + '</td><td>' +
        esc(String(t.rows)) + '</td><td>' +
        (t.partitioned ? badge(t.partitions + ' tháng', 'bg-success') : badge('chưa', 'bg-secondary')) +
        '</td></tr>';
    });
    html += '</tbody></table>';
    if (need.length) {
      html += '<div class="text-warning" style="font-size:11px;">⚠ ' +
        esc(T('fleet.needPartition', 'Chưa partition')) + ': ' + esc(need.join(', ')) + '<br>' +
        esc(T('fleet.partitionHow', 'Chuyển bằng: python tools/partition_events.py --table <bảng> --apply')) +
        '</div>';
    }
    html += '<div class="mt-1">' +
      '<button class="btn btn-sm btn-outline-info me-1" onclick="fleet.rollup()">' +
      esc(T('fleet.rollup', 'Rollup ngay (daily_stats)')) + '</button>' +
      '<button class="btn btn-sm btn-outline-danger" onclick="fleet.dropOld()">' +
      esc(T('fleet.dropOld', 'Xoá dữ liệu quá hạn (DROP partition)')) + '</button></div>';
    box.innerHTML = html;
  }

  function loadStorage() {
    return getJson('/api/health/storage').then(renderStorage).catch(function () {});
  }

  function rollup() {
    return postJson('/api/health/storage/rollup', { days: 30 }).then(function (d) {
      toast(d && d.ok ? (T('fleet.rollupDone', 'Đã rollup') + ' (' + d.rows_in_table + ' dòng)')
                      : ((d && d.error) || 'Error'));
      loadStorage();
      return d;
    }).catch(function () {});
  }

  function dropOld() {
    if (!window.confirm(T('fleet.dropOldConfirm',
        'Xoá các tháng dữ liệu cũ hơn 30 ngày? Chỉ áp dụng cho bảng ĐÃ partition và không thể hoàn tác.'))) {
      return;
    }
    return postJson('/api/health/storage/drop-old', { retention_days: 30 }).then(function (d) {
      toast(T('fleet.dropDone', 'Đã xoá partition cũ') + ' (' + (((d && d.dropped) || []).length) + ')');
      loadStorage();
      return d;
    }).catch(function () {});
  }

  function renderPolicyPreview(p) {
    if (!p || !p.ok) {
      return '<div class="text-danger" style="font-size:11.5px;">' + esc((p && p.error) || 'Error') +
        '</div>';
    }
    var html = '<div style="font-size:11.5px;">' +
      badge('ảnh hưởng ' + esc(String(p.affected)), 'bg-info text-dark') + ' ' +
      badge('đã áp ' + esc(String((p.applied || []).length)), 'bg-success') + ' ' +
      badge('chờ ' + esc(String((p.pending || []).length)), 'bg-secondary') + ' ' +
      badge('lỗi ' + esc(String((p.failed || []).length)), 'bg-danger') + ' ' +
      badge('offline ' + esc(String((p.offline || []).length)), 'bg-dark') + '</div>';
    (p.warnings || []).forEach(function (w) {
      html += '<div class="text-warning" style="font-size:11px;">⚠ ' + esc(w) + '</div>';
    });
    html += '<div class="text-muted" style="font-size:11px;">' +
      esc(T('fleet.policyWaves', 'Đợt')) + ': ' + (p.waves || []).map(function (w) {
        return esc(String(w.index) + '(' + (w.machines || []).length + ')');
      }).join(' → ') + '</div>';
    return html;
  }

  function renderPolicies(d, preview) {
    var box = el('fleetPolicyList');
    if (!box) { return; }
    var items = (d && (d.policies || d.items)) || [];
    if (!items.length) {
      box.innerHTML = '<div class="text-muted" style="font-size:11.5px;">' +
        esc(T('fleet.noPolicy', 'Chưa có chính sách nhóm nào (tạo ở menu Nhóm & Chính sách).')) + '</div>';
      return;
    }
    var html = '<div class="d-flex flex-wrap gap-1 align-items-center mb-1" style="font-size:11.5px;">' +
      '<select id="fleetPolicy" class="form-select form-select-sm" style="width:auto;font-size:11.5px;">' +
      items.map(function (p) {
        return '<option value="' + esc(String(p.id)) + '">' + esc(p.policy_name || p.policy_type) +
          ' (' + esc(p.policy_type || '') + (p.enabled ? '' : ', TẮT') + ')</option>';
      }).join('') + '</select>' +
      '<button class="btn btn-sm btn-outline-info" onclick="fleet.policyPreview()">' +
      esc(T('fleet.policyPreview', 'Xem trước (không gửi)')) + '</button>' +
      '<button class="btn btn-sm btn-success" onclick="fleet.policyWave(0)">' +
      esc(T('fleet.policyCanary', 'Áp đợt canary')) + '</button>' +
      '<button class="btn btn-sm btn-outline-success" onclick="fleet.policyNext()">' +
      esc(T('fleet.policyNext', 'Sang đợt kế')) + '</button></div>' +
      '<div id="fleetPolicyPreview"></div>';
    box.innerHTML = html;
    if (preview) {
      var holder = el('fleetPolicyPreview');
      if (holder) { holder.innerHTML = renderPolicyPreview(preview); }
    }
  }

  function loadPolicies() {
    return getJson('/api/policies/list').then(function (d) { renderPolicies(d, null); })
      .catch(function () {});
  }

  function policyId() {
    var sel = el('fleetPolicy');
    return sel ? parseInt(sel.value, 10) : null;
  }

  function policyPreview() {
    var id = policyId();
    if (!id) { return; }
    return postJson('/api/policies/preview', { policy_id: id }).then(function (p) {
      var holder = el('fleetPolicyPreview');
      if (holder) { holder.innerHTML = renderPolicyPreview(p); }
      return p;
    }).catch(function () {});
  }

  function policyWave(index) {
    var id = policyId();
    if (!id) { return; }
    return postJson('/api/policies/wave-apply', { policy_id: id, wave_index: index })
      .then(function (d) {
        if (d && d.success) {
          // Remember which wave is open: wave-advance expects the CURRENT index,
          // so a hard-coded 0 would re-offer wave 1 forever.
          state.policyWave = index;
        }
        toast(d && d.success
          ? (T('fleet.policyApplied', 'Đã chào đợt') + ' ' + (d.wave + 1) + ': ' + d.count + ' máy')
          : ((d && d.error) || 'Error'));
        return policyPreview();
      }).catch(function () {});
  }

  function policyNext() {
    var id = policyId();
    if (!id) { return; }
    return postJson('/api/policies/wave-advance',
                    { policy_id: id, wave_index: state.policyWave })
      .then(function (d) {
        if (d && d.success && d.wave != null) { state.policyWave = d.wave; }
        toast(d && d.success
          ? (d.done ? T('fleet.policyDone', 'Đã ở đợt cuối')
                    : T('fleet.advanced', 'Đã sang đợt tiếp'))
          : (T('fleet.blocked', 'Bị chặn: ') + ((d && d.reason) || '')));
        return policyPreview();
      }).catch(function () {});
  }

  function loadRollout(id) {
    return getJson(id ? ('/api/fleet/rollout/' + id) : '/api/fleet/rollouts')
      .then(function (d) {
        if (!id) {
          if (d.items && d.items.length) { return loadRollout(d.items[0].id); }
          return renderRollout(null);
        }
        return renderRollout(d);
      }).catch(function () {});
  }

  function plan() {
    var waves = (el('fleetWaves') || {}).value || '';
    return postJson('/api/fleet/rollout/plan', { waves: waves }).then(renderPlan)
      .catch(function () {});
  }

  function start() {
    var waves = (el('fleetWaves') || {}).value || '';
    var version = (el('fleetTarget') || {}).value || '';
    return postJson('/api/fleet/rollout', { waves: waves, target_version: version })
      .then(function (d) {
        if (d.success) {
          // The canary machine can be offline: the rollout still opens (success)
          // but nobody received the build yet - the operator must be told.
          var failed = (d.canary_failed || []).length;
          toast(T('fleet.started', 'Đã bắt đầu đợt canary') + ' #' + d.id +
                (failed ? ' — ' + failed + ' ' + esc(T('fleet.canaryFailed',
                  'máy đang offline, chưa nhận được bản mới')) : ''));
        } else {
          toast(d.error || 'Error');
        }
        if (d.id) { loadRollout(d.id); }
        return d;
      }).catch(function () {});
  }

  function advance(force) {
    if (!state.rolloutId) { return; }
    return postJson('/api/fleet/rollout/' + state.rolloutId + '/advance', { force: !!force })
      .then(function (d) {
        if (!d) { return d; }
        if (d.success && d.state === 'done') {
          // The API answers {"success":true,"state":"done"} on the LAST wave - say
          // "finished", not "advanced" (the old text lied to the operator).
          toast(d.message || T('fleet.rolloutDone', 'Đã hoàn tất đợt cuối'));
        } else if (d.success) {
          toast(T('fleet.advanced', 'Đã sang đợt tiếp') + ' → ' +
                esc(T('fleet.wave', 'đợt')) + ' ' + ((d.wave || 0) + 1) +
                ' (' + (d.sent || 0) + ' ' + esc(T('fleet.machines', 'máy')) + ')');
        } else {
          toast(T('fleet.blocked', 'Bị chặn: ') + (d.reason || ''));
        }
        loadRollout(state.rolloutId);
        return d;
      }).catch(function () {});
  }

  function ack(sourceIp) {
    return postJson('/api/health/ingest/ack', { source_ip: sourceIp }).then(function (d) {
      var g = (d && d.guide) || {};
      var lines = ['Nguồn: ' + sourceIp]
        .concat((g.hosts || []).length ? ['Máy: ' + (g.hosts || []).join(', ')] : [])
        .concat(['Lý do: ' + (g.reason || '')])
        .concat((g.steps || []).map(function (s, i) { return (i + 1) + '. ' + s; }));
      window.alert(T('fleet.ackTitle', 'Cách khắc phục nguồn bị từ chối') + '\n\n' + lines.join('\n'));
      if (!window.confirm(T('fleet.ackDismiss', 'Đã xử lý xong, ẩn cảnh báo này?'))) { return d; }
      return postJson('/api/health/ingest/ack', { source_ip: sourceIp, dismiss: true })
        .then(function (r2) {
          toast(T('fleet.ackDone', 'Đã ẩn cảnh báo cho ') + sourceIp);
          loadHealth();
          return r2;
        });
    }).catch(function () {});
  }

  function rollback() {
    if (!state.rolloutId) { return; }
    var swap = window.confirm(T('fleet.rollbackConfirm',
      'Dừng triển khai. Nếu server có bản lưu trữ của phiên bản trước thì phục hồi luôn?'));
    return postJson('/api/fleet/rollout/' + state.rolloutId + '/rollback',
                    { swap_server_build: !!swap }).then(function (d) {
      toast((d && (d.note || d.error)) || 'OK');
      loadRollout(state.rolloutId);
      return d;
    }).catch(function () {});
  }

  function loadRolloutList() {
    return getJson('/api/fleet/rollouts').then(function (d) {
      var sel = el('fleetRolloutPick');
      if (!sel) { return; }
      var items = (d && d.items) || [];
      sel.innerHTML = items.length
        ? items.map(function (r) {
            return '<option value="' + esc(String(r.id)) + '"' +
              (state.rolloutId === r.id ? ' selected' : '') + '>#' + esc(String(r.id)) + ' ' +
              esc(r.target_version || '') + ' [' + esc(r.state || '') + ']</option>';
          }).join('')
        : '<option value="">--</option>';
    }).catch(function () {});
  }

  function init() {
    var host = el('fleetPanel');
    if (!host) { return; }
    var waves = (el('fleetWaves') || {}).value || '1,10,100';
    host.innerHTML =
      '<div class="card mb-2"><div class="card-header py-1" style="font-size:12px;">' +
      '<i class="bi bi-cloud-upload"></i> <b>' + esc(T('fleet.title', 'Triển khai & Sức khỏe')) + '</b>' +
      ' <span class="text-muted" style="font-size:10.5px;">' +
      esc(T('fleet.subtitle', 'canary → 10% → 100%, tự chặn khi đợt chưa khỏe')) + '</span>' +
      '<button class="btn btn-sm btn-outline-secondary float-end" onclick="fleet.reload()">⟳</button></div>' +
      '<div class="card-body p-2">' +
      '<div class="text-muted mb-2" style="font-size:11px;">' +
      esc(T('fleet.rolloutHint', 'Nâng cấp agent theo từng đợt: đợt 1 là canary (1 máy). Máy báo đúng phiên bản đích mới tính là xong; đợt chưa đạt 90% hoặc có máy lỗi thì nút "Sang đợt tiếp" sẽ bị chặn.')) +
      '</div>' +
      '<div class="row g-2 align-items-center mb-2">' +
      '<div class="col-md-2"><input id="fleetWaves" class="form-control form-control-sm" value="' +
      esc(waves) + '" placeholder="1,10,100"></div>' +
      '<div class="col-md-3"><input id="fleetTarget" class="form-control form-control-sm" placeholder="' +
      esc(T('fleet.targetVersion', 'phiên bản đích (trống = bản server đang phát)')) + '"></div>' +
      '<div class="col-md-3"><select id="fleetRolloutPick" class="form-select form-select-sm" ' +
      'onchange="fleet.loadRollout(this.value)"><option value="">--</option></select></div>' +
      '<div class="col-md-4">' +
      '<button class="btn btn-sm btn-outline-info me-1" onclick="fleet.plan()">' +
      esc(T('fleet.plan', 'Xem kế hoạch')) + '</button>' +
      '<button class="btn btn-sm btn-success" onclick="fleet.start()">' +
      esc(T('fleet.start', 'Bắt đầu (canary)')) + '</button></div></div>' +
      '<div id="fleetPlan"></div><div id="fleetRollout"></div>' +
      '<hr style="border-color:#24313d;">' +
      '<div style="font-size:12px;"><i class="bi bi-activity"></i> <b>' +
      esc(T('fleet.health', 'Sức khỏe đội máy')) + '</b> <span class="text-muted" style="font-size:10.5px;">' +
      esc(T('fleet.healthHint', 'Máy nào im lặng, máy nào phiên bản cũ, thiếu Sysmon/auditpol, và nguồn nào bị server TỪ CHỐI (dữ liệu không vào được).')) +
      '</span></div>' +
      '<div id="fleetHealth" class="mt-2" style="font-size:11.5px;max-height:300px;overflow-y:auto;"></div>' +
      '<hr style="border-color:#24313d;">' +
      '<div style="font-size:12px;"><i class="bi bi-hdd-stack"></i> <b>' +
      esc(T('fleet.storage', 'Dung lượng & partition')) + '</b></div>' +
      '<div id="fleetStorage" class="mt-2"></div>' +
      '<hr style="border-color:#24313d;">' +
      '<div style="font-size:12px;"><i class="bi bi-shield-check"></i> <b>' +
      esc(T('fleet.policy', 'Chính sách theo đợt')) + '</b> <span class="text-muted" style="font-size:10.5px;">' +
      esc(T('fleet.policyHint', 'Áp một chính sách nhóm cho từng đợt máy: chỉ đợt đang chọn được agent nhận, các máy khác tạm bị chặn. "Xem trước" không gửi gì.')) +
      '</span></div>' +
      '<div id="fleetPolicyList" class="mt-2" style="font-size:11.5px;"></div>' +
      '</div></div>';
    return Promise.all([loadHealth(), loadRolloutList(), loadRollout(null), plan(),
                        loadStorage(), loadPolicies()]);
  }

  window.fleet = {
    init: init,
    reload: function () {
      return Promise.all([loadHealth(), loadRolloutList(), loadRollout(state.rolloutId), plan(),
                          loadStorage(), loadPolicies()]);
    },
    plan: plan,
    start: start,
    advance: advance,
    rollback: rollback,
    ack: ack,
    rollup: rollup,
    dropOld: dropOld,
    policyPreview: policyPreview,
    policyWave: policyWave,
    policyNext: policyNext,
    loadHealth: loadHealth,
    loadRollout: loadRollout,
    loadStorage: loadStorage,
    loadPolicies: loadPolicies,
    state: state
  };
})();
