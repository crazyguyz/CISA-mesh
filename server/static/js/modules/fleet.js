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

  var state = { rolloutId: null, plan: null };

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
        '<th>Nguồn</th><th>Lý do</th><th>Loại</th><th>Số lần</th><th>Lần cuối</th></tr></thead><tbody>';
      rows.forEach(function (r) {
        html += '<tr><td>' + esc(r.source_ip) + '</td><td>' + esc(r.reason) + '</td><td>' +
          esc(r.msg_type) + '</td><td>' + esc(String(r.count)) + '</td><td>' +
          esc(r.last_seen || '') + '</td></tr>';
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
        toast(d.success ? (T('fleet.started', 'Đã bắt đầu đợt canary') + ' #' + d.id)
                        : (d.error || 'Error'));
        if (d.id) { loadRollout(d.id); }
        return d;
      }).catch(function () {});
  }

  function advance(force) {
    if (!state.rolloutId) { return; }
    return postJson('/api/fleet/rollout/' + state.rolloutId + '/advance', { force: !!force })
      .then(function (d) {
        toast(d.success ? T('fleet.advanced', 'Đã sang đợt tiếp')
                        : (T('fleet.blocked', 'Bị chặn: ') + (d.reason || '')));
        loadRollout(state.rolloutId);
        return d;
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
      '<div class="row g-2 align-items-center mb-2">' +
      '<div class="col-md-3"><input id="fleetWaves" class="form-control form-control-sm" value="' +
      esc(waves) + '" placeholder="1,10,100"></div>' +
      '<div class="col-md-4"><input id="fleetTarget" class="form-control form-control-sm" placeholder="' +
      esc(T('fleet.targetVersion', 'phiên bản đích (trống = bản server đang phát)')) + '"></div>' +
      '<div class="col-md-5">' +
      '<button class="btn btn-sm btn-outline-info me-1" onclick="fleet.plan()">' +
      esc(T('fleet.plan', 'Xem kế hoạch')) + '</button>' +
      '<button class="btn btn-sm btn-success" onclick="fleet.start()">' +
      esc(T('fleet.start', 'Bắt đầu (canary)')) + '</button></div></div>' +
      '<div id="fleetPlan"></div><div id="fleetRollout"></div>' +
      '<hr style="border-color:#24313d;">' +
      '<div style="font-size:12px;"><i class="bi bi-activity"></i> <b>' +
      esc(T('fleet.health', 'Sức khỏe đội máy')) + '</b></div>' +
      '<div id="fleetHealth" class="mt-2" style="font-size:11.5px;max-height:340px;overflow-y:auto;"></div>' +
      '</div></div>';
    return Promise.all([loadHealth(), loadRollout(null), plan()]);
  }

  window.fleet = {
    init: init,
    reload: function () { return Promise.all([loadHealth(), loadRollout(state.rolloutId), plan()]); },
    plan: plan,
    start: start,
    advance: advance,
    rollback: rollback,
    loadHealth: loadHealth,
    loadRollout: loadRollout,
    state: state
  };
})();
