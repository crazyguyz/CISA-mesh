/**
 * GIAM-SAT unified investigation UI - v5.0.8 ("điều tra 1 chạm")
 *
 * Backed by /api/investigate/* (server/search_engine.py):
 *   - one query box with the mini DSL:  host:PC01 -user:system "cụm từ" OR dst_ip:8.8.8.8
 *   - scope chips (alerts/events/sysmon/traffic/netflow/syslog/fim/sca/yara/vulns/cases)
 *   - clickable facets, click-to-pivot on every value (Entity-360), saved searches,
 *     CSV/JSON evidence export.
 *
 * The same pivot handler is used by the other dashboard tables: any element with
 *   data-pivot="VALUE" data-pivot-kind="host|ip|user|hash|file|domain|rule|cve|any"
 * opens the investigation view for that indicator.
 */
(function () {
  'use strict';

  var SCOPES = ['alerts', 'events', 'sysmon', 'traffic', 'netflow', 'syslog',
    'fim', 'sca', 'yara', 'vulns', 'cases'];
  var DEFAULTS = ['alerts', 'events', 'sysmon', 'traffic'];
  var state = { scopes: DEFAULTS.slice(), hours: 24, inited: false, rows: [], query: '' };

  function T(key, fallback) {
    try { return (typeof t === 'function') ? t(key) : (fallback || key); } catch (e) { return fallback || key; }
  }

  function esc(v) {
    if (typeof escapeHtml === 'function') { return escapeHtml(v == null ? '' : String(v)); }
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function clip(v, n) {
    var s = (v == null ? '' : String(v));
    return s.length > n ? s.slice(0, n) + '…' : s;
  }

  function el(id) { return document.getElementById(id); }

  function getJson(url) {
    return fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.json(); });
  }

  function postJson(url, body, method) {
    return fetch(url, {
      method: method || 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : null
    }).then(function (r) { return r.json(); });
  }

  function pivotChip(kind, value, label) {
    if (!value) { return ''; }
    return '<span class="badge bg-secondary inv-pivot" role="button" style="cursor:pointer;font-weight:400;"' +
      ' data-pivot="' + esc(value) + '" data-pivot-kind="' + esc(kind) + '"' +
      ' title="' + T('inv.pivotHint', 'Mở Entity 360') + '">' +
      esc(label || kind) + ':' + esc(clip(value, 34)) + '</span>';
  }

  function renderScopes() {
    var box = el('invScopes');
    if (!box) { return; }
    box.innerHTML = SCOPES.map(function (s) {
      var on = state.scopes.indexOf(s) >= 0;
      return '<button type="button" class="btn btn-sm ' + (on ? 'btn-success' : 'btn-outline-secondary') +
        ' inv-scope" data-scope="' + s + '" style="font-size:10px;padding:1px 6px;">' + s + '</button>';
    }).join('');
  }

  function run(opts) {
    opts = opts || {};
    var qBox = el('invQuery');
    var q = (opts.query != null ? opts.query : (qBox ? qBox.value : '')) || '';
    state.query = q;
    var hoursSel = el('invHours');
    state.hours = hoursSel ? parseInt(hoursSel.value, 10) : state.hours;
    var res = el('invResults');
    if (res) { res.innerHTML = '<div class="text-center text-muted py-4">' + esc(T('inv.loading', 'Đang tải...')) + '</div>'; }
    var url = '/api/investigate/search?q=' + encodeURIComponent(q) +
      '&scopes=' + encodeURIComponent(state.scopes.join(',')) +
      '&hours=' + state.hours + '&limit=' + (opts.limit || 300);
    return getJson(url).then(function (d) {
      state.rows = d.results || [];
      renderFacets(d);
      renderResults(d);
      return d;
    }).catch(function (e) {
      if (res) { res.innerHTML = '<div class="text-danger p-3">' + esc(String(e)) + '</div>'; }
    });
  }

  function renderFacets(d) {
    var box = el('invFacets');
    if (!box) { return; }
    var f = d.facets || {};
    var html = '<div class="mb-1"><strong>' + esc(String(d.total || 0)) + '</strong> ' +
      esc(T('inv.hits', 'kết quả')) + ' <span class="text-muted">(' + esc(String(d.took_ms || 0)) + 'ms)</span></div>';
    if (f.earliest) {
      html += '<div class="text-muted mb-2" style="font-size:11px;">' + esc(f.earliest) + ' → ' + esc(f.latest) + '</div>';
    }
    var groups = [['scope', 'inv.scope', 'scope'], ['host', 'inv.host', 'host'],
      ['severity', 'inv.severity', 'sev'], ['rule', 'inv.rule', 'rule'], ['user', 'inv.user', 'user']];
    groups.forEach(function (g) {
      var items = f[g[0]] || {};
      var keys = Object.keys(items);
      if (!keys.length) { return; }
      html += '<div class="mb-2"><div class="text-muted" style="font-size:10px;text-transform:uppercase;">' +
        esc(T(g[1], g[0])) + '</div>';
      keys.slice(0, 8).forEach(function (k) {
        html += '<div><a href="#" class="inv-add" data-add="' + esc(g[2]) + ':' + esc(k) +
          '">' + esc(clip(k, 40)) + '</a> <span class="text-muted">(' + esc(String(items[k])) + ')</span></div>';
      });
      html += '</div>';
    });
    (d.unknown || []).forEach(function (u) {
      html += '<div class="text-warning" style="font-size:11px;">⚠ ' + esc(u) + '</div>';
    });
    box.innerHTML = html;
  }

  function rowTitle(r) {
    return r.description || r.rule_name || r.command_line || r.title || r.message ||
      r.path || r.file || r.cve || r.dns_query || r.http_host || '';
  }

  function renderResults(d) {
    var box = el('invResults');
    if (!box) { return; }
    var sum = el('invSummary');
    if (sum) {
      sum.innerHTML = esc(T('inv.results', 'Kết quả')) + ' <span class="badge bg-secondary">' +
        esc(String((d.results || []).length)) + '/' + esc(String(d.total || 0)) + '</span>';
    }
    if (!(d.results || []).length) {
      box.innerHTML = '<div class="text-center text-muted py-4">' + esc(T('inv.empty', 'Không có kết quả')) + '</div>';
      return;
    }
    var html = '<table class="table table-sm table-hover mb-0" style="font-size:12px;"><tbody>';
    d.results.forEach(function (r) {
      var chips = [
        pivotChip('host', r.hostname, 'host'),
        (r.machine_id && r.machine_id !== r.hostname) ? pivotChip('host', r.machine_id, 'id') : '',
        pivotChip('ip', r.source_ip, 'src'), pivotChip('ip', r.src_ip, 'src'),
        pivotChip('ip', r.dst_ip, 'dst'), pivotChip('user', r.user, 'user'),
        pivotChip('hash', r.hashes, 'hash'), pivotChip('file', r.file_path, 'file'),
        pivotChip('file', r.path, 'path'), pivotChip('rule', r.rule_id, 'rule'),
        pivotChip('domain', r.dns_query, 'dns'), pivotChip('domain', r.http_host, 'http'),
        pivotChip('cve', r.cve, 'cve')
      ].filter(Boolean).join(' ');
      var badge = r.severity ? '<span class="badge bg-danger">' + esc(r.severity) + '</span> ' : '';
      html += '<tr><td style="white-space:nowrap;width:150px;">' + esc(r._time || '') +
        '<div><span class="badge bg-dark">' + esc(r._scope || '') + '</span></div></td>' +
        '<td>' + badge + esc(clip(rowTitle(r), 180)) +
        '<div class="mt-1 d-flex flex-wrap gap-1">' + chips + '</div>' +
        '</td></tr>';
    });
    html += '</tbody></table>';
    box.innerHTML = html;
  }

  // ---------------------------------------------------------------- Entity-360
  function entity(kind, value, opts) {
    opts = opts || {};
    switchView('investigate');
    var panel = el('invEntityPanel');
    if (panel) {
      panel.style.display = '';
      panel.innerHTML = '<div class="card"><div class="card-body text-muted">' +
        esc(T('inv.loading', 'Đang tải...')) + '</div></div>';
    }
    var hours = opts.hours != null ? opts.hours : state.hours;
    var url = '/api/investigate/entity/' + encodeURIComponent(kind) + '/' + encodeURIComponent(value) +
      '?hours=' + hours + '&limit=300';
    return getJson(url).then(function (d) {
      if (!panel) { return d; }
      var head = '<div class="card-header py-1 d-flex justify-content-between align-items-center" style="font-size:12px;">' +
        '<span><i class="bi bi-diagram-2"></i> ' + esc(T('inv.entity', 'Entity 360')) + ': ' +
        '<span class="badge bg-primary">' + esc(kind) + '</span> <strong>' + esc(value) + '</strong></span>' +
        '<span><span class="text-muted">' + esc(String(d.total || 0)) + ' ' + esc(T('inv.hits', 'kết quả')) +
        ' (' + esc(String(d.took_ms || 0)) + 'ms)</span> ' +
        '<button class="btn btn-sm btn-outline-secondary" onclick="investigate.closeEntity()">✕</button></span></div>';
      var body = '<div class="card-body p-2" style="font-size:12px;">';
      body += '<div class="mb-2">' + Object.keys(d.by_scope || {}).map(function (s) {
        return '<span class="badge bg-dark me-1">' + esc(s) + ': ' + esc(String(d.by_scope[s])) + '</span>';
      }).join('') + '</div>';
      body += '<div class="text-muted mb-2">' + esc(d.first_seen || '') + ' → ' + esc(d.last_seen || '') + '</div>';
      [['hosts', 'inv.host', 'host'], ['ips', 'inv.ip', 'ip'],
       ['users', 'inv.user', 'user'], ['rules', 'inv.rule', 'rule']].forEach(function (g) {
        var items = d[g[0]] || {};
        var keys = Object.keys(items);
        if (!keys.length) { return; }
        body += '<div class="mb-1"><span class="text-muted">' + esc(T(g[1], g[0])) + ':</span> ' +
          keys.map(function (k) {
            return '<span class="badge bg-secondary inv-pivot" role="button" style="cursor:pointer;font-weight:400;"' +
              ' data-pivot="' + esc(k) + '" data-pivot-kind="' + esc(g[2]) + '">' +
              esc(clip(k, 30)) + ' (' + esc(String(items[k])) + ')</span>';
          }).join(' ') + '</div>';
      });
      body += '</div><div class="card-body p-0" style="max-height:420px;overflow-y:auto;">' +
        '<table class="table table-sm mb-0" style="font-size:11px;"><tbody>';
      (d.results || []).forEach(function (r) {
        body += '<tr><td style="white-space:nowrap;width:140px;">' + esc(r._time || '') + '</td>' +
          '<td><span class="badge bg-dark">' + esc(r._scope || '') + '</span> ' +
          esc(clip(rowTitle(r), 150)) + '</td></tr>';
      });
      body += '</tbody></table></div>';
      panel.innerHTML = '<div class="card">' + head + body + '</div>';
      return d;
    });
  }

  function closeEntity() {
    var panel = el('invEntityPanel');
    if (panel) { panel.style.display = 'none'; panel.innerHTML = ''; }
  }

  function switchView(name) {
    try { if (typeof showView === 'function') { showView(name); return; } } catch (e) { /* ignore */ }
    var link = document.querySelector('.nav-link[data-view="' + name + '"]');
    if (link) { link.click(); }
  }

  // ------------------------------------------------- saved searches + export
  function loadSaved() {
    return getJson('/api/investigate/saved').then(function (d) {
      var box = el('invSaved');
      if (!box) { return; }
      var items = d.items || [];
      if (!items.length) {
        box.innerHTML = '<span class="text-muted" style="font-size:11px;">' +
          esc(T('inv.savedEmpty', 'Chưa có truy vấn đã lưu')) + '</span>';
        return;
      }
      box.innerHTML = items.map(function (s) {
        return '<span class="badge bg-info text-dark" style="font-size:11px;">' +
          '<a href="#" class="inv-load text-dark text-decoration-none" data-q="' + esc(s.query) +
          '" data-scopes="' + esc(s.scopes) + '">' + esc(clip(s.name, 26)) + '</a> ' +
          '<a href="#" class="inv-del text-danger text-decoration-none" data-id="' +
          esc(String(s.id)) + '">✕</a></span>';
      }).join(' ');
    });
  }

  function save() {
    var q = (el('invQuery') || {}).value || '';
    if (!q.trim()) {
      if (typeof showToast === 'function') { showToast(T('inv.saveNoQuery', 'Nhập truy vấn trước khi lưu')); }
      return;
    }
    var name = window.prompt(T('inv.saveName', 'Tên truy vấn'), clip(q, 40));
    if (!name) { return; }
    postJson('/api/investigate/saved', {
      name: name, query: q, scopes: state.scopes.join(','), hours: state.hours, shared: true
    }).then(function (d) {
      if (typeof showToast === 'function') {
        showToast(d.success ? T('inv.saved', 'Đã lưu truy vấn') : (d.error || 'Error'));
      }
      loadSaved();
    });
  }

  function del(id) {
    postJson('/api/investigate/saved/' + id, null, 'DELETE').then(function () { loadSaved(); });
  }

  function exportFmt(fmt) {
    var q = (el('invQuery') || {}).value || '';
    window.location.href = '/api/investigate/export?fmt=' + encodeURIComponent(fmt) +
      '&q=' + encodeURIComponent(q) + '&scopes=' + encodeURIComponent(state.scopes.join(',')) +
      '&hours=' + state.hours;
  }

  // ---------------------------------------------------------------- wiring
  function onScopeClick(ev) {
    var b = ev.target.closest ? ev.target.closest('.inv-scope') : null;
    if (!b) { return; }
    ev.preventDefault();
    var s = b.getAttribute('data-scope');
    var i = state.scopes.indexOf(s);
    if (i >= 0) { state.scopes.splice(i, 1); } else { state.scopes.push(s); }
    if (!state.scopes.length) { state.scopes = [s]; }
    renderScopes();
    if (state.query) { run(); }
  }

  function onPivotClick(ev) {
    var p = ev.target.closest ? ev.target.closest('[data-pivot]') : null;
    if (!p) { return; }
    ev.preventDefault();
    entity(p.getAttribute('data-pivot-kind') || 'any', p.getAttribute('data-pivot'));
  }

  function onAddClick(ev) {
    var a = ev.target.closest ? ev.target.closest('.inv-add') : null;
    if (!a) { return; }
    ev.preventDefault();
    var box = el('invQuery');
    if (!box) { return; }
    box.value = (box.value ? box.value + ' ' : '') + a.getAttribute('data-add');
    run();
  }

  function onSavedClick(ev) {
    var load = ev.target.closest ? ev.target.closest('.inv-load') : null;
    if (load) {
      ev.preventDefault();
      var box = el('invQuery');
      var q = load.getAttribute('data-q') || '';
      if (box) { box.value = q; }
      var sc = (load.getAttribute('data-scopes') || '').split(',').filter(Boolean);
      if (sc.length) { state.scopes = sc; renderScopes(); }
      run({ query: q });
      return;
    }
    var d = ev.target.closest ? ev.target.closest('.inv-del') : null;
    if (d) { ev.preventDefault(); del(d.getAttribute('data-id')); }
  }

  function init() {
    if (state.inited) { loadSaved(); return; }
    state.inited = true;
    renderScopes();
    loadSaved();
    document.addEventListener('click', onScopeClick);
    document.addEventListener('click', onPivotClick);
    document.addEventListener('click', onAddClick);
    document.addEventListener('click', onSavedClick);
  }

  window.investigate = {
    init: init,
    run: run,
    entity: entity,
    closeEntity: closeEntity,
    save: save,
    del: del,
    exportFmt: exportFmt,
    state: state,
    /* open a query (used by other views / deep links) */
    open: function (query, opts) {
      opts = opts || {};
      switchView('investigate');
      var box = el('invQuery');
      if (box) { box.value = query || ''; }
      if (opts.scopes && opts.scopes.length) { state.scopes = opts.scopes; renderScopes(); }
      var hs = el('invHours');
      if (hs && opts.hours != null) { hs.value = String(opts.hours); }
      if (!state.inited) { init(); }
      return run({ query: query || '' });
    }
  };

  /* global pivot helper: other tables call pivotEntity('ip', '8.8.8.8') */
  window.pivotEntity = function (kind, value, opts) {
    if (!state.inited) { init(); }
    return entity(kind || 'any', value, opts || {});
  };
})();
