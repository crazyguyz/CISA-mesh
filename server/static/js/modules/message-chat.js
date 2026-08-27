/**
 * Message Chat Module v3.9.7
 * - Left panel: machine search + group select + "Máy đã chọn" reply grid
 *   Grid shows ALL machines in group (yellow=pending, green=replied)
 * - Right panel: Chat - 1 server message per broadcast, then replies below
 */
window.messageChat = (function() {
  var allMachines = [];
  var allGroups = [];
  var activeMachineId = null;
  var activeGroupId = null;
  var unreadByMachine = {};
  var intervalId = null;

  function init() {
    activeMachineId = null;
    activeGroupId = null;
    if (intervalId) clearInterval(intervalId);
    intervalId = setInterval(function() {
      if (activeMachineId) refreshMessages(activeMachineId);
      else if (activeGroupId) refreshGroupChat(activeGroupId);
      updateUnreadBadge();
    }, 5000);
    loadAllData();
    updateUnreadBadge();
    document.addEventListener('click', function(e) {
      var sug = document.getElementById('msgSearchSuggestions');
      var inp = document.getElementById('msgSearchInput');
      if (sug && inp && e.target !== inp && !sug.contains(e.target)) {
        sug.style.display = 'none';
      }
    });
  }

  function destroy() {
    if (intervalId) clearInterval(intervalId);
    intervalId = null;
    activeMachineId = null;
  }

  function loadAllData() {
    Promise.all([
      fetch('/api/machines').then(function(r){return r.json();}),
      fetch('/api/groups').then(function(r){return r.json();}),
      fetch('/api/message/unread-by-machine').then(function(r){return r.json();})
    ]).then(function(results) {
      allMachines = results[0] || [];
      var groupsData = results[1] || {};
      allGroups = groupsData.groups || [];
      unreadByMachine = results[2] || {};
      populateGroupDropdown();
      populateMachineDropdown(allMachines);
    }).catch(function() {
      showToast(t('chat.loadErr'));
    });
  }

  // ===== DROPDOWNS =====

  function populateMachineDropdown(machines) {
    var sel = document.getElementById('msgMachineSelect');
    if (!sel) return;
    sel.innerHTML = '<option value="">' + t('chat.selectMachine') + '</option>';
    if (activeGroupId) {
      sel.innerHTML += '<option value="__all__">📢 Tat ca may trong nhom</option>';
    }
    var list = (machines || []).slice().sort(function(a, b) {
      return (unreadByMachine[b.machine_id] || 0) - (unreadByMachine[a.machine_id] || 0);
    });
    list.forEach(function(m) {
      var label = (m.hostname || m.machine_id);
      if (m.user_name) label += ' - ' + m.user_name;
      if (m.ip_address) label += ' (' + m.ip_address + ')';
      var status = m.is_online == 1 ? '[ON]' : '[OFF]';
      var unread = unreadByMachine[m.machine_id] || 0;
      var badge = unread > 0 ? ' 🔴(' + unread + ')' : '';
      sel.innerHTML += '<option value="' + esc(m.machine_id) + '">' + status + ' ' + esc(label) + badge + '</option>';
    });
  }

  function populateGroupDropdown() {
    var sel = document.getElementById('msgGroupSelect');
    if (!sel) return;
    sel.innerHTML = '<option value="">' + t('chat.none') + '</option>';
    allGroups.forEach(function(g) {
      sel.innerHTML += '<option value="' + esc(g.id) + '">' + esc(g.name) + ' (' + (g.members ? g.members.length : 0) + ' may)</option>';
    });
  }

  function fetchUnreadByMachine() {
    fetch('/api/message/unread-by-machine')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        unreadByMachine = data || {};
        populateMachineDropdown(allMachines);
        if (allMachines.length) filterMachines();
      })
      .catch(function() {});
  }

  // ===== SEARCH =====

  function filterMachines() {
    var q = (document.getElementById('msgSearchInput') || {}).value || '';
    q = q.toLowerCase().trim();
    var sug = document.getElementById('msgSearchSuggestions');
    if (!sug) return;
    if (!q && !activeGroupId) { sug.style.display = 'none'; return; }

    var pool = allMachines;
    if (activeGroupId) {
      var group = allGroups.find(function(g) { return g.id == activeGroupId; });
      if (group && group.members) {
        var groupMachineIds = group.members.map(function(m) { return m.machine_id; });
        pool = allMachines.filter(function(m) { return groupMachineIds.indexOf(m.machine_id) >= 0; });
      }
    }

    var filtered = pool;
    if (q) {
      filtered = pool.filter(function(m) {
        return (m.hostname || '').toLowerCase().indexOf(q) >= 0 ||
               (m.ip_address || '').toLowerCase().indexOf(q) >= 0 ||
               (m.user_name || '').toLowerCase().indexOf(q) >= 0 ||
               (m.email || '').toLowerCase().indexOf(q) >= 0 ||
               (m.notes || '').toLowerCase().indexOf(q) >= 0 ||
               (m.machine_id || '').toLowerCase().indexOf(q) >= 0;
      });
    }

    if (filtered.length === 0) {
      sug.innerHTML = '<div class="p-2 text-muted" style="font-size:11px;cursor:default;">' + t('chat.noMachineFound') + '</div>';
      sug.style.display = 'block';
      return;
    }

    filtered.sort(function(a, b) {
      return (unreadByMachine[b.machine_id] || 0) - (unreadByMachine[a.machine_id] || 0);
    });
    var display = filtered.slice(0, 15);
    var html = '';
    display.forEach(function(m) {
      var online = m.is_online == 1;
      var dot = online ? '<span class="online-dot online"></span>' : '<span class="online-dot offline"></span>';
      var unread = unreadByMachine[m.machine_id] || 0;
      var badge = unread > 0 ? '<span style="background:#e5484d;color:#fff;border-radius:8px;padding:0 6px;font-size:10px;margin-left:6px;">' + unread + '</span>' : '';
      var userInfo = '';
      if (m.user_name) userInfo += ' 👤 ' + m.user_name;
      if (m.email) userInfo += ' ✉ ' + m.email;
      html += '<div style="padding:8px 12px;cursor:pointer;border-bottom:1px solid #2a3a4a;font-size:12px;transition:background 0.15s;" ' +
        'onmouseover="this.style.background=\'#2a3a4a\'" onmouseout="this.style.background=\'\'" ' +
        'onclick="messageChat.selectMachine(\'' + escJs(m.machine_id) + '\')">' +
        dot + '<strong>' + esc(m.hostname || m.machine_id) + '</strong>' + badge +
        '<span style="color:#6a8aaa;margin-left:8px;">' + (m.ip_address || '-') + '</span>' +
        '<span style="color:#b0c8e0;margin-left:8px;">' + userInfo + '</span>' +
        '<span style="float:right;font-size:10px;color:' + (online ? '#00d4aa' : '#ff4444') + ';">' + (online ? 'ON' : 'OFF') + '</span>' +
        '</div>';
    });
    if (filtered.length > 15) {
      html += '<div class="p-2 text-muted" style="font-size:10px;cursor:default;">...va ' + (filtered.length - 15) + ' may khac (nhap them ki tu de thu hep)</div>';
    }
    sug.innerHTML = html;
    sug.style.display = 'block';
  }

  // ===== SELECTION =====

  function selectMachine(machineId) {
    activeMachineId = machineId;
    activeGroupId = null;
    var sug = document.getElementById('msgSearchSuggestions');
    if (sug) sug.style.display = 'none';
    if (document.getElementById('msgSearchInput')) document.getElementById('msgSearchInput').value = '';
    if (document.getElementById('msgGroupSelect')) document.getElementById('msgGroupSelect').value = '';

    populateMachineDropdown(allMachines);
    var msel = document.getElementById('msgMachineSelect');
    if (msel) msel.value = machineId;

    var m = allMachines.find(function(x) { return x.machine_id === machineId; });
    var label = m ? (m.hostname || m.machine_id) : machineId;
    var online = m && m.is_online == 1;

    updateTargetDisplay(label, online ? 'Online' : 'Offline');

    // Show single machine in "Máy đã chọn" - simple info card
    var selDiv = document.getElementById('msgSelectedMachine');
    if (selDiv) {
      var dot = online ? '<span class="online-dot online"></span>' : '<span class="online-dot offline"></span>';
      var userInfo = '';
      if (m) {
        if (m.user_name) userInfo += ' 👤 ' + esc(m.user_name);
        if (m.email) userInfo += ' ✉ ' + esc(m.email);
      }
      selDiv.innerHTML = dot + '<strong>' + esc(label) + '</strong>' +
        '<br><small style="color:#6a8aaa;">' + (m ? m.ip_address || '' : '') + '</small>' + userInfo +
        ' <button class="btn btn-sm btn-outline-secondary py-0 px-1 ms-2" onclick="messageChat.clearSelection()" title="Bo chon">✕</button>';
    }

    refreshMessages(machineId);
  }

  function onMachineSelect() {
    var mid = document.getElementById('msgMachineSelect').value;
    if (!mid) { clearSelection(); return; }
    if (mid === '__all__') {
      activeMachineId = null;
      updateTargetDisplay('', t('chat.allGroupMachines'));
      if (activeGroupId) refreshGroupChat(activeGroupId);
      return;
    }
    selectMachine(mid);
  }

  function onGroupChange() {
    var groupId = document.getElementById('msgGroupSelect').value;
    activeGroupId = groupId || null;
    activeMachineId = null;

    updateTargetDisplay('', '');
    var container = document.getElementById('chat-messages');
    if (container) container.innerHTML = '<div class="text-center text-muted py-3">Chon may tram hoac "Tat ca may" de xem lich su</div>';
    var msel = document.getElementById('msgMachineSelect');
    if (msel) msel.value = '';

    if (!groupId) {
      populateMachineDropdown(allMachines);
      var sug = document.getElementById('msgSearchSuggestions');
      if (sug) sug.style.display = 'none';
      renderReplyGrid([], []);
      return;
    }

    var group = allGroups.find(function(g) { return g.id == groupId; });
    var groupMachines = [];
    if (group && group.members) {
      var groupMachineIds = group.members.map(function(m) { return m.machine_id; });
      groupMachines = allMachines.filter(function(m) { return groupMachineIds.indexOf(m.machine_id) >= 0; });
    }
    populateMachineDropdown(groupMachines);

    // Show group machines in "Máy đã chọn" as reply grid (all yellow initially)
    renderReplyGrid(groupMachines, []);

    filterMachines();
  }

  function clearSelection() {
    activeMachineId = null;
    activeGroupId = null;
    updateTargetDisplay('', '');
    var container = document.getElementById('chat-messages');
    if (container) container.innerHTML = '<div class="text-center text-muted py-3">' + t('chat.selectHint') + '</div>';
    if (document.getElementById('msgGroupSelect')) document.getElementById('msgGroupSelect').value = '';
    if (document.getElementById('msgMachineSelect')) document.getElementById('msgMachineSelect').value = '';
    populateMachineDropdown(allMachines);
    renderReplyGrid([], []);
  }

  // ===== REPLY GRID ("Máy đã chọn" section) =====

  /**
   * Render the reply grid in the "Máy đã chọn" section.
   * @param {Array} machines - All machines in the current selection
   * @param {Object} replyMap - { machine_id: { status, reply, replied_at } }
   */
  function renderReplyGrid(machines, replyMap) {
    var selDiv = document.getElementById('msgSelectedMachine');
    if (!selDiv) return;

    if (machines.length === 0) {
      selDiv.innerHTML = '<span class="text-muted">' + t('chat.noMachineSelected') + '</span>';
      return;
    }

    var html = '<div style="font-size:10px;color:#6a8aaa;margin-bottom:4px;">📋 ' + machines.length + ' may</div>';
    html += '<div style="display:flex;flex-wrap:wrap;gap:5px;">';

    machines.forEach(function(m) {
      var mid = m.machine_id;
      var hostname = m.hostname || mid;
      var online = m.is_online == 1;
      var reply = replyMap[mid];
      var isReplied = reply && reply.status === 'replied';

      var bg = isReplied ? '#1a3a2a' : '#3a3a1a';
      var border = isReplied ? '#00d4aa' : '#ffcc66';
      var icon = isReplied ? '✅' : (online ? '⏳' : '⚫');
      var color = isReplied ? '#88dd99' : (online ? '#ffcc66' : '#6a7a8a');

      html += '<div style="background:' + bg + ';border:1px solid ' + border + ';border-radius:6px;padding:5px 8px;font-size:11px;cursor:pointer;min-width:100px;" ' +
        'title="' + escapeHtml(hostname) + ': ' + (isReplied ? t('chat.replied', [(reply.reply||'').substring(0, 60)]) : t('chat.waiting')) + '" ' +
        (isReplied ? 'onclick="alert(\'🖥 ' + escJs(hostname) + '\\n\\n📝 Tra loi: ' + escJs(reply.reply||'') + '\\n\\n⏱ Luc: ' + escJs(reply.replied_at||'?') + '\')"' : '') + '>' +
        '<span style="color:' + color + ';font-weight:600;">' + icon + ' ' + esc(hostname) + '</span>' +
        '</div>';
    });

    html += '</div>';
    selDiv.innerHTML = html;
  }

  // ===== CHAT AREA =====

  function updateTargetDisplay(machineLabel, status) {
    var targetEl = document.getElementById('msgChatTarget');
    var statusEl = document.getElementById('msgChatStatus');
    if (targetEl) {
      if (machineLabel) targetEl.innerHTML = '→ <strong>' + escapeHtml(machineLabel) + '</strong>';
      else targetEl.innerHTML = '';
    }
    if (statusEl) statusEl.textContent = status || '';
  }

  // ===== SINGLE MACHINE CHAT =====

  function updateUnreadBadge() {
    // v4.10: reuse the global badge refresher (also run on a 30s global interval
    // and on SSE events) to keep a single source of truth for #msgBadge.
    if (window.refreshMessageBadge) {
      window.refreshMessageBadge();
    } else {
      fetch('/api/message/unread-count')
        .then(function(r) { return r.json(); })
        .then(function(data) {
          var badge = document.getElementById('msgBadge');
          if (!badge) return;
          var count = data.count || 0;
          badge.textContent = count;
          badge.style.display = count > 0 ? 'inline' : 'none';
        })
        .catch(function() {});
    }
    fetchUnreadByMachine();
  }

  function refreshMessages(machineId) {
    if (!machineId) return;
    fetch('/api/message/list/' + machineId)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        renderMessages(data.messages || []);
        // Mark agent messages for this machine as read + refresh badge
        fetch('/api/message/mark-read', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ machine_id: machineId })
        }).then(function() { updateUnreadBadge(); }).catch(function() {});
      })
      .catch(function() {});
  }

  // v5.0.1: support-ticket rendering (structured workstation requests)
  var TICKET_COLORS = {
    network: '#3399ff', software: '#a06ee8', computer: '#0dd4aa',
    monitor: '#5a7dff', printer: '#ff9933', phone: '#ff66aa', other: '#8892a4'
  };
  function ticketBody(m) {
    var h = '';
    if (m.message) h += '<div style="color:#ddd;margin-top:4px;font-size:0.8rem;">' + esc(m.message) + '</div>';
    else h += '<div style="color:#5a6a7a;margin-top:4px;font-size:0.75rem;font-style:italic;">' + t('ticket.noNote') + '</div>';
    if (m.ultraview_id || m.ultraview_password) {
      h += '<div class="mt-1 p-1 rounded" style="background:rgba(0,212,170,0.08);border-left:2px solid #0dd4aa;font-size:0.72rem;color:#9fdcc8;">' +
        '<strong>' + t('ticket.ultraview') + ':</strong> ' + esc(m.ultraview_id || '—') + ' / ' + esc(m.ultraview_password || '—') + '</div>';
    }
    return h;
  }

  function renderMessages(messages) {
    var container = document.getElementById('chat-messages');
    if (!container) return;
    if (messages.length === 0) {
      container.innerHTML = '<div class="text-muted text-center py-3">' + t('chat.noMessages') + '</div>';
      return;
    }
    messages.sort(function(a, b) { return (a.created_at || '').localeCompare(b.created_at || ''); });

    var html = '';
    for (var i = 0; i < messages.length; i++) {
      var m = messages[i];
      var isAgent = m.direction === 'agent';
      var isUnread = isAgent && m.status === 'received';
      var isTicket = m.msg_type === 'support_ticket';
      var catCode = TICKET_COLORS[m.category] ? m.category : 'other';
      html += '<div class="p-2 mb-2 rounded" style="background:' + (isTicket ? '#1a2533' : (isAgent ? '#2b2410' : '#0d2b1e')) + ';' + (isUnread ? 'border:1px solid #ffaa33;box-shadow:0 0 8px rgba(255,170,51,0.4);' : '') + '">' +
        '<div style="display:flex;justify-content:space-between;">' +
        '<span style="font-size:0.75rem;color:#aaa;"><strong>' + (isTicket ? '🎫 ' : isAgent ? '👤 ' : '') + esc(m.sender||'admin') + '</strong>' +
        (isTicket ? ' <span class="badge" style="background:' + TICKET_COLORS[catCode] + ';color:#fff;font-size:9px;">' + esc(t('ticket.cat.' + catCode)) + '</span>' : '') +
        (isUnread ? ' <span class="badge bg-warning text-dark" style="font-size:9px;">MỚI</span>' : (isAgent ? ' <span class="badge bg-warning text-dark" style="font-size:9px;">' + t('chat.fromMachine') + '</span>' : '')) + '</span>' +
        '<span style="font-size:0.7rem;color:#5a6a7a;">' + (m.created_at||'') + '</span>' +
        '</div>' +
        (isTicket ? ticketBody(m) : '<div style="color:#ddd;margin-top:4px;">' + esc(m.message||'') + '</div>') +
        (m.reply ? '<div class="mt-1 p-1 rounded" style="background:rgba(0,212,170,0.1);border-left:2px solid #0dd4aa;">' +
          '<div style="font-size:0.7rem;color:#0dd4aa;">' + t('chat.reply', [m.replied_at||'']) + '</div>' +
          '<div style="color:#ccc;">' + esc(m.reply) + '</div></div>' : '') +
        '</div>';
    }
    container.innerHTML = html;
    container.scrollTop = container.scrollHeight;
  }

  // ===== GROUP CHAT v3.9.7 (BROADCAST MODE) =====

  function refreshGroupChat(groupId) {
    if (!groupId) return;
    fetch('/api/message/group-history/' + groupId)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        renderGroupChat(data.messages || [], data.machine_names || {}, data.group_name || '');
      })
      .catch(function() {});
  }

  /**
   * Group chat: 1 server message per broadcast, then machine replies listed below.
   * Also updates the reply grid in "Máy đã chọn".
   */
  function renderGroupChat(messages, machineNames, groupName) {
    var container = document.getElementById('chat-messages');
    if (!container) return;

    // Get current group machines for reply grid
    var groupMachines = [];
    if (activeGroupId) {
      var group = allGroups.find(function(g) { return g.id == activeGroupId; });
      if (group && group.members) {
        var memberIds = group.members.map(function(m) { return m.machine_id; });
        groupMachines = allMachines.filter(function(m) { return memberIds.indexOf(m.machine_id) >= 0; });
      }
    }

    if (messages.length === 0) {
      container.innerHTML = '<div class="text-muted text-center py-3">' + t('chat.groupNoMessages', [groupName||'']) + '</div>';
      renderReplyGrid(groupMachines, []);
      return;
    }

    // Sort by created_at
    messages.sort(function(a, b) { return (a.created_at || '').localeCompare(b.created_at || ''); });

    // Build reply map: for each machine, track latest reply status
    var replyMap = {};

    // Group into batches by time window (3 seconds = same broadcast)
    var batches = [];
    var currentBatch = null;
    var lastTime = 0;

    messages.forEach(function(m) {
      // Track reply
      if (!replyMap[m.machine_id] || m.status === 'replied') {
        replyMap[m.machine_id] = {
          status: m.status || 'sent',
          reply: m.reply || '',
          replied_at: m.replied_at || ''
        };
      }

      var ts = Date.parse(m.created_at || '') || 0;
      if (!currentBatch || Math.abs(ts - lastTime) > 3000) {
        currentBatch = {
          created_at: m.created_at,
          sender: m.sender,
          title: m.title,
          message: m.message,
          replies: []  // { machine_id, hostname, reply, replied_at }
        };
        batches.push(currentBatch);
      }
      lastTime = ts;

      // If this machine replied, add to replies
      if (m.status === 'replied' && m.reply) {
        currentBatch.replies.push({
          machine_id: m.machine_id,
          hostname: machineNames[m.machine_id] || m.machine_id || '',
          reply: m.reply,
          replied_at: m.replied_at || ''
        });
      }
    });

    // Update reply grid
    renderReplyGrid(groupMachines, replyMap);

    // Render chat - newest batch at top
    var html = '';
    for (var b = batches.length - 1; b >= 0; b--) {
      var batch = batches[b];
      html += '<div style="margin-bottom:10px;">';

      // Server message (only 1 per broadcast)
      html += '<div style="background:#0d2b1e;padding:10px 14px;border-radius:8px 8px 4px 4px;">';
      html += '<div style="display:flex;justify-content:space-between;">';
      html += '<span style="font-size:0.75rem;color:#aaa;"><strong>' + esc(batch.sender||'admin') + '</strong></span>';
      html += '<span style="font-size:0.7rem;color:#5a6a7a;">' + (batch.created_at||'') + '</span>';
      html += '</div>';
      if (batch.title && batch.title !== 'Thong bao') {
        html += '<div style="font-weight:bold;color:#0dd4aa;margin-top:4px;">' + esc(batch.title) + '</div>';
      }
      html += '<div style="color:#ddd;margin-top:4px;">' + esc(batch.message||'') + '</div>';
      html += '</div>';

      // Machine replies below
      if (batch.replies.length > 0) {
        html += '<div style="margin-top:2px;">';
        batch.replies.forEach(function(reply) {
          html += '<div style="background:rgba(0,212,170,0.06);border-left:2px solid #00d4aa;padding:6px 10px;font-size:11px;margin-top:1px;border-radius:0 4px 4px 0;">' +
            '<span style="color:#0dd4aa;font-weight:600;">🖥 ' + esc(reply.hostname) + '</span>' +
            '<span style="color:#5a6a7a;font-size:9px;margin-left:6px;">' + (reply.replied_at||'') + '</span>' +
            '<div style="color:#ccc;margin-top:2px;">' + esc(reply.reply) + '</div>' +
            '</div>';
        });
        html += '</div>';
      }

      html += '</div>';
    }

    container.innerHTML = html;
    container.scrollTop = container.scrollHeight;
  }

  // ===== SEND =====

  function sendMessage() {
    var msg = (document.getElementById('chat-input') || {}).value || '';
    if (!msg.trim()) return;

    var msel = document.getElementById('msgMachineSelect');
    var selectedMid = msel ? msel.value : '';

    if (activeGroupId && selectedMid === '__all__') {
      broadcastToGroup(msg);
      return;
    }

    if (!activeMachineId) {
      showToast(t('chat.selectMachineFirst'));
      return;
    }

    fetch('/api/message/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({machine_id: activeMachineId, message: msg, require_reply: true})
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === 'sent' || data.status === 'queued') {
        if (document.getElementById('chat-input')) document.getElementById('chat-input').value = '';
        showToast(t('chat.sent'));
        refreshMessages(activeMachineId);
      } else {
        showToast('❌ ' + (data.error || t('chat.sendFail')));
      }
    })
    .catch(function() { showToast(t('chat.connErr')); });
  }

  function broadcastToGroup(msg) {
    if (!activeGroupId) { showToast(t('chat.selectGroupFirst')); return; }

    var group = allGroups.find(function(g) { return g.id == activeGroupId; });
    if (!group || !group.members || !group.members.length) {
      showToast(t('chat.groupEmpty'));
      return;
    }
    var ids = group.members.map(function(m) { return m.machine_id; });

    fetch('/api/message/broadcast', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({machine_ids: ids, message: msg, require_reply: true})
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      showToast(t('chat.sentTo', [data.total||0]));
      if (document.getElementById('chat-input')) document.getElementById('chat-input').value = '';
      refreshGroupChat(activeGroupId);
    })
    .catch(function() { showToast(t('chat.connErr')); });
  }

  // ===== UTILS =====

  function esc(text) {
    // v5.0.2 FIX: coerce numbers to String (esc(g.id) crashed the Messages tab:
    // group ids are numbers -> 'text.replace is not a function') and actually
    // HTML-escape (the old replacements were no-ops, escaping nothing).
    if (text === null || text === undefined) return '';
    return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /**
   * v3.9.7: Delete all messages for the currently active chat.
   */
  function clearCurrentChat() {
    if (activeMachineId) {
      if (!confirm(t('chat.confirmDeleteMachine'))) return;
      fetch('/api/message/clear/' + activeMachineId, { method: 'DELETE' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          showToast(t('chat.deleted', [data.count || 0]));
          refreshMessages(activeMachineId);
          if (activeGroupId) refreshGroupChat(activeGroupId);
        })
        .catch(function() { showToast(t('chat.deleteErr')); });
    } else if (activeGroupId) {
      if (!confirm(t('chat.confirmDeleteGroup'))) return;
      fetch('/api/message/clear-group/' + activeGroupId, { method: 'DELETE' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          showToast(t('chat.deleted', [data.count || 0]));
          refreshGroupChat(activeGroupId);
        })
        .catch(function() { showToast(t('chat.deleteErr')); });
    } else {
      showToast(t('chat.selectMachineOrGroup'));
    }
  }

  return {
    init: init,
    destroy: destroy,
    filterMachines: filterMachines,
    selectMachine: selectMachine,
    clearSelection: clearSelection,
    onGroupChange: onGroupChange,
    onMachineSelect: onMachineSelect,
    broadcastToGroup: broadcastToGroup,
    sendMessage: sendMessage,
    clearCurrentChat: clearCurrentChat
  };
})();