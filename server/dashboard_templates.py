"""
Dashboard Template Engine v1.1.0 for GIAM-SAT Server
Server-side rendering: pre-fetches all panel data from DB before generating HTML.
No client-side fetch needed — all data embedded directly in the page.

Architecture:
  JSON Template → TemplateEngine.render_html(db) → HTML with embedded data
"""
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime


def _json_script_safe(obj) -> str:
    """v4.11 (CRITICAL-2 FIX): serialize JSON safely for embedding inside a
    <script> block. json.dumps does NOT escape '<', so an attacker-controlled
    event field like '</script><script>...' could break out (stored XSS).
    Escapes <, >, & and U+2028/U+2029 (OWASP rule for JSON-in-script)."""
    return (json.dumps(obj, default=str, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "dashboard")


class DashboardTemplate:
    """Represents a single dashboard template loaded from JSON."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.name = ""
        self.description = ""
        self.refresh_interval = 60
        self.category = "monitoring"
        self.panels: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.name = data.get("name", self.filename.replace(".json", ""))
            self.description = data.get("description", "")
            self.refresh_interval = data.get("refresh_interval", 60)
            self.category = data.get("category", "monitoring")
            self.panels = data.get("panels", [])
        except (json.JSONDecodeError, IOError) as e:
            print(f"[-] Dashboard: Failed to load {self.filepath}: {e}")


class TemplateEngine:
    """Renders dashboard templates to HTML with server-side data fetching."""

    CHART_COLORS = [
        "#00d4aa", "#3399ff", "#ffcc66", "#ff6b6b", "#a78bfa",
        "#34d399", "#60a5fa", "#f472b6", "#fbbf24", "#818cf8",
    ]

    def __init__(self):
        self._templates: Dict[str, DashboardTemplate] = {}
        self._load_all_templates()

    def _load_all_templates(self):
        if not os.path.exists(TEMPLATE_DIR):
            os.makedirs(TEMPLATE_DIR, exist_ok=True)
            self._create_default_templates()
        for fname in sorted(os.listdir(TEMPLATE_DIR)):
            if fname.endswith(".json"):
                filepath = os.path.join(TEMPLATE_DIR, fname)
                tpl = DashboardTemplate(filepath)
                self._templates[tpl.name] = tpl

    def list_templates(self) -> List[Dict[str, Any]]:
        result = []
        for name, tpl in self._templates.items():
            result.append({
                "name": tpl.name,
                "filename": tpl.filename,
                "description": tpl.description,
                "category": tpl.category,
                "refresh_interval": tpl.refresh_interval,
                "panel_count": len(tpl.panels),
            })
        return result

    def get_template(self, name: str) -> Optional[DashboardTemplate]:
        return self._templates.get(name)

    # ===== DATA FETCHER =====

    def _fetch_data(self, db, data_config: Dict) -> Any:
        """Fetch data from the database based on endpoint config.
        Uses the db_manager directly (no HTTP fetch)."""
        endpoint = data_config.get("endpoint", "")
        params = data_config.get("params", {})
        limit = params.get("limit", 20)

        try:
            if endpoint == "/api/stats":
                return self._fetch_stats(db)
            elif endpoint == "/api/machines":
                return self._fetch_machines(db)
            elif endpoint == "/api/threats":
                return self._fetch_threats(db, limit)
            elif endpoint == "/api/events":
                return self._fetch_events(db, limit)
            elif endpoint == "/api/fim":
                return self._fetch_fim(db, limit)
            elif endpoint == "/api/network":
                return self._fetch_network(db, limit)
            elif endpoint == "/api/vulns":
                return self._fetch_vulns(db, limit)
            elif endpoint == "/api/yara":
                return self._fetch_yara(db, limit)
            elif endpoint == "/api/sysmon":
                return self._fetch_sysmon(db, limit)
            elif endpoint == "/api/responses":
                return self._fetch_responses(db, limit)
            else:
                return None
        except Exception as e:
            print(f"[-] Dashboard fetch error for {endpoint}: {e}")
            return None

    def _fetch_stats(self, db):
        try:
            from datetime import datetime, timedelta
            cutoff = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
            cur = db.conn.execute("SELECT COUNT(*) FROM machines")
            total = cur.fetchone()[0]
            cur = db.conn.execute("SELECT COUNT(*) FROM machines WHERE is_online=1")
            online = cur.fetchone()[0]
            cur = db.conn.execute("SELECT COUNT(*) FROM events WHERE received_at > ?", (cutoff,))
            events = cur.fetchone()[0]
            cur = db.conn.execute("SELECT COUNT(*) FROM threat_alerts WHERE received_at > ?", (cutoff,))
            threats = cur.fetchone()[0]
            cur = db.conn.execute("SELECT COUNT(*) FROM fim_events WHERE received_at > ?", (cutoff,))
            fim = cur.fetchone()[0]
            cur = db.conn.execute("SELECT COUNT(*) FROM syslog WHERE received_at > ?", (cutoff,))
            syslog = cur.fetchone()[0]
            cur = db.conn.execute("SELECT COUNT(*) FROM response_results WHERE received_at > ?", (cutoff,))
            responses = cur.fetchone()[0]
            return {
                "total_machines": total,
                "online_machines": online,
                "offline_machines": total - online,
                "events": events,
                "threats": threats,
                "fim_events": fim,
                "syslog": syslog,
                "responses": responses,
            }
        except Exception:
            return {"online_machines": 0, "events": 0, "threats": 0}

    def _fetch_machines(self, db):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, ip_address, platform, version, is_online "
                "FROM machines ORDER BY is_online DESC, last_seen DESC LIMIT 50"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_threats(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, rule_id, rule_name, severity, description, timestamp "
                "FROM threat_alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_events(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, type, subtype, event_id, event_type, source, time, description "
                "FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_fim(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, action, path, time "
                "FROM fim_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_network(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, src_ip, dst_ip, dst_port, protocol, state, timestamp "
                "FROM network_traffic ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_vulns(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, software, version, cve, severity, description, timestamp "
                "FROM vuln_alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_yara(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, rule_name, description, file, timestamp "
                "FROM yara_alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_sysmon(self, db, limit):
        try:
            rows = db.conn.execute("SELECT * FROM events WHERE type='sysmon_event' ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _fetch_responses(self, db, limit):
        try:
            rows = db.conn.execute(
                "SELECT machine_id, hostname, action, status, output, timestamp "
                "FROM response_results ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    # ===== HTML RENDERER =====

    def render_html(self, name: str, db) -> str:
        """Render a dashboard template to full HTML with server-side data embedded."""
        tpl = self.get_template(name)
        if not tpl:
            return '<div class="alert alert-danger">Dashboard template not found: ' + name + '</div>'

        # v4.10 (HIGH-3): escape template-controlled text before interpolation
        import html as _html
        esc_name = _html.escape(str(tpl.name), quote=False)
        esc_desc = _html.escape(str(tpl.description), quote=False)

        # Pre-fetch all panel data
        panel_data_map = {}
        for panel in tpl.panels:
            panel_id = panel.get("id", "")
            data_config = panel.get("data", {})
            panel_data_map[panel_id] = {
                "data": self._fetch_data(db, data_config),
                "config": data_config,
                "type": panel.get("type", "stat"),
            }

        panels_html = ""
        panel_ids = []
        for panel in tpl.panels:
            panel_id = panel.get("id", f"panel_{len(panel_ids)}")
            panel_ids.append(panel_id)
            panel_type = panel.get("type", "stat")
            title = panel.get("title", "")
            size = panel.get("size", {"w": 3, "h": 1})
            panels_html += self._render_panel_html(panel_id, panel_type, title, size, panel_data_map.get(panel_id, {}))

        # Embed panel data as JS object
        data_map_json = {}
        for pid, pd in panel_data_map.items():
            data_map_json[pid] = {
                "data": pd["data"],
                "config": pd["config"],
                "type": pd["type"],
            }

        html = f'''<div class="dashboard-container">
<style>
.dashboard-grid {{
    display: grid;
    grid-template-columns: repeat(12, 1fr);
    gap: 16px;
    padding: 4px;
}}
.dashboard-panel {{
    background: var(--card-dark, #1a2a3a);
    border: 1px solid var(--border-color, #2a3a4a);
    border-radius: 8px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
}}
.dashboard-panel .panel-header {{
    background: rgba(0,0,0,0.2);
    padding: 8px 12px;
    font-size: 12px;
    font-weight: 600;
    color: #eef4f8;
    border-bottom: 1px solid var(--border-color, #2a3a4a);
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.dashboard-panel .panel-body {{
    flex: 1;
    padding: 8px;
    min-height: 60px;
    position: relative;
    overflow: auto;
}}
.dashboard-panel.stat-panel .panel-body {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 12px;
    text-align: center;
}}
.stat-value {{
    font-size: 32px;
    font-weight: 700;
    color: #00d4aa;
    line-height: 1;
}}
.stat-label {{
    font-size: 11px;
    color: #c8d8e8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
}}
.dashboard-table {{
    width: 100%;
    font-size: 11px;
    border-collapse: collapse;
}}
.dashboard-table th {{
    background: rgba(0,0,0,0.3);
    color: #90a4c4;
    padding: 6px 8px;
    text-align: left;
    font-weight: 600;
    font-size: 10px;
    text-transform: uppercase;
}}
.dashboard-table td {{
    padding: 4px 8px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    color: #eef4f8;
}}
.dashboard-table tr:hover td {{
    background: rgba(0,212,170,0.08);
}}
.dashboard-chart-wrapper {{
    position: relative;
    width: 100%;
    height: 100%;
    min-height: 150px;
}}
.error-placeholder {{
    color: #ff6b6b;
    font-size: 11px;
    text-align: center;
    padding: 12px;
}}
@media (max-width: 768px) {{
    .dashboard-grid {{
        grid-template-columns: repeat(6, 1fr);
    }}
}}
</style>
<div class="d-flex justify-content-between align-items-center mb-3">
    <div>
        <h5 style="color:#eef4f8;margin:0;">{esc_name}</h5>
        <small class="text-muted">{esc_desc}</small>
    </div>
    <div>
        <button class="btn btn-sm btn-outline-secondary" onclick="location.reload();" style="font-size:11px;" title="Làm mới">
            <i class="bi bi-arrow-repeat"></i> Làm mới
        </button>
    </div>
</div>
<div class="dashboard-grid">
    {panels_html}
</div>
</div>
<script>
(function() {{
    // Pre-fetched panel data (server-side)
    // v4.11 (CRITICAL-2 FIX): JSON embedded inside <script> must escape <, >, &
    // and U+2028/2029 - json.dumps does NOT escape '<', so a live event field
    // like "</script><script>alert(1)</script>" could break out (stored XSS).
    var DASH_DATA = {_json_script_safe(data_map_json)};
    var chartInstances = {{}};

    // v4.10 (HIGH-3): HTML-escape helper for all innerHTML interpolation
    function esc(s) {{
        return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }}

    function renderAllPanels() {{
        Object.keys(DASH_DATA).forEach(function(panelId) {{
            var pd = DASH_DATA[panelId];
            if (!pd || pd.data === null) {{
                var body = document.getElementById(panelId + '_body');
                if (body) body.innerHTML = '<div class="error-placeholder">Không có dữ liệu</div>';
                return;
            }}
            if (pd.type === 'stat' || pd.type === 'number') {{
                renderStat(panelId, pd.data, pd.config);
            }} else if (pd.type === 'table') {{
                renderTable(panelId, pd.data, pd.config);
            }} else if (pd.type === 'line_chart' || pd.type === 'bar_chart' || pd.type === 'pie_chart') {{
                renderChart(panelId, pd.data, pd.config, pd.type);
            }}
        }});
    }}

    function renderStat(panelId, data, config) {{
        var body = document.getElementById(panelId + '_body');
        if (!body) return;
        var val = data;
        if (config.field) {{
            val = config.field.split('.').reduce(function(o,k) {{ return o != null ? o[k] : null; }}, data);
        }}
        var displayVal = (val != null) ? val : '0';
        if (typeof displayVal === 'number') displayVal = displayVal.toLocaleString();
        // v4.10 (HIGH-3): escape all user-controlled text before innerHTML
        body.innerHTML = '<div class="stat-value">' + esc(displayVal) + '</div><div class="stat-label">' + esc(config.title || '') + '</div>';
    }}

    function renderTable(panelId, data, config) {{
        var body = document.getElementById(panelId + '_body');
        if (!body) return;
        var items = Array.isArray(data) ? data : (data[config.field || 'data'] || data.results || [data]);
        if (!Array.isArray(items) || !items || items.length === 0) {{
            body.innerHTML = '<div style="color:#6a8aaa;font-size:12px;text-align:center;padding:20px;">Chưa có dữ liệu</div>';
            return;
        }}
        var columns = config.columns || (items.length > 0 ? Object.keys(items[0]) : []);
        var html = '<table class="dashboard-table"><thead><tr>';
        columns.forEach(function(col) {{
            html += '<th>' + (typeof col === 'string' ? esc(col) : esc(col.label || col.field || col)) + '</th>';
        }});
        html += '</tr></thead><tbody>';
        items.slice(0, 20).forEach(function(row) {{
            html += '<tr>';
            columns.forEach(function(col) {{
                var fieldName = typeof col === 'string' ? col : (col.field || col.label || col);
                var val = row[fieldName] !== undefined ? row[fieldName] : '';
                var isHtml = false;
                if (fieldName === 'is_online') {{
                    val = (val == 1) ? '<span class="badge bg-success">Online</span>' : '<span class="badge bg-secondary">Offline</span>';
                    isHtml = true;
                }} else if (fieldName === 'severity') {{
                    var sev = String(val).toUpperCase();
                    var cls = sev === 'CRITICAL' ? 'bg-danger' : sev === 'HIGH' ? 'bg-warning text-dark' : 'bg-info';
                    val = '<span class="badge ' + cls + '">' + esc(val) + '</span>';
                    isHtml = true;
                }}
                if (typeof val === 'object' && val !== null) val = JSON.stringify(val);
                // v4.10 (HIGH-3): escape cell values (except safe badge HTML above)
                html += '<td>' + (isHtml ? val : esc(String(val).substring(0, 200))) + '</td>';
            }});
            html += '</tr>';
        }});
        html += '</tbody></table>';
        body.innerHTML = html;
    }}

    function renderChart(panelId, data, config, panelType) {{
        var body = document.getElementById(panelId + '_body');
        if (!body) return;
        var canvasId = panelId + '_chart';
        // Ensure canvas exists
        if (!body.querySelector('#' + canvasId)) {{
            body.innerHTML = '<div class="dashboard-chart-wrapper"><canvas id="' + canvasId + '"></canvas></div>';
        }}
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;
        var ctx = canvas.getContext('2d');
        if (chartInstances[panelId]) chartInstances[panelId].destroy();

        var items = Array.isArray(data) ? data : (data[config.field || 'data'] || data.results || [data]);
        if (!Array.isArray(items)) items = [items];
        if (!items.length) {{
            body.innerHTML = '<div style="color:#6a8aaa;font-size:12px;text-align:center;padding:20px;">Chưa có dữ liệu</div>';
            return;
        }}

        var labels = items.map(function(item) {{ return item[config.label_field || 'name'] || ''; }});
        var values = items.map(function(item) {{ return Number(item[config.value_field || 'value']) || 0; }});
        var chartType = panelType === 'line_chart' ? 'line' : (panelType === 'pie_chart' ? 'doughnut' : 'bar');
        var colors = {json.dumps(self.CHART_COLORS)};

        var datasets;
        if (chartType === 'doughnut') {{
            datasets = [{{
                data: values,
                backgroundColor: colors.slice(0, values.length),
                borderColor: '#0f1923',
                borderWidth: 2,
            }}];
        }} else {{
            datasets = [{{
                label: config.title || 'Data',
                data: values,
                backgroundColor: (chartType === 'bar' ? colors[0] : colors[0]) + '80',
                borderColor: colors[0],
                borderWidth: 2,
                tension: 0.3,
                fill: chartType === 'line',
            }}];
        }}

        chartInstances[panelId] = new Chart(ctx, {{
            type: chartType,
            data: {{ labels: labels, datasets: datasets }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: chartType === 'doughnut',
                        position: 'bottom',
                        labels: {{ color: '#90a4c4', font: {{ size: 10 }}, padding: 8 }}
                    }}
                }},
                scales: chartType === 'doughnut' ? {{}} : {{
                    x: {{
                        ticks: {{ color: '#6a8aaa', font: {{ size: 10 }}, maxRotation: 45 }},
                        grid: {{ color: 'rgba(255,255,255,0.05)' }}
                    }},
                    y: {{
                        ticks: {{ color: '#6a8aaa', font: {{ size: 10 }} }},
                        grid: {{ color: 'rgba(255,255,255,0.05)' }},
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    }}

    // Render all panels on page load
    if (typeof Chart !== 'undefined') {{
        setTimeout(renderAllPanels, 100);
    }} else {{
        // Wait for Chart.js CDN
        var check = setInterval(function() {{
            if (typeof Chart !== 'undefined') {{
                clearInterval(check);
                renderAllPanels();
            }}
        }}, 200);
    }}
}})();
</script>'''
        return html

    def _render_panel_html(self, panel_id: str, panel_type: str, title: str, size: Dict, panel_data: Dict) -> str:
        """Render the HTML container for a single panel."""
        import html as _html
        # v4.10 (HIGH-3): escape panel title before interpolation
        title_safe = _html.escape(str(title), quote=False)
        w = size.get("w", 3)
        h = size.get("h", 1)
        css_class = "stat-panel" if panel_type in ("stat", "number") else ""

        # For stat panels, render the data directly (no JS needed)
        inner = '<div class="loading-placeholder"><div class="spinner-border spinner-border-sm text-secondary me-2" role="status"></div></div>'
        if panel_type in ("stat", "number") and panel_data.get("data") is not None:
            data = panel_data.get("data", {})
            config = panel_data.get("config", {})
            field = config.get("field", "")
            val = data if not field else data.get(field, "0")
            if isinstance(val, (int, float)):
                val = f"{val:,}"
            val_safe = _html.escape(str(val or "0"), quote=False)
            inner = f'<div class="stat-value">{val_safe}</div><div class="stat-label">{title_safe}</div>'

        return f'''
<div class="dashboard-panel {css_class}" style="grid-column: span {w}; grid-row: span {h};" id="{panel_id}">
    <div class="panel-header"><span>{title_safe}</span></div>
    <div class="panel-body" id="{panel_id}_body">{inner}</div>
</div>'''

    def _create_default_templates(self):
        """Create default dashboard templates with server-side compatible endpoints."""
        overview = {
            "name": "Tổng quan hệ thống",
            "description": "Dashboard mặc định - tổng quan toàn bộ hệ thống",
            "refresh_interval": 60,
            "category": "monitoring",
            "panels": [
                {
                    "id": "stat_online",
                    "type": "stat",
                    "title": "Máy Online",
                    "size": {"w": 2, "h": 1},
                    "data": {"endpoint": "/api/stats", "field": "online_machines"}
                },
                {
                    "id": "stat_offline",
                    "type": "stat",
                    "title": "Máy Offline",
                    "size": {"w": 2, "h": 1},
                    "data": {"endpoint": "/api/stats", "field": "offline_machines"}
                },
                {
                    "id": "stat_events",
                    "type": "stat",
                    "title": "Events 24h",
                    "size": {"w": 2, "h": 1},
                    "data": {"endpoint": "/api/stats", "field": "events"}
                },
                {
                    "id": "stat_threats",
                    "type": "stat",
                    "title": "Threats 24h",
                    "size": {"w": 2, "h": 1},
                    "data": {"endpoint": "/api/stats", "field": "threats"}
                },
                {
                    "id": "stat_fim",
                    "type": "stat",
                    "title": "FIM Events 24h",
                    "size": {"w": 2, "h": 1},
                    "data": {"endpoint": "/api/stats", "field": "fim_events"}
                },
                {
                    "id": "stat_responses",
                    "type": "stat",
                    "title": "Responses 24h",
                    "size": {"w": 2, "h": 1},
                    "data": {"endpoint": "/api/stats", "field": "responses"}
                },
                {
                    "id": "table_machines",
                    "type": "table",
                    "title": "Danh sách máy trạm",
                    "size": {"w": 6, "h": 2},
                    "data": {
                        "endpoint": "/api/machines",
                        "columns": [
                            {"field": "hostname", "label": "Hostname"},
                            {"field": "ip_address", "label": "IP"},
                            {"field": "platform", "label": "OS"},
                            {"field": "version", "label": "Version"},
                            {"field": "is_online", "label": "Online"}
                        ]
                    }
                },
                {
                    "id": "table_threats",
                    "type": "table",
                    "title": "Threats gần đây",
                    "size": {"w": 6, "h": 2},
                    "data": {
                        "endpoint": "/api/threats",
                        "params": {"limit": 10},
                        "columns": [
                            {"field": "hostname", "label": "Hostname"},
                            {"field": "rule_name", "label": "Rule"},
                            {"field": "severity", "label": "Severity"},
                            {"field": "description", "label": "Description"},
                            {"field": "timestamp", "label": "Time"}
                        ]
                    }
                }
            ]
        }
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
        with open(os.path.join(TEMPLATE_DIR, "overview.json"), "w", encoding="utf-8") as f:
            json.dump(overview, f, indent=2, ensure_ascii=False)
        print("[Dashboard] Created default template: overview.json")


# Singleton
_engine: Optional[TemplateEngine] = None


def get_engine() -> TemplateEngine:
    global _engine
    if _engine is None:
        _engine = TemplateEngine()
    return _engine