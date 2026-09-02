"""
Reporting Engine for GIAM-SAT Server v1.6.0
Generates automated PDF/HTML reports:
- Weekly/Monthly security summary
- Threat analysis
- Vulnerability breakdown
- SCA compliance score
"""
import os
import html
import json
import threading
from datetime import datetime, timedelta


class ReportingEngine:
    """Generates periodic security reports in HTML/PDF format."""

    def __init__(self, db_manager=None):
        self.db = db_manager
        self.report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
        os.makedirs(self.report_dir, exist_ok=True)
        # v5.0.4 R9: the weekly/daily schedulers both write report_state.json -
        # serialize the read-modify-write so a lost update can't double-report.
        self._state_lock = threading.Lock()

    def generate_html_report(self, start_date=None, end_date=None, report_type="daily"):
        """Generate a comprehensive HTML report."""
        if not start_date:
            start_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        if not end_date:
            end_date = datetime.now().strftime("%Y-%m-%d")

        # Gather stats from DB
        stats = self._gather_stats(start_date, end_date)
        machines = stats.get("machines", [])
        events = stats.get("events", [])
        threats = stats.get("threats", [])
        vulns = stats.get("vulns", [])
        sca = stats.get("sca", [])
        yara = stats.get("yara", [])

        total_machines = len(machines)
        online_machines = sum(1 for m in machines if m.get("is_online"))
        total_events = len(events)
        total_threats = len(threats)
        total_vulns = len(vulns)
        critical_threats = sum(1 for t in threats if t.get("severity") == "CRITICAL")
        high_threats = sum(1 for t in threats if t.get("severity") == "HIGH")
        sca_pass = sum(1 for s in sca if s.get("status") == "PASS")
        sca_fail = sum(1 for s in sca if s.get("status") == "FAIL")
        sca_total = len(sca)

        # v5.0.4 R9 (MEDIUM-1): every agent/intel-controlled value is HTML-escaped
        _esc = lambda v: html.escape(str(v if v is not None else ''), quote=True)
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
    <title>GIAM-SAT Security Report - {report_type.upper()}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a73e8; border-bottom: 3px solid #1a73e8; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 25px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px; text-align: center; }}
        .card.critical {{ background: linear-gradient(135deg, #ff416c, #ff4b2b); }}
        .card.success {{ background: linear-gradient(135deg, #00b09b, #96c93d); }}
        .card.warning {{ background: linear-gradient(135deg, #f2994a, #f2c94c); }}
        .card h3 {{ margin: 0; font-size: 28px; }}
        .card p {{ margin: 5px 0 0; font-size: 12px; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background: #1a73e8; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f0f4ff; }}
        .severity-CRITICAL {{ color: #ff0000; font-weight: bold; }}
        .severity-HIGH {{ color: #ff6600; font-weight: bold; }}
        .severity-MEDIUM {{ color: #cc9900; }}
        .footer {{ text-align: center; margin-top: 30px; color: #999; font-size: 12px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
        .badge-pass {{ background: #d4edda; color: #155724; }}
        .badge-fail {{ background: #f8d7da; color: #721c24; }}
        .badge-warn {{ background: #fff3cd; color: #856404; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>GIAM-SAT Security Report</h1>
        <p><strong>Report Type:</strong> {report_type.upper()} | <strong>Period:</strong> {start_date} → {end_date}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>Executive Summary</h2>
        <div class="summary-cards">
            <div class="card"><h3>{total_machines}</h3><p>Total Machines ({online_machines} online)</p></div>
            <div class="card"><h3>{total_events}</h3><p>Security Events</p></div>
            <div class="card critical"><h3>{total_threats}</h3><p>Threat Alerts ({critical_threats} critical)</p></div>
            <div class="card warning"><h3>{total_vulns}</h3><p>Vulnerabilities</p></div>
        </div>

        <h2>Threat Alerts ({total_threats})</h2>
"""
        # Threat table
        if threats:
            html += """<table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Host</th><th>Description</th></tr>"""
            for t in threats[:50]:
                sev_class = f"severity-{t.get('severity','LOW')}"
                html += f"""<tr><td>{_esc(t.get('timestamp','')[:16])}</td><td class="{_esc(sev_class)}">{_esc(t.get('severity',''))}</td><td>{_esc(t.get('rule_name',''))}</td><td>{_esc(t.get('hostname',''))}</td><td>{_esc(t.get('description','')[:80])}</td></tr>"""
            html += "</table>"
        else:
            html += "<p style='color:#155724;background:#d4edda;padding:10px;border-radius:4px;'>✓ No threats detected in this period</p>"

        # Vulnerabilities
        html += f"<h2>Vulnerabilities ({total_vulns})</h2>"
        if vulns:
            html += """<table><tr><th>CVE</th><th>Severity</th><th>Software</th><th>Host</th></tr>"""
            for v in vulns[:50]:
                sev_class = f"severity-{v.get('severity','LOW')}"
                html += f"""<tr><td>{_esc(v.get('cve',''))}</td><td class="{_esc(sev_class)}">{_esc(v.get('severity',''))}</td><td>{_esc(v.get('software',''))} {_esc(v.get('version',''))}</td><td>{_esc(v.get('hostname',''))}</td></tr>"""
            html += "</table>"
        else:
            html += "<p style='color:#155724;background:#d4edda;padding:10px;border-radius:4px;'>✓ No vulnerabilities detected</p>"

        # SCA Compliance
        html += f"<h2>SCA Compliance (Pass: {sca_pass} / Fail: {sca_fail})</h2>"
        compliance_pct = int(sca_pass / sca_total * 100) if sca_total > 0 else 100
        bar_color = "#00b09b" if compliance_pct >= 80 else "#f2994a" if compliance_pct >= 50 else "#ff416c"
        html += f"""<div style="background:#eee;border-radius:20px;height:30px;margin:10px 0;">
            <div style="background:{bar_color};width:{compliance_pct}%;height:100%;border-radius:20px;text-align:center;color:white;line-height:30px;font-weight:bold;">{compliance_pct}% Compliant</div>
        </div>"""
        if sca:
            html += """<table><tr><th>Check ID</th><th>Title</th><th>Status</th><th>Severity</th></tr>"""
            for s in sca[:30]:
                badge = "badge-pass" if s.get('status') == 'PASS' else ("badge-fail" if s.get('status') == 'FAIL' else "badge-warn")
                html += f"""<tr><td>{_esc(s.get('check_id',''))}</td><td>{_esc(s.get('title',''))}</td><td><span class="badge {_esc(badge)}">{_esc(s.get('status',''))}</span></td><td>{_esc(s.get('severity',''))}</td></tr>"""
            html += "</table>"

        # YARA
        html += f"<h2>Malware Alerts ({len(yara)})</h2>"
        if yara:
            html += """<table><tr><th>Time</th><th>Rule</th><th>File</th><th>Host</th></tr>"""
            for y in yara[:20]:
                html += f"""<tr><td>{_esc(y.get('timestamp','')[:16])}</td><td>{_esc(y.get('rule_name',''))}</td><td>{_esc(y.get('file','')[:60])}</td><td>{_esc(y.get('hostname',''))}</td></tr>"""
            html += "</table>"
        else:
            html += "<p style='color:#155724;background:#d4edda;padding:10px;border-radius:4px;'>✓ No malware detected</p>"

        html += f"""
        <div class="footer">
            <p>GIAM-SAT v1.6.0 - Automated Security Report | Generated by Reporting Engine</p>
            <p>This report is confidential and intended for authorized security personnel only.</p>
        </div>
    </div>
</body>
</html>"""

        # Save to file
        filename = f"giamsat_report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.report_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        # v5.0.4 (Phase3 B5): record last successful run so a missed schedule can catch up
        try:
            self._save_report_state(report_type, datetime.now().strftime("%Y-%m-%d"))
        except Exception:
            pass

        print(f"[*] Report generated: {filepath}")
        return filepath

    def _gather_stats(self, start_date, end_date):
        """Gather statistics from database."""
        stats = {
            "machines": [], "events": [], "threats": [],
            "vulns": [], "sca": [], "yara": [],
        }
        if self.db:
            try:
                stats["machines"] = self.db.get_machines()
                stats["events"] = self.db.get_events(limit=500) or []
                stats["threats"] = self.db.get_threat_alerts(limit=100) or []
                stats["vulns"] = self.db.get_vuln_alerts(limit=100) or []
                stats["yara"] = self.db.get_yara_alerts(limit=50) or []
                if hasattr(self.db, "get_sca_events"):
                    stats["sca"] = self.db.get_sca_events(limit=100) or []
            except Exception as e:
                print(f"[-] Stats collection error: {e}")
        return stats

    def schedule_weekly_report(self):
        """Start a background thread that generates a weekly report.
        v5.0.4 (Phase3 B5): catches up if the server was down at the scheduled
        time (state persisted in server/data/report_state.json)."""
        def weekly():
            import time
            while True:
                now = datetime.now()
                # Run every Monday at 08:00 (+ catch-up)
                if now.weekday() == 0 and now.hour == 8 and now.minute < 5:
                    try:
                        start = (now - timedelta(days=7)).strftime("%Y-%m-%d")
                        end = now.strftime("%Y-%m-%d")
                        self.generate_html_report(start, end, "weekly")
                    except Exception as e:
                        print(f"[-] Weekly report error: {e}")
                else:
                    try:
                        state = self._load_report_state()
                        if state.get("weekly") and state.get("weekly") < (now - timedelta(days=8)).strftime("%Y-%m-%d"):
                            print("[*] Weekly report catch-up (server was down)")
                            self.generate_html_report((now - timedelta(days=7)).strftime("%Y-%m-%d"),
                                                       now.strftime("%Y-%m-%d"), "weekly")
                    except Exception as e:
                        print(f"[-] Weekly catch-up error: {e}")
                time.sleep(300)

        t = threading.Thread(target=weekly, daemon=True)
        t.start()
        print("[*] Weekly report scheduler started (Mon 08:00 + catch-up)")

    def _load_report_state(self):
        import json as _j
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "report_state.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return _j.load(f)
        except Exception:
            return {}

    def _save_report_state(self, key, value):
        import json as _j
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "report_state.json")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with self._state_lock:  # v5.0.4 R9: atomic read-modify-write
                state = self._load_report_state()
                state[key] = value
                with open(path, "w", encoding="utf-8") as f:
                    _j.dump(state, f)
        except Exception:
            pass

    def schedule_daily_report(self):
        """Start a background thread that generates a daily report.
        v5.0.4 (Phase3 B5): catch-up if server was down at 07:00."""
        def daily():
            import time
            while True:
                now = datetime.now()
                if now.hour == 7 and now.minute < 5:
                    try:
                        start = (now - timedelta(days=1)).strftime("%Y-%m-%d")
                        end = now.strftime("%Y-%m-%d")
                        self.generate_html_report(start, end, "daily")
                    except Exception as e:
                        print(f"[-] Daily report error: {e}")
                else:
                    try:
                        state = self._load_report_state()
                        if state.get("daily") and state.get("daily") < (now - timedelta(days=2)).strftime("%Y-%m-%d"):
                            print("[*] Daily report catch-up (server was down)")
                            self.generate_html_report((now - timedelta(days=1)).strftime("%Y-%m-%d"),
                                                       now.strftime("%Y-%m-%d"), "daily")
                    except Exception as e:
                        print(f"[-] Daily catch-up error: {e}")
                time.sleep(300)

        t = threading.Thread(target=daily, daemon=True)
        t.start()
        print("[*] Daily report scheduler started (07:00 + catch-up)")

    def generate_pdf_report(self, start_date=None, end_date=None, report_type="daily"):
        """Generate PDF version of report. Requires wkhtmltopdf or weasyprint."""
        html_path = self.generate_html_report(start_date, end_date, report_type)
        pdf_path = html_path.replace(".html", ".pdf")
        try:
            import subprocess
            subprocess.run(["wkhtmltopdf", html_path, pdf_path], capture_output=True, timeout=30)
            if os.path.exists(pdf_path):
                return pdf_path
        except Exception:
            pass
        try:
            from weasyprint import HTML
            HTML(filename=html_path).write_pdf(pdf_path)
            return pdf_path
        except ImportError:
            pass
        print("[!] PDF generation requires wkhtmltopdf or weasyprint")
        return html_path