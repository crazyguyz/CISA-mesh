"""
API Assets - v4.4: Quản lý tài sản (máy tính, màn hình)
REST endpoints cho danh sách tài sản và lịch sử thay đổi.
"""
import json
from flask import Blueprint, request, jsonify

assets_bp = Blueprint("api_assets", __name__)


def init_assets_api(app, db):
    """Register asset management routes on the Flask app."""

    @app.route("/api/assets/computers")
    def api_assets_computers():
        search = request.args.get("search", "").strip()
        limit = int(request.args.get("limit", 200))
        rows = db.get_asset_computers(search=search, limit=limit) if db else []
        return jsonify({"computers": rows})

    @app.route("/api/assets/monitors")
    def api_assets_monitors():
        search = request.args.get("search", "").strip()
        limit = int(request.args.get("limit", 200))
        rows = db.get_asset_monitors(search=search, limit=limit) if db else []
        return jsonify({"monitors": rows})

    @app.route("/api/assets/changes")
    def api_assets_changes():
        limit = int(request.args.get("limit", 100))
        unresolved_only = request.args.get("unresolved", "0") == "1"
        rows = db.get_asset_change_log(limit=limit, unresolved_only=unresolved_only) if db else []
        return jsonify({"changes": rows})

    @app.route("/api/assets/changes/<int:change_id>/resolve", methods=["POST"])
    def api_assets_resolve_change(change_id):
        resolved_by = request.json.get("resolved_by", "admin") if request.json else "admin"
        ok = db.resolve_asset_change(change_id, resolved_by) if db else False
        return jsonify({"success": ok})

    @app.route("/api/assets/unresolved_count")
    def api_assets_unresolved_count():
        """Return count of unresolved asset changes for badge display."""
        if not db:
            return jsonify({"count": 0})
        try:
            result = db._execute(
                "SELECT COUNT(*) as cnt FROM assets_change_log WHERE is_resolved=FALSE",
                fetch=True
            )
            return jsonify({"count": result.get("cnt", 0) if result else 0})
        except Exception:
            return jsonify({"count": 0})

    @app.route("/api/assets/export")
    def api_assets_export():
        """Export all assets as Excel file with 2 sheets."""
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
            from io import BytesIO
        except ImportError:
            return jsonify({"error": "openpyxl not installed. Run: pip install openpyxl"}), 500

        wb = openpyxl.Workbook()
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="1a3a5a", end_color="1a3a5a", fill_type="solid")
        thin_border = Border(
            left=Side(style='thin'), right=Side(style='thin'),
            top=Side(style='thin'), bottom=Side(style='thin')
        )

        # Sheet 1: May tinh
        ws1 = wb.active
        ws1.title = "May tinh"
        pc_headers = ["Ma TS", "May tinh", "Nguoi dung", "MNSV", "Email",
                       "Mainboard", "Mainboard Serial", "CPU", "Cores", "Clock MHz",
                       "RAM (GB)", "O cung", "GPU", "Man hinh", "OS", "Online", "Cap nhat"]
        for col, h in enumerate(pc_headers, 1):
            cell = ws1.cell(row=1, column=col, value=h)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')
            cell.border = thin_border

        computers = db.get_asset_computers(limit=5000) if db else []
        for r, c in enumerate(computers, 2):
            row_data = [
                c.get('display_id') or c.get('asset_id', '-'),
                c.get('hostname') or c.get('machine_id', '-'),
                c.get('user_name', '-'),
                c.get('employee_id', '-'),
                c.get('email', '-'),
                (c.get('motherboard_manufacturer','') + ' ' + c.get('motherboard_product','')).strip() or '-',
                c.get('motherboard_serial', '-'),
                c.get('cpu_name', '-'),
                c.get('cpu_cores', 0),
                c.get('cpu_max_clock_mhz', 0),
                c.get('ram_total_gb', 0),
                '',
                '',
                '',
                (c.get('os_name','') + ' ' + c.get('os_version','')).strip() or '-',
                'Online' if c.get('is_online') else 'Offline',
                str(c.get('updated_at', ''))[:19],
            ]
            # Parse disks
            disks = c.get('disks_json', [])
            if isinstance(disks, str):
                try: disks = json.loads(disks)
                except: disks = []
            row_data[11] = '; '.join([f"{d.get('model','?')} ({d.get('size_gb','?')}GB {d.get('interface','')})" for d in disks]) or '-'
            # Parse GPU
            gpus = c.get('gpu_json', [])
            if isinstance(gpus, str):
                try: gpus = json.loads(gpus)
                except: gpus = []
            row_data[12] = '; '.join([f"{g.get('name','?')} ({g.get('ram_gb','?')}GB)" for g in gpus]) or '-'
            # Parse monitors
            monitors_json = c.get('monitors_json', [])
            if isinstance(monitors_json, str):
                try: monitors_json = json.loads(monitors_json)
                except: monitors_json = []
            row_data[13] = '; '.join([f"{m.get('manufacturer','')} {m.get('name','')} ({m.get('resolution','')})" for m in monitors_json]) or '-'
            for col, val in enumerate(row_data, 1):
                cell = ws1.cell(row=r, column=col, value=val)
                cell.border = thin_border

        # Sheet 2: Man hinh
        ws2 = wb.create_sheet("Man hinh")
        mn_headers = ["Ma TS", "Ten man hinh", "Hang", "Do phan giai", "Loai", "May tinh ket noi", "Nguoi dung", "Cap nhat"]
        for col, h in enumerate(mn_headers, 1):
            cell = ws2.cell(row=1, column=col, value=h)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')
            cell.border = thin_border

        monitors = db.get_asset_monitors(limit=5000) if db else []
        for r, m in enumerate(monitors, 2):
            row_data = [
                m.get('display_id') or m.get('asset_id', '-'),
                m.get('name', '-'),
                m.get('manufacturer', '-'),
                m.get('resolution', '-'),
                m.get('model_type', 'Monitor'),
                m.get('computer_hostname', 'Chua gan'),
                m.get('computer_user', '-'),
                str(m.get('updated_at', ''))[:19],
            ]
            for col, val in enumerate(row_data, 1):
                cell = ws2.cell(row=r, column=col, value=val)
                cell.border = thin_border

        # Auto-width
        for ws in [ws1, ws2]:
            for col in ws.columns:
                max_len = 0
                for cell in col:
                    try:
                        max_len = max(max_len, len(str(cell.value or '')))
                    except:
                        pass
                ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 50)

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        from flask import send_file
        timestamp = __import__('datetime').datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'GIAM-SAT_TaiSan_{timestamp}.xlsx'
        )

    print("[*] API Assets registered: /api/assets/*")
