"""GIAM-SAT v5.0.4 (Phase3 improvement #3): user-defined watchlist API.

  GET  /api/watchlist                     list items
  POST /api/watchlist                     add/update one indicator
  POST /api/watchlist/import              bulk add (json items or raw text lines)
  POST /api/watchlist/<id>/toggle         enable/disable
  DELETE /api/watchlist/<id>              remove
  POST /api/watchlist/push-intel          export ip/domain items to the local
                                          threat-intel file (GIAMSAT_INTEL_FILE)

Matching runs in watchlist_matcher (started by server_core) and raises
threat alert IOC-WATCH-001 per indicator when it appears in any ingested row.
"""

import json
import os
from flask import request, jsonify
from .api_common import check_auth

_TYPES = ("ip", "domain", "hash", "url")


def register(app, core):
    @app.route("/api/watchlist")
    def api_watchlist_list():
        _, err, code = check_auth("api")
        if err: return err, code
        en = request.args.get("enabled")
        enabled = None
        if en is not None:
            enabled = str(en).lower() in ("1", "true", "yes", "on")
        rows = core.db.list_watchlist(enabled=enabled) if hasattr(core.db, "list_watchlist") else []
        out = [dict(r) for r in rows]
        return jsonify({"items": out, "count": len(out)})

    @app.route("/api/watchlist", methods=["POST"])
    def api_watchlist_add():
        username, err, code = check_auth("command")
        if err: return err, code
        if not hasattr(core.db, "add_watchlist"):
            return jsonify({"success": False, "error": "unsupported backend"}), 500
        d = request.json or {}
        ind = (d.get("indicator") or "").strip()
        if not ind:
            return jsonify({"success": False, "error": "indicator required"}), 400
        typ = (d.get("type") or "").strip().lower()
        if typ not in _TYPES:
            from watchlist_matcher import WatchlistMatcher
            typ = WatchlistMatcher._auto_type(ind)
        wl_id, created = core.db.add_watchlist(
            ind, type=typ, label=d.get("label", ""), severity=d.get("severity", "HIGH"),
            source=d.get("source", "manual"), created_by=username, note=d.get("note", ""))
        if wl_id is None:
            return jsonify({"success": False, "error": "invalid indicator"}), 400
        core.db.insert_audit_log(username, "watchlist_add",
                                 f"{'Add' if created else 'Update'} watch {typ}:{ind}", request.remote_addr)
        return jsonify({"success": True, "id": wl_id, "created": created, "type": typ})


    @app.route("/api/watchlist/import", methods=["POST"])
    def api_watchlist_import():
        username, err, code = check_auth("command")
        if err: return err, code
        if not hasattr(core.db, "add_watchlist"):
            return jsonify({"success": False, "error": "unsupported backend"}), 500
        d = request.json or {}
        items = []
        if d.get("items"):
            items = d.get("items") or []
        elif d.get("text"):
            text = str(d.get("text") or "")
            for line in text.splitlines():
                v = line.strip()
                if v and not v.startswith("#"):
                    items.append({"indicator": v})
        from watchlist_matcher import WatchlistMatcher
        added = updated = skipped = 0
        for it in items:
            ind = str(it.get("indicator") or "").strip()
            if not ind:
                continue
            typ = str(it.get("type") or "").lower()
            if typ not in _TYPES:
                typ = WatchlistMatcher._auto_type(ind)
            wl_id, created = core.db.add_watchlist(
                ind, type=typ, label=it.get("label", ""), severity=it.get("severity", "HIGH"),
                source="import", created_by=username, note=it.get("note", ""))
            if wl_id is None:
                skipped += 1
            elif created:
                added += 1
            else:
                updated += 1
        core.db.insert_audit_log(username, "watchlist_import", f"added {added}, updated {updated}", request.remote_addr)
        return jsonify({"success": True, "added": added, "updated": updated, "skipped": skipped})

    @app.route("/api/watchlist/<int:wl_id>/toggle", methods=["POST"])
    def api_watchlist_toggle(wl_id):
        _, err, code = check_auth("command")
        if err: return err, code
        enabled = bool((request.json or {}).get("enabled", True))
        ok = core.db.toggle_watchlist(wl_id, enabled) if hasattr(core.db, "toggle_watchlist") else False
        return jsonify({"success": ok})

    @app.route("/api/watchlist/<int:wl_id>", methods=["DELETE"])
    def api_watchlist_delete(wl_id):
        username, err, code = check_auth("command")
        if err: return err, code
        ok = core.db.delete_watchlist(wl_id) if hasattr(core.db, "delete_watchlist") else False
        if ok:
            core.db.insert_audit_log(username, "watchlist_delete", f"removed watch #{wl_id}", request.remote_addr)
        return jsonify({"success": ok})

    @app.route("/api/watchlist/push-intel", methods=["POST"])
    def api_watchlist_push_intel():
        """Export ip/domain items into the local threat-intel file so the intel
        enrichment (threat_intel_server) tags matches as LOCAL:... in every alert
        description - watchlist -> intel file -> alert enrichment (closed loop)."""
        _, err, code = check_auth("command")
        if err: return err, code
        if not hasattr(core.db, "list_watchlist"):
            return jsonify({"success": False, "error": "unsupported backend"}), 500
        try:
            path = os.environ.get("GIAMSAT_INTEL_FILE", "")
            if not path:
                return jsonify({"success": False,
                                "error": "GIAMSAT_INTEL_FILE env not set (server/.env)"}), 400
            cur = {"ips": {}, "domains": {}}
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    cur = json.load(f) or cur
            n_ip = n_dom = 0
            for r in (core.db.list_watchlist() or []):
                ind = str(r.get("indicator") or "").strip()
                typ = str(r.get("type") or "")
                sev = str(r.get("severity") or "HIGH")
                if not ind:
                    continue
                if typ == "ip" and "." in ind:
                    key = "ips"
                    if ind not in cur.setdefault(key, {}):
                        n_ip += 1
                    cur[key][ind] = f"watch:{sev}"
                elif typ == "domain":
                    key = "domains"
                    if ind not in cur.setdefault(key, {}):
                        n_dom += 1
                    cur[key][ind] = f"watch:{sev}"
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cur, f, ensure_ascii=False, indent=2)
            return jsonify({"success": True, "ips": n_ip, "domains": n_dom, "path": path})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500
