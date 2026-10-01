"""GIAM-SAT fleet operations module - v5.0.8 (Phase C: triển khai an toàn + sức khỏe).

Three admin problems this solves, all of which used to mean SSH/RDP and hope:

1. ROLLOUT WITH CANARY + HEALTH GATE. The old "push update" endpoint blasted the
   whole group at once and reported nothing afterwards. `plan_waves()` builds a
   canary -> 10% -> 100% plan, `wave_health()` reads the real `machines.version`
   values and `health_gate()` refuses to promote the next wave while agents have
   not reported back, so a bad build cannot reach the whole fleet.

2. ROLLBACK. The agent keeps `GiamSatAgent.exe.bak` only until the new file boots,
   so a rollback cannot come from the endpoint. The honest implementation: halt
   the rollout, stop promoting, mark untouched machines as skipped and - when the
   server still has an archived build of the previous version - push that version
   back to the machines already updated.

3. INGEST / FLEET HEALTH. "Why is this machine missing?" is usually one of: agent
   silent, agent outdated, log source disabled (Sysmon/auditpol), or the server
   is REJECTING the messages (wrong PSK -> `unauthenticated ... ignored`, unknown
   message type). The last one only ever appeared in the server log - now it is
   counted and shown next to the machine list.

Pure logic lives here (no Flask, no DB) so it is unit-testable; the DB/HTTP/agent
plumbing is in db_*.py, tcp_server.py and api/api_fleet.py.
"""

import json
import math
from datetime import datetime, timedelta

DEFAULT_WAVES = (1, 10, 100)     # percent per wave (wave 0 = canary)
MIN_WAVE_SIZE = 1
HEALTH_MIN_PCT = 90.0            # a wave must be >= 90% updated ...
HEALTH_MAX_FAILED = 0            # ... with zero failures to auto-advance


def parse_waves(value, default=DEFAULT_WAVES):
    """Accept '1,10,100' / [1, 10, 100] / None -> tuple of positive percents."""
    if value is None or value == "":
        return tuple(default)
    items = [x.strip() for x in value.split(",")] if isinstance(value, str) else list(value)
    out = []
    for item in items:
        try:
            pct = float(item)
        except (TypeError, ValueError):
            continue
        if pct > 0:
            out.append(pct)
    if not out:
        return tuple(default)
    if out[-1] < 100:
        out[-1] = 100.0          # the last wave always covers the rest
    return tuple(out)


def plan_waves(machine_ids, waves=DEFAULT_WAVES, canary_first=True):
    """Split the fleet into waves; the canary is always at least one machine.

    Every machine appears exactly once and the last wave absorbs the remainder.
    Returns [{'index': 0, 'pct': 1.0, 'machines': [...]}, ...].
    """
    ids = [m for m in (machine_ids or []) if m]
    total = len(ids)
    if total == 0:
        return []
    pcts = parse_waves(waves)
    plan, cursor = [], 0
    for index, pct in enumerate(pcts):
        if cursor >= total:
            break
        want = max(MIN_WAVE_SIZE, int(math.ceil(total * float(pct) / 100.0)))
        last = index == len(pcts) - 1
        chunk = ids[cursor:] if last else ids[cursor:cursor + want]
        if not chunk:
            continue
        plan.append({"index": len(plan), "pct": float(pct), "machines": list(chunk)})
        cursor += len(chunk)
    if cursor < total and plan:            # safety net: never leave one out
        plan[-1]["machines"].extend(ids[cursor:])
    return plan


def wave_health(targets, wave=None):
    """Summarise one wave (or all targets) -> counts + updated percentage."""
    rows = [t for t in (targets or []) if wave is None or int(t.get("wave", 0)) == int(wave)]
    counts = {"total": len(rows), "updated": 0, "failed": 0, "pending": 0, "requested": 0}
    for row in rows:
        status = str(row.get("status") or "pending").lower()
        if status == "updated":
            counts["updated"] += 1
        elif status in ("failed", "error"):
            counts["failed"] += 1
        elif status == "requested":
            counts["requested"] += 1
        else:
            counts["pending"] += 1
    counts["finished"] = counts["updated"] + counts["failed"]
    counts["updated_pct"] = (round(100.0 * counts["updated"] / counts["total"], 1)
                             if counts["total"] else 0.0)
    return counts


def health_gate(counts, min_pct=HEALTH_MIN_PCT, max_failed=HEALTH_MAX_FAILED):
    """(ok, reason) - may we promote the next wave?"""
    if not counts or not counts.get("total"):
        return False, "không có máy nào trong đợt"
    if counts.get("failed", 0) > max_failed:
        return False, "%d máy cập nhật lỗi (giới hạn %d)" % (counts["failed"], max_failed)
    if counts.get("updated_pct", 0.0) < float(min_pct):
        return False, ("mới %.1f%% máy báo phiên bản mới (cần >= %.1f%%)"
                       % (counts.get("updated_pct", 0.0), float(min_pct)))
    return True, "đợt khỏe (%.1f%% cập nhật, %d lỗi)" % (counts.get("updated_pct", 0.0),
                                                       counts.get("failed", 0))


def reconcile_targets(targets, machines, target_version):
    """Derive each target's status from the live `machines.version` values.

    'updated' as soon as the agent reports the target version, otherwise the
    previous status is kept (an offline machine is NOT a failure). Returns the
    list of rows whose status actually changed, ready to be written back.
    """
    by_id = {m.get("machine_id"): m for m in (machines or [])}
    changed = []
    for row in targets or []:
        mid = row.get("machine_id")
        live = str((by_id.get(mid) or {}).get("version") or "")
        status = str(row.get("status") or "pending").lower()
        new_status = "updated" if (live and live == str(target_version or "")) else status
        if new_status != status:
            changed.append({"machine_id": mid, "status": new_status, "version": live})
    return changed


def machine_health_rows(machines, heartbeat_map=None, server_version="", now=None,
                        silent_minutes=10):
    """Per-machine operational health + fleet summary (silent/outdated/coverage)."""
    now = now or datetime.now()
    heartbeat_map = heartbeat_map or {}
    rows = []
    for machine in machines or []:
        mid = machine.get("machine_id") or ""
        last_hb = heartbeat_map.get(mid)
        age_min = None
        if last_hb:
            parsed = _parse_dt(last_hb)
            if parsed:
                age_min = round((now - parsed).total_seconds() / 60.0, 1)
        online = bool(machine.get("is_online"))
        silent = bool(online and (age_min is None or age_min > silent_minutes))
        flags = []
        if not online:
            flags.append("offline")
        else:
            if silent:
                flags.append("silent")
        version = str(machine.get("version") or "")
        outdated = bool(server_version) and version != server_version
        if outdated:
            flags.append("outdated")
        if not machine.get("sysmon_present"):
            flags.append("no_sysmon")
        if not machine.get("auditpol_enabled"):
            flags.append("no_auditpol")
        if not machine.get("baseline_hardened"):
            flags.append("not_hardened")
        rows.append({
            "machine_id": mid, "hostname": machine.get("hostname") or mid,
            "online": online, "silent": silent, "last_heartbeat": str(last_hb or ""),
            "heartbeat_age_min": age_min, "version": version, "outdated": outdated,
            "sysmon_present": bool(machine.get("sysmon_present")),
            "auditpol_enabled": bool(machine.get("auditpol_enabled")),
            "baseline_hardened": bool(machine.get("baseline_hardened")),
            "flags": flags,
        })
    rows.sort(key=lambda r: (not r["silent"], not r["outdated"], r["hostname"]))
    summary = {
        "machines": len(rows),
        "online": sum(1 for r in rows if r["online"]),
        "silent": sum(1 for r in rows if r["silent"]),
        "offline": sum(1 for r in rows if not r["online"]),
        "outdated": sum(1 for r in rows if r["outdated"]),
        "no_sysmon": sum(1 for r in rows if "no_sysmon" in r["flags"]),
        "no_auditpol": sum(1 for r in rows if "no_auditpol" in r["flags"]),
        "server_version": server_version,
    }
    return {"machines": rows, "summary": summary}


def aggregate_anomalies(rows):
    """Group server-side ingest rejections by source + reason."""
    grouped = {}
    for row in rows or []:
        key = (str(row.get("source_ip") or "?"), str(row.get("reason") or "?"),
               str(row.get("msg_type") or ""))
        item = grouped.setdefault(key, {"source_ip": key[0], "reason": key[1],
                                        "msg_type": key[2], "count": 0, "last_seen": ""})
        item["count"] += int(row.get("count") or 0)
        last = str(row.get("last_seen") or "")
        if last > item["last_seen"]:
            item["last_seen"] = last
    return sorted(grouped.values(), key=lambda i: -i["count"])


def policy_preview(policy, machines, statuses, wave_pcts=DEFAULT_WAVES):
    """What would applying `policy` to `machines` actually do (diff/dry-run)?"""
    policy = policy or {}
    config = policy.get("config_json")
    if isinstance(config, str):
        try:
            config = json.loads(config) if config else {}
        except Exception:
            return {"ok": False, "policy": policy.get("policy_name"),
                    "error": "config_json không phải JSON hợp lệ"}
    status_by_machine = {s.get("machine_id"): s for s in (statuses or [])}
    applied, failed, pending, offline = [], [], [], []
    for machine in machines or []:
        mid = machine.get("machine_id")
        row = status_by_machine.get(mid) or {}
        state = str(row.get("status") or "chưa áp dụng").lower()
        target = {"machine_id": mid, "hostname": machine.get("hostname") or mid,
                  "state": state, "message": row.get("message") or ""}
        if not machine.get("is_online"):
            offline.append(target)
        elif state in ("applied", "ok", "success", "applied_ok"):
            applied.append(target)
        elif state in ("failed", "error"):
            failed.append(target)
        else:
            pending.append(target)
    ids = [m.get("machine_id") for m in (machines or []) if m.get("machine_id")]
    warnings = []
    if not policy.get("enabled"):
        warnings.append("chính sách đang TẮT (enabled = 0)")
    if offline:
        warnings.append("%d máy đang offline (sẽ nhận khi online lại)" % len(offline))
    if config == {}:
        warnings.append("config rỗng - không thay đổi gì trên agent")
    return {
        "ok": True,
        "policy": {"id": policy.get("id"), "name": policy.get("policy_name"),
                   "type": policy.get("policy_type"), "enabled": bool(policy.get("enabled")),
                   "config": config, "apply_status": policy.get("apply_status")},
        "affected": len(ids),
        "applied": applied, "pending": pending, "failed": failed, "offline": offline,
        "waves": plan_waves(ids, wave_pcts),
        "warnings": warnings,
    }


def _parse_dt(value):
    if isinstance(value, datetime):
        return value
    txt = str(value or "").strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(txt[:len(fmt) + 4].strip(), fmt)
        except ValueError:
            continue
    return None


def heartbeat_cutoff(minutes=10, now=None):
    """Cutoff string for 'last heartbeat older than N minutes' queries."""
    return ((now or datetime.now()) - timedelta(minutes=int(minutes))).strftime("%Y-%m-%d %H:%M:%S")
