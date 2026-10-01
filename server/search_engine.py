"""GIAM-SAT unified investigation search engine - v5.0.8 (Phase A: "điều tra 1 chạm").

Why this exists
---------------
Before v5.0.8 the only cross-source search was `search_all()` (machines/alerts/
events, OR-of-LIKE, no operators, no window, no facets) and hunting scanned
tables with `LIKE ? ESCAPE '\\'`. An analyst could not ask "which hosts ran
certutil from a temp path in the last 7 days" across sysmon + events + traffic,
and there was no way to pivot from one indicator to everything else.

This module adds:
  * a small query DSL:
        host:PC01 -user:system cmd:certutil "http://" OR dst_ip:8.8.8.8
      - field:value / field:"quoted value" / -field:value (negation)
      - field:>N  field:>=N  field:<N  (numeric: pid/port/bytes/id), field:!=value
      - free text (matched against the scope's text columns)
      - wildcards * and ? -> SQL LIKE; everything else is escaped
      - ' OR ' separates OR-groups; inside a group conditions are AND-ed
  * index-backed SQL: PostgreSQL uses trigram GIN indexes (pg_trgm, created by
    db_postgres._init_db) so `%substring%` stops scanning the table; SQLite falls
    back to plain LIKE for small/dev installs.
  * cross-scope facets (scope/host/severity/rule/user) for one-click narrowing.
  * entity-360: one indicator (host/ip/user/hash/file/domain/rule/cve) resolved
    across every scope into a single time-ordered timeline.
  * saved searches (table `saved_searches`, PG + SQLite).

Read-only: everything here is SELECT. User input is NEVER interpolated into SQL:
identifiers come from the whitelists below, values are always parameters.
"""

import csv
import io
import re
import time
from contextlib import nullcontext

# --------------------------------------------------------------------------- #
# Scope registry: scope -> table + searchable fields (whitelist!)
#   fields: alias -> (sql column, kind)   kind: text | num
#   text:   columns used for free-text search (ordered by importance)
#   tcol:   time column used for the window + ordering
# --------------------------------------------------------------------------- #
SCOPES = {
    "alerts": {
        "label": "Cảnh báo (threat_alerts)",
        "table": "threat_alerts",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "rule_id", "rule_name", "severity",
                   "description", "source_ip", "timestamp", "received_at", "status"),
        "fields": {
            "id": ("id", "num"), "rule": ("rule_id", "text"), "rule_id": ("rule_id", "text"),
            "name": ("rule_name", "text"), "sev": ("severity", "text"),
            "severity": ("severity", "text"), "host": ("hostname", "text"),
            "machine": ("machine_id", "text"), "ip": ("source_ip", "text"),
            "src_ip": ("source_ip", "text"), "msg": ("description", "text"),
            "status": ("status", "text"),
        },
        "text": ("description", "rule_name", "rule_id", "hostname", "source_ip"),
    },
    "events": {
        "label": "Nhật ký sự kiện (events)",
        "table": "events",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "subtype", "event_id", "source",
                   "computer", "user", "category", "time", "description", "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "user": ("user", "text"), "eid": ("event_id", "text"), "event_id": ("event_id", "text"),
            "type": ("subtype", "text"), "subtype": ("subtype", "text"), "src": ("source", "text"),
            "computer": ("computer", "text"), "cat": ("category", "text"),
            "msg": ("description", "text"),
        },
        "text": ("description", "user", "computer", "hostname", "category", "subtype"),
    },
    "sysmon": {
        "label": "Sysmon (sysmon_events)",
        "table": "sysmon_events",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "sysmon_event_id", "process_name",
                   "process_path", "command_line", "pid", "parent_process",
                   "parent_command_line", "user", "severity", "description", "dst_ip",
                   "dns_query", "file_path", "registry_key", "hashes", "timestamp",
                   "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "eid": ("sysmon_event_id", "num"), "proc": ("process_name", "text"),
            "path": ("process_path", "text"), "cmd": ("command_line", "text"),
            "cmdline": ("command_line", "text"), "pid": ("pid", "num"),
            "parent": ("parent_process", "text"), "parent_cmd": ("parent_command_line", "text"),
            "user": ("user", "text"), "sev": ("severity", "text"),
            "dst_ip": ("dst_ip", "text"), "domain": ("dns_query", "text"),
            "file": ("file_path", "text"), "reg": ("registry_key", "text"),
            "hash": ("hashes", "text"), "msg": ("description", "text"),
        },
        "text": ("command_line", "process_path", "process_name", "parent_command_line",
                 "description", "dns_query", "file_path", "hostname"),
    },
    "traffic": {
        "label": "Lưu lượng mạng (network_traffic)",
        "table": "network_traffic",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "src_ip", "dst_ip", "src_port", "dst_port",
                   "protocol", "dns_query", "http_host", "state", "timestamp", "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "src_ip": ("src_ip", "text"), "dst_ip": ("dst_ip", "text"), "ip": ("dst_ip", "text"),
            "sport": ("src_port", "num"), "dport": ("dst_port", "num"),
            "port": ("dst_port", "num"), "proto": ("protocol", "text"),
            "domain": ("dns_query", "text"), "dns": ("dns_query", "text"),
            "http": ("http_host", "text"),
        },
        "text": ("dst_ip", "src_ip", "dns_query", "http_host", "hostname"),
    },
    "netflow": {
        "label": "NetFlow (netflow_flows)",
        "table": "netflow_flows",
        "tcol": "received_at",
        "select": ("id", "exporter_ip", "src_ip", "dst_ip", "src_port", "dst_port",
                   "protocol", "packets", "bytes", "first", "last", "received_at"),
        "fields": {
            "id": ("id", "num"), "exporter": ("exporter_ip", "text"),
            "src_ip": ("src_ip", "text"), "dst_ip": ("dst_ip", "text"), "ip": ("dst_ip", "text"),
            "sport": ("src_port", "num"), "dport": ("dst_port", "num"),
            "proto": ("protocol", "text"), "bytes": ("bytes", "num"),
        },
        "text": ("dst_ip", "src_ip", "exporter_ip"),
    },
    "syslog": {
        "label": "Syslog thiết bị",
        "table": "syslog",
        "tcol": "received_at",
        "select": ("id", "source_ip", "hostname", "facility", "severity", "timestamp",
                   "message", "received_at"),
        "fields": {
            "id": ("id", "num"), "src_ip": ("source_ip", "text"), "ip": ("source_ip", "text"),
            "host": ("hostname", "text"), "facility": ("facility", "text"),
            "sev": ("severity", "text"), "msg": ("message", "text"),
        },
        "text": ("message", "hostname", "source_ip"),
    },
    "fim": {
        "label": "FIM (fim_events)",
        "table": "fim_events",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "action", "path", "time", "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "action": ("action", "text"), "path": ("path", "text"), "file": ("path", "text"),
        },
        "text": ("path", "action", "hostname"),
    },
    "sca": {
        "label": "SCA (sca_events)",
        "table": "sca_events",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "check_id", "title", "status", "severity",
                   "description", "timestamp", "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "check": ("check_id", "text"), "status": ("status", "text"),
            "sev": ("severity", "text"), "msg": ("title", "text"),
        },
        "text": ("title", "check_id", "description", "hostname"),
    },
    "yara": {
        "label": "YARA (yara_alerts)",
        "table": "yara_alerts",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "rule_name", "description", "file",
                   "timestamp", "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "rule": ("rule_name", "text"), "file": ("file", "text"), "msg": ("description", "text"),
        },
        "text": ("rule_name", "description", "file", "hostname"),
    },
    "vulns": {
        "label": "Lỗ hổng (vuln_alerts)",
        "table": "vuln_alerts",
        "tcol": "received_at",
        "select": ("id", "machine_id", "hostname", "software", "version", "publisher", "cve",
                   "severity", "description", "status", "timestamp", "received_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "cve": ("cve", "text"), "sev": ("severity", "text"), "sw": ("software", "text"),
            "status": ("status", "text"), "msg": ("description", "text"),
        },
        "text": ("cve", "software", "description", "hostname"),
    },
    "cases": {
        "label": "Case điều tra",
        "table": "cases",
        "tcol": "created_at",
        "select": ("id", "machine_id", "hostname", "title", "description", "severity",
                   "status", "created_by", "created_at"),
        "fields": {
            "id": ("id", "num"), "host": ("hostname", "text"), "machine": ("machine_id", "text"),
            "sev": ("severity", "text"), "status": ("status", "text"),
            "msg": ("title", "text"), "by": ("created_by", "text"),
        },
        "text": ("title", "description", "hostname"),
    },
}

DEFAULT_SCOPES = ("alerts", "events", "sysmon", "traffic")

# fields that mean the same thing in every scope (used by entity-360)
ENTITY_FIELDS = {
    "host": ("hostname", "machine_id", "computer"),
    "ip": ("source_ip", "src_ip", "dst_ip", "exporter_ip"),
    "user": ("user", "created_by"),
    "hash": ("hashes", "hash"),
    "file": ("file_path", "file", "path"),
    "domain": ("dns_query", "http_host"),
    "rule": ("rule_id", "rule_name"),
    "cve": ("cve",),
    "any": None,  # -> every text column of the scope
}


# --------------------------------------------------------------------------- #
# Backend helpers
# --------------------------------------------------------------------------- #
def backend_kind(db):
    """'postgres' | 'sqlite' | 'unknown'."""
    name = type(db).__name__.lower()
    mod = type(db).__module__.lower()
    if "postgres" in name or "postgres" in mod:
        return "postgres"
    if "sqlite" in name or "sqlite" in mod:
        return "sqlite"
    return "unknown"


def placeholder(kind):
    return "%s" if kind == "postgres" else "?"


def rows(db, sql, params, kind):
    """Read-only query against either backend; never raises (returns [])."""
    try:
        if kind == "postgres" and hasattr(db, "_execute"):
            return list(db._execute(sql, params, fetchall=True) or [])
        conn = getattr(db, "conn", None)
        if conn is not None:
            lock = getattr(db, "lock", None) or nullcontext()
            with lock:
                cur = conn.execute(sql, params)
                cols = [d[0] for d in (cur.description or [])]
                return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        return []
    return []


def like_escape(value):
    """Escape LIKE wildcards (twin of db_manager._like_escape)."""
    return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def sql_like(term):
    """'*'/'?' are wildcards; everything else is a literal substring."""
    t = like_escape(term)
    if "*" in t or "?" in t:
        return t.replace("*", "%").replace("?", "_")
    return "%" + t + "%"


def build_time_predicate(kind, tcol, hours):
    """Return (sql_fragment, params) applying the look-back window."""
    if not hours or int(hours) <= 0:
        return "", []
    h = int(hours)
    if kind == "postgres":
        return " AND %s >= NOW() - make_interval(hours => %s)" % (tcol, "%s"), [h]
    return " AND %s >= datetime('now', ?)" % tcol, ["-%d hours" % h]


# --------------------------------------------------------------------------- #
# Query DSL
# --------------------------------------------------------------------------- #
_OPS = ((">=", "gte"), ("<=", "lte"), ("!=", "ne"), (">", "gt"), ("<", "lt"))
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _split_or(text):
    """Split on a top-level ' OR ' (case-insensitive, quotes aware)."""
    parts, buf, i, n, inq = [], [], 0, len(text), False
    while i < n:
        ch = text[i]
        if ch == '"':
            inq = not inq
            buf.append(ch)
            i += 1
            continue
        if not inq and text[i:i + 4].lower() == " or ":
            parts.append("".join(buf))
            buf = []
            i += 4
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p for p in parts if p.strip()] or [text]


def _tokenize(text):
    """-> [(negate, token)] keeping "quoted values" as one token."""
    out, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        neg = False
        if text[i] == "-" and i + 1 < n and not text[i + 1].isspace():
            neg = True
            i += 1
        buf = []
        while i < n and not text[i].isspace():
            if text[i] == '"':
                j = text.find('"', i + 1)
                if j == -1:
                    buf.append(text[i + 1:])
                    i = n
                else:
                    buf.append(text[i + 1:j])
                    i = j + 1
            else:
                buf.append(text[i])
                i += 1
        tok = "".join(buf)
        if tok and tok != "-":
            out.append((neg, tok))
    return out


def _looks_like_field(name, rest):
    """Guard so Windows paths / URLs are NOT mistaken for `field:value`."""
    if not _FIELD_RE.match(name) or len(name) < 2 or name != name.lower():
        return False
    if rest.startswith(("/", "\\")):
        return False
    return True


def _token_to_cond(neg, tok):
    """-> (condition dict or None, error string or None)."""
    field, op, value = None, "contains", tok
    if ":" in tok:
        f, _, rest = tok.partition(":")
        if _looks_like_field(f, rest):
            field = f.lower()
            for sym, name in _OPS:
                if rest.startswith(sym):
                    op, rest = name, rest[len(sym):]
                    break
            value = rest
    if value == "":
        return None, ("thiếu giá trị sau '%s:'" % field if field else None)
    if field is None and op != "contains":
        field, op, value = None, "contains", tok
    return {"field": field, "op": op, "value": value, "negate": bool(neg)}, None


def parse_query(q):
    """Parse the DSL into OR-groups of AND-ed conditions.

    'AND' is implicit (and ignored as a literal word); 'NOT' negates the next
    token. Returns {'groups': [[cond, ...]], 'unknown': [msg], 'raw', 'terms'}.
    """
    text = (q or "").strip()
    if not text:
        return {"groups": [], "unknown": [], "raw": "", "terms": 0}
    groups, unknown, terms = [], [], 0
    for chunk in _split_or(text):
        conds = []
        neg_next = False
        for neg, tok in _tokenize(chunk):
            upper = tok.upper()
            if upper == "AND":
                continue
            if upper == "NOT":
                neg_next = True
                continue
            cond, err = _token_to_cond(neg or neg_next, tok)
            neg_next = False
            if err:
                unknown.append(err)
            if cond:
                conds.append(cond)
                terms += 1
        if conds:
            groups.append(conds)
    return {"groups": groups, "unknown": unknown, "raw": text, "terms": terms}


def all_fields(scopes=None):
    """Alias -> list of scopes + the SQL column, for the UI hint panel."""
    out = {}
    for name in (scopes or SCOPES.keys()):
        spec = SCOPES.get(name)
        if not spec:
            continue
        for alias, (col, kind) in spec["fields"].items():
            out.setdefault(alias, {"column": col, "kind": kind, "scopes": []})
            out[alias]["scopes"].append(name)
    return out


# --------------------------------------------------------------------------- #
# SQL building (identifiers from the whitelist, values always parameterised)
# --------------------------------------------------------------------------- #
def _resolve_field(spec, cond):
    """Return (column, kind) for a condition, or (None, None) when unknown."""
    f = cond.get("field")
    if not f:
        return None, None
    hit = spec["fields"].get(f)
    if hit:
        return hit
    for _alias, (col, kind) in spec["fields"].items():
        if col == f:
            return col, kind
    return None, None


def _num_expr(col, kind):
    # numeric comparison even when the column is TEXT (pid, port, bytes)
    if kind == "postgres":
        return "CAST(NULLIF(CAST(%s AS TEXT), '') AS DOUBLE PRECISION)" % col
    return "CAST(%s AS REAL)" % col


def _cond_sql(spec, cond, col_kind, ph, kind):
    """-> (sql fragment, params) for one condition inside one scope."""
    col, fkind = col_kind
    op, value, neg = cond["op"], cond["value"], cond["negate"]
    like_op = "ILIKE" if kind == "postgres" else "LIKE"
    if col is None:  # free text across the scope's text columns
        targets = spec["text"]
        frag = "(" + " OR ".join("%s %s %s" % (c, like_op, ph) for c in targets) + ")"
        params = [sql_like(value)] * len(targets)
    elif op == "contains":
        expr = "CAST(%s AS TEXT)" % col if fkind == "num" else col
        frag, params = "%s %s %s" % (expr, like_op, ph), [sql_like(value)]
    elif op in ("gt", "gte", "lt", "lte"):
        sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        if fkind == "num":
            try:
                num = float(value)
            except ValueError:
                return None, []
            frag, params = "%s %s %s" % (_num_expr(col, kind), sym, ph), [num]
        else:
            frag, params = "%s %s %s" % (col, sym, ph), [value]
    elif op == "eq":
        expr = "CAST(%s AS TEXT)" % col if fkind == "num" else col
        frag, params = "%s = %s" % (expr, ph), [value]
    elif op == "ne":
        expr = "CAST(%s AS TEXT)" % col if fkind == "num" else col
        frag, params = "%s <> %s" % (expr, ph), [value]
    else:
        return None, []
    if neg:
        frag = "NOT (%s)" % frag
    return frag, params


def _build_scope_where(spec, ast, ph, kind):
    """-> (where_sql, params) or (None, []) when the query cannot apply here."""
    if not ast.get("groups"):
        return None, []
    groups_sql, params = [], []
    for group in ast["groups"]:
        conds_sql = []
        for cond in group:
            col_kind = _resolve_field(spec, cond)
            if cond.get("field") and col_kind == (None, None):
                continue  # this scope has no such field -> not part of the group
            frag, p = _cond_sql(spec, cond, col_kind, ph, kind)
            if frag:
                conds_sql.append(frag)
                params.extend(p)
        if conds_sql:
            groups_sql.append("(" + " AND ".join(conds_sql) + ")")
    if not groups_sql:
        return None, []
    return "(" + " OR ".join(groups_sql) + ")", params


def normalize_row(row):
    """JSON-safe copy: datetimes -> 'YYYY-MM-DD HH:MM:SS', keep dict/list as-is."""
    out = {}
    for k, v in row.items():
        if hasattr(v, "strftime"):
            out[k] = v.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(v, (str, int, float, bool, type(None), dict, list)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


def row_time(row, spec):
    for key in (spec["tcol"], "timestamp", "time", "created_at", "received_at"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


# --------------------------------------------------------------------------- #
# Executors
# --------------------------------------------------------------------------- #
def _fetch_scope(db, name, spec, ast, hours, limit, offset, kind):
    ph = placeholder(kind)
    where, params = _build_scope_where(spec, ast, ph, kind)
    if where is None:
        return []
    tpred, tparams = build_time_predicate(kind, spec["tcol"], hours)
    sql = "SELECT %s FROM %s WHERE 1=1%s AND %s ORDER BY %s DESC LIMIT %s OFFSET %s" % (
        ", ".join(spec["select"]), spec["table"], tpred, where, spec["tcol"], ph, ph)
    out = []
    for r in rows(db, sql, list(tparams) + list(params) + [int(limit), int(offset)], kind):
        r = normalize_row(r)
        r["_scope"] = name
        r["_time"] = row_time(r, spec)
        out.append(r)
    return out


def _facets(results, cap=10):
    def top(key, limit=cap):
        counts = {}
        for r in results:
            v = r.get(key)
            if v not in (None, ""):
                counts[str(v)] = counts.get(str(v), 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit])

    hosts = {}
    for r in results:
        h = r.get("hostname") or r.get("machine_id")
        if h:
            hosts[str(h)] = hosts.get(str(h), 0) + 1
    times = [r.get("_time") for r in results if r.get("_time")]
    return {
        "scope": top("_scope"),
        "host": dict(sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:cap]),
        "severity": top("severity"),
        "rule": top("rule_id"),
        "user": top("user"),
        "earliest": min(times) if times else "",
        "latest": max(times) if times else "",
    }


def search(db, q, scopes=None, hours=24, limit=100, offset=0, per_scope=None):
    """Run the DSL across every requested scope.

    Returns {'results', 'facets', 'total', 'took_ms', 'backend', 'unknown'}.
    """
    t0 = time.perf_counter()
    kind = backend_kind(db)
    ast = parse_query(q)
    wanted = [s for s in (scopes if scopes is not None else DEFAULT_SCOPES) if s in SCOPES]
    limit = max(1, min(int(limit or 100), 1000))
    per_scope = int(per_scope or max(200, limit * 3))
    results, errors = [], []
    if ast["groups"]:
        for name in wanted:
            try:
                results.extend(_fetch_scope(db, name, SCOPES[name], ast, hours,
                                            per_scope, offset, kind))
            except Exception as e:  # a broken/older table must not kill the search
                errors.append("%s: %s" % (name, str(e)[:120]))
    results.sort(key=lambda r: r.get("_time") or "", reverse=True)
    return {
        "query": ast["raw"],
        "scopes": wanted,
        "hours": int(hours or 0),
        "backend": kind,
        "total": len(results),
        "returned": len(results[:limit]),
        "results": results[:limit],
        "facets": _facets(results),
        "unknown": list(ast.get("unknown") or []) + errors,
        "took_ms": int((time.perf_counter() - t0) * 1000),
    }


# --------------------------------------------------------------------------- #
# Entity-360
# --------------------------------------------------------------------------- #
def entity(db, kind_name, value, hours=24, limit=500, scopes=None):
    """Everything we know about ONE indicator (host/ip/user/hash/file/domain/
    rule/cve/any), merged across scopes into a single time-ordered timeline."""
    t0 = time.perf_counter()
    kind = backend_kind(db)
    kind_name = (kind_name or "any").lower()
    if kind_name not in ENTITY_FIELDS:
        kind_name = "any"
    cols = ENTITY_FIELDS[kind_name]
    value = str(value or "").strip()
    wanted = [s for s in (scopes if scopes is not None else list(SCOPES)) if s in SCOPES]
    limit = max(1, min(int(limit or 500), 2000))
    results, by_scope = [], {}
    if value:
        for name in wanted:
            spec = SCOPES[name]
            if cols is None:
                groups = [[{"field": None, "op": "contains", "value": value, "negate": False}]]
            else:
                have = {c for _a, (c, _k) in spec["fields"].items()}
                groups = [[{"field": col, "op": "contains", "value": value, "negate": False}]
                          for col in cols if col in have]
            if not groups:
                continue
            rs = _fetch_scope(db, name, spec, {"groups": groups}, hours, limit, 0, kind)
            if rs:
                by_scope[name] = len(rs)
                results.extend(rs)
    results.sort(key=lambda r: r.get("_time") or "", reverse=True)

    def collect(keys, cap=12):
        counts = {}
        for r in results:
            for k in keys:
                v = r.get(k)
                if v:
                    counts[str(v)] = counts.get(str(v), 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:cap])

    times = [r.get("_time") for r in results if r.get("_time")]
    return {
        "entity": {"kind": kind_name, "value": value},
        "scopes": wanted,
        "hours": int(hours or 0),
        "backend": kind,
        "total": len(results),
        "returned": len(results[:limit]),
        "results": results[:limit],
        "by_scope": by_scope,
        "hosts": collect(("hostname", "machine_id")),
        "ips": collect(("source_ip", "src_ip", "dst_ip")),
        "users": collect(("user",)),
        "rules": collect(("rule_id",)),
        "first_seen": min(times) if times else "",
        "last_seen": max(times) if times else "",
        "took_ms": int((time.perf_counter() - t0) * 1000),
    }


# --------------------------------------------------------------------------- #
# Saved searches (PG + SQLite) + CSV evidence export
# --------------------------------------------------------------------------- #
_SAVED_COLS = ("id", "name", "query", "scopes", "hours", "created_by", "shared", "created_at")


def write_sql(db, sql, params, kind, returning=False):
    """INSERT/UPDATE/DELETE against either backend; None on failure."""
    try:
        if kind == "postgres" and hasattr(db, "_execute"):
            return db._execute(sql, params, fetch=returning)
        conn = getattr(db, "conn", None)
        if conn is not None:
            lock = getattr(db, "lock", None) or nullcontext()
            with lock:
                cur = conn.execute(sql, params)
                conn.commit()
                if returning:
                    row = cur.fetchone()
                    return (row[0] if row else None)
                return cur.rowcount
    except Exception:
        return None
    return None


def save_search(db, name, query, scopes, hours, created_by="", shared=True):
    """UPSERT a saved search by name; returns the row id (or None)."""
    kind = backend_kind(db)
    name = str(name or "").strip()[:120]
    if not name or not str(query or "").strip():
        return None
    scope_str = ",".join([s for s in (scopes or DEFAULT_SCOPES) if s in SCOPES])
    if kind == "postgres":
        sql = ("INSERT INTO saved_searches (name, query, scopes, hours, created_by, shared) "
               "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (name) DO UPDATE SET "
               "query=EXCLUDED.query, scopes=EXCLUDED.scopes, hours=EXCLUDED.hours, "
               "shared=EXCLUDED.shared, created_at=NOW() RETURNING id")
    else:
        sql = ("INSERT INTO saved_searches (name, query, scopes, hours, created_by, shared) "
               "VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET query=excluded.query, "
               "scopes=excluded.scopes, hours=excluded.hours, shared=excluded.shared, "
               "created_at=CURRENT_TIMESTAMP RETURNING id")
    params = (name, str(query)[:500], scope_str, int(hours or 24),
              str(created_by or "")[:60], 1 if shared else 0)
    new_id = write_sql(db, sql, params, kind, returning=True)
    if isinstance(new_id, dict):  # psycopg2 RealDictCursor returns {'id': N}
        new_id = new_id.get("id")
    if new_id is None:  # very old SQLite builds without RETURNING
        hit = rows(db, "SELECT id FROM saved_searches WHERE name = %s"
                   % placeholder(kind), (name,), kind)
        new_id = hit[0]["id"] if hit else None
    return new_id


def list_saved_searches(db):
    kind = backend_kind(db)
    sql = "SELECT %s FROM saved_searches ORDER BY name" % ", ".join(_SAVED_COLS)
    return [normalize_row(r) for r in rows(db, sql, None, kind)]


def delete_saved_search(db, sid):
    kind = backend_kind(db)
    return write_sql(db, "DELETE FROM saved_searches WHERE id = %s" % placeholder(kind),
                     (int(sid),), kind) is not None


EXPORT_COLS = ("_time", "_scope", "hostname", "machine_id", "user", "event_id",
               "sysmon_event_id", "rule_id", "severity", "process_path", "command_line",
               "parent_command_line", "dst_ip", "src_ip", "dns_query", "file_path",
               "registry_key", "hashes", "description")


def _csv_cell(v):
    import json as _json
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return _json.dumps(v, ensure_ascii=False)[:2000]
    return str(v)[:4000]


def to_csv(results, columns=None):
    """CSV text for an evidence export (caller prepends a UTF-8 BOM for Excel)."""
    if not results:
        return ""
    cols = list(columns or [c for c in EXPORT_COLS if any(c in r for r in results)])
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for r in results:
        w.writerow([_csv_cell(r.get(c)) for c in cols])
    return buf.getvalue()
