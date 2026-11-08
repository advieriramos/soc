"""Construye un índice SQLite con todos los logs y alertas del dataset.

Así el agente puede preguntar «¿qué hizo este host/usuario/IP entre X e Y?» en milisegundos
sin cargar 800k eventos en memoria. Se ejecuta una vez (≈1-2 min):

    python build_index.py
"""
import csv, json, os, sqlite3, sys, time

from config import DATA_DIR, DB_PATH

LOGDIR = os.path.join(DATA_DIR, "04_logs")


def norm_user(u):
    if not u:
        return None
    u = str(u).strip().lower()
    if "\\" in u:
        u = u.split("\\")[-1]
    if "@" in u:
        u = u.split("@")[0]
    return u or None


def dom_of_url(url):
    if not url:
        return None
    u = url.split("://", 1)[-1]
    return u.split("/", 1)[0].split(":")[0].lower()


def entities(src, e):
    """Devuelve [(tipo, valor)] para indexar un evento."""
    out = []
    add = lambda t, v: v not in (None, "", "-") and out.append((t, str(v).lower()))
    if src == "dns":
        add("host", e.get("hostname")); add("ip", e.get("src_ip")); add("domain", e.get("query"))
    elif src == "firewall":
        add("ip", e.get("src_ip")); add("ip", e.get("dst_ip"))
    elif src == "proxy":
        add("host", e.get("hostname")); add("user", norm_user(e.get("user"))); add("ip", e.get("src_ip"))
        add("ip", e.get("dst_ip")); add("domain", e.get("domain"))
    elif src == "ad_events":
        add("user", norm_user(e.get("subject"))); add("user", norm_user(e.get("target"))); add("host", e.get("src_host"))
        add("host", e.get("dc"))
    elif src == "ai_gateway":
        add("customer", e.get("customer_id")); add("ip", e.get("src_ip")); add("key", e.get("session_id"))
        for tc in e.get("tool_calls") or []:
            cid = (tc.get("args") or {}).get("customer_id")
            if cid and cid != e.get("customer_id"):
                add("customer", cid)
    elif src == "cicd_builds":
        add("host", e.get("runner")); add("key", e.get("build_id"))
    elif src == "cloudtrail":
        ui = e.get("userIdentity") or {}
        add("user", norm_user(ui.get("userName"))); add("key", ui.get("accessKeyId")); add("ip", e.get("sourceIPAddress"))
        rp = e.get("requestParameters") or {}
        add("key", rp.get("bucketName")); add("user", norm_user(rp.get("userName")))
    elif src == "dlp":
        add("user", norm_user(e.get("user"))); add("host", e.get("hostname")); add("domain", e.get("destination"))
    elif src in ("ecom_account", "ecom_auth"):
        add("customer", e.get("customer_id")); add("ip", e.get("src_ip")); add("key", e.get("device_fp"))
    elif src == "edr_events":
        add("host", e.get("hostname")); add("user", norm_user(e.get("user"))); add("key", e.get("sha256"))
        d = e.get("details") or {}
        for k in ("dst_ip", "remote_ip"):
            add("ip", d.get(k))
        add("domain", d.get("domain"))
    elif src == "email":
        add("user", norm_user(e.get("sender")))
        for r in e.get("recipients") or []:
            add("user", norm_user(r))
        add("key", e.get("message_id")); add("ip", e.get("sender_ip"))
        add("domain", (e.get("sender") or "@").split("@")[-1])
        for u in e.get("urls") or []:
            add("domain", dom_of_url(u))
        for a in e.get("attachments") or []:
            if isinstance(a, dict):
                add("key", a.get("sha256"))
    elif src == "email_clicks":
        add("user", norm_user(e.get("user"))); add("ip", e.get("src_ip")); add("key", e.get("message_id"))
        add("domain", dom_of_url(e.get("url")))
    elif src == "idp_audit":
        add("user", norm_user(e.get("actor_upn"))); add("ip", e.get("src_ip"))
        t = e.get("target") or ""
        if "@" in t:
            add("user", norm_user(t))
    elif src == "idp_signins":
        add("user", norm_user(e.get("user_upn"))); add("ip", e.get("src_ip")); add("key", e.get("session_id"))
    elif src == "sql_audit":
        add("user", norm_user(e.get("user"))); add("host", e.get("client_host"))
    elif src == "vpn":
        add("user", norm_user(e.get("user"))); add("ip", e.get("src_ip")); add("ip", e.get("assigned_ip"))
    elif src == "waf":
        add("ip", e.get("src_ip"))
    return list(dict.fromkeys(out))


def alert_entities(a):
    out = []
    add = lambda t, v: v not in (None, "") and out.append((t, str(v).lower()))
    ent = a.get("entities") or {}
    for h in ent.get("hosts") or []:
        add("host", h.get("hostname")); add("ip", h.get("ip"))
    for u in ent.get("users") or []:
        if "(" not in (u.get("upn") or ""):
            add("user", norm_user(u.get("upn")))
    for ip in ent.get("ips") or []:
        add("ip", ip)
    for d in ent.get("domains") or []:
        add("domain", d)
    for f in ent.get("files") or []:
        add("key", f.get("sha256"))
    for c in ent.get("customers") or []:
        add("customer", c.get("customer_id"))
    cl = ent.get("cloud") or {}
    add("user", norm_user(cl.get("identity"))); add("user", norm_user(cl.get("new_user"))); add("key", cl.get("access_key"))
    add("key", cl.get("bucket")); add("key", ent.get("ai_session"))
    ev = a.get("evidence") or {}
    add("key", ev.get("message_id"))
    return list(dict.fromkeys(out))


def iter_source(name):
    jp = os.path.join(LOGDIR, name + ".jsonl"); cp = os.path.join(LOGDIR, name + ".csv")
    if os.path.exists(jp):
        with open(jp, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)
    elif os.path.exists(cp):
        with open(cp, encoding="utf-8") as f:
            yield from csv.DictReader(f)


def index_ok():
    """True si el índice existe, está completo y se puede leer."""
    if not (os.path.exists(DB_PATH) and os.path.exists(DB_PATH + ".ok")):
        return False
    try:
        db = sqlite3.connect(DB_PATH)
        ok = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] > 0 and db.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0
        db.close()
        return ok
    except sqlite3.DatabaseError:
        return False


def build(alert_files=None):
    """Se construye en un fichero temporal y solo al final sustituye al bueno: si se interrumpe, nunca queda un índice roto."""
    t0 = time.time()
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    final, tmp = DB_PATH, DB_PATH + ".tmp"
    for f in (tmp, final + ".ok"):
        if os.path.exists(f):
            os.remove(f)
    db = sqlite3.connect(tmp)
    db.executescript("""
    PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
    DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS ent; DROP TABLE IF EXISTS alerts; DROP TABLE IF EXISTS aent;
    CREATE TABLE events(event_id TEXT PRIMARY KEY, source TEXT, ts TEXT, doc TEXT);
    CREATE TABLE ent(event_id TEXT, source TEXT, ts TEXT, etype TEXT, value TEXT);
    CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, ts TEXT, rule_id TEXT, doc TEXT);
    CREATE TABLE aent(alert_id TEXT, ts TEXT, rule_id TEXT, etype TEXT, value TEXT);
    """)
    sources = sorted({f.rsplit(".", 1)[0] for f in os.listdir(LOGDIR)})
    for s in sources:
        ev, en = [], []
        for e in iter_source(s):
            eid = e.get("event_id"); ts = e.get("timestamp") or e.get("eventTime") or ""
            ev.append((eid, s, ts, json.dumps(e, ensure_ascii=False)))
            en.extend((eid, s, ts, t, v) for t, v in entities(s, e))
        db.executemany("INSERT OR REPLACE INTO events VALUES(?,?,?,?)", ev)
        db.executemany("INSERT INTO ent VALUES(?,?,?,?,?)", en)
        print(f"  {s:14s} {len(ev):>7} eventos  {len(en):>7} entidades", flush=True)
    load_alerts(db, alert_files)
    print("  creando índices…", flush=True)
    db.executescript("""
    CREATE INDEX ix_ent ON ent(etype, value, ts);
    CREATE INDEX ix_ent_src ON ent(source, etype, value, ts);
    CREATE INDEX ix_aent ON aent(etype, value, ts);
    CREATE INDEX ix_alerts_ts ON alerts(ts);
    CREATE INDEX ix_ev_src_ts ON events(source, ts);
    """)
    db.commit(); db.close()
    os.replace(tmp, final)
    with open(DB_PATH + ".ok", "w") as f:  # marca de índice completo (arrancar.sh la comprueba)
        f.write(time.strftime("%Y-%m-%dT%H:%M:%S"))
    print(f"Índice listo en {DB_PATH} ({time.time()-t0:.0f}s)")


def load_alerts(db, alert_files=None):
    files = alert_files or [os.path.join(DATA_DIR, "03_alertas", "alertas.jsonl")]
    n = 0
    for fp in files:
        with open(fp, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                a = json.loads(line)
                db.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?)",
                           (a["alert_id"], a["created_at"], a["rule_id"], json.dumps(a, ensure_ascii=False)))
                db.execute("DELETE FROM aent WHERE alert_id=?", (a["alert_id"],))
                db.executemany("INSERT INTO aent VALUES(?,?,?,?,?)",
                               [(a["alert_id"], a["created_at"], a["rule_id"], t, v) for t, v in alert_entities(a)])
                n += 1
    print(f"  alertas        {n:>7}")


if __name__ == "__main__":
    build(sys.argv[1:] or None)
