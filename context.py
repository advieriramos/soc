"""Contexto y herramientas que usa el agente de triaje.

Cada consulta que hace el agente pasa por `Tools`, que la registra en una traza (qué consultó, con qué argumentos y
qué encontró). Esa traza es la que se muestra en el panel para que el analista vea en qué se basa cada decisión.
"""
import csv, json, os, re, sqlite3, datetime as dt
from functools import lru_cache

from config import DATA_DIR, DB_PATH

P = lambda *x: os.path.join(DATA_DIR, *x)


def _csv(*path):
    with open(P(*path), encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _jl(*path):
    with open(P(*path), encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


# --------------------------------------------------------------------------------------------- tiempo
def parse_ts(s):
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def iso(d):
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def madrid_offset(d_utc):
    """Europe/Madrid sin depender de tzdata: CEST (+2) hasta el último domingo de octubre a las 01:00 UTC."""
    y = d_utc.year
    def last_sunday(month):
        d = dt.datetime(y, month, 31 if month in (3, 10) else 30, 1, tzinfo=dt.timezone.utc)
        return d - dt.timedelta(days=(d.weekday() + 1) % 7)
    return 2 if last_sunday(3) <= d_utc < last_sunday(10) else 1


def local_to_utc(s):
    """Las fechas del calendario de cambios están en hora local de Barcelona."""
    d = dt.datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=dt.timezone.utc)
    return d - dt.timedelta(hours=madrid_offset(d))


def to_local(d_utc):
    return d_utc + dt.timedelta(hours=madrid_offset(d_utc))


DIAS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]


def fmt_local(d_utc):
    l = to_local(d_utc)
    return f"{DIAS[l.weekday()]} {l:%d/%m %H:%M}"


def norm_user(u):
    if not u:
        return ""
    u = str(u).strip().lower()
    if "\\" in u:
        u = u.split("\\")[-1]
    return u.split("@")[0]


# --------------------------------------------------------------------------------------------- inventario
class Inventory:
    def __init__(self):
        self.assets = _csv("02_inventario", "activos.csv")
        self.asset_by_host = {a["hostname"].lower(): a for a in self.assets}
        self.asset_by_ip = {a["ip"]: a for a in self.assets}
        self.users = _csv("02_inventario", "usuarios.csv")
        self.user_by_name = {u["username"].lower(): u for u in self.users}
        self.vulns = _csv("02_inventario", "vulnerabilidades.csv")
        self.hr = _csv("02_inventario", "eventos_rrhh.csv")
        self.services = _csv("02_inventario", "servicios_negocio.csv")
        self.zones = _csv("02_inventario", "zonas_red.csv")
        self.stores = _csv("02_inventario", "tiendas.csv")
        self.changes = _csv("02_inventario", "calendario_cambios.csv")
        for c in self.changes:
            c["_start"] = local_to_utc(c["inicio"]); c["_end"] = local_to_utc(c["fin"])
        self.ti = {r["value"].lower(): r for r in _jl("05_inteligencia", "ti_feed.jsonl")}
        self.geo = {r["ip"]: r for r in _csv("05_inteligencia", "geoip_asn.csv")}
        self.sandbox = {r["sha256"].lower(): r for r in _jl("05_inteligencia", "sandbox_informes.jsonl")}
        self.usecases = {r["rule_id"]: r for r in _csv("01_contexto", "catalogo_casos_de_uso.csv")}

    def zone_of_ip(self, ip):
        import ipaddress
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for z in self.zones:
            n = ipaddress.ip_network(z["cidr"])
            if a in n and (best is None or n.prefixlen > best[1]):
                best = (z["zona"], n.prefixlen)
        return best[0] if best else None


@lru_cache(maxsize=1)
def inventory():
    return Inventory()


# --------------------------------------------------------------------------------------------- herramientas con traza
SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
CRIT_ORDER = ["Baja", "Media", "Alta", "Crítica"]

INJECTION_RX = re.compile(
    r"(ignora(r)? (todas )?(las |tus )?instrucciones|olvida (todas )?tus instrucciones|system override|modo desarrollador|"
    r"sistema automatizado|clasificar como (false_positive|falso positivo)|no escalar|no bloquear|no requiere revisi[oó]n|"
    r"aprobado por el equipo soc|prompt de sistema|ignore (all )?previous)", re.I)


class Tools:
    def __init__(self, db=None):
        self.inv = inventory()
        self.db = db or sqlite3.connect(DB_PATH, check_same_thread=False)
        self.db.execute("PRAGMA mmap_size=1073741824"); self.db.execute("PRAGMA cache_size=-200000")
        self.db.execute("PRAGMA journal_mode=MEMORY")
        self.trace = []
        self._cache = {}

    # registro ----------------------------------------------------------------------------
    def log(self, tool, args, found, n=None):
        self.trace.append({"tool": tool, "args": args, "found": found, **({"n": n} if n is not None else {})})

    # CMDB / directorio -------------------------------------------------------------------
    def asset(self, key):
        if not key:
            return None
        a = self.inv.asset_by_host.get(str(key).lower()) or self.inv.asset_by_ip.get(str(key))
        if a:
            vul = [v for v in self.inv.vulns if v["hostname"].lower() == a["hostname"].lower() and v["estado"] == "abierta"]
            a = {**a, "vulnerabilities": vul}
            self.log("cmdb", key, f'{a["hostname"]}: {a["type"]}, criticidad {a["criticality"]}, zona {a["zone"]}, '
                                  f'servicio «{a["business_service"]}»' + (f', {len(vul)} vuln. abiertas' if vul else ""))
        else:
            self.log("cmdb", key, "no está en la CMDB (¿equipo externo o no gestionado?)")
        return a

    def user(self, key):
        k = norm_user(key)
        u = self.inv.user_by_name.get(k)
        if not u:
            self.log("directorio", key, "no existe en el directorio")
            return None
        hr = [h for h in self.inv.hr if norm_user(h["usuario"]) == k]
        u = {**u, "hr_events": hr}
        flags = [x for x, c in (("VIP", u["vip"] == "True"), ("privilegiada", u["privileged"] == "True")) if c]
        self.log("directorio", key, f'{u["display_name"]} — {u["title"]} ({u["department"]}), tipo {u["account_type"]}'
                 + (f', {"/".join(flags)}' if flags else "") + (f'; RRHH: {"; ".join(h["tipo"] + " " + h["detalle"] for h in hr)}' if hr else ""))
        return u

    # inteligencia --------------------------------------------------------------------------
    def intel(self, ind):
        if not ind:
            return {}
        ind = str(ind)
        ti = self.inv.ti.get(ind.lower())
        if not ti and "." in ind and not re.match(r"^\d+\.\d+\.\d+\.\d+$", ind):
            parts = ind.lower().split(".")
            for i in range(1, len(parts) - 1):
                ti = self.inv.ti.get(".".join(parts[i:]))
                if ti:
                    break
        geo = self.inv.geo.get(ind)
        bits = []
        if ti:
            bits.append(f'TIP: {ti["reputation"]} ({ti["confidence"]}) {ti["malware_family"] or ti["tags"]}'.strip()
                        + (f' — {ti["note"]}' if ti["note"] else ""))
        else:
            bits.append("TIP: sin coincidencias (desconocido ≠ limpio)")
        if geo:
            tags = [t for t, f in (("Tor", "is_tor"), ("VPN comercial", "is_vpn_provider"), ("hosting", "is_hosting"),
                                   ("proxy residencial", "is_residential_proxy")) if geo.get(f) == "True"]
            bits.append(f'GeoIP: {geo["country"]} {geo["city"]}, {geo["as_org"]} ({geo["asn"]})' + (f' [{", ".join(tags)}]' if tags else ""))
        self.log("intel", ind, " · ".join(bits))
        return {"tip": ti, "geo": geo}

    def sandbox(self, sha):
        if not sha:
            return None
        r = self.inv.sandbox.get(sha.lower())
        self.log("sandbox", sha[:16] + "…", f'{r["file_name"]}: {r["verdict"]} ({r["score"]}) {r["malware_family"]}' if r
                 else "sin informe (no se ha enviado a la sandbox)")
        return r

    def changes(self, when, *keywords, scope=None):
        """Cambios aprobados que cubren `when` y mencionan alguna palabra clave."""
        hits = []
        for c in self.inv.changes:
            if not (c["_start"] - dt.timedelta(minutes=30) <= when <= c["_end"] + dt.timedelta(minutes=30)):
                continue
            blob = " ".join([c["titulo"], c["detalle"], c["alcance"], c["id"]]).lower()
            if not keywords or any(k.lower() in blob for k in keywords if k):
                hits.append(c)
        self.log("cambios", {"cuando": fmt_local(when), "claves": [k for k in keywords if k]},
                 "; ".join(f'{c["id"]} «{c["titulo"]}» ({c["inicio"]}→{c["fin"]} local)' for c in hits) or "ningún cambio aprobado lo cubre")
        return hits

    def change_by_id(self, cid):
        c = next((c for c in self.inv.changes if c["id"].lower() == str(cid).lower()), None)
        self.log("cambios", cid, f'{c["id"]} «{c["titulo"]}» {c["inicio"]}→{c["fin"]} local' if c else "no existe en el calendario")
        return c

    # logs ------------------------------------------------------------------------------------
    def event(self, eid):
        r = self.db.execute("SELECT doc FROM events WHERE event_id=?", (eid,)).fetchone()
        return json.loads(r[0]) if r else None

    def related(self, alert):
        evs = [e for e in (self.event(x) for x in alert.get("related_events") or []) if e]
        self.log("eventos relacionados", f'{len(alert.get("related_events") or [])} ids', f"{len(evs)} eventos recuperados", len(evs))
        return evs

    def search(self, etype, value, start, end, sources=None, limit=500, why=""):
        if not value:
            return []
        sql = "SELECT e.doc, e.source FROM ent n JOIN events e ON e.event_id=n.event_id WHERE n.etype=? AND n.value=? AND n.ts BETWEEN ? AND ?"
        args = [etype, str(value).lower(), iso(start), iso(end)]
        if sources:
            sql += f" AND n.source IN ({','.join('?' * len(sources))})"; args += list(sources)
        sql += " ORDER BY n.ts LIMIT ?"; args.append(limit)
        ck = (sql, tuple(args))
        if ck not in self._cache:
            if len(self._cache) > 5000:
                self._cache.clear()
            self._cache[ck] = [{**json.loads(d), "_src": s} for d, s in self.db.execute(sql, args)]
        rows = self._cache[ck]
        by = {}
        for r in rows:
            by[r["_src"]] = by.get(r["_src"], 0) + 1
        self.log("logs", {"entidad": f"{etype}={value}", "desde": iso(start)[:16], "hasta": iso(end)[:16],
                          **({"fuentes": sources} if sources else {}), **({"motivo": why} if why else {})},
                 ", ".join(f"{k}: {v}" for k, v in by.items()) or "sin eventos", len(rows))
        return rows

    def grep(self, source, text, start=None, end=None, limit=200, why=""):
        sql = "SELECT doc FROM events WHERE source=? AND doc LIKE ?"
        args = [source, f"%{text}%"]
        if start:
            sql += " AND ts>=?"; args.append(iso(start))
        if end:
            sql += " AND ts<=?"; args.append(iso(end))
        sql += " ORDER BY ts LIMIT ?"; args.append(limit)
        ck = (sql, tuple(args))
        if ck not in self._cache:
            if len(self._cache) > 5000:
                self._cache.clear()
            self._cache[ck] = [json.loads(d) for (d,) in self.db.execute(sql, args)]
        rows = self._cache[ck]
        self.log("logs (texto)", {"fuente": source, "texto": text, **({"motivo": why} if why else {})}, f"{len(rows)} eventos", len(rows))
        return rows

    def count(self, etype, value, source=None, start=None, end=None):
        sql = "SELECT COUNT(*) FROM ent WHERE etype=? AND value=?"; args = [etype, str(value).lower()]
        if source:
            sql += " AND source=?"; args.append(source)
        if start:
            sql += " AND ts>=?"; args.append(iso(start))
        if end:
            sql += " AND ts<=?"; args.append(iso(end))
        return self.db.execute(sql, args).fetchone()[0]

    def other_alerts(self, alert, hours=24, keys=None):
        t = parse_ts(alert["created_at"])
        ents = keys if keys is not None else alert_keys(alert)
        if not ents:
            return []
        found = {}
        for et, v in ents:
            for aid, rid, ts in self.db.execute(
                    "SELECT alert_id, rule_id, ts FROM aent WHERE etype=? AND value=? AND ts BETWEEN ? AND ? LIMIT 200",
                    (et, v, iso(t - dt.timedelta(hours=hours)), iso(t + dt.timedelta(hours=hours)))):
                if aid != alert["alert_id"]:
                    found.setdefault(aid, {"alert_id": aid, "rule_id": rid, "ts": ts, "via": f"{et}={v}"})
        res = sorted(found.values(), key=lambda x: x["ts"])
        rules = {}
        for r in res:
            rules[r["rule_id"]] = rules.get(r["rule_id"], 0) + 1
        self.log("otras alertas ±%dh" % hours, [f"{a}={b}" for a, b in ents][:6],
                 ", ".join(f"{k}×{v}" for k, v in rules.items()) or "ninguna", len(res))
        return res

    def alert(self, aid):
        r = self.db.execute("SELECT doc FROM alerts WHERE alert_id=?", (aid,)).fetchone()
        return json.loads(r[0]) if r else None


def alert_keys(a):
    """Entidades «fuertes» de una alerta para correlacionar (sin IPs corporativas ni dominios genéricos)."""
    from build_index import alert_entities
    out = []
    for t, v in alert_entities(a):
        if t == "ip" and (v.startswith("10.") or v == "198.18.200.10"):
            continue  # IP interna (ya va por hostname) o salida corporativa compartida
        out.append((t, v))
    return out
