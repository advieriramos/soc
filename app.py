"""Panel del SOC: cola de incidentes, traza de la IA, propuesta y aprobación humana.

    uvicorn app:app --port 8080        →  http://localhost:8080

Si la API simulada (06_herramientas/mock_soc_api.py, puerto 8000) está arrancada, la contención se ejecuta contra ella
(con su approval_token). Si no, se simula aquí con las mismas reglas y se registra en data/containment_local.jsonl.
"""
import datetime as dt, json, os, threading, uuid

import requests
from fastapi import FastAPI, HTTPException, UploadFile, File, Body
from fastapi.responses import HTMLResponse, JSONResponse

from config import DATA_DIR, OUT_DIR, SOC_API, HERE
from context import Tools, SEV_ORDER
from engine import triage, APPROVAL
from correlate import build_incidents
import agent

app = FastAPI(title="Tarvia · Triaje N1 con IA")
LOCK = threading.Lock()
TOOLS = None
STATE = {"tickets": {}, "by_alert": {}, "incidents": [], "inc_by_id": {}, "dataset": ""}
DEMO = os.environ.get("TARVIA_DATASET") == "demo"   # ./arrancar.sh demo → la cola empieza vacía
DECISIONS = os.path.join(OUT_DIR, "decisions_demo.jsonl" if DEMO else "decisions.jsonl")
LOCAL_LOG = os.path.join(OUT_DIR, "containment_local.jsonl")
API_ACTIONS = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email", "disable_access_key"}


SLA = {"critical": "15 min", "high": "30 min", "medium": "4 h", "low": "24 h", "informational": "revisión diaria"}
SLA_MIN = {"critical": 15, "high": 30, "medium": 240, "low": 1440, "informational": 1440}
RECEIVED = {}  # alert_id → cuándo entró en la cola (el reloj del SLA empieza ahí)


def _now():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
# Qué hace que un caso sea más urgente que otro de la misma severidad (impacto para Tarvia).
IMPACT = [
    ({"UC-EDR-007"}, 40, "ransomware inminente"),
    ({"UC-EDR-012"}, 35, "tarjetas de clientes (PCI)"),
    ({"UC-EML-004", "UC-IDP-005"}, 35, "fraude de pagos"),
    ({"UC-CLD-004", "UC-DLP-001", "UC-DLP-002", "UC-NET-006"}, 30, "fuga de datos personales"),
    ({"UC-WEB-003", "UC-WEB-002"}, 25, "cuentas de clientes y fraude"),
    ({"UC-IDP-008", "UC-CLD-002", "UC-EDR-011"}, 25, "persistencia con privilegios"),
    ({"UC-EDR-004", "UC-NET-004"}, 20, "robo de credenciales / movimiento lateral"),
    ({"UC-IDP-003", "UC-IDP-004", "UC-IDP-006", "UC-IDP-002"}, 15, "cuenta comprometida"),
    ({"UC-AI-002"}, 15, "fuga en el asistente Vela"),
    ({"UC-EDR-006"}, 5, "uso indebido de recursos"),
]


def _priority(inc):
    rules = {x["rule_id"] for x in inc.get("_timeline", [])} | {inc.get("_rule_id")}
    score = SEV_ORDER.index(inc["severity"]) * 100 + (60 if inc["escalation"]["escalate"] else 0)
    why = []
    for rs, pts, label in IMPACT:
        if rules & rs:
            score += pts; why.append(label)
    score += min(len(rules), 6) * 3  # cadenas largas: varias fases del ataque
    if len(rules) >= 3:
        why.append(f"cadena de {len(rules)} fases")
    return score, why[:3]


def _report_data(inc):
    from investigate import report
    return report(inc, _kids(inc, 60), STATE["incidents"], Tools())


def _kids(inc, n=15):
    return [STATE["tickets"][c] for c in inc["_children"][:n] if c in STATE["tickets"]]


def _index(tickets, incidents, name):
    STATE["tickets"] = {t["ticket_id"]: t for t in tickets}
    STATE["by_alert"] = {t["alert_ids"][0]: t for t in tickets}
    now = _now()
    for t in tickets:
        RECEIVED.setdefault(t["alert_ids"][0], now)
    human = {}
    if os.path.exists(DECISIONS):
        for line in open(DECISIONS, encoding="utf-8"):
            d = json.loads(line)
            human.setdefault(d.get("incident_id"), []).append(d)
    for i in incidents:
        i["_priority"], i["_priority_why"] = _priority(i)
        i["_sla"] = SLA.get(i["severity"], "")
        i["_sla_min"] = SLA_MIN.get(i["severity"], 1440)
        i["_received_at"] = max(RECEIVED.get(a, now) for a in i["alert_ids"])
        i["_human"] = human.get(i["ticket_id"], [])
        i["executed_actions"] = [d["result"]["record"] for d in i["_human"] if d.get("type") == "action" and d.get("result", {}).get("ok")]
        i["_pending"] = _pending_of(i["_human"])
    # Orden de la cola: primero lo pendiente de decidir, por urgencia; lo ya revisado baja al final.
    incidents.sort(key=lambda i: (bool(_decision_of(i)), -i["_priority"], i["_first_seen"]))
    STATE["incidents"] = incidents
    STATE["inc_by_id"] = {i["ticket_id"]: i for i in incidents}
    STATE["dataset"] = name


def _agent_of(inc):
    return inc.get("_agent") or agent.cached(inc)


CLOSE = {"benign_true_positive", "false_positive"}


def _compare(inc):
    """¿Coinciden la IA y el motor? Autorizado y falsa alarma cuentan igual: los dos significan «cerrar»."""
    P = (_agent_of(inc) or {}).get("prediction")
    if not P:
        return ""
    same_family = (P["verdict"] in CLOSE) == (inc["verdict"] in CLOSE) and (P["verdict"] == "needs_more_info") == (inc["verdict"] == "needs_more_info")
    if not same_family or bool(P.get("escalate")) != bool(inc["escalation"]["escalate"]):
        return "discrepa"
    return "coincide" if P.get("severity") == inc["severity"] or P["verdict"] in CLOSE else "parcial"


def _review_why(inc):
    """Un caso va a «Para revisar» si lo escala el motor, si lo escala la IA, si discrepan o si falta información."""
    why = []
    if inc["escalation"]["escalate"]:
        why.append("el motor lo escala")
    if inc["verdict"] == "needs_more_info":
        why.append("falta información")
    ag = _agent_of(inc) or {}
    P, V = ag.get("prediction") or {}, ag.get("verification") or {}
    if P.get("escalate") and not inc["escalation"]["escalate"]:
        why.append("la IA lo escala")
    if _compare(inc) == "discrepa":
        why.append("la IA y el motor no coinciden")
    return why


def _prio_now(inc):
    """Urgencia actual: la del motor, subida si la IA ve el caso más grave o pide revisarlo."""
    p = inc.get("_priority", 0)
    P = (_agent_of(inc) or {}).get("prediction") or {}
    if P.get("severity") in SEV_ORDER:
        p += max(0, SEV_ORDER.index(P["severity"]) - SEV_ORDER.index(inc["severity"])) * 100
    if _review_why(inc) and not inc["escalation"]["escalate"]:
        p += 60
    return p


def _sev_now(inc):
    """Gravedad que manda en la cola y en el SLA: la mayor entre la del motor y la que predice la IA."""
    P = (_agent_of(inc) or {}).get("prediction") or {}
    s = [inc["severity"]] + ([P["severity"]] if P.get("severity") in SEV_ORDER else [])
    return max(s, key=SEV_ORDER.index)


def _n2_case(inc):
    """Lo que le toca al N2 (§4 y §5): casos escalados (por el motor o la IA) o con aprobaciones pedidas por el N1."""
    P = (_agent_of(inc) or {}).get("prediction") or {}
    return bool(inc["escalation"]["escalate"] or P.get("escalate") or inc.get("_pending"))


def _in_batch(inc):
    ids = STATE.get("batch", {}).get("ids") or set()
    return bool(ids & set(inc["alert_ids"]))


def _decision_of(inc):
    return next((h for h in reversed(inc.get("_human") or []) if h.get("type") == "decision" and h["ts"] >= inc.get("_received_at", "")), None)


# ======================================================================================== avisos al N2 (bandeja)
# Se avisa al N2 solo cuando hace falta: el N1 pide aprobar una acción, el N1 confirma un escalado, o un caso
# crítico/alto está a punto de agotar su SLA sin que nadie lo haya decidido. Un aviso por caso y motivo.
N2_INBOX = []
SEV_ES = {"critical": "crítica", "high": "alta", "medium": "media", "low": "baja", "informational": "informativa"}
ACT_ES = {"isolate_host": "Aislar el equipo", "disable_user": "Deshabilitar la cuenta", "reset_password": "Forzar cambio de contraseña",
          "revoke_sessions": "Cerrar sus sesiones", "disable_access_key": "Desactivar la clave cloud", "block_ioc": "Bloquear el indicador",
          "purge_email": "Borrar el correo de todos los buzones"}


def _notify(inc, kind, why, key):
    k = f'{inc["ticket_id"]}|{key}'
    if any(n["key"] == k for n in N2_INBOX):
        return None
    P = (_agent_of(inc) or {}).get("prediction") or {}
    sev = _sev_now(inc)
    title = P.get("title") or inc["title"]
    aff = inc["affected"]
    acts = [f'- {ACT_ES.get(a["action"], a["action"])}: {a["target"]}' for a in (P.get("actions") or inc["recommended_actions"])
            if a["action"] not in ("close", "escalate")][:5]
    body = (f'{P.get("summary") or inc["summary"][:600]}\n\n'
            f'Afectados: {", ".join((aff.get("users") or [])[:4] + (aff.get("hosts") or [])[:4]) or "ver el caso"}.\n'
            + (("Acciones propuestas:\n" + "\n".join(acts) + "\n") if acts else "")
            + f'\nCaso {inc["ticket_id"]} en el panel del SOC (alertas: {", ".join(inc["alert_ids"][:4])}{"…" if len(inc["alert_ids"]) > 4 else ""}).')
    n = {"id": uuid.uuid4().hex[:10], "key": k, "ts": _now(), "incident_id": inc["ticket_id"], "title": title, "severity": sev,
         "kind": kind, "why": why, "asunto": f"[{SEV_ES.get(sev, sev).upper()}] {title}", "mensaje": body, "by": "plantilla", "read": False}
    N2_INBOX.insert(0, n)
    if agent.available():
        def draft():  # ornith redacta el mensaje definitivo (si no responde, se queda la plantilla)
            n["by"] = "redactando"
            o = agent.write_message(inc, "N2")
            if o and not o.get("error") and o.get("mensaje"):
                n.update(asunto=o.get("asunto") or n["asunto"], mensaje=o["mensaje"], by="ornith")
            else:
                n["by"] = "plantilla"
        threading.Thread(target=draft, daemon=True).start()
    return n


def _sla_watch():
    """Aviso al N2 si un caso crítico o alto pendiente de decidir ha consumido el 75 % de su SLA."""
    now = dt.datetime.now(dt.timezone.utc)
    for inc in STATE["incidents"]:
        sev = _sev_now(inc)
        if sev not in ("critical", "high") or not _review_why(inc) or _decision_of(inc):
            continue
        try:
            rec = dt.datetime.fromisoformat(inc["_received_at"].replace("Z", "+00:00"))
        except Exception:
            continue
        limit = SLA_MIN[sev] * 60
        left = limit - (now - rec).total_seconds()
        if left < 0.25 * limit:
            txt = f"SLA vencido hace {int(-left // 60)} min" if left < 0 else f"quedan {int(left // 60)} min de SLA"
            _notify(inc, "sla", f"Caso {SEV_ES[sev]} sin decidir: {txt} y nadie lo ha revisado", "sla")


@app.get("/api/n2/inbox")
def n2_inbox():
    return {"items": N2_INBOX[:60], "unread": sum(1 for n in N2_INBOX if not n["read"]), "total": len(N2_INBOX)}


@app.post("/api/n2/inbox/read")
def n2_read():
    for n in N2_INBOX:
        n["read"] = True
    return {"unread": 0}


def _pending_of(human):
    """Peticiones de aprobación del N1 que el N2 aún no ha resuelto."""
    pend = {}
    for h in human:
        k = f'{h.get("action")}|{h.get("target")}'
        if h.get("type") == "request":
            pend[k] = h
        elif h.get("type") in ("action", "reject"):
            pend.pop(k, None)
    return pend


def load(name=None):
    global TOOLS
    if TOOLS is None:
        ensure_ready()
        TOOLS = Tools()
    name = name or os.environ.get("TARVIA_DATASET", "all")
    if name == "demo":
        # Modo demo: cola vacía; los logs, el inventario y las 11.061 alertas del mes siguen como contexto
        # para investigar. Al cargar el fichero de la demo, sus alertas entran, se trían y se agrupan en directo.
        if os.path.exists(DECISIONS):
            os.remove(DECISIONS)
        _index([], [], name)
        return
    tp = os.path.join(OUT_DIR, f"{name}_alert_tickets.json"); ip = os.path.join(OUT_DIR, f"{name}_incidents.json")
    if not os.path.exists(tp):
        from run_batch import run, load as load_jsonl
        src = os.path.join(DATA_DIR, "03_alertas", "alertas.jsonl" if name == "all" else "alertas_muestra_desarrollo.jsonl")
        run(load_jsonl(src), name)
    tickets = json.load(open(tp, encoding="utf-8")); incidents = json.load(open(ip, encoding="utf-8"))
    from engine import ENGINE_VERSION
    vp = os.path.join(OUT_DIR, f"{name}_engine_version.txt")
    if not os.path.exists(vp) or open(vp).read().strip() != ENGINE_VERSION:  # casos de una versión anterior del motor
        from run_batch import run, load as load_jsonl
        src = os.path.join(DATA_DIR, "03_alertas", "alertas.jsonl" if name == "all" else "alertas_muestra_desarrollo.jsonl")
        run(load_jsonl(src), name)
        tickets = json.load(open(tp, encoding="utf-8")); incidents = json.load(open(ip, encoding="utf-8"))
        open(vp, "w").write(ENGINE_VERSION)
    _index(tickets, incidents, name)


@app.on_event("startup")
def _startup():
    load()
    # El agente investiga en segundo plano, de uno en uno, los casos a revisar (si hay clave del LLM del DCC).
    agent.precompute([i for i in STATE["incidents"] if _review_why(i)], _kids, prio=agent.PRIO_REVIEW,
                     report_of=_report_data, report_if=lambda i: bool(_review_why(i)))


def ensure_ready():
    """Prepara todo lo necesario antes de arrancar: índice válido y tickets."""
    from build_index import index_ok, build
    if not index_ok():
        print("Creando el índice de logs (solo la primera vez, ~1 min)…", flush=True)
        build()
        for f in os.listdir(OUT_DIR):  # los tickets antiguos dependían del índice anterior
            if f.startswith("all_") and f.endswith(".json"):
                os.remove(os.path.join(OUT_DIR, f))


# ------------------------------------------------------------------------------------------- API de lectura
def _row(i):
    return {k: i.get(k) for k in ("ticket_id", "title", "verdict", "confidence", "severity", "_kind", "_first_seen", "_last_seen",
                                   "_rule_id", "_product", "_priority_why", "_sla", "_sla_min", "_received_at", "_rule_severity")} | {
        "n": len(i["alert_ids"]), "alert_ids": i["alert_ids"][:2], "escalate": i["escalation"]["escalate"], "injection": bool(i.get("_injection")),
        "decided_at": (_decision_of(i) or {}).get("ts"), "decided": bool(_decision_of(i)),
        "decided_by": (_decision_of(i) or {}).get("analyst"), "decided_role": (_decision_of(i) or {}).get("role"), "n2": _n2_case(i), "new": bool(i.get("_new")),
        "pending": len(i.get("_pending") or {}), "review_why": _review_why(i), "in_batch": _in_batch(i),
        "ai_severity": ((_agent_of(i) or {}).get("prediction") or {}).get("severity"),
        "agent_state": agent.state(i["ticket_id"]), "sev_now": _sev_now(i), "ai_done": bool(_agent_of(i)),
        "_sla_min": SLA_MIN.get(_sev_now(i), 1440), "_sla": SLA.get(_sev_now(i), "")}


@app.get("/api/stats")
def stats():
    _sla_watch()
    inc = STATE["incidents"]; t = list(STATE["tickets"].values())
    c = lambda it, k: {x: sum(1 for y in it if y[k] == x) for x in sorted({y[k] for y in it})}
    review = [i for i in inc if _review_why(i)]
    b = STATE.get("batch") or {}
    running = STATE["inc_by_id"].get(agent.STATUS["running"] or "")
    props = [i for i in inc if not _review_why(i) and not _decision_of(i)]
    return {"dataset": STATE["dataset"], "demo": STATE["dataset"] == "demo", "alerts": len(t),
            "proposals_pending": len(props), "info_pending": sum(1 for i in props if _sev_now(i) == "informational"),
            "n2_queue": sum(1 for i in inc if _n2_case(i)), "tickets": len(inc), "escalated": len(review), "review": len(review),
            "closed": len(inc) - len(review),
            "batch": {k: v for k, v in b.items() if k != "ids"} | {"cases": sum(1 for i in inc if _in_batch(i)),
                                                                     "review": sum(1 for i in review if _in_batch(i)),
                                                                     "ai_done": sum(1 for i in inc if _in_batch(i) and _agent_of(i)),
                                                                     "ai_moved": sum(1 for i in review if _in_batch(i) and not i["escalation"]["escalate"])} if b else None,
            "agent_running_title": running["title"] if running else "", "agent_running_kind": agent.STATUS.get("running_kind", ""),
            "alert_verdicts": c(t, "verdict"), "alert_severity": c(t, "severity"),
            "ticket_severity": c(inc, "severity"), "pending_human": sum(1 for i in review if not _decision_of(i)),
            "agent": agent.available(), "agent_model": agent.MODEL, "agent_running": agent.STATUS["running"],
            "agent_queue": len(agent.queued_ids("inv")),
            "n2_unread": sum(1 for n in N2_INBOX if not n["read"]), "n2_total": len(N2_INBOX), "soc_api": _api_up(),
            "reduction": round(100 * (1 - len(inc) / max(1, len(t))), 1),
            "avg_triage_ms": round(1000 * sum(x["triage_seconds"] for x in t) / max(1, len(t)), 1)}


@app.get("/api/incidents")
def incidents(q: str = "", view: str = "escalated", limit: int = 400, role: str = "N1"):
    # Orden en tiempo real: lo pendiente primero y por urgencia; lo ya decidido baja al final.
    rows = sorted(STATE["incidents"], key=lambda i: (bool(_decision_of(i)), not _review_why(i), -_prio_now(i), i["_first_seen"]))
    if q.strip():
        view = "all"  # la búsqueda mira todas las pestañas: una alerta puede estar en un caso cerrado
    if view == "escalated" and role.upper() == "N2":
        rows = [i for i in rows if _n2_case(i)]  # el N2 solo ve lo que se le ha escalado
    elif view == "escalated":
        rows = [i for i in rows if _review_why(i)]
    elif view == "batch":
        rows = [i for i in rows if _in_batch(i)]
    elif view == "closed":
        rows = [i for i in rows if not _review_why(i)]
    elif view == "tp":
        rows = [i for i in rows if i["verdict"] in ("true_positive", "needs_more_info") and not i["escalation"]["escalate"]]
    elif view == "benign":
        rows = [i for i in rows if i["verdict"] in ("benign_true_positive", "false_positive")]
    elif view == "nmi":
        rows = [i for i in rows if i["verdict"] == "needs_more_info"]
    ql = q.strip().lower()
    if ql:
        rows = [i for i in rows if ql in json.dumps({k: i[k] for k in ("ticket_id", "title", "alert_ids", "affected", "_rule_id")}, ensure_ascii=False).lower()]
    items = []
    for i in rows[:limit]:
        r = _row(i)
        r["match"] = [a for a in i["alert_ids"] if ql and ql in a.lower()][:3]
        items.append(r)
    return {"total": len(rows), "items": items}


@app.get("/api/incident/{iid}")
def incident(iid: str):
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    kids = [STATE["tickets"][c] for c in inc["_children"][:60] if c in STATE["tickets"]]
    inc["_agent"] = inc.get("_agent") or agent.cached(inc)
    inc["_agent_state"] = agent.state(iid)
    inc["_review_why"] = _review_why(inc)
    inc["_n2"] = _n2_case(inc)
    inc["_decision"] = _decision_of(inc)
    inc["_compare"] = _compare(inc)
    inc["_sla_min"], inc["_sla"] = SLA_MIN.get(_sev_now(inc), 1440), SLA.get(_sev_now(inc), "")
    return {"incident": inc, "children": kids}


@app.get("/api/alert/{aid}")
def alert(aid: str):
    a = TOOLS.alert(aid)
    if not a:
        raise HTTPException(404)
    t = STATE["by_alert"].get(aid)
    inc = next((i["ticket_id"] for i in STATE["incidents"] if t and t["ticket_id"] in i["_children"]), None)
    return {"alert": a, "ticket": t, "incident_id": inc}


@app.post("/api/retriage/{aid}")
def retriage(aid: str):
    """Vuelve a triar una alerta en directo (para la demo: se ve la traza paso a paso)."""
    a = TOOLS.alert(aid)
    if not a:
        raise HTTPException(404)
    with LOCK:
        t = triage(a, TOOLS)
    return {"alert": a, "ticket": t}


@app.post("/api/ingest")
async def ingest(file: UploadFile = File(...)):
    """Añade alertas nuevas a la cola en vivo: se trían, se correlacionan con todo lo anterior y se reordena la cola.
    Acepta JSONL (una alerta por línea) o una lista JSON. Las que ya estaban en la cola no se duplican."""
    from build_index import alert_entities
    raw = (await file.read()).decode("utf-8-sig", errors="replace").strip()
    alerts, bad = [], 0
    try:
        parsed = json.loads(raw)
        alerts = parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        for line in raw.splitlines():
            if line.strip():
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    bad += 1
    alerts = [x for x in alerts if isinstance(x, dict) and x.get("alert_id") and x.get("created_at") and x.get("rule_id")]
    if not alerts:
        raise HTTPException(400, "El fichero no contiene alertas válidas (se espera JSONL o una lista JSON con alert_id, created_at y rule_id).")
    with LOCK:
        now = _now()
        new = [x for x in alerts if x["alert_id"] not in STATE["by_alert"]]
        for x in new:
            x.setdefault("rule_name", x["rule_id"]); x.setdefault("severity", "medium"); x.setdefault("entities", {}); x.setdefault("evidence", {})
            TOOLS.db.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?)", (x["alert_id"], x["created_at"], x["rule_id"], json.dumps(x, ensure_ascii=False)))
            TOOLS.db.execute("DELETE FROM aent WHERE alert_id=?", (x["alert_id"],))
            TOOLS.db.executemany("INSERT INTO aent VALUES(?,?,?,?,?)", [(x["alert_id"], x["created_at"], x["rule_id"], t, v) for t, v in alert_entities(x)])
        TOOLS.db.commit()
        for x in alerts:  # todo lo cargado «llega ahora»: su reloj de SLA empieza en este momento
            RECEIVED[x["alert_id"]] = now
        fresh = []
        for x in sorted(new, key=lambda x: x["created_at"]):
            try:
                fresh.append(triage(x, TOOLS))
            except Exception:
                bad += 1
        tickets = list(STATE["tickets"].values()) + fresh
        incs = build_incidents(tickets) if fresh else STATE["incidents"]
        new_ids = {t["ticket_id"] for t in fresh}
        for i in incs:
            i["_new"] = bool(new_ids & set(i["_children"])) or i.get("_new", False)
        STATE["batch"] = {"ids": {x["alert_id"] for x in alerts}, "file": file.filename, "ts": now, "received": len(alerts),
                          "new": len(fresh), "existing": len(alerts) - len(new), "invalid": bad}
        # En memoria: al reiniciar el panel se vuelve al mes original (útil para ensayar la demo varias veces).
        _index(tickets, incs, STATE["dataset"] or "all")
    # La IA investiga TODO lo cargado antes que nada (lo más urgente primero); después redacta los informes.
    batch = sorted([i for i in STATE["incidents"] if _in_batch(i)], key=lambda i: (not _review_why(i), -_prio_now(i)))
    rev = [i for i in batch if _review_why(i)]
    agent.precompute(batch, _kids, prio=agent.PRIO_NEW, report_of=_report_data, report_if=lambda i: bool(_review_why(i)))
    return {"received": len(alerts), "new": len(fresh), "already_in_queue": len(alerts) - len(new), "invalid": bad,
            "cases": len(batch), "review": len(rev)}


@app.post("/api/dataset/{name}")
def switch(name: str):
    with LOCK:
        load(name)
    return stats()


@app.get("/api/datasets")
def datasets():
    return sorted({f.rsplit("_alert_tickets.json", 1)[0] for f in os.listdir(OUT_DIR) if f.endswith("_alert_tickets.json")})


# ------------------------------------------------------------------------------------------- humano en el bucle
def _api_up():
    try:
        return requests.get(SOC_API + "/containment/log", timeout=0.6).status_code == 200
    except Exception:
        return False


def _log(rec):
    with open(DECISIONS, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


@app.post("/api/incident/{iid}/action")
def do_action(iid: str, body: dict = Body(...)):
    """Política §4: el N1 ejecuta lo que no requiere aprobación y SOLICITA el resto; solo un N2 puede aprobarlo."""
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    action, target = body["action"], body["target"]
    analyst = (body.get("analyst") or "").strip()
    role = (body.get("role") or "N1").upper()
    if not analyst:
        raise HTTPException(400, "Indica tu nombre")
    if action in ("escalate", "close"):
        raise HTTPException(400, "Escalar o cerrar es una decisión del caso, no una acción de contención")
    if role == "N2" and not _n2_case(inc):
        raise HTTPException(403, "Caso del N1: no está escalado y no requiere al N2 (política §5)")
    req, who = APPROVAL.get(action, (False, ""))
    agent_acts = ((inc.get("_agent") or {}).get("prediction") or {}).get("actions") or []
    prop = next((x for x in inc["recommended_actions"] + agent_acts if x["action"] == action and x["target"] == target), None)
    if prop:
        req = prop["requires_approval"] or req
    if action == "isolate_host" and str(target).upper().startswith(("PLC-", "HMI-")):
        raise HTTPException(403, "Política: el SOC no actúa sobre OT; escalar a Operaciones")
    justification = body.get("justification") or (prop or {}).get("justification", "")
    key = f"{action}|{target}"
    if req and role != "N2":
        d = {"type": "request", "incident_id": iid, "ts": _now(), "analyst": analyst, "role": role, "action": action, "target": target,
             "justification": justification}
        inc.setdefault("_human", []).append(d); _log(d)
        inc["_pending"] = _pending_of(inc["_human"])
        _notify(inc, "aprobación", f'{analyst} (N1) pide aprobar «{ACT_ES.get(action, action)}» sobre {target}', f"req|{action}|{target}")
        return {"pending": True, "message": f"Solicitud enviada al N2: {action} sobre {target}"}
    approver = analyst if req else ""
    rec = None; mode = "manual"
    if action in API_ACTIONS:
        if _api_up():
            mode = "api"
            tok = ""
            if req:
                r = requests.post(SOC_API + "/approvals", json={"action": action, "target": target, "approver": approver, "reason": justification}, timeout=5)
                tok = r.json()["approval_token"]
            r = requests.post(SOC_API + f"/containment/{action}", timeout=5,
                              json={"target": target, "justification": justification, "approval_token": tok, "ticket_id": iid})
            if r.status_code != 200:
                raise HTTPException(r.status_code, r.json().get("detail", r.text))
            rec = r.json()
        else:
            mode = "simulado-local"
            rec = {"timestamp": _now(), "action": action, "target": target, "justification": justification,
                   "approval_token": ("APR-" + uuid.uuid4().hex[:10]) if req else "", "ticket_id": iid, "result": "ok (simulado local)"}
            with open(LOCAL_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    else:
        rec = {"timestamp": _now(), "action": action, "target": target, "justification": justification,
               "ticket_id": iid, "result": "tarea manual registrada"}
    requester = (inc.get("_pending") or {}).get(key, {}).get("analyst")
    rec.update({"executed_by": analyst, "approved_by": approver or None, "requested_by": requester, "mode": mode})
    inc["executed_actions"].append(rec)
    d = {"type": "action", "incident_id": iid, "ts": rec["timestamp"], "analyst": analyst, "role": role, "approver": approver,
         "action": action, "target": target, "result": {"ok": True, "record": rec}}
    inc.setdefault("_human", []).append(d); _log(d)
    inc["_pending"] = _pending_of(inc["_human"])
    return rec


@app.post("/api/incident/{iid}/reject")
def reject(iid: str, body: dict = Body(...)):
    """El N2 rechaza una acción que pidió el N1."""
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    if (body.get("role") or "").upper() != "N2":
        raise HTTPException(403, "Solo un N2 puede rechazar una solicitud")
    d = {"type": "reject", "incident_id": iid, "ts": _now(), "analyst": body.get("analyst", ""), "role": "N2",
         "action": body["action"], "target": body["target"], "comment": body.get("comment", "")}
    inc.setdefault("_human", []).append(d); _log(d)
    inc["_pending"] = _pending_of(inc["_human"])
    return d


@app.post("/api/incident/{iid}/decision")
def decision(iid: str, body: dict = Body(...)):
    """Decisión final del analista: aceptar el triaje de la IA o corregirlo (queda registrado para medir acierto)."""
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    if not (body.get("analyst") or "").strip():
        raise HTTPException(400, "Indica el analista")
    if str(body.get("role", "N1")).upper() == "N2" and not _n2_case(inc):
        raise HTTPException(403, "Caso del N1: no está escalado y no requiere al N2 (política §5)")
    d = {"type": "decision", "incident_id": iid, "ts": _now(), "analyst": body["analyst"], "role": body.get("role", "N1"),
         "decision": body.get("decision"), "verdict": body.get("verdict") or inc["verdict"],
         "severity": body.get("severity") or inc["severity"], "comment": body.get("comment", ""),
         "ai_verdict": inc["verdict"], "ai_severity": inc["severity"],
         "agent_verdict": (((inc.get("_agent") or {}).get("prediction")) or {}).get("verdict"),
         "agent_severity": (((inc.get("_agent") or {}).get("prediction")) or {}).get("severity")}
    inc.setdefault("_human", []).append(d); _log(d)
    P = (_agent_of(inc) or {}).get("prediction") or {}
    must = P.get("escalate") if P else inc["escalation"]["escalate"]
    if d["decision"] == "predicción confirmada" and must and d["role"] != "N2":
        why = (inc["escalation"].get("reason") or "; ".join((P.get("reasons") or [])[:1]) or "la política obliga a escalar")[:220]
        _notify(inc, "escalado", f'{d["analyst"]} (N1) confirma el escalado: {why}', "escalado")
    return d


@app.post("/api/close_batch")
def close_batch(body: dict = Body(...)):
    """Revisión en lote diaria (§3): el N1 confirma de una vez el cierre de los casos INFORMATIVOS que la IA propone cerrar.
    Los bajos y medios se confirman uno a uno (tienen SLA de triaje propio)."""
    analyst = (body.get("analyst") or "").strip()
    if not analyst:
        raise HTTPException(400, "Indica el analista")
    if str(body.get("role", "N1")).upper() != "N1":
        raise HTTPException(403, "La revisión en lote de cierres es del N1")
    n = 0
    for inc in STATE["incidents"]:
        if _review_why(inc) or _decision_of(inc) or _sev_now(inc) != "informational":
            continue
        d = {"type": "decision", "incident_id": inc["ticket_id"], "ts": _now(), "analyst": analyst, "role": "N1",
             "decision": "cierre confirmado en la revisión en lote (§3)", "verdict": inc["verdict"], "severity": inc["severity"],
             "comment": "", "ai_verdict": inc["verdict"], "ai_severity": inc["severity"]}
        inc.setdefault("_human", []).append(d); _log(d); n += 1
    return {"closed": n}


@app.post("/api/incident/{iid}/agent")
def run_agent(iid: str, force: bool = False):
    """El agente investiga el caso y predice; el motor de reglas verifica. Solo predice: decide la persona."""
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    out = agent.investigate(inc, _kids(inc), force=force)
    if "error" not in out:
        inc["_agent"] = out
        why = _review_why(inc)
        if why:  # si ahora hay que revisarlo, la IA redacta también su informe (en segundo plano)
            agent.precompute([inc], _kids, prio=agent.PRIO_NEW, report_of=_report_data, report_if=lambda i: True)
        return {**out, "review_why": why}
    return out


@app.get("/api/incident/{iid}/report")
def incident_report(iid: str):
    """Nivel 3: informe de investigación (informe_incidente.schema.json)."""
    from investigate import report
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    kids = [STATE["tickets"][c] for c in inc["_children"] if c in STATE["tickets"]]
    with LOCK:
        return report(inc, kids, STATE["incidents"], TOOLS)


@app.get("/api/incident/{iid}/report_llm")
def report_llm(iid: str, generate: bool = False):
    """Nivel 3: informe redactado por el LLM + cronología reconstruida por el código."""
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    rep = _report_data(inc)
    rep.pop("_trace", None)
    llm_part = agent.cached_report(inc) or (agent.write_report(inc, rep) if generate else None)
    return {"data": rep, "llm": llm_part}


@app.post("/api/incident/{iid}/message/{to}")
def message(iid: str, to: str):
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    return agent.write_message(inc, to)


@app.post("/api/committee")
def committee():
    return agent.write_committee(STATE["incidents"], stats())


@app.get("/api/incident/{iid}/export")
def export(iid: str):
    """Ticket en el formato de ticket_salida.schema.json (sin campos internos)."""
    inc = STATE["inc_by_id"].get(iid)
    if not inc:
        raise HTTPException(404)
    return JSONResponse({k: v for k, v in inc.items() if not k.startswith("_")})


@app.get("/", response_class=HTMLResponse)
def index():
    return open(os.path.join(HERE, "static", "index.html"), encoding="utf-8").read()


if __name__ == "__main__":
    import uvicorn, webbrowser
    ensure_ready()
    threading.Timer(2.5, lambda: webbrowser.open("http://localhost:8080")).start()
    uvicorn.run(app, host="127.0.0.1", port=8080)
