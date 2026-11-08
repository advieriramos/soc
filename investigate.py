"""Nivel 3: informe de investigación (formato informe_incidente.schema.json) para un incidente escalado.

Reconstruye la cadena con las alertas agrupadas y, además, pivota a los logs de los equipos y cuentas afectados para
encontrar los pasos que NO generaron alerta (que también son huecos de detección).
"""
import datetime as dt

from context import Tools, parse_ts, iso, fmt_local, norm_user, inventory
from engine import host_activity, describe_edr, Result

H = dt.timedelta(hours=1)

ROOT = {
    "UC-EML-002": "Correo con adjunto malicioso (suplantando a un proveedor) entregado y abierto por la usuaria; el EDR solo detectó y no bloqueó.",
    "UC-EML-001": "Campaña de phishing con suplantación de proveedor que llegó a los buzones; usuarios hicieron clic y entregaron la sesión (AiTM).",
    "UC-EML-003": "Phishing con kit AiTM: el usuario introdujo credenciales y el atacante reutilizó la cookie de sesión (el MFA no protege frente a robo de sesión).",
    "UC-IDP-004": "Credenciales y sesión robadas mediante phishing AiTM; acceso desde infraestructura de hosting.",
    "UC-IDP-002": "Password spraying con una contraseña estacional contra una cuenta de servicio excluida de MFA (riesgo aceptado en 2024).",
    "UC-IDP-003": "Fatiga MFA: el usuario aprobó una notificación push no solicitada.",
    "UC-NET-002": "Servidor expuesto a Internet con vulnerabilidad crítica sin parchear (ver vulnerabilidades).",
    "UC-EDR-006": "Servidor expuesto a Internet con vulnerabilidad crítica sin parchear (ver vulnerabilidades).",
    "UC-DEV-001": "Dependency confusion: el build resolvió un paquete público con el nombre de uno interno, que robó las claves AWS del runner.",
    "UC-WEB-002": "Credential stuffing contra la API de login de la app sin captcha; reutilización de contraseñas de clientes.",
    "UC-DLP-001": "Empleada saliente con acceso a datos de clientes; el DLP estaba en modo auditoría y no bloqueó.",
    "UC-AI-001": "El asistente Vela es vulnerable a prompt injection y reveló información interna en una respuesta.",
    "UC-EDR-005": "Ingeniería social (falso soporte) para instalar AnyDesk no aprobado en un portátil de tienda con red plana compartida con los TPV.",
    "UC-VPN-001": "Credenciales (incluido TOTP) del proveedor Logisoft usadas desde un origen no habitual fuera de su ventana contractual.",
}


def related_incidents(inc, incidents):
    mine = set(h.lower() for h in inc["affected"].get("hosts", [])) | set(u.lower() for u in inc["affected"].get("users", []))
    mine |= {e["indicator"].lower() for e in inc.get("enrichment", []) if e["type"] in ("ip", "domain", "sha256")}
    out = []
    for o in incidents:
        if o["ticket_id"] == inc["ticket_id"] or o["verdict"] != "true_positive" or o["_kind"] != "incident":
            continue
        theirs = set(h.lower() for h in o["affected"].get("hosts", [])) | set(u.lower() for u in o["affected"].get("users", []))
        theirs |= {e["indicator"].lower() for e in o.get("enrichment", []) if e["type"] in ("ip", "domain", "sha256")}
        common = (mine & theirs) - {"jump01"}
        if common:
            out.append(f'{o["ticket_id"]} ({", ".join(sorted(common))[:60]})')
    return out


def history(children, T, hours=72, cap=25):
    """Pivot a las alertas del mes: otras alertas sobre los mismos equipos, cuentas e indicadores (48 h antes y hasta
    `hours` después) que no
    están en este caso. Se trían con el motor y solo se quedan las reales: así la cadena se reconstruye aunque el caso
    haya entrado con una sola alerta."""
    from context import alert_keys
    from engine import triage
    from correlate import WEAK_KEYS
    mine = {c["alert_ids"][0] for c in children}
    since = iso(min(parse_ts(c["_created_at"]) for c in children) - dt.timedelta(hours=48)) if children else ""
    cand = {}
    for c in children:
        a = T.alert(c["alert_ids"][0])
        if not a:
            continue
        keys = [k for k in alert_keys(a) if k not in WEAK_KEYS and k[1] != "jump01"]
        for o in T.other_alerts(a, hours=hours, keys=keys):
            if o["alert_id"] not in mine and o["ts"] >= since:
                cand.setdefault(o["alert_id"], o)
    out, saved = [], T.trace
    for o in sorted(cand.values(), key=lambda x: x["ts"])[:200]:
        a = T.alert(o["alert_id"])
        if not a:
            continue
        T.trace = []
        try:
            t = triage(a, T)
        except Exception:
            continue
        if t["verdict"] in ("true_positive", "needs_more_info"):
            out.append((t, o["via"]))
        if len(out) >= cap:
            break
    T.trace = saved
    T.log("pivot a alertas del mes ±%dh" % hours, [v for _, v in out][:6], f"{len(out)} reales de {len(cand)} encontradas", len(out))
    return out


def report(inc, children, incidents, tools=None):
    T = tools or Tools()
    T.trace = []
    inv = inventory()
    first, last = parse_ts(inc["_first_seen"]), parse_ts(inc["_last_seen"])
    tl, seen = [], set()
    for c in children:
        tl.append({"timestamp": c["_created_at"], "event_id": c["alert_ids"][0], "description": "ALERTA · " + c["title"],
                   "mitre": ",".join(c["mitre"])})
        for e in c["evidence"]:
            seen.add(e["event_id"])
    hist = history(children, T)
    for t, via in hist:
        tl.append({"timestamp": t["_created_at"], "event_id": t["alert_ids"][0], "mitre": ",".join(t["mitre"]),
                   "description": f'ALERTA RELACIONADA del mes ({via}) · {t["title"]}'})
    alerted = set()
    for c in list(children) + [t for t, _ in hist]:
        a = T.alert(c["alert_ids"][0])
        alerted |= set((a or {}).get("related_events") or [])
    # Pivot: actividad rara en los equipos del incidente que no está en ninguna alerta.
    gaps = []
    for h in inc["affected"].get("hosts", [])[:12]:
        for e in host_activity(Result({"created_at": inc["_first_seen"]}, T), h, first - 48 * H, last + 24 * H, "pivot: pasos sin alerta"):
            if e["event_id"] in alerted:
                continue
            ch = T.changes(parse_ts(e["timestamp"]), h)
            if ch:
                tl.append({"timestamp": e["timestamp"], "event_id": e["event_id"], "mitre": "",
                           "description": f'{h} · {describe_edr(e)} (sin alerta; cubierto por {ch[0]["id"]}, actividad autorizada)'})
                continue
            tl.append({"timestamp": e["timestamp"], "event_id": e["event_id"], "description": f"{h} · {describe_edr(e)} (sin alerta)", "mitre": ""})
            gaps.append(f'{e.get("event_type")} en {h} ({e.get("process_name")} {(e.get("signer") or "")}) no generó alerta')
    tl.sort(key=lambda x: x["timestamp"])
    for x in tl:
        x["local"] = fmt_local(parse_ts(x["timestamp"]))
    kids = sorted(list(children) + [t for t, _ in hist], key=lambda c: c["_created_at"])
    hosts = list(dict.fromkeys(inc["affected"].get("hosts", []) + [h for t, _ in hist for h in t["affected"].get("hosts", [])]))
    users = list(dict.fromkeys(inc["affected"].get("users", []) + [u for t, _ in hist for u in t["affected"].get("users", [])]))
    first_c = kids[0]
    core = [c for c in kids if c["_rule_id"] != "UC-EML-001"] or kids  # quien reporta el phishing no es el paciente cero
    pz_host = next((h for c in core for h in c["affected"].get("hosts", [])), "")
    pz_user = next((u for c in core for u in c["affected"].get("users", [])), "")
    pz = " / ".join(x for x in (pz_user, pz_host) if x) or (first_c["affected"].get("customers") or ["(externo)"])[0]
    services = inc["affected"].get("business_services", [])
    svc_rows = [s for s in inv.services if s["servicio"] in services]
    data = []
    if any("CRM" in s or "clientes" in s.lower() for s in services) or any(c["_rule_id"] in ("UC-DLP-001", "UC-DLP-002", "UC-CLD-004", "UC-NET-006") for c in kids):
        data.append("datos personales de clientes (RGPD)")
    if any(c["_rule_id"] in ("UC-EDR-012",) for c in kids):
        data.append("datos de tarjeta en memoria de TPV (PCI DSS)")
    if any(c["_rule_id"] in ("UC-EML-004", "UC-IDP-005") for c in kids):
        data.append("correo de Tesorería / pagos a proveedores")
    if any(c["_rule_id"] in ("UC-EDR-004", "UC-IDP-008", "UC-NET-004") for c in kids):
        data.append("credenciales de administrador del dominio")
    notif = []
    if any("personales" in d for d in data):
        notif.append("DPO inmediatamente: evaluar notificación a la AEPD (y CNPD si hay clientes portugueses) en 72 h")
    if any("PCI" in d for d in data):
        notif.append("Responsable PCI y adquirente/procesador de pagos: posible compromiso de tarjetas en tienda")
    if any("pagos" in d for d in data):
        notif.append("Tesorería y Director Financiero: retener pagos al IBAN nuevo y verificar por teléfono con el proveedor")
    if inc["severity"] == "critical":
        notif.append("Responsable SOC y CISO (Alba Rovira) por teléfono — SLA critical 15 min")
    if any(c["_rule_id"] == "UC-VPN-001" for c in kids):
        notif.append("Logisoft (proveedor): confirmar si fueron ellos y rotar su TOTP")
    for c in kids:
        for q in c["open_questions"]:
            pass
    gaps = list(dict.fromkeys(gaps))[:8]
    for c in kids:
        r = " ".join(c["_reasons"]).lower()
        if "solo detectó" in r or "detected_only" in r:
            gaps.append("El EDR estaba en modo «solo detectar» en el puesto: pasar a bloqueo")
        if "solo auditó" in r:
            gaps.append("DLP en modo auditoría para datos de clientes hacia almacenamiento personal: pasar a bloqueo")
        if "excluida de mfa" in r or "sin mfa" in r:
            gaps.append("Cuenta de servicio sin MFA con acceso VPN: revisar el riesgo aceptado (restringir por IP)")
        if "captcha" in r:
            gaps.append("La API de login de la app no tiene captcha: activar captcha y rate limit por huella")
    plan = []
    for a in inc["recommended_actions"]:
        if a["action"] in ("close",):
            continue
        tgt = a["target"]; asset = inv.asset_by_host.get(str(tgt).lower())
        impact = ""
        if asset:
            s = next((s for s in inv.services if s["servicio"] == asset["business_service"]), None)
            impact = f'{asset["business_service"]}' + (f' — {s["impacto"]} (resp.: {s["responsable"]})' if s else "")
        plan.append({"action": a["action"], "target": tgt, "approver": a.get("approver") or ("N1 (sin aprobación)" if not a["requires_approval"] else "N2"),
                     "business_impact": impact or a.get("justification", "")})
    root = next((ROOT[c["_rule_id"]] for c in kids if c["_rule_id"] in ROOT), "Por determinar: " + first_c["title"])
    vulns = [v for h in inc["affected"].get("hosts", []) for v in inv.vulns if v["hostname"] == h and v["estado"] == "abierta"]
    if vulns and first_c["_rule_id"] in ("UC-NET-002", "UC-EDR-006"):
        root += f' {vulns[0]["hostname"]}: {vulns[0]["id"]} — {vulns[0]["notas"]}'
    rep = {
        "incident_id": inc["ticket_id"], "title": inc["title"], "alert_ids": inc["alert_ids"],
        "related_incidents": related_incidents(inc, incidents),
        "patient_zero": pz, "initial_access": f'{first_c["title"]} ({fmt_local(parse_ts(first_c["_created_at"]))}, {",".join(first_c["mitre"])})',
        "timeline": tl[:120],
        "scope": {"users": users, "hosts": hosts,
                  "data": "; ".join(data) or "sin datos sensibles confirmados",
                  "business_impact": "; ".join(f'{s["servicio"]}: {s["impacto"]}' for s in svc_rows) or "puesto(s) de trabajo"},
        "root_cause": root,
        "containment_plan": plan[:25],
        "eradication_and_recovery": [
            "Reimagen de los equipos con implante confirmado antes de reconectarlos",
            "Rotar todas las credenciales expuestas (usuarios, cuentas adm.*, cuentas de servicio, claves cloud, tokens)",
            "Eliminar la persistencia identificada (servicios, Run keys, cron, reglas de buzón, métodos MFA, usuarios IAM)",
            "Vigilancia reforzada 14 días de los IOC del incidente",
        ],
        "notifications": notif,
        "detection_gaps": list(dict.fromkeys(gaps))[:10],
        "confidence": inc["confidence"],
        "open_questions": inc["open_questions"],
        "_trace": T.trace,
    }
    return rep
