"""Agrupación de alertas en incidentes (nivel 2) y reconstrucción de la cadena (nivel 3).

- Ruido benigno (FP, actividad autorizada, escaneos bloqueados…): un ticket por patrón y día (`_group_key`).
- Actividad maliciosa relevante: unión de alertas que comparten entidades fuertes (equipo, cuenta, IP del atacante,
  hash, dominio, clave cloud, tienda…) sin límite de tiempo, para ver cadenas de días o semanas.
"""
import collections, re

from context import SEV_ORDER, parse_ts, fmt_local, to_local

NOISE_PREFIX = ("waf-scan", "av:", "stuffing-noise", "pentest", "sccm", "nessus", "travel", "dga", "beacon:", "sap-excel", "vela-fp",
                "bucket-public", "edr-stop:CHG", "spray-legacy", "cicd:", "dlp:", "phish-report", "vendor-late")
WEAK_KEYS = {("host", "jump01"), ("ip", "198.18.200.10"), ("user", "ext.logisoft")}


class UF:
    def __init__(self): self.p = {}
    def f(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]; x = self.p[x]
        return x
    def u(self, a, b): self.p[self.f(a)] = self.f(b)


def _sev(t): return SEV_ORDER.index(t["severity"])


def is_chain(t):
    if t["verdict"] not in ("true_positive", "needs_more_info"):
        return False
    gk = t.get("_group_key") or ""
    if gk.startswith(NOISE_PREFIX) and not t["escalation"]["escalate"]:
        return False  # ruido repetitivo sin escalar (p. ej. spraying bloqueado de severidad media): va en lotes por día
    if t["verdict"] == "needs_more_info" and not t["_links"]:
        return False
    return t["escalation"]["escalate"] or _sev(t) >= 2 or gk.startswith("campaign:")


def keys_of(t, strong):
    ks = set(tuple(l) for l in t["_links"])
    if strong:
        for et, v in _alert_keys(t):
            ks.add((et, v))
    return {k for k in ks if k not in WEAK_KEYS and k[1]}


def _alert_keys(t):
    out = []
    aff = t["affected"]
    for h in aff.get("hosts") or []:
        out.append(("host", h.lower()))
    for u in aff.get("users") or []:
        out.append(("user", u.lower().split("@")[0]))
    for c in aff.get("customers") or []:
        pass  # los clientes individuales no unen incidentes salvo vínculo explícito
    for e in t["enrichment"]:
        if e["type"] in ("ip", "sha256") and "Microsoft" not in e["result"]:
            out.append(("ip" if e["type"] == "ip" else "key", e["indicator"].lower()))
        if e["type"] == "domain" and "benign" not in e["result"]:
            out.append(("domain", e["indicator"].lower()))
    return out


def build_incidents(tickets):
    chain = [t for t in tickets if is_chain(t)]
    rest = [t for t in tickets if not is_chain(t)]
    uf = UF()
    owner = {}
    for t in chain:
        uf.f(t["ticket_id"])
        strong = (t["escalation"]["escalate"] or _sev(t) >= 2) and t["_rule_id"] not in ("UC-EML-001",)
        for k in keys_of(t, strong):
            if k in owner:
                uf.u(t["ticket_id"], owner[k])
            else:
                owner[k] = t["ticket_id"]
        gk = t.get("_group_key")
        if gk and not gk.startswith(NOISE_PREFIX):
            k = ("group", gk)
            if k in owner:
                uf.u(t["ticket_id"], owner[k])
            else:
                owner[k] = t["ticket_id"]
    groups = collections.defaultdict(list)
    for t in chain:
        groups[uf.f(t["ticket_id"])].append(t)
    # Las alertas bajas sin escalar con vínculo explícito a un incidente se le adjuntan (p. ej. reportes de la campaña).
    noise_groups = collections.defaultdict(list)
    for t in rest:
        attached = False
        if t["verdict"] == "true_positive":
            for k in set(tuple(l) for l in t["_links"]):
                if k in owner and k not in WEAK_KEYS:
                    groups[uf.f(owner[k])].append(t); attached = True; break
        if not attached:
            day = to_local(parse_ts(t["_created_at"])).strftime("%Y-%m-%d")
            gk = t.get("_group_key") or f'{t["_rule_id"]}:{t["title"][:40]}'
            same_day = t["verdict"] != "true_positive" or _sev(t) < 2 or gk.startswith(NOISE_PREFIX)
            noise_groups[(t["verdict"], gk, day if same_day else t["ticket_id"])].append(t)
    incidents = [merge(g, kind="incident") for g in groups.values()]
    incidents += [merge(g, kind="lote") for g in noise_groups.values()]
    incidents.sort(key=lambda i: (-SEV_ORDER.index(i["severity"]), not i["escalation"]["escalate"], i["_first_seen"]))
    return incidents


def merge(ts, kind):
    ts = sorted(ts, key=lambda t: t["_created_at"])
    top = max(ts, key=lambda t: (_sev(t), t["verdict"] == "true_positive", t["confidence"]))
    n = len(ts)
    if n == 1:
        inc = {k: v for k, v in top.items()}
        inc.update({"ticket_id": "INC-" + top["ticket_id"][4:], "_kind": kind, "_children": [top["ticket_id"]],
                    "_first_seen": top["_created_at"], "_last_seen": top["_created_at"], "_timeline": [_tl(top)]})
        return inc
    verdict = top["verdict"]
    sev = top["severity"]
    rules = collections.Counter(t["_rule_id"] for t in ts)
    esc = any(t["escalation"]["escalate"] for t in ts)
    reasons = [t["escalation"]["reason"] for t in ts if t["escalation"]["reason"]]
    # §5: varias alertas que juntas describen una cadena, aunque cada una sea baja
    distinct_tactics = len(rules)
    if verdict == "true_positive" and distinct_tactics >= 3 and kind == "incident" and not esc:
        esc = True; reasons.append(f"§5: {distinct_tactics} tipos de alerta distintos sobre las mismas entidades forman una cadena")
    # La cadena obliga a escalar (§5) pero no cambia la severidad: la política solo admite matriz ±1 por alerta.
    def uniq(items, key=lambda x: str(x)):
        seen, out = set(), []
        for i in items:
            k = key(i)
            if k not in seen:
                seen.add(k); out.append(i)
        return out
    affected = {k: uniq([x for t in ts for x in t["affected"].get(k, [])]) for k in ("users", "hosts", "business_services", "customers")}
    actions = uniq([a for t in ts for a in t["recommended_actions"] if a["action"] != "close" or verdict != "true_positive" or not esc],
                   key=lambda a: (a["action"], a["target"]))
    if not esc:
        actions = uniq([a for t in ts for a in t["recommended_actions"]], key=lambda a: (a["action"], a["target"]))
    first, last = ts[0]["_created_at"], ts[-1]["_created_at"]
    span = parse_ts(last) - parse_ts(first)
    if kind == "incident":
        title = top["title"]
    else:
        title = top["title"]
    summary = top["summary"]
    if kind == "incident" and n > 1:
        summary = (f'Incidente que agrupa {n} alertas entre {fmt_local(parse_ts(first))} y {fmt_local(parse_ts(last))} '
                   f'({span.days} d {span.seconds//3600} h). ') + " ".join(uniq([t["title"] + "." for t in ts]))[:1500]
    elif n > 1:
        summary = f"{n} alertas del mismo patrón ({fmt_local(parse_ts(first))} → {fmt_local(parse_ts(last))}). " + top["summary"]
    to = "N2 de guardia (teléfono) + Responsable SOC + CISO" if sev == "critical" else "N2 (misma jornada) + Responsable SOC" if sev == "high" else "N2"
    inc = {
        "ticket_id": "INC-" + top["ticket_id"][4:],
        "alert_ids": [a for t in ts for a in t["alert_ids"]],
        "title": title, "verdict": verdict, "confidence": round(max(t["confidence"] for t in ts if t["verdict"] == verdict), 2),
        "severity": sev,
        "severity_rationale": top["severity_rationale"] + (f" · Incidente: severidad máxima de sus {n} alertas" if n > 1 else "")
                              + (" +1 por cadena de ataque" if sev != top["severity"] else ""),
        "affected": affected, "summary": summary,
        "evidence": uniq([e for t in ts for e in t["evidence"]], key=lambda e: e["event_id"] + e["finding"][:30])[:40],
        "enrichment": uniq([e for t in ts for e in t["enrichment"]], key=lambda e: e["indicator"])[:30],
        "mitre": uniq([m for t in ts for m in t["mitre"]]),
        "recommended_actions": actions[:40],
        "executed_actions": [],
        "escalation": {"escalate": esc, "to": to if esc else "", "reason": "; ".join(uniq(reasons))[:600] if esc else ""},
        "open_questions": uniq([q for t in ts for q in t["open_questions"]])[:10],
        "triage_seconds": round(sum(t["triage_seconds"] for t in ts), 2),
        "_kind": kind, "_children": [t["ticket_id"] for t in ts], "_first_seen": first, "_last_seen": last,
        "_rule_id": top["_rule_id"], "_runbook": top["_runbook"], "_reasons": top["_reasons"],
        "_timeline": [_tl(t) for t in ts][:400], "_injection": [x for t in ts for x in t["_injection"]][:3],
        "_authorized": top.get("_authorized"), "_product": top.get("_product"), "_rule_severity": top.get("_rule_severity"),
        "_sev_calc": dict(top.get("_sev_calc") or {}, final=sev, n=n, chain=(sev != top["severity"]), chain_rules=distinct_tactics),
    }
    return inc


def _tl(t):
    return {"ts": t["_created_at"], "local": fmt_local(parse_ts(t["_created_at"])), "alert_id": t["alert_ids"][0], "rule_id": t["_rule_id"],
            "title": t["title"], "verdict": t["verdict"], "severity": t["severity"], "ticket_id": t["ticket_id"]}
