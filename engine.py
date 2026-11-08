"""Motor de triaje N1 de Tarvia.

Para cada alerta: entender → contextualizar → enriquecer → correlacionar → veredicto → severidad (matriz de la política)
→ recomendación. Las comprobaciones siguen los runbooks RB-01…RB-10. Todo lo que consulta queda en `trace`.

La lógica es determinista y explicable a propósito: cada veredicto lleva sus motivos y sus evidencias. El LLM (opcional,
llm.py) solo redacta y da una segunda opinión; nunca decide acciones ni se salta la aprobación humana.
"""
import datetime as dt, re, time

from context import (Tools, parse_ts, iso, fmt_local, to_local, norm_user, INJECTION_RX, SEV_ORDER, CRIT_ORDER)

H = dt.timedelta(hours=1)

ENGINE_VERSION = "2026-11-08f"  # si cambia, el panel recalcula los casos guardados al arrancar

MATRIX = {  # política §2: severidad de la regla × criticidad del activo
    "informational": ["informational", "informational", "low", "low"],
    "low": ["informational", "low", "low", "medium"],
    "medium": ["low", "medium", "medium", "high"],
    "high": ["medium", "high", "high", "critical"],
    "critical": ["high", "critical", "critical", "critical"],
}
APPROVAL = {  # política §4
    "purge_email": (False, ""), "block_ioc": (False, ""),
    "revoke_sessions": (True, "N2"), "reset_password": (True, "N2"), "isolate_host": (True, "N2"),
    "disable_user": (True, "N2"), "disable_access_key": (True, "N2"),
}
KNOWN_GOOD_SUFFIX = ("microsoft.com", "googleapis.com", "amazonaws.com", "windows.net", "azureedge.net", "akamaized.net",
                     "cloudfront.net", "office.com", "office365.com", "spamhaus.org", "sophosxl.net", "mcafee.com", "e5.sk",
                     "linkedin.com", "docusign.net", "zalando.example", "retailforum.example")
SAFE_INTERNAL_DOMAINS = ("tarvia.example", "tarvia-printers.example", "bmc-agent.example")
DUAL_USE = ("mega.nz", "wetransfer.com", "anydesk.com", "download.anydesk.com", "teamviewer.com", "dropbox.com", "drive.google.com")


class Result:
    def __init__(self, alert, tools):
        self.a = alert; self.t = tools
        self.verdict = "needs_more_info"; self.conf = 0.5; self.title = ""
        self.why = []; self.evidence = []; self.enrich = []; self.actions = []
        self.up = []; self.down = []; self.authorized = None
        self.crit = []  # [(nivel, motivo)]
        self.affected = {"users": [], "hosts": [], "business_services": [], "customers": []}
        self.questions = []; self.escalate_reasons = []; self.group_key = None; self.links = []
        self.sev_override = None; self.notify = []; self.injection = []

    # helpers ---------------------------------------------------------------------------
    def tp(self, conf, title): self.verdict, self.conf, self.title = "true_positive", conf, title
    def btp(self, conf, title, change=None):
        self.verdict, self.conf, self.title = "benign_true_positive", conf, title
        self.authorized = change
    def fp(self, conf, title): self.verdict, self.conf, self.title = "false_positive", conf, title
    def nmi(self, conf, title): self.verdict, self.conf, self.title = "needs_more_info", conf, title
    def reason(self, s): self.why.append(s)
    def ev(self, source, eid, finding): self.evidence.append({"source": source, "event_id": eid or "", "finding": finding})
    def act(self, action, target, just):
        req, who = APPROVAL.get(action, (False, ""))
        if action == "block_ioc" and any(str(target).lower().endswith(d) for d in DUAL_USE):
            req, who = True, "N2 (servicio de uso dual: no bloquear globalmente sin N2)"
        a = {"action": action, "target": target, "requires_approval": req, "justification": just}
        if who:
            a["approver"] = who
        if a not in self.actions:
            self.actions.append(a)
    def aff(self, kind, v):
        if v and v not in self.affected[kind]:
            self.affected[kind].append(v)
    def critical_of(self, level, why):
        self.crit.append((level, why))
    def service_crit(self, name):
        """Criticidad de un servicio de negocio tal como está en servicios_negocio.csv (nunca escrita a mano)."""
        s = next((x for x in self.t.inv.services if name.lower() in x["servicio"].lower()), None)
        if s:
            self.critical_of(s["criticidad"], f'{s["servicio"]} ({s["criticidad"]} en el inventario)')
            self.aff("business_services", s["servicio"])
        return s
    def host_crit(self, hostname):
        """Criticidad de un equipo tal como está en activos.csv."""
        a = self.t.inv.asset_by_host.get(str(hostname).lower())
        if a:
            self.critical_of(a["criticality"], f'{a["hostname"]} ({a["criticality"]} en el inventario)')
        return a
    def esc(self, why): self.escalate_reasons.append(why)


# ============================================================================================ enriquecimiento común
def common(r):
    a, T = r.a, r.t
    ent = a.get("entities") or {}
    for h in ent.get("hosts") or []:
        asset = T.asset(h.get("hostname") or h.get("ip"))
        r.aff("hosts", h.get("hostname"))
        if asset:
            r.critical_of(asset["criticality"], f'{asset["hostname"]} ({asset["criticality"]})')
            if asset["business_service"] and asset["business_service"] != "Puesto de trabajo":
                r.aff("business_services", asset["business_service"])
            for v in asset.get("vulnerabilities") or []:
                r.reason(f'{asset["hostname"]} tiene abierta {v["id"]} (CVSS {v["severidad_cvss"]}): {v["notas"][:120]}')
    for u in ent.get("users") or []:
        upn = u.get("upn") or ""
        if "(" in upn:
            continue
        usr = T.user(upn)
        r.aff("users", upn)
        if usr:
            lvl = "Media"
            if usr["vip"] == "True" or usr["privileged"] == "True" or usr["account_type"] in ("admin", "service"):
                lvl = "Alta"
                r.up.append(f'identidad {"VIP" if usr["vip"] == "True" else "privilegiada/servicio"} ({usr["username"]})')
            r.critical_of(lvl, f'identidad {usr["username"]} ({lvl})')
    for c in ent.get("customers") or []:
        r.aff("customers", c.get("customer_id"))
    for ip in ent.get("ips") or []:
        if "-" in ip or ip.startswith("10."):
            continue
        i = T.intel(ip)
        r.enrich.append({"indicator": ip, "type": "ip", "source": "TIP + GeoIP", "result": T.trace[-1]["found"]})
    for d in ent.get("domains") or []:
        T.intel(d)
        r.enrich.append({"indicator": d, "type": "domain", "source": "TIP", "result": T.trace[-1]["found"]})
    for f in ent.get("files") or []:
        if f.get("sha256"):
            T.intel(f["sha256"]); ti = T.trace[-1]["found"]
            sb = T.sandbox(f["sha256"])
            r.enrich.append({"indicator": f.get("name") or f["sha256"][:12], "type": "sha256", "source": "TIP + sandbox",
                             "result": ti + " · " + T.trace[-1]["found"]})
    # Los datos los escribe a veces el atacante: buscamos instrucciones dirigidas a sistemas automáticos.
    blob = str(a.get("evidence")) + str(ent)
    for m in INJECTION_RX.finditer(blob):
        r.injection.append(m.group(0))
    if r.injection:
        r.reason("⚠ El contenido de la alerta incluye instrucciones dirigidas al sistema de triaje "
                 f'(«{r.injection[0]}»). Se tratan como dato hostil, no como orden: es un indicio más de malicia.')


def window(a, before=24, after=24):
    t = parse_ts(a["created_at"])
    return t, t - before * H, t + after * H


def host_activity(r, host, t0, t1, why="actividad sospechosa en el equipo"):
    """EDR del equipo: eventos raros (sin firma, servicios, persistencia, LSASS, intérpretes con red…)."""
    T = r.t
    evs = T.search("host", host, t0, t1, sources=["edr_events"], limit=3000, why=why)
    sus = []
    for e in evs:
        cl = (e.get("command_line") or "").lower(); path = (e.get("process_path") or "").lower()
        bad = (e.get("event_type") in ("service_install", "process_access", "registry_set", "agent_status", "file_create", "network_connect")
               or e.get("signer") == "(sin firma)" and e.get("event_type") != "detection"
               or any(k in cl for k in ("curl ", "| bash", "vssadmin", "comsvcs", "minidump", "psexec", "adfind", "nltest", "-enc", "sc.exe stop",
                                        "sqlcmd", "rundll32", "msiexec /q", "7z", "rar a"))
               or any(k in path for k in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp")))
        if bad and "ccmexec" not in (e.get("parent_name") or "").lower():
            sus.append(e)
    return sus


def describe_edr(e):
    d = e.get("details") or {}
    s = f'{e.get("event_type")}: {e.get("parent_name") or ""} → {e.get("process_name")} {(e.get("command_line") or "")[:110]}'
    if d:
        s += " " + ", ".join(f"{k}={str(v)[:60]}" for k, v in list(d.items())[:3])
    return s.strip()


def signins_after(r, user, t0, t1, why):
    evs = r.t.search("user", norm_user(user), t0, t1, sources=["idp_signins", "idp_audit", "vpn"], limit=500, why=why)
    return evs


def is_persistence(e):
    op = str(e.get("operation", "")).lower(); d = e.get("details") or {}
    if "consent" in op:
        return d.get("publisher") != "verificado"
    return any(k in op for k in ("mfa", "security info", "inboxrule", "inbox rule", "forwarding", "add member", "add owner"))


def is_risky_ip(T, ip):
    if not ip or ip.startswith("10."):
        return False
    g = T.inv.geo.get(ip) or {}
    ti = T.inv.ti.get(ip) or {}
    return (any(g.get(k) == "True" for k in ("is_tor", "is_vpn_provider", "is_hosting", "is_residential_proxy"))
            and "Microsoft" not in g.get("as_org", "")) or ti.get("reputation") in ("malicious", "suspicious")


# ============================================================================================ analizadores por caso de uso
AN = {}


def uc(*ids):
    def deco(f):
        for i in ids:
            AN[i] = f
        return f
    return deco


# ---------------------------------------------------------------------------------- RB-01 correo
def _email_lookup(r, msgid):
    t = parse_ts(r.a["created_at"])
    rows = r.t.search("key", msgid.lower(), t - 24 * 30 * H, t + H, sources=["email"], limit=5, why="localizar el mensaje") if msgid else []
    return rows[0] if rows else None


def _supplier_lookalike(T, dom):
    """¿El dominio se parece a un proveedor legítimo con historial limpio? (p. ej. packaging-iberia-pagos vs packaging-iberia)."""
    base = dom.split(".")[0]
    for sep in ("-pagos", "-portal", "-facturas", "-billing", "-docs", "pedidos-", "-sso-login", "-login"):
        if sep in base:
            legit = base.replace(sep, "")
            if legit and T.count("domain", legit + ".example", source="email") > 0:
                return legit + ".example"
    return None


@uc("UC-EML-001")
def an_reported(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a)
    sender = ev.get("sender", ""); dom = sender.split("@")[-1].lower(); subj = ev.get("subject", "")
    r.critical_of("Media", "buzón de usuario"); r.group_key = f"phish-report:{dom}:{subj[:40]}"
    m = _email_lookup(r, ev.get("message_id"))
    if m:
        auth = f'SPF {m.get("spf")}, DKIM {m.get("dkim")}, DMARC {m.get("dmarc")}'
        r.ev("email", m["event_id"], f'De {m["sender"]} «{m["subject"]}» — {auth}; veredicto pasarela {m.get("verdict")}, {m.get("action")}')
    ti = T.intel(dom)["tip"] if dom else None
    look = _supplier_lookalike(T, dom)
    if dom == "tarvia.example" and "simulacro" in subj.lower():
        r.btp(0.95, "Usuario reporta el simulacro de phishing interno de RRHH (comportamiento correcto)")
        r.reason("Remitente interno rrhh@tarvia.example y asunto de simulacro: campaña de concienciación autorizada.")
        r.act("close", "ticket", "Simulacro de concienciación; el usuario lo detectó correctamente")
        return
    malicious = (ti and ti["reputation"] in ("malicious", "suspicious")) or look or r.injection or \
        (m and m.get("spf") == "fail" and m.get("dmarc") == "fail")
    if not malicious and m and m.get("spf") == "pass" and m.get("dmarc") == "pass" and m.get("verdict") in ("clean", "bulk"):
        r.fp(0.9, f"Correo legítimo ({dom}) reportado como phishing: newsletter/notificación con autenticación válida")
        r.reason("SPF/DKIM/DMARC correctos, veredicto limpio de la pasarela y sin coincidencias en el TIP.")
        r.act("close", "ticket", "Correo legítimo; opcionalmente recordar al usuario cómo darse de baja")
        return
    # Alcance de la campaña: cuántos lo recibieron y si alguien hizo clic.
    recips = T.grep("email", f'"subject": "{subj}"', t - 72 * H, t + 24 * H, limit=2000, why="alcance de la campaña") if subj else []
    clicks = T.search("domain", dom, t - 72 * H, t + 48 * H, sources=["email_clicks", "proxy"], why="¿alguien hizo clic?")
    url_doms = {u.split("/")[2] for x in recips for u in (x.get("urls") or []) if "://" in u}
    for ud in list(url_doms)[:3]:
        if ud != dom:
            clicks += T.search("domain", ud, t - 72 * H, t + 48 * H, sources=["email_clicks"], why=f"clics al dominio del enlace {ud}")
    clickers = sorted({c.get("user") for c in clicks if c.get("user")})
    r.tp(0.85, f"Phishing{' con suplantación de proveedor' if look else ''} reportado por usuarios: «{subj[:70]}»")
    if ti:
        r.reason(f'El dominio {dom} está en el TIP como {ti["reputation"]} ({ti["tags"]}).')
    if look:
        r.reason(f"{dom} imita al proveedor legítimo {look} (dominio parecido, con historial de correo limpio).")
    if m and m.get("dmarc") == "fail":
        r.reason("Falla la autenticación del remitente (DMARC fail).")
    r.reason(f"Campaña: {len(recips)} buzones recibieron el mismo asunto; {len(clickers)} usuarios con clic.")
    r.act("purge_email", f"asunto «{subj[:60]}» de {sender}", "Retirar el correo de todos los buzones")
    r.act("block_ioc", dom, "Bloquear el dominio remitente/enlace en correo y proxy")
    for u in list(url_doms)[:2]:
        if u != dom:
            r.act("block_ioc", u, "Dominio del enlace de la campaña")
    if clickers:
        r.up.append("hubo clics en el enlace")
        r.esc(f"Hubo clic de {len(clickers)} usuarios: revisar envío de credenciales (ver alertas UC-EML-003 asociadas)")
        r.questions.append("Confirmar con los usuarios que hicieron clic si introdujeron credenciales.")
        r.reason("Usuarios con clic: " + ", ".join(norm_user(c) for c in clickers[:8]) + ("…" if len(clickers) > 8 else ""))
    r.group_key = f"campaign:{dom}:{subj[:40]}"
    r.links.append(("domain", dom))
    for u in url_doms:
        r.links.append(("domain", u))


@uc("UC-EML-002")
def an_attachment(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 2, 48)
    r.critical_of("Media", "buzón de usuario")
    bad = []
    for f in a["entities"].get("files") or []:
        sb = T.inv.sandbox.get((f.get("sha256") or "").lower())
        if sb and sb["verdict"] == "malicious":
            bad.append((f, sb))
    if ev.get("legit_supplier_domain"):
        r.reason(f'El remitente {ev.get("sender")} suplanta al proveedor {ev["legit_supplier_domain"]} (SPF {ev.get("spf")}, DMARC {ev.get("dmarc")}).')
    users = [u["upn"] for u in a["entities"].get("users") or []]
    executed = []
    for u in users:
        usr = T.inv.user_by_name.get(norm_user(u))
        ws = usr and usr.get("workstation")
        if ws:
            for f, sb in bad:
                hits = T.grep("edr_events", f["name"].rsplit(".", 1)[0], t0, t1, why=f"¿se abrió el adjunto en {ws}?")
                hits = [h for h in hits if h.get("hostname") == ws]
                for h in hits[:3]:
                    executed.append(h); r.ev("edr_events", h["event_id"], describe_edr(h))
            r.links.append(("host", ws.lower()))
    if bad:
        r.tp(0.95, f'Adjunto malicioso ({bad[0][1]["malware_family"]}) entregado a {", ".join(norm_user(u) for u in users)}')
        r.reason(f'Sandbox: {bad[0][1]["file_name"]} → {bad[0][1]["verdict"]} ({bad[0][1]["score"]}), {bad[0][1]["malware_family"]}.')
        r.act("purge_email", ev.get("message_id", ""), "Retirar el correo de todos los buzones")
        r.act("block_ioc", ev.get("sender", "").split("@")[-1], "Dominio remitente malicioso")
        for f, sb in bad:
            r.act("block_ioc", f["sha256"], f'Hash de {f["name"]}')
            for d in (sb.get("network") or {}).get("domains") or []:
                r.act("block_ioc", d, f"C2/descarga según sandbox")
    else:
        r.nmi(0.5, "Adjunto sospechoso entregado sin veredicto concluyente de sandbox")
        r.questions.append("Enviar el adjunto a sandbox; un adjunto limpio también puede ser fraude por su contenido.")
    if executed:
        r.up.append("el adjunto se ejecutó en el puesto")
        r.esc("Ejecución confirmada del adjunto en el puesto: ver alertas EDR del mismo equipo")


@uc("UC-EML-003")
def an_click(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 6, 24)
    users = [u["upn"] for u in a["entities"].get("users") or []]
    hosts = [h["hostname"] for h in a["entities"].get("hosts") or []]
    doms = a["entities"].get("domains") or []
    r.tp(0.85, f'Clic en enlace de phishing por {", ".join(norm_user(u) for u in users)}')
    r.reason(f'La reescritura de enlaces reclasificó la URL como {ev.get("rewrite_verdict_now")}.')
    # ¿Envío de credenciales? POST al dominio desde el puesto.
    posted = []
    for d in doms:
        px = T.search("domain", d, t - 2 * H, t1, sources=["proxy"], why="¿POST de credenciales al dominio?")
        posted += [p for p in px if p.get("method") == "POST"]
        for p in px[:4]:
            r.ev("proxy", p["event_id"], f'{p.get("method")} {p.get("url", "")[:80]} → {p.get("status")} ({p.get("bytes_out")} B salientes)')
        r.act("block_ioc", d, "Dominio de phishing"); r.links.append(("domain", d))
    # Inicios de sesión después desde IPs de riesgo.
    risky = []
    for u in users:
        for s in signins_after(r, u, t - 6 * H, t1, "¿inicio de sesión del atacante tras el clic?"):
            if s.get("_src") == "idp_signins" and s.get("result") == "success" and is_risky_ip(T, s.get("src_ip")):
                risky.append(s)
            if s.get("_src") == "idp_audit" and is_persistence(s):
                r.ev("idp_audit", s["event_id"], f'{s["operation"]} desde {s.get("src_ip")}: {str(s.get("details"))[:100]}')
                r.up.append("persistencia en la cuenta")
    for ip in a["entities"].get("ips") or []:
        risky += [s for s in T.search("ip", ip, t - 6 * H, t1, sources=["idp_signins"], why="sesiones desde la IP del kit de phishing") if s.get("result") == "success"]
    if posted:
        r.reason(f"Hubo {len(posted)} POST al dominio de phishing desde el puesto: probable envío de credenciales.")
    if risky:
        s = risky[0]
        r.tp(0.95, f'Robo de credenciales/sesión (AiTM) tras clic en phishing: {", ".join(norm_user(u) for u in users)}')
        r.reason(f'Inicio de sesión correcto desde {s.get("src_ip")} ({s.get("country")}, {s.get("asn")}) con '
                 f'{s.get("user_agent", "")[:40]} tras el clic: la cuenta está comprometida.')
        r.ev("idp_signins", s["event_id"], f'Login {s.get("result")} desde {s.get("src_ip")} MFA {s.get("mfa_result")}')
        r.up.append("acceso confirmado del atacante a la cuenta")
        for u in users:
            r.act("revoke_sessions", u, "Sesión robada"); r.act("reset_password", u, "Credenciales enviadas al kit")
        r.esc("Credenciales robadas y sesión del atacante activa")
        r.links += [("ip", s.get("src_ip"))]
    else:
        r.questions.append("Confirmar con el usuario si introdujo credenciales (el gateway no lo sabe).")
        r.act("watch", users[0] if users else "", "Vigilar la cuenta 24 h (RB-01)")
    if r.injection:
        r.esc("El correo contiene texto oculto que intenta manipular al sistema de triaje")
    r.act("purge_email", ev.get("message_id", ""), "Retirar el correo de todos los buzones")
    for h in hosts:
        r.links.append(("host", h.lower()))


@uc("UC-EML-004")
def an_bec(r):
    a, T = r.a, r.t; ev = a["evidence"]
    r.service_crit("ERP")  # pagos a proveedores
    r.tp(0.9, f'Fraude BEC: petición de cambio de IBAN ({ev.get("amount_mentioned", "")}) a cuenta en {ev.get("new_iban_country", "?")}')
    ip = ev.get("submitted_from_ip")
    if ip:
        T.intel(ip)
        r.reason(f"El correo se envió desde {ip}: {T.trace[-1]['found']}.")
        prev = T.search("ip", ip, parse_ts(a["created_at"]) - 72 * H, parse_ts(a["created_at"]), sources=["idp_signins"], why="¿la IP ya se usó para entrar en buzones?")
        if prev:
            r.reason(f"La misma IP inició sesión antes en el buzón de {', '.join(sorted({norm_user(p.get('user_upn')) for p in prev}))}: "
                     "el correo sale de una cuenta interna comprometida, no de un externo.")
            r.links += [("ip", ip)]
    r.up.append("pagos implicados")
    r.reason("Matriz §2: regla medium × activo Alta (ERP, pagos a proveedores) = medium; +1 por pagos implicados = high. "
             "El escalado es obligatorio igualmente (§5: fraude económico) y RB-01 pide avisar a Tesorería para retener el pago.")
    r.act("notify", "Tesorería", "Retener cualquier pago al nuevo IBAN y verificar con el proveedor por teléfono")
    r.act("purge_email", ev.get("message_id", ""), "Retirar el correo")
    r.esc("Fraude económico (cambio de IBAN): escalado obligatorio §5")
    # RB-01 lo marca como critical, pero la política (§2) solo permite ±1 sobre la matriz: Media × Alta = Media, +1 por pagos = high.


# ---------------------------------------------------------------------------------- RB-03 identidad
@uc("UC-IDP-001")
def an_travel(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 6, 24)
    user = (a["entities"].get("users") or [{}])[0].get("upn", "")
    cur = ev.get("current_login") or {}
    ip = cur.get("ip") or (a["entities"].get("ips") or [""])[-1]
    g = T.inv.geo.get(ip) or {}
    rel = T.related(a)
    usr = T.inv.user_by_name.get(norm_user(user)) or {}
    trips = [h for h in T.inv.hr if norm_user(h["usuario"]) == norm_user(user) and h["tipo"] in ("viaje", "teletrabajo_temporal")]
    r.group_key = f"travel:{g.get('as_org', '')[:30]}"
    post = [e for e in signins_after(r, user, t - 1 * H, t + 12 * H, "¿qué hizo la sesión después?") if e.get("_src") == "idp_audit"]
    persist = [e for e in post if is_persistence(e) and e.get("src_ip") != "198.18.200.10"]
    for e in post[:5]:
        r.ev("idp_audit", e["event_id"], f'{e.get("operation")} → {e.get("target")} desde {e.get("src_ip")}')
    relay = "Private Relay" in g.get("as_org", "")
    if not persist and not ev.get("post_login_actions") and (relay or ("conforme" in str(ev.get("device", "")) and not is_risky_ip(T, ip)
                                                                         and not trips)):
        r.fp(0.9, f'Falso «viaje imposible»: salida de Private Relay/VPN del móvil corporativo de {norm_user(user)}')
        r.reason(f'La IP {ip} es de {g.get("as_org", "?")}: la geolocalización es la del relay, no la del usuario.')
        r.reason(f'Dispositivo {ev.get("device", "conocido")}; sin acciones sospechosas posteriores.')
        r.act("close", "ticket", "Proponer excluir los rangos de Private Relay de la regla de viaje imposible")
        return
    if trips and not persist:
        tr = trips[0]
        r.btp(0.9, f'Viaje notificado: {norm_user(user)} en {tr["detalle"][:40]}', change=f'RRHH {tr["tipo"]} {tr["fecha_efectiva"]}')
        r.reason(f'RRHH tiene registrado: {tr["detalle"]}. Dispositivo {ev.get("device", "")}.')
        r.act("close", "ticket", "Viaje notificado y dispositivo conocido")
        return
    risky = is_risky_ip(T, ip)
    if persist or risky:
        r.tp(0.85 if persist else 0.6, f'Acceso a la cuenta de {norm_user(user)} desde {g.get("as_org") or ip}'
             + (" con persistencia (nuevo MFA/regla)" if persist else ""))
        r.reason(f'Origen {ip}: {g.get("as_org", "")} {"(VPN comercial/hosting)" if risky else ""}.')
        if ev.get("post_login_actions"):
            r.reason(f'Acciones tras el login: {", ".join(ev["post_login_actions"])}.')
        if persist:
            r.up.append("persistencia registrada tras el acceso")
            r.act("revoke_sessions", user, "Sesión sospechosa"); r.act("reset_password", user, "Posible robo de credenciales")
            r.act("remove_persistence", user, "Eliminar el método MFA/regla registrados por la sesión sospechosa")
            r.esc("Persistencia en la cuenta (nuevo MFA) desde origen anómalo")
        r.links.append(("ip", ip))
    else:
        r.nmi(0.5, f"Viaje imposible de {norm_user(user)} sin explicación clara")
        r.questions.append("Contactar con el usuario para confirmar la ubicación.")


@uc("UC-IDP-002")
def an_spray(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 2, 24)
    ips = a["entities"].get("ips") or []
    if ev.get("app") == "VPN":
        r.host_crit("VPN-GW01") or r.service_crit("Acceso remoto")  # si no, cuentan las identidades atacadas
    tor = [ip for ip in ips if (T.inv.geo.get(ip) or {}).get("is_tor") == "True" or "tor" in (T.inv.ti.get(ip) or {}).get("tags", "")]
    for ip in ips[:6]:
        T.intel(ip)
    succ = []; baseline = set()
    risky_src = [ip for ip in ips if is_risky_ip(T, ip)]
    for ip in (ips if (risky_src or (ev.get("successes") or 0) > 0) else []):
        for e in T.search("ip", ip, t - 1 * H, t1, sources=["vpn", "idp_signins"], why="¿algún acceso correcto desde el origen del spraying?"):
            ok = (e.get("_src") == "vpn" and e.get("action") == "connect") or (e.get("_src") == "idp_signins" and e.get("result") == "success")
            if ok:
                u = norm_user(e.get("user") or e.get("user_upn"))
                hist = T.count("user", u, start=t - 14 * 24 * H, end=t - 2 * H) and \
                    T.db.execute("SELECT COUNT(*) FROM ent a JOIN ent b ON a.event_id=b.event_id WHERE a.etype='user' AND a.value=? "
                                 "AND b.etype='ip' AND b.value=? AND a.ts < ?", (u, ip, iso(t - 2 * H))).fetchone()[0]
                if hist >= 3:
                    baseline.add((u, ip, hist)); continue
                succ.append(e)
    r.reason(f'{ev.get("failed_attempts", "?")} fallos contra {ev.get("distinct_accounts", "?")} cuentas en {ev.get("window_min", "?")} min'
             + (f'; {len(tor)} orígenes son nodos Tor' if tor else "") + ".")
    for u, ip, n in sorted(baseline)[:3]:
        r.reason(f"El acceso correcto de {u} desde {ip} no cuenta como éxito del ataque: es su origen habitual ({n} eventos previos).")
    for ip in ips:
        r.act("block_ioc", ip, "Origen del password spraying")
    if succ or (ev.get("successes") or 0) > 0:
        accts = sorted({norm_user(e.get("user") or e.get("user_upn")) for e in succ})
        r.tp(0.95, f'Password spraying con éxito: acceso de {", ".join(accts) or "una cuenta"} vía {ev.get("app", "IdP")}')
        for e in succ[:3]:
            r.ev(e["_src"], e["event_id"], f'Acceso correcto de {e.get("user") or e.get("user_upn")} desde {e.get("src_ip")} (MFA {e.get("mfa_result", "n/a")})')
        r.up.append("acceso confirmado")
        for u in accts:
            usr = T.user(u)
            if usr and usr["account_type"] == "service":
                r.reason(f'{u} es cuenta de servicio sin MFA (riesgo aceptado): el atacante entra con solo la contraseña.')
                r.act("disable_user", u, "Cuenta de servicio comprometida — avisar: puede parar las copias de seguridad")
            else:
                r.act("reset_password", u, "Contraseña adivinada"); r.act("revoke_sessions", u, "Sesión del atacante")
            r.links.append(("user", u))
        r.esc("Robo de credenciales confirmado (acceso correcto desde el origen del ataque)")
    else:
        r.tp(0.85, f'Password spraying sin éxito contra {ev.get("app", "IdP")}' + (f' ({ev["protocol"]})' if ev.get("protocol") else ""))
        r.down.append("ningún acceso correcto (bloqueado por política/smart lockout)")
        if "legacy" in str(ev.get("protocol", "")).lower() and len(ips) <= 2 and (ev.get("failed_attempts") or 0) < 50:
            g = T.inv.geo.get(ips[0]) if ips else None
            r.reason(f'Origen {", ".join(ips)} ({(g or {}).get("as_org", "sin GeoIP")}) ; autenticación heredada '
                     'bloqueada por política: patrón de cliente de correo antiguo o bot de bajo volumen, sin éxito.')
            r.reason("Legacy auth bloqueada por política, volumen bajo (un origen, <50 intentos) y ningún acceso.")
            r.group_key = f"spray-legacy:{to_local(t):%Y-%m-%d}"
            return
    r.group_key = "spray:" + ",".join(sorted(ips))[:60]


@uc("UC-IDP-003")
def an_mfa_fatigue(r):
    a, ev = r.a, r.a["evidence"]
    user = a["entities"]["users"][0]["upn"]
    t, t0, t1 = window(a, 1, 24)
    r.tp(0.9 if ev.get("final_result") == "approved" else 0.8, f'Fatiga MFA: {ev.get("push_requests")} push en {ev.get("window_min")} min a {norm_user(user)}'
         + (" y el usuario acabó aprobando" if ev.get("final_result") == "approved" else ""))
    r.reason(f'Hora local {ev.get("local_time", "")}; el usuario está en {ev.get("user_location", "?")} y el origen es {ev.get("src_city", "?")}.')
    post = [e for e in signins_after(r, user, t, t1, "¿qué hizo el atacante con la sesión?") if e.get("_src") == "idp_audit"]
    for e in post[:5]:
        r.ev("idp_audit", e["event_id"], f'{e.get("operation")} → {e.get("target")} ({str(e.get("details"))[:80]})')
    if ev.get("final_result") == "approved":
        r.up.append("MFA aprobado: acceso confirmado")
        r.act("revoke_sessions", user, "Sesión obtenida por fatiga MFA"); r.act("reset_password", user, "Contraseña en manos del atacante")
        r.act("remove_persistence", user, "Revisar y borrar métodos MFA registrados en la sesión")
        r.esc("Cuenta comprometida por fatiga MFA")
    for ip in a["entities"].get("ips") or []:
        r.act("block_ioc", ip, "Origen del ataque"); r.links.append(("ip", ip))


@uc("UC-IDP-004")
def an_anon_login(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 6, 24)
    user = a["entities"]["users"][0]["upn"]; ip = ev.get("src_ip") or a["entities"]["ips"][0]
    usr = T.inv.user_by_name.get(norm_user(user)) or {}
    r.tp(0.9, f'Inicio de sesión correcto de {norm_user(user)} desde infraestructura {"Tor" if ev.get("is_tor") else "de hosting"} ({ip})')
    r.up.append("acceso correcto (no solo intento)")
    if usr.get("account_type") == "service":
        r.reason(f'{norm_user(user)} es cuenta de servicio excluida de MFA: con la contraseña basta. Nadie debería usarla desde Tor.')
        r.act("disable_user", user, "Cuenta de servicio comprometida — impacto: copias de seguridad; coordinar con Tecnología")
    else:
        r.act("revoke_sessions", user, "Sesión desde infraestructura anónima"); r.act("reset_password", user, "Credenciales comprometidas")
    after = T.search("ip", ip, t, t1, why="¿qué hizo la sesión?")
    if after:
        r.reason(f"Hay {len(after)} eventos más desde {ip} en las 24 h siguientes.")
    if usr.get("account_type") == "service":
        vpn = [e for e in T.search("user", norm_user(user), t, t1, sources=["vpn"], why="IP asignada en la VPN") if e.get("assigned_ip")]
        for v in vpn[:1]:
            fw = T.search("ip", v["assigned_ip"], t, t1, sources=["firewall"], why="¿a qué servidores llegó por la VPN?")
            dst = sorted({f.get("dst_ip") for f in fw})
            if dst:
                r.reason(f'Desde la VPN ({v["assigned_ip"]}) contactó con {", ".join(dst[:6])}.')
    r.act("block_ioc", ip, "Origen del acceso"); r.esc("Cuenta comprometida desde infraestructura anónima")
    r.links += [("ip", ip)]


@uc("UC-IDP-005")
def an_inbox_rule(r):
    a, ev = r.a, r.a["evidence"]; user = a["entities"]["users"][0]["upn"]
    r.tp(0.95, f'Regla de buzón oculta en {norm_user(user)} que esconde correos de pagos/IBAN (preparación de fraude BEC)')
    r.reason(f'Regla «{ev.get("rule_name")}» con palabras {ev.get("keywords")}: {ev.get("action")}; creada desde {ev.get("created_from_ip")}.')
    r.up.append("persistencia en la cuenta"); r.up.append("pagos implicados")
    r.act("remove_persistence", user, "Eliminar la regla de buzón"); r.act("revoke_sessions", user, "Sesión del atacante")
    r.act("reset_password", user, "Credenciales comprometidas"); r.act("notify", "Tesorería", "Posible fraude de pago en curso")
    r.esc("Persistencia y riesgo de fraude económico")
    r.links.append(("ip", ev.get("created_from_ip")))


@uc("UC-IDP-006")
def an_token(r):
    a, T = r.a, r.t; ev = a["evidence"]; user = a["entities"]["users"][0]["upn"]; t, t0, t1 = window(a, 24, 24)
    r.tp(0.95, f'Robo de cookie de sesión (AiTM): la sesión de {norm_user(user)} se reutiliza desde {", ".join(a["entities"].get("ips") or [])}')
    r.reason(f'Misma sesión {ev.get("session_id")} con un user agent de script ({ev.get("new_user_agent") or ev.get("user_agent")}) y dispositivo no conforme.')
    ses = T.search("key", ev.get("session_id"), t0, t1, sources=["idp_signins"], why="historia de la sesión")
    for s in ses[:4]:
        r.ev("idp_signins", s["event_id"], f'{s.get("src_ip")} {s.get("user_agent", "")[:40]} MFA {s.get("mfa_result")}')
    clicks = T.search("user", norm_user(user), t - 24 * H, t + 2 * H, sources=["email_clicks"], why="¿clic previo en phishing?")
    for c in clicks:
        if c.get("verdict_at_click") != "clean" or "tarvia" not in (c.get("url") or ""):
            r.ev("email_clicks", c["event_id"], f'Clic en {c.get("url", "")[:70]} ({c.get("verdict_at_click")})')
    r.up.append("acceso confirmado con sesión robada")
    r.act("revoke_sessions", user, "Sesión robada"); r.act("reset_password", user, "Credenciales robadas por el kit AiTM")
    r.esc("Robo de sesión confirmado")
    for ip in a["entities"].get("ips") or []:
        r.act("block_ioc", ip, "Infraestructura AiTM"); r.links.append(("ip", ip))


@uc("UC-IDP-007")
def an_oauth(r):
    a, ev = r.a, r.a["evidence"]; user = a["entities"]["users"][0]["upn"]
    r.tp(0.8, f'Consentimiento OAuth a aplicación no verificada por {norm_user(user)}')
    r.up.append("persistencia (token OAuth)")
    r.act("revoke_app_consent", user, "Revocar el consentimiento"); r.esc("Persistencia vía OAuth")


@uc("UC-IDP-008")
def an_priv_group(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a)
    r.service_crit("Identidad y directorio")
    by = ev.get("by", ""); host = ev.get("from_host", "")
    ch = T.change_by_id(ev["change_ticket"]) if ev.get("change_ticket") and ev["change_ticket"] != "ninguno" else None
    in_window = ch and ch["_start"] - H <= t <= ch["_end"] + H
    if ch and in_window and host.upper() == "JUMP01":
        r.btp(0.9, f'Alta en {ev.get("group")} autorizada ({ch["id"]}) desde JUMP01', change=ch["id"])
        r.reason(f'{ch["id"]} «{ch["titulo"]}» cubre la hora ({fmt_local(t)}) y se hizo desde JUMP01 con {by}.')
        r.act("close", "ticket", "Cambio aprobado")
        return
    r.tp(0.95, f'Alta no autorizada en {ev.get("group")}: {ev.get("member_added", "")} por {by} desde {host}')
    if host.upper() != "JUMP01" and by.startswith("adm."):
        r.reason(f"Las cuentas adm.* solo pueden usarse desde JUMP01 y esta se usó desde {host}.")
    r.reason(f'Hora local {ev.get("local_time") or fmt_local(t)}; ticket de cambio: {ev.get("change_ticket", "ninguno")}.')
    r.up.append("identidad privilegiada")
    member = (ev.get("member_added") or "").split(" ")[0]
    if member:
        r.act("disable_user", member, "Cuenta creada por el atacante como persistencia"); r.links.append(("user", member.lower()))
    r.act("disable_user", by, "Cuenta de administrador comprometida"); r.act("reset_password", by, "Credenciales robadas")
    r.act("isolate_host", host, "Equipo desde el que actúa el atacante (requiere N2 + responsable del servicio)")
    r.links += [("user", norm_user(by)), ("host", host.lower())]
    r.esc("Persistencia con privilegios de dominio")


@uc("UC-VPN-001")
def an_vendor_vpn(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 1, 12)
    user = a["entities"]["users"][0]["upn"]; ip = (a["entities"].get("ips") or [""])[0]
    r.service_crit("Gestión de almacén")
    r.aff("business_services", "Gestión de almacén (WMS)")
    ch = []
    if ev.get("change_ticket"):
        c = T.change_by_id(ev["change_ticket"])
        if c and c["_start"] - H <= t <= c["_end"] + H:
            ch = [c]
    ch = ch or T.changes(t, "logisoft", "ext.logisoft", "WMS")
    if ch and ("Logisoft" in ev.get("src_asn", "") or not ev.get("usual_src")):
        r.btp(0.9, f'Acceso de Logisoft fuera de horario cubierto por {ch[0]["id"]}', change=ch[0]["id"])
        r.reason(f'{ch[0]["id"]} «{ch[0]["titulo"]}» autoriza el acceso fuera de horario desde su IP corporativa ({ev.get("src_asn")}).')
        r.act("close", "ticket", "Mantenimiento aprobado")
        return
    T.intel(ip)
    lt = to_local(t)
    if "Logisoft" in ev.get("src_asn", "") and lt.weekday() < 5 and 18 <= lt.hour < 20:
        r.tp(0.8, f'Logisoft alarga su sesión VPN poco después de su ventana ({ev.get("local_time")}) desde su red corporativa')
        r.down.append("origen habitual del proveedor y desviación de minutos")
        r.reason(f'Origen {ip} ({ev.get("src_asn")}), el habitual; laborable a las {lt:%H:%M}, justo tras la ventana {ev.get("contract_window")}.')
        r.act("notify", "Responsable del contrato con Logisoft (Logística)", "Recordar la ventana contractual o ampliarla formalmente")
        r.group_key = f"vendor-late:{lt:%Y-%m-%d}"
        return
    r.tp(0.75, f'Cuenta del proveedor Logisoft usada fuera de su ventana ({ev.get("local_time")}) desde un ASN nuevo ({ev.get("src_asn")})')
    r.reason(f'Ventana contractual {ev.get("contract_window")}; origen habitual {ev.get("usual_src")}; esta vez {ev.get("src_asn")} ({ip}).')
    r.reason("Sin cambio aprobado que lo cubra. MFA TOTP aprobado: quien entra tiene contraseña y segundo factor (¿semilla TOTP robada?).")
    vpn = [e for e in T.search("ip", ip, t - H, t1, sources=["vpn"], why="sesión VPN") if e.get("assigned_ip")]
    if vpn:
        r.up.append("sesión VPN establecida (acceso, no solo intento)")
    prev = T.other_alerts(a, 24 * 30, keys=[("ip", ip)])
    if prev:
        r.reason(f"El mismo origen {ip} aparece en {len(prev)} alertas más del mes ({', '.join(sorted({p['rule_id'] for p in prev}))}): patrón recurrente.")
        r.esc("Accesos repetidos del proveedor fuera de contrato desde un origen no habitual")
    for v in vpn[:1]:
        fw = T.search("ip", v["assigned_ip"], t - H, t1, sources=["firewall"], why="¿a qué llegó por la VPN?")
        dst = sorted({(f.get("dst_ip"), f.get("dst_port")) for f in fw})
        for f in fw[:3]:
            r.ev("firewall", f["event_id"], f'{f["src_ip"]} → {f["dst_ip"]}:{f["dst_port"]} {f["action"]} ({f.get("zone_dst")})')
        for d, _ in dst:
            asset = T.inv.asset_by_ip.get(d)
            if asset:
                r.links.append(("host", asset["hostname"].lower()))
                sus = host_activity(r, asset["hostname"], t - H, t + 6 * H, "¿qué hizo en el servidor?")
                for e in sus[:4]:
                    r.ev("edr_events", e["event_id"], f'{asset["hostname"]}: {describe_edr(e)}')
                if sus:
                    r.up.append("actividad maliciosa en el servidor tras el acceso")
                    r.tp(0.9, f'Acceso ilegítimo con la cuenta de Logisoft e implante en {asset["hostname"]}')
                    r.esc(f'Actividad sospechosa en {asset["hostname"]} tras el acceso del proveedor')
    r.act("disable_user", user, "Cuenta de tercero usada fuera de contrato — avisar a Logisoft y a Logística")
    r.act("block_ioc", ip, "Origen no habitual del proveedor")
    r.questions.append("Confirmar con Logisoft por teléfono si alguien de su equipo se conectó.")
    r.links.append(("ip", ip))
    r.group_key = f"vendor-vpn:{ip}"


# ---------------------------------------------------------------------------------- RB-02 endpoint
@uc("UC-EDR-001")
def an_office_child(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 2, 24)
    tree = ev.get("process_tree", "")
    host = (a["entities"].get("hosts") or [{}])[0].get("hostname")
    if "saplogon" in tree.lower() and ev.get("signer") == "SAP SE":
        r.fp(0.9, f"Excel abre SAP GUI (integración habitual de negocio) en {host}")
        r.reason("saplogon.exe firmado por SAP SE lanzado desde Excel: macro/añadido de SAP habitual; no hay red ni hijos raros.")
        r.act("close", "ticket", "Proponer excluir EXCEL.EXE > saplogon.exe firmado por SAP SE de la regla")
        r.group_key = "sap-excel"
        return
    r.tp(0.9, f'Cadena de ejecución maliciosa en {host}: {tree}')
    if ev.get("persistence"):
        r.reason(f'Persistencia creada: {ev["persistence"]}.'); r.up.append("ejecución confirmada y persistencia")
    if ev.get("edr_action") == "detected_only":
        r.reason("El EDR solo detectó: no bloqueó nada.")
    for e in T.related(a)[:6]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
        if e.get("sha256"):
            sb = T.sandbox(e["sha256"])
            if sb and sb["verdict"] == "malicious":
                r.reason(f'Sandbox: {sb["file_name"]} es {sb["malware_family"]} ({sb["score"]}).')
                for d in (sb.get("network") or {}).get("domains") or []:
                    r.act("block_ioc", d, f'C2 de {sb["malware_family"]}'); r.links.append(("domain", d))
    r.act("isolate_host", host, "Ejecución confirmada de malware"); r.esc("Ejecución confirmada de código malicioso")


@uc("UC-EDR-002")
def an_encoded_ps(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a)
    host = (a["entities"].get("hosts") or [{}])[0].get("hostname")
    parent = ev.get("parent", "")
    ch = T.changes(t, "SCCM", "EncodedCommand") if "ccmexec" in parent.lower() else []
    if ch and "Get-CimInstance Win32_Product" in ev.get("decoded_preview", ""):
        lt = to_local(t)
        r.btp(0.95, "Inventario de software de SCCM (PowerShell codificado autorizado)", change=ch[0]["id"])
        r.reason(f'Padre CcmExec.exe (agente SCCM) como SYSTEM; el comando decodificado solo inventaría software. {ch[0]["id"]} lo autoriza '
                 f'(08:00-10:00; esta ejecución a las {lt:%H:%M} local).')
        if not (7 <= lt.hour <= 10):
            r.reason("Ojo: fuera de la franja habitual 08:00-10:00, pero mismo contenido.")
        r.act("close", "ticket", "Proponer excluir CcmExec.exe + hash del script de la regla")
        r.group_key = "sccm-inventory"
        return
    r.nmi(0.5, f"PowerShell codificado en {host} sin explicación autorizada")
    sus = host_activity(r, host, t0, t1)
    for e in sus[:5]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
    if sus:
        r.tp(0.8, f"PowerShell codificado con actividad sospechosa asociada en {host}")
        r.act("isolate_host", host, "Ejecución sospechosa"); r.esc("Ejecución sospechosa")


@uc("UC-EDR-003")
def an_av(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 1, 24)
    host = (a["entities"].get("hosts") or [{}])[0].get("hostname")
    det = ev.get("detection_name", ""); act = ev.get("action")
    f = (a["entities"].get("files") or [{}])[0]
    sb = T.inv.sandbox.get((f.get("sha256") or "").lower())
    r.group_key = f"av:{det}"
    if "EICAR" in det:
        r.btp(0.95, f"Fichero de prueba EICAR en {host} (prueba del antivirus)")
        r.reason("EICAR es un fichero de prueba inofensivo; se puso en cuarentena.")
        r.act("close", "ticket", "Fichero de prueba")
        return
    sus = host_activity(r, host, t, t1, "¿actividad posterior a la detección?")
    sus = [e for e in sus if e.get("event_type") != "detection"]
    if act in ("quarantined", "blocked") and ev.get("executed") is False and not sus:
        kind = "PUA/adware" if det.startswith("PUA") else ("activador ilegal" if "AutoKMS" in det or "KMS" in det else "malware")
        r.tp(0.9, f'{kind} ({det}) {"bloqueado" if act == "blocked" else "en cuarentena"} antes de ejecutarse en {host}')
        r.down.append(f"{'bloqueado' if act == 'blocked' else 'cuarentena'} sin ejecución ni actividad posterior")
        if sb:
            r.reason(f'Sandbox: {sb["file_name"]} {sb["verdict"]} ({sb["score"]}) {sb["malware_family"]}.')
        r.reason("Descargado por el usuario (Downloads). Sin procesos, red ni persistencia posteriores en el equipo.")
        r.act("full_scan", host, "Escaneo completo (RB-02)")
        if "KMS" in det or "crack" in (f.get("name") or "").lower():
            r.act("notify", "responsable del usuario", "Software pirata: recordar la política de uso aceptable")
        return
    r.tp(0.85, f"Malware {det} en {host} con ejecución o actividad posterior")
    for e in sus[:5]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
    r.up.append("ejecución/actividad posterior"); r.act("isolate_host", host, "Malware activo"); r.esc("Ejecución de malware")


@uc("UC-EDR-004")
def an_lsass(r):
    a, ev = r.a, r.a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]
    r.tp(0.97, f'Volcado de credenciales (LSASS) en {host} con {ev.get("technique")}')
    r.up.append("robo de credenciales confirmado")
    creds = ev.get("cached_credentials_on_host") or []
    if creds:
        r.reason(f'En el equipo había credenciales en caché de {", ".join(creds)}: hay que darlas por robadas.')
    r.act("isolate_host", host, "Robo de credenciales en curso")
    for c in creds:
        r.act("reset_password", c, "Credencial expuesta en el volcado de LSASS"); r.act("revoke_sessions", c, "Credencial expuesta")
        r.links.append(("user", c.lower()))
    r.esc("Robo de credenciales (LSASS)")


@uc("UC-EDR-005")
def an_rmm(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 1, 24)
    host = a["entities"]["hosts"][0]["hostname"]; user = (a["entities"].get("users") or [{}])[0].get("upn")
    r.tp(0.85, f'AnyDesk no aprobado con sesión entrante desde {ev.get("remote_country", "?")} en {host}')
    r.reason(f'Herramienta aprobada: {ev.get("approved_rmm")}. Sesión {ev.get("session_direction")}, ticket IT: {ev.get("it_ticket")}.')
    if ev.get("child_processes"):
        r.reason(f'Procesos hijos: {ev["child_processes"]} → el operador remoto está explorando recursos internos.')
        r.up.append("control remoto con acciones confirmadas")
    asset = T.inv.asset_by_host.get(host.lower()) or {}
    if asset.get("zone") == "STORES":
        r.links.append(("store", host.split("-")[1].lower()))
        r.reason(f'{host} está en la red plana de tienda ({asset.get("location")}): comparte segmento con los TPV.')
        r.service_crit("Cobro en tienda")  # segmento compartido con los TPV
    r.act("isolate_host", host, "Acceso remoto no autorizado"); r.act("kill_process", f"AnyDesk en {host}", "Cortar la sesión")
    r.act("block_ioc", "download.anydesk.com", "Uso dual: solo con N2")
    if user:
        r.act("reset_password", user, "Posible ingeniería social (soporte falso)")
    r.questions.append("Llamar a la tienda: ¿alguien pidió al usuario instalar AnyDesk (falso soporte)?")
    r.esc("Control remoto no autorizado con actividad en el equipo")


@uc("UC-EDR-006")
def an_miner(r):
    a, T = r.a, r.t; ev = a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]; t, t0, t1 = window(a, 3, 3)
    r.tp(0.97, f'Criptominero en {host} tras explotar el servidor')
    r.reason(f'{ev.get("process")}; cadena {ev.get("parent_chain")}; persistencia {ev.get("persistence")}.')
    if ev.get("known_vuln"):
        r.reason(f'Vía de entrada probable: {ev["known_vuln"]}.')
    for e in host_activity(r, host, t0, t1)[:4]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
    r.up.append("ejecución confirmada")
    r.act("isolate_host", host, "Servidor comprometido (N2 + responsable de Integración continua)")
    r.act("patch", host, "Parchear la vulnerabilidad expuesta antes de reconectar"); r.act("rotate_secrets", host, "Rotar credenciales de Jenkins")
    for d in a["entities"].get("domains") or []:
        r.act("block_ioc", d, "Pool de minería")
    r.esc("Ejecución confirmada en servidor expuesto a Internet")


@uc("UC-EDR-007")
def an_shadow(r):
    a, ev = r.a, r.a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]
    user = (a["entities"].get("users") or [{}])[0].get("upn")
    r.tp(0.98, f'Borrado de instantáneas en {host}: precursor de ransomware')
    r.reason(f'Lanzado por {ev.get("parent")}; el EDR lo {ev.get("edr_action")}. {ev.get("note", "")}')
    if ev.get("edr_action") == "blocked":
        r.reason("Aunque se bloqueó, el atacante ya tiene ejecución y privilegios en el servidor: no aplica el −1.")
    r.up.append("ejecución confirmada con privilegios")
    r.act("isolate_host", host, "Ransomware inminente (N2 + responsable del servicio)")
    if user:
        r.act("disable_user", user, "Cuenta usada por el atacante"); r.links.append(("user", norm_user(user)))
    r.act("call", "N2 de guardia", "RB-02: borrado de shadow copies → escalado inmediato por teléfono")
    r.esc("Ransomware inminente")


@uc("UC-EDR-008")
def an_recon(r):
    a, ev = r.a, r.a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]
    mal = "rundll32" in (ev.get("parent") or "").lower() or "loader" in (ev.get("parent") or "").lower()
    if mal:
        r.tp(0.95, f'Reconocimiento del dominio desde el malware en {host} ({", ".join(ev.get("tools") or [])})')
        r.reason(f'Padre {ev.get("parent")}, {ev.get("commands")} comandos en {ev.get("window_s")} s a las {ev.get("time_local")}.')
        r.up.append("ejecución confirmada"); r.act("isolate_host", host, "Operador humano activo"); r.esc("Fase de descubrimiento de una intrusión")
    else:
        r.nmi(0.5, f"Comandos de reconocimiento en {host}")
        r.questions.append("¿Lo ejecutó un administrador? Confirmar con el usuario.")


@uc("UC-EDR-009")
def an_webshell(r):
    a = r.a; host = a["entities"]["hosts"][0]["hostname"]
    r.tp(0.95, f"Web shell en {host}"); r.up.append("ejecución confirmada")
    r.act("isolate_host", host, "Aislar el nodo (quedan otros frontales) — N2 + negocio"); r.act("rotate_secrets", host, "Rotar secretos")
    r.esc("Web shell en frontal")


@uc("UC-EDR-010")
def an_browser_creds(r):
    a = r.a; host = a["entities"]["hosts"][0]["hostname"]
    r.tp(0.9, f"Robo de credenciales del navegador en {host}"); r.up.append("robo de credenciales")
    r.act("isolate_host", host, "Infostealer"); r.esc("Robo de credenciales")


@uc("UC-EDR-011")
def an_edr_tamper(r):
    a, T = r.a, r.t; ev = a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]; t, t0, t1 = window(a, 2, 2)
    mw = ev.get("maintenance_window")
    ch = T.change_by_id(mw) if mw and mw != "ninguna" else None
    r.group_key = f"edr-stop:{mw or 'none'}"
    if ch:
        inside = ch["_start"] - H <= t <= ch["_end"] + H
        if inside and str(ev.get("restarted_after_s", "")).strip():
            r.btp(0.9, f'Parada del agente EDR durante la actualización aprobada {ch["id"]}', change=ch["id"])
            r.reason(f'{ch["id"]} «{ch["titulo"]}» ({ch["detalle"]}); el agente volvió en {ev.get("restarted_after_s")}.')
            r.act("close", "ticket", "Mantenimiento aprobado")
            return
        if str(ev.get("restarted_after_s", "")).strip():
            r.btp(0.7, f'Parada breve del agente EDR en {host} asociada a {ch["id"]}, pero fuera de su ventana', change=ch["id"])
            r.reason(f'{ch["id"]} está planificado {ch["inicio"]}→{ch["fin"]} (local) y la parada fue {fmt_local(t)}: '
                     f'{"antes" if t < ch["_start"] else "después"} de la ventana. El agente se reinició en {ev.get("restarted_after_s")}.')
            r.questions.append(f"Confirmar con Ciberseguridad que el despliegue de {ch['id']} empezó antes de lo previsto.")
            r.act("verify", "Ciberseguridad", f"Confirmar el adelanto del cambio {ch['id']}")
            return
    r.tp(0.95, f'Agente EDR detenido en {host} por {ev.get("parent_process", "proceso desconocido")} sin mantenimiento')
    r.reason(f'Proceso padre {ev.get("parent_process")}; ventana de mantenimiento: {mw or "ninguna"}.')
    for e in host_activity(r, host, t0, t1)[:5]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
    r.up.append("evasión de defensas con ejecución")
    r.act("isolate_host", host, "Evasión de defensas (N2 + responsable del servicio)"); r.esc("Manipulación del EDR")


@uc("UC-EDR-012")
def an_pos(r):
    a, T = r.a, r.t; ev = a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]; t, t0, t1 = window(a, 24, 24)
    r.tp(0.97, f'RAM scraper de tarjetas en el TPV {host}')
    r.reason(f'{ev.get("reader")} lee la memoria de {ev.get("target")}. La descripción del servicio dice {ev.get("service_description")} '
             "— texto escrito por el atacante para engañar al analista: el ticket citado "
             + ("no existe en el calendario." if not T.change_by_id("SEC-2210") else "existe."))
    r.up.append("datos de pago (PCI)")
    for e in host_activity(r, host, t0, t, "¿cómo llegó el scraper al TPV?"):
        if e.get("event_type") == "service_install":
            r.ev("edr_events", e["event_id"], f'{fmt_local(parse_ts(e["timestamp"]))}: servicio {(e.get("details") or {}).get("service_name", "")} '
                 f'instalado por {e.get("user")} ({(e.get("details") or {}).get("image", "")})')
            r.reason(f'El servicio se instaló la víspera ({fmt_local(parse_ts(e["timestamp"]))}) con la cuenta {e.get("user")}.')
            r.links.append(("user", norm_user(e.get("user"))))
    r.act("isolate_host", host, "TPV comprometido — N2 + negocio (impacto en ventas de la tienda)")
    r.act("block_ioc", (a["entities"].get("files") or [{}])[0].get("sha256", ""), "Hash del scraper")
    r.act("notify", "Responsable PCI / Directora de Operaciones", "Posible compromiso de tarjetas: obligaciones PCI DSS")
    store = host.split("-")[1] if host.count("-") >= 2 else ""
    if store:
        r.links.append(("store", store.lower())); r.group_key = f"pos:{store}"
    r.esc("Datos de pago comprometidos")


# ---------------------------------------------------------------------------------- RB-09 red
@uc("UC-NET-001")
def an_beacon(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 24, 24)
    dom = ev.get("domain") or (a["entities"].get("domains") or [""])[0]
    hosts = [h["hostname"] for h in a["entities"].get("hosts") or []]
    ti = T.intel(dom)["tip"]
    r.group_key = f"beacon:{dom}"
    known = (ti and ti["reputation"] == "benign") or dom.endswith(KNOWN_GOOD_SUFFIX) or dom.endswith(SAFE_INTERNAL_DOMAINS)
    if known and (ev.get("domain_age_days") or 9999) > 90:
        r.fp(0.9, f"Beaconing legítimo a {dom} (telemetría/actualización de software conocido)")
        r.reason(f'Dominio con {ev.get("domain_age_days")} días, {"benigno en el TIP" if ti else "de un proveedor conocido"}; '
                 f'intervalo {ev.get("mean_interval_s")} s típico de agentes y clientes de actualización.')
        r.act("close", "ticket", f"Proponer añadir {dom} a la lista de exclusión de la regla de beaconing")
        return
    r.tp(0.85, f'Beaconing a {dom} desde {", ".join(hosts)}' + (f' ({ti["malware_family"]})' if ti and ti.get("malware_family") else ""))
    if ti:
        r.reason(f'TIP: {dom} {ti["reputation"]} {ti["malware_family"]} ({ti["tags"]}).')
    r.reason(f'Intervalo medio {ev.get("mean_interval_s")} s (σ {ev.get("stddev_interval_s", "?")}), dominio de {ev.get("domain_age_days")} días, '
             f'visto por {ev.get("distinct_hosts_seen")} equipo(s). UA: {ev.get("user_agent", "")}.')
    if ev.get("hosts_type") == "TPV":
        r.reason("Los equipos que balizan son TPV: deberían hablar solo con la pasarela de pago.")
        r.up.append("TPV en ámbito PCI")
    for h in hosts:
        r.act("isolate_host", h, "Implante con C2 activo"); r.links.append(("host", h.lower()))
        if h.startswith("POS-"):
            r.links.append(("store", h.split("-")[1].lower()))
    r.act("block_ioc", dom, "Dominio de C2")
    for ip in a["entities"].get("ips") or []:
        r.act("block_ioc", ip, "IP de C2")
    r.links.append(("domain", dom)); r.esc("C2 activo")


@uc("UC-NET-002")
def an_ti_ip(r):
    a, T = r.a, r.t; ev = a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]; t, t0, t1 = window(a, 3, 3)
    ip = ev.get("dst_ip")
    r.tp(0.9, f'{host} conecta con {ip} ({ev.get("ti_match")})')
    sus = host_activity(r, host, t0, t1, "proceso detrás de la conexión")
    for e in sus[:4]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
    if sus:
        r.up.append("proceso malicioso confirmado detrás de la conexión")
        r.act("isolate_host", host, "Equipo con proceso malicioso conectado al C2"); r.esc("C2 confirmado con proceso detrás")
    r.act("block_ioc", ip, "IP en la inteligencia de amenazas")
    r.links += [("ip", ip), ("host", host.lower())]


@uc("UC-NET-003")
def an_scan(r):
    a, T = r.a, r.t; ev = a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]; t, t0, t1 = window(a)
    if host.upper() == "NESSUS01":
        ch = T.changes(t, "NESSUS01", "Escaneo semanal")
        r.group_key = f"nessus:{to_local(t):%Y-%m-%d}" if to_local(t).hour < 12 else f"nessus:{(to_local(t)+dt.timedelta(days=1)):%Y-%m-%d}"
        if ch:
            r.btp(0.97, f'Escaneo semanal autorizado de NESSUS01 ({ch[0]["id"]})', change=ch[0]["id"])
            r.reason(f'Origen el escáner autorizado y dentro de su ventana de miércoles 01:00-05:00 ({fmt_local(t)}).')
            r.act("close", "ticket", "Proponer excluir NESSUS01 de la regla en su ventana")
            return
        r.nmi(0.6, f"NESSUS01 escaneando fuera de su ventana ({fmt_local(t)})")
        r.questions.append("Confirmar con Ciberseguridad si se lanzó un escaneo extraordinario.")
        return
    r.tp(0.9, f'Escaneo interno desde {host}: {ev.get("distinct_dst_hosts")} equipos, puertos {ev.get("ports") or ev.get("distinct_ports")}')
    r.reason("No es el escáner autorizado. Puertos de administración (SMB/RDP/WinRM/SSH/SQL): búsqueda de movimiento lateral.")
    r.act("isolate_host", host, "Origen de escaneo hostil"); r.esc("Descubrimiento de red desde un puesto"); r.links.append(("host", host.lower()))


@uc("UC-NET-004")
def an_lateral(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a)
    src, dst, acct = ev.get("src", ""), ev.get("dst", ""), ev.get("account", "")
    r.group_key = f"lateral:{src}:{acct}"
    ch = T.changes(t, "PsExec", dst, acct)
    ch = [c for c in ch if dst.lower() in c["alcance"].lower() or dst.lower() in c["detalle"].lower()]
    if src.upper() == "JUMP01" and acct.startswith("adm.") and ch:
        r.btp(0.95, f'PsExec autorizado desde JUMP01 a {dst} ({ch[0]["id"]})', change=ch[0]["id"])
        r.reason(f'{ch[0]["id"]} «{ch[0]["titulo"]}»: PsExec desde JUMP01 con cuenta adm. a {ch[0]["alcance"]}.')
        r.act("close", "ticket", "Cambio aprobado")
        return
    r.tp(0.95, f'Movimiento lateral con {acct} de {src} a {dst} ({ev.get("method")})')
    if src.upper() != "JUMP01" and acct.startswith("adm."):
        r.reason(f'{ev.get("policy_note", "Las cuentas adm.* solo pueden usarse desde JUMP01")}: se usó desde {src}.')
    r.reason(f'Ticket de cambio: {ev.get("change_ticket", "ninguno")}.')
    for f in a["entities"].get("files") or []:
        sb = T.sandbox(f.get("sha256"))
        if sb and sb["verdict"] == "malicious":
            r.reason(f'Binario desplegado {sb["file_name"]}: {sb["malware_family"]}.'); r.up.append("ejecución de binario malicioso")
    r.up.append("identidad privilegiada")
    r.act("isolate_host", src, "Origen del movimiento lateral"); r.act("isolate_host", dst, "Destino comprometido (N2 + responsable del servicio)")
    r.act("disable_user", acct, "Cuenta de administrador robada"); r.act("reset_password", acct, "Credencial robada")
    r.links += [("host", src.lower()), ("host", dst.lower()), ("user", acct.lower())]
    r.esc("Movimiento lateral no autorizado")


@uc("UC-NET-005")
def an_dga(r):
    a, T = r.a, r.t; ev = a["evidence"]
    dom = ev.get("query", ""); parent = ev.get("parent_domain", "")
    ti = T.intel(parent)["tip"]
    r.group_key = f"dga:{parent}"
    if (ti and ti["reputation"] == "benign") or parent.endswith(KNOWN_GOOD_SUFFIX) or "cdn" in parent:
        r.fp(0.9, f"Subdominio aleatorio legítimo de {parent} (CDN/nube), no DGA")
        r.reason(f"Los servicios cloud/CDN generan subdominios con alta entropía (entropía {ev.get('entropy')}); {parent} es un proveedor conocido.")
        r.act("close", "ticket", f"Proponer excluir *.{parent} de la regla DGA")
        return
    r.nmi(0.55, f"Dominio con aspecto DGA {dom}")
    r.questions.append("Revisar qué proceso hizo la consulta (EDR) y si hubo conexión posterior.")


@uc("UC-NET-006")
def an_dns_tunnel(r):
    a, T = r.a, r.t; ev = a["evidence"]; host = a["entities"]["hosts"][0]["hostname"]; t, t0, t1 = window(a, 2, 1)
    parent = ev.get("parent_domain", "")
    ti = T.intel(parent)["tip"]
    r.group_key = f"dnstun:{parent}"
    if parent.endswith(KNOWN_GOOD_SUFFIX) or (ev.get("distinct_clients") or 0) > 20 and (ev.get("domain_age_days") or 0) > 365:
        r.fp(0.9, f"Consultas DNS largas a {parent}: servicio de reputación/antivirus legítimo")
        r.reason(f'{parent}: {ev.get("distinct_clients")} clientes, {ev.get("domain_age_days")} días de antigüedad; los antivirus y listas DNSBL codifican hashes en subdominios.')
        r.act("close", "ticket", f"Proponer excluir {parent} de la regla de túnel DNS")
        return
    r.tp(0.9, f'Exfiltración por túnel DNS desde {host} a {parent} ({ev.get("qtype")})')
    r.reason(f'{ev.get("queries_1h")} consultas/h con etiquetas de {ev.get("avg_label_len")} caracteres, dominio de {ev.get("domain_age_days")} días, '
             f'{ev.get("distinct_clients")} cliente; franja {ev.get("local_time", "")}.')
    sus = host_activity(r, host, t - 30 * 24 * H, t1, "origen del túnel en el servidor (30 días atrás)")
    for e in sus[:5]:
        r.ev("edr_events", e["event_id"], describe_edr(e))
    asset = T.inv.asset_by_host.get(host.lower()) or {}
    if asset:
        r.reason(f'{host}: {asset.get("description") or asset.get("business_service")}.')
    if sus:
        r.up.append("implante confirmado en el servidor")
        if any("sqlcmd" in (e.get("command_line") or "") for e in sus):
            r.up.append("datos personales (envíos con nombre, dirección y teléfono)")
            r.reason("Un servicio sin firma vuelca datos de clientes (nombre, dirección, teléfono) con sqlcmd: posible brecha RGPD.")
            r.act("notify", "DPO", "Posible salida de datos personales de clientes: plazo de 72 h AEPD")
    r.act("block_ioc", parent, "Dominio del túnel")
    r.act("isolate_host", host, "Servidor con implante — N2 + responsable del WMS (impacto en salida de pedidos)")
    r.links += [("host", host.lower()), ("domain", parent)]
    r.esc("Exfiltración de datos")


# ---------------------------------------------------------------------------------- RB-05 web
@uc("UC-WEB-001")
def an_waf(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 1, 24)
    ip = (a["entities"].get("ips") or [""])[0]; url = (a["entities"].get("urls") or [""])[0]
    r.service_crit("Tienda online")
    ch = [c for c in T.changes(t, "pentest", "192.0.2") if ip.startswith("192.0.2.")]
    if ch and ev.get("action") == "blocked":
        r.btp(0.95, f'Pentest autorizado ({ch[0]["id"]}) bloqueado por el WAF: {ev.get("rule_msg")}', change=ch[0]["id"])
        r.reason(f'Origen {ip} dentro del rango de la auditora (192.0.2.10-12) y de la ventana del pentest.')
        r.act("close", "ticket", "Actividad del pentest"); r.group_key = f"pentest:{ch[0]['id']}"
        return
    ok = [e for e in T.search("ip", ip, t - 1 * H, t1, sources=["waf"], why="¿alguna petición del atacante tuvo éxito?")
          if e.get("rule_id") and str(e.get("status")) in ("200", "201", "302") and e.get("action") != "blocked"]
    path = url.split("tarvia.example")[-1]
    vul = [v for v in T.inv.vulns if v["hostname"].startswith("WEB-ECOM") and any(seg and seg in path for seg in v["notas"].split("/") if len(seg) > 6)]
    if ok or vul:
        r.tp(0.8, f'Ataque web con peticiones no bloqueadas o contra una ruta vulnerable ({path[:50]})')
        for e in ok[:3]:
            r.ev("waf", e["event_id"], f'{e["method"]} {e["uri"][:60]} → {e["status"]} ({e["action"]})')
        r.esc("Posible explotación de la tienda online")
        return
    T.intel(ip)
    r.tp(0.9, f'Escaneo oportunista de Internet ({ev.get("rule_msg")}) contra la tienda, bloqueado por el WAF')
    r.down.append("bloqueado por el WAF sin peticiones con éxito")
    r.reason(f'{ev.get("hits")} peticiones desde {ip}, todas {ev.get("action")}; ninguna petición del origen pasó el WAF.')
    if any(k in path for k in ("wp-login", ".env", "cgi-bin", "luci", "phpunit", ".git")):
        r.reason("La ruta atacada no existe en la tienda (sondeo genérico de bots).")
        pass  # la matriz manda: low × Crítica = medium, −1 por bloqueo = low
    r.act("close", "ticket", "Bloqueado, sin impacto")
    r.group_key = f"waf-scan:{to_local(t):%Y-%m-%d}"


@uc("UC-WEB-002")
def an_stuffing(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 1, 6)
    r.service_crit("Tienda online")
    succ = ev.get("success_count") or 0
    ips = a["entities"].get("ips") or []
    r.group_key = "stuffing:" + (ev.get("device_fingerprint", "")[:12] or ",".join(ips[:2]))
    if succ == 0:
        r.tp(0.85, f'Credential stuffing contra el login de clientes sin accesos correctos (rate limit {ev.get("rate_limit", "?")})')
        r.down.append("rate limit activado y ningún acceso correcto")
        if (ev.get("distinct_src_ips") or 0) <= 3:
            r.reason(f'{ev.get("distinct_src_ips")} IP y 0 accesos: el rate limit funcionó y no hay cuentas afectadas.')
        r.reason(f'{ev.get("failed_logins_15min")} fallos en 15 min desde {ev.get("distinct_src_ips")} IP(s), 0 éxitos.')
        for ip in ips:
            r.act("block_ioc", ip, "Origen del stuffing")
        r.group_key = "stuffing-blocked"  # mismo patrón todo el mes (1 IP, 0 accesos): un único ticket para el N2 (§6)
        return
    r.tp(0.95, f'Credential stuffing masivo con {succ} accesos correctos a cuentas de clientes')
    r.reason(f'{ev.get("failed_logins_15min")} fallos/15 min (base {ev.get("baseline_failed_15min")}), {ev.get("distinct_accounts")} cuentas, '
             f'{ev.get("distinct_src_ips")} IPs de proxies residenciales; captcha: {ev.get("captcha")}.')
    fp = ev.get("device_fingerprint")
    oks = [e for e in T.search("key", fp, t - H, t1, sources=["ecom_auth"], why="accesos correctos con la huella del bot") if e.get("result") == "success"] if fp else []
    victims = sorted({e["customer_id"] for e in oks})
    if victims:
        r.reason(f'Cuentas con acceso correcto: {", ".join(victims)}.')
        for v in victims:
            r.aff("customers", v); r.links.append(("customer", v.lower()))
    r.up.append("datos personales y pagos de clientes")
    r.act("enable_captcha", "API de login de la app", "Captcha y rate limit (RB-05)")
    for ip in ips[:10]:
        r.act("block_ioc", ip, "Proxy residencial del stuffing")
    for v in victims:
        r.act("reset_customer_password", v, "Cuenta de cliente con acceso del atacante")
    r.act("notify", "equipo de Fraude", "Vigilar compras de tarjetas regalo")
    r.esc("Accesos correctos a cuentas de clientes")


@uc("UC-WEB-003")
def an_ato(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 2, 2)
    cust = a["entities"]["customers"][0]["customer_id"]
    r.service_crit("Tienda online")
    r.tp(0.95, f'Toma de control de la cuenta de cliente {cust} y compra de tarjeta regalo')
    r.reason(f'Secuencia: {ev.get("sequence")} en {ev.get("minutes_between")} min; nuevo email en {ev.get("new_email_domain")}.')
    for e in T.related(a):
        r.ev("ecom_account", e["event_id"], f'{e.get("event")} {str(e.get("details"))[:80]} {e.get("amount") or ""}')
    r.up.append("fraude con pagos")
    r.act("lock_customer_account", cust, "Recuperar la cuenta y restaurar el email original")
    r.act("cancel_order", f"tarjetas regalo de {cust}", "Anular la tarjeta regalo antes de que se canjee")
    r.act("notify", "equipo de Fraude", "Fraude con tarjetas regalo")
    r.esc("Fraude económico (tarjetas regalo) §5")
    r.group_key = "ato-giftcards"; r.links.append(("customer", cust.lower()))


# ---------------------------------------------------------------------------------- RB-06 cloud
@uc("UC-CLD-001")
def an_cloud_key(r):
    a, T = r.a, r.t; ev = a["evidence"]; cl = a["entities"]["cloud"]; t, t0, t1 = window(a, 24 * 7, 48)
    ip = (a["entities"].get("ips") or [""])[0]
    r.service_crit("Tienda online")  # cuenta AWS de producción
    r.tp(0.95, f'Clave AWS de {cl.get("identity")} usada desde fuera ({ip}) con herramientas de Kali')
    r.reason(f'Origen habitual {ev.get("usual_sources")}; ahora {ip}, UA {ev.get("user_agent")}; llamadas de reconocimiento {ev.get("calls")}.')
    key = cl.get("access_key")
    if key:
        hist = T.search("key", key, t0, t1, sources=["cloudtrail"], limit=2000, why="historial de la access key")
        srcs = sorted({h.get("sourceIPAddress") for h in hist})
        r.reason(f'La clave {key} se ha usado desde: {", ".join(srcs)}.')
        ci = T.grep("cicd_builds", "AWS_ACCESS_KEY_ID", t - 7 * 24 * H, t, why="¿se filtró la clave en un build?")
        for c in ci[:2]:
            r.reason(f'Build {c.get("build_id")} en {c.get("runner")}: un paquete leyó AWS_ACCESS_KEY_ID ({fmt_local(parse_ts(c["timestamp"]))}).')
            r.ev("cicd_builds", c["event_id"], str(c.get("details"))[:120]); r.links.append(("host", (c.get("runner") or "").lower()))
        r.act("disable_access_key", key, "Clave filtrada en uso por el atacante")
        r.links.append(("key", key.lower()))
    r.act("block_ioc", ip, "Origen del atacante"); r.up.append("acceso confirmado"); r.links += [("ip", ip), ("user", (cl.get("identity") or "").lower())]
    r.esc("Credenciales cloud comprometidas")


@uc("UC-CLD-002")
def an_cloud_admin(r):
    a, T = r.a, r.t; ev = a["evidence"]; cl = a["entities"]["cloud"]
    r.service_crit("Tienda online")  # cuenta AWS de producción
    r.tp(0.97, f'Persistencia en AWS: {cl.get("identity")} crea el usuario {cl.get("new_user")} con AdministratorAccess')
    r.reason(f'Acciones {ev.get("actions")} sin ticket de cambio ({ev.get("change_ticket")}), desde {", ".join(a["entities"].get("ips") or [])}.')
    r.up.append("privilegios de administrador")
    r.act("disable_user", f'IAM {cl.get("new_user")}', "Usuario creado por el atacante")
    r.act("disable_access_key", f'claves de {cl.get("new_user")} y {cl.get("identity")}', "Persistencia")
    r.links += [("user", (cl.get("identity") or "").lower()), ("user", (cl.get("new_user") or "").lower())] + [("ip", i) for i in a["entities"].get("ips") or []]
    r.esc("Persistencia con privilegios de administrador en la nube")


@uc("UC-CLD-003")
def an_bucket_public(r):
    a, T = r.a, r.t; ev = a["evidence"]; cl = a["entities"]["cloud"]
    rel = T.related(a)
    src_ip = (rel[0].get("sourceIPAddress") if rel else "") or ""
    r.group_key = f"bucket-public:{cl.get('bucket')}"
    if "public" in (cl.get("bucket") or "") and "terraform" in (ev.get("source") or "") and (src_ip.startswith("172.16.") or not src_ip):
        r.btp(0.85, f'Política pública en {cl.get("bucket")} aplicada por Terraform desde el runner interno (bucket público por diseño)')
        r.reason(f'Bucket de medios públicos de la web; cambio hecho por {cl.get("identity")} desde el CI interno {src_ip}.')
        r.act("close", "ticket", "Proponer excluir tarvia-media-public de la regla")
        return
    r.tp(0.7, f'Bucket {cl.get("bucket")} expuesto públicamente'); r.esc("Exposición de datos")


@uc("UC-CLD-004")
def an_cloud_exfil(r):
    a, T = r.a, r.t; ev = a["evidence"]; cl = a["entities"]["cloud"]
    r.critical_of("Crítica", f'bucket {cl.get("bucket")} ({ev.get("bucket_classification")})')
    r.aff("business_services", "CRM y datos de clientes (1,3 M registros, RGPD)")
    r.tp(0.97, f'Exfiltración de copias del CRM desde {cl.get("bucket")} ({ev.get("bytes_estimated")}) por {cl.get("identity")}')
    r.reason(f'{ev.get("get_object_count_10min")} GetObject en 10 min sobre {ev.get("objects_prefix")} desde {", ".join(a["entities"].get("ips") or [])}.')
    r.up.append("datos personales de 1,3 M clientes")
    r.act("disable_access_key", f'claves de {cl.get("identity")}', "Cortar la descarga"); r.act("notify", "DPO", "Brecha de datos personales: 72 h AEPD/CNPD")
    r.links += [("user", (cl.get("identity") or "").lower())] + [("ip", i) for i in a["entities"].get("ips") or []]
    r.esc("Datos personales de clientes fuera de la organización (DPO)")


# ---------------------------------------------------------------------------------- RB-04 DLP
@uc("UC-DLP-001", "UC-DLP-002")
def an_dlp(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 24, 4)
    user = (a["entities"].get("users") or [{}])[0].get("upn", "")
    usr = T.user(user) if user else None
    dest = ev.get("destination") or ev.get("recipient") or (a["entities"].get("domains") or [""])[0]
    pii = ev.get("personal_data_matches") or sum((ev.get("matches") or {}).values()) if isinstance(ev.get("matches"), dict) else ev.get("personal_data_matches") or 0
    fl = ", ".join(f.get("name", "") for f in a["entities"].get("files") or []) or ev.get("file", "")
    flows = T.changes(t, dest) if dest else []
    r.group_key = f"dlp:{dest}:{fl[:30]}"
    if flows:
        r.btp(0.95, f'Envío de {fl} a {dest}: flujo aprobado {flows[0]["id"]}', change=flows[0]["id"])
        r.reason(f'{flows[0]["id"]} «{flows[0]["titulo"]}»: {flows[0]["detalle"]}. Los datos personales están cubiertos por el contrato.')
        r.act("close", "ticket", "Flujo aprobado")
        return
    leaving = [h for h in (usr or {}).get("hr_events", []) if "baja" in h["tipo"]]
    sql = T.search("user", norm_user(user), t - 24 * H, t, sources=["sql_audit"], why="¿consultas masivas previas al CRM?") if user else []
    big = [s for s in sql if (s.get("rows_returned") or 0) > 10000]
    if not pii and not leaving and not big and not ev.get("file_encrypted") and dest.endswith(DUAL_USE):
        r.fp(0.8, f'Subida voluminosa sin datos personales a {dest} ({fl})')
        r.reason(f"Fichero de trabajo ({fl}) sin coincidencias de datos personales; {usr['department'] if usr else ''}: uso habitual.")
        r.act("close", "ticket", "Sin datos sensibles; recordar el uso de la herramienta corporativa de envío")
        return
    r.tp(0.9, f'Fuga de datos de clientes: {norm_user(user)} envía {fl} a {dest}')
    if leaving:
        r.reason(f'RRHH: {leaving[0]["detalle"]}'); r.links.append(("user", norm_user(user)))
    for s in big[:3]:
        r.ev("sql_audit", s["event_id"], f'{s.get("statement_type")} {s.get("object")} → {s.get("rows_returned")} filas desde {s.get("client_host")}')
    if big:
        r.reason(f"Antes del envío extrajo {sum(s.get('rows_returned', 0) for s in big):,} filas del CRM.".replace(",", "."))
    if ev.get("file_encrypted"):
        r.reason("El fichero va cifrado con contraseña: el DLP no puede inspeccionarlo (cuenta como sospechoso).")
    if pii:
        r.reason(f"Coincidencias de datos personales: {ev.get('matches') or pii}.")
    r.reason(f"Destino personal/no corporativo: {dest}. El DLP solo auditó, no bloqueó.")
    r.up.append("datos personales de clientes")
    r.act("notify", "DPO + RRHH + Legal", "Datos personales fuera de la organización (72 h AEPD)")
    r.act("disable_user", user, "Empleada saliente exfiltrando datos (coordinar con RRHH/Legal)")
    r.esc("Datos personales fuera de la organización (DPO)")
    r.group_key = f"insider:{norm_user(user)}"


# ---------------------------------------------------------------------------------- RB-07 Vela
@uc("UC-AI-001", "UC-AI-002")
def an_vela(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 24, 24)
    r.service_crit("Vela")
    rel = T.related(a)
    prompt = (rel[0].get("prompt") if rel else "") or ev.get("prompt_excerpt", "")
    sess = a["entities"].get("ai_session") or (rel[0].get("session_id") if rel else None)
    events = T.search("key", sess, t0, t1, sources=["ai_gateway"], why="sesión completa del asistente") if sess else rel
    auth = (a["entities"].get("customers") or [{}])[0].get("customer_id")
    cross = [e for e in events for tc in e.get("tool_calls") or [] if (tc.get("args") or {}).get("customer_id") not in (None, e.get("customer_id"))]
    leak = [e for e in events if re.search(r"(c[oó]digo|interno|descuento|staff|prompt|sistema|instrucciones)", e.get("response_summary") or "", re.I)
            and not (e.get("guardrail") or {}).get("action") == "blocked"]
    for e in events[:6]:
        r.ev("ai_gateway", e["event_id"], f'«{(e.get("prompt") or "")[:70]}» → {(e.get("response_summary") or "")[:70]} '
             f'[{(e.get("guardrail") or {}).get("action")}]')
    hostile = INJECTION_RX.search(prompt or "") or ev.get("action") == "blocked" or cross
    if not hostile and not leak:
        r.fp(0.9, f'Cliente corrigiéndose en el chat de Vela («{prompt[:50]}»), no es prompt injection')
        r.reason("Lenguaje natural de un cliente que rectifica o pide un rol inocuo; ninguna herramienta llamada con datos de otro cliente.")
        r.act("close", "ticket", "Proponer afinar el guardarraíl (frases como «ignora lo anterior, me equivoqué…»)")
        r.group_key = "vela-fp"
        return
    r.tp(0.95 if (cross or leak) else 0.85, "Ataque de prompt injection contra Vela" + (" con fuga de información" if leak else ""))
    r.reason(f'Prompt: «{prompt[:120]}». Es un intento deliberado de saltarse las instrucciones del asistente.')
    if cross:
        r.reason(f'El asistente intentó llamar a herramientas con datos de otro cliente ({", ".join(sorted({(tc.get("args") or {}).get("customer_id") for e in cross for tc in e["tool_calls"]}))}).')
    if leak:
        r.reason(f'Fuga en un mensaje sin alerta: «{leak[0].get("response_summary", "")[:120]}».')
        r.up.append("fuga de información interna/clientes")
        r.act("rotate_secrets", "códigos internos filtrados por Vela", "Invalidar lo que reveló el asistente")
        r.esc("Fuga de información a través del asistente")
    src_ip = (a["entities"].get("ips") or [""])[0]
    others = T.search("ip", src_ip, t - 7 * 24 * H, t + 7 * 24 * H, sources=["ai_gateway"], why="¿la misma IP en otras sesiones?") if src_ip else []
    sess_other = sorted({e.get("session_id") for e in others} - {sess})
    if sess_other:
        r.reason(f"La IP {src_ip} aparece en otras {len(sess_other)} sesiones ({', '.join(sess_other[:3])}): atacante recurrente.")
    r.act("block_session", sess or "", "Cortar la sesión"); r.act("lock_customer_account", auth or "", "Cuenta usada para atacar al asistente")
    r.act("block_ioc", src_ip, "IP del atacante"); r.act("notify", "Responsable de IA", "Reforzar guardarraíles y autorización de herramientas")
    r.links += [("ip", src_ip)]; r.group_key = f"vela-attack:{src_ip}"
    if not leak and not cross:
        r.down.append("bloqueado por el guardarraíl sin fuga")


# ---------------------------------------------------------------------------------- RB-08 OT
@uc("UC-OT-001")
def an_ot(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a)
    src = ev.get("src", "")
    r.service_crit("Clasificación automática")
    if src.upper() in ("ENG-WS01", "WMS01"):
        r.btp(0.9, f"Acceso a OT desde origen autorizado {src}"); return
    ch = T.changes(t, src, "OT-MAINT", "clasificador", "PLC")
    if ch and (ev.get("firewall_rule") or "") in ch[0]["detalle"] + "OT-MAINT-TEMP":
        r.btp(0.9, f'Mantenimiento del fabricante del clasificador aprobado ({ch[0]["id"]}) vía JUMP01', change=ch[0]["id"])
        r.reason(f'{ch[0]["id"]}: {ch[0]["detalle"]}; regla {ev.get("firewall_rule")}; puertos {ev.get("ports")} (Modbus/EtherNet-IP) a {ch[0]["alcance"]}.')
        r.act("close", "ticket", "Mantenimiento aprobado; recordar retirar OT-MAINT-TEMP al terminar")
        return
    r.tp(0.85, f"Acceso a la red OT desde origen no autorizado {src}")
    r.reason("RB-08: nunca aislar ni bloquear nada en OT desde el SOC.")
    r.act("escalate_ot", "Responsable de Operaciones", "Solo escalar: el SOC no actúa sobre OT"); r.esc("Acceso no autorizado a OT")


# ---------------------------------------------------------------------------------- RB-10 CI/CD
@uc("UC-DEV-001")
def an_supply(r):
    a, T = r.a, r.t; ev = a["evidence"]; t, t0, t1 = window(a, 1, 24 * 5)
    host = a["entities"]["hosts"][0]["hostname"]
    pkg = ev.get("package", ""); exp = ev.get("expected_package", "")
    secrets = [v for v in ev.get("env_vars_read") or [] if re.search(r"AWS|TOKEN|SECRET|KEY|PASS", v, re.I)]
    r.group_key = f"cicd:{pkg.split('@')[0]}" if not secrets else None
    if "registro público" in pkg and exp.startswith("@tarvia"):
        r.tp(0.95, f'Dependency confusion en {ev.get("build")}: {pkg} suplanta a {exp} y roba secretos')
        r.reason(f'El paquete viene del registro público con el nombre de uno interno ({exp}); leyó {ev.get("env_vars_read")} y {ev.get("network")}.')
        r.reason(f'Resultado del build: {ev.get("build_result", "?")}.')
    elif secrets:
        r.tp(0.8, f"Script de instalación de {pkg} lee secretos ({', '.join(secrets)}) en {ev.get('pipeline')}")
    else:
        r.fp(0.9, f"Dependencia conocida ({pkg}) que descarga binarios por diseño desde {ev.get('network')}")
        r.reason(f'{pkg} es un paquete popular del {ev.get("registry", "registro público")}; su postinstall «{ev.get("postinstall", "")}» '
                 f'descarga binarios de {ev.get("network")} y solo lee {ev.get("env_vars_read")}: sin secretos.')
        r.act("close", "ticket", f"Proponer excluir {pkg.split('@')[0]} de la regla"); return
    r.up.append("secretos de producción expuestos")
    ct = T.search("ip", "172.16.10.21", t, t1, sources=["cloudtrail"], limit=50, why="uso legítimo de las claves desde el runner") if False else []
    leaked = [e for e in T.grep("cloudtrail", "kali", t, t1, why="¿uso posterior de las claves robadas?")]
    for e in leaked[:3]:
        r.ev("cloudtrail", e["event_id"], f'{e["eventName"]} por {e["userIdentity"].get("userName")} desde {e["sourceIPAddress"]} ({fmt_local(parse_ts(e["timestamp"]))})')
    if leaked:
        r.reason("Las claves del entorno del build se usan después desde fuera: ver alertas cloud enlazadas.")
        for e in leaked[:1]:
            r.links += [("key", (e["userIdentity"].get("accessKeyId") or "").lower()), ("user", (e["userIdentity"].get("userName") or "").lower())]
    for d in a["entities"].get("domains") or []:
        r.act("block_ioc", d, "Dominio de exfiltración del paquete")
    r.act("disable_access_key", "AWS_ACCESS_KEY_ID del runner (svc_ecom_deploy)", "Rotar todas las credenciales del entorno del build")
    r.act("rotate_secrets", "NPM_TOKEN", "Token expuesto"); r.act("pin_registry", "ecom-frontend", "Forzar @tarvia/* al registro interno")
    r.links.append(("host", host.lower())); r.esc("Robo de secretos de producción")


# ============================================================================================ orquestación
def severity(r):
    rule_sev = r.a.get("severity", "low")
    crit = max([CRIT_ORDER.index(c) for c, _ in r.crit if c in CRIT_ORDER] or [1])
    base = MATRIX.get(rule_sev, MATRIX["low"])[crit]
    asset_why = next((w for c, w in r.crit if CRIT_ORDER.index(c) == crit), "por defecto")
    steps = [f"Regla {rule_sev} × activo {CRIT_ORDER[crit]} ({asset_why}) = {base}"]
    # Desglose para el panel: cómo entra la alerta y cómo sale tras la matriz (§2) y el ajuste.
    r.sev_calc = {"rule": rule_sev, "asset": CRIT_ORDER[crit], "asset_why": asset_why, "base": base, "adj": 0, "adj_why": "", "note": ""}
    sev = SEV_ORDER.index(base)
    if r.verdict in ("benign_true_positive",):
        final = "low" if sev >= 3 else "informational"
        steps.append(f"Actividad autorizada ({r.authorized}) → {final}")
        r.sev_calc.update(note=f"Actividad autorizada{f' ({r.authorized})' if r.authorized else ''}", final=final)
        return final, "; ".join(steps)
    if r.verdict == "false_positive":
        steps.append("Falso positivo → informational")
        r.sev_calc.update(note="Falso positivo", final="informational")
        return "informational", "; ".join(steps)
    adj = 0
    if r.up and not r.down:
        adj = 1; steps.append(f"+1 ({r.up[0]})")
    elif r.down and not r.up:
        adj = -1; steps.append(f"−1 ({r.down[0]})")
    r.sev_calc.update(adj=adj, adj_why=(r.up[0] if adj > 0 else r.down[0] if adj < 0 else ""))
    sev = max(0, min(4, sev + adj))
    final = SEV_ORDER[sev]
    if r.sev_override:
        final = r.sev_override[0]; steps = [r.sev_override[1]]
        r.sev_calc.update(note=r.sev_override[1], note_kind="runbook")
    r.sev_calc["final"] = final
    return final, "; ".join(steps) + f" → {final}"


def triage(alert, tools=None):
    t_start = time.time()
    T = tools or Tools()
    T.trace = []
    T.log("alerta", alert["alert_id"], f'{alert["rule_id"]} «{alert["rule_name"]}» severidad de regla {alert["severity"]} — {fmt_local(parse_ts(alert["created_at"]))}')
    r = Result(alert, T)
    common(r)
    fn = AN.get(alert["rule_id"])
    if fn:
        try:
            fn(r)
        except Exception as e:  # nunca tirar la cola por una alerta rara
            r.nmi(0.3, f'{alert.get("rule_name") or alert["rule_id"]} (faltan datos en la alerta para analizarla)')
            r.questions.append(f"La alerta no trae todos los campos esperados ({e}); revisar a mano.")
    else:
        r.nmi(0.3, f'{alert["rule_name"]} (regla nueva: el motor no tiene comprobaciones para ella)')
        r.reason("Esta regla no está en el catálogo de casos de uso, así que el motor no puede dar un veredicto fiable. "
                 "La investiga la IA y decide una persona.")
        r.questions.append("Regla nueva no cubierta por el motor: confirmar el veredicto de la IA.")
    if r.injection and r.verdict in ("false_positive", "benign_true_positive"):
        r.questions.append("El contenido intenta forzar un veredicto benigno; revisar con especial cuidado.")
    others = T.other_alerts(alert, 24)
    sev, why = severity(r)
    escalate = r.verdict == "true_positive" and (sev in ("high", "critical") or bool(r.escalate_reasons))
    if r.verdict == "needs_more_info":
        # No se puede descartar: si por matriz es high/critical, que lo vea el N2 (no se cierra a ciegas).
        escalate = sev in ("high", "critical")
        if escalate:
            r.esc(f"No se puede descartar y la matriz da {sev}: decide el N2")
    reason = "; ".join(r.escalate_reasons) or (f"true_positive {sev}" if escalate else "")
    if escalate and sev in ("high", "critical") and not r.escalate_reasons:
        reason = f"§5: true_positive de severidad {sev}"
    if escalate and not [x for x in r.actions if x["action"] not in ("close",)]:
        r.act("escalate", "N2", reason)
    if not escalate and r.verdict == "true_positive" and not any(x["action"] == "close" for x in r.actions):
        r.act("close", "ticket", "Contenido sin impacto; cerrar tras ejecutar las acciones sin aprobación")
    to = "N2 de guardia (teléfono) + Responsable SOC + CISO" if sev == "critical" else "N2 (misma jornada) + Responsable SOC" if sev == "high" else "N2"
    uc_ = T.inv.usecases.get(alert["rule_id"], {})
    mitre = [x for x in [(alert.get("mitre") or {}).get("technique_id")] if x]
    ticket = {
        "ticket_id": "TKT-" + alert["alert_id"][4:],
        "alert_ids": [alert["alert_id"]],
        "title": r.title or alert["rule_name"],
        "verdict": r.verdict, "confidence": round(r.conf, 2), "severity": sev, "severity_rationale": why,
        "affected": r.affected, "summary": " ".join(r.why) or r.title,
        "evidence": r.evidence, "enrichment": r.enrich, "mitre": mitre,
        "recommended_actions": r.actions, "executed_actions": [],
        "escalation": {"escalate": escalate, "to": to if escalate else "", "reason": reason if escalate else ""},
        "open_questions": r.questions,
        "triage_seconds": round(time.time() - t_start, 4),
        # extra para el panel y la correlación (no forman parte del esquema obligatorio)
        "_rule_id": alert["rule_id"], "_rule_severity": alert["severity"], "_created_at": alert["created_at"],
        "_runbook": alert.get("runbook") or uc_.get("runbook"), "_reasons": r.why, "_trace": T.trace,
        "_group_key": r.group_key, "_links": [l for l in r.links if l and l[1]], "_authorized": r.authorized,
        "_injection": r.injection, "_related_alerts": others[:30], "_product": alert.get("source_product"),
        "_sev_calc": getattr(r, "sev_calc", None),
    }
    return ticket
