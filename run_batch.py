"""Triaje en lote: lee alertas (JSONL), genera un ticket por alerta y agrupa en incidentes.

    python run_batch.py                       # muestra de desarrollo (150 alertas)
    python run_batch.py --all                 # las 11.061 alertas
    python run_batch.py --file nuevas.jsonl   # alertas nuevas (p. ej. las del día de la defensa)
"""
import argparse, collections, json, os, sys, time

from config import DATA_DIR, OUT_DIR
from context import Tools
from engine import triage
from correlate import build_incidents


def load(fp):
    with open(fp, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def run(alerts, out_name, verbose=True):
    T = Tools()
    tickets = []
    t0 = time.time()
    for i, a in enumerate(sorted(alerts, key=lambda x: x["created_at"])):
        tickets.append(triage(a, T))
        if verbose and (i + 1) % 500 == 0:
            print(f"  {i+1}/{len(alerts)} ({time.time()-t0:.0f}s)", flush=True)
    incidents = build_incidents(tickets)
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, f"{out_name}_alert_tickets.json"), "w", encoding="utf-8") as f:
        json.dump(tickets, f, ensure_ascii=False)
    with open(os.path.join(OUT_DIR, f"{out_name}_incidents.json"), "w", encoding="utf-8") as f:
        json.dump(incidents, f, ensure_ascii=False, indent=1)
    if verbose:
        v = collections.Counter(t["verdict"] for t in tickets)
        s = collections.Counter(t["severity"] for t in tickets)
        print(f"{len(tickets)} alertas triadas en {time.time()-t0:.1f}s → {len(incidents)} tickets/incidentes")
        print("  veredictos:", dict(v)); print("  severidades:", dict(s))
        print("  escaladas:", sum(t["escalation"]["escalate"] for t in tickets))
    return tickets, incidents


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true"); ap.add_argument("--file")
    a = ap.parse_args()
    if a.file:
        fp, name = a.file, os.path.splitext(os.path.basename(a.file))[0]
        # Las alertas nuevas se añaden al índice para poder correlacionarlas entre sí.
        from build_index import load_alerts
        import sqlite3
        from config import DB_PATH
        db = sqlite3.connect(DB_PATH); load_alerts(db, [fp]); db.commit(); db.close()
    elif a.all:
        fp, name = os.path.join(DATA_DIR, "03_alertas", "alertas.jsonl"), "all"
    else:
        fp, name = os.path.join(DATA_DIR, "03_alertas", "alertas_muestra_desarrollo.jsonl"), "dev"
    run(load(fp), name)
