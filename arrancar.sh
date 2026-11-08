#!/usr/bin/env bash
# Arranca la simulación: dependencias, clave del LLM del DCC, API simulada del SOC y panel.
# Uso: ./arrancar.sh        → cola con las 11.061 alertas del mes
#      ./arrancar.sh demo   → cola vacía, para cargar en directo las alertas de la demo
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt

# --- Clave del LLM del DCC (UAB THE HACK!). Se guarda en ~/.uth_key (fuera del proyecto), nunca en el código.
if [ -z "$UTH_KEY" ] && [ -f "$HOME/.uth_key" ]; then export UTH_KEY="$(cat "$HOME/.uth_key")"; fi
if [ -z "$UTH_KEY" ]; then
  echo "Pega la clave del LLM del equipo (empieza por uth-; está en tu plaza → Recursos)."
  read -r -s -p "Clave (Enter para seguir sin agente IA): " UTH_KEY; echo
  if [ -n "$UTH_KEY" ]; then printf '%s' "$UTH_KEY" > "$HOME/.uth_key"; chmod 600 "$HOME/.uth_key"; export UTH_KEY; fi
fi
if [ -n "$UTH_KEY" ]; then
  if curl -s -o /dev/null -w "%{http_code}" https://dcc-llm-gw.uab.cat/uabthehack/v1/models -H "Authorization: Bearer $UTH_KEY" | grep -q 200; then
    echo "Agente IA listo (ornith, LLM del DCC). Investigará los casos de uno en uno."
  else
    echo "Aviso: el LLM del DCC no responde con esa clave. El panel funciona igual sin agente (borra ~/.uth_key para cambiarla)."
  fi
fi

(cd ../06_herramientas && python3 -m uvicorn mock_soc_api:app --port 8000 >/tmp/tarvia_api.log 2>&1 &)
if [ "$1" = "demo" ]; then
  export TARVIA_DATASET=demo
  echo "Modo demo: la cola empieza vacía. Pulsa «Cargar alertas» en el panel y elige el fichero de la demo."
fi
python3 app.py
