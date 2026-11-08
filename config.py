import os

HERE = os.path.dirname(os.path.abspath(__file__))
# Carpeta raíz del dataset (la que contiene 01_contexto, 02_inventario, …). Por defecto, la carpeta padre de solucion/.
DATA_DIR = os.environ.get("TARVIA_DATA", os.path.abspath(os.path.join(HERE, "..")))
DB_PATH = os.environ.get("TARVIA_DB", os.path.join(HERE, "data", "indice.sqlite"))
OUT_DIR = os.path.join(HERE, "data")
# API simulada del SOC (06_herramientas/mock_soc_api.py). Si no responde, la contención se simula en local.
SOC_API = os.environ.get("TARVIA_SOC_API", "http://localhost:8000")
# LLM opcional para redactar el resumen y dar una segunda opinión. Sin clave, el sistema funciona igual (determinista).
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.environ.get("TARVIA_LLM_MODEL", "claude-sonnet-5-5")
