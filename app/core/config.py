# =============================================================
# 💠 ZENTHRA.CORE_SECURITY — CONFIGURACIÓN GLOBAL (v3.7 Legacy Wrapper)
# =============================================================
# Capa de compatibilidad para imports antiguos:
#
#     from app.core.config import settings
#
# La fuente única de verdad es app.core.settings:
#     - Settings (clase)
#     - settings (instancia global)
#
# =============================================================

from app.core.settings import Settings, settings

__all__ = ["Settings", "settings"]