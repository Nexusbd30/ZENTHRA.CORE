# =============================================================
# 🌐 NetworkMonitor — ZENTHRA.CORE_SECURITY (v1.3 - Corrección Deadlock)
# =============================================================
# v1.3: Añade un 'sleep' inicial en _monitor_loop para evitar
#       un deadlock con Uvicorn durante el arranque.
# =============================================================

import random
import threading
import time
from typing import Any, Dict

import psutil
import requests

# --- Plantillas de Amenazas Simuladas ---
SIMULATED_THREATS = [
    {
        "title": "Simulación: Escaneo de puertos detectado",
        "source": "Zenthra-Simulator",
        "description": "Se detectó un barrido Nmap simulado en el puerto 22 (SSH) desde la IP 192.168.1.101.",
        "level": "medium",
    },
    {
        "title": "Simulación: Intento de Fuerza Bruta",
        "source": "Zenthra-Simulator",
        "description": "Múltiples intentos de inicio de sesión fallidos en el servicio 'admin-panel' desde la IP 10.0.5.23.",
        "level": "high",
    },
    {
        "title": "Simulación: Conexión a IP maliciosa",
        "source": "Zenthra-Simulator",
        "description": "Tráfico saliente detectado hacia la IP 185.12.33.4 (conocida por C2 Botnet).",
        "level": "critical",
    },
    {
        "title": "Simulación: Actividad de red anómala",
        "source": "Zenthra-Simulator",
        "description": "Pico de tráfico inusual (TX 45MB/s) detectado fuera de horario laboral.",
        "level": "low",
    },
]


# -----------------------------------------


class NetworkMonitor:
    """
    Clase que supervisa la actividad de red.
    Puede ejecutarse en modo 'real' (psutil) o 'simulado' (genera alertas).
    """

    def __init__(
            self,
            api_url: str,
            token: str,
            check_interval: int = 10,
            simulate: bool = True,  # Por defecto, activamos la simulación
    ):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.check_interval = check_interval
        self.simulate = simulate
        self.running = False
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.thread = None

    # =============================================================
    # 🚀 Iniciar monitor
    # =============================================================
    def start(self):
        if self.running:
            print("[⚙️] Monitor de red ya en ejecución.")
            return

        mode = "SIMULACIÓN" if self.simulate else "REAL (psutil)"
        print(f"[🟢] Iniciando monitor de red en modo: {mode}...")

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    # =============================================================
    # 🛑 Detener monitor
    # =============================================================
    def stop(self):
        print("[🔴] Deteniendo monitor de red...")
        self.running = False
        if self.thread:
            self.thread.join()

    # =============================================================
    # 🔍 Bucle principal (selector de modo)
    # =============================================================
    def _monitor_loop(self):

        # =========================================================
        # ✅ INICIO DE LA CORRECCIÓN (v1.3)
        # =========================================================
        # Esperamos 5 segundos ANTES de empezar el bucle.
        # Esto le da tiempo a Uvicorn a terminar de arrancar
        # y estar listo para recibir peticiones HTTP.
        print("[⚙️] Monitor: Esperando 5 segundos a que la API esté lista...")
        time.sleep(5)
        # =========================================================
        # FIN DE LA CORRECCIÓN
        # =========================================================

        # Inicializa contadores para el modo real
        if not self.simulate:
            self.last_bytes_sent = psutil.net_io_counters().bytes_sent
            self.last_bytes_recv = psutil.net_io_counters().bytes_recv

        while self.running:
            if self.simulate:
                # --- MODO SIMULACIÓN ---
                sim_wait_time = random.randint(15, 30)
                time.sleep(sim_wait_time)

                payload = random.choice(SIMULATED_THREATS)
                print(f"[🤖] Simulación: Generando amenaza '{payload['title']}'...")
                self._post_threat(payload)

            else:
                # --- MODO REAL (psutil) ---
                time.sleep(self.check_interval)
                try:
                    counters = psutil.net_io_counters()
                    sent_rate = (counters.bytes_sent - self.last_bytes_sent) / self.check_interval
                    recv_rate = (counters.bytes_recv - self.last_bytes_recv) / self.check_interval

                    self.last_bytes_sent = counters.bytes_sent
                    self.last_bytes_recv = counters.bytes_recv

                    if sent_rate > 10_000_000 or recv_rate > 10_000_000:
                        print(f"[⚠️] Pico de tráfico real detectado: TX={sent_rate:.2f}B/s, RX={recv_rate:.2f}B/s")
                        self._report_real_threat(sent_rate, recv_rate)

                except Exception as e:
                    print(f"[❌] Error en el bucle de 'psutil': {e}")

    # =============================================================
    # 🚨 Reportar amenaza (Modo Real)
    # =============================================================
    def _report_real_threat(self, sent_rate: float, recv_rate: float):
        payload = {
            "title": "Actividad de red anómala detectada",
            "source": "NetworkMonitor (psutil)",
            "description": (
                f"Se detectó un pico inusual de tráfico real.\n"
                f"TX: {sent_rate:.2f} B/s | RX: {recv_rate:.2f} B/s."
            ),
            "level": "medium",
        }
        self._post_threat(payload)

    # =============================================================
    # 📦 Función genérica para enviar la amenaza al backend
    # =============================================================
    def _post_threat(self, payload: Dict[str, Any]):
        """
        Envía la amenaza (payload) al endpoint /threats/ de la API.
        """
        try:
            response = requests.post(
                f"{self.api_url}/threats/",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=10,
            )

            if response.status_code == 201:
                print(f"[✅] Amenaza registrada correctamente: {payload['title']}")
            else:
                # Si recibes 401, el token del .env expiró.
                print(f"[❌] Error al registrar amenaza: {response.status_code} → {response.text}")

        except Exception as e:
            print(f"[⚠️] Fallo de conexión al enviar amenaza: {e}")