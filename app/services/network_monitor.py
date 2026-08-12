# =============================================================
# ðŸŒ NetworkMonitor â€” VAELQORIX.XDR_COMMAND (v1.3 - CorrecciÃ³n Deadlock)
# =============================================================
# v1.3: AÃ±ade un 'sleep' inicial en _monitor_loop para evitar
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
        "title": "SimulaciÃ³n: Escaneo de puertos detectado",
        "source": "Vaelqorix-Simulator",
        "description": "Se detectÃ³ un barrido Nmap simulado en el puerto 22 (SSH) desde la IP 192.168.1.101.",
        "level": "medium",
    },
    {
        "title": "SimulaciÃ³n: Intento de Fuerza Bruta",
        "source": "Vaelqorix-Simulator",
        "description": "MÃºltiples intentos de inicio de sesiÃ³n fallidos en el servicio 'admin-panel' desde la IP 10.0.5.23.",
        "level": "high",
    },
    {
        "title": "SimulaciÃ³n: ConexiÃ³n a IP maliciosa",
        "source": "Vaelqorix-Simulator",
        "description": "TrÃ¡fico saliente detectado hacia la IP 185.12.33.4 (conocida por C2 Botnet).",
        "level": "critical",
    },
    {
        "title": "SimulaciÃ³n: Actividad de red anÃ³mala",
        "source": "Vaelqorix-Simulator",
        "description": "Pico de trÃ¡fico inusual (TX 45MB/s) detectado fuera de horario laboral.",
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
            simulate: bool = True,  # Por defecto, activamos la simulaciÃ³n
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
    # ðŸš€ Iniciar monitor
    # =============================================================
    def start(self):
        if self.running:
            print("[âš™ï¸] Monitor de red ya en ejecuciÃ³n.")
            return

        mode = "SIMULACIÃ“N" if self.simulate else "REAL (psutil)"
        print(f"[ðŸŸ¢] Iniciando monitor de red en modo: {mode}...")

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    # =============================================================
    # ðŸ›‘ Detener monitor
    # =============================================================
    def stop(self):
        print("[ðŸ”´] Deteniendo monitor de red...")
        self.running = False
        if self.thread:
            self.thread.join()

    # =============================================================
    # ðŸ” Bucle principal (selector de modo)
    # =============================================================
    def _monitor_loop(self):

        # =========================================================
        # âœ… INICIO DE LA CORRECCIÃ“N (v1.3)
        # =========================================================
        # Esperamos 5 segundos ANTES de empezar el bucle.
        # Esto le da tiempo a Uvicorn a terminar de arrancar
        # y estar listo para recibir peticiones HTTP.
        print("[âš™ï¸] Monitor: Esperando 5 segundos a que la API estÃ© lista...")
        time.sleep(5)
        # =========================================================
        # FIN DE LA CORRECCIÃ“N
        # =========================================================

        # Inicializa contadores para el modo real
        if not self.simulate:
            counters = psutil.net_io_counters()
            self.last_bytes_sent = counters.bytes_sent
            self.last_bytes_recv = counters.bytes_recv

        while self.running:
            if self.simulate:
                # --- MODO SIMULACIÃ“N ---
                sim_wait_time = random.randint(15, 30)
                time.sleep(sim_wait_time)

                payload = random.choice(SIMULATED_THREATS)
                print(f"[ðŸ¤–] SimulaciÃ³n: Generando amenaza '{payload['title']}'...")
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
                        print(f"[âš ï¸] Pico de trÃ¡fico real detectado: TX={sent_rate:.2f}B/s, RX={recv_rate:.2f}B/s")
                        self._report_real_threat(sent_rate, recv_rate)

                except Exception as e:
                    print(f"[âŒ] Error en el bucle de 'psutil': {e}")

    # =============================================================
    # ðŸš¨ Reportar amenaza (Modo Real)
    # =============================================================
    def _report_real_threat(self, sent_rate: float, recv_rate: float):
        payload = {
            "title": "Actividad de red anÃ³mala detectada",
            "source": "NetworkMonitor (psutil)",
            "description": (
                f"Se detectÃ³ un pico inusual de trÃ¡fico real.\n"
                f"TX: {sent_rate:.2f} B/s | RX: {recv_rate:.2f} B/s."
            ),
            "level": "medium",
        }
        self._post_threat(payload)

    # =============================================================
    # ðŸ“¦ FunciÃ³n genÃ©rica para enviar la amenaza al backend
    # =============================================================
    def _post_threat(self, payload: Dict[str, Any]):
        """
        EnvÃ­a la amenaza (payload) al endpoint /threats/ de la API.
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
                print(f"[âœ…] Amenaza registrada correctamente: {payload['title']}")
            else:
                # Si recibes 401, el token del .env expirÃ³.
                print(f"[âŒ] Error al registrar amenaza: {response.status_code} â†’ {response.text}")

        except Exception as e:
            print(f"[âš ï¸] Fallo de conexiÃ³n al enviar amenaza: {e}")
