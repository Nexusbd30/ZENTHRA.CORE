// =============================================================
// 📡 NetworkTrafficCard — Monitoreo de Tráfico Real (Windows)
// =============================================================
// - Usa Prometheus vía /monitoring/query_range (promRange)
// - Compatible con tu Windows Exporter actual (collector `net`)
// - Métrica: windows_net_bytes_total{nic="<NIC>"}
// - Muestra tráfico TOTAL (RX+TX) en Mb/s
// - Firma compatible con DataCenterPage:
//     <NetworkTrafficCard
//       nic="Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC"
//       windowMinutes={10}
//       stepSeconds={10}
//       refreshMs={10000}
//     />
// =============================================================

import { useEffect, useState } from "react";
import { promQuery, promRange } from "@/api/nexusApi";
import TimeSeriesChart from "@/components/charts/TimeSeriesChart";

const nowRange = (minutes) => {
  const end = Math.floor(Date.now() / 1000);
  return { start: end - minutes * 60, end };
};

const toSeries = (result, key) => {
  const values = result?.values ?? [];
  if (!Array.isArray(values) || values.length === 0) return [];
  return values.map(([ts, v]) => ({
    t: Number(ts) * 1000,
    [key]: Number(v) || 0,
  }));
};

const instantPoint = async (q, key) => {
  const response = await promQuery(q);
  const raw = response?.data?.result?.[0]?.value;
  if (!Array.isArray(raw)) return [];
  const value = Number(raw[1]);
  if (!Number.isFinite(value)) return [];
  return [{ t: Number(raw[0]) * 1000, [key]: value }];
};

export default function NetworkTrafficCard({
  nic = "Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC",
  windowMinutes = 10,
  stepSeconds = 10,
  refreshMs = 10000,
}) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    const fetchData = async () => {
      try {
        setError("");

        const { start, end } = nowRange(windowMinutes);
        const step = `${stepSeconds}s`;

        // =====================================================
        // 📡 Tráfico total (Mb/s) por NIC
        //
        // Métrica de windows_exporter (collector `net`):
        //   windows_net_bytes_total{nic="<NIC>"}
        //
        // PromQL:
        //   rate(windows_net_bytes_total{nic="<NIC>"}[2m]) * 8 / 1024 / 1024
        //   -> bytes/s → bits/s → megabits/s
        // =====================================================
        const nicName = String(nic || "").trim();
        if (!nicName || nicName === "NIC not detected") {
          throw new Error("NIC no detectada desde Prometheus.");
        }

        const nicEscaped = nicName.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        const totalQuery =
          `sum(rate(windows_net_bytes_total{nic="${nicEscaped}"}[2m])) * 8 / 1024 / 1024`;
        const splitQuery =
          `(` +
          `sum(rate(windows_net_bytes_received_total{nic="${nicEscaped}"}[2m])) + ` +
          `sum(rate(windows_net_bytes_sent_total{nic="${nicEscaped}"}[2m]))` +
          `) * 8 / 1024 / 1024`;

        let res = await promRange({ q: totalQuery, start, end, step });
        let result = res?.data?.result?.[0];
        let series = toSeries(result, "traffic");

        if (!series.length) {
          res = await promRange({ q: splitQuery, start, end, step });
          result = res?.data?.result?.[0];
          series = toSeries(result, "traffic");
        }
        if (!series.length) {
          series = await instantPoint(totalQuery, "traffic");
        }
        if (!series.length) {
          series = await instantPoint(splitQuery, "traffic");
        }

        if (!cancelled) {
          setData(series);
          if (!series.length) {
            setError(
              "Sin datos de red — comprueba que windows_exporter expone windows_net_bytes_total para esa NIC."
            );
          }
        }
      } catch (err) {
        console.error("[NetworkTrafficCard] Error obteniendo métricas de red:", err);
        if (!cancelled) {
          setError("Error al obtener métricas de red desde Prometheus.");
          setData([]);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchData();
    if (refreshMs > 0) {
      const timer = setInterval(
        fetchData,
        Math.max(refreshMs, stepSeconds * 1000, 10000) // mínimo 10s
      );
      return () => {
        clearInterval(timer);
        cancelled = true;
      };
    }

    return () => {
      cancelled = true;
    };
  }, [nic, windowMinutes, stepSeconds, refreshMs]);

  // === UI ===
  if (loading) {
    return (
      <div className="space-y-3">
        <div className="h-6 w-40 bg-white/10 rounded animate-pulse" />
        <div className="h-64 bg-white/5 rounded-xl animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {error && (
        <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/40 px-3 py-2 rounded-lg">
          {error}
        </div>
      )}

      <TimeSeriesChart
        data={data}
        lines={[{ key: "traffic", label: "Total (Mb/s)" }]}
        yLabel="Mb/s"
        height={260}
        noDataMessage="Sin datos de red — revisa collector `net` y nombre exacto de la NIC."
      />
    </div>
  );
}
