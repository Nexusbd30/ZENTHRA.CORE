// =============================================================
// 💠 SystemMetrics — VAELQORIX XDR Command (v5.4 Windows-Exporter Safe)
// =============================================================
// - CPU % a partir de windows_cpu_time_total{mode="idle"}
//   Fórmula (por instancia):
//     100 - avg(rate(windows_cpu_time_total{mode="idle"}[2m])) * 100
//
// - Memoria libre (GB), robusto:
//   1) windows_os_physical_memory_free_bytes (collector `os`)
//   2) fallback: windows_memory_available_bytes (collector `memory`)
// =============================================================

import { useEffect, useState } from "react";
import { promQuery, promRange } from "@/api/nexusApi";
import TimeSeriesChart from "@/components/charts/TimeSeriesChart";

const nowRange = (minutes) => {
  const end = Math.floor(Date.now() / 1000);
  return { start: end - minutes * 60, end };
};

const mergeSeriesAverage = (results, key) => {
  if (!Array.isArray(results) || results.length === 0) return [];
  const bucket = new Map();
  for (const res of results) {
    const values = res?.values ?? [];
    for (const [ts, v] of values) {
      const t = Number(ts) * 1000;
      const val = Number(v);
      if (!Number.isFinite(t) || !Number.isFinite(val)) continue;
      const current = bucket.get(t) || { sum: 0, count: 0 };
      bucket.set(t, { sum: current.sum + val, count: current.count + 1 });
    }
  }
  return Array.from(bucket.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([t, item]) => ({ t, [key]: item.count ? item.sum / item.count : null }))
    .filter((point) => Number.isFinite(point[key]));
};

const instantPoint = async (q, key) => {
  const response = await promQuery(q);
  const raw = response?.data?.result?.[0]?.value;
  if (!Array.isArray(raw)) return [];
  const value = Number(raw[1]);
  if (!Number.isFinite(value)) return [];
  return [{ t: Number(raw[0]) * 1000, [key]: value }];
};

export default function SystemMetrics({
  windowMinutes = 10, // ventana de tiempo (min)
  stepSeconds = 15, // resolución (s)
}) {
  const [loading, setLoading] = useState(true);
  const [cpu, setCpu] = useState([]);
  const [mem, setMem] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    const fetchData = async () => {
      try {
        setError(null);

        const { start, end } = nowRange(windowMinutes);
        const step = `${stepSeconds}s`;

        // =====================================================
        // 🧠 CPU %
        //   100 - avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[2m]) * 100)
        // =====================================================
        const qCPU =
          '100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[2m])) * 100)';
        const cpuResp = await promRange({ q: qCPU, start, end, step });

        const cpuResAll = cpuResp?.data?.result ?? [];
        let cpuSeries = mergeSeriesAverage(cpuResAll, "cpu");
        if (!cpuSeries.length) {
          cpuSeries = await instantPoint(qCPU, "cpu");
        }

        if (!cancelled) {
          setCpu(cpuSeries);
        }

        // =====================================================
        // 🧠 Memoria libre (GB)
        //
        // 1) windows_os_physical_memory_free_bytes (collector `os`)
        // 2) fallback: windows_memory_available_bytes (collector `memory`)
        //
        // Mostramos "Memoria libre (GB)" para el NOC.
        // =====================================================
        const qMEM_OS =
          "100 * (1 - (windows_memory_available_bytes / windows_memory_physical_total_bytes))";

        let memResp = await promRange({ q: qMEM_OS, start, end, step });
        let memResAll = memResp?.data?.result ?? [];
        let memSeries = mergeSeriesAverage(memResAll, "mem");

        // Si no hay datos, probamos con windows_memory_available_bytes
        if (!memSeries.length) {
          const qMEM_FALLBACK =
            "100 * (1 - (windows_memory_physical_free_bytes / windows_memory_physical_total_bytes))";
          memResp = await promRange({ q: qMEM_FALLBACK, start, end, step });
          memResAll = memResp?.data?.result ?? [];
          memSeries = mergeSeriesAverage(memResAll, "mem");
          if (!memSeries.length) {
            memSeries = await instantPoint(qMEM_FALLBACK, "mem");
          }
        }

        if (!cancelled) {
          setMem(memSeries);

          if (!cpuSeries.length && !memSeries.length) {
            setError(
              "Sin datos reales de CPU/memoria desde Prometheus."
            );
          }
        }
      } catch (e) {
        console.error("[SystemMetrics] metrics error:", e);
        if (!cancelled) {
          setError("Error al obtener métricas de Prometheus.");
          setCpu([]);
          setMem([]);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchData();
    const id = setInterval(
      fetchData,
      Math.max(stepSeconds * 1000, 10000) // ≥10s
    );

    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [windowMinutes, stepSeconds]);

  // =========================================================
  // 🎨 UI
  // =========================================================
  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-64 bg-white/10 rounded animate-pulse" />
        <div className="h-64 bg-white/5 rounded-xl animate-pulse" />
        <div className="h-64 bg-white/5 rounded-xl animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/40 px-3 py-2 rounded-lg">
          {error}
        </div>
      )}

      {/* CPU */}
      <TimeSeriesChart
        data={cpu}
        lines={[{ key: "cpu", label: "CPU %" }]}
        yLabel="Uso de CPU (%)"
        noDataMessage="Sin datos de CPU — comprueba que windows_exporter expone windows_cpu_time_total."
      />

      {/* Memoria libre */}
      <TimeSeriesChart
        data={mem}
        lines={[{ key: "mem", label: "Memoria %" }]}
        yLabel="Uso de memoria (%)"
        noDataMessage="Sin datos de memoria — comprueba métricas de memoria en windows_exporter."
      />
    </div>
  );
}
