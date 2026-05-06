import { useEffect, useState } from "react";
import { promQuery, promRange } from "@/api/nexusApi";
import TimeSeriesChart from "@/components/charts/TimeSeriesChart";

const GPU_QUERIES = [
  { label: "DCGM GPU %", q: "avg(DCGM_FI_DEV_GPU_UTIL)" },
  { label: "NVIDIA GPU %", q: "avg(nvidia_smi_utilization_gpu_ratio) * 100" },
  { label: "NVIDIA GPU %", q: "avg(nvidia_smi_utilization_gpu)" },
  { label: "Windows GPU %", q: "avg(windows_gpu_engine_utilization_percentage)" },
];

let gpuUnavailableUntil = 0;

const nowRange = (minutes) => {
  const end = Math.floor(Date.now() / 1000);
  return { start: end - minutes * 60, end };
};

const toSeries = (result) => {
  const values = result?.values ?? [];
  if (!Array.isArray(values) || values.length === 0) return [];
  return values.map(([ts, v]) => ({
    t: Number(ts) * 1000,
    gpu: Math.max(0, Math.min(Number(v) || 0, 100)),
  }));
};

const instantPoint = async (q) => {
  const response = await promQuery(q);
  const raw = response?.data?.result?.[0]?.value;
  if (!Array.isArray(raw)) return [];
  const value = Number(raw[1]);
  if (!Number.isFinite(value)) return [];
  return [{ t: Number(raw[0]) * 1000, gpu: Math.max(0, Math.min(value, 100)) }];
};

export default function GpuMetrics({ windowMinutes = 10, stepSeconds = 15 }) {
  const [loading, setLoading] = useState(true);
  const [series, setSeries] = useState([]);
  const [source, setSource] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    const fetchData = async () => {
      try {
        setError("");
        if (Date.now() < gpuUnavailableUntil) {
          setSeries([]);
          setSource("");
          return;
        }
        const { start, end } = nowRange(windowMinutes);
        const step = `${stepSeconds}s`;

        let nextSeries = [];
        let nextSource = "";
        for (const candidate of GPU_QUERIES) {
          const response = await promRange({ q: candidate.q, start, end, step });
          nextSeries = toSeries(response?.data?.result?.[0]);
          if (!nextSeries.length) {
            nextSeries = await instantPoint(candidate.q);
          }
          if (nextSeries.length) {
            nextSource = candidate.label;
            break;
          }
        }

        if (!cancelled) {
          setSeries(nextSeries);
          setSource(nextSource);
          if (!nextSeries.length) {
            setError("");
            gpuUnavailableUntil = Date.now() + 60_000;
          }
        }
      } catch (err) {
        console.error("[GpuMetrics] metrics error:", err);
        if (!cancelled) {
          setSeries([]);
          setSource("");
          setError("Error al obtener metricas GPU desde Prometheus.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchData();
    const id = setInterval(fetchData, Math.max(stepSeconds * 1000, 10000));

    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [windowMinutes, stepSeconds]);

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
      {source && <div className="text-xs text-slate-400">Fuente GPU: {source}</div>}
      {error && (
        <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/40 px-3 py-2 rounded-lg">
          {error}
        </div>
      )}
      <TimeSeriesChart
        data={series}
        lines={[{ key: "gpu", label: "GPU %" }]}
        yLabel="Uso de GPU (%)"
        noDataMessage="Sin datos de GPU disponibles."
      />
    </div>
  );
}
