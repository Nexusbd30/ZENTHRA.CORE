// src/components/charts/TimeSeriesChart.jsx
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";

/**
 * TimeSeriesChart (stable/pro)
 * - data: [{ t: epochMs, <serie1>: number, <serie2>?: number, ... }]
 * - lines: [{ key: "rx", label?: "RX" }, { key: "tx", label?: "TX" }]
 * - yLabel?: string
 * - height?: number (default 260)
 * - margin?: { top,right,bottom,left }
 * - tickFormatter?: (tsMs:number) => string   // X-axis
 * - valueFormatter?: (value:number, key:string) => [string, string] // Tooltip
 */
export default function TimeSeriesChart({
  data = [],
  lines = [],
  yLabel = "",
  height = 260,
  margin = { top: 12, right: 24, bottom: 8, left: 8 },
  tickFormatter,
  valueFormatter,
  noDataMessage = "Sin datos disponibles",
}) {
  const fmtTick =
    tickFormatter ||
    ((v) =>
      new Date(v).toLocaleTimeString("es-ES", { hour12: false }));

  const fmtLabel =
    (v) => new Date(v).toLocaleString("es-ES", { hour12: false });

  const fmtValue =
    valueFormatter ||
    ((value, name) => [Number(value ?? 0).toFixed(2), name]);

  // Estado vacío (no rompe layout)
  if (!Array.isArray(data) || data.length === 0) {
    return (
      <div className="bg-white rounded-2xl p-6 shadow border text-center text-sm text-slate-500">
        {noDataMessage}
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl p-4 shadow border">
      {yLabel ? (
        <div className="text-sm text-slate-600 mb-2">{yLabel}</div>
      ) : null}

      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={margin}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="t" tickFormatter={fmtTick} minTickGap={60} />
          <YAxis />
          <Tooltip
            labelFormatter={fmtLabel}
            formatter={fmtValue}
            // estilos sobrios (opcional)
            wrapperStyle={{ outline: "none" }}
          />
          {lines?.length > 1 ? (
            <Legend verticalAlign="top" height={24} />
          ) : null}
          {lines.map((ln, idx) => (
            <Line
              key={ln.key || idx}
              type="monotone"
              dataKey={ln.key}
              name={ln.label || ln.key}
              dot={false}
              strokeWidth={2}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
