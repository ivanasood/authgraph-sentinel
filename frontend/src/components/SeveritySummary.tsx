import { SEVERITY_ORDER, SEVERITY_COLOR } from "../types";
import type { SeverityCounts } from "../types";

export default function SeveritySummary({ counts }: { counts: SeverityCounts }) {
  const total = SEVERITY_ORDER.reduce((n, s) => n + (counts[s] || 0), 0);

  return (
    <div className="severity">
      <div className="severity-bar" role="img" aria-label="Severity distribution">
        {total === 0 ? (
          <div className="severity-seg" style={{ flex: 1, background: "var(--line)" }} />
        ) : (
          SEVERITY_ORDER.map((s) =>
            counts[s] > 0 ? (
              <div
                key={s}
                className="severity-seg"
                style={{ flex: counts[s], background: SEVERITY_COLOR[s] }}
                title={`${s}: ${counts[s]}`}
              />
            ) : null
          )
        )}
      </div>
      <div className="severity-legend">
        {SEVERITY_ORDER.map((s) => (
          <div key={s} className="severity-item">
            <span className="dot" style={{ background: SEVERITY_COLOR[s] }} />
            <span className="severity-count">{counts[s] || 0}</span>
            <span className="severity-label">{s}</span>
          </div>
        ))}
        <div className="severity-item severity-total">
          <span className="severity-count">{total}</span>
          <span className="severity-label">total</span>
        </div>
      </div>
    </div>
  );
}
