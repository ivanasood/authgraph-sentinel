import { SEVERITY_COLOR } from "../types";
import type { Finding } from "../types";

interface Props {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  categoryFilter: string;
  onFilter: (category: string) => void;
}

export default function FindingsList({
  findings,
  selectedId,
  onSelect,
  categoryFilter,
  onFilter,
}: Props) {
  const categories = ["All", ...Array.from(new Set(findings.map((f) => f.category)))];
  const shown =
    categoryFilter === "All"
      ? findings
      : findings.filter((f) => f.category === categoryFilter);

  return (
    <div className="list">
      <div className="chips">
        {categories.map((c) => (
          <button
            key={c}
            className={`chip ${categoryFilter === c ? "chip-on" : ""}`}
            onClick={() => onFilter(c)}
          >
            {c}
          </button>
        ))}
      </div>

      <div className="rows">
        {shown.map((f) => (
          <button
            key={f.id}
            className={`row ${selectedId === f.id ? "row-on" : ""}`}
            onClick={() => onSelect(f.id)}
          >
            <span className="score" style={{ color: SEVERITY_COLOR[f.severity] }}>
              {f.cvss_score.toFixed(1)}
            </span>
            <span className="row-main">
              <span className="row-title">{f.title}</span>
              <span className="row-meta">
                <span style={{ color: SEVERITY_COLOR[f.severity] }}>{f.severity}</span>
                <span className="row-cat">{f.category}</span>
                {f.endpoint && <span className="row-endpoint">{f.endpoint}</span>}
              </span>
            </span>
            {f.confidence === "verified" && <span className="verified">verified</span>}
          </button>
        ))}
      </div>
    </div>
  );
}
