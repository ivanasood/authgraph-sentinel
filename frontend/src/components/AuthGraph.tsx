import { REL_COLOR } from "../types";
import type { GraphData, GraphNode, GraphLink } from "../types";

const COL_X: Record<string, number> = { principal: 90, role: 360, resource: 630 };
const NODE_W = 170;
const NODE_H = 34;
const ROW_H = 54;
const TOP = 48;

interface Placed {
  node: GraphNode;
  x: number;
  y: number;
  cx: number;
  cy: number;
}

function shortLabel(n: GraphNode): string {
  if (n.kind === "principal") return `${n.username} · ${n.role}`;
  if (n.kind === "role") return n.role || n.id;
  return n.id;
}

export default function AuthGraph({ data }: { data: GraphData }) {
  const edges: GraphLink[] = data.edges || data.links || [];

  const byKind: Record<string, GraphNode[]> = { principal: [], role: [], resource: [] };
  for (const n of data.nodes) {
    const k = n.kind || "resource";
    (byKind[k] ||= []).push(n);
  }

  const placed = new Map<string, Placed>();
  (["principal", "role", "resource"] as const).forEach((kind) => {
    byKind[kind].forEach((node, i) => {
      const x = COL_X[kind];
      const y = TOP + i * ROW_H;
      placed.set(node.id, { node, x, y, cx: x + NODE_W / 2, cy: y + NODE_H / 2 });
    });
  });

  const maxRows = Math.max(1, ...Object.values(byKind).map((a) => a.length));
  const height = TOP + maxRows * ROW_H + 20;
  const width = COL_X.resource + NODE_W + 40;

  const colTitles: [string, number][] = [
    ["Principals", COL_X.principal],
    ["Roles", COL_X.role],
    ["Resources", COL_X.resource],
  ];

  return (
    <div className="graph-wrap">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="graph-svg"
        preserveAspectRatio="xMidYMin meet"
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill={REL_COLOR.requested} />
          </marker>
        </defs>

        {colTitles.map(([title, x]) => (
          <text key={title} x={x + NODE_W / 2} y={28} className="graph-coltitle">
            {title}
          </text>
        ))}

        {edges.map((e, i) => {
          const s = placed.get(e.source);
          const t = placed.get(e.target);
          if (!s || !t) return null;
          const rel = e.rel || "requested";
          const color = REL_COLOR[rel] || REL_COLOR.requested;
          return (
            <line
              key={i}
              x1={s.cx} y1={s.cy} x2={t.cx} y2={t.cy}
              stroke={color}
              strokeWidth={rel === "owns" ? 1.6 : 1.2}
              strokeDasharray={rel === "requested" ? "4 3" : undefined}
              markerEnd={rel === "requested" ? "url(#arrow)" : undefined}
              opacity={0.75}
            />
          );
        })}

        {Array.from(placed.values()).map(({ node, x, y }) => {
          const kind = node.kind || "resource";
          return (
            <g key={node.id}>
              <rect
                x={x} y={y} width={NODE_W} height={NODE_H} rx={7}
                className={`gnode gnode-${kind}`}
              />
              <text x={x + NODE_W / 2} y={y + NODE_H / 2 + 4} className="gnode-label">
                {shortLabel(node)}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="graph-legend">
        <span className="gl"><span className="gl-line" style={{ background: REL_COLOR.owns }} /> owns</span>
        <span className="gl"><span className="gl-line gl-dash" style={{ background: REL_COLOR.requested }} /> requested</span>
        <span className="gl"><span className="gl-line" style={{ background: REL_COLOR.has_role }} /> has role</span>
      </div>
    </div>
  );
}
