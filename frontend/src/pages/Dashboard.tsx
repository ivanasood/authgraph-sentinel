import { useState } from "react";
import { api } from "../api/client";
import type { AssessmentSummary, Finding, GraphData } from "../types";
import SeveritySummary from "../components/SeveritySummary";
import FindingsList from "../components/FindingsList";
import FindingDetail from "../components/FindingDetail";
import AuthGraph from "../components/AuthGraph";
import ReportView from "../components/ReportView";

type Tab = "findings" | "graph" | "report";

export default function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<AssessmentSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [report, setReport] = useState<string>("");
  const [tab, setTab] = useState<Tab>("findings");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState("All");

  async function runAssessment() {
    setLoading(true);
    setError(null);
    try {
      const s = await api.runAssessment();
      const [f, g, r] = await Promise.all([
        api.findings(s.id),
        api.graph(s.id),
        api.reportMarkdown(s.id),
      ]);
      setSummary(s);
      setFindings(f);
      setGraph(g);
      setReport(r);
      setSelectedId(f.length ? f[0].id : null);
      setCategoryFilter("All");
      setTab("findings");
    } catch (e: any) {
      setError(
        `Couldn't run the assessment: ${e.message}. ` +
          `Check that the API is on ${api.base} and the lab is running at http://127.0.0.1:8000.`
      );
    } finally {
      setLoading(false);
    }
  }

  const selected = findings.find((f) => f.id === selectedId) || null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden="true">
            <line x1="5" y1="13" x2="13" y2="5" stroke="var(--accent)" strokeWidth="1.4" />
            <line x1="5" y1="13" x2="13" y2="21" stroke="var(--rel-req)" strokeWidth="1.4" strokeDasharray="3 2" />
            <line x1="13" y1="5" x2="21" y2="13" stroke="var(--muted)" strokeWidth="1.4" />
            <circle cx="5" cy="13" r="3.4" fill="var(--accent)" />
            <circle cx="13" cy="5" r="3.4" fill="var(--panel-2)" stroke="var(--accent)" strokeWidth="1.4" />
            <circle cx="13" cy="21" r="3.4" fill="var(--panel-2)" stroke="var(--line)" strokeWidth="1.4" />
            <circle cx="21" cy="13" r="3.4" fill="var(--panel-2)" stroke="var(--line)" strokeWidth="1.4" />
          </svg>
          <span className="wordmark">AuthGraph Sentinel</span>
        </div>
        <div className="topbar-right">
          {summary && (
            <span className="target">
              {summary.target.name} <span className="mono muted">{summary.target.url}</span>
            </span>
          )}
          <button className="run" onClick={runAssessment} disabled={loading}>
            {loading ? "Assessing…" : summary ? "Re-run assessment" : "Run assessment"}
          </button>
        </div>
      </header>

      {error && <div className="banner banner-error">{error}</div>}

      {!summary && !error && (
        <div className="empty">
          <h1 className="empty-title">Map the access control of World Monitor.</h1>
          <p className="empty-sub">
            Sentinel discovers endpoints, builds an authorization graph of who owns and who
            requests each resource, and proves access-control flaws by reproducing them against
            a local lab. Run an assessment to begin.
          </p>
          <button className="run run-lg" onClick={runAssessment} disabled={loading}>
            {loading ? "Assessing…" : "Run assessment"}
          </button>
        </div>
      )}

      {summary && (
        <main className="main">
          <SeveritySummary counts={summary.severity} />

          <nav className="tabs">
            <button className={tab === "findings" ? "tab tab-on" : "tab"} onClick={() => setTab("findings")}>
              Findings <span className="tab-count">{findings.length}</span>
            </button>
            <button className={tab === "graph" ? "tab tab-on" : "tab"} onClick={() => setTab("graph")}>
              Authorization graph
            </button>
            <button className={tab === "report" ? "tab tab-on" : "tab"} onClick={() => setTab("report")}>
              Report
            </button>
          </nav>

          {tab === "findings" && (
            <div className="split">
              <FindingsList
                findings={findings}
                selectedId={selectedId}
                onSelect={setSelectedId}
                categoryFilter={categoryFilter}
                onFilter={setCategoryFilter}
              />
              <FindingDetail finding={selected} />
            </div>
          )}

          {tab === "graph" && graph && <AuthGraph data={graph} />}

          {tab === "report" && <ReportView markdown={report} />}
        </main>
      )}
    </div>
  );
}
