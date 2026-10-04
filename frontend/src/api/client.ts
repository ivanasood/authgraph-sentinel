import type { AssessmentSummary, Finding, GraphData } from "../types";

const API_BASE =
  (import.meta.env.VITE_API_BASE as string) || "http://127.0.0.1:8001";

async function json<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(API_BASE + path, opts);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} - ${body || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  base: API_BASE,
  runAssessment: () =>
    json<AssessmentSummary>("/api/assessments", { method: "POST" }),
  listAssessments: () => json<AssessmentSummary[]>("/api/assessments"),
  findings: (id: string) => json<Finding[]>(`/api/assessments/${id}/findings`),
  graph: (id: string) => json<GraphData>(`/api/assessments/${id}/graph`),
  reportMarkdown: async (id: string) => {
    const res = await fetch(`${API_BASE}/api/assessments/${id}/report.md`);
    if (!res.ok) throw new Error(`${res.status}`);
    return res.text();
  },
};
