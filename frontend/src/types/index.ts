export interface SeverityCounts {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  None: number;
}

export interface AssessmentSummary {
  id: string;
  created: string;
  target: { name: string; url: string };
  status: string;
  finding_count: number;
  severity: SeverityCounts;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  confidence: string;
  cvss_vector: string;
  cvss_score: number;
  severity: string;
  actor_role: string | null;
  endpoint: string | null;
  business_impact: string;
  remediation: string;
  evidence: any[];
  retest: any | null;
}

export interface GraphNode {
  id: string;
  kind?: string;
  username?: string;
  role?: string;
  rtype?: string;
  owner?: string | null;
}

export interface GraphLink {
  source: string;
  target: string;
  rel?: string;
  [k: string]: any;
}

export interface GraphData {
  nodes: GraphNode[];
  edges?: GraphLink[];
  links?: GraphLink[];
}

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"] as const;

export const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#e5484d",
  High: "#ff8a3d",
  Medium: "#e5b84b",
  Low: "#4a9eed",
  None: "#5b6773",
};

export const REL_COLOR: Record<string, string> = {
  owns: "#3fb9b0",
  requested: "#e5b84b",
  has_role: "#5b6773",
};
