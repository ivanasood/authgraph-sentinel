import { SEVERITY_COLOR } from "../types";
import type { Finding } from "../types";

export default function FindingDetail({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return (
      <div className="detail detail-empty">
        <p>Select a finding to see its evidence and remediation.</p>
      </div>
    );
  }

  const color = SEVERITY_COLOR[finding.severity];

  return (
    <div className="detail">
      <h2 className="detail-title">{finding.title}</h2>

      <div className="badges">
        <span className="badge" style={{ borderColor: color, color }}>
          {finding.severity} · {finding.cvss_score.toFixed(1)}
        </span>
        <span className="badge badge-muted">{finding.category}</span>
        <span className={`badge ${finding.confidence === "verified" ? "badge-ok" : "badge-muted"}`}>
          {finding.confidence}
        </span>
        <span className="badge badge-muted">
          re-test: {finding.retest ? "available" : "n/a"}
        </span>
      </div>

      <dl className="facts">
        <dt>Vector</dt>
        <dd className="mono">{finding.cvss_vector}</dd>
        {finding.endpoint && (
          <>
            <dt>Endpoint</dt>
            <dd className="mono">{finding.endpoint}</dd>
          </>
        )}
        {finding.actor_role && (
          <>
            <dt>Actor role</dt>
            <dd>{finding.actor_role}</dd>
          </>
        )}
      </dl>

      <section className="block">
        <h3>Business impact</h3>
        <p>{finding.business_impact}</p>
      </section>

      <section className="block">
        <h3>Remediation</h3>
        <p>{finding.remediation}</p>
      </section>

      <section className="block">
        <h3>Evidence (redacted)</h3>
        <pre className="code">{JSON.stringify(finding.evidence, null, 2)}</pre>
      </section>
    </div>
  );
}
