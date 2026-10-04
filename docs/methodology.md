# Methodology

AuthGraph Sentinel is **evidence-first**: a potential issue is not called a
finding until it has been reproduced deterministically against the lab.

## Confidence states

Every candidate issue moves through explicit states:

| State | Meaning |
| --- | --- |
| **suspected** | The authorization graph judged an observed access as not permitted, or the auth analyzer saw a structural weakness. Not yet proven. |
| **verified** | A detector performed the access and the response confirmed the leak or mutation. |
| **not_reproduced** | A detector tried and the behaviour did not occur. A real, expected outcome - it reports honestly rather than inflating. |

AI-driven analysis and graph inference produce *suspected* items. Only a
reproduced test promotes an item to *verified*. The tool never presents an
unproven inference as a confirmed finding.

## The authorization graph

The graph fuses three evidence streams:

- **identities and roles** - who is acting;
- **ownership** - who owns each resource (learned from the correctly-scoped list
  endpoint, not by reading the database);
- **observed access** - who reached what (from authenticated probing).

A request is a violation when the acting role is not permitted the access *class*
of the resource it reached (for example, a viewer reading a report owned by
another user = `other_report`, which viewers may not access). This turns a flat
access map into judged, explainable results.

### The policy is an assumption

Real targets rarely ship a machine-readable access policy, so the baseline policy
(viewer/analyst = own resources only; admin = everything) is **derived** and
**editable** in `backend/app/engine/authorization.py`. It is a hypothesis to be
adjusted to the real application's intended model, not ground truth.

## Deterministic verification

Detectors reproduce each suspected violation:

- **Non-destructive** tests (cross-user reads, reaching an admin listing) simply
  perform the request and check the response.
- **Destructive** tests (deleting another user's resource, privilege escalation)
  are bracketed by `POST /api/_lab/reset`: reset to known state, perform the test,
  confirm the effect, then reset again. This is only safe because the target is a
  dedicated lab with masked data and a reset hook - the same actions must never be
  run against production.

## Redaction

Evidence is redacted at capture. Secret values (password hashes, API keys, tokens)
are masked before they are stored or displayed; a finding records that a secret
*leaked* without copying its value.

## Scoring

Findings are scored with the CVSS v3.1 base metric equations
(`backend/app/risk/cvss.py`), validated against published reference vectors. Scores
are reported as calculated rather than inflated; the business-impact text carries
the contextual severity. Privilege escalation and token forgery cross a security
boundary and are scored `Scope: Changed`, which is visible in each finding's vector
string.

## Re-test scenarios

Each verified finding serialises to a replayable scenario (acting role, steps,
expected result, and cleanup for destructive cases). These support regression
re-testing after a fix.

## Known limitations

- **Policy is derived**, not supplied - tune it to the real intended model.
- **Discovery is read-only** and samples object IDs; detectors sweep real owned IDs
  but the mutation tests are written against the known endpoints.
- **The assessment store is in-memory** - results are lost when the API restarts.
- **Assessments run synchronously** inside the request.
- **Two findings are derived** (forgeable session, excessive exposure) from other
  reproductions rather than a dedicated test, though both trace to verified results.

These are deliberate MVP boundaries, each a self-contained hardening step.
