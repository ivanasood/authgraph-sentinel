# Demo walkthrough

A five-minute tour of a full assessment.

## Start the stack

```bash
docker compose up --build
```

Wait for all three services to report ready, then open the dashboard:

- Dashboard: http://localhost:5173
- API docs: http://localhost:8001/docs
- Lab (target): http://localhost:8000/docs

## Run an assessment

On the dashboard, click **Run assessment**. The engine discovers the lab, builds
the authorization graph, reproduces each issue, scores it, and returns results in
a few seconds.

You should see **8 findings: 3 Critical, 5 Medium**.

## Findings tab

The list is ordered by CVSS. Click any finding to see its detail panel.

| CVSS | Finding |
| --- | --- |
| 10.0 | Forged token impersonates another user without credentials |
| 9.9 | Viewer escalates to admin via mass assignment |
| 9.9 | Viewer changes another user's role |
| 6.5 | Viewer deletes another user's report |
| 6.5 | Viewer reads another user's report |
| 6.5 | Analyst reads another user's record (leaks secrets) |
| 6.5 | Non-admin reaches the admin listing |
| 6.5 | API responses expose secret fields |

Open the top finding. The **Evidence (redacted)** block shows the proof: logged in
as `carol`, a forged token for user id 1 was accepted and returned `alice`. That is
a reproduction, not an inference - note the `verified` badge.

Use the category chips (BOLA, PRIV_ESC, ...) to filter.

## Authorization graph tab

Three columns - **Principals, Roles, Resources** - with edges coloured by relation:

- teal solid = **owns**
- amber dashed = **requested**
- grey = **has role**

Follow `carol - viewer`: dashed "requested" edges reach `report:2`, `user:1`, and
`admin:/api/admin/users` - resources she does not own and should not reach. The
picture *is* the set of violations the engine proved.

## Report tab

The full assessment report: severity summary, then each finding with its CVSS
vector, confidence, business impact, remediation, and redacted evidence. The same
content is available from the API as Markdown or JSON:

```
GET http://localhost:8001/api/assessments/{id}/report.md
GET http://localhost:8001/api/assessments/{id}/report.json
```

## Re-test after a fix

Each verified finding has a re-test scenario:

```
GET http://localhost:8001/api/assessments/{id}/retests
```

Fix an issue in the lab, re-run the assessment, and the corresponding finding
should drop to `not_reproduced`.
