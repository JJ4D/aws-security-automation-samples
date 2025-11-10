# Security Automation Samples

Lightweight scripts that highlight practical DevSecOps automation for an AWS-focused environment. Each folder includes a runnable script, sample data, and usage notes.

## Projects
- `cloudtrail_alert_enricher` – flag risky IAM and network actions, enrich with context, export CSV summaries.
- `guardduty_triage_cli` – triage GuardDuty findings locally or directly from AWS with optional enrichment.
- `k8s_baseline_drift` – compare Kubernetes state against a security baseline and surface drift.

Utilities shared across scripts live in `utils/`.

