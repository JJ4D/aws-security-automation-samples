## GuardDuty Triage CLI

Summarize GuardDuty findings from a local file or live AWS account to speed up incident triage.

### Run with sample data

```shell
python guardduty_triage_cli.py
```

### Run against AWS

```shell
python guardduty_triage_cli.py --fetch-live --region us-east-1 --output findings.csv
```

AWS credentials must be configured (e.g., via `aws configure`) and the GuardDuty detector enabled.

