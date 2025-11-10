# CloudTrail Alert Enricher

This script parses CloudTrail events, tags risky activity, and exports a triage-friendly CSV.

## Usage

```shell
python cloudtrail_alert_enricher.py --input data/sample_cloudtrail.json --output alerts.csv
```

Optional flags:
- `--allowed-regions us-east-1 us-west-2`
- `--privileged-principals arn:aws:iam::123456789012:role/Admin`
- `--include-unflagged`

