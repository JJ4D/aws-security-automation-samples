from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize GuardDuty findings for quicker triage."
    )
    parser.add_argument(
        "--findings-file",
        type=Path,
        default=Path("guardduty_triage_cli/sample_findings.json"),
        help="Local JSON/NDJSON file with GuardDuty findings.",
    )
    parser.add_argument(
        "--fetch-live",
        action="store_true",
        help="Fetch findings from GuardDuty using boto3 (requires AWS credentials).",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to query when --fetch-live is set.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=20,
        help="Maximum findings to fetch from GuardDuty.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional CSV output path.",
    )
    return parser.parse_args()


def load_local_findings(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        first_char = handle.read(1)
        handle.seek(0)
        if first_char == "[":
            return json.load(handle)
        return [json.loads(line) for line in handle if line.strip()]


def fetch_guardduty_findings(region: str, max_findings: int) -> List[Dict]:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ModuleNotFoundError:
        print("boto3 is not available. Install boto3 or disable --fetch-live.", file=sys.stderr)
        return []

    client = boto3.client("guardduty", region_name=region)
    try:
        detectors = client.list_detectors().get("DetectorIds", [])
        if not detectors:
            return []
        detector_id = detectors[0]
        finding_ids = client.list_findings(
            DetectorId=detector_id,
            MaxResults=max_findings,
        ).get("FindingIds", [])
        if not finding_ids:
            return []
        response = client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids,
        )
        return response.get("Findings", [])
    except (BotoCoreError, ClientError) as exc:
        print(f"Unable to fetch findings: {exc}", file=sys.stderr)
        return []


def severity_label(score: float) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def enrich_finding(finding: Dict) -> Dict:
    detail = finding.get("Service", {})
    resource = finding.get("Resource", {})
    severity = float(finding.get("Severity", 0))
    label = severity_label(severity)
    return {
        "id": finding.get("Id"),
        "title": finding.get("Title", "Untitled"),
        "severity": label,
        "severityScore": severity,
        "resourceType": resource.get("ResourceType", "Unknown"),
        "affectedResource": resource.get("InstanceDetails", {}).get("InstanceId")
        or resource.get("AccessKeyDetails", {}).get("AccessKeyId")
        or resource.get("KubernetesDetails", {}).get("KubernetesUserDetails", {}).get("Username")
        or "N/A",
        "eventFirstSeen": detail.get("EventFirstSeen"),
        "eventLastSeen": detail.get("EventLastSeen"),
    }


def summarize_by_severity(findings: Iterable[Dict]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for finding in findings:
        key = finding["severity"]
        summary[key] = summary.get(key, 0) + 1
    return summary


def write_csv(path: Path, findings: Iterable[Dict]) -> None:
    fieldnames = [
        "id",
        "title",
        "severity",
        "severityScore",
        "resourceType",
        "affectedResource",
        "eventFirstSeen",
        "eventLastSeen",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)


def display(findings: Iterable[Dict]) -> None:
    for finding in findings:
        print(f"[{finding['severity'].upper():>5}] {finding['title']}")
        print(f"     resource: {finding['resourceType']} -> {finding['affectedResource']}")
        print(f"     seen: {finding['eventFirstSeen']} to {finding['eventLastSeen']}")
        print(f"     id: {finding['id']}")
        print()


def main() -> None:
    args = parse_args()
    findings: List[Dict] = []
    if args.fetch_live:
        findings = fetch_guardduty_findings(args.region, args.max_findings)
    if not findings:
        findings = load_local_findings(args.findings_file)

    enriched = [enrich_finding(finding) for finding in findings]
    if args.output and enriched:
        write_csv(args.output, enriched)

    if enriched:
        summary = summarize_by_severity(enriched)
        print("Severity counts:", summary)
        print()
        display(enriched)
        if args.output:
            print(f"Wrote {len(enriched)} findings to {args.output}")
    else:
        print("No findings available. Provide --findings-file or enable --fetch-live.")


if __name__ == "__main__":
    main()

