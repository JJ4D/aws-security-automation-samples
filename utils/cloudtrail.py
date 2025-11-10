from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


SUSPICIOUS_ACTION_PREFIXES: Sequence[str] = (
    "iam:Create",
    "iam:Delete",
    "iam:Attach",
    "iam:Put",
    "iam:Update",
    "sts:AssumeRole",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:ModifyInstanceAttribute",
    "secretsmanager:PutSecretValue",
    "kms:DisableKey",
)


def load_cloudtrail_records(source: Path) -> List[Dict]:
    """
    Load CloudTrail events from a file or directory.

    Accepts:
    - Single JSON file containing an array of records
    - NDJSON file (one JSON object per line)
    - Directory of JSON/NDJSON files
    """
    if source.is_dir():
        records: List[Dict] = []
        for path in sorted(source.glob("*.json")):
            records.extend(load_cloudtrail_records(path))
        for path in sorted(source.glob("*.ndjson")):
            records.extend(load_cloudtrail_records(path))
        return records

    with source.open("r", encoding="utf-8") as handle:
        first_char = handle.read(1)
        handle.seek(0)
        if first_char == "[":
            return json.load(handle)
        return [json.loads(line) for line in handle if line.strip()]


def is_suspicious_action(event_name: str) -> bool:
    event_name_lower = event_name.lower()
    for prefix in SUSPICIOUS_ACTION_PREFIXES:
        if event_name_lower.startswith(prefix.lower()):
            return True
    return False


def flag_record(
    record: Dict,
    allowed_regions: Iterable[str],
    privileged_principals: Iterable[str],
) -> Dict:
    """
    Return a summary dict with flags for the record.
    """
    event_name = record.get("eventName", "unknown")
    user_identity = record.get("userIdentity", {}) or {}
    principal = user_identity.get("arn") or user_identity.get("userName") or "unknown"
    source_ip = record.get("sourceIPAddress", "unknown")
    region = record.get("awsRegion", "unknown")

    flags: List[str] = []
    if is_suspicious_action(event_name):
        flags.append("suspicious-action")
    if principal in privileged_principals:
        flags.append("privileged-principal")
    if region not in allowed_regions:
        flags.append("region-anomaly")
    if user_identity.get("type") == "Root":
        flags.append("root-usage")

    return {
        "eventTime": record.get("eventTime"),
        "eventName": event_name,
        "user": principal,
        "userType": user_identity.get("type", "unknown"),
        "sourceIP": source_ip,
        "region": region,
        "flags": ";".join(flags) if flags else "none",
    }


def summarize(records: Sequence[Dict]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for record in records:
        for flag in record.get("flags", "").split(";"):
            if not flag or flag == "none":
                continue
            summary[flag] = summary.get(flag, 0) + 1
    return summary

