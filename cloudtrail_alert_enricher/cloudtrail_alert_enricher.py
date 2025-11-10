from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from utils.cloudtrail import flag_record, load_cloudtrail_records, summarize


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enrich CloudTrail events and flag suspicious activity."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to CloudTrail JSON/NDJSON file or directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("cloudtrail_alerts.csv"),
        help="CSV output path (default: cloudtrail_alerts.csv).",
    )
    parser.add_argument(
        "--allowed-regions",
        nargs="+",
        default=["us-east-1", "us-west-2"],
        help="List of expected AWS regions.",
    )
    parser.add_argument(
        "--privileged-principals",
        nargs="+",
        default=["arn:aws:iam::123456789012:role/Admin"],
        help="List of ARNs or usernames considered privileged.",
    )
    parser.add_argument(
        "--include-unflagged",
        action="store_true",
        help="Include events that do not trigger any flags.",
    )
    return parser.parse_args()


def write_csv(output_path: Path, records: Iterable[dict]) -> None:
    fieldnames = [
        "eventTime",
        "eventName",
        "user",
        "userType",
        "sourceIP",
        "region",
        "flags",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(record)


def main() -> None:
    args = parse_args()
    raw_records = load_cloudtrail_records(args.input)
    enriched: List[dict] = [
        flag_record(
            record,
            allowed_regions=set(args.allowed_regions),
            privileged_principals=set(args.privileged_principals),
        )
        for record in raw_records
    ]

    if not args.include_unflagged:
        enriched = [entry for entry in enriched if entry["flags"] != "none"]

    write_csv(args.output, enriched)
    summary = summarize(enriched)

    print(f"Wrote {len(enriched)} records to {args.output}")
    if summary:
        print("Flag counts:")
        for flag, count in sorted(summary.items(), key=lambda item: item[0]):
            print(f"  {flag}: {count}")
    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    main()

