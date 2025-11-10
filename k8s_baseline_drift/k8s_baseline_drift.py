from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    yaml = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare Kubernetes state against a security baseline."
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("k8s_baseline_drift/baseline_policy.yaml"),
        help="Baseline policy file (YAML or JSON).",
    )
    parser.add_argument(
        "--current",
        type=Path,
        default=Path("k8s_baseline_drift/current_state.yaml"),
        help="Current cluster snapshot (YAML/JSON).",
    )
    parser.add_argument(
        "--kubectl-cmd",
        help="Optional kubectl command to capture live state, e.g. \"kubectl get pods -A -o yaml\".",
    )
    return parser.parse_args()


def load_serialized(path: Path) -> Dict:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required for YAML files. Install with `pip install pyyaml`."
            ) from None
        return yaml.safe_load(text)


def load_current_state(path: Path) -> Dict:
    data = load_serialized(path)
    if "items" not in data:
        raise ValueError("Expected a list of resources under 'items'.")
    return data


def run_kubectl(cmd: str) -> Dict:
    completed = subprocess.run(
        cmd,
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    output = completed.stdout
    temp_path = Path(".live_k8s_snapshot.tmp")
    temp_path.write_text(output, encoding="utf-8")
    try:
        return load_serialized(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


def find_privileged_pods(baseline: Dict, current: Dict) -> List[str]:
    if not baseline.get("spec", {}).get("blockPrivilegedPods", True):
        return []
    violations: List[str] = []
    for item in current["items"]:
        if item.get("kind") != "Pod":
            continue
        metadata = item.get("metadata", {})
        spec = item.get("spec", {})
        for container in spec.get("containers", []):
            sc = container.get("securityContext", {})
            if sc.get("privileged"):
                violations.append(
                    f"{metadata.get('namespace','default')}/{metadata.get('name')} container {container.get('name')}"
                )
    return violations


def find_root_containers(baseline: Dict, current: Dict) -> List[str]:
    if not baseline.get("spec", {}).get("enforceRunAsNonRoot", True):
        return []
    findings: List[str] = []
    for item in current["items"]:
        if item.get("kind") != "Pod":
            continue
        metadata = item.get("metadata", {})
        spec = item.get("spec", {})
        for container in spec.get("containers", []):
            sc = container.get("securityContext", {})
            run_as_non_root = sc.get("runAsNonRoot")
            if run_as_non_root is False or (run_as_non_root is None and sc.get("runAsUser") in (0, None)):
                findings.append(
                    f"{metadata.get('namespace','default')}/{metadata.get('name')} container {container.get('name')}"
                )
    return findings


def find_missing_network_policies(baseline: Dict, current: Dict) -> List[str]:
    required_namespaces = baseline.get("spec", {}).get("namespacesRequiringNetworkPolicy", [])
    if not required_namespaces:
        return []
    namespace_policies = {ns: False for ns in required_namespaces}
    for item in current["items"]:
        if item.get("kind") != "NetworkPolicy":
            continue
        metadata = item.get("metadata", {})
        ns = metadata.get("namespace")
        if ns in namespace_policies:
            namespace_policies[ns] = True
    return [ns for ns, present in namespace_policies.items() if not present]


def report(baseline: Dict, current: Dict) -> int:
    violations = {
        "privilegedPods": find_privileged_pods(baseline, current),
        "runAsRoot": find_root_containers(baseline, current),
        "missingNetworkPolicies": find_missing_network_policies(baseline, current),
    }
    exit_code = 0
    for key, items in violations.items():
        if not items:
            continue
        exit_code = 1
        print(f"[ALERT] {key} ({len(items)})")
        for item in items:
            print(f"  - {item}")
        print()
    if exit_code == 0:
        print("Cluster matches baseline requirements.")
    return exit_code


def main() -> None:
    args = parse_args()
    baseline = load_serialized(args.baseline)
    if args.kubectl_cmd:
        current = run_kubectl(args.kubectl_cmd)
    else:
        current = load_current_state(args.current)
    exit_code = report(baseline, current)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

