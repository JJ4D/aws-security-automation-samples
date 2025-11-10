## Kubernetes Baseline Drift Checker

Compares current Kubernetes resources against a lightweight security baseline.

### Check sample snapshot

```shell
python k8s_baseline_drift.py
```

### Check live cluster

```shell
python k8s_baseline_drift.py --kubectl-cmd "kubectl get pods -A -o yaml"
```

Install `pyyaml` if your manifests are YAML formatted:

```shell
pip install pyyaml
```

