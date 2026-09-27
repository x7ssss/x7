# 🚀 x7 (v1.0.0)

Unified zero-dependency infrastructure triage and safe remediation engine.

`x7` combines 12 diagnostic engines across Kubernetes, databases, and infrastructure state into a single static binary.

---

## ⚡ Core Features

- 📦 **Pure Static Compilation**: Compiled with `CGO_ENABLED=0` and `-ldflags="-s -w"`.
- 🚀 **Ultra-Compact**: Binary footprint is under 10MB (strictly below the 12MB invariant).
- 🛡️ **Zero External Heavy SDKs**: No AWS, Azure, or GCP SDK dependencies. All cloud and database integrations use standard library wire protocols and signed HTTP requests.
- ⚡ **Concurrency & Isolation**: Built-in `errgroup` worker pool with a maximum concurrency limit of 6 and hard 10-second per-check timeouts. Sibling checks never cancel on isolated engine failures.
- 🔒 **Safe Two-Phase Remediation**: Every remediation executes a safe dry-run preview before live application. Interactive and CI/CD force modes supported.

---

## 🔍 Engine Coverage

### 1. ☸️ Kubernetes (`k8s`)
- ☸️ `k8s-unstuck`: Detects namespaces stuck in `Terminating` and flags failing APIServices poisoning discovery.
- 📦 `k8s-helm`: Scans Secrets for Helm releases deadlocked in `pending-install`, `pending-upgrade`, or `pending-rollback`. Remediate function patches state to `failed`.
- 🧹 `k8s-crds`: Audits CustomResourceDefinitions stuck in deletion with orphaned custom resources lingering in etcd.
- 🩺 `k8s-dns`: Inspects `/proc/net/stat/nf_conntrack` for `insert_failed` UDP DNS race condition drops.
- ⚡ `k8s-gitops`: Server-side admission drift evaluator catching mutating webhook reconciliation loops.

### 2. 🐘 Databases & Storage (`db`)
- 🐘 `db-pgwal`: Audits PostgreSQL `pg_wal` disk capacity and catches lagging replication slots.
- 🔍 `db-pgxid`: Audits `datfrozenxid` age against the 2-billion transaction wraparound cliff.
- ⚡ `db-clickhouse`: Audits active MergeTree parts per partition against 150 delay and 300 throw thresholds.

### 3. 🔧 Infrastructure, State & Messaging (`infra`)
- 🛡️ `infra-vpcdrain`: Detects unattached, available ENIs locking VPC subnet IPv4 addresses.
- 🔓 `infra-tflock`: Inspects Terraform state locks (`.tflock`, `.terraform.tfstate.lock.info`) across backends.
- 📨 `infra-kafka`: Wire-level group coordinator inspector detecting `PreparingRebalance` storms and zombie members.
- 🩺 `infra-cgroup`: Linux cgroup v2 PSI memory watchdog detecting direct reclaim stalls.

---

## 🔧 CLI Usage

### 🩺 Triage: `x7 doctor`
Run concurrent triage across all subsystems:
```bash
./dist/x7 doctor
```

Target a specific subsystem (`k8s`, `db`, or `infra`):
```bash
./dist/x7 doctor --subsystem k8s
```

JSON output format:
```bash
./dist/x7 doctor -o json
```

### ⚡ Remediation: `x7 heal`
Preview remediations in safe dry-run mode:
```bash
./dist/x7 heal
```

Interactive live remediation:
```bash
./dist/x7 heal --dry-run=false --interactive
```

Automated non-interactive live remediation (CI/CD):
```bash
./dist/x7 heal --dry-run=false --force
```

### 📋 Version: `x7 version`
Inspect binary build details, commit, and platform:
```bash
./dist/x7 version
```

---

## 📦 Compilation

Build all targets using PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File dist/build.ps1
```

Or using Make:
```bash
make -f dist/Makefile build-all
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 x7ssss
