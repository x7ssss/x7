# ⚡ x7 — Unified Infrastructure Remediation Engine

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Architecture](https://img.shields.io/badge/Architecture-Zero--Dependency%20Static%20Binary-blueviolet)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20darwin%20%7C%20windows-lightgrey)]()

**x7** is the definitive, zero-dependency infrastructure triage and safe remediation CLI for Site Reliability Engineers (SREs), Platform Teams, and DevOps engineers. 

It unifies four specialized remediation engines into a single standalone binary:
1. **Terraform / OpenTofu State Locks (`x7 tf`)** — Ingested from [`tf-unlock`](https://github.com/x7ssss/tf-unlock)
2. **Helm v3 Stuck Releases (`x7 helm`)** — Ingested from [`helm-unwedge`](https://github.com/x7ssss/helm-unwedge)
3. **Kubernetes Terminating Namespaces & CRDs (`x7 k8s`)** — Ingested from [`k8s-unstuck`](https://github.com/x7ssss/k8s-unstuck)
4. **AWS Ephemeral VPC & ENI Drainage (`x7 aws`)** — Ingested from [`vpcdrain`](https://github.com/x7ssss/vpcdrain)
5. **Fleet Diagnostic Triage & Self-Healing (`x7 doctor` & `x7 heal`)** — 12 concurrent diagnostic engines across databases, Kubernetes, and cloud networking.

---

## 🏗️ Architecture & Philosophy

- **Zero Heavy SDK Dependencies**: No sprawling AWS, Azure, or GCP SDK dependencies. All cloud and database integrations use standard library wire protocols, SigV4 signed requests, and atomic REST primitives.
- **Fail-Closed Safety Invariant**: State is never altered if any safety gate, staleness threshold, or liveness check fails.
- **Dry-Run by Default**: Destructive operations default to dry-run previews (`--dry-run`), requiring explicit `--force` or interactive confirmation before committing live cluster or cloud changes.
- **Deterministic Mutual Exclusion**: Prevents split-brain races across concurrent CI/CD pipelines using distributed locks (`coordination.k8s.io/v1` Leases and DynamoDB mutexes).
- **Dual Output Channels**: Monospace terminal tables with status badges for human operators, and clean `--json` output for automated CI/CD pipelines.

---

## 💻 Subcommands & Terminal Examples

```text
Usage:
  x7 [command]

Available Commands:
  tf          Inspect and unlock remote Terraform and OpenTofu state locks
  helm        Inspect and recover deadlocked Helm v3 releases
  k8s         Diagnose and unstick terminating Kubernetes namespaces and CRDs
  aws         Remediation and drainage engines for AWS cloud infrastructure
  doctor      Run concurrent triage inspection across infrastructure subsystems
  heal        Interactive or automated safe two-phase remediation
  version     Display version, git commit, and runtime build info
```

---

### 1. 🔓 Terraform & OpenTofu State Locks (`x7 tf`)

Inspects remote backend state locks across AWS S3/DynamoDB, S3 Native Object locks, Azure Blob Storage, and PostgreSQL backends. Evaluates lock staleness thresholds and verifies GitHub Actions runner termination before breaking locks.

#### Inspect Lock Status (Safe & Non-Mutating)
```bash
x7 tf inspect --state .terraform/terraform.tfstate
```

```text
+------------------------------------------------------------------------------+
|  TF-UNLOCK :: REMOTE STATE LOCK INSPECTOR
+------------------------------------------------------------------------------+
|  STATUS      : [LOCKED - STALE]
|  LOCK ID     : a8f411cd-8931-4be5-94cf-1e8557a6e14a
|  BACKEND     : s3-dynamodb
|  TARGET      : s3://prod-infra-state-bucket/vpc/terraform.tfstate
|  WHO         : runner@gh-runner-p7f9z
|  CREATED     : 2026-10-05T08:14:22Z (1h 12m 30s ago)
|  STALENESS   : STALE (age 1h 12m 30s exceeds 30m threshold)
|  INFO        : terraform apply -auto-approve
+------------------------------------------------------------------------------+
```

#### Break Stale Lock with Runner Liveness Verification
```bash
x7 tf unlock --stale-after 30m \
  --github-repo my-org/infrastructure \
  --github-run-id 1839201948 \
  --yes
```

#### CI/CD Pipeline Automation (Pure JSON)
```bash
x7 tf inspect --state .terraform/terraform.tfstate --json
```

```json
{
  "status": "LOCKED_STALE",
  "backendType": "s3-dynamodb",
  "target": "s3://prod-infra-state-bucket/vpc/terraform.tfstate",
  "isStale": true,
  "ageSeconds": 4350,
  "staleAfter": "30m0s",
  "dryRun": false,
  "lock": {
    "ID": "a8f411cd-8931-4be5-94cf-1e8557a6e14a",
    "Operation": "OperationTypeApply",
    "Info": "terraform apply -auto-approve",
    "Who": "runner@gh-runner-p7f9z",
    "Version": "1.10.0",
    "Created": "2026-10-05T08:14:22Z"
  }
}
```

---

### 2. 📦 Helm v3 Stuck Releases (`x7 helm`)

Diagnoses and unlocks Helm v3 releases stranded in `pending-install`, `pending-upgrade`, or `pending-rollback`. Executes atomic dual-mutations patching both Kubernetes Secret labels and internal release JSON payloads, while guarding operations with `coordination.k8s.io` distributed lease locks.

#### Diagnostic Audit of a Deadlocked Release
```bash
x7 helm inspect ingress-controller -n networking
```

```text
+------------------------------------------------------------------------------+
| HELM RELEASE AUDIT: INGRESS-CONTROLLER (V4)                                  |
+------------------------------------------------------------------------------+
| Release Name        : ingress-controller
| Namespace           : networking
| Latest Revision     : v4
| Secret Name         : sh.helm.release.v1.ingress-controller.v4
| Secret Label Status : pending-upgrade
| Payload Status      : pending-upgrade
| State Alignment     : Synchronized
| Last Modified       : 45m 12s ago (2026-10-05T08:35:10Z)
| Stale Threshold     : 10m0s
| Distributed Lock    : None (Unlocked)
| Verdict             : DEADLOCKED (Pending operation abandoned)
| Recommended Action  : Run: x7 helm recover ingress-controller -n networking
+------------------------------------------------------------------------------+
```

#### Surgically Recover Deadlocked Release (Atomic Dual-Mutation)
```bash
x7 helm recover ingress-controller -n networking --strategy=mark-failed
```

```text
Acquiring distributed lease lock 'helm-lock-ingress-controller'...
Distributed lease lock acquired successfully.

+------------------------------------------------------------------------------+
| RELEASE SUCCESSFULLY RECOVERED                                               |
+------------------------------------------------------------------------------+
| Action              : ATOMIC DUAL-MUTATION UNLOCK
| Release             : ingress-controller
| Namespace           : networking
| Revision            : v4
| Secret Patched      : sh.helm.release.v1.ingress-controller.v4
| Previous Status     : pending-upgrade
| New Status          : failed
| Labels Modified     : status=failed, modifiedAt=now
| Payload Modified    : .info.status=failed, .info.description=Release unlocked by x7
| Next Step           : Run 'helm upgrade --install ingress-controller <chart>'
+------------------------------------------------------------------------------+
```

---

### 3. ☸️ Kubernetes Terminating Namespaces & CRDs (`x7 k8s`)

Safely resolves namespaces stuck in the `Terminating` state through a deterministic 5-phase DAG:
1. **Acquire Distributed Lease Lock** (`coordination.k8s.io/v1` in `kube-system`)
2. **Fence GitOps Reconcilers & Disarm VAP** (suspends ArgoCD/Flux sync and disarms blocking `ValidatingAdmissionPolicy` bindings)
3. **APIService Triage** (detects and removes dead extension aggregated APIServices poisoning discovery)
4. **Admission Webhook Neutralization** (temporarily sets failing webhooks to `failurePolicy=Ignore`)
5. **Storage Detach & Surgical Finalizer Stripping** (applies out-of-service node taints to unwedge PVCs and drops blocking child finalizers)

#### Non-Invasive Diagnostic Inspection
```bash
x7 k8s diagnose staging-ephemeral
```

```text
================================================================================
                   x7 k8s: Namespace Deadlock Resolver                          
================================================================================
  Command          : DIAGNOSE
  Target Namespace : staging-ephemeral
  Mode             : NON-INVASIVE DIAGNOSTIC
  Namespace Status : Terminating (Deletion in progress)
--------------------------------------------------------------------------------

[Phase 2] GitOps Controller Fencing & VAP Disarmer:
   [FENCE] ArgoCD reconciler found: argocd/staging-apps (via argocd.argoproj.io/managed-by)
   [PASS] No blocking ValidatingAdmissionPolicyBindings detected.

[Phase 3] Extension APIService Triage:
   [FAIL] Dead APIService: v1beta1.custom.metrics.k8s.io (Group: custom.metrics.k8s.io/v1beta1, Reason: EndpointUnavailable)

[Phase 4] Admission Webhook Neutralization:
   [WARN] Webhook validate.security.corp in ValidatingWebhookConfiguration corp-gatekeeper has failurePolicy=Fail

[Phase 5] CSI Storage Node Taints & Child Finalizer Stripping:
   [PASS] No dead nodes hosting stuck PVC pods detected.

   --- Diagnostic Tree (3 objects across 2 GVRs) ---
   RESOURCE               NAME          CATEGORY         ACTION           DETAILS
   --------               ----          --------         ------           -------
   customresourcedefs     db.corp.io    OrphanedCRD      StripFinalizer   Finalizers: [corp.io/cleanup] | Dead operator
   persistentvolumeclaims redis-data    StorageDetach    Skip             Waiting on CSI node unmount
```

#### Execute Live 5-Phase Namespace Unsticking
```bash
x7 k8s unstick staging-ephemeral --force
```

---

### 4. 🌐 AWS Ephemeral VPC & ENI Teardown (`x7 aws vpc-drain`)

Performs non-blocking discovery and deterministic dependency-ordered sweeping of orphaned ephemeral VPCs created during CI/CD test runs, pull request previews, or staging environments.

Sweeps resources across 8 strict tiers to eliminate dependency deadlocks:
- **Tier 1**: NAT Gateways & Elastic IPs
- **Tier 2**: Application & Network Load Balancers (ALB / NLB)
- **Tier 3**: ECS Tasks & Services, Lambda VPC Attachments
- **Tier 4**: Attached & Orphaned Elastic Network Interfaces (ENIs)
- **Tier 5**: Security Group Cross-Reference Dependency Cycles
- **Tier 6**: VPC Endpoints (Gateway & Interface)
- **Tier 7**: Subnets & Route Tables
- **Tier 8**: Internet Gateways & VPC Deletion

#### Dry-Run Inspection & DAG Preview
```bash
x7 aws vpc-drain --vpc-id vpc-0abc1234def56789a --tag PR=1442
```

```text
[12:30:15] INFO  Running safety guardrails verification...
[12:30:16] PASS  Safety guardrails passed: Account 123456789012 (Caller: arn:aws:iam::123456789012:role/CI-Runner)
[12:30:17] INFO  Discovering all resources in VPC vpc-0abc1234def56789a...

================================================================================
                 AWS VPC DRAINAGE MANIFEST: vpc-0abc1234def56789a
================================================================================
  [Tier 1] NAT Gateways        : 2 items   (nat-01a2b3c4, nat-05d6e7f8)
  [Tier 2] Load Balancers      : 1 items   (app/pr-1442-alb/918273918)
  [Tier 3] ECS Tasks           : 4 items   (task/pr-1442-backend-*)
  [Tier 4] Elastic Network IPs : 8 items   (eni-0123..., eni-4567...)
  [Tier 5] Security Groups     : 3 items   (sg-01a2b3c4 [cyclic dependency resolved])
  [Tier 6] Subnets             : 4 items   (subnet-01, subnet-02, subnet-03, subnet-04)
--------------------------------------------------------------------------------
Mode: DRY-RUN PREVIEW (no AWS resources were modified)
```

#### Execute Live Teardown with Distributed DynamoDB Mutex
```bash
x7 aws vpc-drain --vpc-id vpc-0abc1234def56789a --tag PR=1442 \
  --account-id 123456789012 \
  --lock-table vpcdrain-locks \
  --emit-summary \
  --dry-run=false
```

```text
[12:31:02] PASS  FinOps Impact: Prevented $248.50/month in cloud waste ($2,982.00 annualized)
[12:31:02] PASS  FinOps step summary appended to $GITHUB_STEP_SUMMARY
```

---

### 5. 🩺 Fleet Health Triage & Remediation (`x7 doctor` & `x7 heal`)

Runs concurrent background diagnostic triage across 12 infrastructure subsystems.

```bash
# Concurrent diagnostic triage across all subsystems
x7 doctor

# Triage specific subsystem (k8s, db, infra)
x7 doctor --subsystem k8s

# Automated safe two-phase remediation
x7 heal --dry-run
x7 heal --interactive
x7 heal --force
```

---

## 🛡️ The Safety Model

Every operation in `x7` is governed by hard safety invariants:

| Safety Gate | Behavior | Override Flag |
| :--- | :--- | :--- |
| **Staleness Gate** | Locks and operations younger than staleness threshold are refused | `--force` |
| **Runner Liveness** | Refuses to break locks while GitHub Actions workflow is still `queued` or `in_progress` | `--force` |
| **Protected Namespaces** | Blocks deletion/purging on `kube-system`, `kube-public`, `kube-node-lease`, and `default` | `--force` |
| **Cross-Account Blast Radius** | Fails immediately if AWS caller account does not match expected `--account-id` | N/A (Strict) |
| **Tag Scoping** | AWS resources lacking the designated `--tag Key=Value` are skipped | N/A (Strict) |
| **Mutual Exclusion** | Acquires cluster/cloud distributed lease prior to mutations | N/A (Automatic) |

---

## 🏢 Editions & Tier Comparison

`x7` is distributed as both a free, open-source standalone CLI and a high-throughput enterprise platform:

| Capability | Free Local CLI (Open Source) | Team & Enterprise Platform |
| :--- | :---: | :---: |
| **License** | **MIT / Apache-2.0** | Commercial Subscription |
| **Deployment** | Standalone static binary | Daemon, Sidecar, & Central Orchestrator |
| **Terraform Lock Breaker** | ✔ Local & S3/Dynamo/Azure/PG | ✔ Fleet-wide across 100+ repos |
| **Helm Release Unwedger** | ✔ Single-cluster manual/scripted | ✔ Automated drift & deadlock reconciler |
| **Kubernetes Unstuck** | ✔ CLI diagnostic & healing | ✔ Multi-cluster daemon with admission guards |
| **AWS VPC Drainage** | ✔ Single VPC CLI sweeper | ✔ Scheduled stale ephemeral cleanup daemon |
| **Multi-Pipeline Concurrency** | Local Lease Locks | Global Redis / DynamoDB Fleet Mutex |
| **Slack / PagerDuty Broadcasts** | ❌ | ✔ Incident triage cards & approval buttons |
| **Audit Logs & Compliance** | Stdout / JSON logs | Immutable central audit trail & SIEM ingest |

---

## 📦 Building from Source

Requirements: **Go 1.26+**

```bash
# Clone the unified engine
git clone https://github.com/x7ssss/x7.git
cd x7

# Run all tests
go test -v ./...

# Compile unified static binary
go build -o bin/x7 ./cmd/x7

# Windows
go build -o bin/x7.exe ./cmd/x7
```

---

## 📄 License

This software is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete details.

Copyright (c) 2026 x7ssss
