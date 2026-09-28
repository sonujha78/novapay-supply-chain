# NovaPay Supply Chain Security Lab

Securing the CI/CD software supply chain for a payments-API microservice using
**SLSA** and **Sigstore (cosign, Fulcio, Rekor)**.

## What this repo demonstrates
- Hardened GitHub Actions pipeline (pinned actions, least-privilege permissions, no long-lived secrets)
- SBOM generation (syft) and vulnerability gate (grype)
- Keyless image signing and attestations with cosign
- SLSA build provenance
- Deploy-time verification with Kyverno on a kind cluster
- Attack simulations and threat model

## Repo layout
- `app/` sample payments API + Dockerfile
- `.github/workflows/` CI pipeline
- `k8s/` Kyverno policy and manifests
- `docs/` threat model, attack log, report
- `evidence/` command outputs and screenshots

## Progress
- [ ] Task 1: Threat model
- [ ] Task 2: Hardened CI pipeline
- [ ] Task 3: SBOM and vulnerability gate
- [ ] Task 4: Keyless signing with cosign
- [ ] Task 5: SLSA provenance
- [ ] Task 6: Kyverno admission enforcement
- [ ] Task 7: Attack simulation
- [ ] Task 8: Report and executive summary
