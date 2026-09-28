# Task 5: SLSA Build Provenance

## Approach chosen: Option B — GitHub Artifact Attestations

Used `actions/attest-build-provenance` in a dedicated `provenance` job that runs after `build` and `sign`
succeed. Chosen over Option A (`slsa-github-generator`) because it is GitHub-native (no separate reusable
workflow or extra OIDC trust setup), integrates directly with `gh attestation verify`, and the pipeline
already uses the same job-isolation and least-privilege pattern established in Tasks 2-4. The trade-off is
discussed in the SLSA level assessment below.

## Verification
gh attestation verify oci://ghcr.io/sonujha78/novapay-supply-chain@sha256:275b64a4f899e1e2e17bf3826d50e7b95026f3ba3eb1b315a1f3ac054c61de17
--owner sonujha78

Result: **Verification succeeded** — predicate type `https://slsa.dev/provenance/v1`, source repository owner
`https://github.com/sonujha78`, OIDC issuer `https://token.actions.githubusercontent.com`.
Full output: `evidence/task5-attestation-verify.txt`. Decoded statement: `evidence/task5-attestation-full.json`.

## Decoded provenance (key fields)

| Field | Value |
|---|---|
| Build type | `https://actions.github.io/buildtypes/workflow/v1` |
| Builder ID | `https://github.com/sonujha78/novapay-supply-chain/.github/workflows/build-sign-attest.yml@refs/heads/main` |
| Source repository | `https://github.com/sonujha78/novapay-supply-chain` |
| Source commit | `74d7186e16d8e4e4f0392fbe22bfd87c5ac0c465` |
| Source ref | `refs/heads/main` |
| Workflow path | `.github/workflows/build-sign-attest.yml` |
| Run invocation | `https://github.com/sonujha78/novapay-supply-chain/actions/runs/36465972488/attempts/1` |
| Subject (artifact) | `ghcr.io/sonujha78/novapay-supply-chain@sha256:275b64a4f899e1e2e17bf3826d50e7b95026f3ba3eb1b315a1f3ac054c61de17` |

The provenance ties the exact image digest to the exact source commit, the exact workflow file and ref that
built it, and the exact run that produced it — enough to answer "was this built from what we think it was
built from, by our pipeline?" for any image pulled from the registry.

## SLSA Build level self-assessment

**This pipeline achieves SLSA Build L2.**

- **L1 (met):** provenance exists, describing how the artifact was built.
- **L2 (met):** the provenance is generated and signed by a hosted build platform (GitHub Actions, via Sigstore/
  Fulcio-backed OIDC), not by the build job's own script, and it is tamper-evident (any edit invalidates the
  signature, and it is recorded in the GitHub attestation store and Rekor).
- **L3 (not met):** L3 requires the build platform to *isolate* provenance generation from the build steps
  strongly enough that the build job itself cannot forge or influence what goes into the provenance — e.g. a
  separate, hardened environment the build job cannot write to. In this pipeline, `build`, `scan`, `sign` and
  `provenance` are separate jobs (so a compromised `build` step cannot directly edit the `provenance` job's
  output), but they all run on the same class of GitHub-hosted runner under the same repository's control,
  and the provenance job trusts `needs.build.outputs.digest` as passed between jobs rather than an
  independently-verified build environment. `slsa-github-generator`'s reusable workflow (Option A) generates
  provenance in an isolated, dedicated repository-external workflow specifically to close this gap and is the
  standard route to L3.

**To reach L3:** switch the `provenance` job to `slsa-framework/slsa-github-generator`'s container generator
reusable workflow, which runs provenance generation in an isolated caller/reusable-workflow boundary that the
build job cannot influence, and re-verify with `slsa-verifier` instead of (or alongside) `gh attestation verify`.
