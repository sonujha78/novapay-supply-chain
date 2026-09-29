# Task 6: Enforce Verification at Deploy Time

## Setup

- Local `kind` cluster (`novapay-lab`), Kyverno v1.19.1 installed via Helm (admission, background, cleanup, and reports controllers all running).
- A `ClusterPolicy` named `verify-signed-images` (`k8s/verify-signed-images.yaml`) in `Enforce` mode, requiring every Pod whose image matches `ghcr.io/sonujha78/novapay-supply-chain*` to carry a valid keyless cosign signature from this repository's workflow identity, verified against the public Rekor log.

```yaml
attestors:
  - count: 1
    entries:
      - keyless:
          issuer: "https://token.actions.githubusercontent.com"
          subject: "https://github.com/sonujha78/novapay-supply-chain/.github/workflows/build-sign-attest.yml@refs/heads/main"
          rekor:
            url: "https://rekor.sigstore.dev"
```

## A production pitfall discovered and fixed

cosign v3 defaults to storing signatures and attestations as OCI 1.1 Referrers artifacts. GHCR does not fully support the Referrers API for verification clients, so neither Kyverno nor `cosign verify` (v2 or v3) could find a signature at all (`no signatures found`), even though the image *was* signed.

Fixed by forcing cosign to also write the legacy `sha256-<digest>.sig` / `.att` tags, using `--new-bundle-format=false --use-signing-config=false` on both `cosign sign` and `cosign attest` in the workflow. This is a real-world interoperability gap between a newer signing tool and the deploy-time verifier, and is called out explicitly here rather than hidden, since the task rewards honest reporting of gaps.

## Result: admitted vs denied

**Signed image — admitted:**

```
$ kubectl apply -f k8s/pod-signed.yaml
$ kubectl get pod novapay-signed -n novapay-demo
NAME             READY   STATUS    RESTARTS   AGE
novapay-signed   1/1     Running   0          61s
```

Image: `ghcr.io/sonujha78/novapay-supply-chain@sha256:c2aef30af311a4fc3daa87dd1bb52d7b00a475ac176c825094984db0517c087c` (signed by the `build-sign-attest.yml` workflow on `main`, verified in Task 4/5).

**Unsigned image, same registry path — denied:**

```
$ kubectl run novapay-unsigned --image=ghcr.io/sonujha78/novapay-supply-chain:121d668609df0977dbe18ec60fbf716b1ded5d85 -n novapay-demo
Error from server: admission webhook "mutate.kyverno.svc-fail" denied the request:

resource Pod/novapay-demo/novapay-unsigned was blocked due to the following policies

verify-signed-images:
  verify-cosign-keyless: 'failed to verify image ...: .attestors[0].entries[0].keyless: no signatures found'
```

This tag predates Task 4 (pushed by the workflow before the `sign` job existed), so it carries no signature — Kyverno correctly refuses to admit it, proving the control: **an unsigned image from the exact same registry path as trusted images is still rejected at deploy time.**

Full evidence: `evidence/task6/pods-status.txt`, `evidence/task6/denied-unsigned.txt`, `evidence/task6/clusterpolicy-applied.yaml`.
