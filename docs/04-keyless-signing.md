# Task 4: Keyless Signing with cosign

## What was done
- `sign` job runs after `build` and `scan` succeed, so a failed scan blocks signing.
- Only the `sign` job has `id-token: write` (least privilege).
- The image is signed **by digest**, never by tag:
  `ghcr.io/sonujha78/novapay-supply-chain@sha256:287391bad5fcf08fa80c44a7604ddc35378eaa435fbbc05ab339c9a32eaf99b6`
- The SPDX SBOM produced in Task 3 is attached as a signed attestation (`cosign attest --type spdxjson`).
- Verified independently from a laptop (not from CI) with an identity anchored to this repository,
  this exact workflow file, and the `main` branch — see `evidence/task4-verify.json` and
  `evidence/task4-verify-attestation.json` (both exit code 0).

## Q1: What identity and issuer are embedded in the Fulcio certificate? Why is this stronger than a shared key?

The certificate's Subject Alternative Name (URI) is:
https://github.com/sonujha78/novapay-supply-chain/.github/workflows/build-sign-attest.yml@refs/heads/main

The issuer is `https://token.actions.githubusercontent.com` (GitHub's OIDC provider), and the Fulcio-issued
certificate is chained to `O=sigstore.dev, CN=sigstore-intermediate`. The certificate also carries the full
GitHub Actions OIDC claims as Fulcio SAN extension OIDs, including source repository
(`1.3.6.1.4.1.57264.1.12` → `https://github.com/sonujha78/novapay-supply-chain`), source ref
(`1.3.6.1.4.1.57264.1.14` → `refs/heads/main`), build signer/workflow URI (`1.3.6.1.4.1.57264.1.9`),
runner environment (`1.3.6.1.4.1.57264.1.11` → `github-hosted`) and the exact run invocation
(`1.3.6.1.4.1.57264.1.21` → `.../actions/runs/36445390298/attempts/1`).

Crucially, `Not Before` / `Not After` on this certificate span only **10 minutes**
(`2026-09-28 15:43:46 GMT` → `15:53:46 GMT`). This is stronger than a shared long-lived private key because:
- **No secret to steal.** There is no signing key sitting in a repo secret, disk, or KMS that an attacker can
  exfiltrate; a fresh identity token and certificate are minted per run and expire almost immediately.
- **Identity is provable, not assumed.** The certificate cryptographically binds the signature to *this*
  repository, *this* workflow file, and *this* ref, issued by GitHub's OIDC provider — not to "whoever had
  the key."
- **No rotation burden.** Because nothing long-lived exists, there is nothing to rotate, and a leaked runner
  cannot be used to sign anything after the job ends.

## Q2: Find your signature in the Rekor transparency log. What fields does it contain, and why does an append-only log help?

Both entries were fetched directly from the public Rekor API:

| | Signature entry | SBOM attestation entry |
|---|---|---|
| logIndex | 2984075021 | 2984075535 |
| logID | c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d | (same Rekor instance) |
| integratedTime | 1790610223 (Unix) | — |
| body kind | dsse | dsse |

Each entry's fields include: `logIndex` (position in the log), `logID` (which Rekor tree/instance), the
`integratedTime` (when it was appended), and a `body` containing the DSSE envelope with the signed payload's
digest, the signature, and the signing certificate — this is what `cosign verify` checks offline against.

An append-only, publicly auditable log matters because:
- **Nothing can be silently removed or edited.** Rekor is backed by a Merkle tree; changing a past entry would
  change the tree root, which is independently checkable via signed tree heads.
- **Compromise becomes detectable, not just preventable.** Even if a signing identity is later compromised, every
  signature it ever produced is permanently recorded with a timestamp — an incident response can enumerate
  every artifact signed by that identity (see Task 8's playbook).
- **Anyone can monitor the log** for certificates issued to their repository/workflow identity, catching a
  forged signature attempt even before it reaches a registry.

## Q3: Why is verifying with a loose identity pattern (e.g. any repository) dangerous?

`cosign verify` only proves a signature is *cryptographically valid* — that some Fulcio-issued certificate signed
the artifact. It says nothing about *whose* certificate that was unless `--certificate-identity` /
`--certificate-identity-regexp` and `--certificate-oidc-issuer` are pinned tightly. A loose pattern such as
`.*` for the identity, or accepting any issuer, would let **any GitHub Actions workflow in any repository**
(including an attacker's own public fork) produce a signature that passes verification. Combined with Attack A2
in Task 7, a fork of this repo could sign a malicious image and it would verify successfully under a loose
policy. Anchoring the regexp to this exact repository, this exact workflow file path, and `refs/heads/main`
(as used above and in the Kyverno policy in Task 6) ensures only builds from NovaPay's own protected main
branch, run through NovaPay's own hardened workflow, are trusted.
