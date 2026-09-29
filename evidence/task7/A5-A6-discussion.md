# A5: Compromised build step modifies the artifact after build

**Scenario:** an attacker who has compromised the `build` job's environment (a malicious dependency
executing at build time, or a compromised action) modifies the built binary or image layers after the
`docker build` step but before push.

**What exposes this:**
- The image is pushed by digest, and every downstream step (`scan`, `sign`, `provenance`) operates on
  `needs.build.outputs.digest` — the exact content hash of what was pushed. If the artifact differs from
  what a reviewer expects, the digest itself will differ from any previously-known-good digest, so digest
  pinning (Task 7 A3) exposes drift immediately on comparison.
- The SLSA provenance (Task 5) records the exact source commit, workflow file, and run ID that produced
  the digest. If the attacker's tampering happened inside the same `build` job (not a separate job), the
  provenance's builder ID and source commit would still match — provenance at SLSA L2 does **not** prove
  the build steps themselves were not tampered with internally, only that a hosted platform (not the
  artifact's own script) issued the provenance.
- This is precisely the gap named in Task 5's SLSA level assessment: reaching **L3** via
  `slsa-github-generator`'s isolated provenance-generation job would let an independent, isolated process
  attest to what was actually produced, closing the gap where a compromised build job could tamper with
  its own output before the provenance step ever sees it.

**Classification:** partially preventable today (digest pinning + SBOM diffing across builds gives
*detection* after the fact), not fully preventable without SLSA L3 isolation. This is a known gap in this
pipeline.

# A6: Dependency in the lockfile is replaced by a vulnerable or malicious version

**Scenario:** a Go module dependency is swapped for a typosquatted or backdoored version, either via a
compromised upstream release or a malicious PR editing `go.sum`.

**What exposes this:**
- `go.sum` pins every dependency to a specific content hash; a swapped module with different content
  would fail the Go toolchain's hash verification at build time, so a naive typosquat that doesn't also
  compromise the legitimate upstream release is caught immediately by `go build` itself.
- If the malicious version is a genuine upstream release (supply-chain compromise at the source, not a
  local tamper), the SBOM (Task 3) records every component and its exact version in `sbom.spdx.json`. When
  a compromise is later disclosed publicly, the SBOM lets us grep every past build's SBOM artifact for the
  affected package/version instantly, without re-inspecting source.
- The grype vulnerability gate (Task 3) would catch a *known* CVE in the new version if one is disclosed
  and has a fix version available, but would **not** catch a zero-day or an intentionally-planted backdoor
  with no CVE — this is an accepted limitation, documented in Task 3's "what an SBOM does and does not
  protect you from".
- Dependabot (configured in Task 2 for `gomod`) would separately flag known-vulnerable dependency versions
  on a schedule, independent of any specific build.

**Classification:** detection via SBOM + dependency scanning, not prevention. A sufficiently novel or
targeted malicious dependency with no known CVE would not be blocked before merge; only PR review and
`go.sum` hash pinning reduce the attack surface for this pipeline.
