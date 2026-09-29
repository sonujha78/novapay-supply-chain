# Task 3: SBOM and Vulnerability Gate

## Pipeline behaviour

- The `build` job pushes the image and outputs its digest.
- The `scan` job generates an SPDX JSON SBOM with syft (via `anchore/sbom-action`) for `image@digest`.
- grype scans the same digest. The job fails on any **Critical** finding that has a **fix available** (`only-fixed: true`).
- The SBOM and scan report are uploaded as the `sbom-and-scan` workflow artifact.

## Risk acceptance process

Accepted risks live in `.grype.yaml`. Every entry needs a CVE id, a written justification, an owner, and an expiry date. Entries are added only through a pull request with review, and expired entries must be removed or re-approved. Unfixed vulnerabilities are not blocking, but they stay visible in the report and are reviewed weekly.

## What an SBOM does and does not protect you from

An SBOM is an inventory of every component in the image (Go stdlib version, base image packages). It lets us answer "are we affected?" within minutes when a new CVE or a compromised package is announced, and it feeds vulnerability scanning and the incident-response search in Task 8.

It does **not** prevent an attack by itself: it does not detect malicious code inside a component, does not prove the image was built from the expected source (that is provenance), does not stop tampering (that is signing), and is only as accurate as the tool that generated it. Scanners also miss zero-days and statically linked or renamed code. An SBOM is visibility, not protection.
