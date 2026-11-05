# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub security advisories:
<https://github.com/petrhromadka/mcp-warden/security/advisories/new>

Do not open a public issue or pull request for a security problem. Include the affected
version, a minimal reproduction (a config file or `tools/list` dump is ideal) and the impact
you expect. You should get a first reply within 7 days.

## Supported versions

Only the latest release receives security fixes.

## Scope

mcp-warden is an offline static scanner. By default it reads files and makes no network
requests. In scope: crashes or hangs on crafted input, a scan that executes or contacts
something without `--connect`, and release artifacts that do not match their published
checksums or provenance attestations. A rule that fails to flag a poisoned server is a
detection gap, not a vulnerability; please open a normal issue with a sample.

## Verifying a release

Every release archive is listed in `SHA256SUMS` and has a build provenance attestation:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify mcp-warden-<target>.tar.gz --repo petrhromadka/mcp-warden
```
