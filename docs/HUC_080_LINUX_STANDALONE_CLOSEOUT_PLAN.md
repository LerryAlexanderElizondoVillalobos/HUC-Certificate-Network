# HUC 0.8.0 — Linux Standalone Closeout Plan

**Project:** HUC — Certificates with UTXO Infrastructure  
**Release target:** 0.8.0 Linux Standalone  
**Author:** LAEV  
**Baseline branch:** `main`  
**Closeout branch:** `docs/huc-0.8.0-linux-standalone-closeout`

## 1. Release objective

Deliver HUC 0.8.0 as a downloadable, verifiable, installable and usable Linux user-space product. The first release target is Linux Standalone: one host, one local authoritative registry, no peer nodes required, and no network connection required after installation for the offline operations explicitly supported by the release.

This release is software that runs on Linux. It does not constitute an official certification of a Linux distribution and must not silently install a system-wide root certificate or modify the operating system trust store.

## 2. Scope freeze

Until the Linux Standalone release passes its acceptance campaign:

- Do not prioritize additional operating systems.
- Do not prioritize new certificate families.
- Do not expand institutional or federated deployment features.
- Do not add BFT features unless required to correct a release-blocking defect in the supported code path.
- Keep existing platform and institutional pull requests separate from the closeout work.

The current open pull requests are not implicitly approved for merging by this plan. Review each only if a specific change is necessary for the Standalone release.

## 3. Repository baseline and known gaps

The repository already contains the HUC Python modules, `pyproject.toml`, `requirements.txt`, test suite, demos, Direct SDK, release-validation workflow and documentation describing Standalone and federated modes.

The current repository does not yet provide a complete end-user Linux user-space installer and published Linux release asset set. The existing release workflow validates a tagged release but does not, by itself, produce and publish the complete standalone distribution described here.

A recent CI run on the baseline branch reported failures in the four Python-version test-suite jobs (3.10, 3.11, 3.12 and 3.13), while the four-process TLS cluster, Direct SDK Python tests and public certificate lifecycle fixture jobs succeeded. Treat this as a release blocker until the failure logs are diagnosed and a new run passes.

Reference CI run: https://github.com/LerryAlexanderElizondoVillalobos/HUC-Certificate-Network/actions/runs/43215740467

## 4. Work packages

### WP0 — Freeze and baseline

1. Record the exact baseline commit and branch.
2. Keep this closeout on a dedicated branch and pull request.
3. Inventory open pull requests and classify them as required, deferred or unrelated.
4. Record current CI status and existing test evidence.
5. Do not merge unrelated platform or institutional work into the closeout branch.

**Exit criteria:** scope is frozen, baseline is recorded, and closeout changes are isolated.

### WP1 — Core stabilization

1. Diagnose the failing Python test-suite jobs across supported Python versions.
2. Fix only reproducible defects and add regression tests.
3. Review SQLite connection lifecycle and explicit resource closure.
4. Verify transaction boundaries and atomic state updates.
5. Verify unique UTXO/outpoint consumption under concurrent requests.
6. Verify persistence after process and host restarts.
7. Verify recovery and backup restoration behavior.
8. Verify rollback detection and fail-closed behavior where required.
9. Verify permissions for state, database, evidence and private-key material.
10. Verify evidence integrity and deterministic error handling.

**Exit criteria:** complete core suite passes on Python 3.10, 3.11, 3.12 and 3.13; no unresolved release-blocking test failures.

### WP2 — Linux user-space runtime

1. Define a supported Linux user-space installation layout.
2. Keep executable/runtime files under `~/.local/opt/huc`.
3. Install the command wrapper under `~/.local/bin/huc`.
4. Store configuration under `~/.config/huc`.
5. Store mutable state under `~/.local/state/huc`.
6. Do not require root for installation, initialization or supported Standalone operations.
7. Do not install private keys, real certificates or user secrets in the distribution archive.
8. Do not modify system-wide trust stores by default.
9. Ensure the package includes every dependency required for the advertised offline installation.

**Exit criteria:** clean installation and removal work for a non-privileged Linux user.

### WP3 — User-facing CLI

1. Confirm the actual supported commands from implemented code.
2. Provide version and help output.
3. Provide initialization, status and diagnostics.
4. Provide certificate inspection and verification where implemented.
5. Provide evidence export and backup/restore only after their behavior is tested.
6. Ensure exit codes are stable and documented.
7. Ensure errors are actionable and secrets are never printed.

Proposed command names are not a statement that these commands already exist. Only commands implemented and tested may appear in the user manual.

**Exit criteria:** a user can complete the documented primary workflow from the terminal without editing Python source.

### WP4 — Offline distribution and installer

1. Build a Linux x86_64 user-space archive.
2. Include the runtime, required dependencies, installer, uninstaller and documentation.
3. Generate a package manifest.
4. Generate SHA-256 checksums.
5. Sign the release manifest using a controlled release-signing key.
6. Verify the archive and signature from a clean test environment.
7. Build ARM64 only after a separate successful compatibility campaign.
8. Make the installer fail safely on unsupported architecture or corrupted package input.

**Exit criteria:** the archive installs and runs without network access after download, and its authenticity/integrity can be verified independently.

### WP5 — Linux acceptance campaign

Initial target environments:

- Ubuntu 24.04 LTS.
- Debian 13.

Record exact OS image/version, architecture, Python version and dependency versions for every run.

Required scenarios:

- Clean install as a normal user, without root.
- Package checksum and signature verification.
- Initialization and primary certificate workflow.
- Offline installation and supported offline verification after disconnecting the network.
- Process restart and host reboot persistence.
- Concurrent attempts to consume the same outpoint; exactly one succeeds.
- Backup and restore.
- Corrupt or stale state rejection where applicable.
- Permission checks for sensitive directories and files.
- Clean uninstall without deleting user data unless explicitly requested.

Offline verification has a defined freshness boundary: a disconnected verifier cannot learn about revocations or policy changes published after its last trusted update. The product must disclose this limitation.

**Exit criteria:** all critical scenarios pass with retained logs, environment metadata and test evidence.

### WP6 — Release publication

1. Tag the exact tested commit as `v0.8.0`.
2. Run release validation against that tag.
3. Build the release assets from the tagged source.
4. Publish the Linux archive, checksum file and detached signature.
5. Publish installation instructions, user manual, security notes and release notes.
6. Attach the acceptance report and identify any known limitations.
7. Verify that the public assets can be downloaded and independently checked.

**Exit criteria:** public GitHub Release contains the exact tested package and all required supporting artifacts.

## 5. Required release assets

Initial x86_64 release:

- `huc-linux-user-x86_64.tar.gz`
- `SHA256SUMS`
- `SHA256SUMS.sig`
- `INSTALL.md`
- `USER-MANUAL.md`
- `SECURITY.md`
- `RELEASE-NOTES.md`
- `ACCEPTANCE-REPORT.md`

Do not advertise an ARM64 asset until it has been built and tested.

## 6. Release gates

A release is blocked if any of the following is true:

- The core test suite fails on a supported Python version.
- A documented installation requires undocumented root privileges.
- An advertised offline installation needs network access after the package is downloaded.
- Two concurrent requests successfully consume the same logical outpoint.
- State is lost or silently rolled back after restart or restore.
- Sensitive files are created with unsafe permissions.
- The package contains private keys or user-specific secrets.
- The package has no independently verifiable integrity/authenticity metadata.
- The user documentation describes commands or behavior that do not exist.
- The tested source does not match the published tag and assets.

## 7. Final acceptance definition

HUC 0.8.0 Linux Standalone is accepted only when a person who did not develop the package can:

1. Download it from the public release.
2. Verify the release signature and checksum.
3. Install it without root.
4. Initialize and use the documented Standalone workflow.
5. Inspect and verify supported certificate/evidence artifacts.
6. Perform the documented offline operations with the network disconnected.
7. Restart the process and host without losing valid state.
8. Confirm single-consumption behavior under concurrency.
9. Uninstall the software safely.

## 8. Expansion rule

No new platform, certificate family or institutional expansion becomes a development priority until the public HUC 0.8.0 Linux Standalone release and its acceptance campaign have passed.

**Product decision:** prove the downloadable product first; expand the ecosystem afterward.
