# HUC 0.8.0 Linux Standalone — Acceptance Checklist

This checklist is the execution record for the HUC 0.8.0 Linux Standalone release. A box may be checked only when the test has actually been executed and its evidence retained.

## A. Baseline and scope

- [ ] Baseline commit SHA recorded.
- [ ] Closeout branch and pull request isolated from unrelated work.
- [ ] Open pull requests classified; no unrelated feature merged.
- [ ] CI failure logs reviewed and root causes documented.

## B. Core stability

- [ ] Python 3.10 full test suite passes.
- [ ] Python 3.11 full test suite passes.
- [ ] Python 3.12 full test suite passes.
- [ ] Python 3.13 full test suite passes.
- [ ] SQLite connections/resources close deterministically.
- [ ] Transaction atomicity verified.
- [ ] Concurrent consume test: exactly one successful spend.
- [ ] Restart persistence test passes.
- [ ] Backup and restore test passes.
- [ ] Rollback/stale-state rejection tested.
- [ ] Sensitive file and directory permissions verified.
- [ ] Evidence integrity/tamper tests pass.

## C. Linux runtime and installer

- [ ] User-space installation layout documented.
- [ ] Clean Ubuntu 24.04 install without root passes.
- [ ] Clean Debian 13 install without root passes.
- [ ] Installer rejects corrupt package input.
- [ ] Installer rejects unsupported architecture safely.
- [ ] All advertised runtime dependencies are bundled.
- [ ] CLI help/version/status/doctor behavior verified.
- [ ] Only implemented commands appear in the manual.
- [ ] Uninstaller behavior verified.
- [ ] User data retention/deletion behavior documented.

## D. Offline behavior

- [ ] Package checksum verified before installation.
- [ ] Release signature verified independently.
- [ ] Installation completed with network disconnected.
- [ ] Documented offline certificate verification passes.
- [ ] Offline limitations for revocation/policy freshness documented.
- [ ] No hidden network dependency in the advertised Standalone workflow.

## E. Release and evidence

- [ ] x86_64 archive built from the tested commit.
- [ ] Archive contents and manifest inspected.
- [ ] SHA256SUMS generated and independently verified.
- [ ] SHA256SUMS.sig generated and independently verified.
- [ ] Release workflow passes against the tag.
- [ ] Acceptance report includes environment metadata and logs.
- [ ] Public GitHub Release created.
- [ ] Public assets downloaded and re-verified from GitHub.
- [ ] Release tag, source commit and package manifest match.

## F. Final independent-user test

- [ ] Independent user downloads the package.
- [ ] Independent user verifies signature and checksum.
- [ ] Independent user installs without root.
- [ ] Independent user completes the documented Standalone workflow.
- [ ] Independent user performs supported offline verification.
- [ ] Independent user confirms persistence after restart.
- [ ] Independent user confirms single-consumption behavior.
- [ ] Independent user uninstalls safely.

## Release decision

- [ ] ACCEPTED — all critical gates passed and evidence retained.
- [ ] REJECTED — one or more critical gates failed; release remains blocked.

**Rule:** an unchecked item is not evidence of completion. Do not mark a test as passed based solely on source inspection or a previous run against a different commit.
