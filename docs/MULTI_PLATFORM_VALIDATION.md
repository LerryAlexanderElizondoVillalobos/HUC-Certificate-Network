# HUC 0.8.0 — Multi-platform validation plan

## Purpose

Validate the existing HUC 0.8.0 implementation before changing certificate formats, protocol rules or version numbers. This test plan does not alter the certificate specification.

## Automated GitHub Actions matrix

| Target | Automated scope | Boundary |
|---|---|---|
| Ubuntu Linux | HUC core, Direct SDK, four-process TLS, public fixtures | Hosted Linux runner |
| Windows | HUC core and Direct SDK Python suites | Hosted Windows runner |
| macOS | HUC core and Direct SDK Python suites | Hosted macOS runner |
| Android | Kotlin library and sample APK compilation | Hosted Linux runner with Android SDK; compilation is not a device test |

The core matrix covers Python 3.10, 3.11, 3.12 and 3.13 on Ubuntu, Windows and macOS. The Direct SDK matrix uses Python 3.13 on all three operating systems. The four-process TLS test remains on Linux because it launches independent local server processes and uses loopback sockets.

JUnit XML reports and Android build outputs are uploaded as GitHub Actions artifacts.

## Interoperability acceptance

The next test layer must use identical, fixed public fixtures and trust pins across operating systems:

1. Verify the same active credential bundle on Ubuntu, Windows, macOS and Android.
2. Verify the same renewed bundle and reject its superseded predecessor.
3. Reject revoked, tampered, expired and wrong-trust-anchor bundles.
4. Verify challenge-response with matching audience and reject replay or audience mismatch.
5. Confirm byte-for-byte canonical JSON and SHA-256 identifiers across runtimes.
6. Record OS version, runtime version, SDK version, fixture digest, test result and workflow run URL.

A green OS test suite is compatibility evidence for that runner/runtime combination. It is not proof of production readiness or every device/OEM version.

## Physical and network acceptance

GitHub-hosted runners do not replace physical Android devices or independent institutional nodes. The physical-device procedure in PHYSICAL_DEVICE_TEST.md remains a separate acceptance stage. It requires four distinct devices, separately held private keys, authenticated network connectivity, TLS certificates with correct SANs, and a recorded recovery/partition test.

## Financing validation — scope not yet defined

HUC 0.8.0 currently provides certificate issuance, presentation, verification and lifecycle state. It does not implement credit scoring, loan underwriting, payment processing, lending, funding or settlement.

A financing test harness must therefore be specified separately. It must use synthetic identities and sandbox funds only, and must not represent a certificate's cryptographic validity as proof of creditworthiness. No real money movement or financial institution integration is included in this workflow.

Before adding financing scenarios, define whether HUC is being tested as:
- a credential prerequisite for a financing application (for example, validating professional qualifications or business registration), or
- a system for funding the HUC project itself (contributions, investment, grants or payment processing).

Any external payment or lending provider must use its official sandbox, test credentials stored as GitHub Actions secrets, idempotency checks and explicit no-live-money safeguards.

## Stop condition

Do not modify the HUC certificate specification or bump the version until the cross-platform reports, Android build status, physical-device evidence and separately scoped financing tests have been reviewed.
