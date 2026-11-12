# HUC Modular Monorepo Architecture

## Decision

HUC is maintained in one repository with independent platform modules and independent CI workflows. This avoids duplicated protocol specifications while allowing each platform to build, test and release on its own cadence.

## Platform lanes

| Platform | Workflow | Responsibility |
|---|---|---|
| Linux | `platform-linux.yml` | Reference runtime, full core suite, multi-process TLS, synthetic funding |
| Windows | `platform-windows.yml` | Portable core suite across Python 3.10–3.13 and BFT TCP recovery |
| macOS | `platform-macos.yml` | Portable core suite across Python 3.10–3.13 and funding regression |
| Android | `platform-android.yml` | Kotlin/Gradle build and API 35 Keystore instrumentation |

## Shared versus platform-owned code

**Shared contract:** protocol versioning, canonical serialization, certificate/credential semantics, UTXO evidence rules, hash construction, consensus message schemas, error codes and conformance vectors.

**Platform-owned:** packaging, runtime lifecycle, OS APIs, secure-key-store adapters, permissions, filesystem/network adapters, build tooling and release artifacts.

A platform adapter MUST NOT change canonical bytes, hash preimages, signature verification rules, UTXO state transitions or certificate semantics.

## Migration policy

1. Keep the existing root Python modules as the compatibility reference while interfaces are extracted.
2. Move implementation code into explicit packages only after import compatibility tests and a passing platform lane exist.
3. Give each platform its own dependency manifest, tests, build artifact and release notes where applicable.
4. Keep shared conformance vectors outside platform-owned code and run them against every implementation.
5. Add the translator only after at least two independent implementations pass the same vectors. The translator maps APIs and data representations; it never exports private keys or rewrites cryptographic evidence.

## Workflow policy

Each platform workflow has its own path filters, concurrency group, test scope and evidence artifacts. Shared protocol or core changes trigger all relevant lanes. A green workflow for one platform does not imply another platform passed.

The legacy combined workflow is retained temporarily as a cross-platform integration gate until the new independent lanes have demonstrated equivalent coverage. It must not be treated as a substitute for platform-specific results.

## Release gate

A platform release requires its own build and test workflow to pass, plus shared conformance tests. Android physical-device validation remains a separate evidence item; emulator success is not physical-device success.