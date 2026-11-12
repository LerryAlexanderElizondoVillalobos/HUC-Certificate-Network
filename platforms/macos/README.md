# HUC macOS Platform

Status: independent validation lane; native packaging is a later migration step.

The current portable Python implementation is validated by `.github/workflows/platform-macos.yml` on Python 3.10–3.13, including the synthetic funding regression.

Target boundary: macOS packaging, launch/service integration, Keychain adapter and platform-specific permissions. Protocol behavior remains shared.