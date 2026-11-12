# HUC Windows Platform

Status: independent validation lane; native packaging is a later migration step.

The current portable Python implementation is validated by `.github/workflows/platform-windows.yml` on Python 3.10–3.13. The BFT TCP recovery regression is explicitly repeated here.

Target boundary: Windows packaging, service lifecycle, filesystem/network adapters and native credential-store integration. Do not fork protocol or certificate semantics.