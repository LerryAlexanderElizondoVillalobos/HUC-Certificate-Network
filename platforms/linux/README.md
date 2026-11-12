# HUC Linux Platform

Status: reference runtime and primary integration target.

Current implementation remains in the repository root (`huc*.py`, `tests/`, `validation/`) during the compatibility-preserving migration. The Linux workflow owns the full core suite, multi-process TLS cluster and synthetic funding evidence.

Target boundary: Linux packaging, runtime adapters, service integration and platform-specific deployment. Shared protocol behavior must remain platform-neutral.