# LAEV HUC 0.8 — Public demonstration and reproducible tests

The public demo directory contains X.509, HUC-CC, membership, commit, view-change and state-sync fixtures from earlier HUC versions. All artifacts are public-only; no authority, CA, validator or subject private keys are included.

HUC 0.8 adds the BFT-inspired protocol in the source modules and automated tests. Reproduce its complete test suite from the project root:

```bash
bash run_tests.sh
```

Run the four-process TLS integration test specifically:

```bash
python -m unittest tests.test_bft_process_cluster -v
```

The four processes and TLS transport run on one host over loopback. This does not prove interoperability across physical devices or real institution networks. Follow `PHYSICAL_DEVICE_TEST.md` for that test.
