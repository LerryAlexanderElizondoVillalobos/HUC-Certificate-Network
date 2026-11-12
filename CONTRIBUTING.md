# Contributing

HUC is experimental research software. Contributions should be small, reviewable and accompanied by tests.

1. Open an issue describing the problem or proposal.
2. Work on a dedicated branch.
3. Add or update tests for behavioral changes.
4. Run `python -m unittest discover -s tests -v` and `ruff check src tests`.
5. Submit a pull request describing design decisions, security impact and compatibility.

Do not submit secrets, private keys, personal data or production credentials. Protocol changes must update the relevant specification in `docs/`.
