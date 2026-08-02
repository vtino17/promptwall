# Contributing

Use a focused branch and pull request. Keep behavior changes covered by tests,
use only synthetic credentials and personal data, and explain any security
trade-off or compatibility impact.

Before submitting, run:

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest -q --cov=promptwall --cov-fail-under=85
python -m build
twine check dist/*
```

By contributing, you agree that your contribution is licensed under the MIT
license in this repository.
