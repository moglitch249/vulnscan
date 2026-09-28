# Contributing to VulnScanner

Thank you for your interest in contributing! This document outlines the process and guidelines.

## Development Setup

```bash
git clone <repository-url>
cd vulnscanner
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

## Code Quality

We enforce code quality via:

- **Ruff** — linting and formatting
- **MyPy** — static type checking
- **Pytest** — automated testing

Run all checks before submitting:

```bash
ruff check vulnscanner/ tests/
ruff format --check vulnscanner/ tests/
mypy vulnscanner/
pytest
```

## Type Hints

All code must use Python 3.12+ type hints. Use `from __future__ import annotations` in every module.

## Testing Guidelines

- **Every new feature** must have unit tests
- **Every new source adapter** must have tests with mocked API responses
- Tests must **not** require real API keys or network access
- Use `pytest-mock` and `respx` for mocking HTTP calls
- Mark slow tests with `@pytest.mark.slow`
- Mark integration tests with `@pytest.mark.integration`

## Adding a Vulnerability Source

1. Research the API/feed:
   - Verify it's publicly accessible
   - Document authentication requirements
   - Document rate limits
   - Identify the correct endpoints and schema
   - Check licensing/usage restrictions

2. Create `vulnscanner/sources/<name>/`:
   - `__init__.py`
   - `source.py` — implements `VulnerabilitySource` ABC
   - `parser.py` — response parsing if complex

3. Add configuration to `config.yaml`

4. Write tests in `tests/test_source_<name>.py`

5. If the source **cannot** be implemented (paid API, no public access):
   - Use `NotImplementedSource` with a clear explanation
   - Document the reason in the source module

## Commit Messages

Use conventional commit format:

```
feat(sources): add Alpine SecDB integration
fix(nmap): handle missing version in service detection
docs(readme): add troubleshooting section
test(nvd): add rate limit handling tests
```

## Security

- **Never** commit API keys, tokens, or secrets
- **Never** log secrets (use the structured logger with redaction)
- **Never** construct shell commands from user input
- **Always** use `subprocess.run([...], shell=False)`
- **Always** validate all user inputs through `vulnscanner.core.validators`

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure all checks pass
4. Submit PR with a clear description
5. Address review feedback

## Code of Conduct

Be respectful, constructive, and professional. This is a security tool —
maintain the highest standards of responsible disclosure and ethical use.
