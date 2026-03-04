.PHONY: openapi check-drift

VENV_PYTHON := packages/auth-service/../../.venv/bin/python

# Regenerate openapi.json from the live FastAPI app
openapi:
	cd packages/auth-service && PYTHONPATH=. ../../.venv/bin/python scripts/export_openapi.py

# CI gate: fails if openapi.json is out of date with the current source
check-drift: openapi
	git diff --exit-code packages/auth-service/openapi.json

# Version bumping (updates both pyproject.toml files + commits + tags)
bump-patch:
	uv run bump-my-version bump patch

bump-minor:
	uv run bump-my-version bump minor

bump-major:
	uv run bump-my-version bump major

.PHONY: bump-patch bump-minor bump-major
