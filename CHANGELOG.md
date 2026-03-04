# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Breaking Change Checklist

A **MAJOR** bump is required when any of the following change:

- An endpoint path or HTTP method is modified or removed
- A required request field is added, renamed, or removed
- A response field is renamed or removed (`UserResponse`, `AuthResponse`, `TokenResponse`)
- JWT claim structure or signing algorithm changes
- An Alembic migration that is not backwards-compatible

Use `make bump-major` for breaking changes, `make bump-minor` for new features, `make bump-patch` for bug fixes.

---

## [Unreleased]

## [0.1.0] - 2026-03-04

### Added
- `/register`, `/login`, `/logout`, `/refresh`, `/me` endpoints under `/api/v1/auth/`
- JWT access + refresh token rotation with family-based reuse detection
- Permission system: plan-based + per-user overrides via `PermissionService`
- Canonical `UserResponse` model across all auth endpoints (no dict returns)
- `OkResponse` for test-support endpoints
- OpenAPI single source of truth (`packages/auth-service/openapi.json`)
- Export script: `packages/auth-service/scripts/export_openapi.py`
- `Makefile` with `openapi`, `check-drift`, `bump-*` targets
- Python auth-client SDK (`packages/auth-client`) with FastAPI middleware and `LocalTokenVerifier`
