"""Export the FastAPI OpenAPI spec to openapi.json in the auth-service root."""
import json
from pathlib import Path


def main() -> None:
    from app.main import app  # noqa: PLC0415 — import here to avoid side-effects at module level

    spec = app.openapi()
    out = Path(__file__).parent.parent / "openapi.json"
    out.write_text(json.dumps(spec, indent=2) + "\n")
    print(f"✓ Spec written to {out}")


if __name__ == "__main__":
    main()
