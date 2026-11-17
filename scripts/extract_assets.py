"""One-shot migration helper.

Pulls the big embedded resources out of the OLD monolithic main.py and writes them as real files:
    LANDING_HTML  -> templates/landing.html
    ADMIN_HTML    -> templates/admin.html
    LOGO_PNG_B64  -> static/logo.png
    FAVICON_PNG_B64 -> static/favicon.png

Usage:  python scripts/extract_assets.py /path/to/old/main.py
"""
from __future__ import annotations

import ast
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def literal(node: ast.AST) -> str:
    # Handles a plain string and a parenthesised triple-quoted string followed by .replace(...), without executing the old module.
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
        return literal(node.func.value).replace(*[ast.literal_eval(a) for a in node.args])
    return ast.literal_eval(node)


def main(src: str) -> None:
    tree = ast.parse(Path(src).read_text(encoding="utf-8"))
    found: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"LANDING_HTML", "ADMIN_HTML", "LOGO_PNG_B64", "FAVICON_PNG_B64"}:
                found[name] = literal(node.value)
    missing = {"LANDING_HTML", "ADMIN_HTML", "LOGO_PNG_B64", "FAVICON_PNG_B64"} - found.keys()
    if missing:
        sys.exit(f"not found in {src}: {', '.join(sorted(missing))}")

    (ROOT / "templates").mkdir(exist_ok=True)
    (ROOT / "static").mkdir(exist_ok=True)
    (ROOT / "templates" / "landing.html").write_text(found["LANDING_HTML"], encoding="utf-8")
    (ROOT / "templates" / "admin.html").write_text(found["ADMIN_HTML"], encoding="utf-8")
    (ROOT / "static" / "logo.png").write_bytes(base64.b64decode(found["LOGO_PNG_B64"]))
    (ROOT / "static" / "favicon.png").write_bytes(base64.b64decode(found["FAVICON_PNG_B64"]))
    print("OK: templates/landing.html, templates/admin.html, static/logo.png, static/favicon.png")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
