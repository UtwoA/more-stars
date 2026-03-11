import re


def parse_og_meta(html: str) -> dict:
    def _find(prop: str) -> str | None:
        pattern = re.compile(
            rf'<meta[^>]+property=["\']{prop}["\'][^>]+content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        match = pattern.search(html)
        return match.group(1).strip() if match else None

    return {
        "title": _find("og:title"),
        "image": _find("og:image"),
        "description": _find("og:description"),
    }

