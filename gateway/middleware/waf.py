"""Pattern-based Web Application Firewall.

Detects common SQL injection and XSS payloads in the request URL and
body. Uses a scoring system: a single suspicious pattern may not block,
but multiple signals together will.

Design decisions:
- Two independent rule sets (SQLi, XSS) so we can report which category triggered.
- Scores accumulate across all rules. Threshold of 2 triggers a block.
- Strong single signals (e.g. UNION SELECT) block immediately.
- All matching is case-insensitive and applied to URL-decoded text.
- Body is only inspected for content types that can carry payloads.
"""
import json
import re
import urllib.parse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule: (name, pattern, weight)
# Weight 2 = block on its own. Weight 1 = block only if other signals also fire.

SQLI_RULES = [
    # Strong single-signal patterns (weight 2 → auto-block)
    ("sqli_union_select",   re.compile(r"\bunion\b.{0,20}\bselect\b", re.I), 2),
    ("sqli_or_true",        re.compile(r"('\s*or\s*'?1'?\s*=\s*'?1)", re.I), 2),
    ("sqli_always_true",    re.compile(r"\bor\s+1\s*=\s*1\b", re.I), 2),
    ("sqli_drop",           re.compile(r";\s*drop\s+table\b", re.I), 2),
    ("sqli_stacked",        re.compile(r";\s*(insert|update|delete)\s+", re.I), 2),
    ("sqli_sleep",          re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(", re.I), 2),
    ("sqli_information_schema", re.compile(r"\binformation_schema\b", re.I), 2),

    # Weaker signals (weight 1 → need corroboration)
    ("sqli_comment",        re.compile(r"(--|#)\s*$", re.M), 1),
    ("sqli_quote",          re.compile(r"'\s*(or|and)\s+", re.I), 1),
    ("sqli_select_from",    re.compile(r"\bselect\b.{0,40}\bfrom\b", re.I), 1),
]

XSS_RULES = [
    # Strong single-signal patterns (weight 2 → auto-block)
    ("xss_script_tag",      re.compile(r"<\s*script\b", re.I), 2),
    ("xss_javascript_uri",  re.compile(r"javascript\s*:", re.I), 2),
    ("xss_onerror",         re.compile(r"\bon(error|load|click|mouseover)\s*=", re.I), 2),
    ("xss_iframe",          re.compile(r"<\s*iframe\b", re.I), 2),
    ("xss_svg_onload",      re.compile(r"<\s*svg\b.{0,40}\bonload\s*=", re.I), 2),
    ("xss_document_cookie", re.compile(r"\bdocument\s*\.\s*cookie\b", re.I), 2),

    # Weaker signals
    ("xss_html_event",      re.compile(r"\bon[a-z]{3,12}\s*=", re.I), 1),
    ("xss_img_tag",         re.compile(r"<\s*img\b", re.I), 1),
]

BLOCK_THRESHOLD = 2


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

def _decode_safely(text: str) -> str:
    """URL-decode twice, in case of double-encoding."""
    try:
        once = urllib.parse.unquote_plus(text)
        return urllib.parse.unquote_plus(once)
    except Exception:
        return text


def inspect_text(text: str) -> tuple[int, list[str]]:
    """Return (score, matched_rule_names) for a single piece of text."""
    if not text:
        return 0, []

    decoded = _decode_safely(text)
    score = 0
    matched = []

    for name, pattern, weight in SQLI_RULES + XSS_RULES:
        if pattern.search(decoded):
            score += weight
            matched.append(name)

    return score, matched


def inspect_request_parts(
    method: str,
    path: str,
    query_string: str,
    content_type: str,
    body: bytes,
) -> tuple[int, list[str]]:
    """Inspect URL + body. Returns (total_score, all_matched_rules)."""
    total_score = 0
    all_matched: list[str] = []

    # URL and query string
    for part in (path, query_string):
        s, m = inspect_text(part)
        total_score += s
        all_matched.extend(m)

    # Body — only if content type suggests text
    if body:
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        ct = (content_type or "").lower()
        if "json" in ct:
            # Parse JSON and re-serialize each string value to inspect it
            try:
                obj = json.loads(text)
                strings = list(_iter_strings(obj))
                for s in strings:
                    score, matched = inspect_text(s)
                    total_score += score
                    all_matched.extend(matched)
            except Exception:
                # Invalid JSON — still inspect raw
                score, matched = inspect_text(text)
                total_score += score
                all_matched.extend(matched)
        else:
            score, matched = inspect_text(text)
            total_score += score
            all_matched.extend(matched)

    return total_score, all_matched


def _iter_strings(obj):
    """Yield every string value from a nested JSON object."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class WAFMiddleware(BaseHTTPMiddleware):
    """Blocks requests that score at or above BLOCK_THRESHOLD on
    SQLi/XSS heuristics."""

    async def dispatch(self, request: Request, call_next):
        # Read body once. Starlette caches it for downstream handlers.
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

        score, matched = inspect_request_parts(
            method=request.method,
            path=request.url.path,
            query_string=request.url.query or "",
            content_type=request.headers.get("content-type", ""),
            body=body,
        )

        if score >= BLOCK_THRESHOLD:
            rule_summary = ",".join(sorted(set(matched))[:3])
            return JSONResponse(
                {
                    "error": "request blocked by WAF",
                    "reason": rule_summary,
                },
                status_code=403,
                headers={"X-WAF-Blocked": rule_summary},
            )

        return await call_next(request)
