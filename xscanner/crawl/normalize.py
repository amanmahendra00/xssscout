from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# FIX: Added missing static extensions (.pdf, .zip, .tar, .gz, .eot, .ttf, .otf, .bmp, .tif)
STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".css",
    ".woff", ".woff2", ".eot", ".ttf", ".otf",
    ".mp4", ".mp3", ".webm", ".ogg", ".avi", ".mov",
    ".ico", ".pdf", ".zip", ".tar", ".gz", ".bz2",
    ".bmp", ".tiff", ".tif", ".swf", ".exe", ".dmg",
}

# FIX: Added more high-value parameter patterns and legacy markers
HIGH_VALUE_PARAMS = {
    "q", "s", "search", "query", "keyword", "term",
    "redirect", "url", "next", "return", "returnurl", "goto",
    "callback", "jsonp", "cb",
    "msg", "message", "text", "content", "body",
    "name", "title", "description",
    "id", "uid", "user", "username",
    "error", "err", "code",
    "ref", "referrer",
}

HIGH_VALUE_PATH_TOKENS = {
    "api", "admin", "legacy", "search", "login",
    "register", "upload", "callback", "redirect", "oauth",
    "v1", "v2", "v3", "graphql",
}


def should_skip(url: str) -> bool:
    """Return True for URLs that should not be scanned (static assets)."""
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def normalize_url(url: str) -> str:
    """
    Canonical form: lowercase scheme+host, sorted query params, no fragment.
    FIX: was missing lowercasing of path; also strips default ports.
    """
    parts = urlsplit(url.strip())
    netloc = parts.netloc.lower()
    # Strip default ports
    if netloc.endswith(":80") and parts.scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and parts.scheme == "https":
        netloc = netloc[:-4]
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))


def score_url(url: str) -> int:
    """
    Priority score — higher = scan sooner.
    FIX: was only checking for '?' in url; now checks individual params and path tokens.
    """
    parts = urlsplit(url.lower())
    score = 0

    # Parameterised URLs are highest value
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    if params:
        score += 15
        for p in params:
            if p in HIGH_VALUE_PARAMS:
                score += 5

    # High-value path tokens
    path_lower = parts.path.lower()
    for token in HIGH_VALUE_PATH_TOKENS:
        if token in path_lower:
            score += 3

    return score
