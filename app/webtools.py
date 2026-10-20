"""Web reconnaissance helpers for puzzle and OSINT research.

These helpers exist because several public sources used by puzzle hunters are
protected by JavaScript anti-bot gates (Anubis, Cloudflare, …) that refuse
plain HTTP clients, and because content is frequently edited or removed after
publication. The functions here recover that material read-only:

* :func:`detect_antibot` — name the anti-bot gate in a fetched page.
* :func:`wayback_available` / :func:`wayback_snapshot_url` — find an archived
  copy of a URL in the Internet Archive.
* :func:`fetch_wayback` — fetch the archived copy (raw bytes optional).
* :func:`instagram_image` / :func:`extract_og_image` — pull the media URL out
  of an Instagram post page.
* :func:`parse_iptc_records` — surface the IPTC-NAA records hidden inside a
  Photoshop APP13/IRB blob (image viewers normally discard them).

Security model
--------------
Every outbound request goes through :func:`validate_url`, which refuses
non-http(s) schemes, URLs carrying credentials, and any destination that is
not a public IP address. Hostnames are resolved and *every* returned address
is checked, and the redirect handler re-validates each hop, so a redirect (or
a rebinding name) cannot smuggle a request to a private, loopback, link-local,
or cloud-metadata address. If the policy cannot be enforced the request is
refused rather than attempted.

Nothing here writes files, derives keys, signs, or broadcasts anything.
"""

from __future__ import annotations

import html as _html
import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

DEFAULT_TIMEOUT = 20

#: Hard cap on a single response body. Streaming reads abort past this.
MAX_BODY_BYTES = 1_000_000

#: Browser-like headers so ordinary sites serve real markup to us.
BROWSER_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

#: Signatures of anti-bot / JavaScript-challenge gates.
ANTIBOT_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    "Anubis": ("anubis", "techaro.lol", "within.website"),
    "Cloudflare": ("cf-browser-verification", "challenge-platform",
                   "cf_chl", "just a moment"),
    "PerimeterX": ("perimeterx", "px-captcha"),
    "DataDome": ("datadome", "ddjskey"),
    "Sucuri": ("sucuri", "x-sucuri-id"),
    "Imperva": ("incapsula", "visid_incap"),
}

Fetcher = Callable[[str, Dict[str, str], float], bytes]
Resolver = Callable[[str], Sequence[str]]

#: Internet Archive hosts we are willing to fetch an archived page from.
WAYBACK_HOSTS: Tuple[str, ...] = ("web.archive.org", "archive.org")

#: Fixed HTTPS endpoint for the availability API.
WAYBACK_AVAILABLE_URL = "https://archive.org/wayback/available"

_ALLOWED_SCHEMES = ("http", "https")

#: Destination ranges that must never be contacted: loopback, RFC1918 private
#: space, link-local, CGNAT, multicast, reserved, documentation nets, and the
#: IPv6 equivalents (including IPv4-mapped space).
_BLOCKED_NETWORKS: Tuple[Any, ...] = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",            # "this network"
        "10.0.0.0/8",           # RFC1918
        "100.64.0.0/10",        # carrier-grade NAT
        "127.0.0.0/8",          # loopback
        "169.254.0.0/16",       # link-local (incl. cloud metadata)
        "172.16.0.0/12",        # RFC1918
        "192.0.0.0/24",         # IETF protocol assignments
        "192.0.2.0/24",         # TEST-NET-1
        "192.168.0.0/16",       # RFC1918
        "198.18.0.0/15",        # benchmarking
        "198.51.100.0/24",      # TEST-NET-2
        "203.0.113.0/24",       # TEST-NET-3
        "224.0.0.0/4",          # multicast
        "240.0.0.0/4",          # reserved
        "255.255.255.255/32",   # broadcast
        "::/128",               # unspecified
        "::1/128",              # loopback
        "::ffff:0:0/96",        # IPv4-mapped IPv6
        "64:ff9b::/96",         # NAT64 well-known prefix
        "100::/64",             # discard-only
        "2001:db8::/32",        # documentation
        "fc00::/7",             # unique local
        "fe80::/10",            # link-local
        "ff00::/8",             # multicast
    )
)

#: MIME prefixes that clearly are not an HTML page. Anything unlisted (or a
#: missing Content-Type) is accepted so ordinary text/XML/JSON pages keep
#: working.
_DISALLOWED_MIME_PREFIXES: Tuple[str, ...] = (
    "image/", "video/", "audio/", "font/",
    "application/octet-stream", "application/pdf",
    "application/zip", "application/x-zip", "application/gzip",
    "application/x-gzip", "application/x-tar", "application/x-7z",
    "application/x-rar", "application/x-bzip", "application/x-xz",
    "application/x-msdownload", "application/x-shockwave-flash",
)


class UnsafeUrlError(ValueError):
    """Raised when a URL or response fails the fetch safety policy."""


# ---------------------------------------------------------------------------
# URL policy
# ---------------------------------------------------------------------------

def _default_resolver(hostname: str) -> List[str]:
    """Resolve *hostname* to a list of IP address strings."""
    return [str(info[4][0]) for info in socket.getaddrinfo(hostname, None)]


def _ip_is_prohibited(value: Any) -> bool:
    """True when *value* is an IP address we must never contact.

    IPv4-mapped and 6to4 IPv6 addresses are unwrapped first so their embedded
    IPv4 is checked against the IPv4 ranges.
    """
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        # Not an IP literal at all — treat as unsafe (defensive default).
        return True
    if addr.version == 6:
        unwrapped = (getattr(addr, "ipv4_mapped", None)
                     or getattr(addr, "sixtofour", None))
        if unwrapped is not None:
            addr = unwrapped
    return any(addr in net for net in _BLOCKED_NETWORKS)


def validate_url(
    url: Any,
    *,
    resolver: Optional[Resolver] = None,
    resolve: bool = True,
) -> None:
    """Raise :class:`UnsafeUrlError` unless *url* is a safe public http(s) URL.

    *resolver* replaces DNS in tests; by default the real resolver is used.
    Set *resolve* to ``False`` for a policy-only check on a URL that is never
    fetched (e.g. a link rendered into a message).
    """
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
    except ValueError as exc:
        raise UnsafeUrlError("malformed URL") from exc

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeUrlError("unsupported scheme")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("credentials are not allowed")
    if not parsed.hostname:
        raise UnsafeUrlError("missing hostname")

    host = parsed.hostname
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_prohibited(literal):
            raise UnsafeUrlError("prohibited IP address")
        return

    if not resolve:
        return

    lookup = resolver if resolver is not None else _default_resolver
    try:
        addresses = list(lookup(host))
    except Exception as exc:
        raise UnsafeUrlError("cannot resolve hostname") from exc
    if not addresses:
        raise UnsafeUrlError("cannot resolve hostname")
    for address in addresses:
        if _ip_is_prohibited(address):
            raise UnsafeUrlError("prohibited IP address")


def validate_public_https(
    url: Any, *, resolver: Optional[Resolver] = None
) -> None:
    """Like :func:`validate_url` but require HTTPS (for link-only URLs)."""
    if urllib.parse.urlsplit(str(url).strip()).scheme.lower() != "https":
        raise UnsafeUrlError("https is required")
    validate_url(url, resolver=resolver)


def _check_content_type(content_type: Optional[str]) -> None:
    """Reject clearly-binary responses when an HTML page was expected."""
    if not content_type:
        return
    mime = content_type.split(";", 1)[0].strip().lower()
    if any(mime.startswith(prefix) for prefix in _DISALLOWED_MIME_PREFIXES):
        raise UnsafeUrlError("unsupported content type")


def _read_bounded(resp: Any, max_bytes: int) -> bytes:
    """Read *resp* in bounded chunks, aborting past *max_bytes*."""
    chunks: List[bytes] = []
    total = 0
    while total <= max_bytes:
        chunk = resp.read(min(65536, max_bytes - total + 1))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
    raise UnsafeUrlError("response body exceeds limit")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that re-validates every hop before following it."""

    def __init__(self, resolver: Optional[Resolver] = None):
        self._resolver = resolver

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Fail closed: an unsafe redirect destination aborts the request.
        validate_url(newurl, resolver=self._resolver)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch_text(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    fetcher: Optional[Fetcher] = None,
    resolver: Optional[Resolver] = None,
    max_bytes: int = MAX_BODY_BYTES,
) -> str:
    """GET *url* and return the decoded body.

    The URL is validated before any request is made, and the response body is
    capped at *max_bytes*. *fetcher* and *resolver* exist for offline tests;
    both the URL policy and the size limit still apply on that path.
    """
    target = str(url).strip()
    validate_url(target, resolver=resolver)

    hdrs = dict(BROWSER_HEADERS)
    if headers:
        hdrs.update(headers)

    if fetcher is not None:
        raw = fetcher(target, hdrs, timeout)
        if len(raw) > max_bytes:
            raise UnsafeUrlError("response body exceeds limit")
        return raw.decode("utf-8", "replace")

    opener = urllib.request.build_opener(_SafeRedirectHandler(resolver))
    request = urllib.request.Request(target, headers=hdrs)
    with opener.open(request, timeout=timeout) as resp:
        _check_content_type(resp.headers.get("Content-Type"))
        return _read_bounded(resp, max_bytes).decode("utf-8", "replace")


def detect_antibot(text: Optional[str]) -> Optional[str]:
    """Return the name of an anti-bot gate present in *text*, else ``None``."""
    low = (text or "").lower()
    for name, needles in ANTIBOT_SIGNATURES.items():
        if any(needle in low for needle in needles):
            return name
    return None


def describe_antibot(text: Optional[str]) -> Optional[str]:
    """Human-readable note when *text* sits behind an anti-bot gate."""
    name = detect_antibot(text)
    if not name:
        return None
    return (
        f"⚠️ {name} anti-bot protection detected — plain HTTP clients are "
        f"blocked. Use an archived copy (/archive) instead."
    )


# ---------------------------------------------------------------------------
# Internet Archive
# ---------------------------------------------------------------------------

def _validate_snapshot_url(url: Any) -> None:
    """Require an HTTPS URL on a permitted Internet Archive host."""
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
    except ValueError as exc:
        raise UnsafeUrlError("malformed snapshot URL") from exc
    if parsed.scheme.lower() != "https":
        raise UnsafeUrlError("snapshot must use https")
    host = (parsed.hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in WAYBACK_HOSTS):
        raise UnsafeUrlError("snapshot host is not permitted")
    if not parsed.path.startswith("/web/"):
        raise UnsafeUrlError("snapshot path is not permitted")


def wayback_available(
    url: str, *, timeout: float = 15.0, fetcher: Optional[Fetcher] = None,
    resolver: Optional[Resolver] = None,
) -> Optional[Dict[str, Any]]:
    """Return the closest Wayback snapshot record for *url*, or ``None``."""
    endpoint = (
        WAYBACK_AVAILABLE_URL + "?" + urllib.parse.urlencode({"url": url})
    )
    try:
        payload = json.loads(fetch_text(
            endpoint, timeout=timeout, fetcher=fetcher, resolver=resolver
        ))
    except Exception:
        return None
    snap = (payload or {}).get("archived_snapshots", {}).get("closest")
    if isinstance(snap, dict) and snap.get("available"):
        return snap
    return None


def wayback_snapshot_url(
    url: str, *, raw: bool = False, timeout: float = 15.0,
    fetcher: Optional[Fetcher] = None, resolver: Optional[Resolver] = None,
) -> Optional[str]:
    """Return a Wayback URL for *url*, or ``None`` when it is not archived.

    With *raw*, the ``id_`` modifier yields the original bytes instead of the
    archive's instrumented copy (useful for images).
    """
    snap = wayback_available(url, timeout=timeout, fetcher=fetcher,
                             resolver=resolver)
    if not snap or not snap.get("url"):
        return None
    snapshot = str(snap["url"])
    try:
        _validate_snapshot_url(snapshot)
    except UnsafeUrlError:
        return None
    if raw and "/web/" in snapshot:
        head, _, tail = snapshot.partition("/web/")
        if "id_" not in tail:
            stamp, _, rest = tail.partition("/")
            snapshot = f"{head}/web/{stamp}id_/{rest}"
    return snapshot


def fetch_wayback(
    url: str, *, raw: bool = False, timeout: float = 45.0,
    fetcher: Optional[Fetcher] = None, resolver: Optional[Resolver] = None,
) -> Optional[str]:
    """Fetch the archived copy of *url* as text, or ``None`` on any failure."""
    snapshot = wayback_snapshot_url(url, raw=raw, timeout=20.0,
                                    fetcher=fetcher, resolver=resolver)
    if not snapshot:
        return None
    try:
        return fetch_text(snapshot, timeout=timeout, fetcher=fetcher,
                          resolver=resolver)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Open Graph / Instagram
# ---------------------------------------------------------------------------

_OG_IMAGE = re.compile(r'property="og:image"\s+content="([^"]+)"', re.I)
_OG_IMAGE_ALT = re.compile(r'content="([^"]+)"\s+property="og:image"', re.I)


def extract_og_image(page_html: Optional[str]) -> Optional[str]:
    """Pull the ``og:image`` URL out of a page's meta tags."""
    if not page_html:
        return None
    match = _OG_IMAGE.search(page_html) or _OG_IMAGE_ALT.search(page_html)
    if not match:
        return None
    return _html.unescape(match.group(1))


def instagram_image(page_html: Optional[str]) -> Optional[str]:
    """Extract the post media URL from an Instagram post or embed page.

    Instagram serves the post image through ``og:image``; the raw URL carries
    a signature that must be used verbatim (see :func:`fetch_text`).
    """
    return extract_og_image(page_html)


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def parse_iptc_records(data: bytes) -> List[Tuple[int, int, bytes]]:
    """Parse IPTC-NAA records out of a Photoshop APP13 (IRB) byte blob.

    Returns ``[(record, dataset, payload), ...]``. Each record is framed by
    ``0x1C <record> <dataset> <len_hi> <len_lo> <payload>``.
    """
    records: List[Tuple[int, int, bytes]] = []
    index = data.find(b"\x1c")
    while index != -1 and index + 5 <= len(data):
        record = data[index + 1]
        dataset = data[index + 2]
        length = int.from_bytes(data[index + 3:index + 5], "big")
        if length <= 0:
            break
        payload = data[index + 5:index + 5 + length]
        if len(payload) < length:
            break
        records.append((record, dataset, payload))
        index = data.find(b"\x1c", index + 5 + length)
    return records


def summarize_page(text: str, *, limit: int = 1200) -> str:
    """Collapse *text* into a short, tag-stripped plain-text excerpt.

    The result is **plain text** and must be escaped by the caller when it is
    inserted into an HTML-formatted message (see ``_archive_text``).
    """
    if not text:
        return ""
    stripped = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    stripped = re.sub(r"<style.*?</style>", " ", stripped, flags=re.S | re.I)
    stripped = re.sub(r"<!--.*?-->", " ", stripped, flags=re.S)
    stripped = re.sub(r"<[^>]+>", " ", stripped)
    stripped = _html.unescape(stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    return stripped[:limit]
