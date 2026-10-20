"""Web reconnaissance helper tests — fully offline, no network.

The Internet Archive and Instagram are never contacted: every HTTP call is
replaced with a deterministic fake fetcher, and DNS is replaced with a fake
resolver. The security tests below exercise the *policy* (scheme, credentials,
IP ranges, redirects, size caps) rather than live endpoints.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

from app.webtools import (
    MAX_BODY_BYTES,
    UnsafeUrlError,
    _check_content_type,
    _read_bounded,
    _SafeRedirectHandler,
    detect_antibot,
    describe_antibot,
    extract_og_image,
    fetch_text,
    fetch_wayback,
    instagram_image,
    parse_iptc_records,
    summarize_page,
    validate_public_https,
    validate_url,
    wayback_available,
    wayback_snapshot_url,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ANUBIS_PAGE = (
    "<html><head><title>Anubis</title></head><body>"
    "Proof-of-Work required. github.com/TecharoHQ/anubis"
    " techaro.lol within.website"
    "</body></html>"
)

CLOUDFLARE_PAGE = (
    "<html><body>cf-browser-verification challenge-platform "
    "Just a moment...</body></html>"
)

IG_PAGE = (
    '<html><head>'
    '<meta property="og:image" content="https://scontent.cdninstagram.com/v/'
    't51.82787-15/619562177_18078555959351369_591489700102169264_n.jpg'
    '?stp=c216.0.648.648a_dst-jpg_e35_s640x640_tt6&amp;_nc_cat=109">'
    "</head><body>post</body></html>"
)

IPTC_BLOB = (
    b"\x1c\x02\x28\x00\x0a"
    b"HELLOWORLD"
    b"\x1c\x02\x5f\x00\x06"
    b"ABC123"
)

#: A public address the fake resolver hands back for any hostname.
PUBLIC_IPS = ["93.184.216.34"]

#: Snapshot records. The availability API returns the snapshot URL verbatim.
SNAP_HTTPS = {
    "archived_snapshots": {
        "closest": {
            "available": True, "status": "200",
            "url": "https://web.archive.org/web/20260328203432/"
                   "https://example.com/page",
            "timestamp": "20260328203432",
        }
    }
}
SNAP_HTTP = {
    "archived_snapshots": {
        "closest": {
            "available": True, "status": "200",
            "url": "http://web.archive.org/web/20260328203432/"
                   "https://example.com/page",
            "timestamp": "20260328203432",
        }
    }
}
SNAP_FOREIGN_HOST = {
    "archived_snapshots": {
        "closest": {
            "available": True, "status": "200",
            "url": "https://evil.example/web/20260328203432/"
                   "https://example.com/page",
            "timestamp": "20260328203432",
        }
    }
}
SNAP_LOOKALIKE_HOST = {
    "archived_snapshots": {
        "closest": {
            "available": True, "status": "200",
            "url": "https://web.archive.org.evil.example/web/20260101/"
                   "https://example.com",
            "timestamp": "20260101000000",
        }
    }
}


def _public_resolver(hostname):
    return PUBLIC_IPS


def _loopback_resolver(hostname):
    return ["127.0.0.1"]


def _mixed_resolver(hostname):
    # One public, one private: the private address must veto the request.
    return ["93.184.216.34", "10.0.0.5"]


def _json_fetcher(mapping):
    """Build a fetcher that answers from *mapping* by URL prefix."""
    def fetch(url, headers, timeout):
        for prefix, payload in mapping.items():
            if url.startswith(prefix):
                return payload.encode() if isinstance(payload, str) else payload
        raise AssertionError(f"unexpected URL: {url}")
    return fetch


def _fake_response(chunks):
    """A minimal file-like object for :func:`_read_bounded`."""
    remaining = list(chunks)

    class _Resp:
        def read(self, size):
            return remaining.pop(0) if remaining else b""
    return _Resp()


# ---------------------------------------------------------------------------
# URL policy — schemes, credentials, hosts
# ---------------------------------------------------------------------------

def test_valid_public_https_url_accepted():
    validate_url("https://example.com/page", resolver=_public_resolver)


def test_valid_public_http_url_accepted():
    validate_url("http://example.com/page", resolver=_public_resolver)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/file",
    "data:text/html,<script>alert(1)</script>",
    "gopher://example.com/",
    "javascript:alert(1)",
    "mailto:someone@example.com",
    "telnet://example.com/",
    "not-a-url",
    "",
])
def test_unsupported_schemes_rejected(url):
    with pytest.raises(UnsafeUrlError):
        validate_url(url, resolver=_public_resolver)


@pytest.mark.parametrize("url", [
    "https://user:password@example.com/",
    "http://user@example.com/",
    "https://user:pa%40ss@example.com/page",
])
def test_credentials_in_url_rejected(url):
    with pytest.raises(UnsafeUrlError):
        validate_url(url, resolver=_public_resolver)


@pytest.mark.parametrize("url", [
    "https:///path-only",
    "https://",
    "https://:8080/",
])
def test_missing_hostname_rejected(url):
    with pytest.raises(UnsafeUrlError):
        validate_url(url, resolver=_public_resolver)


# ---------------------------------------------------------------------------
# URL policy — prohibited IP destinations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.1.2.3",          # loopback
    "10.0.0.5", "10.255.255.255",      # RFC1918
    "172.16.0.1", "172.31.255.255",    # RFC1918
    "192.168.1.1",                     # RFC1918
    "169.254.169.254",                 # link-local / cloud metadata
    "100.64.0.1",                      # CGNAT
    "0.0.0.0",                         # unspecified
    "224.0.0.1",                       # multicast
    "255.255.255.255",                 # broadcast
    "::1", "::",                       # IPv6 loopback / unspecified
    "fe80::1",                         # IPv6 link-local
    "fc00::1", "fd12:3456::1",         # IPv6 unique local
    "2001:db8::1",                     # documentation
    "::ffff:127.0.0.1",                # IPv4-mapped loopback
    "::ffff:10.0.0.1",                 # IPv4-mapped private
    "2002:7f00:1::",                   # 6to4 embedding 127.0.0.1
])
def test_prohibited_literal_addresses_rejected(host):
    # IPv6 literals must be bracketed in a URL; IPv4 literals are not.
    target = f"http://[{host}]/" if ":" in host else f"http://{host}/"
    with pytest.raises(UnsafeUrlError):
        validate_url(target, resolver=_public_resolver)


def test_hostname_resolving_to_loopback_rejected():
    with pytest.raises(UnsafeUrlError):
        validate_url("http://example.com/", resolver=_loopback_resolver)


def test_any_prohibited_resolved_address_vetoes():
    with pytest.raises(UnsafeUrlError):
        validate_url("http://example.com/", resolver=_mixed_resolver)


def test_unresolvable_hostname_rejected():
    def _boom(hostname):
        raise OSError("dns failure")
    with pytest.raises(UnsafeUrlError):
        validate_url("http://example.com/", resolver=_boom)


def test_validate_url_resolve_false_skips_dns():
    # Policy-only mode: no resolver call, still enforces scheme/IP literals.
    validate_url("http://example.com/", resolve=False)
    with pytest.raises(UnsafeUrlError):
        validate_url("http://127.0.0.1/", resolve=False)


def test_validate_public_https_requires_tls():
    validate_public_https("https://example.com/", resolver=_public_resolver)
    with pytest.raises(UnsafeUrlError):
        validate_public_https("http://example.com/", resolver=_public_resolver)


# ---------------------------------------------------------------------------
# fetch_text — policy, redirects, size, content type
# ---------------------------------------------------------------------------

def test_fetch_text_accepts_public_url():
    fetcher = _json_fetcher({"https://example.com/": "<p>hello</p>"})
    assert fetch_text("https://example.com/", fetcher=fetcher,
                      resolver=_public_resolver) == "<p>hello</p>"


def test_fetch_text_rejects_private_url():
    fetcher = _json_fetcher({"http://127.0.0.1/": "secret"})
    with pytest.raises(UnsafeUrlError):
        fetch_text("http://127.0.0.1/", fetcher=fetcher,
                   resolver=_public_resolver)


def test_fetch_text_rejects_file_scheme():
    with pytest.raises(UnsafeUrlError):
        fetch_text("file:///data/data/com.termux/files/home/.hermes/.env",
                   resolver=_public_resolver)


def test_fetch_text_enforces_size_limit_on_fetcher_path():
    body = "x" * (MAX_BODY_BYTES + 1)
    fetcher = _json_fetcher({"https://example.com/big": body})
    with pytest.raises(UnsafeUrlError):
        fetch_text("https://example.com/big", fetcher=fetcher,
                   resolver=_public_resolver)


def test_fetch_text_size_limit_boundary_allowed():
    body = "x" * MAX_BODY_BYTES
    fetcher = _json_fetcher({"https://example.com/ok": body})
    assert len(fetch_text("https://example.com/ok", fetcher=fetcher,
                          resolver=_public_resolver)) == MAX_BODY_BYTES


def test_read_bounded_aborts_past_limit():
    resp = _fake_response([b"a" * 100, b"b" * 100])
    with pytest.raises(UnsafeUrlError):
        _read_bounded(resp, 150)


def test_read_bounded_returns_full_body_within_limit():
    resp = _fake_response([b"a" * 100, b"b" * 50])
    assert _read_bounded(resp, 150) == b"a" * 100 + b"b" * 50


def test_read_bounded_ignores_content_length():
    # A lying Content-Length is irrelevant: the stream itself is capped.
    resp = _fake_response([b"a" * 1024] * 3)
    with pytest.raises(UnsafeUrlError):
        _read_bounded(resp, 1024)


@pytest.mark.parametrize("ctype", [
    "image/png", "video/mp4", "audio/mpeg", "font/woff2",
    "application/octet-stream", "application/pdf", "application/zip",
])
def test_binary_content_types_rejected(ctype):
    with pytest.raises(UnsafeUrlError):
        _check_content_type(ctype)


@pytest.mark.parametrize("ctype", [
    "text/html; charset=utf-8", "application/xhtml+xml",
    "text/plain", "application/json", "application/xml", "",
])
def test_text_content_types_allowed(ctype):
    _check_content_type(ctype)


def _request(url):
    return urllib.request.Request(url)


def test_redirect_to_prohibited_destination_rejected():
    handler = _SafeRedirectHandler(_public_resolver)
    with pytest.raises(UnsafeUrlError):
        handler.redirect_request(
            _request("https://example.com/a"), None, 302, "Found", {},
            "http://169.254.169.254/latest/meta-data/")


def test_redirect_to_private_hostname_rejected():
    handler = _SafeRedirectHandler(_loopback_resolver)
    with pytest.raises(UnsafeUrlError):
        handler.redirect_request(
            _request("https://example.com/a"), None, 302, "Found", {},
            "http://internal.example/")


def test_redirect_to_public_destination_allowed():
    handler = _SafeRedirectHandler(_public_resolver)
    result = handler.redirect_request(
        _request("https://example.com/a"), None, 302, "Found", {},
        "https://other.example/b")
    assert result is not None


# ---------------------------------------------------------------------------
# Internet Archive helpers
# ---------------------------------------------------------------------------

def test_wayback_available_hit():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available": json.dumps(SNAP_HTTPS)}
    )
    snap = wayback_available("https://example.com/page", fetcher=fetcher,
                             resolver=_public_resolver)
    assert snap is not None
    assert snap["timestamp"] == "20260328203432"


def test_wayback_available_miss():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available":
         json.dumps({"archived_snapshots": {}})}
    )
    assert wayback_available("https://nope.example/", fetcher=fetcher,
                             resolver=_public_resolver) is None


def test_wayback_snapshot_url_plain():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available": json.dumps(SNAP_HTTPS)}
    )
    url = wayback_snapshot_url("https://example.com/page", fetcher=fetcher,
                               resolver=_public_resolver)
    assert url == ("https://web.archive.org/web/20260328203432/"
                   "https://example.com/page")


def test_wayback_snapshot_url_raw_uses_id_modifier():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available": json.dumps(SNAP_HTTPS)}
    )
    url = wayback_snapshot_url("https://example.com/page", raw=True,
                               fetcher=fetcher, resolver=_public_resolver)
    assert url is not None
    assert "20260328203432id_/" in url


def test_wayback_snapshot_url_rejects_http():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available": json.dumps(SNAP_HTTP)}
    )
    assert wayback_snapshot_url("https://example.com/page", fetcher=fetcher,
                                resolver=_public_resolver) is None


def test_wayback_snapshot_url_rejects_foreign_host():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available": json.dumps(SNAP_FOREIGN_HOST)}
    )
    assert wayback_snapshot_url("https://example.com/page", fetcher=fetcher,
                                resolver=_public_resolver) is None


def test_wayback_snapshot_url_rejects_lookalike_host():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available":
         json.dumps(SNAP_LOOKALIKE_HOST)}
    )
    assert wayback_snapshot_url("https://example.com/", fetcher=fetcher,
                                resolver=_public_resolver) is None


def test_wayback_snapshot_url_none_when_unarchived():
    fetcher = _json_fetcher(
        {"https://archive.org/wayback/available":
         json.dumps({"archived_snapshots": {}})}
    )
    assert wayback_snapshot_url("https://nope/", fetcher=fetcher,
                                resolver=_public_resolver) is None


def test_fetch_wayback_returns_text():
    mapping = {
        "https://archive.org/wayback/available": json.dumps(SNAP_HTTPS),
        "https://web.archive.org/web/20260328203432/": "<p>archived body</p>",
    }
    fetcher = _json_fetcher(mapping)
    assert fetch_wayback("https://example.com/page", fetcher=fetcher,
                         resolver=_public_resolver) == "<p>archived body</p>"


# ---------------------------------------------------------------------------
# Open Graph / Instagram
# ---------------------------------------------------------------------------

def test_extract_og_image():
    url = extract_og_image(IG_PAGE)
    assert url is not None
    assert "cdninstagram.com" in url
    # HTML entities must be unescaped.
    assert "&amp;" not in url
    assert "&_nc_cat=109" in url


def test_extract_og_image_missing():
    assert extract_og_image("<html><body>no meta</body></html>") is None
    assert extract_og_image("") is None
    assert extract_og_image(None) is None


def test_instagram_image():
    url = instagram_image(IG_PAGE)
    assert url is not None
    assert "619562177_18078555959351369" in url


def test_instagram_image_returns_any_og_image():
    page = '<meta property="og:image" content="https://example.com/x.jpg">'
    assert instagram_image(page) == "https://example.com/x.jpg"


def test_instagram_image_missing():
    assert instagram_image("<html></html>") is None


# ---------------------------------------------------------------------------
# IPTC
# ---------------------------------------------------------------------------

def test_parse_iptc_records():
    records = parse_iptc_records(IPTC_BLOB)
    assert records == [
        (2, 0x28, b"HELLOWORLD"),
        (2, 0x5F, b"ABC123"),
    ]


def test_parse_iptc_records_empty():
    assert parse_iptc_records(b"") == []
    assert parse_iptc_records(b"no markers here") == []


# ---------------------------------------------------------------------------
# Summariser
# ---------------------------------------------------------------------------

def test_summarize_page_strips_tags_and_collapses():
    text = summarize_page("<html><body><p>  Hello   <b>world</b>  </p>"
                          "</body></html>")
    assert text == "Hello world"


def test_summarize_page_respects_limit():
    assert summarize_page("x" * 5000, limit=10) == "x" * 10


def test_summarize_page_empty():
    assert summarize_page("") == ""


# ---------------------------------------------------------------------------
# Bot command handlers (network mocked)
# ---------------------------------------------------------------------------

def _bare_bot():
    """A TelegramBot instance without running its constructor."""
    from app.telegram.bot import TelegramBot
    return TelegramBot.__new__(TelegramBot)


def test_archive_text_usage_without_args():
    assert "Usage" in _bare_bot()._archive_text([])


def test_ig_text_usage_without_args():
    assert "Usage" in _bare_bot()._instagram_text([])


def test_archive_text_reports_snapshot_and_body(monkeypatch):
    import app.telegram.bot as botmod

    monkeypatch.setattr(botmod, "wayback_available", lambda url: {
        "url": "https://web.archive.org/web/20260101000000/https://example.com",
        "timestamp": "20260101000000",
    })
    monkeypatch.setattr(botmod, "fetch_wayback", lambda url: "<p>hello</p>")
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)

    out = _bare_bot()._archive_text(["https://example.com"])
    assert "20260101000000" in out
    assert "hello" in out


def test_archive_text_no_snapshot(monkeypatch):
    import app.telegram.bot as botmod
    monkeypatch.setattr(botmod, "wayback_available", lambda url: None)

    out = _bare_bot()._archive_text(["https://example.com"])
    assert "No archived copy found" in out


def test_archive_text_reports_bot_gate(monkeypatch):
    import app.telegram.bot as botmod

    monkeypatch.setattr(botmod, "wayback_available", lambda url: {
        "url": "https://web.archive.org/web/20260101000000/https://x",
        "timestamp": "20260101000000",
    })
    monkeypatch.setattr(botmod, "fetch_wayback", lambda url: "<p>body</p>")
    monkeypatch.setattr(botmod, "describe_antibot",
                        lambda t: "⚠️ Anubis anti-bot protection detected")

    out = _bare_bot()._archive_text(["https://x"])
    assert "Anubis" in out


def test_archive_text_escapes_archived_markup(monkeypatch):
    """Entities in archived HTML must not become live Telegram markup."""
    import app.telegram.bot as botmod

    monkeypatch.setattr(botmod, "wayback_available", lambda url: {
        "url": "https://web.archive.org/web/20260101000000/https://x",
        "timestamp": "20260101000000",
    })
    # The archived page encodes a tag and an attribute payload as entities.
    body = ("&lt;b&gt;bold&lt;/b&gt; "
            "&lt;a href=&quot;javascript:alert(1)&quot;&gt;click&lt;/a&gt;")
    monkeypatch.setattr(botmod, "fetch_wayback", lambda url: body)
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)

    out = _bare_bot()._archive_text(["https://x"])

    # The excerpt is escaped: no raw tag from the archive survives. The
    # snapshot link's own <a href="..."> is intentional bot formatting.
    assert "<b>bold</b>" not in out
    assert 'href="javascript:' not in out
    assert "&lt;b&gt;bold&lt;/b&gt;" in out
    assert "&lt;a href=&quot;javascript:alert(1)&quot;&gt;" in out


def test_archive_text_does_not_double_escape_snapshot(monkeypatch):
    import app.telegram.bot as botmod

    snap_url = "https://web.archive.org/web/20260101000000/https://example.com"
    monkeypatch.setattr(botmod, "wayback_available",
                        lambda url: {"url": snap_url,
                                     "timestamp": "20260101000000"})
    monkeypatch.setattr(botmod, "fetch_wayback", lambda url: "<p>ok</p>")
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)

    out = _bare_bot()._archive_text(["https://example.com"])
    assert f'href="{snap_url}"' in out


def test_ig_text_returns_image(monkeypatch):
    import app.telegram.bot as botmod

    monkeypatch.setattr(botmod, "fetch_text", lambda url, timeout=20: IG_PAGE)
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)
    monkeypatch.setattr(botmod, "validate_public_https", lambda url: None)

    out = _bare_bot()._instagram_text(
        ["https://www.instagram.com/p/COz5r-0Ljui/"])
    assert "cdninstagram.com" in out
    assert "open image" in out


@pytest.mark.parametrize("url", [
    "https://example.com/p/abc/",
    "https://instagram.com.evil.example/p/abc/",
    "https://notinstagram.com/p/abc/",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "https://www.instagram.com/",
    "https://www.instagram.com/reels/",
    "not-a-url",
])
def test_ig_text_rejects_non_instagram_or_unsafe_urls(url, monkeypatch):
    import app.telegram.bot as botmod

    def _forbidden(*a, **k):
        pytest.fail("must not fetch an unapproved URL")

    monkeypatch.setattr(botmod, "fetch_text", _forbidden)

    out = _bare_bot()._instagram_text([url])
    assert "only Instagram post URLs are supported" in out


def test_ig_text_accepts_legitimate_subdomains(monkeypatch):
    import app.telegram.bot as botmod

    monkeypatch.setattr(botmod, "fetch_text", lambda url, timeout=20: IG_PAGE)
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)
    monkeypatch.setattr(botmod, "validate_public_https", lambda url: None)

    for url in ("https://m.instagram.com/p/ABC/",
                "https://www.instagram.com/reel/ABC/",
                "https://instagram.com/tv/ABC/"):
        out = _bare_bot()._instagram_text([url])
        assert "cdninstagram.com" in out


def test_ig_text_rejects_malicious_og_image(monkeypatch):
    import app.telegram.bot as botmod

    page = ('<meta property="og:image" '
            'content="http://169.254.169.254/latest/meta-data/">')
    monkeypatch.setattr(botmod, "fetch_text", lambda url, timeout=20: page)
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)
    # validate_public_https is deliberately NOT mocked: the real check must
    # reject the non-HTTPS, link-local image URL.
    out = _bare_bot()._instagram_text(
        ["https://www.instagram.com/p/ABC/"])
    assert "No media URL found" in out


def test_ig_text_no_media(monkeypatch):
    import app.telegram.bot as botmod

    monkeypatch.setattr(botmod, "fetch_text",
                        lambda url, timeout=20: "<html></html>")
    monkeypatch.setattr(botmod, "describe_antibot", lambda t: None)

    out = _bare_bot()._instagram_text(["https://www.instagram.com/p/ABC/"])
    assert "No media URL found" in out


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------

def test_register_commands_includes_archive_and_ig():
    captured = {}

    class _FakeClient:
        configured = True

        def call(self, method, payload=None):
            captured[method] = payload
            return True

    bot = _bare_bot()
    bot.client = _FakeClient()
    assert bot.register_commands() is True

    cmds = captured["setMyCommands"]["commands"]
    names = [c["command"] for c in cmds]

    assert "archive" in names
    assert "ig" in names
    # No duplicates, and the existing commands are untouched.
    assert len(names) == len(set(names))
    for existing in ("inspect", "puzzles", "scan", "image", "goal", "help"):
        assert existing in names

    by_name = {c["command"]: c for c in cmds}
    assert by_name["archive"]["description"]
    assert by_name["ig"]["description"]


# ---------------------------------------------------------------------------
# Anti-bot detection (regression guards)
# ---------------------------------------------------------------------------

def test_detect_antibot_anubis():
    assert detect_antibot(ANUBIS_PAGE) == "Anubis"


def test_detect_antibot_cloudflare():
    assert detect_antibot(CLOUDFLARE_PAGE) == "Cloudflare"


def test_detect_antibot_clean_page():
    assert detect_antibot("<html><body>Hello world</body></html>") is None


def test_detect_antibot_empty():
    assert detect_antibot("") is None
    assert detect_antibot(None) is None


def test_describe_antibot():
    note = describe_antibot(ANUBIS_PAGE)
    assert note is not None
    assert "Anubis" in note
    assert "/archive" in note


def test_describe_antibot_clean():
    assert describe_antibot("<p>plain</p>") is None
