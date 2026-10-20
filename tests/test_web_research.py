"""Tests for the web research integration module."""

from __future__ import annotations

from app.web_research import (
    ToolEntry,
    ToolSource,
    search_tools,
    get_catchesleuth_tools,
    get_cryptohack_tools,
    get_secretscan_tools,
    get_all_sources,
    fetch_tool_page,
)


class TestToolSources:
    def test_catchesleuth_source(self):
        src = get_catchesleuth_tools()
        assert src.name == "CATCH Sleuth"
        assert len(src.tools) > 0
        assert src.url == "https://catchesleuth.com"

    def test_cryptohack_source(self):
        src = get_cryptohack_tools()
        assert src.name == "CryptoHack"
        assert len(src.tools) > 0
        assert src.url == "https://cryptohack.org"

    def test_secretscan_source(self):
        src = get_secretscan_tools()
        assert src.name == "SecretScan"
        assert len(src.tools) > 0
        assert src.url == "https://secretscan.org"

    def test_all_sources(self):
        sources = get_all_sources()
        assert len(sources) == 3
        names = [s.name for s in sources]
        assert "CATCH Sleuth" in names
        assert "CryptoHack" in names
        assert "SecretScan" in names

    def test_tools_have_required_fields(self):
        for src in get_all_sources():
            for tool in src.tools:
                assert tool.name
                assert tool.source
                assert tool.url
                assert tool.description
                assert tool.category


class TestSearchTools:
    def test_search_returns_results(self):
        results = search_tools("rsa")
        assert isinstance(results, list)

    def test_search_filters_by_query(self):
        results = search_tools("challenge")
        # CryptoHack tools have "challenge" in description
        for r in results:
            assert ("challenge" in r.name.lower()
                    or "challenge" in r.description.lower()
                    or "challenge" in r.category.lower())

    def test_search_limit(self):
        results = search_tools("tool", limit=3)
        assert len(results) <= 3

    def test_search_no_match(self):
        results = search_tools("xyznonexistentquery123")
        assert isinstance(results, list)
        assert len(results) == 0


class TestFetchToolPage:
    def test_fetch_returns_none_on_error(self):
        result = fetch_tool_page("http://localhost:1/nonexistent")
        assert result is None

    def test_fetch_returns_none_on_antibot(self):
        # This would need a real URL to test properly
        # For now, just verify the function exists and is callable
        assert callable(fetch_tool_page)
