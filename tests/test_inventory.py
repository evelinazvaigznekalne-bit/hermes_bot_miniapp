"""Inventory tests.

The inventory reads a filesystem and produces something you might paste into a
chat, so two properties matter:

  * **Redaction.** Identifiers embedded in filenames (wallet addresses, onion
    hosts, long hex) must be masked by default, and the mask must not be
    reversible.
  * **Contents are never read.** The listing is metadata only; a file full of
    secrets must not leak any of them through the listing.

Also covered: the walk is bounded (depth, count, time), so it cannot hang, and
the owner-only gate on the API.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.inventory import (  # noqa: E402
    FileEntry,
    build_inventory,
    classify,
    human_size,
    redact_name,
    redact_value,
    render_listing,
    summarize,
)

BTC = "1F654t1HxrZtg7uhcXyZeFvRsyB8HCnBXJ"
EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
ONION = "pre77djyuj74wm4s53lnfto4qcpob3zvbxrxlcpiflorl27zbb4uk6yd.onion"
SECRET_TEXT = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"


# --- redaction --------------------------------------------------------------

class TestRedaction:
    def test_bitcoin_address_in_filename_is_masked(self):
        out = redact_name(f"{BTC}.dat")
        assert BTC not in out
        assert out.endswith(".dat")

    def test_evm_address_in_filename_is_masked(self):
        assert EVM not in redact_name(f"{EVM}.json")

    def test_onion_host_in_filename_is_masked(self):
        out = redact_name(f"{ONION}.txt")
        assert ONION not in out

    def test_long_hex_in_filename_is_masked(self):
        h = "a" * 64
        assert h not in redact_name(f"{h}.log")

    def test_ipv4_in_filename_is_masked(self):
        assert "144.124.239.226" not in redact_name("144.124.239.226.html")

    def test_email_in_filename_is_masked(self):
        assert "someone@example.com" not in redact_name("someone@example.com.txt")

    def test_ordinary_filename_is_untouched(self):
        assert redact_name("rockyou.txt") == "rockyou.txt"
        assert redact_name("pwd_v5_chunk3.txt") == "pwd_v5_chunk3.txt"

    def test_mask_keeps_a_recognisable_prefix_and_suffix(self):
        out = redact_name(f"{BTC}.dat")
        assert out.startswith(BTC[:6])
        assert BTC[-5:] in out

    def test_mask_is_not_reversible(self):
        out = redact_name(f"{BTC}.dat")
        assert len(out) < len(BTC) + 4

    def test_redact_value_masks_standalone_identifier(self):
        out = redact_value(BTC)
        assert BTC not in out
        assert out.startswith(BTC[:6])

    def test_redact_value_handles_empty(self):
        assert redact_value("") == ""

    def test_redact_value_handles_short(self):
        assert redact_value("abc") == "•••"


# --- no contents ------------------------------------------------------------

class TestContentsNeverRead:
    def test_secret_in_file_body_never_reaches_the_listing(self, tmp_path):
        secret_file = tmp_path / "notes.txt"
        secret_file.write_text(f"my key is {SECRET_TEXT}\n")
        result = build_inventory([str(tmp_path)], max_depth=2, hashes=False)
        blob = render_listing(result)
        assert SECRET_TEXT not in blob

    def test_listing_contains_only_metadata(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        result = build_inventory([str(tmp_path)], hashes=False)
        entry = result.entries[0]
        assert not hasattr(entry, "content")
        assert "hello" not in render_listing(result)

    def test_hash_is_optional(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        assert build_inventory([str(tmp_path)], hashes=False).entries[0].sha256 is None

    def test_hash_computed_when_requested(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        entry = build_inventory([str(tmp_path)], hashes=True).entries[0]
        assert entry.sha256 == ("2cf24dba5fb0a30e26e83b2ac5b9e29e"
                                "1b161e5c1fa7425e73043362938b9824")


# --- classification ---------------------------------------------------------

class TestClassification:
    def test_dat_is_a_wallet(self):
        assert classify(Path("wallet.dat"), "wallet.dat")[0] == "wallet"

    def test_rockyou_is_a_wordlist(self):
        assert classify(Path("rockyou.txt"), "rockyou.txt")[0] == "wordlist"

    def test_puzzle_file_is_a_puzzle(self):
        assert classify(Path("puzzles.json"), "puzzles.json")[0] == "puzzle"

    def test_telegram_export_is_osint(self):
        assert classify(Path("@keyhunters_messages.csv"),
                        "@keyhunters_messages.csv")[0] == "osint"

    def test_pdf_is_a_document(self):
        assert classify(Path("report.pdf"), "report.pdf")[0] == "document"

    def test_wallet_notes_document_is_osint(self):
        """A document ABOUT wallets is OSINT, not a generic document."""
        assert classify(Path("wallet_data.pdf"), "wallet_data.pdf")[0] == "osint"

    def test_escrow_notes_are_osint(self):
        assert classify(Path("escrows.txt"), "escrows.txt")[0] == "osint"

    def test_wallet_name_without_doc_ext_is_not_osint(self):
        """Precedence check: 'wallet' alone must not force the OSINT bucket."""
        assert classify(Path("wallet.bin"), "wallet.bin")[0] == "other"

    def test_py_is_code(self):
        assert classify(Path("main.py"), "main.py")[0] == "code"

    def test_unknown_is_other(self):
        assert classify(Path("blob.bin"), "blob.bin")[0] == "other"


# --- bounds -----------------------------------------------------------------

class TestBounds:
    def test_depth_is_respected(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "deep.txt").write_text("x")
        (tmp_path / "shallow.txt").write_text("x")
        result = build_inventory([str(tmp_path)], max_depth=1, hashes=False)
        names = [e.raw_name for e in result.entries]
        assert "shallow.txt" in names
        assert "deep.txt" not in names

    def test_file_limit_is_enforced(self, tmp_path):
        for i in range(30):
            (tmp_path / f"f{i}.txt").write_text("x")
        result = build_inventory([str(tmp_path)], max_files=10, hashes=False)
        assert len(result.entries) == 10
        assert result.truncated is True

    def test_time_budget_is_enforced(self, tmp_path):
        for i in range(200):
            (tmp_path / f"f{i}.txt").write_text("x")
        result = build_inventory([str(tmp_path)], time_budget=0.0, hashes=False)
        assert result.elapsed < 5.0

    def test_skip_dirs_are_not_walked(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "junk.js").write_text("x")
        (tmp_path / "keep.txt").write_text("x")
        result = build_inventory([str(tmp_path)], max_depth=3, hashes=False)
        names = [e.raw_name for e in result.entries]
        assert "keep.txt" in names
        assert "junk.js" not in names

    def test_missing_root_reports_an_error(self, tmp_path):
        result = build_inventory([str(tmp_path / "nope")], hashes=False)
        assert result.entries == []
        assert result.errors

    def test_hidden_files_excluded_by_default(self, tmp_path):
        (tmp_path / ".secret").write_text("x")
        (tmp_path / "visible.txt").write_text("x")
        result = build_inventory([str(tmp_path)], hashes=False)
        names = [e.raw_name for e in result.entries]
        assert "visible.txt" in names
        assert ".secret" not in names


# --- rendering --------------------------------------------------------------

class TestRendering:
    def test_listing_declares_redaction_state(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        out = render_listing(build_inventory([str(tmp_path)], hashes=False))
        assert "redaction   ON" in out

    def test_listing_says_no_contents_read(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        out = render_listing(build_inventory([str(tmp_path)], hashes=False))
        assert "no file contents were read" in out

    def test_max_rows_is_honoured(self, tmp_path):
        for i in range(50):
            (tmp_path / f"f{i}.txt").write_text("x")
        out = render_listing(build_inventory([str(tmp_path)], hashes=False),
                             max_rows=5)
        assert "more" in out

    def test_no_redact_shows_real_names(self, tmp_path):
        (tmp_path / f"{BTC}.dat").write_text("x")
        result = build_inventory([str(tmp_path)], hashes=False)
        assert BTC not in render_listing(result, redact=True)
        assert BTC in render_listing(result, redact=False)

    def test_summary_is_json_safe(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        blob = json.dumps(summarize(build_inventory([str(tmp_path)],
                                                    hashes=False)))
        assert "count" in blob

    def test_entry_dict_omits_path_when_redacted(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        entry = build_inventory([str(tmp_path)], hashes=False).entries[0]
        assert "path" not in entry.as_dict(redact=True)
        assert "path" in entry.as_dict(redact=False)


# --- human_size -------------------------------------------------------------

class TestHumanSize:
    @pytest.mark.parametrize("n,expected", [
        (0, "0 B"), (512, "512 B"), (1024, "1.0 KB"),
        (1536, "1.5 KB"), (1048576, "1.0 MB"),
    ])
    def test_sizes(self, n, expected):
        assert human_size(n) == expected


# --- API gate ---------------------------------------------------------------

class TestInventoryApiGate:
    """The endpoint is owner-only; non-owners must not learn it exists."""

    @pytest.fixture
    def api(self, settings, tracker):
        from app.chains.base import Asset, AssetReport
        from app.chains.registry import ChainRegistry
        from app.service import WalletService
        from app.webapp.server import MiniAppAPI

        class Stub:
            family = "evm"
            chain = "ethereum"
            label = "Ethereum"
            native_symbol = "ETH"

            def accepts(self, address):
                return True

            def validate(self, address):
                return address

            def explorer_url(self, address):
                return None

            def fetch_assets(self, address, *, limit=50):
                r = AssetReport(address=address, chain="ethereum", family="evm",
                                native_symbol="ETH", status="✓")
                r.assets.append(Asset(symbol="ETH", amount=1.0, raw="1",
                                      decimals=18))
                return r

        registry = ChainRegistry()
        registry.register(Stub())
        return MiniAppAPI(WalletService(settings, tracker=tracker,
                                        registry=registry), settings=settings)

    def test_missing_session_is_rejected(self, api):
        from app.errors import SignatureError
        with pytest.raises(SignatureError):
            api.inventory({})

    def test_invalid_session_is_rejected(self, api):
        from app.errors import SignatureError
        with pytest.raises(SignatureError):
            api.inventory({"session_token": "bogus"})

    def test_listing_endpoint_also_gated(self, api):
        from app.errors import SignatureError
        with pytest.raises(SignatureError):
            api.inventory_listing({})
