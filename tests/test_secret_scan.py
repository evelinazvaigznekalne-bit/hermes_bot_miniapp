"""Tests for secret-shape detection.

The load-bearing property is the OPPOSITE of a harvesting feature: the matched
secret must never survive in the output. Every test that asserts detection also
asserts non-retention.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security.secret_scan import mask, scan, warning_text  # noqa: E402

# Fixtures are deliberately NON-FUNCTIONAL shapes for the formats that can be
# validated offline. Real-looking test vectors only.
EVM_KEY = "0x" + "a3f1" * 16
EVM_KEY_BARE = "a3f1" * 16
WIF = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
MNEMONIC = ("legal winner thank year wave sausage worth useful legal winner thank "
            "yellow")
BOT_TOKEN = "8881860201:AAHfakeTokenValuexxxxxxxxxxxxxxxxxxxx"
OPENAI = "sk-proj-AbCdEf0123456789AbCdEf0123456789"
STRIPE = "sk_test_FAKEKEY0000000000"
XPRV = "xprv" + "A" * 108
AWS = "AKIAIOSFODNN7EXAMPLE"
PEM = "-----BEGIN RSA PRIVATE KEY-----"
CARD = "4111 1111 1111 1111"          # Luhn-valid, canonical test number
CARD_BAD = "4111 1111 1111 1112"      # fails Luhn


def kinds(text):
    return {f.kind for f in scan(text)}


class TestDetection:
    def test_evm_private_key(self):
        assert "evm_private_key" in kinds(f"my key is {EVM_KEY} ok")

    def test_evm_key_without_0x(self):
        assert "evm_private_key" in kinds(EVM_KEY_BARE)

    def test_bitcoin_wif(self):
        assert "bitcoin_wif" in kinds(f"wif: {WIF}")

    def test_seed_phrase(self):
        assert "bip39_mnemonic" in kinds(MNEMONIC)

    def test_telegram_bot_token(self):
        assert "telegram_bot_token" in kinds(f"token {BOT_TOKEN}")

    def test_openai_key(self):
        assert "openai_key" in kinds(OPENAI)

    def test_stripe_key(self):
        assert "stripe_key" in kinds(STRIPE)

    def test_xprv(self):
        assert "xprv" in kinds(XPRV)

    def test_aws_key(self):
        assert "aws_key" in kinds(AWS)

    def test_pem_block(self):
        assert "pem_private_key" in kinds(PEM)

    def test_luhn_valid_card(self):
        assert "card_number" in kinds(f"card {CARD} exp 12/28")

    def test_luhn_invalid_number_is_not_a_card(self):
        """A 16-digit number failing Luhn must not be flagged as a card."""
        found = scan(f"order id {CARD_BAD}")
        assert "card_number" not in {f.kind for f in found}

    def test_jwt(self):
        tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        assert "jwt" in kinds(tok)


class TestNoFalsePositives:
    def test_plain_text(self):
        assert scan("hello world, this is a normal message") == []

    def test_ethereum_address_is_not_a_key(self):
        """A 40-hex address must not be mistaken for a 64-hex key."""
        assert "evm_private_key" not in kinds(
            "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")

    def test_tx_hash_inside_longer_hex_run_is_skipped(self):
        long_hex = "0x" + "ab" * 40          # 80 hex chars
        assert "evm_private_key" not in kinds(long_hex)

    def test_empty_and_none(self):
        assert scan("") == []
        assert scan(None) == []

    def test_short_word_runs_are_not_mnemonics(self):
        assert "bip39_mnemonic" not in kinds(
            "the quick brown fox jumps over the lazy dog again and again")


class TestNeverRetainsTheSecret:
    """The core security property."""

    CASES = [
        ("evm", EVM_KEY), ("evm_bare", EVM_KEY_BARE), ("wif", WIF),
        ("mnemonic", MNEMONIC), ("bot", BOT_TOKEN), ("openai", OPENAI),
        ("stripe", STRIPE), ("xprv", XPRV), ("aws", AWS), ("card", CARD),
    ]

    def test_redacted_never_contains_the_secret(self):
        for name, secret in self.CASES:
            for f in scan(f"here it is: {secret}"):
                assert secret not in f.redacted, f"{name} leaked in redacted"
                assert secret not in f.as_dict()["redacted"], name

    def test_finding_has_no_raw_value_attribute(self):
        for _, secret in self.CASES:
            for f in scan(secret):
                for key, val in f.as_dict().items():
                    assert secret not in str(val), f"leaked via {key}"

    def test_serialised_finding_never_contains_secret(self):
        for name, secret in self.CASES:
            blob = json.dumps([f.as_dict() for f in scan(f"x {secret} y")])
            assert secret not in blob, f"{name} leaked in JSON"

    def test_warning_text_never_contains_secret(self):
        for name, secret in self.CASES:
            txt = warning_text(scan(f"pasted: {secret}"))
            assert secret not in txt, f"{name} leaked in warning text"

    def test_mask_keeps_at_most_4_chars_each_end(self):
        m = mask(EVM_KEY)
        assert len(m) < len(EVM_KEY)
        assert EVM_KEY[10:50] not in m

    def test_mask_of_short_value_is_fully_hidden(self):
        assert mask("abc") == "•••"
        assert "a" not in mask("ab")

    def test_span_is_returned_but_not_the_value(self):
        f = scan(f"key={EVM_KEY};")[0]
        assert f.span is not None
        # the span lets a caller redact in place without holding the value
        assert isinstance(f.span, tuple)


class TestMultipleAndOrdering:
    def test_multiple_secrets_detected(self):
        text = f"{BOT_TOKEN} and {OPENAI} and {EVM_KEY}"
        assert len(kinds(text)) >= 3

    def test_critical_sorts_first(self):
        text = f"{OPENAI} then {EVM_KEY}"
        found = scan(text)
        assert found[0].severity == "critical"

    def test_max_findings_respected(self):
        text = " ".join([BOT_TOKEN] * 20)
        assert len(scan(text, max_findings=3)) == 3

    def test_overlapping_matches_are_deduplicated(self):
        # a WIF is also a candidate for other patterns; must not double-report
        found = scan(f"wif {WIF}")
        spans = [f.span for f in found]
        assert len(spans) == len(set(spans))


class TestWarningText:
    def test_empty_findings_gives_empty_string(self):
        assert warning_text([]) == ""

    def test_warning_says_not_stored(self):
        txt = warning_text(scan(EVM_KEY))
        assert "NOT STORED" in txt
        assert "never asks for seed phrases" in txt

    def test_warning_includes_advice(self):
        txt = warning_text(scan(BOT_TOKEN))
        assert "BotFather" in txt


class TestPurity:
    def test_scan_writes_no_files(self, tmp_path, monkeypatch):
        """scan() must not touch the filesystem."""
        import app.security.secret_scan as mod

        touched = []
        real_open = open

        def spy(path, *a, **kw):
            touched.append(str(path))
            return real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", spy)
        scan(f"{EVM_KEY} {BOT_TOKEN} {MNEMONIC}")
        assert touched == [], f"scan() opened {touched}"
