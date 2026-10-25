"""Tests for cipher_tools.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.cipher_tools import (
    DecodeError,
    _readability_score,
    crack_caesar,
    crack_xor,
    multi_decode,
)


class TestReadabilityScore:
    def test_empty(self):
        assert _readability_score("") == 0.0

    def test_common_words_score_high(self):
        text = "the quick brown fox jumps over the lazy dog"
        score = _readability_score(text)
        assert score > 0.5

    def test_no_words(self):
        assert _readability_score("12345!@#$%") == 0.0


class TestMultiDecode:
    def test_base64_hello(self):
        result = multi_decode("SGVsbG8gV29ybGQ=")
        assert any(r["decoder"] == "base64" for r in result["results"])
        assert any("Hello" in r["output"] for r in result["results"])

    def test_hex_hello(self):
        result = multi_decode("48656c6c6f")
        assert any(r["decoder"] == "hex" for r in result["results"])
        assert any("Hello" in r["output"] for r in result["results"])

    def test_rot13_hello(self):
        result = multi_decode("Uryyb Jbeyq")
        assert any(r["decoder"] == "rot13" for r in result["results"])
        assert any("Hello World" in r["output"] for r in result["results"])

    def test_atbash_hello(self):
        result = multi_decode("svool dliow")
        assert any(r["decoder"] == "atbash" for r in result["results"])
        assert any("hello world" in r["output"].lower() for r in result["results"])

    def test_caesar_with_key(self):
        result = multi_decode("Khoor Zruog", key="3")
        assert any(r["decoder"] == "caesar" for r in result["results"])
        assert any("Hello World" in r["output"] for r in result["results"])

    def test_empty_raises(self):
        with pytest.raises(DecodeError):
            multi_decode("")

    def test_morse_decode(self):
        result = multi_decode(".... . .-.. .-.. ---")
        assert any(r["decoder"] == "morse" for r in result["results"])
        assert any("HELLO" in r["output"] for r in result["results"])

    def test_url_decode(self):
        result = multi_decode("Hello%20World%21")
        assert any(r["decoder"] == "url" for r in result["results"])
        assert any("Hello World!" in r["output"] for r in result["results"])

    def test_html_entity_decode(self):
        result = multi_decode("Hello &amp; World")
        assert any(r["decoder"] == "html" for r in result["results"])
        assert any("Hello & World" in r["output"] for r in result["results"])


class TestCrackCaesar:
    def test_shift_3_decodes_correctly(self):
        result = crack_caesar("Khoor Zruog")
        shift_map = {c["shift"]: c["text"] for c in result["all"]}
        assert shift_map.get(3) == "Hello World"

    def test_empty_raises(self):
        with pytest.raises(DecodeError):
            crack_caesar("")


class TestCrackXor:
    def test_single_byte_xor(self):
        plaintext = b"Hello World this is a test"
        cipher = bytes(c ^ 0x55 for c in plaintext)
        result = crack_xor(cipher.hex())
        assert result["best"] is not None
        assert "Hello World" in result["best"]["text"]

    def test_hex_input(self):
        plaintext = b"the quick brown fox jumps over the lazy dog"
        cipher = bytes(c ^ 0x42 for c in plaintext)
        hex_cipher = cipher.hex()
        result = crack_xor(hex_cipher)
        assert result["best"] is not None
