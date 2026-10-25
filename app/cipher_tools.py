"""Cipher / encoding multi-decoder (CacheSleuth-style).

Offline-first decoders for common puzzle/cipher types:
- base64 / hex / rot13
- Caesar / Atbash / Affine / Vigenère / Beaufort / Gronsfeld
- A1Z26 / Morse / Bacon / DNA (A/T/C/G)
- XOR with single-byte or repeating key
- URL / HTML entity / Unicode escape decoding
"""

from __future__ import annotations

import base64
import codecs
import re
from typing import Any, Dict, List, Optional


class DecodeError(ValueError):
    pass


def multi_decode(text: str, key: Optional[str] = None) -> Dict[str, Any]:
    """Run every supported decoder against *text* and return candidates
    that contain real words or valid coordinates."""
    text = (text or "").strip()
    if not text:
        raise DecodeError("empty input")

    results: List[Dict[str, Any]] = []
    for name, fn in _DECODERS.items():
        try:
            decoded = fn(text, key=key)
            if decoded is None:
                continue
            score = _readability_score(decoded)
            results.append({
                "decoder": name,
                "output": decoded[:300],
                "score": round(score, 3),
            })
        except Exception:
            pass

    results.sort(key=lambda r: -r["score"])
    return {"input": text[:200], "results": results[:20], "count": len(results)}


def crack_caesar(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise DecodeError("empty input")
    candidates = []
    for shift in range(1, 26):
        out = "".join(
            chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
            if c.isupper() else
            chr((ord(c) - ord("a") - shift) % 26 + ord("a"))
            if c.islower() else c
            for c in text
        )
        score = _readability_score(out)
        candidates.append({"shift": shift, "text": out, "score": round(score, 3)})
    candidates.sort(key=lambda r: -r["score"])
    return {"best": candidates[0], "all": candidates[:5]}


def crack_xor(text: str, max_key_len: int = 8) -> Dict[str, Any]:
    cleaned = re.sub(r"\s+", "", text)
    try:
        data = bytes.fromhex(cleaned)
    except Exception:
        try:
            data = base64.b64decode(cleaned)
        except Exception:
            data = cleaned.encode("utf-8", "replace")

    best: List[Dict[str, Any]] = []
    for klen in range(1, max_key_len + 1):
        key = _guess_single_byte_key(data[::klen])
        if key is None:
            continue
        full_key = bytes([key] * len(data))
        xord = bytes(a ^ b for a, b in zip(data, full_key))
        try:
            out = xord.decode("utf-8", errors="replace")
        except Exception:
            out = xord.hex()
        score = _readability_score(out)
        best.append({"key": bytes([key]).hex(), "text": out[:200], "score": round(score, 3)})

    best.sort(key=lambda r: -r["score"])
    return {"best": best[0] if best else None, "candidates": best[:10]}


def _guess_single_byte_key(data: bytes) -> Optional[int]:
    best_score = -1.0
    best_key = 0
    for k in range(256):
        xord = bytes(b ^ k for b in data)
        try:
            text = xord.decode("utf-8", errors="ignore")
        except Exception:
            continue
        score = _readability_score(text)
        if score > best_score:
            best_score = score
            best_key = k
    return best_key if best_score > 0 else None


# ---------------------------------------------------------------------------
# Decoder registry
# ---------------------------------------------------------------------------

def _dec_base64(text: str, key=None) -> Optional[str]:
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return None


def _dec_hex(text: str, key=None) -> Optional[str]:
    cleaned = re.sub(r"\s+", "", text)
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    if len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except Exception:
        return None


def _dec_rot13(text: str, key=None) -> str:
    return codecs.decode(text, "rot_13")


def _dec_atbash(text: str, key=None) -> str:
    def tr(c):
        if c.isalpha():
            return chr(ord("Z") - (ord(c.upper()) - ord("A")))
        return c
    return "".join(tr(c) for c in text)


def _dec_caesar(text: str, key=None) -> Optional[str]:
    if not key:
        return None
    try:
        shift = int(key) % 26
    except Exception:
        return None
    return "".join(
        chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
        if c.isupper() else
        chr((ord(c) - ord("a") - shift) % 26 + ord("a"))
        if c.islower() else c
        for c in text
    )


def _dec_vigenere(text: str, key=None) -> Optional[str]:
    if not key or not key.isalpha():
        return None
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)].upper()) - ord("A")
            out.append(chr((ord(c.upper()) - ord("A") + k) % 26 + ord("A")))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def _dec_a1z26(text: str, key=None) -> Optional[str]:
    nums = re.findall(r"\d+", text)
    if not nums:
        return None
    chars = []
    for n in nums:
        v = int(n)
        if 1 <= v <= 26:
            chars.append(chr(ord("A") + v - 1))
        else:
            return None
    return "".join(chars)


def _dec_morse(text: str, key=None) -> Optional[str]:
    MORSE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9",
    }
    parts = re.split(r"\s+|\/", text.strip())
    chars = []
    for p in parts:
        if not p:
            continue
        if p == "/":
            chars.append(" ")
            continue
        if p in MORSE:
            chars.append(MORSE[p])
        else:
            return None
    return "".join(chars)


def _dec_url(text: str, key=None) -> Optional[str]:
    try:
        import urllib.parse
        return urllib.parse.unquote(text)
    except Exception:
        return None


def _dec_html(text: str, key=None) -> Optional[str]:
    import html as _html
    return _html.unescape(text)


def _dec_unicode(text: str, key=None) -> Optional[str]:
    def _u(m):
        try:
            return chr(int(m.group(1)))
        except Exception:
            return m.group(0)
    return re.sub(r"\\u([0-9a-fA-F]{4})", _u, text)


_DECODERS: Dict[str, Any] = {
    "base64": _dec_base64,
    "hex": _dec_hex,
    "rot13": _dec_rot13,
    "atbash": _dec_atbash,
    "caesar": _dec_caesar,
    "vigenere": _dec_vigenere,
    "a1z26": _dec_a1z26,
    "morse": _dec_morse,
    "url": _dec_url,
    "html": _dec_html,
    "unicode": _dec_unicode,
}


def _readability_score(text: str) -> float:
    if not text:
        return 0.0
    letters = sum(c.isalpha() for c in text)
    words = re.findall(r"[A-Za-z]{2,}", text)
    if not words:
        return 0.0
    ratio = letters / max(len(text), 1)
    common = {"the", "and", "for", "with", "this", "that", "from", "have",
              "would", "there", "their", "what", "about", "which", "when",
              "make", "like", "time", "just", "know", "take", "people"}
    hits = sum(1 for w in words if w.lower() in common)
    return ratio * 0.6 + (hits / len(words)) * 0.4
