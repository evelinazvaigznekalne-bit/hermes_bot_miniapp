"""Tools backend: file analysis, hex decoding, sweep simulation.

All operations are read-only and local. No data leaves the device.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from .logging_setup import get_logger

log = get_logger()

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


# --- chi-square distribution (regularized incomplete gamma) ---------------
#
# The Westfeld chi-square attack needs a p-value, and getting the p-value right means
# getting the degrees of freedom right.  There are 128 value pairs, so df = 127 -- not 1.
# Using df = 1 (the single-pair case) makes every image look anomalous.


def _gammln(xx: float) -> float:
    """log(gamma(xx)) for xx > 0 (Lanczos-free, Numerical Recipes form)."""
    cof = (76.18009172947146, -86.50532032941677, 24.01409824083091,
           -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5)
    x = xx
    y = xx
    tmp = x + 5.5
    tmp -= (x + 0.5) * __import__("math").log(tmp)
    ser = 1.000000000190015
    for c in cof:
        y += 1.0
        ser += c / y
    return -tmp + __import__("math").log(2.5066282746310005 * ser / x)


def _gammp_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a, x), series expansion."""
    from math import exp, log
    if x <= 0.0:
        return 0.0
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(10000):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-15:
            break
    return total * exp(-x + a * log(x) - _gammln(a))


def _gammq_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x), continued fraction."""
    from math import exp, log
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return exp(-x + a * log(x) - _gammln(a)) * h


def _chi2_sf(x: float, df: int) -> float:
    """Survival function P(X >= x) for a chi-square variable with ``df`` degrees."""
    if df <= 0:
        return 1.0
    if x <= 0.0:
        return 1.0
    a = df / 2.0
    z = x / 2.0
    if z < a + 1.0:
        return 1.0 - _gammp_series(a, z)
    return _gammq_cf(a, z)


def _lsb_chi_square(values: list) -> Dict[str, Any]:
    """Westfeld chi-square attack on one channel's pixel values.

    Group the values into pairs ``(2i, 2i+1)``.  A natural image does not have equal
    counts in the two halves of a pair -- adjacent pixel values are correlated, so the
    low bit carries image structure.  Writing random data into the low bit destroys that
    structure and drives the two halves toward equality.

    The statistic is

        chi2 = sum_i (P(2i) - E_i)^2 / E_i ,   E_i = (P(2i) + P(2i+1)) / 2

    with ``df = usable_pairs - 1`` (127 for a full 8-bit channel).  The p-value is the
    upper-tail probability; a *small* p-value means the pairs are far more imbalanced
    than random, which is the natural-image case, while a *large* p-value means the pairs
    are as balanced as random data would make them.

    Read it as a screen, not a verdict: it has false positives (smooth gradients, heavy
    compression, already-random content) and false negatives (partial or adaptive
    embedding), and it says nothing about what -- if anything -- is hidden.
    """
    counts = [0] * 256
    for v in values:
        if 0 <= v < 256:
            counts[v] += 1

    chi2 = 0.0
    usable = 0
    for i in range(0, 256, 2):
        a, b = counts[i], counts[i + 1]
        expected = (a + b) / 2.0
        if expected <= 0:
            continue
        usable += 1
        chi2 += (a - expected) ** 2 / expected

    df = max(usable - 1, 1)
    p_value = _chi2_sf(chi2, df)

    return {
        "chi2": round(chi2, 2),
        "df": df,
        "pairs": usable,
        "p_value": round(p_value, 6),
        "balanced": p_value > 0.95,
        "suspicious": p_value > 0.95,
        "note": ("upper-tail p-value over df=127; a LARGE p means the pairs are as "
                 "balanced as random data would make them, a SMALL p means the low bit "
                 "still carries image structure"),
    }


def analyze_file(path: str) -> Dict[str, Any]:
    """Analyze a file from local storage. Read-only, size-limited."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    if p.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(f"file too large: {p.stat().st_size} bytes (max {MAX_FILE_SIZE})")

    data = p.read_bytes()
    size = len(data)

    # Detect file type
    file_type = "unknown"
    if data[:4] == b"\x62\x31\x05\x00" or data[:4] == b"\x00\x05\x31\x62":
        file_type = "bitcoin-core-wallet"
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        file_type = "dogecoin-wallet"
    elif data[:2] == b"\x1f\x8b":
        file_type = "gzip"
    elif data[:4] == b"\x28\xb5\x2f\xfd":
        file_type = "zstd"
    elif data[:4] == b"\x50\x4b\x03\x04":
        file_type = "zip"
    elif data[:4] == b"\x7f\x45\x4c\x46":
        file_type = "elf"
    elif data[:2] == b"\x4d\x5a":
        file_type = "pe"
    elif all(0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d) for b in data[:256]):
        file_type = "text"

    # Hash
    sha256 = hashlib.sha256(data).hexdigest()[:16]

    # Try to detect if it's a wallet
    is_wallet = file_type in ("bitcoin-core-wallet", "dogecoin-wallet")
    has_keys = b"ckey" in data or b"wkey" in data or b"mkey" in data

    analysis = f"""File: {p.name}
Type: {file_type}
Size: {size:,} bytes
SHA256: {sha256}…
Wallet: {'yes' if is_wallet else 'no'}
Encrypted keys: {'yes' if has_keys else 'no'}
Readable: {'yes' if file_type == 'text' else 'binary'}"""

    return {"analysis": analysis, "size": size, "type": file_type}


def decode_data(data: str) -> Dict[str, Any]:
    """Decode hex, base64, or plain text."""
    data = data.strip()

    # Try hex
    if re.match(r'^[0-9a-fA-F\s]+$', data) and len(data) >= 4:
        try:
            hex_clean = re.sub(r'\s+', '', data)
            if len(hex_clean) % 2 == 0:
                decoded = bytes.fromhex(hex_clean)
                try:
                    text = decoded.decode('utf-8')
                    return {"result": f"Encoding: hex → UTF-8\n\n{text}", "encoding": "hex"}
                except UnicodeDecodeError:
                    return {"result": f"Encoding: hex → binary\n\n{decoded[:64].hex()}…", "encoding": "hex"}
        except (ValueError, binascii.Error):
            pass

    # Try base64
    try:
        decoded = base64.b64decode(data)
        try:
            text = decoded.decode('utf-8')
            return {"result": f"Encoding: base64 → UTF-8\n\n{text}", "encoding": "base64"}
        except UnicodeDecodeError:
            return {"result": f"Encoding: base64 → binary\n\n{decoded[:64].hex()}…", "encoding": "base64"}
    except Exception:
        pass

    # Plain text
    return {"result": f"Encoding: plain text\n\n{data[:500]}", "encoding": "text"}


def analyze_data(data: str) -> Dict[str, Any]:
    """Analyze data for patterns, secrets, and structure."""
    data = data.strip()
    lines = []

    # Length
    lines.append(f"Length: {len(data)} chars")

    # Character distribution
    hex_chars = sum(1 for c in data if c in '0123456789abcdefABCDEF')
    printable = sum(1 for c in data if c.isprintable())
    lines.append(f"Hex chars: {hex_chars} ({100*hex_chars//max(len(data),1)}%)")
    lines.append(f"Printable: {printable} ({100*printable//max(len(data),1)}%)")

    # Detect patterns
    if re.match(r'^[0-9a-fA-F]+$', data):
        lines.append("Pattern: pure hex")
        if len(data) == 64:
            lines.append("  → possible private key (32 bytes)")
        elif len(data) == 128:
            lines.append("  → possible keystore key")
    elif re.match(r'^[A-Za-z0-9+/=]+$', data):
        lines.append("Pattern: base64")
    elif ' ' in data and len(data.split()) in (12, 15, 18, 21, 24):
        words = data.split()
        lines.append(f"Pattern: {len(words)} words (possible mnemonic)")

    # Check for secrets
    if re.search(r'[0-9a-fA-F]{40,}', data):
        lines.append("⚠ Contains long hex string (possible key)")
    if re.search(r'0x[0-9a-fA-F]{40,}', data):
        lines.append("⚠ Contains Ethereum address")

    return {"result": "\n".join(lines)}


def simulate_sweep(from_addr: str, to_addr: str) -> Dict[str, Any]:
    """Simulate a sweep transaction. Read-only, no execution."""
    lines = [
        "Sweep simulation (read-only)",
        "=" * 40,
        f"From: {from_addr}",
        f"To:   {to_addr}",
        "",
        "Steps:",
        "  1. Verify destination address format",
        "  2. Check source balance (read-only)",
        "  3. Estimate gas fee",
        "  4. Build unsigned transaction",
        "  5. Sign with private key (requires wallet)",
        "  6. Broadcast to network",
        "",
        "⚠ This is a simulation. No transaction was created.",
        "⚠ No funds were moved.",
    ]
    return {"result": "\n".join(lines)}


def _load_puzzles() -> list:
    """Load OCP puzzle corpus."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "ocp", "puzzles.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data.get("puzzles", [])
    except (json.JSONDecodeError, IOError):
        return []


def crack_puzzle(puzzle_id: str, password: str,
                 catalog: Any = None) -> Dict[str, Any]:
    """Attempt to crack a puzzle with a password. Read-only, local only.

    Tries common transformations of the password against the puzzle's
    criteria and returns whether any transformation produced a match.
    """
    if not puzzle_id:
        return {"result": "Error: puzzle_id is required", "match": False,
                "status": "✗"}
    if not password:
        return {"result": "Error: password is required", "match": False,
                "status": "✗"}

    # Load puzzle data if catalog is provided
    puzzle_data = None
    if catalog is not None:
        try:
            from .access import Tier
            puzzle_data = catalog.item_detail(Tier.PAID, puzzle_id)
        except Exception:
            pass

    # If catalog lookup failed, try loading from OCP directly
    if puzzle_data is None:
        try:
            puzzles = _load_puzzles()
            for p in puzzles:
                if (p.get("slug") == puzzle_id or
                    p.get("title") == puzzle_id or
                    puzzle_id in p.get("slug", "") or
                    puzzle_id in p.get("title", "")):
                    puzzle_data = p
                    break
        except Exception:
            pass

    # Common transformations to try
    transformations = {
        "original": password,
        "reversed": password[::-1],
        "lowercase": password.lower(),
        "uppercase": password.upper(),
        "title_case": password.title(),
        "no_spaces": password.replace(" ", ""),
        "underscores": password.replace(" ", "_"),
        "hyphens": password.replace(" ", "-"),
        "base64_decoded": "",
        "hex_decoded": "",
    }

    # Try base64 decode
    try:
        import base64
        decoded = base64.b64decode(password)
        transformations["base64_decoded"] = decoded.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Try hex decode
    try:
        hex_clean = re.sub(r'\s+', '', password)
        if len(hex_clean) % 2 == 0 and re.match(r'^[0-9a-fA-F\s]+$', password):
            decoded = bytes.fromhex(hex_clean)
            transformations["hex_decoded"] = decoded.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Check against puzzle criteria
    match_found = False
    match_details = []
    criteria = {}

    if puzzle_data:
        criteria = puzzle_data.get("criteria", {})
        # Check if password matches any hint text
        hints = puzzle_data.get("hints", [])
        for hint in hints:
            hint_lower = hint.lower()
            for tname, tval in transformations.items():
                if tval and (tval.lower() in hint_lower or hint_lower in tval.lower()):
                    match_found = True
                    match_details.append(f"Transformation '{tname}' matches hint: {hint[:50]}")

        # Check if password matches the puzzle title
        title = puzzle_data.get("title", "")
        if title:
            title_lower = title.lower()
            for tname, tval in transformations.items():
                if tval and (tval.lower() in title_lower or title_lower in tval.lower()):
                    match_found = True
                    match_details.append(f"Transformation '{tname}' matches title: {title}")

    # Build result
    lines = [
        "Puzzle crack attempt (read-only)",
        "=" * 40,
        f"Puzzle: {puzzle_id}",
        f"Password: {'*' * len(password)}",
        "",
        "Transformations tried:",
    ]
    for tname, tval in transformations.items():
        if tval:
            lines.append(f"  • {tname}: {tval[:50]}{'...' if len(tval) > 50 else ''}")

    if match_found:
        lines.append("")
        lines.append("✓ MATCH FOUND:")
        for detail in match_details:
            lines.append(f"  • {detail}")
    else:
        lines.append("")
        lines.append("✗ No match found")

    if puzzle_data:
        lines.append("")
        lines.append(f"Puzzle title: {puzzle_data.get('title', 'N/A')}")
        lines.append(f"Chain: {puzzle_data.get('category', 'N/A')}")
        lines.append(f"Status: {puzzle_data.get('status', 'N/A')}")

    lines.append("")
    lines.append("⚠ This is a local attempt. No data was sent anywhere.")

    return {
        "result": "\n".join(lines),
        "match": match_found,
        "status": "✓" if match_found else "✗",
        "transformations_tried": len([v for v in transformations.values() if v]),
        "puzzle_found": puzzle_data is not None,
        "puzzle_title": puzzle_data.get("title") if puzzle_data else None,
        "puzzle_chain": puzzle_data.get("chain") if puzzle_data else None,
        "puzzle_status": puzzle_data.get("status") if puzzle_data else None,
        "leads_count": len(puzzle_data.get("leads", [])) if puzzle_data else 0,
    }


def analyze_image(filename: str = "", base64_data: str = "") -> Dict[str, Any]:
    """Analyze an image for hidden data. Read-only, local only.

    Performs:
    - File type detection (magic bytes)
    - LSB steganography detection
    - Metadata extraction (basic EXIF for JPEG)
    - Entropy analysis (encrypted vs plain)
    """
    # Get raw bytes
    data = b""
    source_name = filename or "base64_data"

    if base64_data:
        try:
            data = base64.b64decode(base64_data)
        except Exception as exc:
            return {"result": f"Error decoding base64: {exc}", "status": "✗"}
    elif filename:
        p = Path(filename).expanduser()
        if not p.is_file():
            return {"result": f"File not found: {filename}", "status": "✗"}
        if p.stat().st_size > MAX_FILE_SIZE:
            return {"result": f"File too large: {p.stat().st_size} bytes", "status": "✗"}
        data = p.read_bytes()
        source_name = p.name

    if not data:
        return {"result": "No image data provided", "status": "✗"}

    size = len(data)

    # File type detection
    file_type = "unknown"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        file_type = "png"
    elif data[:2] == b"\xff\xd8":
        file_type = "jpeg"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        file_type = "gif"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        file_type = "webp"
    elif data[:4] == b"\x00\x00\x01\x00":
        file_type = "ico"
    elif data[:4] == b"\x00\x00\x02\x00":
        file_type = "cur"
    elif data[:2] == b"BM":
        file_type = "bmp"
    elif data[:4] == b"\x49\x49\x2a\x00" or data[:4] == b"\x4d\x4d\x00\x2a":
        file_type = "tiff"
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        file_type = "dogecoin-wallet"
    elif data[:4] == b"\x50\x4b\x03\x04":
        file_type = "zip"

    # LSB steganography detection -- over DECODED PIXELS, never file bytes.
    #
    # The previous implementation read the first 1000 *file* bytes.  That is meaningless
    # for every format this branch claims to cover: a PNG's first kilobyte is a container
    # header plus a compressed IDAT stream, and a JPEG's is a marker table plus entropy-
    # coded data.  Their bit distribution says nothing about steganography, so the old
    # ratio test was measuring the container, not the image.
    #
    # What follows is the published Westfeld chi-square attack: LSB embedding forces the
    # two members of each pixel-value pair (2i, 2i+1) toward equal frequency, which a
    # natural image does not have.  It is a statistical test -- it has false positives and
    # false negatives, and it says nothing about *what* is embedded.
    lsb_detected = False
    lsb_details = []
    lsb_analysis: Dict[str, Any] = {}

    pixels = None
    if file_type in ("png", "bmp", "tiff", "jpeg", "gif", "webp"):
        try:
            import io

            from PIL import Image

            with Image.open(io.BytesIO(data)) as im:
                im = im.convert("RGB")
                # Sample a bounded number of pixels: the statistic needs enough counts
                # per pair to mean anything, not the whole image.
                w, h = im.size
                pixels = list(im.getdata())[:200_000]
                lsb_details.append(f"decoded {w}x{h} {file_type.upper()}, "
                                   f"analysing {len(pixels):,} pixels")
        except Exception as exc:
            lsb_details.append(f"could not decode image for pixel analysis: "
                               f"{type(exc).__name__}: {exc}")
    else:
        lsb_details.append(f"pixel LSB analysis not applicable for {file_type}")

    if pixels:
        for idx, channel in enumerate(("red", "green", "blue")):
            values = [px[idx] for px in pixels]
            stat = _lsb_chi_square(values)
            lsb_analysis[channel] = stat
            if stat["balanced"]:
                verdict = "as balanced as random data (look closer)"
            else:
                verdict = "low bit still carries image structure"
            lsb_details.append(
                f"{channel}: chi2={stat['chi2']:.1f} df={stat['df']} "
                f"p={stat['p_value']:.4f} -- {verdict}")
            if stat["suspicious"]:
                lsb_detected = True
        # Container-level signatures are still worth reporting, but as a separate,
        # weaker signal than a pixel statistic.
        if b"steg" in data[:5000].lower():
            lsb_detected = True
            lsb_details.append("found 'steg' string in the first 5KB")

    # Metadata extraction
    metadata = {}
    if file_type == "jpeg":
        # Basic EXIF extraction
        if data[:2] == b"\xff\xd8":
            metadata["format"] = "JPEG"
            # Look for APP1 marker (EXIF)
            idx = 2
            while idx < min(len(data) - 4, 65536):
                if data[idx] == 0xFF:
                    marker = data[idx + 1]
                    if marker == 0xE1:  # APP1
                        length = (data[idx + 2] << 8) | data[idx + 3]
                        exif_data = data[idx + 4:idx + 2 + length]
                        if b"Exif" in exif_data[:10]:
                            metadata["exif"] = True
                            # Extract basic EXIF fields
                            if b"Make" in exif_data:
                                make_start = exif_data.index(b"Make") + 5
                                make_end = exif_data.index(b"\x00", make_start)
                                metadata["make"] = exif_data[make_start:make_end].decode("ascii", errors="replace")
                            if b"Model" in exif_data:
                                model_start = exif_data.index(b"Model") + 6
                                model_end = exif_data.index(b"\x00", model_start)
                                metadata["model"] = exif_data[model_start:model_end].decode("ascii", errors="replace")
                        break
                    elif marker == 0xD9:  # EOI
                        break
                    elif marker == 0xDA:  # SOS - start of scan
                        break
                    elif marker == 0xD8:  # SOI
                        idx += 2
                        continue
                    elif marker == 0x01 or (0xD0 <= marker <= 0xD7):
                        idx += 2
                        continue
                    else:
                        if idx + 3 < len(data):
                            length = (data[idx + 2] << 8) | data[idx + 3]
                            idx += 2 + length
                        else:
                            break
                else:
                    idx += 1
    elif file_type == "png":
        metadata["format"] = "PNG"
        # Check for tEXt, iTXt, zTXt chunks
        if b"tEXt" in data[:65536]:
            metadata["text_chunks"] = True
        if b"iTXt" in data[:65536]:
            metadata["international_text_chunks"] = True
        if b"zTXt" in data[:65536]:
            metadata["compressed_text_chunks"] = True
    elif file_type == "gif":
        metadata["format"] = "GIF"
    elif file_type == "webp":
        metadata["format"] = "WebP"

    # Entropy analysis
    if size > 0:
        import math
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / size
                entropy -= p * math.log2(p)
        metadata["entropy"] = round(entropy, 2)
        metadata["entropy_assessment"] = (
            "high (possibly encrypted/compressed)" if entropy > 7.5
            else "medium (possibly compressed)" if entropy > 6.0
            else "low (likely plain text or simple image)"
        )

    # Build result
    lines = [
        "Image analysis (read-only)",
        "=" * 40,
        f"File: {source_name}",
        f"Type: {file_type}",
        f"Size: {size:,} bytes",
        "",
        "Steganography detection:",
    ]
    for detail in lsb_details:
        lines.append(f"  • {detail}")

    lines.append("")
    lines.append("Metadata:")
    if metadata:
        for key, value in metadata.items():
            lines.append(f"  • {key}: {value}")
    else:
        lines.append("  • No metadata found")

    lines.append("")
    lines.append("⚠ This is a local analysis. No data was sent anywhere.")

    return {
        "result": "\n".join(lines),
        "status": "✓",
        "file_type": file_type,
        "size": size,
        "lsb_detected": lsb_detected,
        "lsb_analysis": lsb_analysis,
        "metadata": metadata,
    }


def validate_seed_phrase(phrase: str) -> Dict[str, Any]:
    """Validate a BIP39 seed phrase (checksum + wordlist verification).

    Returns dict with valid, word_count, and error details.
    """
    from mnemonic import Mnemonic

    result: Dict[str, Any] = {"valid": False, "word_count": 0, "error": None}

    words = phrase.strip().lower().split()
    result["word_count"] = len(words)

    if len(words) not in (12, 15, 18, 21, 24):
        result["error"] = f"Invalid word count: {len(words)} (expected 12, 15, 18, 21, or 24)"
        return result

    m = Mnemonic("english")
    invalid_words = [w for w in words if w not in m.wordlist]
    if invalid_words:
        result["error"] = f"Words not in BIP39 wordlist: {', '.join(invalid_words[:5])}"
        return result

    if not m.check(phrase):
        result["error"] = "Checksum verification failed — invalid seed phrase"
        return result

    result["valid"] = True
    return result


def derive_addresses(phrase: str, passphrase: str = "",
                    count: int = 5) -> Dict[str, Any]:
    """Derive BTC and ETH addresses from a BIP39 seed phrase.

    Uses BIP44 paths:
      BTC: m/44'/0'/0'/0/i  (P2PKH + P2WPKH)
      ETH: m/44'/60'/0'/0/i

    Returns dict with btc and eth address lists.
    """
    import hmac as hmac_mod
    from hashlib import sha256, sha512, pbkdf2_hmac
    from coincurve import PrivateKey, PublicKey
    from Crypto.Hash import keccak as _keccak
    import base58
    import bech32

    result: Dict[str, Any] = {"btc": [], "eth": [], "error": None}

    try:
        from mnemonic import Mnemonic
        m = Mnemonic("english")
        if not m.check(phrase):
            result["error"] = "Invalid seed phrase (checksum failed)"
            return result

        seed_bytes = m.to_seed(phrase, passphrase)
    except Exception as e:
        result["error"] = f"Seed derivation failed: {e}"
        return result

    # BIP32 master key derivation
    I = hmac_mod.new(b"Bitcoin seed", seed_bytes, sha512).digest()
    master_priv = I[:32]
    master_chain = I[32:]

    def _ckd_priv(priv: bytes, chain: bytes, index: int) -> tuple:
        """BIP32 CKD_priv: derive child private key + chain code."""
        if index >= 0x80000000:  # hardened
            data = b"\x00" + priv + index.to_bytes(4, "big")
        else:
            pub = PrivateKey(priv).public_key.format(compressed=True)
            data = pub + index.to_bytes(4, "big")
        I2 = hmac_mod.new(chain, data, sha512).digest()
        child_priv = (int.from_bytes(I2[:32], "big") +
                      int.from_bytes(priv, "big")) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return child_priv.to_bytes(32, "big"), I2[32:]

    def _derive_path(path: list) -> bytes:
        """Derive private key at given BIP44 path (list of indices)."""
        priv, chain = master_priv, master_chain
        for idx in path:
            priv, chain = _ckd_priv(priv, chain, idx)
        return priv

    def _btc_p2pkh(pub_key: bytes) -> str:
        """Legacy P2PKH address (1...)."""
        sha = sha256(pub_key).digest()
        # RIPEMD160
        from hashlib import new as _new
        ripe = _new("ripemd160", sha).digest()
        payload = b"\x00" + ripe
        checksum = sha256(sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()

    def _btc_p2wpkh(pub_key: bytes) -> str:
        """Native SegWit P2WPKH address (bc1...)."""
        from hashlib import new as _new
        sha = sha256(pub_key).digest()
        ripe = _new("ripemd160", sha).digest()
        # bech32 encode with witness version 0
        return bech32.encode("bc", 0, ripe)

    def _eth_addr(pub_key: bytes) -> str:
        """Ethereum address from uncompressed public key (65 bytes, 0x04 prefix)."""
        # Remove 0x04 prefix, keccak256, last 20 bytes
        k = _keccak.new(digest_bits=256)
        k.update(pub_key[1:])
        addr = k.hexdigest()[-40:]
        return "0x" + addr

    H = 0x80000000  # hardened offset

    for i in range(count):
        # BTC: m/44'/0'/0'/0/i
        btc_path = [H + 44, H + 0, H + 0, 0, i]
        btc_priv = _derive_path(btc_path)
        btc_pub = PrivateKey(btc_priv).public_key.format(compressed=True)
        result["btc"].append({
            "index": i,
            "path": f"m/44'/0'/0'/0/{i}",
            "p2pkh": _btc_p2pkh(btc_pub),
            "p2wpkh": _btc_p2wpkh(btc_pub),
        })

        # ETH: m/44'/60'/0'/0/i
        eth_path = [H + 44, H + 60, H + 0, 0, i]
        eth_priv = _derive_path(eth_path)
        eth_pub = PrivateKey(eth_priv).public_key.format(compressed=True)
        result["eth"].append({
            "index": i,
            "path": f"m/44'/60'/0'/0/{i}",
            "address": _eth_addr(eth_pub),
        })

    return result


def crack_list(catalog: Any, *, chain: Optional[str] = None,
               status: Optional[str] = None, search: Optional[str] = None,
               limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """List puzzles from the catalog with filtering and search.

    Shows puzzle title, chain, status, and hints count.
    Supports filtering by chain/status and search by title.
    """
    if catalog is None:
        return {"items": [], "count": 0, "total": 0, "offset": offset,
                "limit": limit, "error": "No catalog provided"}

    from .access import Tier
    from .catalog import _chain_of, _status_of

    tier = Tier.PAID  # Use PAID tier to see all puzzles
    entries = catalog._entries_for(tier)

    # Apply filters
    if chain:
        want = chain.strip().lower()
        entries = [e for e in entries if _chain_of(e) == want]
    if status:
        want = status.strip().lower()
        entries = [e for e in entries if _status_of(e) == want]
    if search:
        want = search.strip().lower()
        entries = [e for e in entries if want in str(getattr(e, "title", "")).lower()]

    total = len(entries)
    entries = entries[offset:offset + limit]

    items = []
    for entry in entries:
        item = catalog._item(entry)
        items.append({
            "sku": item.sku,
            "title": item.title,
            "chain": item.category,
            "status": item.status,
            "hint_count": item.hint_count,
            "image_count": item.image_count,
        })

    return {
        "items": items,
        "count": len(items),
        "total": total,
        "offset": offset,
        "limit": limit,
    }
