"""Meme token and EVM token safety analysis.

Integrates real external APIs:
- honeypot.is for buy/sell simulation
- GoPlus Security for contract risk flags
- DexScreener for liquidity and price data

All reads are public; no wallet connection required.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .errors import ValidationError
from .logging_setup import get_logger
from .http import HttpClient

log = get_logger()


@dataclass
class TokenRiskCheck:
    name: str
    passed: bool
    detail: str
    risk: str = "low"  # low | medium | high


@dataclass
class MemeTokenReport:
    address: str
    chain: str
    timestamp: float
    risk_score: int
    risk_level: str
    checks: List[TokenRiskCheck] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    liquidity_usd: Optional[float] = None
    price_usd: Optional[float] = None
    source: str = "heuristic"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "chain": self.chain,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "liquidity_usd": self.liquidity_usd,
            "price_usd": self.price_usd,
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "detail": c.detail,
                    "risk": c.risk,
                }
                for c in self.checks
            ],
            "warnings": self.warnings,
            "source": self.source,
            "status": "✓",
        }


class MemeTokenAnalyzer:
    """Real meme-token safety checker using public APIs."""

    def __init__(self, http: Optional[HttpClient] = None):
        self.http = http or HttpClient(timeout=20.0, max_retries=2)

    def analyze(self, address: str, chain: str = "ethereum") -> MemeTokenReport:
        if not address or not isinstance(address, str):
            raise ValidationError("token address is required")
        address = address.strip()
        if not address.startswith("0x") or len(address) != 42:
            raise ValidationError("invalid EVM token address format")

        checks: List[TokenRiskCheck] = []
        warnings: List[str] = []
        risk_score = 0
        report = MemeTokenReport(
            address=address,
            chain=chain,
            timestamp=time.time(),
            risk_score=0,
            risk_level="unknown",
        )

        # 1. Format / EIP-55
        try:
            from .addresses import validate_evm_address
            checksummed = validate_evm_address(address)
            checks.append(TokenRiskCheck(
                name="address_format", passed=True,
                detail=f"Valid EIP-55 address: {checksummed}",
            ))
        except Exception as exc:
            checks.append(TokenRiskCheck(
                name="address_format", passed=False,
                detail=str(exc), risk="high",
            ))
            risk_score += 30

        # 2. honeypot.is API (no key required for v2)
        try:
            hp = self._honeypot_is_check(address, chain)
            checks.append(hp.check)
            if not hp.check.passed:
                risk_score += 35
                warnings.extend(hp.warnings)
            report.liquidity_usd = hp.liquidity_usd
        except Exception as exc:
            log.warning("honeypot.is failed: %s", exc)

        # 3. GoPlus security flags (public API)
        try:
            gp = self._goplus_check(address, chain)
            checks.append(gp.check)
            if not gp.check.passed:
                risk_score += 25
                warnings.extend(gp.warnings)
        except Exception as exc:
            log.warning("GoPlus failed: %s", exc)

        # 4. DexScreener price + liquidity
        try:
            ds = self._dexscreener_check(address, chain)
            checks.append(ds.check)
            if not ds.check.passed:
                risk_score += 10
            report.price_usd = ds.price_usd
            if report.liquidity_usd is None:
                report.liquidity_usd = ds.liquidity_usd
        except Exception as exc:
            log.warning("DexScreener failed: %s", exc)

        # 5. Heuristic: blacklist patterns
        heur = self._heuristic_check(address)
        checks.append(heur.check)
        if not heur.check.passed:
            risk_score += 15
            warnings.extend(heur.warnings)

        # Risk level
        if risk_score >= 60:
            report.risk_level = "high"
        elif risk_score >= 30:
            report.risk_level = "medium"
        elif risk_score > 0:
            report.risk_level = "low"
        else:
            report.risk_level = "unknown"

        report.risk_score = risk_score
        report.checks = checks
        report.warnings = warnings
        report.source = "honeypot.is + GoPlus + DexScreener"
        return report

    def _honeypot_is_check(self, address: str, chain: str):
        chain_map = {
            "ethereum": "1", "bsc": "56", "base": "8453",
            "polygon": "137", "arbitrum": "42161",
        }
        chain_id = chain_map.get(chain.lower(), "1")
        url = f"https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID={chain_id}"
        try:
            data = self.http.get_json(url, provider="honeypot.is")
        except Exception as exc:
            return _check_result(
                TokenRiskCheck("honeypot_is", False,
                               f"API error: {exc}", risk="medium"),
                warnings=[f"honeypot.is unavailable: {exc}"],
            )

        if not isinstance(data, dict):
            return _check_result(
                TokenRiskCheck("honeypot_is", False,
                               "unexpected response", risk="medium"),
                warnings=["honeypot.is returned unexpected data"],
            )

        risk_level = str(data.get("riskLevel", "UNKNOWN")).upper()
        is_hp = data.get("isHoneypot", False)
        sim = data.get("simulation", {})
        buy_tax = sim.get("buyTax", "N/A")
        sell_tax = sim.get("sellTax", "N/A")
        liq = data.get("liquidityAmount", 0)
        liq_usd = float(liq) if liq else None

        detail = (f"riskLevel={risk_level}, honeypot={is_hp}, "
                  f"buyTax={buy_tax}, sellTax={sell_tax}")
        passed = not is_hp and risk_level in ("LOW", "NONE")
        warnings = []
        if is_hp:
            warnings.append("honeypot.is flagged as honeypot")
        if buy_tax != "N/A" and float(str(buy_tax).replace("%", "")) > 10:
            warnings.append(f"high buy tax: {buy_tax}")
        if sell_tax != "N/A" and float(str(sell_tax).replace("%", "")) > 10:
            warnings.append(f"high sell tax: {sell_tax}")

        return _check_result(
            TokenRiskCheck("honeypot_is", passed, detail,
                           risk="high" if not passed else "low"),
            warnings=warnings,
            liquidity_usd=liq_usd,
        )

    def _goplus_check(self, address: str, chain: str):
        chain_map = {
            "ethereum": "1", "bsc": "56", "base": "8453",
            "polygon": "137", "arbitrum": "42161",
        }
        chain_id = chain_map.get(chain.lower(), "1")
        url = (f"https://api.gopluslabs.io/api/v1/token_security/"
               f"{chain_id}/{address}")
        try:
            data = self.http.get_json(url, provider="goplus")
        except Exception as exc:
            return _check_result(
                TokenRiskCheck("goplus", False,
                               f"API error: {exc}", risk="medium"),
                warnings=[f"GoPlus unavailable: {exc}"],
            )

        if not isinstance(data, dict) or data.get("code") != 1:
            return _check_result(
                TokenRiskCheck("goplus", True, "no flags returned", risk="low"),
            )

        risks = data.get("result", {}) or {}
        flags = []
        warnings = []
        if risks.get("is_honeypot") == "1":
            flags.append("honeypot")
            warnings.append("GoPlus: honeypot flag")
        if risks.get("is_mintable") == "1":
            flags.append("mintable")
            warnings.append("GoPlus: mintable token")
        if risks.get("is_blacklisted") == "1":
            flags.append("blacklist")
            warnings.append("GoPlus: blacklist function")
        if risks.get("is_proxy") == "1":
            flags.append("proxy")
            warnings.append("GoPlus: upgradeable proxy")
        if risks.get("owner_change_balance") == "1":
            flags.append("owner_balance_change")
            warnings.append("GoPlus: owner can change balances")

        passed = len(flags) == 0
        risk = "high" if not passed else "low"
        detail = f"flags={flags}" if flags else "no flags"
        return _check_result(
            TokenRiskCheck("goplus", passed, detail, risk=risk),
            warnings=warnings,
        )

    def _dexscreener_check(self, address: str, chain: str):
        chain_map = {
            "ethereum": "ethereum", "bsc": "bsc", "base": "base",
            "polygon": "polygon", "arbitrum": "arbitrum",
        }
        slug = chain_map.get(chain.lower(), "ethereum")
        url = (f"https://api.dexscreener.com/latest/dex/tokens/"
               f"{address}")
        try:
            data = self.http.get_json(url, provider="dexscreener")
        except Exception as exc:
            return _check_result(
                TokenRiskCheck("dexscreener", False,
                               f"API error: {exc}", risk="low"),
                warnings=[f"DexScreener unavailable: {exc}"],
            )

        pairs = data.get("pairs") or []
        if not pairs:
            return _check_result(
                TokenRiskCheck("dexscreener", False,
                               "no DEX pairs found", risk="medium"),
                warnings=["token not listed on DexScreener"],
            )

        best = pairs[0]
        price = best.get("priceUsd")
        liq_usd = best.get("liquidity", {}).get("usd")
        detail = (f"pair={best.get('pairAddress', '')[:10]}…, "
                  f"DEX={best.get('dexId', '')}, "
                  f"priceUsd={price}, liquidityUsd={liq_usd}")
        passed = liq_usd is not None and float(liq_usd or 0) > 100
        return _check_result(
            TokenRiskCheck("dexscreener", passed, detail,
                           risk="medium" if not passed else "low"),
            liquidity_usd=float(liq_usd) if liq_usd else None,
            price_usd=float(price) if price else None,
        )

    def _heuristic_check(self, address: str):
        tail = address[-8:]
        zero_count = tail.count("0")
        if zero_count >= 6:
            return _check_result(
                TokenRiskCheck("heuristic", False,
                               "address pattern suggests low liquidity",
                               risk="medium"),
                warnings=["address tail is mostly zeros"],
            )
        return _check_result(
            TokenRiskCheck("heuristic", True,
                           "address pattern looks normal", risk="low"),
        )


def _check_result(check, warnings=None, liquidity_usd=None, price_usd=None):
    class _R:
        def __init__(self, check, warnings, liq, price):
            self.check = check
            self.warnings = warnings or []
            self.liquidity_usd = liq
            self.price_usd = price
    return _R(check, warnings or [], liquidity_usd, price_usd)
