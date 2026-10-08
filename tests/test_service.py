"""End-to-end service tests: challenge -> sign -> verify -> assets."""

from __future__ import annotations

import pytest

from app.auth import personal_sign_hash
from app.chains.base import Asset, AssetReport
from app.chains.registry import ChainRegistry
from app.config import Settings
from app.errors import AddressValidationError
from app.service import WalletService
from app.status import FAIL, OK

SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
SAMPLE_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
PRIV = "11" * 32


class StubProvider:
    """Minimal provider used to avoid network access in tests."""

    def __init__(self, family, chain, status="✓"):
        self.family = family
        self.chain = chain
        self.label = chain
        self.native_symbol = "ETH" if family == "evm" else "BTC"
        self.status = status
        self.seen = []

    def accepts(self, address):
        if self.family == "evm":
            return address.startswith("0x") and len(address) == 42
        return not address.startswith("0x")

    def validate(self, address):
        if not self.accepts(address):
            raise AddressValidationError(f"not a {self.family} address")
        return address

    def explorer_url(self, address):
        return None

    def fetch_assets(self, address, *, limit=50):
        self.seen.append(address)
        report = AssetReport(address=address, chain=self.chain, family=self.family,
                             native_symbol=self.native_symbol, status=self.status)
        if self.status == "✓":
            report.balance_native = 1.5
            report.assets.append(Asset(symbol=self.native_symbol, amount=1.5,
                                       raw="1500000000000000000", decimals=18))
        else:
            report.detail = "upstream failure"
        return report


def make_service(settings, tracker, providers):
    registry = ChainRegistry()
    for provider in providers:
        registry.register(provider)
    return WalletService(settings, tracker=tracker, registry=registry)


def sign(private_hex, message):
    from eth_keys import keys

    priv = keys.PrivateKey(bytes.fromhex(private_hex))
    sig = priv.sign_msg_hash(personal_sign_hash(message))
    return "0x" + sig.to_bytes().hex(), priv.public_key.to_checksum_address()


@pytest.fixture
def evm_service(settings, tracker):
    return make_service(settings, tracker, [StubProvider("evm", "ethereum")])


class TestSigningFlow:
    def test_challenge_then_verify(self, evm_service):
        sig, address = sign(PRIV, "placeholder")
        challenge = evm_service.issue_challenge(address)
        assert challenge["status"] == "⏳"
        assert challenge["nonce"] in challenge["message"]

        signature = sign(PRIV, challenge["message"])[0]
        result = evm_service.verify(address, signature, challenge["nonce"])
        assert result.verified is True
        assert result.status == "✓"
        assert result.address == address
        assert result.token

    def test_nonce_cannot_be_reused(self, evm_service):
        _, address = sign(PRIV, "x")
        challenge = evm_service.issue_challenge(address)
        signature = sign(PRIV, challenge["message"])[0]
        assert evm_service.verify(address, signature, challenge["nonce"]).verified
        second = evm_service.verify(address, signature, challenge["nonce"])
        assert second.verified is False
        assert second.status == "✗"

    def test_wrong_signer_rejected(self, evm_service):
        _, address = sign(PRIV, "x")
        challenge = evm_service.issue_challenge(address)
        other_sig = sign("22" * 32, challenge["message"])[0]
        result = evm_service.verify(address, other_sig, challenge["nonce"])
        assert result.verified is False
        assert "does not match" in result.detail

    def test_address_mismatch_against_nonce(self, evm_service):
        _, address = sign(PRIV, "x")
        _, other = sign("22" * 32, "x")
        challenge = evm_service.issue_challenge(address)
        signature = sign(PRIV, challenge["message"])[0]
        result = evm_service.verify(other, signature, challenge["nonce"])
        assert result.verified is False
        assert "different address" in result.detail

    def test_status_reflects_failure(self, evm_service):
        _, address = sign(PRIV, "x")
        challenge = evm_service.issue_challenge(address)
        evm_service.verify(address, "0x" + "00" * 65, challenge["nonce"])
        assert evm_service.tracker.compact()["wallet_data"] == FAIL

    def test_status_reflects_success(self, evm_service):
        _, address = sign(PRIV, "x")
        challenge = evm_service.issue_challenge(address)
        signature = sign(PRIV, challenge["message"])[0]
        evm_service.verify(address, signature, challenge["nonce"])
        assert evm_service.tracker.compact()["wallet_data"] == OK


class TestAssetFetching:
    def test_evm_assets(self, evm_service):
        payload = evm_service.inspect_public(SAMPLE_EVM)
        assert payload["status"] == "✓"
        assert payload["wallet"]["chain"] == "ethereum"
        assert evm_service.tracker.compact()["assets_chains"] == OK

    def test_bitcoin_assets(self, settings, tracker):
        service = make_service(settings, tracker, [StubProvider("bitcoin", "bitcoin")])
        payload = service.inspect_public(SAMPLE_BTC)
        assert payload["wallet"]["family"] == "bitcoin"
        assert payload["wallet"]["native_symbol"] == "BTC"

    def test_evm_provider_never_sees_bitcoin_address(self, evm_service):
        with pytest.raises(AddressValidationError):
            evm_service.inspect_public(SAMPLE_BTC, chain="ethereum")

    def test_unknown_address_format_rejected(self, evm_service):
        with pytest.raises(AddressValidationError):
            evm_service.inspect_public("not-an-address")

    def test_unknown_chain_rejected(self, evm_service):
        with pytest.raises(AddressValidationError):
            evm_service.inspect_public(SAMPLE_EVM, chain="dogecoin")

    def test_upstream_failure_sets_fail_status(self, settings, tracker):
        service = make_service(
            settings, tracker, [StubProvider("evm", "ethereum", status="✗")]
        )
        payload = service.inspect_public(SAMPLE_EVM)
        assert payload["status"] == "✗"
        assert service.tracker.compact()["assets_chains"] == FAIL

    def test_puzzle_layer_reports_error_when_unconfigured(self, settings, tracker, tmp_path):
        """With no dataset available at all, the verdict must be `error`."""
        from dataclasses import replace

        from app.chains.registry import ChainRegistry
        from app.service import WalletService

        isolated = replace(settings, memepol_api_key=None,
                           ocp_dataset_path=tmp_path / "missing.json")
        registry = ChainRegistry()
        registry.register(StubProvider("evm", "ethereum"))
        service = WalletService(isolated, tracker=tracker, registry=registry)
        payload = service.inspect_public(SAMPLE_EVM, include_puzzles=True)
        analysis = payload["puzzle_analysis"]
        assert analysis["verdict"] == "error"
        assert analysis["matches"] == []


class TestCapabilities:
    def test_read_only_contract(self, evm_service):
        caps = evm_service.capabilities()
        assert caps["read_only"] is True
        assert caps["secrets_requested"] is False
        assert set(caps["families"]) == {"evm", "bitcoin"}

    def test_memepol_flag_false_without_key(self, evm_service):
        assert evm_service.capabilities()["memepol_configured"] is False


class TestSessionBinding:
    def test_require_session_returns_address(self, evm_service):
        _, address = sign(PRIV, "x")
        challenge = evm_service.issue_challenge(address)
        signature = sign(PRIV, challenge["message"])[0]
        result = evm_service.verify(address, signature, challenge["nonce"])
        assert evm_service.require_session(result.token) == address


class TestSessionIssuerSecretBinding:
    """Regression: login/signup/Telegram tokens must validate in the service.

    ``build_service`` previously constructed ``SessionIssuer()`` with a random
    per-process secret while the auth paths minted tokens with SESSION_SECRET,
    so every authenticated request silently degraded to ANONYMOUS.
    """

    def test_login_token_validates_in_service(self):
        from app.auth import SessionIssuer
        from app.config import get_settings
        from app.service import build_service

        settings = get_settings()
        secret = settings.session_secret or "test-secret"
        service = build_service(settings)

        token, _ = SessionIssuer(secret=secret).issue("0xabc123")
        assert service.require_session(token) == "0xabc123"

    def test_service_and_auth_share_the_same_secret(self):
        from app.auth import SessionIssuer
        from app.config import get_settings
        from app.service import build_service

        settings = get_settings()
        service = build_service(settings)
        token, _ = service.sessions.issue("0xdef456")

        # A token minted by the service must verify with SESSION_SECRET, which is
        # exactly what the login/signup/telegram handlers use.
        assert SessionIssuer(secret=settings.session_secret).verify(token) == "0xdef456"
