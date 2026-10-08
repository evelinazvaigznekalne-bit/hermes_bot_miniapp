"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import Settings  # noqa: E402
from app.status import StatusTracker  # noqa: E402


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        telegram_bot_token=None,
        telegram_webapp_url=None,
        memepol_base_url="https://api.memepol.test/v1",
        memepol_api_key=None,
        eth_rpc_urls=("https://rpc.test",),
        log_dir=tmp_path / "logs",
    )


@pytest.fixture
def tracker(tmp_path) -> StatusTracker:
    return StatusTracker(tmp_path / "logs" / "status.log")


#: A known-good Ethereum mainnet address (checksummed).
SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
#: Bitcoin genesis coinbase address.
SAMPLE_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
