"""Tests for the second-poller guard.

The critical property: this must never print a token, and must never allow a
poll to start on a bot that something else is already polling.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.check_bot_token import (  # noqa: E402
    GATEWAY_CLASH,
    NO_TOKEN,
    OK,
    REJECTED,
    UNVERIFIED,
    check,
    digest,
    main,
)

GATEWAY_TOKEN = "8881860201:AAHfakeGatewayTokenValuexxxxxxxxxxxxxxxx"
FRESH_TOKEN = "1234567890:AAHfreshTokenForANewBotxxxxxxxxxxxxxxxxx"
SAMPLE_ME = {"id": 1234567890, "username": "hermesgotdat",
             "first_name": "Hermes Got Dat"}


def digests_for(*tokens):
    return {digest(t): "/home/user/.hermes/.env" for t in tokens}


def _bot_pids() -> list:
    """PIDs of running app.bot_main processes (used to prove none is started)."""
    import subprocess

    try:
        out = subprocess.run(["ps", "aux"], capture_output=True, text=True,
                             timeout=10).stdout
    except Exception:  # pragma: no cover
        return []
    pids = []
    for line in out.splitlines():
        if "app.bot_main" in line and "grep" not in line:
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                pids.append(parts[1])
    return pids


class TestVerdicts:
    def test_no_token_is_refused(self):
        r = check(token="", gateway_digests={}, gateway_pid=None)
        assert r["code"] == NO_TOKEN
        assert r["token_present"] is False

    def test_gateway_token_is_refused(self):
        r = check(token=GATEWAY_TOKEN, gateway_digests=digests_for(GATEWAY_TOKEN),
                  gateway_pid=14623)
        assert r["code"] == GATEWAY_CLASH
        assert r["same_as_gateway"] is True
        assert "14623" in r["message"]

    def test_gateway_token_refused_even_when_gateway_not_running(self):
        """A stopped gateway may be about to restart — still refuse."""
        r = check(token=GATEWAY_TOKEN, gateway_digests=digests_for(GATEWAY_TOKEN),
                  gateway_pid=None)
        assert r["code"] == GATEWAY_CLASH

    def test_fresh_valid_token_is_allowed(self):
        r = check(token=FRESH_TOKEN, gateway_digests=digests_for(GATEWAY_TOKEN),
                  gateway_pid=14623, me=SAMPLE_ME)
        assert r["code"] == OK
        assert r["same_as_gateway"] is False
        assert r["bot"]["username"] == "hermesgotdat"

    def test_rejected_token(self):
        r = check(token=FRESH_TOKEN, gateway_digests={}, gateway_pid=None,
                  me_error="HTTP 401: Unauthorized")
        assert r["code"] == REJECTED

    def test_revoked_token_reports_404(self):
        r = check(token=FRESH_TOKEN, gateway_digests={}, gateway_pid=None,
                  me_error="HTTP 404: Not Found")
        assert r["code"] == REJECTED

    def test_network_failure_is_unverified_not_rejected(self):
        r = check(token=FRESH_TOKEN, gateway_digests={}, gateway_pid=None,
                  me_error="URLError: <urlopen error timed out>")
        assert r["code"] == UNVERIFIED

    def test_no_gateway_config_at_all_still_allows_fresh_token(self):
        r = check(token=FRESH_TOKEN, gateway_digests={}, gateway_pid=None,
                  me=SAMPLE_ME)
        assert r["code"] == OK


class TestTokenNeverLeaks:
    def test_message_contains_no_token(self):
        for tok in (GATEWAY_TOKEN, FRESH_TOKEN):
            for r in (
                check(token=tok, gateway_digests=digests_for(GATEWAY_TOKEN),
                      gateway_pid=14623, me=SAMPLE_ME),
                check(token=tok, gateway_digests=digests_for(GATEWAY_TOKEN),
                      gateway_pid=None, me_error="HTTP 401: Unauthorized"),
            ):
                blob = json.dumps(r)
                assert tok not in blob
                assert tok.split(":")[1] not in blob

    def test_cli_output_contains_no_token(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "scripts.check_bot_token.check",
            lambda **kw: check(token=GATEWAY_TOKEN,
                               gateway_digests=digests_for(GATEWAY_TOKEN),
                               gateway_pid=14623),
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([])
        out = buf.getvalue()
        assert code == GATEWAY_CLASH
        assert GATEWAY_TOKEN not in out
        assert "8881860201" not in out

    def test_json_output_contains_no_token(self, monkeypatch):
        monkeypatch.setattr(
            "scripts.check_bot_token.check",
            lambda **kw: check(token=GATEWAY_TOKEN,
                               gateway_digests=digests_for(GATEWAY_TOKEN),
                               gateway_pid=14623),
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["--json"])
        payload = json.loads(buf.getvalue())
        assert payload["code"] == GATEWAY_CLASH
        assert GATEWAY_TOKEN not in buf.getvalue()


class TestDigestComparison:
    def test_same_token_same_digest(self):
        assert digest(GATEWAY_TOKEN) == digest(GATEWAY_TOKEN)

    def test_whitespace_ignored(self):
        assert digest(f"  {GATEWAY_TOKEN}  ") == digest(GATEWAY_TOKEN)

    def test_different_tokens_differ(self):
        assert digest(GATEWAY_TOKEN) != digest(FRESH_TOKEN)

    def test_near_miss_token_is_not_matched(self):
        """A token differing by one char must NOT be treated as the gateway's."""
        r = check(token=GATEWAY_TOKEN[:-1] + "z",
                  gateway_digests=digests_for(GATEWAY_TOKEN), gateway_pid=14623,
                  me=SAMPLE_ME)
        assert r["same_as_gateway"] is False
        assert r["code"] == OK


class TestEnvFileParsing:
    def test_reads_tokens_from_files(self, tmp_path, monkeypatch):
        import scripts.check_bot_token as mod

        f1 = tmp_path / ".env"
        f1.write_text(
            "# comment\n"
            "TELEGRAM_BOT_TOKEN='quoted-token-value'\n"
            "OTHER=1\n"
        )
        f2 = tmp_path / "secrets.env"
        f2.write_text("TELEGRAM_BOT_TOKEN=second-token-value\n")
        monkeypatch.setattr(mod, "GATEWAY_ENV_FILES", (f1, f2))

        found = mod.gateway_token_digests()
        assert digest("quoted-token-value") in found
        assert digest("second-token-value") in found
        assert len(found) == 2

    def test_placeholder_tokens_ignored(self, tmp_path, monkeypatch):
        import scripts.check_bot_token as mod

        f = tmp_path / ".env"
        f.write_text("TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN\n")
        monkeypatch.setattr(mod, "GATEWAY_ENV_FILES", (f,))
        assert mod.gateway_token_digests() == {}

    def test_missing_file_is_not_fatal(self, tmp_path, monkeypatch):
        import scripts.check_bot_token as mod

        monkeypatch.setattr(mod, "GATEWAY_ENV_FILES",
                            (tmp_path / "nope.env",))
        assert mod.gateway_token_digests() == {}


class TestRunBotIntegration:
    """run_bot.sh must block before starting a poller.

    Deterministic: a fake gateway env file is injected via the env var the
    script honours, so the test does not depend on the machine's live tokens.
    """

    def test_run_bot_refuses_gateway_token(self, tmp_path):
        """The script must exit 3 and NEVER reach the polling loop.

        `PY` is stubbed with /bin/false so that if the guard were ever bypassed,
        the script could not start a real poller as a side effect of the test.
        """
        import os
        import subprocess

        project = Path(__file__).resolve().parent.parent
        script = project / "scripts" / "run_bot.sh"

        token = ""
        proj_env = project / ".env"
        if proj_env.exists():
            for line in proj_env.read_text().splitlines():
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    token = line.split("=", 1)[1].strip().strip("'\"")
        if not token:
            pytest.skip("project .env has no token to test the clash with")

        # A fake "gateway" env file containing the project's own token forces
        # the clash deterministically, regardless of the machine's live tokens.
        fake_gw = tmp_path / "gateway.env"
        fake_gw.write_text(f"TELEGRAM_BOT_TOKEN={token}\n")

        env = dict(os.environ)
        env["HERMES_GATEWAY_ENV_FILES"] = str(fake_gw)
        env["PY"] = "/bin/false"          # cannot start a bot even if reached
        env.pop("SKIP_TOKEN_CHECK", None)

        before = set(_bot_pids())

        proc = subprocess.run(
            ["bash", str(script)],
            cwd=project, capture_output=True, text=True, timeout=120, env=env,
        )

        assert proc.returncode == 3, (
            f"expected 3, got {proc.returncode}\n{proc.stdout}\n{proc.stderr}")
        assert "BotFather" in proc.stderr
        # the guard must run BEFORE anything is started
        assert "stopping previous bot" not in proc.stdout
        assert set(_bot_pids()) == before, "a poller was started despite the clash"
