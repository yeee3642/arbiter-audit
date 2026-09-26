"""Redaction, and the false positives that make shape-only scanning unusable here.

The negative tests carry more weight than the positive ones. A first cut of this
module matched on entropy alone and rewrote three real research artefacts -- the
UniswapV2 init-code hash inside a detector example, a Solidity `token` variable,
and the published split digests. Each of those is now a regression test, because
the cost profile is asymmetric: a missed secret is a key rotation, but a
corrupted artefact is a silently wrong measurement that nobody notices.

Every credential-shaped string below is synthetic. The pragma on the next line
tells the pre-commit guard so, which it honours by demoting its hits here to
advisory instead of blocking -- narrower than --no-verify, which would disable the
guard for every other file in the same commit.

pre-commit: allow-credential-fixtures
"""

from __future__ import annotations

import pytest

from bastet_cc.redact import redact, redact_error, scan


# A synthetic stand-in for the identifier that actually leaked. Using the real
# value here would put it back into the repository -- in a file whose whole purpose
# is to prove it gets removed -- and the pre-commit guard blocks the commit for
# exactly that reason. The shape is what the scanner keys on, so a fake 64-hex
# string tests the same code path.
FAKE_KEY = "deadbeef" * 8


class TestCatchesRealCredentials:
    def test_gateway_429_body(self):
        body = ("RateLimitError: Error code: 429 - {'error': {'message': 'Rate limit "
                f"exceeded for api_key: {FAKE_KEY}. Limit type: requests. "
                "Current limit: 120'}}")
        out = redact_error(body)
        assert FAKE_KEY not in out
        assert "[REDACTED:api_key]" in out

    def test_rate_limit_facts_survive_redaction(self):
        # The measured cap is the research-relevant part of that error and must
        # not be collateral damage.
        body = "for api_key: " + "a" * 64 + ". Limit type: requests. Current limit: 120"
        out = redact_error(body)
        assert "Current limit: 120" in out
        assert "Limit type: requests" in out

    @pytest.mark.parametrize("text", [
        'api_key="sk_live_0123456789abcdefghij"',
        "API_KEY: 0123456789abcdefghijklmn",
        "authorization=Bearer0123456789abcdefgh",
        "client_secret: abcdefghijklmnopqrstuvwx",
        "password = hunter2hunter2hunter2hunter2",
    ])
    def test_context_anchored_forms(self, text):
        assert "[REDACTED" in redact(text)

    @pytest.mark.parametrize("token", [
        "sk-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_abcdefghijklmnopqrstuvwxyz01234",
        "xoxb-abcdefghijklmnopqrstuvwx",
    ])
    def test_provider_prefixed_tokens_need_no_context(self, token):
        assert token not in redact(f"value: {token}")

    def test_bearer_header(self):
        out = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        assert "eyJhbGci" not in out


class TestDoesNotDamageTheCorpus:
    def test_uniswap_init_code_hash_survives(self):
        # The real false positive: this is a public protocol constant quoted
        # inside detectors_synth, and masking it breaks the detector.
        code = ('pair = address(uint160(uint256(keccak256(abi.encodePacked(hex"ff",'
                ' factory, keccak256(abi.encodePacked(token0, token1)),'
                ' hex"e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303"'
                ')))));')
        assert redact(code) == code

    def test_solidity_token_variable_survives(self):
        code = "address token = considerationFulfillments[i].token;"
        assert redact(code) == code

    def test_published_split_digests_survive(self):
        manifest = ('{"splits_sha256": "4b3d5279e6ca9f9ce591474e11ef35375aea47a950a48'
                    'ea9e2359c5241134295"}')
        assert redact(manifest) == manifest

    @pytest.mark.parametrize("code", [
        "bytes32 constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;",
        "bytes32 private constant _DOMAIN_SEPARATOR = keccak256(abi.encode(...));",
        "uint256 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;",
        "IERC20 token = IERC20(_token);",
        "mapping(address => uint256) public tokenBalances;",
    ])
    def test_evm_domain_vocabulary_is_untouched(self, code):
        assert redact(code) == code

    def test_redaction_is_idempotent(self):
        once = redact("api_key: " + "b" * 40)
        assert redact(once) == once

    def test_empty_and_none(self):
        assert redact("") == ""
        assert redact_error(None) is None


class TestScanSeverity:
    def test_credentials_are_blocking(self):
        hits = scan("api_key: " + "c" * 40)
        assert any(blocking for _, _, blocking in hits)

    def test_bare_hex_is_advisory_only(self):
        hits = scan("hex" + '"' + "e" * 64 + '"')
        assert hits, "the hook should still mention it"
        assert not any(blocking for _, _, blocking in hits), \
            "shape alone must never block a commit on this corpus"

    def test_advisory_can_be_switched_off(self):
        assert scan("f" * 64, advisory=False) == []

    def test_clean_text_produces_nothing(self):
        assert scan("function withdraw(uint256 amount) public {}") == []
