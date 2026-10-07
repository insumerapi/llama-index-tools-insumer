"""Unit tests for the InsumerToolSpec — mocked HTTP, verifies request/response
shape plumbing without hitting the live API.

Integration tests that hit api.insumermodel.com live are in
``tests/test_integration.py`` and are skipped unless ``INSUMER_API_KEY`` is set
in the environment.
"""

import json
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import requests

from llama_index.tools.insumer import InsumerToolSpec


API_KEY = "insr_live_0000000000000000000000000000000000000000"


@pytest.fixture
def spec() -> InsumerToolSpec:
    return InsumerToolSpec(api_key=API_KEY)


def _mock_response(payload: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


def test_spec_functions_exported(spec: InsumerToolSpec) -> None:
    assert spec.spec_functions == [
        "attest_wallet",
        "get_trust_profile",
        "list_compliance_templates",
        "get_jwks",
        "buy_api_key",
        "buy_credits",
    ]


def test_no_key_raises_for_authed_call() -> None:
    spec = InsumerToolSpec()
    with pytest.raises(ValueError, match="InsumerAPI key required"):
        spec.attest_wallet(conditions=[], wallet="0x" + "a" * 40)


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_evm_token_balance(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({
        "ok": True,
        "data": {
            "attestation": {
                "id": "ATST-ABCDEF0123456789",
                "pass": True,
                "results": [{"met": True, "conditionHash": "0xabc"}],
                "passCount": 1,
                "failCount": 0,
                "attestedAt": "2026-04-16T00:00:00.000Z",
                "expiresAt": "2026-04-16T00:30:00.000Z",
            },
            "sig": "aGVsbG8=",
            "kid": "insumer-attest-v1",
        },
        "meta": {"creditsRemaining": 99, "creditsCharged": 1},
    })

    wallet = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    result = spec.attest_wallet(
        wallet=wallet,
        conditions=[{
            "type": "token_balance",
            "contractAddress": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "chainId": 8453,
            "threshold": 100,
            "decimals": 6,
            "label": "USDC on Base >= 100",
        }],
    )

    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args.args[0] == "https://api.insumermodel.com/v1/attest"
    body = call_args.kwargs["json"]
    assert body["wallet"] == wallet
    assert body["conditions"][0]["type"] == "token_balance"
    assert body["conditions"][0]["chainId"] == 8453
    # token_balance threshold is coerced to a decimal string (v2 keys require it).
    assert body["conditions"][0]["threshold"] == "100"
    assert "solanaWallet" not in body
    assert "xrplWallet" not in body
    headers = call_args.kwargs["headers"]
    assert headers["X-API-Key"] == API_KEY
    assert headers["Content-Type"] == "application/json"

    assert result["ok"] is True
    assert result["data"]["attestation"]["pass"] is True
    assert result["data"]["kid"] == "insumer-attest-v1"
    assert result["meta"]["creditsCharged"] == 1


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_jwt_format(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({
        "ok": True,
        "data": {
            "attestation": {"id": "ATST-1", "pass": True, "results": [],
                            "passCount": 0, "failCount": 0,
                            "attestedAt": "2026-04-16T00:00:00.000Z",
                            "expiresAt": "2026-04-16T00:30:00.000Z"},
            "sig": "aGVsbG8=",
            "kid": "insumer-attest-v1",
            "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imluc3VtZXItYXR0ZXN0LXYxIn0.eyJwYXNzIjp0cnVlfQ.sig",
        },
        "meta": {},
    })
    result = spec.attest_wallet(
        wallet="0x" + "a" * 40,
        conditions=[{"type": "farcaster_id"}],
        format="jwt",
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["format"] == "jwt"
    assert result["data"]["jwt"].startswith("eyJ")


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_account_code_passes_expect_and_delegate_through(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    """vitalik.eth is EIP-7702-delegated on Base: met only, no code, no target in the result."""
    mock_post.return_value = _mock_response({
        "ok": True,
        "data": {
            "attestation": {"pass": True, "results": [{
                "condition": 0, "met": True,
                "evaluatedCondition": {"type": "account_code", "chainId": 8453, "expect": "eip7702", "operator": "code_state"},
                "conditionHash": "0x6c5752bfbfcfd6ba36c9cda6c74df567f0e0414da6b7a3176061ba734aeadc46",
            }], "passCount": 1, "failCount": 0},
            "sig": "aGVsbG8=", "kid": "insumer-attest-v2",
        },
        "meta": {"creditsCharged": 1},
    })
    result = spec.attest_wallet(
        wallet="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        conditions=[
            {"type": "account_code", "chainId": 8453, "expect": "eip7702"},
            {"type": "account_code", "chainId": 1, "expect": "eip7702", "delegate": "0x" + "ab" * 20},
        ],
    )
    sent = mock_post.call_args.kwargs["json"]["conditions"]
    assert sent[0] == {"type": "account_code", "chainId": 8453, "expect": "eip7702"}
    assert sent[1]["delegate"] == "0x" + "ab" * 20
    first = result["data"]["attestation"]["results"][0]
    assert first["met"] is True
    assert first["evaluatedCondition"]["operator"] == "code_state"
    assert "code" not in first


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_xrpl(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.attest_wallet(
        xrpl_wallet="rN7n3473SaZBCG4dFL83w7p1W9cgPJqKro",
        conditions=[{
            "type": "token_balance",
            "contractAddress": "native",
            "chainId": "xrpl",
            "threshold": 100,
            "label": "XRP >= 100",
        }],
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["xrplWallet"] == "rN7n3473SaZBCG4dFL83w7p1W9cgPJqKro"
    assert body["conditions"][0]["chainId"] == "xrpl"
    assert "wallet" not in body


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_merkle_proof(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.attest_wallet(
        wallet="0x" + "a" * 40,
        conditions=[{"type": "token_balance", "contractAddress": "0x" + "b" * 40,
                     "chainId": 1, "threshold": 1, "decimals": 18}],
        proof="merkle",
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["proof"] == "merkle"


@patch("llama_index.tools.insumer.base.requests.post")
def test_get_trust_profile(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({
        "ok": True,
        "data": {
            "trust": {
                "id": "TRST-A1B2C",
                "wallet": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                "conditionSetVersion": "2026-10-08",
                "dimensions": {
                    "stablecoins": {"checks": [], "passCount": 0, "failCount": 0, "total": 0},
                    "governance": {"checks": [], "passCount": 0, "failCount": 0, "total": 0},
                    "nfts": {"checks": [], "passCount": 0, "failCount": 0, "total": 0},
                    "staking": {"checks": [], "passCount": 0, "failCount": 0, "total": 0},
                    "institutional_stablecoins": {"checks": [], "passCount": 0, "failCount": 0, "notEvaluatedCount": 0, "total": 0},
                    # The live account dimension for 0x1601843c5E9bC251A3272907010AFa41Fa18347E (a contract on all five chains): first two rows.
                    "account": {
                        "checks": [
                            {"label": "Contract code on Ethereum", "chainId": 1, "met": True,
                             "evaluatedCondition": {"type": "account_code", "chainId": 1, "expect": "contract", "operator": "code_state"},
                             "conditionHash": "0xfd7b6aa42eb012184fa54d9d5d99c6ab18481e0ce33ec0ec0e9d28d37b54ccbc"},
                            {"label": "EIP-7702 delegation on Ethereum", "chainId": 1, "met": False,
                             "evaluatedCondition": {"type": "account_code", "chainId": 1, "expect": "eip7702", "operator": "code_state"},
                             "conditionHash": "0xdef6fadcef95f59f4621fa2bf788e6be0ffc0492dba22038999b8cd757adf18b"},
                        ],
                        "passCount": 5, "failCount": 5, "notEvaluatedCount": 0, "total": 10,
                    },
                },
                "summary": {
                    "totalChecks": 10, "totalPassed": 5, "totalFailed": 5, "totalNotEvaluated": 0,
                    "dimensionsWithActivity": 1, "dimensionsChecked": 6,
                },
                "profiledAt": "2026-04-16T00:00:00.000Z",
                "expiresAt": "2026-04-16T00:30:00.000Z",
            },
            "sig": "aGVsbG8=",
            "kid": "insumer-attest-v1",
        },
        "meta": {"creditsRemaining": 97, "creditsCharged": 3},
    })

    wallet = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    result = spec.get_trust_profile(wallet=wallet)

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "https://api.insumermodel.com/v1/trust"
    body = mock_post.call_args.kwargs["json"]
    assert body["wallet"] == wallet
    assert "solanaWallet" not in body

    assert result["data"]["trust"]["conditionSetVersion"] == "2026-10-08"
    assert set(result["data"]["trust"]["dimensions"].keys()) == {
        "stablecoins", "governance", "nfts", "staking", "institutional_stablecoins", "account",
    }
    account = result["data"]["trust"]["dimensions"]["account"]
    assert account["total"] == 10
    assert account["checks"][0]["evaluatedCondition"]["operator"] == "code_state"
    assert "code" not in account["checks"][0]
    assert result["data"]["kid"] == "insumer-attest-v1"
    assert result["meta"]["creditsCharged"] == 3


@patch("llama_index.tools.insumer.base.requests.post")
def test_get_trust_profile_multichain(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.get_trust_profile(
        wallet="0x" + "a" * 40,
        solana_wallet="5Hdh2n3473SaZBCG4dFL83w7p1W9cgPJqKroabc",
        xrpl_wallet="rN7n3473SaZBCG4dFL83w7p1W9cgPJqKro",
        bitcoin_wallet="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        tron_wallet="TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX",
        stellar_wallet="GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        sui_wallet="0x" + "0" * 63 + "5",
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["solanaWallet"].startswith("5Hdh")
    assert body["xrplWallet"].startswith("r")
    assert body["bitcoinWallet"].startswith("bc1")
    assert body["tronWallet"].startswith("T")
    assert body["stellarWallet"].startswith("G")
    assert body["suiWallet"].startswith("0x")
    assert len(body["suiWallet"]) == 66


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_tron(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.attest_wallet(
        tron_wallet="TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX",
        conditions=[{
            "type": "token_balance",
            "contractAddress": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
            "chainId": "tron",
            "threshold": 1,
            "decimals": 6,
            "label": "USDT-TRC20 >= 1",
        }],
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["tronWallet"] == "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX"
    assert body["conditions"][0]["chainId"] == "tron"
    assert "wallet" not in body


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_stellar(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.attest_wallet(
        stellar_wallet="GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        conditions=[{
            "type": "token_balance",
            "contractAddress": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "chainId": "stellar",
            "assetCode": "USDC",
            "threshold": 1,
            "label": "USDC trustline >= 1",
        }],
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["stellarWallet"].startswith("G")
    assert body["conditions"][0]["chainId"] == "stellar"
    assert body["conditions"][0]["assetCode"] == "USDC"


@patch("llama_index.tools.insumer.base.requests.post")
def test_attest_wallet_sui(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.attest_wallet(
        sui_wallet="0x" + "0" * 63 + "5",
        conditions=[{
            "type": "token_balance",
            "contractAddress": "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC",
            "chainId": "sui",
            "threshold": 1,
            "decimals": 6,
            "label": "USDC on Sui >= 1",
        }],
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["suiWallet"].startswith("0x")
    assert len(body["suiWallet"]) == 66
    assert body["conditions"][0]["chainId"] == "sui"


@patch("llama_index.tools.insumer.base.requests.get")
def test_list_compliance_templates_no_auth(mock_get: MagicMock) -> None:
    mock_get.return_value = _mock_response({
        "ok": True,
        "data": {
            "templates": {
                "coinbase_verified_account": {
                    "provider": "Coinbase",
                    "description": "Coinbase Verified Account",
                    "chainId": 8453,
                    "chainName": "Base",
                },
                "gitcoin_passport_score": {
                    "provider": "Gitcoin",
                    "description": "Gitcoin Passport Score (>=20)",
                    "chainId": 10,
                    "chainName": "Optimism",
                },
            },
        },
        "meta": {},
    })

    # Template discovery works without an API key.
    spec = InsumerToolSpec()
    result = spec.list_compliance_templates()

    mock_get.assert_called_once()
    call_args = mock_get.call_args
    assert call_args.args[0] == "https://api.insumermodel.com/v1/compliance/templates"
    headers = call_args.kwargs["headers"]
    assert "X-API-Key" not in headers

    assert "coinbase_verified_account" in result["data"]["templates"]
    assert result["data"]["templates"]["coinbase_verified_account"]["chainId"] == 8453


@patch("llama_index.tools.insumer.base.requests.get")
def test_get_jwks_no_auth(mock_get: MagicMock) -> None:
    mock_get.return_value = _mock_response({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
            "y": "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
            "use": "sig",
            "alg": "ES256",
            "kid": "insumer-attest-v1",
        }],
    })

    spec = InsumerToolSpec()  # no key — JWKS is public
    result = spec.get_jwks()

    mock_get.assert_called_once()
    assert mock_get.call_args.args[0].endswith("/.well-known/jwks.json")

    assert result["keys"][0]["kty"] == "EC"
    assert result["keys"][0]["crv"] == "P-256"
    assert result["keys"][0]["alg"] == "ES256"
    assert result["keys"][0]["kid"] == "insumer-attest-v1"


def test_custom_base_url() -> None:
    spec = InsumerToolSpec(api_key=API_KEY, base_url="https://staging.insumermodel.com/")
    # Trailing slash stripped at construction.
    assert spec.base_url == "https://staging.insumermodel.com"


def test_to_tool_list_integration(spec: InsumerToolSpec) -> None:
    """Verifies BaseToolSpec --> FunctionTool conversion works."""
    tools = spec.to_tool_list()
    assert len(tools) == 6
    tool_names = {t.metadata.name for t in tools}
    assert tool_names == {
        "attest_wallet",
        "get_trust_profile",
        "list_compliance_templates",
        "get_jwks",
        "buy_api_key",
        "buy_credits",
    }


@patch("llama_index.tools.insumer.base.requests.post")
def test_buy_api_key_no_auth_required(mock_post: MagicMock) -> None:
    """buy_api_key must NOT require an API key — wallet address is the identity."""
    mock_post.return_value = _mock_response({
        "ok": True,
        "data": {
            "success": True,
            "key": "insr_live_newwallet000000000000000000000000000000",
            "name": "my-agent",
            "tier": "paid",
            "dailyLimit": 10000,
            "creditsAdded": 2500,
            "totalCredits": 2500,
            "effectiveRate": "$0.04/credit",
            "chainName": "Base",
            "registeredWallet": "0x" + "a" * 40,
            "expiresAt": "2026-05-16T00:00:00.000Z",
            "usdcPaid": "100.00",
        },
        "meta": {},
    })

    # No api_key provided — this must still work for buy_api_key
    spec = InsumerToolSpec()
    result = spec.buy_api_key(
        tx_hash="0x" + "b" * 64,
        chain_id=8453,
        app_name="my-agent",
        amount=100.0,
    )

    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args.args[0] == "https://api.insumermodel.com/v1/keys/buy"
    body = call_args.kwargs["json"]
    assert body == {
        "txHash": "0x" + "b" * 64,
        "chainId": 8453,
        "appName": "my-agent",
        "amount": 100.0,
    }
    headers = call_args.kwargs["headers"]
    # Critically: no X-API-Key header on buy_api_key
    assert "X-API-Key" not in headers
    assert headers["Content-Type"] == "application/json"

    assert result["data"]["key"].startswith("insr_live_")
    assert result["data"]["tier"] == "paid"


@patch("llama_index.tools.insumer.base.requests.post")
def test_buy_api_key_bitcoin_no_amount(mock_post: MagicMock) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec = InsumerToolSpec()
    spec.buy_api_key(
        tx_hash="abc123" * 10,
        chain_id="bitcoin",
        app_name="btc-agent",
    )
    body = mock_post.call_args.kwargs["json"]
    # For Bitcoin, amount is not required — USD value derived from on-chain
    assert "amount" not in body
    assert body["chainId"] == "bitcoin"


@patch("llama_index.tools.insumer.base.requests.post")
def test_buy_api_key_channel_tag(mock_post: MagicMock) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec = InsumerToolSpec()
    spec.buy_api_key(
        tx_hash="0x" + "c" * 64,
        chain_id=1,
        app_name="my-agent",
        amount=50.0,
        channel="llamaindex-agent",
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["channel"] == "llamaindex-agent"


@patch("llama_index.tools.insumer.base.requests.post")
def test_buy_credits_requires_auth(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({
        "ok": True,
        "data": {
            "creditsAdded": 2500,
            "totalCredits": 3499,
            "usdcPaid": "100.00",
            "effectiveRate": "$0.04/credit",
            "chainName": "Base",
        },
        "meta": {},
    })
    result = spec.buy_credits(
        tx_hash="0x" + "d" * 64,
        chain_id=8453,
        amount=100.0,
    )

    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "https://api.insumermodel.com/v1/credits/buy"
    body = mock_post.call_args.kwargs["json"]
    assert body == {
        "txHash": "0x" + "d" * 64,
        "chainId": 8453,
        "amount": 100.0,
    }
    headers = mock_post.call_args.kwargs["headers"]
    # buy_credits REQUIRES the X-API-Key header (auth endpoint)
    assert headers["X-API-Key"] == API_KEY
    assert result["data"]["creditsAdded"] == 2500


def test_buy_credits_no_key_raises() -> None:
    spec = InsumerToolSpec()  # no key
    with pytest.raises(ValueError, match="InsumerAPI key required"):
        spec.buy_credits(tx_hash="0x" + "d" * 64, chain_id=8453, amount=100.0)


@patch("llama_index.tools.insumer.base.requests.post")
def test_buy_credits_update_wallet_flag(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _mock_response({"ok": True, "data": {}, "meta": {}})
    spec.buy_credits(
        tx_hash="0x" + "e" * 64,
        chain_id="bitcoin",
        update_wallet=True,
    )
    body = mock_post.call_args.kwargs["json"]
    assert body["updateWallet"] is True
    assert "amount" not in body  # Not required for Bitcoin


def _error_response(status: int, payload: Optional[dict] = None) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp.reason = "Error"
    resp.url = "https://api.insumermodel.com/v1/attest"
    if payload is None:
        resp._content = b"<html>upstream error</html>"
    else:
        resp._content = json.dumps(payload).encode()
    return resp


@patch("llama_index.tools.insumer.base.requests.post")
def test_400_message_is_surfaced(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    message = "decimals does not match the token: the token reports 6"
    mock_post.return_value = _error_response(
        400, {"ok": False, "error": {"code": "invalid_request", "message": message}}
    )
    with pytest.raises(requests.HTTPError) as excinfo:
        spec.attest_wallet(
            wallet="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            conditions=[{
                "type": "token_balance",
                "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "chainId": 1,
                "threshold": "100",
                "decimals": 18,
            }],
        )
    assert message in str(excinfo.value)
    assert "400" in str(excinfo.value)
    assert excinfo.value.response.status_code == 400


@patch("llama_index.tools.insumer.base.requests.post")
def test_503_lists_failed_conditions(mock_post: MagicMock, spec: InsumerToolSpec) -> None:
    mock_post.return_value = _error_response(503, {
        "ok": False,
        "error": {
            "code": "rpc_failure",
            "message": "Unable to read one or more data sources",
            "failedConditions": [{"condition": 0, "chainId": "sui", "source": "balance_read"}],
        },
    })
    with pytest.raises(requests.HTTPError) as excinfo:
        spec.get_trust_profile(wallet="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
    text = str(excinfo.value)
    assert "rpc_failure" in text
    assert "failedConditions" in text
    assert "balance_read" in text
    assert excinfo.value.response.status_code == 503


@patch("llama_index.tools.insumer.base.requests.get")
def test_non_json_error_body_falls_back_to_status_error(mock_get: MagicMock) -> None:
    mock_get.return_value = _error_response(502)
    with pytest.raises(requests.HTTPError) as excinfo:
        InsumerToolSpec().list_compliance_templates()
    assert "502" in str(excinfo.value)
    assert excinfo.value.response.status_code == 502
