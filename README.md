# LlamaIndex Tools Integration: InsumerAPI

Wallet auth and condition-based access for LlamaIndex agents. Across 37 chains: read → evaluate → sign → keep, returning an ECDSA-signed boolean your agent can verify offline against the public JWKS. Boolean, not balance: the API never exposes wallet holdings, only a signed yes-or-no against the conditions you configure.

Part of [InsumerAPI](https://insumermodel.com/developers/). No secrets. No identity-first. No static credentials.

## Installation

```bash
pip install llama-index-tools-insumer
# the Quickstart's agent additionally needs:
pip install llama-index-llms-openai
```

## Quickstart

**Get a key: no signup, no dashboard, no password.** Two paths, both return an `insr_live_...` key instantly with 10 free verifications plus 100 requests a day:

```bash
curl -X POST https://api.insumermodel.com/v1/keys/create \
    -H "Content-Type: application/json" \
    -d '{"email": "you@example.com", "appName": "my-agent", "tier": "free"}'
```

Or enter your email on [insumermodel.com](https://insumermodel.com/?utm_source=pypi-llama-index-tools-insumer), and the key appears inline. Already have a key? Manage it at [insumermodel.com/developers/account/](https://insumermodel.com/developers/account/?utm_source=pypi-llama-index-tools-insumer).

Then use the tool spec in any LlamaIndex agent:

```python
import asyncio

from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.openai import OpenAI
from llama_index.tools.insumer import InsumerToolSpec

insumer = InsumerToolSpec()  # reads INSUMER_API_KEY; or pass api_key="insr_live_..."

agent = FunctionAgent(
    tools=insumer.to_tool_list(),
    llm=OpenAI(model="gpt-4o-mini"),
)

response = asyncio.run(agent.run(
    "Does wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 "
    "hold at least 1 ETH on Ethereum?"
))
print(response)
```

## The six tools

### `attest_wallet`

Run wallet attestation against 1–10 conditions. Returns an ECDSA-signed verdict per condition plus a condition hash for tamper detection.

Supported condition types:

- `token_balance`: ERC-20 / SPL / XRPL trust line / native BTC / TRC-20 / Stellar trustline / Sui-native ≥ threshold
- `nft_ownership`: ERC-721 / Solana NFT / XRPL NFToken holding
- `eas_attestation`: EAS schema check (pass a `template` like `coinbase_verified_account` or a raw `schemaId`)
- `farcaster_id`: Farcaster ID registered on Optimism
- `ratio_to_amount`: self-scaling agent-spend rule, balance ≥ `multiple` × `amount` (EVM chains only)
- `ratio_to_supply`: share-of-supply rule, balance / `totalSupply()` ≥ `minFraction`, a fraction in (0, 1] (EVM chains only, ERC-20 only)
- `evm_view_call`: any single-address-argument view function returning bool, named by `selector` (e.g. `"hasAccess(address)"`) (EVM chains only)
- `erc8004_agent`: ERC-8004 agent registration on Base, met when the wallet owns the agent NFT for `agentId` or is its registry agentWallet binding (registration is permissionless; no vetting implied)
- `erc7710_delegation`: ERC-7710 delegation validity on Base (max 3 per call), met when the wallet is the delegate of a signed, unrevoked `delegation` from `expectedDelegator`; attestations expire in 5 minutes
- `account_code`: the code state of the wallet address itself on an EVM chain at the anchored block, named by `expect`: `"none"` (no code: a plain key account), `"eip7702"` (the EIP-7702 delegation designator: a key that has delegated execution to a contract) or `"contract"` (any other code: a smart-contract wallet, a protocol, a token); the three states are exclusive on a chain. Optional `delegate` (an EVM address, only with `expect: "eip7702"`, a 400 otherwise) makes it met only when the designator points at it. The answer is `met` only: the code and the delegation target are never returned, in any format or mode. With `proof="merkle"` the proof is an EIP-1186 account proof (`subject: "account_code"`; `codeHash` is the proven value, never the code). vitalik.eth is EIP-7702-delegated on Base, so `{"type": "account_code", "chainId": 8453, "expect": "eip7702"}` with wallet `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045` returns `met: true`, `evaluatedCondition: {"type": "account_code", "chainId": 8453, "expect": "eip7702", "operator": "code_state"}`, `conditionHash: 0x6c5752bfbfcfd6ba36c9cda6c74df567f0e0414da6b7a3176061ba734aeadc46`

`decimals` is optional on `token_balance` and `ratio_to_amount`. Leave it out: the token's own decimals are always read from the chain. If sent it is only a cross-check, and a value that differs from the token's own decimals is rejected with a 400. `contractAddress: "native"` is for `token_balance` and `ratio_to_amount` only; `nft_ownership` needs the NFT contract address and `"native"` there is a 400.

```python
insumer.attest_wallet(
    wallet="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    conditions=[
        {
            "type": "token_balance",
            "contractAddress": "native",
            "chainId": 1,
            "threshold": "1",
            "label": "ETH >= 1 on Ethereum",  # a condition the example wallet reliably meets
        },
    ],
)
```

> **`token_balance` thresholds are decimal strings**: send `"threshold": "100"`, not `100`. Keys created from 2026-06-10 sign with `kid: insumer-attest-v2` and reject a JSON number with a `400` (a string works on both v1 and v2 keys). This tool coerces a number to a string for you.

Response shape:

```python
{
    "ok": True,
    "data": {
        "attestation": {
            "id": "ATST-...",
            "pass": True,
            "results": [...],      # per-condition booleans + conditionHash
            "passCount": 1,
            "failCount": 0,
            "attestedAt": "2026-04-16T...",
            "expiresAt": "2026-04-16T...",  # +30 min
        },
        "sig": "...",              # ECDSA P-256 signature, base64 P1363
        "kid": "insumer-attest-v2",   # v2 keys; v1 keys return insumer-attest-v1
        "pqSig": "...",            # ML-DSA-65 post-quantum signature, base64
        "pqKid": "insumer-attest-pq1",
        "jwt": "...",              # only with format="jwt"; its ML-DSA-65 sibling pqJwt sits beside it
    },
    "meta": {"creditsRemaining": ..., "creditsCharged": 1, ...},
}
```

Every attest and trust response is signed twice: ES256 and a post-quantum ML-DSA-65 signature (`pqSig`, `pqKid`; `pqJwt` beside `jwt`) over the same bytes the classical `kid` selects. It is additive: `sig` and `kid` are unchanged. Trust responses carry `kid: insumer-trust-v2` and `pqKid: insumer-trust-pq1`. [insumer-verify](https://www.npmjs.com/package/insumer-verify) 1.8.1 and later report the post-quantum signature as a fifth verdict beside signature, condition hashes, freshness, and expiry.

Costs 1 credit per call (2 with `proof="merkle"` for EIP-1186 storage proofs, available on 27 of the 31 EVM chains: not ZKsync Era, Sei, Viction or XDC Network).

A rejected request raises `requests.HTTPError`. The exception message carries the API's own error message (for a 503, also the `failedConditions` list), and the response is attached as `exc.response`.

### `get_trust_profile`

Multi-dimensional wallet trust profile: stablecoins, governance, NFTs, staking, institutional stablecoins, tokenized treasuries, stablecoin deposits, wrapped bitcoin, names and account (plus Solana, XRPL, Bitcoin and Tron dimensions when those wallet addresses are supplied; Stellar and Sui wallets switch on rows inside the base dimensions). Returns a signed summary showing which dimensions have activity, without exposing raw balances. 155 base checks across 27 chains in 10 dimensions; up to 176 across 29 chains in 14 dimensions. Every check is a presence check. The `account` dimension (10 checks) reports contract code or an EIP-7702 delegation present at the wallet address on Ethereum, Base, Arbitrum, Optimism and Polygon: two rows per chain, exclusive, a plain key reads false on both; which contract is never named. The signed `conditionSetVersion` (currently `2026-10-08`) names the check list run; log it, never reject on it. Dimensions come back in a fixed order: the ten base dimensions as listed, then whichever of solana, xrpl, bitcoin and tron were switched on, in that order. A check whose chain wallet was not supplied stays in the signed profile with `evaluated: false` and is counted in `notEvaluatedCount`, never as a pass or a fail.

```python
insumer.get_trust_profile(
    wallet="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    solana_wallet="...",       # optional
    xrpl_wallet="r...",        # optional
    bitcoin_wallet="bc1q...",  # optional
    tron_wallet="T...",        # optional
    stellar_wallet="G...",     # optional
    sui_wallet="0x...",        # optional (64 hex chars)
)
```

Costs 3 credits per call (6 with `proof="merkle"`; account rows carry `proof.available: false` with a reason pointing at `/v1/attest`, where an `account_code` condition carries an account proof).

### `list_compliance_templates`

Discover pre-configured EAS compliance templates (Coinbase Verified Account, Coinbase Verified Country, Coinbase One, Gitcoin Passport, etc.). No API key required.

```python
templates = insumer.list_compliance_templates()
# Use a template name directly in attest_wallet:
insumer.attest_wallet(
    wallet="0x...",
    conditions=[{"type": "eas_attestation", "template": "coinbase_verified_account"}],
)
```

### `get_jwks`

Fetch the public JWKS used to sign attestation and trust responses. Enables offline verification of any result with a standard JWT/JOSE library. No API key required.

To run every check the specification defines (signature, condition hashes, freshness, expiry bound to the signed `attestedAt`, and the post-quantum signature) rather than the signature alone, use [insumer-verify](https://pypi.org/project/insumer-verify/) (`pip install "insumer-verify[pq]"`): `verify_attestation(response, jwks_url=...)` and `verify_trust_profile(response, jwks_url=...)` each return a `valid` flag and a per-check breakdown. It passes the same 27 published test vectors as the npm package of the same name.

The set holds five entries over two keys: the ECDSA P-256 key under three kids, followed by the ML-DSA-65 post-quantum key under two RFC 9964 `AKP` entries (raw key in `pub`). Match on the `kid` or `pqKid` your response carries, never on position; treat an unknown kid as unverifiable. Values below are from the live file:

```python
jwks = insumer.get_jwks()
# {
#     "keys": [
#         {"kty": "EC", "crv": "P-256",
#          "x": "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
#          "y": "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
#          "use": "sig", "alg": "ES256", "kid": "insumer-attest-v1"},
#         {..., "kid": "insumer-attest-v2"},   # same EC key; attest responses on current keys
#         {..., "kid": "insumer-trust-v2"},    # same EC key; trust responses on current keys
#         {"kty": "AKP", "alg": "ML-DSA-65", "use": "sig", "kid": "insumer-attest-pq1",
#          "pub": "lWQSprOGRxWovc9LfqqiQtO6..."},   # 2603-char base64url ML-DSA-65 public key
#         {..., "kid": "insumer-trust-pq1"}    # same post-quantum key
#     ]
# }
```

### `buy_api_key`

Agentic commerce: let an agent purchase its own new API key on-chain with USDC, USDT or BTC. The transaction sender wallet becomes the registered identity. No email, no signup flow, no human in the loop. No API key required to call: the payment *is* the auth.

Pre-requisite: broadcast a USDC, USDT or BTC transfer to the platform wallet first, then submit the transaction hash here.

```python
# After the agent broadcasts a 100 USDC transfer on Base to the platform wallet:
result = InsumerToolSpec().buy_api_key(
    tx_hash="0xabc...",
    chain_id=8453,            # Base; use "solana", "bitcoin", or "tron" for those chains
    app_name="my-agent",
    amount=100.0,              # USDC amount; not required for Bitcoin
)
new_key = result["data"].get("key")   # insr_live_..., shown once; omitted when the
                                      # EVM wallet receives the Insumer Access pass
                                      # (the default): it then signs with Authorization: Wallet
```

One key per wallet: if the sending wallet already has a self-serve key, the API returns 409 and asks you to top up the existing key via `buy_credits` instead.

### `buy_credits`

Top up credits on an existing API key (the one you passed to `InsumerToolSpec`) with a USDC, USDT or BTC payment. Same pattern: broadcast the transfer, submit the `tx_hash`.

```python
insumer.buy_credits(
    tx_hash="0xdef...",
    chain_id=8453,
    amount=100.0,
)
```

## No key at all: x402 pay-per-call

This tool spec authenticates with an API key (free tier: 10 free verifications plus 100 requests a day via `POST /v1/keys/create`, or on-chain purchase via `buy_api_key`). If your agent wants zero signup of any kind, the same core endpoints (`POST /v1/attest`, `POST /v1/trust`, `POST /v1/trust/batch`) also accept [x402](https://www.x402.org) payments directly: call with no credentials, receive a 402 quote, sign a USDC payment for the exact quoted amount on Base, Polygon, Arbitrum, Arc or Solana (an EIP-3009 authorization on the EVM networks), retry with the `PAYMENT-SIGNATURE` header. $0.05 per attestation ($0.10 with a Merkle proof), settlement is gasless for the payer. That flow lives outside this package (it needs wallet signing, not an LLM tool), but the responses are identical: same signed attestations, verifiable against the same JWKS.

A pay-per-call wallet whose cumulative spend qualifies is told so in the response and can then claim a soulbound Insumer Access pass (nothing mints unless the wallet asks; its first wallet-auth request is the claim), which unlocks prepaid credit rates ($0.04–$0.02/call) and single-round-trip calls. Details: [insumermodel.com/llms.txt](https://insumermodel.com/llms.txt).

## Supported chains

37 total:

- **31 EVM chains**: Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, BNB, XDC, Robinhood Chain, Arc, Unichain, Linea, zkSync, Scroll, Blast, Mantle, Celo, Gnosis, Sonic, and more
- **Solana** (mainnet)
- **XRPL** (mainnet): native XRP plus trust-line tokens
- **Bitcoin** (mainnet): native BTC only
- **Tron**: native TRX plus TRC-20 (USDT-TRC20)
- **Stellar**: native XLM plus classic trustline assets (USDC, BENJI, etc.)
- **Sui**: native SUI (`contractAddress: "0x2::sui::SUI"`; `"native"` is not accepted on Sui) plus Sui-native tokens by full coin type (USDC)

## Positioning

Wallet auth is the primitive. Condition-based access is the category. Token gating is one use case. The API turns a programmable predicate over on-chain state into a short-lived cryptographic artifact any service can verify.

- **No secrets**: conditions are public, the signature binds the condition hash.
- **No identity-first**: a wallet address and a condition are enough.
- **No static credentials**: every response has an expiry and is re-checkable.

## Other ways to reach the same API

- **Hosted MCP server**: `https://api.insumermodel.com/mcp` (MCP streamable HTTP). Connect by URL from ChatGPT, claude.ai or any hosted agent, with no install and no key. It serves ten tools on a shared daily allowance: `insumer_attest`, `insumer_wallet_trust`, `insumer_batch_wallet_trust`, `insumer_compliance_templates`, `insumer_jwks`, `insumer_list_merchants`, `insumer_get_merchant`, `insumer_list_tokens`, `insumer_check_discount` and `insumer_validate_code` (no ACP/UCP discount issuance or merchant setup). In LlamaIndex, the same endpoint can also be loaded as tools through [`llama-index-tools-mcp`](https://pypi.org/project/llama-index-tools-mcp/). For all 27 tools on your own key: `npx -y mcp-server-insumer`.
- **x402 pay-per-call**: this tool spec authenticates with an API key; the attest and trust endpoints also take x402 with no key at all (see [No key at all: x402 pay-per-call](#no-key-at-all-x402-pay-per-call) above). The discount endpoints do not take x402.

## Learn more

- Docs: [insumermodel.com/developers/](https://insumermodel.com/developers/)
- OpenAPI spec: [insumermodel.com/openapi.yaml](https://insumermodel.com/openapi.yaml)
- Public JWKS: [api.insumermodel.com/.well-known/jwks.json](https://api.insumermodel.com/.well-known/jwks.json)
- Related packages: `langchain-insumer` (LangChain), `mcp-server-insumer` (Model Context Protocol), `@insumermodel/plugin-eliza` (ElizaOS)

## License

Apache-2.0
