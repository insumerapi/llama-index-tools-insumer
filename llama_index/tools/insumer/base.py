"""InsumerAPI tool spec for LlamaIndex.

Wallet auth and condition-based access across 37 chains.
Read → evaluate → sign → keep. Returns an ECDSA-signed boolean you
can verify offline against our public JWKS. Boolean, not balance: the API
never exposes wallet holdings, only a signed yes-or-no against the
conditions you configure.
"""

import os

from typing import Any, Dict, List, Optional

from decimal import Decimal

import requests
from llama_index.core.tools.tool_spec.base import BaseToolSpec

DEFAULT_BASE_URL = "https://api.insumermodel.com"
DEFAULT_JWKS_URL = "https://api.insumermodel.com/.well-known/jwks.json"
DEFAULT_TIMEOUT = 30



def _decimal_str(value: Any) -> str:
    """A number as a plain decimal string.

    ``str()`` of a float switches to exponent notation for very small and very
    large values ("1e-07"), which the API does not read as a decimal string.
    """
    if isinstance(value, bool):
        raise ValueError("a condition quantity must be a number or a decimal string, not a bool")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return format(Decimal(repr(value)), "f")
    return str(value)

def _raise_for_status(response: requests.Response) -> None:
    """Raise ``requests.HTTPError`` on a 4xx/5xx, carrying the API's own message.

    The API explains a rejected request in its JSON body (``error.message``),
    and a refused read (503) lists the conditions it could not read in
    ``error.failedConditions``. Both are included in the exception message so
    the caller, or the agent, can see what to change. The response is attached
    as ``exc.response``. When the body is not JSON, the plain status error is
    raised.
    """
    status = response.status_code
    if not isinstance(status, int) or status < 400:
        return
    detail = ""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            parts = []
            if err.get("code"):
                parts.append(str(err["code"]))
            if err.get("message"):
                parts.append(str(err["message"]))
            detail = ": ".join(parts)
            failed = err.get("failedConditions")
            if failed:
                detail = f"{detail} (failedConditions: {failed})"
        elif isinstance(err, str):
            detail = err
    if not detail:
        response.raise_for_status()
        raise requests.HTTPError(
            f"InsumerAPI returned HTTP {status}", response=response
        )
    raise requests.HTTPError(
        f"InsumerAPI returned HTTP {status}: {detail}", response=response
    )


class InsumerToolSpec(BaseToolSpec):
    """Tool spec for InsumerAPI.

    Exposes six methods as LlamaIndex tools:

    - ``attest_wallet``: run wallet attestation against one or more conditions
      (token balance, NFT ownership, EAS attestation, Farcaster ID, view
      calls, ratios, ERC-8004 registration, ERC-7710 delegation, account
      code state) across 37 chains. Returns an ECDSA-signed boolean verdict
      per condition plus condition hashes for tamper detection.
    - ``get_trust_profile``: fetch a multi-dimensional wallet trust profile
      (stablecoins, governance, NFTs, staking, institutional stablecoins,
      tokenized treasuries, stablecoin deposits, wrapped bitcoin, names and
      account, plus optional Solana/XRPL/Bitcoin/Tron dimensions). Returns a
      signed summary of which dimensions show activity. 155 base checks
      across 27 chains in 10 dimensions, up to 176 across 29 chains in 14.
    - ``list_compliance_templates``: discover pre-configured compliance
      templates (Coinbase Verified Account, Gitcoin Passport, etc.) usable
      directly in attest_wallet without raw EAS schema IDs. No API key
      required.
    - ``get_jwks``: fetch the JSON Web Key Set used to verify signatures on
      attestation and trust responses: the ECDSA P-256 key under three kids
      plus the ML-DSA-65 post-quantum companion key under two RFC 9964 AKP
      entries. No API key required. Enables offline verification.
    - ``buy_api_key``: let an agent purchase its own new API key on-chain with
      USDC, USDT, or BTC, no human in the loop. Wallet address is the
      identity; no email required.
    - ``buy_credits``: top up credits on an existing API key with a USDC,
      USDT, or BTC payment, no out-of-band billing.
    """

    spec_functions = [
        "attest_wallet",
        "get_trust_profile",
        "list_compliance_templates",
        "get_jwks",
        "buy_api_key",
        "buy_credits",
    ]

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the InsumerAPI tool spec.

        Args:
            api_key: Your InsumerAPI key (format ``insr_live_...``). Falls
                back to the ``INSUMER_API_KEY`` environment variable when
                omitted, so keys stay out of source code. Required for
                ``attest_wallet`` and ``get_trust_profile``. Not needed for
                ``list_compliance_templates`` or ``get_jwks``. Get a free key
                at https://insumermodel.com/developers/.
            base_url: API base URL. Defaults to ``https://api.insumermodel.com``.
            timeout: HTTP request timeout in seconds. Defaults to 30.
        """
        self.api_key = api_key or os.environ.get("INSUMER_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, include_auth: bool = True) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if include_auth:
            if not self.api_key:
                raise ValueError(
                    "InsumerAPI key required for this operation. "
                    "Get one at https://insumermodel.com/developers/."
                )
            headers["X-API-Key"] = self.api_key
        return headers

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}{path}",
            json=body,
            headers=self._headers(include_auth=True),
            timeout=self.timeout,
        )
        _raise_for_status(response)
        return response.json()

    def _get(self, path: str, include_auth: bool = False) -> Dict[str, Any]:
        response = requests.get(
            f"{self.base_url}{path}",
            headers=self._headers(include_auth=include_auth),
            timeout=self.timeout,
        )
        _raise_for_status(response)
        return response.json()

    def attest_wallet(
        self,
        conditions: List[Dict[str, Any]],
        wallet: Optional[str] = None,
        solana_wallet: Optional[str] = None,
        xrpl_wallet: Optional[str] = None,
        bitcoin_wallet: Optional[str] = None,
        tron_wallet: Optional[str] = None,
        stellar_wallet: Optional[str] = None,
        sui_wallet: Optional[str] = None,
        proof: Optional[str] = None,
        format: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run wallet attestation against 1-10 conditions. Returns an
        ECDSA-signed verdict per condition.

        Wallet auth primitive: read → evaluate → sign → keep. The API
        reads the relevant wallet state (token balance, NFT ownership, EAS
        attestation, Farcaster ID, a balance ratio, or the account's code
        state), evaluates it against the caller-specified condition, and
        returns a signed boolean. Raw balances are never returned in standard mode
        (use proof="merkle" if you want the storage proof, which reveals the
        balance); code and delegation targets are never returned in any
        mode.

        Args:
            conditions: List of 1 to 10 condition objects. Each object must
                have a ``type`` field: ``token_balance``, ``nft_ownership``
                (33 of the 37 chains: EVM + Solana + XRPL; Bitcoin, Tron,
                Stellar and Sui are token-balance only), ``eas_attestation``,
                ``farcaster_id``, ``evm_view_call``, ``ratio_to_amount``,
                ``ratio_to_supply``, ``erc8004_agent``,
                ``erc7710_delegation``, or ``account_code``.
                ``account_code`` (EVM chains only; a non-EVM ``chainId`` is
                a 400; no ``contractAddress``) requires ``chainId`` and
                ``expect``, the code state the wallet address itself must
                be in at the anchored block: ``"none"`` (no code: a plain
                key account), ``"eip7702"`` (the EIP-7702 delegation
                designator: a key that has delegated execution to a
                contract) or ``"contract"`` (any other code: a
                smart-contract wallet, a protocol, a token). The three
                states are exclusive on a chain. Optional ``delegate`` (an
                EVM address, only with ``expect: "eip7702"``; a 400 with
                any other expect): met iff the designator points at it. The
                answer is ``met`` only: the code and the delegation target
                are never returned, in any format or mode; a supplied
                ``delegate`` is echoed (lowercase) inside the signed
                ``evaluatedCondition`` (``{type, chainId, expect, operator:
                "code_state"}``). Example: ``{"type": "account_code",
                "chainId": 8453, "expect": "eip7702"}``. Token balance conditions require
                ``contractAddress``, ``chainId`` and ``threshold`` (a decimal
                string in token units, e.g. ``"100"``; a number is coerced).
                ``decimals`` is optional. Leave it out: the token's own
                decimals are always read from the chain. If sent it is only
                a cross-check, and a value that differs from the token's own
                decimals is rejected with a 400. ``contractAddress:
                "native"`` is for ``token_balance`` and ``ratio_to_amount``
                only; ``nft_ownership`` needs the NFT contract address (0x +
                40 hex on EVM) and ``"native"`` there is a 400. EAS
                conditions can use a pre-configured
                ``template`` (from list_compliance_templates) or a raw
                ``schemaId``. ``ratio_to_amount`` (EVM chains only)
                requires ``contractAddress``, ``chainId``, ``multiple``, and
                ``amount``: met iff balance >= multiple * amount.
                ``ratio_to_supply`` (EVM chains only, ERC-20 only) requires
                ``contractAddress``, ``chainId``, and ``minFraction``, a
                fraction in (0, 1]: met iff balance / totalSupply >=
                minFraction. ``evm_view_call`` (EVM chains only) requires
                ``contractAddress`` and ``selector``, the canonical
                signature of a single-address-argument view function
                returning bool (e.g. ``"hasAccess(address)"``).
                ``erc8004_agent`` (Base, chainId 8453) requires
                ``agentId``, a uint256 decimal string: met iff the wallet
                owns the agent NFT or is the registry's agentWallet binding
                (registration is permissionless; no vetting implied).
                ``erc7710_delegation`` (Base, chainId 8453, max 3 per
                call) requires ``delegationManager``,
                ``expectedDelegator``, and ``delegation`` ({delegator,
                delegate, authority, caveats, salt, signature}): met iff
                the wallet is the delegate, the delegator matches, the
                EIP-712 signature verifies (EOA or ERC-1271), unrevoked at
                the anchored block, all caveat enforcers recognized, and
                time windows are satisfied. Spend/target/call limits are
                reported as declaredLimits, not simulated; delegation
                attestations expire in 5 minutes. An XRPL trust line
                token condition (``chainId: "xrpl"``, ``contractAddress``
                is the issuer r-address) requires ``currency`` (e.g.
                ``"RLUSD"``). Currency codes are case-sensitive: send the
                code exactly as the issuer created it and never change its
                letter case. For XRP itself use ``contractAddress:
                "native"`` with no ``currency``. ``taxon`` is an optional
                XRPL NFToken taxon filter: a whole number from 0 to
                4294967295.
            wallet: EVM wallet address (0x + 40 hex). Required if any
                condition targets an EVM chain.
            solana_wallet: Solana wallet address (base58, 32-44 chars).
                Required for conditions with ``chainId: "solana"``.
            xrpl_wallet: XRPL address (r-address, 25-35 chars). Required for
                conditions with ``chainId: "xrpl"``.
            bitcoin_wallet: Bitcoin address (P2PKH, P2SH, bech32, or Taproot).
                Required for conditions with ``chainId: "bitcoin"``. Bitcoin
                only supports ``token_balance`` with ``contractAddress:
                "native"``.
            tron_wallet: Tron address (T-prefixed base58, 34 chars). Required
                for conditions with ``chainId: "tron"``. Supports native TRX
                (``contractAddress: "native"``) and TRC-20 tokens like
                USDT-TRC20.
            stellar_wallet: Stellar address (G-prefixed, 56 chars). Required
                for conditions with ``chainId: "stellar"``. Supports native
                XLM (``contractAddress: "native"``) and classic trustline
                assets: pass the issuer G-address as ``contractAddress`` and
                the asset code (e.g. ``"USDC"``, ``"BENJI"``) as
                ``assetCode``. Soroban contract balances are not visible.
            sui_wallet: Sui address (0x + 64 hex chars). Required for
                conditions with ``chainId: "sui"``. On Sui ``contractAddress``
                is the full coin type ``address::module::Name``: native SUI
                is ``"0x2::sui::SUI"`` (``"native"`` is not accepted on Sui,
                it is a 400), and other coins look like
                ``"0xdba34672...::usdc::USDC"``.
            proof: Set to ``"merkle"`` to include EIP-1186 Merkle proofs in
                results: a storage proof of the balance slot for a ``token_balance``
                or ``ratio_to_amount`` condition (an account proof, ``subject:
                "account_balance"``, when ``contractAddress`` is ``"native"``), a
                revocation-slot proof (``subject: "delegation_revocation"``) for an
                ``erc7710_delegation`` condition, an account proof (``subject: "account_code"``; fields
                ``blockNumber``, ``nonce``, ``balance``, ``storageHash``,
                ``codeHash``, ``accountProof``) for an ``account_code``
                condition, on 27 of the 31 EVM chains (not ZKsync Era, Sei,
                Viction or XDC Network). Costs 2 credits instead of 1,
                refunded to 1 when no proof is delivered. A storage proof
                reveals the raw balance to the caller; an account proof
                carries ``codeHash``, never the code.
            format: Set to ``"jwt"`` to include an ES256-signed JWT in the
                response alongside the boolean result, with its ML-DSA-65
                sibling ``pqJwt`` beside it.

        Returns:
            API response envelope. On success:

            .. code-block:: python

                {
                    "ok": True,
                    "data": {
                        "attestation": {
                            "id": "ATST-...",
                            "pass": bool,
                            "results": [...],
                            "passCount": int,
                            "failCount": int,
                            "attestedAt": ISO8601,
                            "expiresAt": ISO8601,
                        },
                        "sig": str,                # ECDSA P-256, base64 P1363
                        "kid": str,                # "insumer-attest-v2" on v2 keys;
                                                   # "insumer-attest-v1" on v1 keys
                        "pqSig": str,              # ML-DSA-65 post-quantum companion,
                                                   # base64; additive, sig/kid unchanged
                        "pqKid": str,              # "insumer-attest-pq1"
                        "jwt": str,                # if format="jwt"
                        "pqJwt": str,              # if format="jwt": ML-DSA-65 sibling
                    },
                    "meta": {"creditsRemaining": int, "creditsCharged": int, ...},
                }
        """
        # v2 keys require agent-supplied quantities as decimal strings (full precision,
        # no float in signed bytes); v1 keys accept either. Coerce numbers to strings so
        # the request works on any key. (str() only: the builtin format() is shadowed by
        # the `format` parameter of this method.)
        #   token_balance.threshold, ratio_to_amount.multiple/amount, ratio_to_supply.minFraction.
        _str_fields = {
            "token_balance": ("threshold",),
            "ratio_to_amount": ("multiple", "amount"),
            "ratio_to_supply": ("minFraction",),
        }
        norm_conditions: List[Dict[str, Any]] = []
        for c in conditions:
            if isinstance(c, dict):
                fields = _str_fields.get(c.get("type"))
                if fields:
                    updates = {
                        f: _decimal_str(c[f])
                        for f in fields
                        if c.get(f) is not None and not isinstance(c[f], str)
                    }
                    if updates:
                        c = {**c, **updates}
            norm_conditions.append(c)
        body: Dict[str, Any] = {"conditions": norm_conditions}
        if wallet:
            body["wallet"] = wallet
        if solana_wallet:
            body["solanaWallet"] = solana_wallet
        if xrpl_wallet:
            body["xrplWallet"] = xrpl_wallet
        if bitcoin_wallet:
            body["bitcoinWallet"] = bitcoin_wallet
        if tron_wallet:
            body["tronWallet"] = tron_wallet
        if stellar_wallet:
            body["stellarWallet"] = stellar_wallet
        if sui_wallet:
            body["suiWallet"] = sui_wallet
        if proof:
            body["proof"] = proof
        if format:
            body["format"] = format
        return self._post("/v1/attest", body)

    def get_trust_profile(
        self,
        wallet: str,
        solana_wallet: Optional[str] = None,
        xrpl_wallet: Optional[str] = None,
        bitcoin_wallet: Optional[str] = None,
        tron_wallet: Optional[str] = None,
        stellar_wallet: Optional[str] = None,
        sui_wallet: Optional[str] = None,
        proof: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch a multi-dimensional wallet trust profile. Returns an
        ECDSA-signed summary across the stablecoins, governance, nfts,
        staking, institutional_stablecoins, tokenized_treasuries,
        stablecoin_deposits, wrapped_bitcoin, names and account dimensions
        (plus solana/xrpl/bitcoin/tron dimensions when those wallet addresses
        are provided; Stellar and Sui rows sit inside the base dimensions:
        institutional_stablecoins, and tokenized_treasuries for USDY on Sui).

        Trust profile reports which dimensions show activity. Each dimension
        runs a curated set of presence checks (a balance above zero, an NFT
        held, or a code state present; never the balance or the code
        itself): 155 base checks across 27 chains in 10 dimensions, up to 176
        across 29 chains in 14 dimensions with the optional wallets. The
        account dimension (10 checks) reports contract code or an EIP-7702
        delegation present at the wallet address on Ethereum, Base, Arbitrum,
        Optimism and Polygon: two rows per chain, exclusive, a plain key
        reads false on both; which contract is never named. A check
        whose chain wallet was not supplied stays in the signed profile with
        ``evaluated: False`` and ``reason: "wallet_not_provided"``, counted in
        ``notEvaluatedCount`` rather than passed or failed. The signed
        ``conditionSetVersion`` (currently ``"2026-10-08"``) names the check
        list that was run; log it, never reject on it. Dimensions come back
        in a fixed order: the base dimensions in the order above, then
        whichever of solana, xrpl, bitcoin and tron were switched on, in that
        order. The response includes per-check booleans, a summary, and a
        signature over the whole payload. 3 credits standard, 6 with
        proof="merkle".

        Args:
            wallet: EVM wallet address to profile (required, 0x + 40 hex).
            solana_wallet: Optional Solana address. Adds the 14-check solana
                dimension (USDC, EURC, OUSD, PYUSD, USD1, USDG, USDS, BUIDL,
                USDY, WBTC, cbBTC, tBTC, JitoSOL, mSOL) and lets the
                institutional EURCV/USDCV on Solana rows evaluate.
            xrpl_wallet: Optional XRPL r-address. Adds the xrpl dimension
                (RLUSD, USDC, OUSG) and lets the institutional EURCV on XRPL
                row evaluate.
            bitcoin_wallet: Optional Bitcoin address. Adds the bitcoin
                dimension (one native BTC presence check).
            tron_wallet: Optional Tron T-address. Adds the tron dimension
                (USDT, USD1, WBTC on Tron).
            stellar_wallet: Optional Stellar G-address. Adds no dimension; lets
                the institutional USDC and BENJI (Franklin) trustline rows on
                Stellar evaluate.
            sui_wallet: Optional Sui address (0x + 64 hex). Adds no dimension;
                lets the institutional USDC on Sui and tokenized-treasury USDY
                on Sui rows evaluate.
            proof: Set to ``"merkle"`` for EIP-1186 Merkle storage proofs on
                EVM token checks, on 27 of the 31 EVM chains (not ZKsync Era,
                Sei, Viction or XDC Network). Rows whose balance is computed
                rather than stored (Aave aTokens, BUIDL), NFT rows, non-EVM
                rows and account rows (``proof.available: False`` with a
                reason pointing at ``/v1/attest``) are declined with a
                reason, and the premium is refunded whenever no proof is
                delivered. Costs 6 credits instead of 3.

        Returns:
            API response envelope. On success:

            .. code-block:: python

                {
                    "ok": True,
                    "data": {
                        "trust": {
                            "id": "TRST-...",
                            "wallet": "0x...",
                            "conditionSetVersion": "2026-10-08",   # dated set id, signed; log it, never reject on it
                            "dimensions": {                        # fixed order: these ten, then the optional ones switched on
                                "stablecoins": {"checks": [...], "passCount": int, "failCount": int, "notEvaluatedCount": int, "total": int},
                                "governance": {...},
                                "nfts": {...},
                                "staking": {...},
                                "institutional_stablecoins": {...},   # 8 checks, always present; Solana/XRPL/Stellar/Sui rows evaluated: false without the wallet
                                "tokenized_treasuries": {...},        # 16 checks, always present; USDY on Sui needs sui_wallet
                                "stablecoin_deposits": {...},         # 39 checks, always present
                                "wrapped_bitcoin": {...},             # 12 checks, always present
                                "names": {...},                       # 2 checks, always present
                                "account": {...},                     # 10 checks, always present: contract code / EIP-7702 delegation on Ethereum, Base, Arbitrum, Optimism, Polygon
                                # Optional dimensions when wallet addresses provided, in this order:
                                "solana": {...},
                                "xrpl": {...},
                                "bitcoin": {...},
                                "tron": {...},
                            },
                            "summary": {
                                "totalChecks": int,
                                "totalPassed": int,
                                "totalFailed": int,
                                "totalNotEvaluated": int,   # passed + failed + not evaluated = totalChecks
                                "dimensionsWithActivity": int,
                                "dimensionsChecked": int,
                            },
                            "profiledAt": ISO8601,
                            "expiresAt": ISO8601,
                        },
                        "sig": str,                # ECDSA P-256, base64 P1363
                        "kid": str,                # "insumer-trust-v2" on v2 keys;
                                                   # "insumer-attest-v1" on v1 keys
                        "pqSig": str,              # ML-DSA-65 post-quantum companion,
                                                   # base64; additive, sig/kid unchanged
                        "pqKid": str,              # "insumer-trust-pq1"
                    },
                    "meta": {"creditsRemaining": int, "creditsCharged": int, ...},
                }
        """
        body: Dict[str, Any] = {"wallet": wallet}
        if solana_wallet:
            body["solanaWallet"] = solana_wallet
        if xrpl_wallet:
            body["xrplWallet"] = xrpl_wallet
        if bitcoin_wallet:
            body["bitcoinWallet"] = bitcoin_wallet
        if tron_wallet:
            body["tronWallet"] = tron_wallet
        if stellar_wallet:
            body["stellarWallet"] = stellar_wallet
        if sui_wallet:
            body["suiWallet"] = sui_wallet
        if proof:
            body["proof"] = proof
        return self._post("/v1/trust", body)

    def list_compliance_templates(self) -> Dict[str, Any]:
        """Discover pre-configured compliance templates for EAS attestations.

        Templates abstract away raw EAS schema IDs, attester addresses, and
        decoder contracts. Pass the template name directly as
        ``conditions[].template`` in attest_wallet.

        No API key required.

        Returns:
            API response envelope. On success:

            .. code-block:: python

                {
                    "ok": True,
                    "data": {
                        "templates": {
                            "coinbase_verified_account": {
                                "provider": "Coinbase",
                                "description": "Coinbase Verified Account",
                                "chainId": 8453,
                                "chainName": "Base",
                            },
                            "gitcoin_passport_score": {...},
                            ...
                        }
                    },
                    "meta": {...},
                }
        """
        return self._get("/v1/compliance/templates", include_auth=False)

    def get_jwks(self) -> Dict[str, Any]:
        """Fetch the public JSON Web Key Set for offline verification of
        signatures on attestation and trust responses.

        Standard JWKS format, five entries over two keys: the ECDSA P-256 key
        under three kids, followed by the ML-DSA-65 post-quantum companion key
        under two RFC 9964 ``AKP`` entries (raw key in ``pub``). Match on the
        ``kid`` or ``pqKid`` your response carries, never on position; treat
        an unknown kid as unverifiable. The EC entries work with any JWT/JOSE
        library (jose, PyJWT, python-jose, etc.); ML-DSA-65 needs a FIPS 204
        implementation. No API key required.

        Returns:
            JWKS response (values from the live file):

            .. code-block:: python

                {
                    "keys": [
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "JtHPhDPnv8AfP0JSlGutxbOlxreV2Chey27Z76q3V2c",
                            "y": "kn34HaxVSJfn8NxwNEBjjLkcrM_GDw1lgnqyADGuc4c",
                            "use": "sig",
                            "alg": "ES256",
                            "kid": "insumer-attest-v1",
                        },
                        {..., "kid": "insumer-attest-v2"},  # same EC key; attest on current keys
                        {..., "kid": "insumer-trust-v2"},   # same EC key; trust on current keys
                        {
                            "kty": "AKP",
                            "alg": "ML-DSA-65",
                            "use": "sig",
                            "kid": "insumer-attest-pq1",
                            "pub": "lWQSprOGRxWovc9LfqqiQtO6...",  # 2603-char base64url key
                        },
                        {..., "kid": "insumer-trust-pq1"},  # same post-quantum key
                    ]
                }
        """
        # JWKS is served at the same origin but at /.well-known/jwks.json
        # rather than /v1/*, so we hit the full URL directly.
        response = requests.get(
            DEFAULT_JWKS_URL if self.base_url == DEFAULT_BASE_URL
            else f"{self.base_url}/.well-known/jwks.json",
            timeout=self.timeout,
        )
        _raise_for_status(response)
        return response.json()

    def buy_api_key(
        self,
        tx_hash: str,
        chain_id: Any,
        app_name: str,
        amount: Optional[float] = None,
        channel: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Buy a new API key on-chain with USDC, USDT, or BTC. Agent-friendly:
        the sender wallet address of the transaction becomes the registered
        identity on the new key. No email, no human signup flow.

        Pre-requisite: the agent must have already broadcast a USDC, USDT, or
        BTC transfer to the platform wallet BEFORE calling this method. The
        transaction hash is then submitted here for on-chain verification.
        USDC and USDT are auto-detected on EVM chains and Solana; USDT-TRC20
        is supported on Tron.

        One key per wallet: if the sending wallet already has a self-serve
        key, the API returns 409 and asks you to top up the existing key
        with ``buy_credits`` instead.

        Keys from this endpoint have tier ``paid`` and no fixed expiry.

        Args:
            tx_hash: Transaction hash of the USDC, USDT, or BTC transfer to the
                platform wallet. Must not have been used before.
            chain_id: Either an EVM chain ID (int, e.g. 1, 8453, 10) for USDC
                or USDT transfers, the string ``"solana"`` for USDC or USDT on
                Solana, the string ``"tron"`` for USDT-TRC20 on Tron, or the
                string ``"bitcoin"`` for BTC.
            app_name: Human-readable name for the key (max 100 chars).
            amount: Stablecoin amount paid in USD (required for USDC, USDT,
                and USDT-TRC20 chains). Not required for Bitcoin: the USD
                value is derived from the on-chain BTC amount at market
                rate.
            channel: Optional tracking tag for the purchase channel.

        Returns:
            API response envelope. ``key`` (the raw API key, shown once) is
            omitted when the paying EVM wallet receives the Insumer Access
            pass on this purchase, the default; that wallet then
            authenticates with ``Authorization: Wallet``. It is returned on
            non-EVM purchases and whenever the pass cannot be delivered:

            .. code-block:: python

                {
                    "ok": True,
                    "data": {
                        "success": True,
                        "key": "insr_live_...",           # the raw key; show once
                        "name": str,
                        "tier": "paid",
                        "dailyLimit": 10000,
                        "creditsAdded": int,
                        "totalCredits": int,
                        "effectiveRate": "$0.04/credit",
                        "chainName": str,
                        "registeredWallet": "0x...",
                        # Bitcoin only:
                        "btcPaid": str, "btcPrice": float, "usdEquivalent": str,
                        # USDC or USDT (usdcPaid carries the stablecoin amount,
                        # USDC or USDT):
                        "usdcPaid": str,
                    },
                    "meta": {...},
                }
        """
        body: Dict[str, Any] = {
            "txHash": tx_hash,
            "chainId": chain_id,
            "appName": app_name,
        }
        if amount is not None:
            body["amount"] = amount
        if channel:
            body["channel"] = channel
        # This endpoint is public (no auth); the transaction sender wallet
        # is the identity.
        response = requests.post(
            f"{self.base_url}/v1/keys/buy",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=self.timeout,
        )
        _raise_for_status(response)
        return response.json()

    def buy_credits(
        self,
        tx_hash: str,
        chain_id: Any,
        amount: Optional[float] = None,
        update_wallet: bool = False,
    ) -> Dict[str, Any]:
        """Top up attestation credits on an existing API key with a USDC,
        USDT, or BTC payment. Requires the API key the tool spec was
        initialized with.

        Pre-requisite: the agent or operator must have already broadcast a
        USDC, USDT, or BTC transfer to the platform wallet BEFORE calling
        this method. USDC and USDT are auto-detected on EVM chains and
        Solana; USDT-TRC20 is supported on Tron.

        Args:
            tx_hash: Transaction hash of the USDC, USDT, or BTC transfer to
                the platform wallet. Must not have been used before.
            chain_id: Either an EVM chain ID (int) for USDC or USDT
                transfers, the string ``"solana"`` for USDC or USDT on
                Solana, the string ``"tron"`` for USDT-TRC20 on Tron, or
                the string ``"bitcoin"`` for BTC.
            amount: Stablecoin amount paid in USD (required for USDC, USDT,
                and USDT-TRC20 chains). Not required for Bitcoin: USD
                value is derived from the on-chain BTC amount at market
                rate.
            update_wallet: If the transaction sender differs from the wallet
                currently registered on this API key, set to ``True`` to
                rebind the registered wallet to the new sender. Defaults to
                ``False``, which rejects mismatched senders with a 403.

        Returns:
            API response envelope:

            .. code-block:: python

                {
                    "ok": True,
                    "data": {
                        "creditsAdded": int,
                        "totalCredits": int,
                        "effectiveRate": "$0.04/credit",
                        "chainName": str,
                        # USDC or USDT (usdcPaid carries the stablecoin amount,
                        # USDC or USDT):
                        "usdcPaid": str,
                        # Bitcoin:
                        "btcPaid": str, "btcPrice": float, "usdEquivalent": str,
                    },
                    "meta": {...},
                }
        """
        body: Dict[str, Any] = {
            "txHash": tx_hash,
            "chainId": chain_id,
        }
        if amount is not None:
            body["amount"] = amount
        if update_wallet:
            body["updateWallet"] = True
        return self._post("/v1/credits/buy", body)
