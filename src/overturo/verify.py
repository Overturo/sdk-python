"""
Receipt verification (Ed25519) + JWKS cache.

Embedded in this SDK (no separate package — Python ecosystem doesn't
fragment standalone verification the way JS does).

Validates: JWT structure, signature (Ed25519 via `cryptography`),
`iss_role` claim presence + closed-enum membership, temporal claims
(iat / exp with configurable clock skew). Returns the payload
augmented with the computed `trust_weight`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authorize.receipt import b64url_decode, peek_receipt
from .errors import ReceiptInvalid
from .models import JwksKey, OfflineVerifyResult, VerifiedReceipt
from .oversight.iss_role import ISS_ROLE_TO_TRUST_WEIGHT, is_valid_iss_role


@dataclass
class _CachedJwks:
    keys: list[dict]
    expires_at: float


class JwksCache:
    """Per-URL JWKS cache; honors `Cache-Control: max-age`.

    G7 — single-flight: concurrent `fetch(url)` calls on a cold cache
    share the same in-flight asyncio.Task instead of each issuing its
    own HTTPS round-trip. Lock is `threading.Lock` because we only
    hold it around the dict ops (never across an `await`).
    """

    _entries: dict[str, _CachedJwks]
    _inflight: dict[str, asyncio.Future[list[dict]]]
    _default_ttl: float
    _lock: threading.Lock

    def __init__(self, default_ttl_seconds: float = 300.0) -> None:
        self._entries = {}
        self._inflight = {}
        self._default_ttl = default_ttl_seconds
        self._lock = threading.Lock()

    async def fetch(self, jwks_url: str, client: httpx.AsyncClient | None = None) -> list[dict]:
        with self._lock:
            cached = self._entries.get(jwks_url)
            if cached and cached.expires_at > time.time():
                return cached.keys
            inflight = self._inflight.get(jwks_url)
            if inflight is not None:
                # Hand off to the existing in-flight fetch.
                return await asyncio.shield(inflight)
            future: asyncio.Future[list[dict]] = asyncio.get_event_loop().create_future()
            self._inflight[jwks_url] = future

        try:
            keys = await self._do_fetch(jwks_url, client=client)
        except BaseException as e:
            with self._lock:
                self._inflight.pop(jwks_url, None)
            if not future.done():
                future.set_exception(e)
            raise
        else:
            with self._lock:
                self._inflight.pop(jwks_url, None)
            if not future.done():
                future.set_result(keys)
            return keys

    async def _do_fetch(self, jwks_url: str, client: httpx.AsyncClient | None = None) -> list[dict]:
        owns_client = client is None
        if owns_client:
            client = httpx.AsyncClient(timeout=10.0)
        try:
            response = await client.get(jwks_url)
        except httpx.HTTPError as e:
            raise ReceiptInvalid(
                "jwks_fetch_failed",
                f"Network error fetching JWKS at {jwks_url}: {e}",
            ) from e
        finally:
            if owns_client and client is not None:
                await client.aclose()

        if response.status_code >= 400:
            raise ReceiptInvalid(
                "jwks_fetch_failed",
                f"JWKS fetch at {jwks_url} returned HTTP {response.status_code}",
            )

        try:
            body = response.json()
            keys = body["keys"]
            if not isinstance(keys, list):
                raise KeyError
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            raise ReceiptInvalid(
                "jwks_fetch_failed", f"JWKS at {jwks_url} missing `keys` array"
            ) from e

        ttl = _parse_max_age(response.headers.get("cache-control")) or self._default_ttl
        with self._lock:
            self._entries[jwks_url] = _CachedJwks(keys=keys, expires_at=time.time() + ttl)
        return keys

    def invalidate(self, jwks_url: str) -> None:
        with self._lock:
            self._entries.pop(jwks_url, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    async def find_key(
        self,
        jwks_url: str,
        kid: str,
        client: httpx.AsyncClient | None = None,
    ) -> dict:
        keys = await self.fetch(jwks_url, client=client)
        for k in keys:
            if k.get("kid") == kid:
                return k
        # Cache miss — possibly server-side rotation. Refetch once.
        self.invalidate(jwks_url)
        keys = await self.fetch(jwks_url, client=client)
        for k in keys:
            if k.get("kid") == kid:
                return k
        raise ReceiptInvalid(
            "unknown_kid", f"JWKS at {jwks_url} has no key with kid={kid} (after refetch)"
        )


# Module singleton; tests + long-running apps may reset via `_reset_jwks_cache`.
_global_cache = JwksCache()


def _reset_jwks_cache() -> None:
    """Test helper — drop cached JWKS across all URLs."""
    _global_cache.clear()


async def verify_receipt(
    jwt: str,
    *,
    jwks_url: str | None = None,
    jwks: dict | None = None,
    clock_skew_seconds: int = 300,
    http_client: httpx.AsyncClient | None = None,
    expected_issuer: Any | None = None,  # str | list[str]
    audience: Any | None = None,  # str | list[str]
) -> VerifiedReceipt:
    """Verify an Overturo-issued receipt JWT.

    Either `jwks_url` (lazy fetch) or `jwks` (pre-fetched JWKS dict
    with `keys` array) must be supplied.

    G8 — Optional `expected_issuer` and `audience` reject the receipt
    if the `iss` / `aud` claim doesn't match. Both default to None
    (no validation) for back-compat; counterparty verifiers SHOULD
    set them to defend against malicious or misconfigured receipts.
    """
    if jwks_url is None and jwks is None:
        raise ReceiptInvalid("jwks_fetch_failed", "Either `jwks_url` or `jwks` must be supplied")

    header, payload, signed, signature = _parse_jwt(jwt)

    if header.get("alg") != "EdDSA":
        raise ReceiptInvalid(
            "unsupported_algorithm",
            f"Receipts MUST be signed with EdDSA (Ed25519); got {header.get('alg')}",
        )
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise ReceiptInvalid("malformed_jwt", "JWT header missing `kid`")

    if "iss_role" not in payload:
        raise ReceiptInvalid(
            "missing_iss_role",
            "Missing required iss_role claim — refusing to verify witness/authorizer-ambiguous receipt",
        )
    if not is_valid_iss_role(payload["iss_role"]):
        raise ReceiptInvalid("unknown_iss_role", f"Unknown iss_role: {payload['iss_role']!r}")

    if jwks is not None:
        key = _find_key_in_jwks(jwks, kid)
    else:
        assert jwks_url is not None  # for type-checker
        key = await _global_cache.find_key(jwks_url, kid, client=http_client)

    _verify_ed25519(signed, signature, key)
    _validate_temporal(payload, clock_skew_seconds)
    _validate_issuer_audience(payload, expected_issuer=expected_issuer, audience=audience)

    iss_role = payload["iss_role"]
    known_keys = {"iss", "iat", "exp", "jti", "sub", "aud", "iss_role"}
    extras = {k: v for k, v in payload.items() if k not in known_keys}
    return VerifiedReceipt(
        iss=str(payload.get("iss", "")),
        iat=int(payload.get("iat", 0)),
        exp=int(payload["exp"]) if isinstance(payload.get("exp"), (int, float)) else None,
        jti=payload.get("jti"),
        sub=payload.get("sub"),
        aud=payload.get("aud"),
        iss_role=iss_role,
        trust_weight=ISS_ROLE_TO_TRUST_WEIGHT[iss_role],
        extra=extras,
    )


# ── internals ──────────────────────────────────────────────────────


def _parse_jwt(jwt: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ReceiptInvalid("malformed_jwt", "JWT must have exactly 3 dot-separated parts")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as e:
        raise ReceiptInvalid(
            "malformed_jwt", "JWT header or payload is not valid base64url-encoded JSON"
        ) from e

    if not isinstance(header.get("alg"), str):
        raise ReceiptInvalid("malformed_jwt", "JWT header missing `alg`")

    signed = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode_bytes(signature_b64)
    return header, payload, signed, signature


def _find_key_in_jwks(jwks: dict, kid: str) -> dict:
    keys = jwks.get("keys", [])
    for k in keys:
        if k.get("kid") == kid:
            return k
    raise ReceiptInvalid("unknown_kid", f"JWKS has no key with kid={kid}")


def _verify_ed25519(signed: bytes, signature: bytes, key: dict) -> None:
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        raise ReceiptInvalid(
            "unsupported_algorithm",
            f"JWKS key must be (kty=OKP, crv=Ed25519); got kty={key.get('kty')!r}, crv={key.get('crv')!r}",
        )
    x = key.get("x")
    if not isinstance(x, str):
        raise ReceiptInvalid("malformed_jwt", "JWKS key missing `x` parameter (public key bytes)")

    public_key_bytes = _b64url_decode_bytes(x)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, signed)
    except InvalidSignature as e:
        raise ReceiptInvalid("signature_failed", "Ed25519 signature verification failed") from e
    except (ValueError, TypeError) as e:
        raise ReceiptInvalid("malformed_jwt", f"Ed25519 key construction failed: {e}") from e


def _validate_issuer_audience(
    payload: dict,
    *,
    expected_issuer: Any,
    audience: Any,
) -> None:
    """G8 — optional issuer + audience claim validation.

    Both args default to None (skip validation). When supplied (str
    or list of str), the corresponding claim MUST be present + match.
    """
    if expected_issuer is not None:
        allowed = [expected_issuer] if isinstance(expected_issuer, str) else list(expected_issuer)
        iss = payload.get("iss")
        if not isinstance(iss, str) or iss not in allowed:
            raise ReceiptInvalid(
                "issuer_not_allowed",
                f"Receipt iss={iss!r} not in allowed set {allowed!r}",
            )

    if audience is not None:
        allowed = [audience] if isinstance(audience, str) else list(audience)
        aud = payload.get("aud")
        if not isinstance(aud, str) or aud not in allowed:
            raise ReceiptInvalid(
                "audience_mismatch",
                f"Receipt aud={aud!r} not in allowed set {allowed!r}",
            )


def _validate_temporal(payload: dict, clock_skew_seconds: int) -> None:
    now = int(time.time())

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + clock_skew_seconds:
        raise ReceiptInvalid("future_issued", f"Receipt iat={iat} is in the future (now={now})")

    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp + clock_skew_seconds < now:
        raise ReceiptInvalid("expired", f"Receipt exp={exp} has elapsed (now={now})")


def _b64url_decode(value: str) -> str:
    return _b64url_decode_bytes(value).decode("utf-8")


def _b64url_decode_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _parse_max_age(header: str | None) -> float | None:
    if not header:
        return None
    match = re.search(r"max-age\s*=\s*(\d+)", header, re.IGNORECASE)
    if not match:
        return None
    seconds = int(match.group(1))
    return float(seconds) if seconds >= 0 else None


# ─── OAP authorize-side offline verify (from overturo-authorize-py) ──
# Below: verify_receipt_offline, raw_ed25519_to_jwk, and OAP-prefixed
# helpers (the unprefixed `_verify_ed25519` / `_fail` above belong to
# oversight's `verify_receipt` path; this OAP variant has different
# signature semantics — JwksKey input vs JWKS-dict, returns bool vs
# raises, so they coexist as distinct module-private helpers).
# JwksKey + OfflineVerifyResult dataclasses moved to overturo.models.

OAP_VERSION = "1.0"


def verify_receipt_offline(
    jwt: str,
    *,
    audience: str,
    accepted_issuers,
    jwks,
    skew_seconds: int = 30,
    at: float | None = None,
) -> OfflineVerifyResult:
    """Run the full OAP receipt-validity check pipeline (offline).

    Mirrors `Oap::ReceiptVerificationService`. Returns an
    OfflineVerifyResult on every path — never raises on receipt-shape
    problems. Callers pre-fetch the JWKS for a fully-sync verify.
    """
    peeked = peek_receipt(jwt)
    if peeked is None:
        return OfflineVerifyResult(valid=False, reason_code="malformed")

    header = peeked.header
    if header.get("alg") != "EdDSA":
        return _fail_oap("invalid_alg", peeked.claims)
    if header.get("typ") != "oap+jwt":
        return _fail_oap("invalid_typ", peeked.claims)
    if not header.get("kid"):
        return _fail_oap("unknown_kid", peeked.claims)

    key = next((k for k in jwks if k.kid == header["kid"]), None)
    if key is None:
        return _fail_oap("unknown_kid", peeked.claims)

    if not _verify_ed25519_oap(peeked.signing_input, peeked.signature, key):
        return _fail_oap("bad_signature", peeked.claims)

    claims = peeked.claims
    now = at if at is not None else time.time()

    if claims.get("oap_ver") != OAP_VERSION:
        return _fail_oap("invalid_version", claims)
    if claims.get("iss") not in set(accepted_issuers):
        return _fail_oap("invalid_iss", claims)
    if claims.get("aud") != audience:
        return _fail_oap("invalid_aud", claims)

    iat = claims.get("iat")
    exp = claims.get("exp")
    if not isinstance(iat, (int, float)) or iat - skew_seconds > now:
        return _fail_oap("not_yet_valid", claims)
    if not isinstance(exp, (int, float)) or exp + skew_seconds < now:
        return _fail_oap("expired", claims)

    return OfflineVerifyResult(valid=True, claims=claims)


def _fail_oap(reason_code: str, claims: dict[str, Any] | None) -> OfflineVerifyResult:
    return OfflineVerifyResult(valid=False, claims=claims, reason_code=reason_code)


def _verify_ed25519_oap(signing_input: bytes, signature: bytes, jwk: JwksKey) -> bool:
    try:
        raw = b64url_decode(jwk.x)
        if len(raw) != 32:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(raw)
        public_key.verify(signature, signing_input)
        return True
    except (InvalidSignature, ValueError):
        return False


def raw_ed25519_to_jwk(kid: str, raw_b64url: str) -> JwksKey:
    """Convenience: wrap a base64url-encoded raw 32-byte Ed25519 public
    key as a JwksKey."""
    if len(b64url_decode(raw_b64url)) != 32:
        raise ValueError("Ed25519 public key must decode to 32 bytes")
    return JwksKey(kid=kid, x=raw_b64url.rstrip("="))
