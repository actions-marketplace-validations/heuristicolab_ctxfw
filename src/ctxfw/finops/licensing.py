# manifest_hash: a425559f56edf617a357d8abbfec0ecbb9591379a696ba28a1e9c9cf57fdfcbc
"""
src/ctxfw/finops/licensing.py — Sovereign Asymmetric License Verifier & Issuer (v4.1.0)
=======================================================================================
Enforces asymmetric RSA-2048 SHA-256 (EMSA-PKCS1-v1_5) license verification for
Team Governance ($199 USD/month Flat Squad up to 15 devs & 5 CI/CD repos) and
7-Day Team Trial (`TEAM_TRIAL`) without requiring external C-extension libraries
or leaking source code/telemetry (100% Zero-Egress).
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional, Set
import urllib.request

from pydantic import BaseModel, ConfigDict, Field

PUBLIC_MODULUS_N_HEX = (
    "5ee7cba92ca23c19a01eb21a8307f2e9fcff902970af0c8ee2be3247119ca55b"
    "2fa09df6e9f1b1edb3124590056e46676893d9009c9f3301acc884d6b160a9a4"
    "e954f9f79aa5ea7453c9ed385dd2a8eab4b299590665ab8d08e54af336f60d74"
    "c54968e047a7ed7d0f0d9f4ced728584e1337ba54bd7ab3c79348cdf51b2d39b"
    "d27c83236d2a58ab4e431cbf7f4839b0813ed8aabac5adec84065a40d1906748"
    "b4ff18516f12efb656dbf8bb5cbc33911aa19ba842277f4680a002b0dae4b77a"
    "0adf2d50f8cbbd67fe44b0d2b836028f1967174840ee03803fe43b6c47c47183"
    "d67e2506b6c404a4ae825857c2ca8d624e1909b204242543a91621d9fcf69c39"
)
PUBLIC_MODULUS_N = int(PUBLIC_MODULUS_N_HEX, 16)
PUBLIC_EXPONENT_E = 65537
KEY_BYTE_LENGTH = 256  # 2048 bits

DEFAULT_REVOCATION_URL = "https://ctxfw.heuristicolab.com/v1/revoked.json"
PRICING_URL = "https://ctxfw.heuristicolab.com/pricing/"

# ASN.1 DigestInfo prefix for SHA-256 per RFC 8017 Section 9.2
_SHA256_ASN1_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class LicenseTier(str, Enum):
    TEAM_TRIAL = "TEAM_TRIAL"
    TEAM_PRO = "TEAM_PRO"
    ENTERPRISE = "ENTERPRISE"


class LicenseStatus(str, Enum):
    ACTIVE = "LICENSE_ACTIVE"
    UNLICENSED = "UNLICENSED"
    EXPIRED = "LICENSE_EXPIRED"
    REVOKED = "LICENSE_REVOKED"
    QUARANTINED = "QUARANTINED"


class LicensePayloadDTO(BaseModel):
    """Signed payload embedded inside a CTXFW Team/Enterprise license key."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=4, max_length=64, description="Unique license identifier (e.g. LIC-2026-0001)")
    org: str = Field(..., min_length=1, max_length=128, description="Organization or squad slug")
    tier: LicenseTier = Field(..., description="Subscription tier: TEAM_TRIAL, TEAM_PRO, or ENTERPRISE")
    iat: str = Field(..., min_length=10, max_length=40, description="Issued-at ISO-8601 UTC timestamp")
    exp: str = Field(..., min_length=10, max_length=40, description="Expiration ISO-8601 UTC timestamp")
    max_devs: int = Field(default=15, ge=1, le=5000, description="Maximum developers covered by squad license")
    max_repos: int = Field(default=5, ge=1, le=1000, description="Maximum CI/CD repositories covered")


class LicenseVerificationResult(BaseModel):
    """Immutable result of verifying a CTXFW license key."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: LicenseStatus
    is_valid: bool
    license_id: Optional[str] = None
    org: Optional[str] = None
    tier: Optional[LicenseTier] = None
    expires_at: Optional[str] = None
    days_remaining: Optional[int] = None
    max_devs: int = 0
    max_repos: int = 0
    message: str


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _emsa_pkcs1_v15_encode(payload_bytes: bytes) -> int:
    """Deterministic EMSA-PKCS1-v1_5 encoding over SHA-256(CTXFW-LIC-V1: || payload_bytes)."""
    digest = hashlib.sha256(b"CTXFW-LIC-V1:" + payload_bytes).digest()
    t = _SHA256_ASN1_PREFIX + digest
    ps_len = KEY_BYTE_LENGTH - len(t) - 3
    em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    return int.from_bytes(em, "big")


def _resolve_raw_license_key(explicit_key: Optional[str] = None) -> str:
    """Resolves license key from explicit argument, CTXFW_LICENSE_KEY env var, or .ctxfwrc / ~/.ctxfw/config.json."""
    if explicit_key and isinstance(explicit_key, str) and explicit_key.strip():
        return explicit_key.strip()

    env_key = os.environ.get("CTXFW_LICENSE_KEY", "").strip()
    if env_key:
        return env_key

    candidates = [
        Path.cwd() / ".ctxfwrc",
        Path.cwd() / ".ctxfw.json",
        Path.home() / ".ctxfw" / "config.json",
        Path.home() / ".ctxfw" / "license.key",
    ]
    for p in candidates:
        if p.is_file():
            try:
                raw_text = p.read_text(encoding="utf-8").strip()
                if p.name == "license.key" and raw_text.startswith("CTXFW-"):
                    return raw_text
                data = json.loads(raw_text)
                if isinstance(data, dict):
                    k = data.get("license_key") or data.get("finops", {}).get("license_key")
                    if isinstance(k, str) and k.strip():
                        return k.strip()
            except Exception:
                continue
    return ""


def fetch_revoked_license_ids(
    url: str = DEFAULT_REVOCATION_URL,
    timeout_sec: float = 1.5,
) -> Set[str]:
    """
    Fetches the static revocation list (`revoked.json`) with zero telemetry egress.
    Fails open on transient offline/air-gapped network errors so air-gapped VPCs
    continue operating on valid signed keys until `exp`.
    """
    if os.environ.get("CTXFW_OFFLINE_LICENSE_CHECK") == "1":
        return set()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ctxfw-license-verifier/4.1.0", "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return set()
            data = json.loads(resp.read(65536).decode("utf-8"))
            if isinstance(data, dict):
                rev = data.get("revoked", [])
                if isinstance(rev, list):
                    return {str(item).strip() for item in rev if item}
    except Exception:
        return set()
    return set()


def verify_license_key(
    raw_key: Optional[str] = None,
    *,
    check_revocation: bool = True,
    revocation_url: str = DEFAULT_REVOCATION_URL,
    revoked_ids_override: Optional[Set[str]] = None,
    now_utc: Optional[datetime] = None,
) -> LicenseVerificationResult:
    """
    Verifies a CTXFW Team/Enterprise license key using RSA-2048 public key verification,
    UTC expiration check, and static revocation ledger lookup.
    """
    resolved = _resolve_raw_license_key(raw_key)
    if not resolved:
        return LicenseVerificationResult(
            status=LicenseStatus.UNLICENSED,
            is_valid=False,
            message=(
                "[CTXFW LICENSE REQUIRED] Team Governance & CI Gate (`ctxfw gate` / `ctxfw report --team-merge`) "
                "requires an active Team Squad ($199 USD/mo flat up to 15 devs) or 7-Day Trial license key.\n"
                f"  -> Set `export CTXFW_LICENSE_KEY=<your-key>` or activate a 7-day trial at: {PRICING_URL}"
            ),
        )

    # Strip known prefix (`CTXFW-LIC-`, `CTXFW-TEAM-TRIAL-`, `CTXFW-TEAM-PRO-`, `CTXFW-ENTERPRISE-`)
    token_body = resolved
    for prefix in ("CTXFW-LIC-", "CTXFW-TEAM-TRIAL-", "CTXFW-TEAM-PRO-", "CTXFW-ENTERPRISE-"):
        if token_body.startswith(prefix):
            token_body = token_body[len(prefix):]
            break
    else:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message=f"[CTXFW LICENSE INVALID] Unrecognized license key prefix. Request a valid key at {PRICING_URL}",
        )

    parts = token_body.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message=f"[CTXFW LICENSE INVALID] Malformed license token structure. Request a valid key at {PRICING_URL}",
        )

    try:
        payload_bytes = _b64url_decode(parts[0])
        sig_bytes = _b64url_decode(parts[1])
    except Exception:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message="[CTXFW LICENSE INVALID] Base64url decoding failed on license key.",
        )

    if len(sig_bytes) != KEY_BYTE_LENGTH:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message="[CTXFW LICENSE INVALID] Invalid RSA-2048 signature block length.",
        )

    # 1. Verify RSA-2048 SHA-256 signature against PUBLIC_MODULUS_N
    sig_int = int.from_bytes(sig_bytes, "big")
    recovered_int = pow(sig_int, PUBLIC_EXPONENT_E, PUBLIC_MODULUS_N)
    expected_int = _emsa_pkcs1_v15_encode(payload_bytes)
    if recovered_int != expected_int:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message="[CTXFW LICENSE QUARANTINED] Cryptographic signature verification failed (tampered or forged key).",
        )

    # 2. Parse and validate payload schema
    try:
        payload_dict = json.loads(payload_bytes.decode("utf-8"))
        dto = LicensePayloadDTO(**payload_dict)
    except Exception as exc:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message=f"[CTXFW LICENSE INVALID] Malformed license payload schema: {exc}",
        )

    # 3. Check expiration timestamp
    now = now_utc or datetime.now(timezone.utc)
    try:
        exp_str = dto.exp.replace("Z", "+00:00")
        exp_dt = datetime.fromisoformat(exp_str)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return LicenseVerificationResult(
            status=LicenseStatus.QUARANTINED,
            is_valid=False,
            message="[CTXFW LICENSE INVALID] Invalid expiration timestamp in license payload.",
        )

    if now > exp_dt:
        tier_label = "7-Day Trial" if dto.tier is LicenseTier.TEAM_TRIAL else dto.tier.value
        return LicenseVerificationResult(
            status=LicenseStatus.EXPIRED,
            is_valid=False,
            license_id=dto.id,
            org=dto.org,
            tier=dto.tier,
            expires_at=dto.exp,
            days_remaining=0,
            max_devs=dto.max_devs,
            max_repos=dto.max_repos,
            message=(
                f"[CTXFW LICENSE EXPIRED] Your {tier_label} license ({dto.id} for '{dto.org}') expired on {dto.exp[:10]}.\n"
                f"  -> Activate your Team Squad subscription ($199 USD/mo flat for up to 15 devs) at: {PRICING_URL}"
            ),
        )

    # 4. Check static revocation list
    revoked_set: Set[str] = set()
    if revoked_ids_override is not None:
        revoked_set = revoked_ids_override
    elif check_revocation:
        revoked_set = fetch_revoked_license_ids(url=revocation_url)

    if dto.id in revoked_set:
        return LicenseVerificationResult(
            status=LicenseStatus.REVOKED,
            is_valid=False,
            license_id=dto.id,
            org=dto.org,
            tier=dto.tier,
            expires_at=dto.exp,
            days_remaining=0,
            max_devs=dto.max_devs,
            max_repos=dto.max_repos,
            message=(
                f"[CTXFW LICENSE REVOKED] License {dto.id} ('{dto.org}') has been suspended due to billing cancellation or revocation.\n"
                f"  -> Restore your subscription at: {PRICING_URL} or contact mo@heuristicolab.com"
            ),
        )

    delta_sec = max(0.0, (exp_dt - now).total_seconds())
    days_left = int((delta_sec + 86399) // 86400)

    return LicenseVerificationResult(
        status=LicenseStatus.ACTIVE,
        is_valid=True,
        license_id=dto.id,
        org=dto.org,
        tier=dto.tier,
        expires_at=dto.exp,
        days_remaining=days_left,
        max_devs=dto.max_devs,
        max_repos=dto.max_repos,
        message=(
            f"[LICENSE: {dto.tier.value} // Org: {dto.org} // ID: {dto.id} // "
            f"{days_left} day(s) remaining (up to {dto.max_devs} devs / {dto.max_repos} repos)]"
        ),
    )


def issue_license_key(
    *,
    org: str,
    tier: str | LicenseTier = LicenseTier.TEAM_TRIAL,
    days: int = 7,
    license_id: Optional[str] = None,
    max_devs: int = 15,
    max_repos: int = 5,
    private_key_hex: Optional[str] = None,
    now_utc: Optional[datetime] = None,
) -> str:
    """
    Signs and emits a new CTXFW license key using `CTXFW_MASTER_PRIVATE_KEY`.
    This function only operates on the sovereign issuer host (VPS or founder machine)
    where `CTXFW_MASTER_PRIVATE_KEY` is present in the environment or `.env`.
    """
    priv_hex = (private_key_hex or os.environ.get("CTXFW_MASTER_PRIVATE_KEY") or "").strip()
    if not priv_hex:
        env_file = Path.cwd() / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("CTXFW_MASTER_PRIVATE_KEY="):
                    priv_hex = line.split("=", 1)[1].strip()
                    break
    if not priv_hex:
        raise ValueError(
            "SECURITY_ERROR: CTXFW_MASTER_PRIVATE_KEY is required to issue signed license keys."
        )

    d_int = int(priv_hex, 16)
    tier_enum = LicenseTier(tier) if isinstance(tier, str) else tier
    now = now_utc or datetime.now(timezone.utc)
    exp = now + timedelta(days=max(1, int(days)))

    if not license_id:
        digest_short = hashlib.sha256(f"{org}:{now.isoformat()}".encode("utf-8")).hexdigest()[:8].upper()
        license_id = f"LIC-{digest_short}"

    dto = LicensePayloadDTO(
        id=license_id,
        org=org.strip(),
        tier=tier_enum,
        iat=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        exp=exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        max_devs=max_devs,
        max_repos=max_repos,
    )
    payload_bytes = json.dumps(
        dto.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
    ).encode("utf-8")

    em_int = _emsa_pkcs1_v15_encode(payload_bytes)
    sig_int = pow(em_int, d_int, PUBLIC_MODULUS_N)
    sig_bytes = sig_int.to_bytes(KEY_BYTE_LENGTH, "big")

    prefix_map = {
        LicenseTier.TEAM_TRIAL: "CTXFW-TEAM-TRIAL-",
        LicenseTier.TEAM_PRO: "CTXFW-TEAM-PRO-",
        LicenseTier.ENTERPRISE: "CTXFW-ENTERPRISE-",
    }
    prefix = prefix_map.get(tier_enum, "CTXFW-LIC-")
    return f"{prefix}{_b64url_encode(payload_bytes)}.{_b64url_encode(sig_bytes)}"
