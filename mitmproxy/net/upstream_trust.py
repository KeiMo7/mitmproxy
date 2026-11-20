"""
Per-target upstream TLS trust policy and handshake failure classification.

The global :option:`ssl_insecure` switch disables certificate verification for
*every* upstream connection.  The helpers in this module implement the more
fine-grained alternative: extra trust anchors and verification bypasses can be
declared for individual targets only, while all other targets keep using the
system trust store.

Nothing in this module ever exposes certificate bodies, private keys or full
trust chains -- failure classes only carry stable machine-readable identifiers
and short, human-readable explanations.
"""

from __future__ import annotations

import atexit
import ipaddress
import logging
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import certifi
from OpenSSL import SSL

logger = logging.getLogger(__name__)


class TlsFailure(Enum):
    """Stable, machine-consumable classification of an upstream TLS failure."""

    UNTRUSTED_CHAIN = "untrusted_chain"
    """The certificate chain does not chain to a trusted anchor."""

    NAME_MISMATCH = "name_mismatch"
    """The certificate's identity (DNS name or IP address) does not match."""

    CERTIFICATE_EXPIRED = "certificate_expired"
    """The certificate is not within its validity period."""

    NOT_TLS = "not_tls"
    """The peer responded, but its response is not a valid TLS handshake."""

    NO_VERIFIABLE_NAME = "no_verifiable_name"
    """No name/address is available that the certificate could be checked against."""

    TRANSPORT_INTERRUPTED = "transport_interrupted"
    """The transport connection broke before the handshake completed."""

    HANDSHAKE_FAILURE = "handshake_failure"
    """A TLS handshake failure that does not fall into one of the classes above."""


# OpenSSL X509_STORE_CTX verify result codes (see ``openssl verify -help`` /
# x509_vfy.h).  Only numeric codes are matched so that this keeps working across
# OpenSSL versions and locales.
_VFY = SSL._lib  # type: ignore

_NAME_MISMATCH_CODES = frozenset(
    {
        _VFY.X509_V_ERR_HOSTNAME_MISMATCH,
        _VFY.X509_V_ERR_IP_ADDRESS_MISMATCH,
        _VFY.X509_V_ERR_EMAIL_MISMATCH,
    }
)
_VALIDITY_CODES = frozenset(
    {
        _VFY.X509_V_ERR_CERT_HAS_EXPIRED,
        _VFY.X509_V_ERR_CERT_NOT_YET_VALID,
        _VFY.X509_V_ERR_CRL_HAS_EXPIRED,
        _VFY.X509_V_ERR_CRL_NOT_YET_VALID,
    }
)
# Everything else reported alongside "certificate verify failed" is a chain /
# trust problem (unknown CA, self-signed chain, revoked cert, bad signature, ...).


def classify_verify_result(verify_result: int) -> TlsFailure:
    """Map an OpenSSL ``X509_V_*`` verify result code to a `TlsFailure`."""
    if verify_result in _NAME_MISMATCH_CODES:
        return TlsFailure.NAME_MISMATCH
    if verify_result in _VALIDITY_CODES:
        return TlsFailure.CERTIFICATE_EXPIRED
    return TlsFailure.UNTRUSTED_CHAIN


def format_failure(failure: TlsFailure, detail: str) -> str:
    """Render the client-facing error string.

    The historical wording of ``detail`` is preserved verbatim (so existing
    client-visible semantics do not change), but a stable, machine-parseable
    category tag is prepended.
    """
    return f"[{failure.value}] {detail}"


def parse_failure_category(message: str) -> str | None:
    """Extract a category tag previously produced by `format_failure`."""
    if message.startswith("["):
        closing = message.find("]")
        if 0 < closing <= 40:
            candidate = message[1:closing]
            if candidate and all(
                c.isascii() and (c.isalnum() or c == "_") for c in candidate
            ):
                return candidate
    return None


def strip_failure_prefix(message: str) -> str:
    """Remove a leading ``[category]`` tag, returning the original wording."""
    if parse_failure_category(message) is not None:
        return message[message.index("]") + 2 :]
    return message


@dataclass(frozen=True)
class TargetPolicy:
    """The effective trust policy for a single upstream target."""

    verify: bool
    """Whether the upstream certificate must be verified at all."""

    extra_ca_file: str | None
    """Path to an additional PEM trust anchor that applies to this target only."""

    matched_spec: str | None
    """The configuration entry this policy was derived from, for audit logging."""


@dataclass(frozen=True)
class _Entry:
    raw_spec: str
    target: str
    is_ip: bool
    value: str | None


def _validate_dns_name(target: str, raw_spec: str) -> str:
    """Validate and normalize a DNS target name.

    Python's IDNA 2003 codec is permissive and lets characters such as
    underscores or spaces pass through unchanged.  A name that cannot be
    encoded into a legal verification identity must be rejected at config
    time rather than surfacing as a confusing mismatch later.
    """
    labels = target.split(".")
    if any(not label for label in labels):
        raise ValueError(
            f"Invalid upstream trust target {target!r} in {raw_spec!r}: "
            "empty DNS label."
        )
    for label in labels:
        # After IDNA encoding every label must be LDH (letters, digits,
        # hyphen); a leading wildcard or underscore/space is not a verifiable
        # identity for upstream certificate checks.
        try:
            encoded = label.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise ValueError(
                f"Invalid upstream trust target {target!r} in {raw_spec!r}: "
                f"cannot encode hostname for verification ({e})."
            ) from e
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in encoded):
            raise ValueError(
                f"Invalid upstream trust target {target!r} in {raw_spec!r}: "
                f"illegal character in hostname, cannot verify certificates."
            )
        if encoded.startswith("-") or encoded.endswith("-"):
            raise ValueError(
                f"Invalid upstream trust target {target!r} in {raw_spec!r}: "
                "DNS labels must not start or end with a hyphen."
            )
    return target.encode("idna").decode("ascii").lower()


def _parse_spec(spec: str) -> _Entry:
    if "=" not in spec:
        raise ValueError(
            f"Invalid upstream trust entry {spec!r}: expected '<host>=<value>'."
        )
    target, value = spec.split("=", 1)
    target = target.strip().lower()
    value = value.strip()
    if not target:
        raise ValueError(f"Invalid upstream trust entry {spec!r}: empty target host.")
    try:
        ipaddress.ip_address(target)
    except ValueError:
        target = _validate_dns_name(target, spec)
        return _Entry(raw_spec=spec, target=target, is_ip=False, value=value)
    else:
        return _Entry(raw_spec=spec, target=target, is_ip=True, value=value)


def _targets_for(server_sni: str | None, server_address_host: str | None) -> set[str]:
    """All normalized names/addresses that identify this upstream."""
    targets: set[str] = set()
    for candidate in (server_sni, server_address_host):
        if not candidate:
            continue
        host = candidate.strip().lower()
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # Reuse the same strictness as config parsing, but never raise on
            # runtime input: an un-verifiable name simply cannot match an
            # entry. The TLS layer reports such names as "no verifiable name".
            try:
                host = _validate_dns_name(host, f"<runtime target {host!r}>")
            except ValueError:
                logger.debug(
                    "Upstream target %r cannot be encoded for verification, "
                    "skipping per-target trust match.",
                    candidate,
                )
                continue
        targets.add(host)
    return targets


class UpstreamTrustConfig:
    """Parsed, validated per-target upstream trust configuration.

    Construction validates every entry eagerly: unknown hosts raise immediately
    at startup/configure time rather than failing on the first connection, and
    referenced CA files are opened once so that a missing or malformed trust
    anchor is a configuration error, not a runtime surprise.
    """

    def __init__(
        self,
        extra_ca_specs: list[str] | tuple[str, ...] = (),
        insecure_specs: list[str] | tuple[str, ...] = (),
    ):
        self._extra_ca_entries: list[_Entry] = []
        self._insecure_entries: list[_Entry] = []
        # Keep insertion order for deterministic audit messages.
        self._extra_ca_files: dict[str, str] = {}
        # aioquic takes a single cafile, so QUIC needs a combined bundle on disk.
        self._combined_bundles: dict[str, str] = {}
        atexit.register(self._cleanup_combined_bundles)

        for spec in extra_ca_specs:
            entry = _parse_spec(spec)
            if not entry.value:
                raise ValueError(
                    f"Invalid upstream trust entry {spec!r}: no CA file given."
                )
            ca_path = str(Path(entry.value).expanduser())
            self._validate_ca_file(spec, ca_path)
            self._extra_ca_files[entry.target] = ca_path
            self._extra_ca_entries.append(entry)

        for spec in insecure_specs:
            entry = _parse_spec(spec)
            if entry.value:
                raise ValueError(
                    f"Invalid insecure upstream entry {spec!r}: "
                    "host bypass entries take no value, use '<host>='."
                )
            self._insecure_entries.append(entry)

    @staticmethod
    def _validate_ca_file(spec: str, ca_path: str) -> None:
        path = Path(ca_path)
        if not path.is_file():
            raise ValueError(
                f"Cannot read upstream trust anchor from {spec!r}: "
                f"{ca_path} is not a file."
            )
        # Open the store once at config time so a malformed PEM is a startup
        # error.  We deliberately do not retain the loaded object here, the
        # OpenSSL context cache owns the long-lived context.
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        try:
            ctx.load_verify_locations(ca_path, None)
        except SSL.Error as e:
            raise ValueError(
                f"Cannot parse upstream trust anchor from {spec!r} ({ca_path}): {e}"
            ) from e

    def policy_for(
        self, server_sni: str | None, server_address_host: str | None
    ) -> TargetPolicy:
        """Resolve the effective policy for one upstream target."""
        targets = _targets_for(server_sni, server_address_host)

        for entry in self._insecure_entries:
            if entry.target in targets:
                # Every bypass must leave an audit trail, silent overrides are
                # not acceptable.
                logger.warning(
                    "Upstream TLS certificate verification DISABLED for %s "
                    "due to matching option entry %r",
                    entry.target,
                    entry.raw_spec,
                )
                return TargetPolicy(
                    verify=False, extra_ca_file=None, matched_spec=entry.raw_spec
                )

        for entry in self._extra_ca_entries:
            if entry.target in targets:
                ca_file = self._extra_ca_files[entry.target]
                logger.info(
                    "Upstream TLS trust anchor from option entry %r applied to %s",
                    entry.raw_spec,
                    entry.target,
                )
                return TargetPolicy(
                    verify=True, extra_ca_file=ca_file, matched_spec=entry.raw_spec
                )

        return TargetPolicy(verify=True, extra_ca_file=None, matched_spec=None)

    def combined_ca_bundle(self, extra_ca_file: str) -> str:
        """Return an on-disk PEM bundle with the system store plus one anchor.

        Needed for the QUIC/aioquic path, which accepts a single cafile.  The
        OpenSSL-based TCP path loads both stores directly and does not need
        this. Bundles are cached per anchor and removed on interpreter exit.
        """
        if extra_ca_file in self._combined_bundles:
            return self._combined_bundles[extra_ca_file]
        system_ca = Path(certifi.where()).read_bytes()
        extra = Path(extra_ca_file).read_bytes()
        fd, bundle_path = tempfile.mkstemp(
            prefix="mitmproxy-upstream-ca-", suffix=".pem"
        )
        with open(fd, "wb") as f:
            f.write(system_ca)
            if not extra.endswith(b"\n"):
                f.write(b"\n")
            f.write(extra)
        self._combined_bundles[extra_ca_file] = bundle_path
        return bundle_path

    def _cleanup_combined_bundles(self) -> None:
        for path in self._combined_bundles.values():
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:  # pragma: no cover - best effort cleanup
                pass
