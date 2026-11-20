import logging
from pathlib import Path

import pytest
from OpenSSL import SSL

from mitmproxy.net.upstream_trust import classify_verify_result
from mitmproxy.net.upstream_trust import format_failure
from mitmproxy.net.upstream_trust import parse_failure_category
from mitmproxy.net.upstream_trust import strip_failure_prefix
from mitmproxy.net.upstream_trust import TlsFailure
from mitmproxy.net.upstream_trust import UpstreamTrustConfig

VFY = SSL._lib

TRUSTED_ROOT = "mitmproxy/net/data/verificationcerts/trusted-root.crt"
SELF_SIGNED = "mitmproxy/net/data/verificationcerts/self-signed.crt"


class TestClassification:
    def test_verify_result_mapping(self):
        assert (
            classify_verify_result(VFY.X509_V_ERR_HOSTNAME_MISMATCH)
            is TlsFailure.NAME_MISMATCH
        )
        assert (
            classify_verify_result(VFY.X509_V_ERR_IP_ADDRESS_MISMATCH)
            is TlsFailure.NAME_MISMATCH
        )
        assert (
            classify_verify_result(VFY.X509_V_ERR_CERT_HAS_EXPIRED)
            is TlsFailure.CERTIFICATE_EXPIRED
        )
        assert (
            classify_verify_result(VFY.X509_V_ERR_CERT_NOT_YET_VALID)
            is TlsFailure.CERTIFICATE_EXPIRED
        )
        assert (
            classify_verify_result(VFY.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            is TlsFailure.UNTRUSTED_CHAIN
        )
        assert (
            classify_verify_result(VFY.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
            is TlsFailure.UNTRUSTED_CHAIN
        )

    def test_all_required_categories_present(self):
        required = {
            "untrusted_chain",
            "name_mismatch",
            "certificate_expired",
            "not_tls",
            "no_verifiable_name",
            "transport_interrupted",
        }
        assert required <= {f.value for f in TlsFailure}

    def test_format_and_parse_roundtrip(self):
        msg = format_failure(
            TlsFailure.NOT_TLS, "The remote server does not speak TLS."
        )
        assert parse_failure_category(msg) == "not_tls"
        assert strip_failure_prefix(msg) == "The remote server does not speak TLS."

    @pytest.mark.parametrize(
        "plain",
        ["Certificate verify failed: boom", "[not a tag] x", "plain", ""],
    )
    def test_parse_returns_none_for_plain_messages(self, plain):
        assert parse_failure_category(plain) is None
        assert strip_failure_prefix(plain) == plain


class TestConfigParsing:
    def test_valid_ca_entry(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"internal.example={tdata.path(TRUSTED_ROOT)}"]
        )
        policy = cfg.policy_for("internal.example", None)
        assert policy.verify is True
        assert policy.extra_ca_file == tdata.path(TRUSTED_ROOT)
        assert policy.matched_spec == f"internal.example={tdata.path(TRUSTED_ROOT)}"

    def test_unmatched_target_keeps_system_store(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"internal.example={tdata.path(TRUSTED_ROOT)}"]
        )
        policy = cfg.policy_for("public.example", None)
        assert policy.verify is True
        assert policy.extra_ca_file is None
        assert policy.matched_spec is None

    def test_match_by_address_host(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"192.0.2.42={tdata.path(TRUSTED_ROOT)}"]
        )
        # SNI absent, only the literal connection address is known.
        policy = cfg.policy_for(None, "192.0.2.42")
        assert policy.extra_ca_file == tdata.path(TRUSTED_ROOT)

    def test_case_insensitive_and_idna(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"xn--r8jz45g.com={tdata.path(TRUSTED_ROOT)}"]
        )
        policy = cfg.policy_for("例え.com", None)
        assert policy.extra_ca_file == tdata.path(TRUSTED_ROOT)

    def test_insecure_bypass_entry(self, caplog):
        cfg = UpstreamTrustConfig(insecure_specs=["bad.example="])
        with caplog.at_level(logging.WARNING):
            policy = cfg.policy_for("bad.example", "bad.example")
        assert policy.verify is False
        assert policy.extra_ca_file is None
        # every bypass must leave an audit trail
        assert any("DISABLED" in r.message for r in caplog.records)

    def test_insecure_does_not_affect_other_targets(self):
        cfg = UpstreamTrustConfig(insecure_specs=["bad.example="])
        policy = cfg.policy_for("good.example", None)
        assert policy.verify is True

    def test_insecure_takes_precedence_over_ca(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"host.example={tdata.path(TRUSTED_ROOT)}"],
            insecure_specs=["host.example="],
        )
        assert cfg.policy_for("host.example", None).verify is False

    def test_missing_ca_file_fails_fast(self, tmp_path):
        missing = tmp_path / "nope.pem"
        with pytest.raises(ValueError, match="not a file"):
            UpstreamTrustConfig(extra_ca_specs=[f"host.example={missing}"])

    def test_malformed_ca_fails_fast(self, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text("this is definitely not a certificate")
        with pytest.raises(ValueError, match="Cannot parse upstream trust anchor"):
            UpstreamTrustConfig(extra_ca_specs=[f"host.example={bad}"])

    def test_malformed_host_spec_fails_fast(self, tdata):
        ca = tdata.path(TRUSTED_ROOT)
        with pytest.raises(ValueError, match="expected '<host>=<value>'"):
            UpstreamTrustConfig(extra_ca_specs=[f"host.example {ca}"])

    @pytest.mark.parametrize(
        "illegal", ["bad host.example", "*.example", "-lead.example"]
    )
    def test_illegal_hostname_fails_fast(self, tdata, illegal):
        ca = tdata.path(TRUSTED_ROOT)
        with pytest.raises(ValueError, match="Invalid upstream trust target"):
            UpstreamTrustConfig(extra_ca_specs=[f"{illegal}={ca}"])

    def test_insecure_entry_with_value_rejected(self):
        with pytest.raises(ValueError, match="host bypass entries take no value"):
            UpstreamTrustConfig(insecure_specs=["host.example=something"])

    def test_unencodable_runtime_name_does_not_crash(self, tdata):
        # An illegal name arriving at runtime just never matches; the error is
        # reserved for names that cannot be encoded for verification at all.
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"good.example={tdata.path(TRUSTED_ROOT)}"]
        )
        policy = cfg.policy_for("bad_name.example", None)
        assert policy.extra_ca_file is None

    def test_no_certificate_material_in_failure_strings(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"host.example={tdata.path(SELF_SIGNED)}"]
        )
        policy = cfg.policy_for("host.example", None)
        assert "BEGIN CERTIFICATE" not in policy.matched_spec
        for failure in TlsFailure:
            msg = format_failure(failure, "detail")
            assert "BEGIN" not in msg and "PRIVATE KEY" not in msg

    def test_combined_bundle_contains_both_stores(self, tdata):
        cfg = UpstreamTrustConfig()
        extra = tdata.path(TRUSTED_ROOT)
        bundle = cfg.combined_ca_bundle(extra)
        content = open(bundle, encoding="utf-8").read()
        assert "BEGIN CERTIFICATE" in content
        extra_content = open(extra, encoding="utf-8").read()
        assert extra_content.strip() in content
        # cached on second call
        assert cfg.combined_ca_bundle(extra) == bundle

    def test_combined_bundle_adds_newline_only_when_missing(self, tdata, tmp_path):
        cfg = UpstreamTrustConfig()
        # anchor without trailing newline -> separator newline is written
        no_newline = tmp_path / "no-newline.pem"
        no_newline.write_bytes(
            Path(tdata.path(TRUSTED_ROOT)).read_bytes().rstrip(b"\n")
        )
        bundle = cfg.combined_ca_bundle(str(no_newline))
        assert Path(bundle).read_bytes().count(b"BEGIN CERTIFICATE") >= 2

    def test_cleanup_removes_bundles(self, tdata):
        cfg = UpstreamTrustConfig()
        bundle = cfg.combined_ca_bundle(tdata.path(TRUSTED_ROOT))
        assert Path(bundle).exists()
        cfg._cleanup_combined_bundles()
        assert not Path(bundle).exists()
        # a second cleanup is a no-op
        cfg._cleanup_combined_bundles()

    def test_empty_dns_label_rejected(self, tdata):
        ca = tdata.path(TRUSTED_ROOT)
        with pytest.raises(ValueError, match="empty DNS label"):
            UpstreamTrustConfig(extra_ca_specs=[f"example..com={ca}"])

    def test_overlong_label_raises_encoding_error(self, tdata):
        ca = tdata.path(TRUSTED_ROOT)
        long_label = "a" * 64
        with pytest.raises(ValueError, match="cannot encode hostname"):
            UpstreamTrustConfig(extra_ca_specs=[f"{long_label}.example={ca}"])

    def test_empty_target_host_rejected(self, tdata):
        ca = tdata.path(TRUSTED_ROOT)
        with pytest.raises(ValueError, match="empty target host"):
            UpstreamTrustConfig(extra_ca_specs=[f" ={ca}"])

    def test_blank_runtime_name_is_skipped(self, tdata):
        cfg = UpstreamTrustConfig(
            extra_ca_specs=[f"good.example={tdata.path(TRUSTED_ROOT)}"]
        )
        # whitespace-only runtime name contributes no target
        policy = cfg.policy_for("   ", None)
        assert policy.extra_ca_file is None
        assert cfg.policy_for(None, None).matched_spec is None
