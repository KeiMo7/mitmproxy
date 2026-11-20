import ipaddress
import logging
import ssl
import time
from pathlib import Path

import pytest
from cryptography import x509
from OpenSSL import SSL

from mitmproxy import certs
from mitmproxy import connection
from mitmproxy import options
from mitmproxy import tls
from mitmproxy.addons import tlsconfig
from mitmproxy.net import tls as net_tls
from mitmproxy.proxy import context
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.layers import quic
from mitmproxy.proxy.layers import tls as proxy_tls
from mitmproxy.test import taddons
from test.mitmproxy.proxy.layers import test_tls
from test.mitmproxy.proxy.layers.quic import test__stream_layers as test_quic
from test.mitmproxy.test_flow import tflow


def test_alpn_select_callback():
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(ctx)

    # Test that we respect addons setting `client.alpn`.
    conn.set_app_data(
        tlsconfig.AppData(server_alpn=b"h2", http2=True, client_alpn=b"qux")
    )
    assert tlsconfig.alpn_select_callback(conn, [b"http/1.1", b"qux", b"h2"]) == b"qux"
    conn.set_app_data(tlsconfig.AppData(server_alpn=b"h2", http2=True, client_alpn=b""))
    assert (
        tlsconfig.alpn_select_callback(conn, [b"http/1.1", b"qux", b"h2"])
        == SSL.NO_OVERLAPPING_PROTOCOLS
    )

    # Test that we try to mirror the server connection's ALPN
    conn.set_app_data(
        tlsconfig.AppData(server_alpn=b"h2", http2=True, client_alpn=None)
    )
    assert tlsconfig.alpn_select_callback(conn, [b"http/1.1", b"qux", b"h2"]) == b"h2"

    # Test that we respect the client's preferred HTTP ALPN.
    conn.set_app_data(tlsconfig.AppData(server_alpn=None, http2=True, client_alpn=None))
    assert (
        tlsconfig.alpn_select_callback(conn, [b"qux", b"http/1.1", b"h2"])
        == b"http/1.1"
    )
    assert tlsconfig.alpn_select_callback(conn, [b"qux", b"h2", b"http/1.1"]) == b"h2"

    # Test no overlap
    assert (
        tlsconfig.alpn_select_callback(conn, [b"qux", b"quux"])
        == SSL.NO_OVERLAPPING_PROTOCOLS
    )

    # Test that we don't select an ALPN if the server refused to select one.
    conn.set_app_data(tlsconfig.AppData(server_alpn=b"", http2=True, client_alpn=None))
    assert (
        tlsconfig.alpn_select_callback(conn, [b"http/1.1"])
        == SSL.NO_OVERLAPPING_PROTOCOLS
    )


here = Path(__file__).parent


def _ctx(opts: options.Options) -> context.Context:
    return context.Context(
        connection.Client(
            peername=("client", 1234),
            sockname=("127.0.0.1", 8080),
            timestamp_start=1605699329,
        ),
        opts,
    )


class TestTlsConfig:
    def test_configure(self, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            with pytest.raises(Exception, match="file does not exist"):
                tctx.configure(ta, certs=["*=nonexistent"])

            with pytest.raises(Exception, match="Invalid ECDH curve"):
                tctx.configure(ta, tls_ecdh_curve_client="invalid")

            with pytest.raises(Exception, match="Invalid certificate format"):
                tctx.configure(
                    ta,
                    certs=[
                        tdata.path(
                            "mitmproxy/net/data/verificationcerts/trusted-leaf.key"
                        )
                    ],
                )

            assert not ta.certstore.certs
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
            )
            assert ta.certstore.certs

    def test_configure_tls_version(self, caplog):
        caplog.set_level(logging.INFO)
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            for attr in [
                "tls_version_client_min",
                "tls_version_client_max",
                "tls_version_server_min",
                "tls_version_server_max",
            ]:
                caplog.clear()
                tctx.configure(ta, **{attr: "SSL3"})
                assert (
                    f"{attr} has been set to SSL3, "
                    "which is not supported by the current OpenSSL build."
                ) in caplog.text
            caplog.clear()
            tctx.configure(ta, tls_version_client_min="UNBOUNDED")
            assert (
                "tls_version_client_min has been set to UNBOUNDED. "
                "Note that your OpenSSL build only supports the following TLS versions"
            ) in caplog.text

    def test_configure_ciphers(self, caplog):
        caplog.set_level(logging.INFO)
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                tls_version_client_min="TLS1",
                ciphers_client="ALL",
            )
            assert (
                "With tls_version_client_min set to TLS1, "
                'ciphers_client must include "@SECLEVEL=0" for insecure TLS versions to work.'
            ) in caplog.text
            caplog.clear()

            tctx.configure(
                ta,
                ciphers_server="ALL",
            )
            assert not caplog.text
            tctx.configure(
                ta,
                tls_version_server_min="SSL3",
            )
            assert (
                "With tls_version_server_min set to SSL3, "
                'ciphers_server must include "@SECLEVEL=0" for insecure TLS versions to work.'
            ) in caplog.text

    def test_get_cert(self, tdata):
        """Test that we generate a certificate matching the connection's context."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])

            ctx = _ctx(tctx.options)

            # Edge case first: We don't have _any_ idea about the server nor is there a SNI,
            # so we just return our local IP as subject.
            entry = ta.get_cert(ctx)
            assert entry.cert.cn == "127.0.0.1"

            # Here we have an existing server connection...
            ctx.server.address = ("server-address.example", 443)
            with open(
                tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.crt"),
                "rb",
            ) as f:
                ctx.server.certificate_list = [certs.Cert.from_pem(f.read())]
            entry = ta.get_cert(ctx)
            assert entry.cert.cn == "example.mitmproxy.org"
            assert entry.cert.altnames == x509.GeneralNames(
                [
                    x509.DNSName("example.mitmproxy.org"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("server-address.example"),
                ]
            )

            # And now we also incorporate SNI.
            ctx.client.sni = "🌈.sni.example"
            entry = ta.get_cert(ctx)
            assert entry.cert.altnames == x509.GeneralNames(
                [
                    x509.DNSName("example.mitmproxy.org"),
                    x509.DNSName("xn--og8h.sni.example"),
                    x509.DNSName("server-address.example"),
                ]
            )

            with open(tdata.path("mitmproxy/data/invalid-subject.pem"), "rb") as f:
                ctx.server.certificate_list = [certs.Cert.from_pem(f.read())]
            with pytest.warns(UserWarning):
                assert ta.get_cert(ctx)  # does not raise

    def test_tls_clienthello(self):
        # only really testing for coverage here, there's no point in mirroring the individual conditions
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ch = tls.ClientHelloData(ctx, None)  # type: ignore
            ta.tls_clienthello(ch)
            assert not ch.establish_server_tls_first

    def do_handshake(
        self,
        tssl_client: test_tls.SSLTest | SSL.Connection,
        tssl_server: test_tls.SSLTest | SSL.Connection,
    ) -> bool:
        # ClientHello
        with pytest.raises((ssl.SSLWantReadError, SSL.WantReadError)):
            tssl_client.do_handshake()
        tssl_server.bio_write(tssl_client.bio_read(65536))

        # ServerHello
        with pytest.raises((ssl.SSLWantReadError, SSL.WantReadError)):
            tssl_server.do_handshake()
        tssl_client.bio_write(tssl_server.bio_read(65536))

        # done
        tssl_client.do_handshake()
        tssl_server.bio_write(tssl_client.bio_read(65536))
        tssl_server.do_handshake()

        return True

    def quic_do_handshake(
        self,
        tssl_client: test_quic.SSLTest,
        tssl_server: test_quic.SSLTest,
    ) -> bool:
        tssl_server.write(tssl_client.read())
        tssl_client.write(tssl_server.read())
        tssl_server.write(tssl_client.read())
        return tssl_client.handshake_completed() and tssl_server.handshake_completed()

    def test_tls_start_client(self, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
                ciphers_client="ECDHE-ECDSA-AES128-GCM-SHA256",
            )
            ctx = _ctx(tctx.options)

            tls_start = tls.TlsData(ctx.client, context=ctx)
            ta.tls_start_client(tls_start)
            tssl_server = tls_start.ssl_conn

            # assert that a preexisting ssl_conn is not overwritten
            ta.tls_start_client(tls_start)
            assert tssl_server is tls_start.ssl_conn

            tssl_client = test_tls.SSLTest()
            assert self.do_handshake(tssl_client, tssl_server)
            assert tssl_client.obj.getpeercert()["subjectAltName"] == (
                ("DNS", "example.mitmproxy.org"),
            )

    def test_quic_start_client(self, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
                ciphers_client="CHACHA20_POLY1305_SHA256",
            )
            ctx = _ctx(tctx.options)

            tls_start = quic.QuicTlsData(ctx.client, context=ctx)
            ta.quic_start_client(tls_start)
            settings_server = tls_start.settings
            settings_server.alpn_protocols = ["h3"]
            tssl_server = test_quic.SSLTest(server_side=True, settings=settings_server)

            # assert that a preexisting settings is not overwritten
            ta.quic_start_client(tls_start)
            assert settings_server is tls_start.settings

            tssl_client = test_quic.SSLTest(alpn=["h3"])
            assert self.quic_do_handshake(tssl_client, tssl_server)
            san = tssl_client.quic.tls._peer_certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            assert san.value.get_values_for_type(x509.DNSName) == [
                "example.mitmproxy.org"
            ]

    @pytest.mark.parametrize(
        ["opts", "trusted_root"],
        [
            (
                {"emudhra": True},
                # emSign ECC Root CA - G3
                "-----BEGIN CERTIFICATE-----\n"
                "MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG\n"
                "EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo\n"
                "bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g\n"
                "RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ\n"
                "TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s\n"
                "b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw\n"
                "djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0\n"
                "WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS\n"
                "fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB\n"
                "zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq\n"
                "hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB\n"
                "CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD\n"
                "+JbNR6iC8hZVdyR+EhCVBCyj\n"
                "-----END CERTIFICATE-----\n",
            ),
            (
                {"emudhra_old": True},
                # AAA Certificate Services
                "-----BEGIN CERTIFICATE-----\n"
                "MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb\n"
                "MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow\n"
                "GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj\n"
                "YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL\n"
                "MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\n"
                "BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM\n"
                "GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
                "ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua\n"
                "BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe\n"
                "3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4\n"
                "YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR\n"
                "rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm\n"
                "ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU\n"
                "oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF\n"
                "MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v\n"
                "QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t\n"
                "b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF\n"
                "AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q\n"
                "GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz\n"
                "Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2\n"
                "G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi\n"
                "l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3\n"
                "smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==\n"
                "-----END CERTIFICATE-----\n",
            ),
        ],
    )
    def test_emudhra(self, opts, trusted_root, tmp_path):
        ca_file = tmp_path / "root.pem"
        ca_file.write_text(trusted_root)

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=str(ca_file),
                **opts,
            )
            ctx = _ctx(tctx.options)
            ctx.client.sni = "example.mitmproxy.org"

            tls_start = tls.TlsData(ctx.client, context=ctx)
            ta.tls_start_client(tls_start)
            tssl_server = tls_start.ssl_conn

            ctx.server.address = ("example.mitmproxy.org", 443)
            tls_start_server = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start_server)
            tssl_client = tls_start_server.ssl_conn

            assert self.do_handshake(tssl_client, tssl_server)
            san = (
                tssl_client.get_peer_certificate()
                .to_cryptography()
                .extensions.get_extension_for_class(x509.SubjectAlternativeName)
            )
            assert san.value.get_values_for_type(x509.DNSName) == [
                "example.mitmproxy.org"
            ]

            quic_tls_start = quic.QuicTlsData(ctx.client, context=ctx)
            ta.quic_start_client(quic_tls_start)
            assert len(quic_tls_start.settings.certificate_chain) == 3

    def test_tls_start_server_cannot_verify(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            ctx.server.sni = ""  # explicitly opt out of using the address.

            tls_start = tls.TlsData(ctx.server, context=ctx)
            with pytest.raises(
                ValueError, match="Cannot validate certificate hostname without SNI"
            ):
                ta.tls_start_server(tls_start)

    def test_tls_start_server_verify_failed(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.client.alpn_offers = [b"h2"]
            ctx.client.cipher_list = ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-SHA"]
            ctx.server.address = ("example.mitmproxy.org", 443)

            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn
            tssl_server = test_tls.SSLTest(server_side=True)
            with pytest.raises(SSL.Error, match="certificate verify failed"):
                assert self.do_handshake(tssl_client, tssl_server)

    @pytest.mark.parametrize("hostname", ["example.mitmproxy.org", "192.0.2.42"])
    def test_tls_start_server_verify_ok(self, hostname, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = (hostname, 443)
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=tdata.path(
                    "mitmproxy/net/data/verificationcerts/trusted-root.crt"
                ),
            )

            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn

            # assert that a preexisting ssl_conn is not overwritten
            ta.tls_start_server(tls_start)
            assert tssl_client is tls_start.ssl_conn

            tssl_server = test_tls.SSLTest(server_side=True, sni=hostname.encode())
            assert self.do_handshake(tssl_client, tssl_server)

    @pytest.mark.parametrize("hostname", ["example.mitmproxy.org", "192.0.2.42"])
    def test_quic_start_server_verify_ok(self, hostname, tdata):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = (hostname, 443)
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=tdata.path(
                    "mitmproxy/net/data/verificationcerts/trusted-root.crt"
                ),
            )

            tls_start = quic.QuicTlsData(ctx.server, context=ctx)
            ta.quic_start_server(tls_start)
            settings_client = tls_start.settings
            settings_client.alpn_protocols = ["h3"]
            tssl_client = test_quic.SSLTest(settings=settings_client)

            # assert that a preexisting ssl_conn is not overwritten
            ta.quic_start_server(tls_start)
            assert settings_client is tls_start.settings

            tssl_server = test_quic.SSLTest(
                server_side=True, sni=hostname.encode(), alpn=["h3"]
            )
            assert self.quic_do_handshake(tssl_client, tssl_server)

    def test_tls_start_server_insecure(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)

            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_insecure=True,
                http2=False,
                ciphers_server="ALL",
            )
            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn
            tssl_server = test_tls.SSLTest(server_side=True)
            assert self.do_handshake(tssl_client, tssl_server)

    def test_quic_start_server_insecure(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            ctx.client.alpn_offers = [b"h3"]

            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_insecure=True,
                ciphers_server="CHACHA20_POLY1305_SHA256",
            )
            tls_start = quic.QuicTlsData(ctx.server, context=ctx)
            ta.quic_start_server(tls_start)
            tssl_client = test_quic.SSLTest(settings=tls_start.settings)
            tssl_server = test_quic.SSLTest(server_side=True, alpn=["h3"])
            assert self.quic_do_handshake(tssl_client, tssl_server)

    def test_alpn_selection(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            tls_start = tls.TlsData(ctx.server, context=ctx)

            def assert_alpn(http2, client_offers, expected):
                tctx.configure(ta, http2=http2)
                ctx.client.alpn_offers = client_offers
                ctx.server.alpn_offers = None
                tls_start.ssl_conn = None
                ta.tls_start_server(tls_start)
                assert ctx.server.alpn_offers == expected

            assert_alpn(
                True,
                (proxy_tls.HTTP2_ALPN, *proxy_tls.HTTP1_ALPNS, b"foo"),
                (proxy_tls.HTTP2_ALPN, *proxy_tls.HTTP1_ALPNS, b"foo"),
            )
            assert_alpn(
                False,
                (proxy_tls.HTTP2_ALPN, *proxy_tls.HTTP1_ALPNS, b"foo"),
                (*proxy_tls.HTTP1_ALPNS, b"foo"),
            )
            assert_alpn(True, [], [])
            assert_alpn(False, [], [])
            ctx.client.timestamp_tls_setup = time.time()
            # make sure that we don't upgrade h1 to h2,
            # see comment in tlsconfig.py
            assert_alpn(True, [], [])

    def test_no_h2_proxy(self, tdata):
        """Do not negotiate h2 on the client<->proxy connection in secure web proxy mode,
        https://github.com/mitmproxy/mitmproxy/issues/4689"""

        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                certs=[
                    tdata.path("mitmproxy/net/data/verificationcerts/trusted-leaf.pem")
                ],
            )

            ctx = _ctx(tctx.options)
            # mock up something that looks like a secure web proxy.
            ctx.layers = [modes.HttpProxy(ctx), 123]
            tls_start = tls.TlsData(ctx.client, context=ctx)
            ta.tls_start_client(tls_start)
            assert tls_start.ssl_conn.get_app_data()["client_alpn"] == b"http/1.1"

    @pytest.mark.parametrize(
        "client_certs",
        [
            "mitmproxy/net/data/verificationcerts/trusted-leaf.pem",
            "mitmproxy/net/data/verificationcerts/",
        ],
    )
    def test_client_cert_file(self, tdata, client_certs):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            tctx.configure(
                ta,
                client_certs=tdata.path(client_certs),
                ssl_verify_upstream_trusted_ca=tdata.path(
                    "mitmproxy/net/data/verificationcerts/trusted-root.crt"
                ),
            )

            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            tssl_client = tls_start.ssl_conn
            tssl_server = test_tls.SSLTest(server_side=True)

            assert self.do_handshake(tssl_client, tssl_server)
            assert tssl_server.obj.getpeercert()

    async def test_ca_expired(self, monkeypatch, caplog):
        monkeypatch.setattr(certs.Cert, "has_expired", lambda self: True)
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta):
            ta.configure(["confdir"])
            assert "The mitmproxy certificate authority has expired" in caplog.text

    @pytest.mark.parametrize(
        "cert,expect_crl",
        [
            pytest.param(
                "mitmproxy/net/data/verificationcerts/trusted-leaf.crt",
                True,
                id="with-crl",
            ),
            pytest.param(
                "mitmproxy/net/data/verificationcerts/trusted-root.crt",
                False,
                id="without-crl",
            ),
            pytest.param(
                "mitmproxy/net/data/verificationcerts/invalid-crl.crt",
                False,
                id="invalid-crl",
            ),
        ],
    )
    def test_crl_substitution(self, tdata, cert, expect_crl) -> None:
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ta.configure(["confdir"])
            ctx = _ctx(tctx.options)
            with open(tdata.path(cert), "rb") as f:
                ctx.server.certificate_list = [certs.Cert.from_pem(f.read())]

            crt = ta.get_cert(ctx)

            if expect_crl:
                assert crt.cert.crl_distribution_points[0].endswith(ta.crl_path())
            else:
                assert not crt.cert.crl_distribution_points

    def test_crl_request(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta):
            ta.configure(["confdir"])

            f = tflow.tflow(req=tflow.treq(path="/other.crl"))
            ta.request(f)
            assert not f.response

            f = tflow.tflow(req=tflow.treq(path=ta.crl_path()))
            ta.request(f)
            assert f.response

            f = tflow.tflow(req=tflow.treq(path=ta.crl_path()), live=False)
            ta.request(f)
            assert not f.response

    def test_emudhra_revocation_block(self):
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(ta, emudhra=True)
            ta.configure(["confdir"])

            # Revocation lookups for the eMudhra chain are blocked.
            for host in tlsconfig._EMUDHRA_REVOCATION_HOSTS:
                f = tflow.tflow(req=tflow.treq(host=host))
                ta.request(f)
                assert f.error

            # The magic CRL endpoint is still served, not blocked.
            f = tflow.tflow(req=tflow.treq(host="crl.emsign.com", path=ta.crl_path()))
            ta.request(f)
            assert f.response

            # Other hosts are unaffected.
            f = tflow.tflow(req=tflow.treq(host="example.com"))
            ta.request(f)
            assert not f.error
            assert not f.response

        # Without --emudhra, revocation hosts are left alone.
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(ta)
            ta.configure(["confdir"])
            f = tflow.tflow(req=tflow.treq(host="ocsp-a.emsign.com"))
            ta.request(f)
            assert not f.error


def test_default_ciphers():
    assert (
        tlsconfig._default_ciphers(net_tls.Version.TLS1_3) == tlsconfig._DEFAULT_CIPHERS
    )
    assert (
        tlsconfig._default_ciphers(net_tls.Version.SSL3)
        == tlsconfig._DEFAULT_CIPHERS_WITH_SECLEVEL_0
    )
    assert (
        tlsconfig._default_ciphers(net_tls.Version.UNBOUNDED)
        == tlsconfig._DEFAULT_CIPHERS_WITH_SECLEVEL_0
    )


# ---------------------------------------------------------------------------
# Per-target upstream trust policy (scoped trust anchors / scoped bypasses)
# ---------------------------------------------------------------------------

VERIFICATIONCERTS = "mitmproxy/net/data/verificationcerts"


def _mem_server(tdata, cert_name: str) -> SSL.Connection:
    """A pyOpenSSL in-memory TLS server presenting the given test cert."""
    sctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    sctx.use_certificate_file(tdata.path(f"{VERIFICATIONCERTS}/{cert_name}.crt"))
    sctx.use_privatekey_file(tdata.path(f"{VERIFICATIONCERTS}/{cert_name}.key"))
    server = SSL.Connection(sctx)
    server.set_accept_state()
    return server


def _drive_handshake_until_error_or_done(
    client: SSL.Connection, server: SSL.Connection
) -> Exception | None:
    """Pump a memory-BIO handshake, returning the client-side exception."""
    try:
        client.do_handshake()
    except SSL.WantReadError:
        pass
    for _ in range(10):
        try:
            server.bio_write(client.bio_read(65535))
            server.do_handshake()
        except SSL.WantReadError:
            pass
        try:
            client.bio_write(server.bio_read(65535))
        except SSL.Error:
            pass
        try:
            client.do_handshake()
            return None
        except SSL.WantReadError:
            continue
        except SSL.Error as e:
            return e
    return RuntimeError("handshake did not terminate")


class TestPerTargetUpstreamTrust:
    def _start(self, tctx, ta, host: str) -> SSL.Connection:
        ctx = _ctx(tctx.options)
        ctx.server.address = (host, 443)
        tls_start = tls.TlsData(ctx.server, context=ctx)
        ta.tls_start_server(tls_start)
        return tls_start.ssl_conn

    def test_self_signed_rejected_by_default(self, tdata, caplog):
        """Acceptance 1: self-signed upstream rejected, chain-untrusted."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(ta, ssl_verify_upstream_trusted_ca=None)
            client = self._start(tctx, ta, "example.mitmproxy.org")
            server = _mem_server(tdata, "self-signed")
            err = _drive_handshake_until_error_or_done(client, server)
            assert isinstance(err, SSL.Error)
            assert "certificate verify failed" in str(err)
            verify_result = SSL._lib.SSL_get_verify_result(client._ssl)
            from mitmproxy.net.upstream_trust import classify_verify_result
            from mitmproxy.net.upstream_trust import TlsFailure

            assert classify_verify_result(verify_result) is TlsFailure.UNTRUSTED_CHAIN

    def test_trust_anchor_scoped_to_one_target(self, tdata):
        """Acceptance 2: anchor applies only to its target; other self-signed fails."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_verify_upstream_trusted_ca_by_host=[
                    f"example.mitmproxy.org={root}"
                ],
            )

            # The declared target trusts the anchor and handshakes successfully.
            ok_client = self._start(tctx, ta, "example.mitmproxy.org")
            ok_server = _mem_server(tdata, "trusted-leaf")
            assert _drive_handshake_until_error_or_done(ok_client, ok_server) is None

            # A different self-signed target must still be rejected.
            other_client = self._start(tctx, ta, "other.example")
            other_server = _mem_server(tdata, "self-signed")
            other_err = _drive_handshake_until_error_or_done(other_client, other_server)
            assert isinstance(other_err, SSL.Error)

    def test_bypass_scoped_to_target_and_logged(self, tdata, caplog):
        """A scoped bypass verifies nothing for its target, others stay verified."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_insecure_upstream_hosts=["bad.example="],
            )
            import logging

            with caplog.at_level(logging.WARNING):
                bypassed = self._start(tctx, ta, "bad.example")
            assert bypassed.get_verify_mode() == SSL.VERIFY_NONE
            assert any("DISABLED" in r.message for r in caplog.records)

            verified = self._start(tctx, ta, "good.example")
            assert verified.get_verify_mode() == SSL.VERIFY_PEER

    def test_global_ssl_insecure_semantics_unchanged(self):
        """Hard constraint 4: the global switch keeps its old all-or-nothing."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(ta, ssl_insecure=True)
            conn = self._start(tctx, ta, "anything.example")
            assert conn.get_verify_mode() == SSL.VERIFY_NONE

    def test_ip_address_with_ip_san_passes(self, tdata):
        """Acceptance 3: literal IP + cert with IP SAN verifies via the anchor."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_verify_upstream_trusted_ca_by_host=[f"192.0.2.42={root}"],
            )
            client = self._start(tctx, ta, "192.0.2.42")
            server = _mem_server(tdata, "trusted-leaf-ip")
            assert _drive_handshake_until_error_or_done(client, server) is None

    def test_ip_address_with_dns_only_cert_fails_name_mismatch(self, tdata):
        """Acceptance 3: IP target but cert only has DNS entries -> name mismatch."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_verify_upstream_trusted_ca_by_host=[f"192.0.2.42={root}"],
            )
            client = self._start(tctx, ta, "192.0.2.42")
            # trusted-leaf only carries a DNS SAN, no IP entry
            server = _mem_server(tdata, "trusted-leaf")
            err = _drive_handshake_until_error_or_done(client, server)
            assert isinstance(err, SSL.Error)
            verify_result = SSL._lib.SSL_get_verify_result(client._ssl)
            from mitmproxy.net.upstream_trust import classify_verify_result
            from mitmproxy.net.upstream_trust import TlsFailure

            assert classify_verify_result(verify_result) is TlsFailure.NAME_MISMATCH

    def test_no_verifiable_name_without_sni(self):
        """Acceptance 4: no SNI/name gives a categorized error, not a network error."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            ctx.server.sni = ""  # explicitly opt out of a verification name
            tls_start = tls.TlsData(ctx.server, context=ctx)
            with pytest.raises(ValueError) as exc_info:
                ta.tls_start_server(tls_start)
            from mitmproxy.net.upstream_trust import parse_failure_category
            from mitmproxy.net.upstream_trust import TlsFailure

            assert (
                parse_failure_category(str(exc_info.value))
                == TlsFailure.NO_VERIFIABLE_NAME.value
            )

    def test_bad_anchor_path_fails_at_configure(self, tmp_path):
        """Hard constraint / failure 1: unreadable anchor errors at startup."""
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            with pytest.raises(Exception):
                tctx.configure(
                    ta,
                    ssl_verify_upstream_trusted_ca_by_host=[
                        f"host.example={tmp_path / 'missing.pem'}"
                    ],
                )

    def test_malformed_anchor_fails_at_configure(self, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            with pytest.raises(Exception):
                tctx.configure(
                    ta,
                    ssl_verify_upstream_trusted_ca_by_host=[f"host.example={bad}"],
                )

    def test_sni_takes_precedence_for_verification_name(self, tdata):
        """Acceptance 5: verification uses the tunnel SNI, visible via set host."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                # anchor keyed to the SNI name, not the literal loopback address
                ssl_verify_upstream_trusted_ca_by_host=[
                    f"example.mitmproxy.org={root}"
                ],
            )
            ctx = _ctx(tctx.options)
            # address is loopback, but the client tunnel carries a distinct name
            ctx.server.address = ("127.0.0.1", 443)
            ctx.client.sni = "example.mitmproxy.org"
            tls_start = tls.TlsData(ctx.server, context=ctx)
            ta.tls_start_server(tls_start)
            # policy matched on the SNI name even though address differs
            policy = ta.upstream_trust.policy_for(ctx.server.sni, ctx.server.address[0])
            assert policy.extra_ca_file == root

    def test_same_target_reuses_ssl_context_within_session(self, tdata):
        """Acceptance 7: identical targets reuse the cached verification context."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_verify_upstream_trusted_ca_by_host=[
                    f"example.mitmproxy.org={root}"
                ],
            )
            first = self._start(tctx, ta, "example.mitmproxy.org")
            second = self._start(tctx, ta, "example.mitmproxy.org")
            # same underlying OpenSSL context object -> verification decision reused
            assert first.get_context() is second.get_context()

    def test_trust_change_invalidates_cached_context(self, tdata):
        """Acceptance 7: a trust-config change yields a different context.

        The OpenSSL context cache is keyed on all trust inputs, so changing
        the per-target anchor changes the key and produces a fresh context
        rather than silently reusing the pre-change verification decision.
        """
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(ta, ssl_verify_upstream_trusted_ca=None)
            before = self._start(tctx, ta, "example.mitmproxy.org")
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca_by_host=[
                    f"example.mitmproxy.org={root}"
                ],
            )
            after = self._start(tctx, ta, "example.mitmproxy.org")
            assert before.get_context() is not after.get_context()

    def test_quic_scoped_anchor_uses_combined_bundle(self, tdata):
        """QUIC path applies the same per-target anchor (via a combined bundle)."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_verify_upstream_trusted_ca_by_host=[
                    f"example.mitmproxy.org={root}"
                ],
            )
            ctx = _ctx(tctx.options)
            ctx.server.address = ("example.mitmproxy.org", 443)
            quic_start = quic.QuicTlsData(ctx.server, context=ctx)
            ta.quic_start_server(quic_start)
            assert quic_start.settings.verify_mode == ssl.CERT_REQUIRED
            assert quic_start.settings.ca_file == (
                ta.upstream_trust.combined_ca_bundle(root)
            )

    def test_quic_unmatched_target_keeps_system_store(self, tdata):
        """QUIC path does not leak the anchor to other targets."""
        root = tdata.path(f"{VERIFICATIONCERTS}/trusted-root.crt")
        ta = tlsconfig.TlsConfig()
        with taddons.context(ta) as tctx:
            tctx.configure(
                ta,
                ssl_verify_upstream_trusted_ca=None,
                ssl_verify_upstream_trusted_ca_by_host=[
                    f"example.mitmproxy.org={root}"
                ],
            )
            ctx = _ctx(tctx.options)
            ctx.server.address = ("other.example", 443)
            quic_start = quic.QuicTlsData(ctx.server, context=ctx)
            ta.quic_start_server(quic_start)
            assert quic_start.settings.ca_file is None
            assert quic_start.settings.verify_mode == ssl.CERT_REQUIRED
