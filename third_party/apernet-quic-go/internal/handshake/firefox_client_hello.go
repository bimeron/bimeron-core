// Adapted from refraction-networking/uquic u_parrot.go (MIT); see LICENSE.uquic.
package handshake

import tls "github.com/refraction-networking/utls"

func firefoxQUICClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS13,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		CompressionMethods: []uint8{
			0x0,
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.CurveX25519,
					tls.CurveSECP256R1,
					tls.CurveSECP384R1,
					tls.CurveSECP521R1,
					tls.FakeCurveFFDHE2048,
					tls.FakeCurveFFDHE3072,
					tls.FakeCurveFFDHE4096,
					tls.FakeCurveFFDHE6144,
					tls.FakeCurveFFDHE8192,
				},
			},
			&tls.ALPNExtension{
				AlpnProtocols: []string{
					"h3",
				},
			},
			&tls.StatusRequestExtension{},
			&tls.FakeDelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.ECDSAWithSHA1,
				},
			},
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{
						Group: tls.X25519,
					},
				},
			},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.VersionTLS13,
				},
			},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.ECDSAWithSHA1,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
					tls.PKCS1WithSHA1,
				},
			},
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{
					tls.PskModeDHE,
				},
			},
			&tls.FakeRecordSizeLimitExtension{
				Limit: 0x4001,
			},
			&tls.QUICTransportParametersExtension{},
			&tls.UtlsPaddingExtension{
				GetPaddingLen: tls.BoringPaddingStyle,
			},
		},
	}
}
