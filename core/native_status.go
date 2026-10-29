package core

// NativeStatus is an authoritative lifecycle snapshot, not a policy inspection
// or a promise against privileged changes to Windows policy.
type NativeStatus struct {
	ProfileReadiness     string `json:"profile_readiness"`
	CredentialReadiness  string `json:"credential_readiness"`
	CertificateReadiness string `json:"certificate_readiness"`
	Requested            bool   `json:"requested"`
	WFP                  string `json:"wfp"`
	DNS                  string `json:"dns"`
	RASCleanup           string `json:"ras_cleanup"`
	DNSCleanup           string `json:"dns_cleanup"`
	WFPCleanup           string `json:"wfp_cleanup"`
	RecoveryRequired     bool   `json:"recovery_required"`
}

func (c SessionConfig) updateNative(update func(*NativeStatus)) {
	if c.nativeUpdate != nil {
		c.nativeUpdate(update)
	}
}
