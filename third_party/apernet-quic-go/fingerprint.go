package quic

// QUICFingerprint selects a pinned QUIC handshake, never a TLS-over-TCP preset.
type QUICFingerprint string

const (
	QUICFirefox116  QUICFingerprint = "firefox-116"
	QUICFirefox116B QUICFingerprint = "firefox-116b"
	QUICFirefox116C QUICFingerprint = "firefox-116c"
	// QUICChrome selects the ChromeParrot implementation pinned by this module.
	// It is not an alias for uquic's Chrome 115 or 146 presets.
	QUICChrome    QUICFingerprint = "chrome"
	QUICChrome115 QUICFingerprint = "chrome-115"
	QUICChrome146 QUICFingerprint = "chrome-146"
)

func (f QUICFingerprint) IsFirefox() bool {
	return f == QUICFirefox116 || f == QUICFirefox116B || f == QUICFirefox116C
}
func (f QUICFingerprint) IsVersionedChrome() bool { return f == QUICChrome115 || f == QUICChrome146 }
func (f QUICFingerprint) Valid() bool {
	return f == "" || f == QUICChrome || f.IsVersionedChrome() || f.IsFirefox()
}
func (f QUICFingerprint) initialDCIDLength() int {
	switch f {
	case QUICFirefox116B:
		return 9
	case QUICFirefox116C:
		return 15
	default:
		return 8
	}
}
