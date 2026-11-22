package conf

// CertConfig is how a node gets its TLS certificate.
type CertConfig struct {
	// CertMode is none, file, self, http or dns.
	CertMode   string `json:"CertMode"`
	CertDomain string `json:"CertDomain"`
	CertFile   string `json:"CertFile"`
	KeyFile    string `json:"KeyFile"`
	// Provider is the lego DNS provider in dns mode; DNSEnv its environment.
	Provider string            `json:"Provider"`
	Email    string            `json:"Email"`
	DNSEnv   map[string]string `json:"DNSEnv"`
}

// NewCertConfig returns a config without certificate.
func NewCertConfig() *CertConfig {
	return &CertConfig{CertMode: "none"}
}
