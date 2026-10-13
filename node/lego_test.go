package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
)

func TestLego_RenewCertMissingFile(t *testing.T) {
	l := &Lego{
		config: &conf.CertConfig{
			CertFile: filepath.Join(t.TempDir(), "missing.pem"),
		},
	}

	err := l.RenewCert()
	if err == nil {
		t.Fatal("RenewCert() missing file error = nil")
	}
	if !strings.Contains(err.Error(), "read cert file error") {
		t.Fatalf("RenewCert() error = %v, want read cert file error", err)
	}
}

func TestLego_CreateCertByDns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ACME DNS integration test in short mode")
	}
	if strings.TrimSpace(getenv("V2BX_ACME_INTEGRATION")) != "1" {
		t.Skip("set V2BX_ACME_INTEGRATION=1 to run ACME DNS integration test")
	}
	if getenv("CF_DNS_API_TOKEN") == "" {
		t.Skip("set CF_DNS_API_TOKEN to run ACME DNS integration test")
	}

	tmpDir := t.TempDir()
	l, err := NewLego(&conf.CertConfig{
		CertMode:   "dns",
		Email:      getenvOrDefault("V2BX_ACME_EMAIL", "test@test.com"),
		CertDomain: getenvOrDefault("V2BX_ACME_DOMAIN", "test.test.com"),
		Provider:   getenvOrDefault("V2BX_ACME_PROVIDER", "cloudflare"),
		DNSEnv: map[string]string{
			"CF_DNS_API_TOKEN": getenv("CF_DNS_API_TOKEN"),
		},
		CertFile: filepath.Join(tmpDir, "cert.pem"),
		KeyFile:  filepath.Join(tmpDir, "cert.key"),
	})
	if err != nil {
		t.Fatalf("NewLego() error = %v", err)
	}
	if err := l.CreateCert(); err != nil {
		t.Fatalf("CreateCert() error = %v", err)
	}
}

func getenv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func getenvOrDefault(name, fallback string) string {
	if value := getenv(name); value != "" {
		return value
	}
	return fallback
}
