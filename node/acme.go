package node

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AnixOps/anix-agent/v5/conf"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

// renewBefore is how long before it expires a certificate is renewed.
const renewBefore = 30 * 24 * time.Hour

// acmeAccount is the ACME account of an e-mail address (registration.User).
type acmeAccount struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (a *acmeAccount) GetEmail() string                        { return a.email }
func (a *acmeAccount) GetRegistration() *registration.Resource { return a.registration }
func (a *acmeAccount) GetPrivateKey() crypto.PrivateKey        { return a.key }

// accountFile is the stored account: the key is SEC 1 PEM.
type accountFile struct {
	Email        string
	Registration *registration.Resource
	Key          string
}

// accountPath is where the account of email is stored, next to certFile.
func accountPath(certFile, email string) string {
	return filepath.Join(filepath.Dir(certFile), "user", "user-"+email+".json")
}

// loadACMEAccount reads the account of email from path. Without a stored
// account of that e-mail it returns a new, unregistered one.
func loadACMEAccount(path, email string) (*acmeAccount, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var stored accountFile
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, fmt.Errorf("decode the ACME account %s: %w", path, err)
		}
		if stored.Email == email && stored.Registration != nil {
			key, err := parseAccountKey(stored.Key)
			if err != nil {
				return nil, fmt.Errorf("the ACME account %s: %w", path, err)
			}
			return &acmeAccount{email: email, registration: stored.Registration, key: key}, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &acmeAccount{email: email, key: key}, nil
}

// parseAccountKey reads the account key, PEM text or base64 of it.
func parseAccountKey(text string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			block, _ = pem.Decode(decoded)
		}
	}
	if block == nil {
		return nil, errors.New("no PEM key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// saveACMEAccount writes account to path (0600).
func saveACMEAccount(path string, account *acmeAccount) error {
	key, ok := account.key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("the ACME account key is not ECDSA")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(accountFile{
		Email:        account.email,
		Registration: account.registration,
		Key:          string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, data, 0o600)
}

// newACMEClient returns a client of config's account, registered, with the
// challenge of config's mode.
func newACMEClient(config *conf.CertConfig) (*lego.Client, error) {
	path := accountPath(config.CertFile, config.Email)
	account, err := loadACMEAccount(path, config.Email)
	if err != nil {
		return nil, err
	}
	legoConfig := lego.NewConfig(account)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}
	if account.registration == nil {
		account.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register the ACME account of %s: %w", config.Email, err)
		}
		if err := saveACMEAccount(path, account); err != nil {
			return nil, err
		}
	}
	switch config.CertMode {
	case "http":
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	case "dns":
		for name, value := range config.DNSEnv {
			if err := os.Setenv(name, value); err != nil {
				return nil, err
			}
		}
		provider, providerErr := dns.NewDNSChallengeProviderByName(config.Provider)
		if providerErr != nil {
			return nil, providerErr
		}
		err = client.Challenge.SetDNS01Provider(provider)
	default:
		err = fmt.Errorf("certificate mode %q has no ACME challenge", config.CertMode)
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

// obtainCertificate gets a certificate for CertDomain from the ACME CA.
func obtainCertificate(config *conf.CertConfig) error {
	client, err := newACMEClient(config)
	if err != nil {
		return err
	}
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{config.CertDomain}, Bundle: true})
	if err != nil {
		return fmt.Errorf("obtain a certificate for %s: %w", config.CertDomain, err)
	}
	return writeCertificate(config.CertFile, config.KeyFile, resource.Certificate, resource.PrivateKey)
}

// renewCertificate is the daily renewal job.
func (c *Controller) renewCertificate() error {
	return renewCertificate(c.CertConfig)
}

// renewCertificate renews CertFile when it expires within renewBefore.
func renewCertificate(config *conf.CertConfig) error {
	certPEM, err := os.ReadFile(config.CertFile)
	if err != nil {
		return err
	}
	cert, err := certcrypto.ParsePEMCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("read %s: %w", config.CertFile, err)
	}
	if time.Until(cert.NotAfter) > renewBefore {
		return nil
	}
	client, err := newACMEClient(config)
	if err != nil {
		return err
	}
	resource, err := client.Certificate.RenewWithOptions(certificate.Resource{Domain: config.CertDomain, Certificate: certPEM}, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return fmt.Errorf("renew the certificate of %s: %w", config.CertDomain, err)
	}
	return writeCertificate(config.CertFile, config.KeyFile, resource.Certificate, resource.PrivateKey)
}
