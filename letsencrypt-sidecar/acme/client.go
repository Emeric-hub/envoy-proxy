package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// acmeUser implements lego's registration.User interface. Only the
// account private key is persisted to disk (loadOrCreateKey below) — the
// registration resource itself isn't, since re-registering an existing
// account key against an ACME server (Let's Encrypt included) is
// idempotent and just returns the existing account, so there's nothing
// gained by also serializing that response across restarts.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey         { return u.key }

type Client struct {
	lego *lego.Client
}

type ClientConfig struct {
	Email      string
	Staging    bool
	AccountDir string
	Provider   challenge.Provider
}

// NewClient sets up the ACME account (loading or creating a persistent
// account key under AccountDir) and registers the HTTP-01 provider.
// Staging defaults true at the call site (see main.go) — production Let's
// Encrypt has real, low rate limits; staging is the safe default the same
// way this repo's other dry-run-style flags (AUDIT_MODE) default safe.
func NewClient(cfg ClientConfig) (*Client, error) {
	priv, err := loadOrCreateKey(filepath.Join(cfg.AccountDir, "account.key"))
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}

	user := &acmeUser{email: cfg.Email, key: priv}

	legoCfg := lego.NewConfig(user)
	if cfg.Staging {
		legoCfg.CADirURL = lego.LEDirectoryStaging
	} else {
		legoCfg.CADirURL = lego.LEDirectoryProduction
	}
	legoCfg.Certificate.KeyType = certcrypto.RSA2048

	legoClient, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}
	if err := legoClient.Challenge.SetHTTP01Provider(cfg.Provider); err != nil {
		return nil, fmt.Errorf("registering http-01 provider: %w", err)
	}

	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("acme registration: %w", err)
	}
	user.registration = reg

	return &Client{lego: legoClient}, nil
}

// ObtainCertificate runs the full HTTP-01 issuance flow for one domain —
// lego calls back into the registered Provider's Present()/CleanUp()
// during this call. Returns PEM-encoded cert (with chain, Bundle: true)
// and private key.
func (c *Client) ObtainCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	res, err := c.lego.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	})
	if err != nil {
		return nil, nil, err
	}
	return res.Certificate, res.PrivateKey, nil
}

// loadOrCreateKey persists the ACME account key as EC P-256 (lego/Let's
// Encrypt both support it, and it's smaller/faster than RSA for an
// account key that never needs to be human-portable).
func loadOrCreateKey(path string) (crypto.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM in %s", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
