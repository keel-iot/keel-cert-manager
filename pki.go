// Package main implements keel-cert-manager: a standalone enrollment and
// renewal client for Clavex's Device CA (internal/devicepki), used to
// authenticate a device to keel-mqtt-gateway via mTLS.
//
// It does exactly one thing: keep a certificate/key/CA bundle on disk valid,
// enrolling it once with a bootstrap secret and renewing it unattended
// thereafter (like ACME/kubelet renewal). Anything that connects to
// keel-mqtt-gateway — keel-agent, a vendor's own agent, a non-Go device
// process — reads the files this tool maintains; it has no opinion on what
// consumes them.
//
// Contract fixed by keel-mqtt-gateway (internal/auth/crypto.go
// VerifyCertificate) and mirrored by Clavex (internal/devicepki
// expectedCN/ParseCN): the certificate's Subject CommonName MUST be exactly
// "<deviceID>@<tenantID>".
//
// Enrollment consumes a one-time bootstrap secret over Clavex's main API
// (POST .../devices/enroll). Renewal instead authenticates with the
// device's own current, still-valid certificate over Clavex's dedicated
// Device CA mTLS listener (POST /renew) — no secret or operator involved.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// config configures the Clavex Device CA enrollment/renewal client.
type config struct {
	EnrollURL       string // POST https://clavex/api/v1/organizations/<org_id>/devices/enroll
	RenewAddr       string // host:port of Clavex's dedicated Device CA mTLS renewal listener
	ServerCAPath    string // optional: extra root CA to trust Clavex's TLS server certificate; empty = system pool
	OrgID           string // tenant id; the "@<tenantID>" half of the certificate CN
	DeviceID        string // device external id; the "<deviceID>@" half of the CN
	BootstrapSecret string // one-time secret, consumed by exactly one Enroll call
	CertPath        string
	KeyPath         string
	CAPath          string
	RenewWindow     time.Duration // renew once time-to-expiry drops below this
	CheckInterval   time.Duration // how often the run loop checks time-to-expiry
}

// cn builds the external CN contract "<deviceID>@<tenantID>".
func (c config) cn() string {
	return c.DeviceID + "@" + c.OrgID
}

type enrollResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	IssuingCAPEM   string    `json:"issuing_ca_pem"`
	SerialNumber   string    `json:"serial_number"`
	NotAfter       time.Time `json:"not_after"`
}

// generateCSR creates a fresh ECDSA P-256 key and a self-signed PKCS#10 CSR
// for it with the given Subject CommonName. A new key is generated on every
// call (including renewals) rather than reusing the previous one: the CSR
// only proves possession of whichever key is presented, so a fresh keypair
// per certificate avoids any single private key living longer than one
// certificate's lifetime.
func generateCSR(cn string) (csrPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, keyPEM, nil
}

// writeFileAtomic writes data to path via a temp file + rename in the same
// directory, so a concurrent reader (or a crash mid-write) never observes a
// truncated cert/key file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed away

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// saveIssuedCertificate persists the newly issued certificate, its private
// key, and the issuing CA to cfg's configured paths.
func saveIssuedCertificate(cfg config, resp enrollResponse, keyPEM []byte) error {
	if err := writeFileAtomic(cfg.KeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := writeFileAtomic(cfg.CertPath, []byte(resp.CertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := writeFileAtomic(cfg.CAPath, []byte(resp.IssuingCAPEM), 0o644); err != nil {
		return fmt.Errorf("write issuing CA: %w", err)
	}
	return nil
}

// enroll performs the one-time bootstrap enrollment: generates a keypair +
// CSR, exchanges the bootstrap secret for the device's first certificate,
// and writes cert/key/CA to disk.
func enroll(ctx context.Context, cfg config) (*enrollResponse, error) {
	if cfg.BootstrapSecret == "" {
		return nil, fmt.Errorf("enroll: no bootstrap secret available")
	}
	csrPEM, keyPEM, err := generateCSR(cfg.cn())
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]string{
		"device_id":        cfg.DeviceID,
		"bootstrap_secret": cfg.BootstrapSecret,
		"csr_pem":          string(csrPEM),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EnrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll request: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enroll: server returned %d", httpResp.StatusCode)
	}

	var resp enrollResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}
	if err := saveIssuedCertificate(cfg, resp, keyPEM); err != nil {
		return nil, err
	}
	return &resp, nil
}

// renew authenticates with the device's current certificate over Clavex's
// dedicated Device CA mTLS listener and exchanges it for a fresh one. The
// current certificate must still be valid (renewal happens well before
// expiry, per cfg.RenewWindow) since it is what authenticates this call —
// there is no bootstrap secret involved.
func renew(ctx context.Context, cfg config) (*enrollResponse, error) {
	current, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load current certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{current},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.ServerCAPath != "" {
		caPEM, err := os.ReadFile(cfg.ServerCAPath)
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse server CA: no certificates found in %s", cfg.ServerCAPath)
		}
		tlsConfig.RootCAs = pool
	}

	csrPEM, keyPEM, err := generateCSR(cfg.cn())
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+cfg.RenewAddr+"/renew", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("renew request: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renew: server returned %d", httpResp.StatusCode)
	}

	var resp enrollResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode renew response: %w", err)
	}
	if err := saveIssuedCertificate(cfg, resp, keyPEM); err != nil {
		return nil, err
	}
	return &resp, nil
}

// certTimeToExpiry parses the PEM certificate at path and returns how long
// until it expires.
func certTimeToExpiry(path string) (time.Duration, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return 0, fmt.Errorf("no PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("parse certificate: %w", err)
	}
	return time.Until(cert.NotAfter), nil
}

// run enrolls (if no certificate exists yet) and then loops forever,
// renewing the certificate whenever its time-to-expiry drops below
// cfg.RenewWindow. Intended to run as a long-lived sidecar/daemon (e.g. a
// systemd service) alongside whatever process actually uses the cert/key
// files for its own mTLS connection to keel-mqtt-gateway.
func run(ctx context.Context, cfg config, logf func(string, ...any)) error {
	if _, err := os.Stat(cfg.CertPath); err != nil {
		if _, err := enroll(ctx, cfg); err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		logf("enrolled %s", cfg.cn())
	}

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ttl, err := certTimeToExpiry(cfg.CertPath)
			if err != nil {
				logf("check expiry: %v", err)
				continue
			}
			if ttl > cfg.RenewWindow {
				continue
			}
			if _, err := renew(ctx, cfg); err != nil {
				logf("renewal failed (retrying in %s): %v", cfg.CheckInterval, err)
				continue
			}
			logf("renewed %s", cfg.cn())
		}
	}
}
