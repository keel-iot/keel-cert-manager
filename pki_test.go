package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCSR(t *testing.T) {
	csrPEM, keyPEM, err := generateCSR("device-1@org-1")
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected CSR PEM block, got %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "device-1@org-1" {
		t.Fatalf("CN = %q, want device-1@org-1", csr.Subject.CommonName)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatalf("expected EC PRIVATE KEY PEM block, got %v", keyBlock)
	}
}

func TestGenerateCSRFreshKeyEachCall(t *testing.T) {
	_, key1, _ := generateCSR("device-1@org-1")
	_, key2, _ := generateCSR("device-1@org-1")
	if string(key1) == string(key2) {
		t.Fatal("expected a fresh key pair on each call")
	}
}

func TestConfigCN(t *testing.T) {
	cfg := config{DeviceID: "device-42", OrgID: "acme-org"}
	if got, want := cfg.cn(), "device-42@acme-org"; got != want {
		t.Fatalf("cn() = %q, want %q", got, want)
	}
}

func TestWriteFileAtomicCreatesAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "file.pem")

	if err := writeFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "first" {
		t.Fatalf("content = %q, want %q", got, "first")
	}

	if err := writeFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("content = %q, want %q", got, "second")
	}

	// No leftover temp files in the target directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 file in dir, got %d: %v", len(entries), entries)
	}
}

func TestCertTimeToExpiry(t *testing.T) {
	certPEM, _, err := selfSignedTestCert(24 * time.Hour)
	if err != nil {
		t.Fatalf("build test cert: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	ttl, err := certTimeToExpiry(path)
	if err != nil {
		t.Fatalf("certTimeToExpiry: %v", err)
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		t.Fatalf("ttl = %v, want in (0, 24h]", ttl)
	}
}

func TestCertTimeToExpiryMissingFile(t *testing.T) {
	if _, err := certTimeToExpiry("/nonexistent/path.pem"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
