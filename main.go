package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid %s: %v", key, err)
	}
	return d
}

// bootstrapSecret reads the one-time bootstrap secret from a file
// (CLAVEX_BOOTSTRAP_SECRET_FILE, preferred — avoids leaving it in the
// process environment/shell history) or falls back to
// CLAVEX_BOOTSTRAP_SECRET directly. Only needed for the first enrollment.
func bootstrapSecret() string {
	if path := os.Getenv("CLAVEX_BOOTSTRAP_SECRET_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read CLAVEX_BOOTSTRAP_SECRET_FILE: %v", err)
		}
		return trimNewline(string(data))
	}
	return os.Getenv("CLAVEX_BOOTSTRAP_SECRET")
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func configFromEnv() config {
	deviceID := os.Getenv("DEVICE_ID")
	if deviceID == "" {
		log.Fatal("DEVICE_ID is required")
	}
	orgID := os.Getenv("CLAVEX_ORG_ID")
	if orgID == "" {
		log.Fatal("CLAVEX_ORG_ID is required")
	}
	return config{
		EnrollURL:       os.Getenv("CLAVEX_ENROLL_URL"),
		RenewAddr:       os.Getenv("CLAVEX_RENEW_ADDR"),
		ServerCAPath:    os.Getenv("CLAVEX_SERVER_CA_PATH"),
		OrgID:           orgID,
		DeviceID:        deviceID,
		BootstrapSecret: bootstrapSecret(),
		CertPath:        env("CERT_PATH", "/etc/keel/device-pki/device.crt"),
		KeyPath:         env("KEY_PATH", "/etc/keel/device-pki/device.key"),
		CAPath:          env("CA_PATH", "/etc/keel/device-pki/ca.crt"),
		RenewWindow:     envDuration("RENEW_WINDOW", 48*time.Hour),
		CheckInterval:   envDuration("CHECK_INTERVAL", 30*time.Minute),
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `keel-cert-manager: Clavex Device CA enrollment/renewal client

Usage:
  keel-cert-manager enroll   one-time bootstrap enrollment, then exit
  keel-cert-manager renew    renew the current certificate now, then exit
  keel-cert-manager status   print the current certificate's time-to-expiry
  keel-cert-manager run      enroll if needed, then renew unattended forever

Configuration is via environment variables — see README.md.`)
}

func main() {
	if len(os.Args) != 2 {
		usage()
		os.Exit(2)
	}

	cfg := configFromEnv()
	ctx := context.Background()

	switch os.Args[1] {
	case "enroll":
		if _, err := enroll(ctx, cfg); err != nil {
			log.Fatalf("enroll: %v", err)
		}
		log.Printf("enrolled %s", cfg.cn())

	case "renew":
		if _, err := renew(ctx, cfg); err != nil {
			log.Fatalf("renew: %v", err)
		}
		log.Printf("renewed %s", cfg.cn())

	case "status":
		ttl, err := certTimeToExpiry(cfg.CertPath)
		if err != nil {
			log.Fatalf("status: %v", err)
		}
		fmt.Printf("%s expires in %s\n", cfg.cn(), ttl.Round(time.Second))

	case "run":
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := run(ctx, cfg, log.Printf); err != nil {
			log.Fatalf("run: %v", err)
		}

	default:
		usage()
		os.Exit(2)
	}
}
