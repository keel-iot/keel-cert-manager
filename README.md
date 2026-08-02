# keel-cert-manager

Standalone enrollment and renewal client for Clavex's Device CA
(`internal/devicepki` in `clavex-eu/clavex`), used to authenticate a device
to [`keel-mqtt-gateway`](../keel-mqtt-cluster) via mTLS.

It does exactly one thing: keep a certificate/key/CA bundle valid on disk,
enrolling it once with a bootstrap secret and renewing it unattended
thereafter (like ACME/kubelet certificate renewal). Anything that connects
to `keel-mqtt-gateway` — `keel-agent`, a vendor's own agent, a non-Go device
process — reads the files this tool maintains; it has no opinion on what
consumes them.

This is the **"full" auth tier**: real certificate rotation and revocation,
backed by a Vault-anchored CA that Clavex custodies. For tenants without
Clavex, see [`keel-jwt-agent`](../keel-jwt-agent) — a strictly weaker
"basic" tier (generic OAuth2/OIDC, no real revocation) for the same broker.

## Contract

The certificate's Subject CommonName MUST be exactly `<deviceID>@<tenantID>`
— fixed by `keel-mqtt-gateway` (`internal/auth/crypto.go`'s
`VerifyCertificate`) and mirrored by Clavex (`internal/devicepki`'s
`expectedCN`/`ParseCN`).

- **Enrollment** consumes a one-time bootstrap secret over Clavex's main API
  (`POST .../organizations/<org_id>/devices/enroll`).
- **Renewal** authenticates with the device's own current, still-valid
  certificate over Clavex's dedicated Device CA mTLS listener
  (`POST /renew`) — no secret or operator involved.
- A fresh ECDSA P-256 keypair is generated on every enroll/renew — the CSR
  only proves possession of whichever key is presented, so no single
  private key outlives one certificate's lifetime.

## Usage

```
keel-cert-manager enroll   one-time bootstrap enrollment, then exit
keel-cert-manager renew    renew the current certificate now, then exit
keel-cert-manager status   print the current certificate's time-to-expiry
keel-cert-manager run      enroll if needed, then renew unattended forever
```

Run as a long-lived sidecar/daemon (systemd service, K8s sidecar container)
alongside whatever process actually uses the cert/key files for its own
mTLS connection to `keel-mqtt-gateway`.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `DEVICE_ID` | yes | — | device external id, the `<deviceID>@` half of the CN |
| `CLAVEX_ORG_ID` | yes | — | tenant id, the `@<tenantID>` half of the CN |
| `CLAVEX_ENROLL_URL` | yes (for `enroll`) | — | `POST https://clavex/api/v1/organizations/<org_id>/devices/enroll` |
| `CLAVEX_RENEW_ADDR` | yes (for `renew`) | — | host:port of Clavex's Device CA mTLS renewal listener |
| `CLAVEX_BOOTSTRAP_SECRET_FILE` | one of these two | — | path to the one-time bootstrap secret (preferred — avoids leaving it in the process environment/shell history) |
| `CLAVEX_BOOTSTRAP_SECRET` | | — | bootstrap secret, inline (fallback if no `_FILE` var set) |
| `CLAVEX_SERVER_CA_PATH` | no | system pool | extra root CA to trust Clavex's own TLS server certificate |
| `CERT_PATH` | no | `/etc/keel/device-pki/device.crt` | where the issued certificate is written |
| `KEY_PATH` | no | `/etc/keel/device-pki/device.key` | where the private key is written (mode `0600`) |
| `CA_PATH` | no | `/etc/keel/device-pki/ca.crt` | where the issuing CA is written |
| `RENEW_WINDOW` | no | `48h` | renew once time-to-expiry drops below this |
| `CHECK_INTERVAL` | no | `30m` | how often `run` checks time-to-expiry |

## Build

```
go build ./...
go test ./...
```
