# Cuevello Relay

Docker service for Cuevello relay connections. The Mac server connects to the control port, clients connect to per-device subdomains, and the relay forwards encrypted Cuevello traffic to the registered Mac.

## Container Image

```text
ghcr.io/hosy/cuevello-relay:latest
```

The included GitHub Actions workflow publishes the image to GitHub Container Registry when the `main` branch is pushed.

## Required DNS

Use one relay hostname and a wildcard record for device subdomains:

```text
relay.example.com      A      203.0.113.10
*.relay.example.com    A      203.0.113.10
```

## TLS Certificate

The relay TLS certificate is used for the Mac server control connection and must cover the relay hostname:

```text
relay.example.com
```

Example with Certbot DNS challenge:

```sh
certbot certonly --manual --preferred-challenges dns \
  -d relay.example.com \
  --agree-tos \
  --email you@example.com \
  --no-eff-email
```

The client port uses TLS passthrough to the Mac server. A wildcard DNS record is required for device subdomains, but a wildcard TLS certificate is not required for the relay.

## Run

```sh
mkdir -p /opt/cuevello-relay/certs
cd /opt/cuevello-relay
cp /etc/letsencrypt/live/relay.example.com/fullchain.pem ./certs/fullchain.pem
cp /etc/letsencrypt/live/relay.example.com/privkey.pem ./certs/privkey.pem
openssl rand -base64 48
```

Set the generated value as `RELAY_SECRET_PEPPER` in `compose.yaml`, then start:

```sh
docker compose up -d
docker compose logs -f --tail=100
```

## Ports

- `9443` externally maps to container port `443` for clients.
- `9444` externally maps to container port `8443` for Mac server control connections.

## Environment

```text
RELAY_SECRET_PEPPER  Required. Long random secret used to bind device secrets.
TLS_CERT_FILE        Defaults to /certs/fullchain.pem in compose.
TLS_KEY_FILE         Defaults to /certs/privkey.pem in compose.
RELAY_DATA_FILE      Defaults to /data/devices.json.
CLIENT_ADDR          Defaults to :443.
CONTROL_ADDR         Defaults to :8443.
MAX_STREAMS_PER_DEVICE        Defaults to 32. Caps parallel tunnels to one Mac.
CLIENT_RATE_LIMIT_PER_MINUTE  Defaults to 120. Limits public client connects per IP.
CONTROL_RATE_LIMIT_PER_MINUTE Defaults to 30. Limits Mac control registrations per IP.
REQUIRE_SIGNED_REGISTRATION   Defaults to true. Requires Mac server control registrations to be signed by the device key.
```

## Security Notes

- Knowing a relay URL is not enough to control a Mac. The Cuevello client still has to complete end-to-end TLS with a paired client certificate, and the Mac checks the certificate fingerprint before executing any action.
- The public client port uses TLS passthrough. The relay only reads the SNI hostname needed for routing and cannot decrypt Cuevello requests.
- Mac server control registrations are signed with a persistent device key. After the relay has stored the public key for a device, the relay secret alone is not sufficient to take over that device registration.
- The container enforces TLS 1.3, bounded registration requests, per-IP connection rate limits, and per-device stream limits to reduce abuse if a relay URL becomes known.
- Keep `RELAY_SECRET_PEPPER`, `/data/devices.json`, and the TLS private key backed up and private.
