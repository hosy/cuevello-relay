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

The certificate must cover both names:

```text
relay.example.com
*.relay.example.com
```

Example with Certbot DNS challenge:

```sh
certbot certonly --manual --preferred-challenges dns \
  -d relay.example.com \
  -d '*.relay.example.com' \
  --agree-tos \
  --email you@example.com \
  --no-eff-email
```

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
```
