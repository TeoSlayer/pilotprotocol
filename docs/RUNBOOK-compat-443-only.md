# Runbook — compat mode on a single TCP/443 port (v1.10.3)

Goal: a compat-mode daemon (`-transport=compat`) talks to the network using
**only outbound TCP/443**. Today it also needs TCP/9000 for the registry; this
runbook routes both ports through 443 on the production rendezvous box using
nginx SNI-routing.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  rendezvous box (34.71.57.205)          │
                    │                                          │
   daemon ──────────┼──── 443 ── nginx stream ── ssl_preread ─┼─┐
   (TCP/443 only)   │              │            (read SNI)    │ │
                    │              │                          │ │
                    │              ├── if SNI=beacon.* ──> 14443 (nginx http,
                    │              │                              terminates TLS,
                    │              │                              proxies WS to
                    │              │                              127.0.0.1:18443)
                    │              │                          │
                    │              ├── if SNI=console.* ─> 14443 (existing vhost)
                    │              │                          │
                    │              └── if SNI=registry.* ─> 14444 (nginx stream,
                    │                                            terminates TLS,
                    │                                            proxies plain
                    │                                            TCP to 9000)
                    │                                          │
                    │   registry on :9000  ←──── plain TCP ────┘
                    └─────────────────────────────────────────┘
```

Nothing in `pkg/registry` changes — the registry stays plain-TCP on 9000.
TLS is terminated entirely at nginx; the certificate for
`registry.pilotprotocol.network` lives only on the rendezvous box.

## Pre-conditions

- nginx 1.18+ built with `stream_ssl_module` and `stream_ssl_preread_module`
  (the production box has both — confirmed via `nginx -V`).
- DNS A record: `registry.pilotprotocol.network` → `34.71.57.205`.
- certbot installed (already present for beacon/console/polo).

## Step 1 — DNS

Add an A record at the DNS provider (Cloudflare for `pilotprotocol.network`):

```
registry.pilotprotocol.network   A   34.71.57.205   proxy=off
```

Wait for propagation (≤5 min for short TTLs). Verify:

```bash
dig +short registry.pilotprotocol.network @1.1.1.1
# → 34.71.57.205
```

## Step 2 — Let's Encrypt certificate

Run on the rendezvous box:

```bash
# Stop nginx briefly so certbot can bind :80 standalone, OR use the
# existing webroot challenge if the certbot/nginx pairing is healthy.
sudo certbot certonly --nginx -d registry.pilotprotocol.network \
  --non-interactive --agree-tos -m teodor@vulturelabs.io

# Verify cert files exist
sudo ls -la /etc/letsencrypt/live/registry.pilotprotocol.network/
```

Auto-renewal is already wired (the certbot systemd timer covers all certs in
`/etc/letsencrypt/live/`).

## Step 3 — Move the existing nginx HTTP vhosts off port 443

Each file in `/etc/nginx/sites-enabled/` with `listen 443 ssl;` needs to
change to `listen 127.0.0.1:14443 ssl;`. Affected vhosts:

- `beacon.pilotprotocol.network`
- `console.pilotprotocol.network`
- `polo.pilotprotocol.network`

```bash
cd /etc/nginx/sites-enabled
sudo sed -i.pre-sni-$(date +%s) \
  -e 's/listen 443 ssl;/listen 127.0.0.1:14443 ssl;/g' \
  -e 's/listen \[::\]:443 ssl;/listen [::1]:14443 ssl;/g' \
  beacon.pilotprotocol.network \
  console.pilotprotocol.network \
  polo.pilotprotocol.network
```

Sanity check the changes:

```bash
grep "listen " /etc/nginx/sites-enabled/{beacon,console,polo}.pilotprotocol.network
# expected: listen 127.0.0.1:14443 ssl;
```

## Step 4 — Add the stream block

Create `/etc/nginx/streams.d/443-sni.conf` (or wherever the existing nginx.conf
sources `stream {}` from — on Debian-style installs it's `/etc/nginx/nginx.conf`
under the `stream` directive). Add:

```nginx
# /etc/nginx/streams.d/443-sni.conf
# Front-end on 443: pre-read TLS ClientHello SNI, route by hostname.
# - registry.pilotprotocol.network -> nginx stream TLS terminator on 14444
#                                     -> plain TCP to local registry on 9000
# - everything else (beacon/console/polo)
#                                  -> nginx http on 14443 (terminates TLS,
#                                     dispatches by Host header to existing vhosts)
map $ssl_preread_server_name $sni_443_upstream {
    registry.pilotprotocol.network  127.0.0.1:14444;
    default                         127.0.0.1:14443;
}

server {
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_pass $sni_443_upstream;
    proxy_protocol off;
    # Standard 443 timeouts — keep connections idle a while since compat
    # daemons keep one long-lived WS connection per node.
    proxy_timeout 1h;
    proxy_connect_timeout 5s;
}

# Internal listener that TERMINATES TLS for registry.pilotprotocol.network
# and proxies plain bytes to the existing plain-TCP registry on 9000.
# The registry's wire protocol (length-prefixed JSON) is non-HTTP, which is
# why this terminates here in the stream module rather than as an HTTP vhost.
server {
    listen 127.0.0.1:14444 ssl;
    ssl_certificate /etc/letsencrypt/live/registry.pilotprotocol.network/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/registry.pilotprotocol.network/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    proxy_pass 127.0.0.1:9000;
    proxy_timeout 5m;
    proxy_connect_timeout 5s;
}
```

If `/etc/nginx/streams.d/` doesn't exist, instead add a `stream { ... }` block
to `/etc/nginx/nginx.conf` (at the same level as `http { ... }`).

## Step 5 — Test the nginx config + reload

```bash
sudo nginx -t
# → "syntax is ok" and "test is successful"

sudo systemctl reload nginx

# Verify the new listeners
sudo ss -tlnp | grep -E ':443|:14443|:14444'
# → expect nginx on 0.0.0.0:443 (stream) and on 127.0.0.1:14443 + 14444
```

## Step 6 — Smoke-test end-to-end from outside

From any machine with DNS access (the macbook works):

```bash
# Sanity: beacon.* still works
curl -sI https://beacon.pilotprotocol.network/health
# → HTTP/1.1 200 OK

# Registry: TLS handshake should complete to the new SNI
openssl s_client -connect registry.pilotprotocol.network:443 \
  -servername registry.pilotprotocol.network -brief </dev/null
# → CONNECTION ESTABLISHED + cert CN=registry.pilotprotocol.network

# End-to-end: dial the registry via the v1.10.3 daemon
PILOT_REGISTRY=registry.pilotprotocol.network:443 \
  ~/.pilot/bin/pilot-daemon \
    -transport compat \
    -registry-tls -registry-trust system \
    -socket /tmp/443-compat.sock \
    -identity /tmp/443-id.json \
    -email compat-443-test@vulturelabs.io \
    -log-level info &
sleep 5
PILOT_SOCKET=/tmp/443-compat.sock ~/.pilot/bin/pilotctl info | head -5
# → daemon should report a node_id; only TCP/443 connections in lsof
```

## Rollback

If anything goes sideways:

```bash
# Revert sites-enabled changes
cd /etc/nginx/sites-enabled
for f in beacon.pilotprotocol.network console.pilotprotocol.network \
         polo.pilotprotocol.network; do
    sudo cp -p "$f.pre-sni-<TIMESTAMP>" "$f"
done

# Drop the new stream config
sudo rm /etc/nginx/streams.d/443-sni.conf
sudo nginx -t && sudo systemctl reload nginx
```

`/etc/letsencrypt/live/registry.pilotprotocol.network/` is harmless to leave in
place even after rollback.

## After-the-fact: what the daemon does

In v1.10.3, `pilot-daemon -transport compat` (with no other flags) auto-
configures itself for the 443-only path:

```
-registry         registry.pilotprotocol.network:443  (default in compat mode)
-registry-tls     true                                (auto-set in compat mode)
-registry-trust   system                              (auto-set in compat mode)
-compat-beacon    wss://beacon.pilotprotocol.network/v1/compat
-tls-trust        system
```

Anyone passing `-registry <hostport>` explicitly opts out of the auto-config
and continues to hit the plain-TCP 9000 path.
