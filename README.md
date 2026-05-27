# SSF Transmitter

Standalone FastAPI service that provides Shared Signals Framework endpoints next to a free Authentik installation.

## Public URLs

- SSF Config URL: `https://idp.example.com/shared-signals/.well-known/ssf-configuration`
- JWKS: `https://idp.example.com/shared-signals/jwks.json`
- Stream endpoint: `https://idp.example.com/shared-signals/ssf/streams`
- Status endpoint: `https://idp.example.com/shared-signals/ssf/status`

## Environment

```env
SSF_ISSUER=https://idp.example.com/application/o/apple-id/
SSF_BASE_URL=https://idp.example.com/shared-signals
SSF_ROOT_PATH=/shared-signals
SSF_CONTAINER_PORT=8000
AUTHENTIK_WEBHOOK_SECRET=change_me_to_random_string_min_32_chars
LOG_LEVEL=INFO
```

For Docker Compose on Synology, add the variables from `.env.example` next to your Authentik compose file.

## Nginx Proxy Manager

Add this custom location to the existing `idp.example.com` proxy host:

```nginx
location ^~ /shared-signals/ {
    proxy_pass http://127.0.0.1:62107/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

If `SSF_HOST_PORT` changes, update the port in Nginx Proxy Manager too.

## Authentik Webhook

Configure a Generic Webhook transport in Authentik:

- URL: `http://authentik-ssf:8000/webhook/authentik`
- HMAC secret: the value of `SSF_WEBHOOK_SECRET`
- Events: `authentik.core.auth.logout`, `authentik.core.user.write`, `authentik.core.user.delete`

If you change `SSF_CONTAINER_PORT`, update the internal webhook URL port.

## Logging

The service logs to stdout/stderr only, so logs are visible in Portainer and `docker logs`.
Secrets, bearer tokens, and full SET JWT payloads are not logged.
