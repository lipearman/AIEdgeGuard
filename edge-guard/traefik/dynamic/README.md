# Dynamic config directory

Traefik watches this folder for dynamic configuration (TLS certs, custom
middlewares, file-based routers). Currently empty — the CrowdSec middleware
comes from container labels on the traefik service.

To add your own TLS certificates later, create `tls.yml`, for example:

```yaml
tls:
  certificates:
    - certFile: /etc/traefik/dynamic/certs/example.crt
      keyFile: /etc/traefik/dynamic/certs/example.key
```

(then mount the certs folder into the traefik container)
