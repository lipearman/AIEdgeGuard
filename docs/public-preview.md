# Temporary public preview

The user explicitly requested temporary removal of authentication for the canonical `/AIEdgeGuard` website and API, and public Internet access without Tailscale.

## Verified URLs

- Public: `https://llm-server.tail923b9a.ts.net/AIEdgeGuard/mission`
- Existing tailnet URL: `https://llm-server.tail923b9a.ts.net:8443/AIEdgeGuard/mission`
- Canonical base path redirects to Mission Control.

The canonical Traefik route omits `aiedge-auth` and retains `crowdsec@docker`. This includes write API endpoints as requested. The `/aiedge` alias retains Basic Auth. Direct API port8099 stays loopback-only. There is no automatic expiry because no duration was specified.

## Restore authentication

```powershell
python tools/set_preview_auth.py --enable
docker restart traefik
```

To close the public preview completely, also detach its public entrypoint and remove only its prefix handler (the existing public portal root shares that entrypoint):

```powershell
python tools/set_preview_auth.py --enable --close-public
docker restart traefik
tailscale funnel --https=443 --set-path=/AIEdgeGuard off
```

Original route files were saved under `.artifacts/auth-preview-20261112-181643/`; original Tailscale handlers were recorded in `.artifacts/tailscale-before-public-preview.json`. Avoid restoring the whole Tailscale configuration over unrelated later changes; remove only the preview prefix.

## Deployment evidence

- Canonical base URL, Mission page, health, incidents and visibility API returned HTTP200 without credentials.
- A POST to approval for nonexistent decision0 returned404, confirming routing without executing any action.
- Public DNS was resolved through an external resolver and HTTPS was forced to a public Funnel address; Mission returned200 through that Internet route. The default web-fetch tool could not access the site, so that was not used as proof.
- Existing TCP/Funnel flags and other Tailscale handlers were preserved. Only the canonical8443 handler was moved from localhost8080 to the dedicated localhost18083 gateway listener; the public443 prefix uses localhost18082.
- Localhost8080 was shadowed by WSL relay. Dedicated gateway listeners avoid that conflict. Canonical Traefik entrypoints now include `web`, `funnelroot443`, `funnelroot8443`.
- Docker engine was initially unreachable. A normal Desktop restart timed out; restarting verified Docker Desktop processes and terminating only its `docker-desktop` distro recovered the engine. Ubuntu was left running.
