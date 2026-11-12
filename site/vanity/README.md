# kevaso.com Go vanity paths

Makes `import "kevaso.com/core/api"` resolve to the right GitHub repo, so repos can move (to an org,
anywhere) without changing a single import. One Cloudflare Worker, one map: `MODULES` in `vanity.js`.

## One-time Cloudflare setup

1. Cloudflare dashboard → **Add a site** → `kevaso.com` (Free plan). Note the two nameservers it gives.
2. Namecheap → Domain List → `kevaso.com` → **Nameservers: Custom DNS** → paste Cloudflare's two.
3. Cloudflare → DNS: add `A  kevaso.com  192.0.2.1`, **Proxied** (orange cloud). The address is a
   placeholder: the Worker answers every request, so nothing ever reaches it.
4. Deploy (below). The route `kevaso.com/*` is in `wrangler.toml`.

When kevaso.com gets a real site, point that record at it and set `SITE_ORIGIN = true`.

## Develop and deploy

```bash
node --test          # unit tests (also run in CI)
npx wrangler login   # once
npx wrangler deploy  # publish to the kevaso.com/* route
```

Check after deploying:

```bash
curl -s 'https://kevaso.com/core/api?go-get=1'   # shows the go-import meta tag
```

Adding a repo: one line in `MODULES`, `node --test`, `npx wrangler deploy`.
