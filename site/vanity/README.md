# kevaso.com Go vanity paths

Makes `import "kevaso.com/core/api"` resolve to the right GitHub repo, so repos can move (to an org,
anywhere) without changing a single import. One Cloudflare Worker, one map: `MODULES` in `vanity.js`.

The Worker is routed only the module paths (`kevaso.com/core*`, …; other paths it catches go to the
site through the `SITE` service binding). Everything
else on kevaso.com is the public website (Worker `kevaso-www`,
its own private repo); the two never get in each other's way.

## One-time Cloudflare setup

1. Cloudflare dashboard → **Add a site** → `kevaso.com` (Free plan). Note the two nameservers it gives.
2. Namecheap → Domain List → `kevaso.com` → **Nameservers: Custom DNS** → paste Cloudflare's two.
3. Cloudflare → DNS: add `A  kevaso.com  192.0.2.1`, **Proxied** (orange cloud). The address is a
   placeholder: Workers answer every path (this one the module paths, the website's Worker
   `kevaso-www` on `kevaso.com/*` the rest; the most specific route wins), so nothing reaches it.
4. Deploy (below). The routes are in `wrangler.toml`.

## Develop and deploy

```bash
node --test          # unit tests (also run in CI)
npx wrangler login   # once
npx wrangler deploy  # publish to the module routes
```

Check after deploying:

```bash
curl -s 'https://kevaso.com/core/api?go-get=1'   # shows the go-import meta tag
```

Adding a repo: one line in `MODULES`, its route in `wrangler.toml` (a test fails if they
disagree), `node --test`, `npx wrangler deploy`.
