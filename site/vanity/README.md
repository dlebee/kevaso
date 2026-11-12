# kevaso.com Go vanity paths

Makes `import "kevaso.com/core/api"` resolve to the right GitHub repo, so repos can move (to an org,
anywhere) without changing a single import. One Cloudflare Worker, one map: `MODULES` in `vanity.js`.

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
