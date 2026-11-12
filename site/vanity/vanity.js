// Cloudflare Worker for Go vanity import paths on kevaso.com.
//
// `go get kevaso.com/core/api` asks https://kevaso.com/core/api?go-get=1 where the code lives. This
// Worker answers those requests from MODULES below, and leaves every other request alone (it goes to
// the site's origin). A browser opening a module path (e.g. https://kevaso.com/core) is redirected to
// its repo.
//
// To add or move a repo: edit MODULES, run the tests, redeploy. Import paths never change.

export const HOST = "kevaso.com";

// Module root (first path segment) → git repository. Modules inside a repo (core/api, core/sdk) are
// covered by their root's entry.
export const MODULES = {
  core: "https://github.com/dlebee/kevaso",
  // "provider-linode": "https://github.com/dlebee/kevaso-provider-linode",
  // "provider-juicefs": "https://github.com/dlebee/kevaso-provider-juicefs",
};

const escape = (s) =>
  s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// route decides what to do with a request URL. Pure, so it's unit-tested without Cloudflare.
//   { kind: "go-import", status, body }  answer for the go command
//   { kind: "redirect", location }       a browser on a module path
//   { kind: "pass" }                     not ours: let the origin handle it
export function route(url, modules = MODULES, host = HOST) {
  const u = new URL(url);
  const segments = u.pathname.split("/").filter(Boolean);
  const root = segments[0];
  const repo = root && Object.hasOwn(modules, root) ? modules[root] : undefined;
  const goGet = u.searchParams.get("go-get") === "1";

  if (goGet) {
    if (!repo) {
      return { kind: "go-import", status: 404, body: `no Go module at ${host}${u.pathname}\n` };
    }
    const prefix = `${host}/${root}`;
    const body =
      `<!doctype html>\n<meta name="go-import" content="${escape(`${prefix} git ${repo}`)}">\n` +
      `<meta name="go-source" content="${escape(
        `${prefix} ${repo} ${repo}/tree/main{/dir} ${repo}/blob/main{/dir}/{file}#L{line}`,
      )}">\n` +
      `<a href="${escape(repo)}">${escape(repo)}</a>\n`;
    return { kind: "go-import", status: 200, body };
  }
  if (repo) {
    const rest = segments.slice(1).join("/");
    return { kind: "redirect", location: rest ? `${repo}/tree/main/${rest}` : repo };
  }
  return { kind: "pass" };
}

export default {
  async fetch(request) {
    const r = route(request.url);
    switch (r.kind) {
      case "go-import":
        return new Response(r.body, {
          status: r.status,
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" },
        });
      case "redirect":
        return Response.redirect(r.location, 302);
      default:
        return fetch(request);
    }
  },
};
