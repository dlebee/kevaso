// Run with: node --test   (from site/vanity)
import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { route } from "./vanity.js";

const mods = { core: "https://github.com/dlebee/kevaso", "provider-linode": "https://github.com/dlebee/kevaso-provider-linode" };

test("go get on a module root and its sub-modules answers with the repo", () => {
  for (const path of ["/core", "/core/", "/core/api", "/core/sdk/kri"]) {
    const r = route(`https://kevaso.com${path}?go-get=1`, mods);
    assert.equal(r.kind, "go-import", path);
    assert.equal(r.status, 200, path);
    assert.match(r.body, /<meta name="go-import" content="kevaso\.com\/core git https:\/\/github\.com\/dlebee\/kevaso">/, path);
    assert.match(r.body, /<meta name="go-source" content="kevaso\.com\/core https:\/\/github\.com\/dlebee\/kevaso /, path);
  }
});

test("each repo gets its own prefix", () => {
  const r = route("https://kevaso.com/provider-linode?go-get=1", mods);
  assert.match(r.body, /content="kevaso\.com\/provider-linode git https:\/\/github\.com\/dlebee\/kevaso-provider-linode"/);
});

test("go get on an unknown path is a 404, never someone else's repo", () => {
  for (const path of ["/", "/nope", "/corex", "/__proto__", "/constructor"]) {
    const r = route(`https://kevaso.com${path}?go-get=1`, mods);
    assert.deepEqual([r.kind, r.status], ["go-import", 404], path);
  }
});

test("browsers on a module path go to the repo", () => {
  assert.deepEqual(route("https://kevaso.com/core", mods), { kind: "redirect", location: "https://github.com/dlebee/kevaso" });
  assert.deepEqual(route("https://kevaso.com/core/api", mods), { kind: "redirect", location: "https://github.com/dlebee/kevaso/tree/main/api" });
});

test("everything else passes through to the site", () => {
  for (const url of ["https://kevaso.com/", "https://kevaso.com/about", "https://kevaso.com/core?go-get=0".replace("/core", "/blog")]) {
    assert.deepEqual(route(url, mods), { kind: "pass" }, url);
  }
});

test("without a site yet, the worker answers / itself and 404s the rest", async () => {
  const home = await worker.fetch(new Request("https://kevaso.com/"));
  assert.equal(home.status, 200);
  assert.match(await home.text(), /github\.com\/dlebee\/kevaso/);
  assert.equal((await worker.fetch(new Request("https://kevaso.com/about"))).status, 404);
});

test("the worker serves HTML the go command can parse", async () => {
  const res = await worker.fetch(new Request("https://kevaso.com/core/api?go-get=1"));
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /^text\/html/);
  assert.match(await res.text(), /go-import" content="kevaso\.com\/core git https:\/\/github\.com\/dlebee\/kevaso"/);
});
