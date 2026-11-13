// kvo ui: a terminal (a WebSocket to kvo, which holds the API session) and a file explorer.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const status = (text, bad) => { $("status").textContent = text; $("status").classList.toggle("bad", !!bad); };

  // ── terminal ─────────────────────────────────────────────────────────
  const term = new Terminal({ cursorBlink: true, fontFamily: "ui-monospace, Menlo, Consolas, monospace", fontSize: 13,
    theme: { background: "#10131a" }, scrollback: 5000 });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("term"));
  fit.fit();
  let ws = null;
  const enc = new TextEncoder();

  function connect() {
    $("reconnect").hidden = true;
    const url = "ws://" + location.host + "/ws/terminal?rows=" + term.rows + "&cols=" + term.cols;
    ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => { status("connected"); term.focus(); };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") { term.write(new Uint8Array(ev.data)); return; }
      const m = JSON.parse(ev.data);
      if (m.error) { term.write("\r\n\x1b[31m" + m.error + "\x1b[0m\r\n"); status("error", true); }
      if (m.exit !== undefined) { term.write("\r\n[the shell exited with " + m.exit + "]\r\n"); status("shell exited"); }
    };
    ws.onclose = () => { $("reconnect").hidden = false; if ($("status").textContent === "connected") status("disconnected", true); };
  }
  term.onData((d) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d)); });
  term.onBinary((d) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(Uint8Array.from(d, (c) => c.charCodeAt(0))); });
  term.onResize(({ rows, cols }) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ resize: [rows, cols] })); });
  new ResizeObserver(() => fit.fit()).observe($("term"));
  $("reconnect").onclick = () => { term.reset(); connect(); };

  // ── files ────────────────────────────────────────────────────────────
  let cwd = "/";
  const join = (dir, name) => (dir.endsWith("/") ? dir : dir + "/") + name;
  const parent = (p) => { const i = p.replace(/\/+$/, "").lastIndexOf("/"); return i <= 0 ? "/" : p.slice(0, i); };
  const size = (n) => n < 1024 ? n + " B" : n < 1 << 20 ? (n / 1024).toFixed(1) + " KiB" : n < 1 << 30 ? (n / (1 << 20)).toFixed(1) + " MiB" : (n / (1 << 30)).toFixed(1) + " GiB";
  function message(text, ok) { const m = $("message"); m.hidden = !text; m.textContent = text || ""; m.classList.toggle("ok", !!ok); }
  function download(p) { const a = document.createElement("a"); a.href = "/api/download?path=" + encodeURIComponent(p); a.download = ""; a.click(); }

  async function list(p) {
    message("");
    const r = await fetch("/api/list?path=" + encodeURIComponent(p));
    if (!r.ok) { message(await r.text()); return; }
    const data = await r.json();
    cwd = data.path; $("path").value = cwd;
    const rows = data.entries.slice().sort((a, b) => (a.type === "dir") === (b.type === "dir") ? a.name.localeCompare(b.name) : a.type === "dir" ? -1 : 1);
    const body = $("entries");
    body.replaceChildren();
    for (const e of rows) {
      const tr = document.createElement("tr");
      const name = document.createElement("td"); name.className = "name";
      const a = document.createElement("a");
      a.textContent = e.name + (e.type === "dir" ? "/" : "") + (e.type === "link" ? " → " + e.target : "");
      a.title = e.mode;
      const full = join(cwd, e.name);
      if (e.type === "dir" || e.type === "link") a.onclick = () => list(full); else if (e.type === "file") a.onclick = () => download(full); else a.className = "dim";
      name.append(a);
      const sz = document.createElement("td"); sz.className = "num dim"; sz.textContent = e.type === "file" ? size(e.size) : "";
      const t = document.createElement("td"); t.className = "dim"; t.textContent = e.time;
      const act = document.createElement("td");
      if (e.type === "dir") { const b = document.createElement("a"); b.textContent = ".tar"; b.title = "Download this folder as a tar"; b.onclick = () => download(full); act.append(b); }
      tr.append(name, sz, t, act);
      body.append(tr);
    }
    if (!rows.length) { const tr = document.createElement("tr"); const td = document.createElement("td"); td.colSpan = 4; td.className = "dim"; td.textContent = "empty"; tr.append(td); body.append(tr); }
  }

  $("up").onclick = () => list(parent(cwd));
  $("refresh").onclick = () => list(cwd);
  $("goto").onsubmit = (ev) => { ev.preventDefault(); list($("path").value.trim() || "/"); };
  $("upload").onchange = async (ev) => {
    const files = Array.from(ev.target.files); ev.target.value = "";
    for (const f of files) {
      message("uploading " + f.name + "…", true);
      const r = await fetch("/api/upload?dir=" + encodeURIComponent(cwd) + "&name=" + encodeURIComponent(f.name), { method: "POST", body: f });
      if (!r.ok) { message(f.name + ": " + await r.text()); return; }
    }
    await list(cwd);
    message(files.length + " uploaded", true);
  };

  fetch("/api/info").then((r) => r.json()).then((i) => { $("silo").textContent = "silo " + i.namespace + "/" + i.name; document.title = "kvo ui · " + i.name; });
  connect();
  list("/");
})();
