# ADR 0007: The HTML pane bundle format

**Status:** accepted · **Date:** 2026-11-13

## Context

An HTML pane (design §10.1) is a bundle uploaded once by its silo (`pane-bundle` on the broker
channel, named by its sha256 digest) plus small data updates. The control plane keeps the bundle as
an opaque blob: it weighs and hashes it and serves it only as a download. The macOS panes app
(`apps/panes`, `PaneBundle.swift`) unpacks it into a folder of the pane's own and renders it in a
sealed web view. The app accepted a ustar archive holding `index.html`, or a single HTML file, but
nothing said so on the Kevaso side: `kvo-guest pane html --bundle` took any file.

## Decision

1. **A bundle is one of two things.** A POSIX **ustar** archive (magic `ustar` at offset 257) of
   regular files and folders only, with `index.html` at its top; or **anything else**, taken as the
   pane's single `index.html`, byte for byte.
2. **Archive rules** (the app refuses the whole bundle otherwise):
   - entry names are relative: no leading `/`, no empty, `.` or `..` part, no `\`, no control
     characters, under 256 bytes (ustar's name and prefix fields; a leading `./` is dropped);
   - no links, devices or FIFOs; no pax or GNU extension headers (the app reads plain ustar);
   - no file twice; at most **256 files** unpacking to at most **8 MiB**.
3. **At most 512 KiB** as uploaded, either form (the control plane's default limit, `panes.Limits`).
4. **`kvo-guest pane html NAME --bundle PATH`** builds or checks it in the silo:
   - a folder is packed deterministically: names in sorted order, folders as their own entries,
     times at the epoch, uid/gid 0 and no owner names, modes 0644 (files) and 0755 (folders);
     links and special files are refused, not followed. The same files always give the same
     digest, so an unchanged pane is never uploaded as a new bundle;
   - a ustar file is checked by the rules above before it's sent;
   - any other file is sent as it is (a single HTML page).
5. **The control plane never opens a bundle.** The format lives in `api/v1` (the doc comment on
   `PaneBundleMaxBytes`) for the two ends that do: the silo that builds it and the app that renders
   it. No server-side parsing is to be added: a bundle is untrusted content for one viewer, and the
   server staying blind to it keeps it from being a renderer, a scanner or a parser of it.

## Consequences

- One definition for both ends; the app's limits (`PaneBundle.maxBytes`, `maxFiles`,
  `maxUnpacked`) match `v1.PaneBundleMax*`, and a change to either side must change both.
- A bundle the app would refuse is caught in the silo, with the reason, for archives `kvo-guest`
  builds or checks. One uploaded some other way (a raw broker call) is still refused only when a
  person opens the pane.
- No compression: the 512 KiB limit is on the archive as sent. A pane that needs more should load
  less, not be compressed.
