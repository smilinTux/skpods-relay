# skpods-relay

A small Cloudflare Worker that pushes "something changed at URL X" pings between the participants of an SKPods Chat
conversation, so their clients re-read the Solid pods sooner instead of waiting for the next poll.

The relay is an accelerator, never a dependency. It carries no message bodies, file contents or titles, and a ping is
only a hint: the client re-reads the pod it points at and trusts only what the pod returns. With the relay down, unset
or out of free quota, Pod Chat polls exactly as it does without one.

It has two parts, both Durable Objects with SQLite storage:

* **Room**, one per room id (`GET /v1/room/:id`, a WebSocket). Members send pings and typing frames; the room relays
  them to the other connected members, stamped with the sender's verified WebID.
* **Mailbox**, one per WebID (`GET /v1/me?w=<sha256 hex of the WebID>`, a WebSocket). When a member is not connected
  to a room, the room forwards the ping to that member's mailbox, which holds it (at most 500 items, 7 days) and
  hands the queue over the next time its owner connects.

Everything else, including `/internal/*`, is 404 from the outside. Rooms reach mailboxes only through Durable Object
stubs.

## Wire protocol

Version 1, sent as `"v":1` in the auth frame. The full contract (frames, error and close codes, limits, trust rules)
is [docs/CHAT-PROTOCOL.md](https://github.com/smilinTux/skpods/blob/main/docs/CHAT-PROTOCOL.md) in the skpods
repository. In short:

1. The client opens the socket and, within 5 s, sends `{"t":"auth","v":1,"token":"...","proof":"..."}`: a
   Solid-OIDC DPoP-bound access token and a fresh DPoP proof for `GET` on the socket URL (scheme `https`, no query).
2. The relay answers `{"t":"ready","webid":"..."}` with the WebID it verified, or an `error` frame and a 44xx close.
3. On a room, the client then sends `{"t":"ping","kind":"message","url":"https://..."}` and `{"t":"typing"}`. On the
   mailbox it only receives `queued` frames.

`tests/relay-v1.fixtures.json` is a copy of the shared frame fixtures in the skpods `protocol/` folder; both the relay
and the Pod Chat client test against them.

## Build and test

Needs a Rust toolchain with the `wasm32-unknown-unknown` target, `worker-build` (`cargo install worker-build`) and
Node.js for `wrangler`.

```sh
cargo test                                   # unit tests on the host
cargo clippy --all-targets                   # native lints
cargo clippy --target wasm32-unknown-unknown # lints for the Worker build
worker-build --release                       # builds build/ (the Worker bundle and its wasm)
npx wrangler dev --port 8787                 # local relay on ws://127.0.0.1:8787
```

`.cargo/config.toml` selects the `wasm_js` backend of `getrandom` (a dependency of the Turtle parser) for the wasm
build; nothing else is needed.

The skpods repository has a live integration test that drives a local relay with real pod logins
(`SKP_RELAY_URL=ws://127.0.0.1:8787`, see its Pod Chat README).

## Deploy

The relay is built to run on the Cloudflare Workers **Free** plan with SQLite-backed Durable Objects only, at no cost.
Check the current Free limits before you deploy (at the time of writing: 100,000 requests a day, 100,000 SQLite rows
written a day, 1 GB per object, 5 GB per account). Hitting a limit only makes clients fall back to polling.

```sh
npx wrangler login
npx wrangler deploy
```

`wrangler.toml` declares the `ROOM` and `MAILBOX` bindings and the `v1` migration that creates both classes. There are
no secrets or environment variables to set. Point Pod Chat at the deployed URL with `VITE_RELAY_URL=wss://<host>`.

## Security model

**What is verified.** Identity comes only from a verified token plus proof; a claimed WebID is never trusted. For every
auth frame the relay checks:

* the access token: an asymmetric signature (RS256 or ES256) against the issuer's published JWKS, found through the
  issuer's OpenID configuration, and `exp`;
* that the issuer is listed as a `solid:oidcIssuer` of the WebID in its profile document. The profile is parsed as
  Turtle, and only triples whose subject is exactly the WebID count, so text in literals or comments, or statements
  about other subjects in the same document, cannot add an issuer;
* the DPoP proof: signed by the key the token binds in `cnf.jkt`, `htm` GET, `htu` equal to the socket URL, `ath`
  matching the token, `iat` within 60 s of the relay clock, and a `jti` not seen before on that object;
* on a mailbox, that `sha256(verified WebID)` equals the mailbox name `w`.

Any failure is `auth_failed` (close 4401) and the socket never gets `ready`. Profile, discovery and JWKS documents are
fetched over https only, with no redirects, a 5 s deadline and a 512 KB cap, and cached for 600 s.

**What is never logged.** Logs carry a component tag, counts and error codes only: never access tokens, proofs, WebIDs,
ping URLs or room ids. `wrangler.toml` turns on no persistent log storage; if you enable Workers Logs, keep retention
at 24 hours or less.

**Limits.**

| Limit | Value |
|---|---|
| Client frame size | 4096 UTF-8 bytes (`too_large` 4413) |
| Frames per socket | 60 per rolling 60 s (`rate_limited` 4429) |
| Auth verifications per object | 30 per rolling 60 s (`rate_limited` 4429), checked before any fetch |
| Time to send `auth` | 5 s; 20 s from open while a verification is still running (`auth_failed` 4401) |
| Members per room | 50 (`room_full` 4403) |
| Verified WebID | 512 UTF-8 bytes (`auth_failed` 4401) |
| `Host` header | 255 bytes (HTTP 400) |
| Mailbox | 500 items, 7 days, repeats of one (room, URL, kind) collapsed |
| Mailbox forwards | at most one per (room, member) per 30 s |

An internal failure (storage, quota) closes the socket with 1011. An object that ends up holding nothing worth keeping
(a room nobody was admitted to, an empty mailbox) drops all of its storage once its replay and rate-limit rows have
aged out.

**What a room id gives.** Room ids are 128-bit random values stored only in the conversation descriptor, which only
participants can read. Someone who learns one can join (within the 50 member cap) but only receives "something changed
at URL X" hints for URLs they cannot read.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
