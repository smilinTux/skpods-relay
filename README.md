# skpods-relay

A small Cloudflare Worker relay for SKPods Chat. It pushes "something changed at URL X" pings between participants
so clients can refetch from their Solid pods sooner. It never carries message bodies, and Pod Chat works without it.

Identity comes only from a verified Solid-OIDC DPoP-bound access token plus a fresh DPoP proof.

Licensed under the Apache License, Version 2.0. See LICENSE.
