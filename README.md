# pegproof-ops

Operational relay for the pegproof collector (an issuance observatory for
tokenized stocks on Robinhood Chain).

The collector runs as a Cloudflare Worker, but the chain's public RPC
rate-limits Cloudflare's shared egress IPs almost permanently, and the
account's cron triggers do not fire. This repo works around both from a
GitHub Actions runner, every 10 minutes:

1. `ingest-relay.mjs` asks the Worker what block range and log queries it
   needs (`GET /__ingest/next`), fetches them from the chain's public RPC
   (runner IPs are not rate-limited), and POSTs the raw logs back
   (`POST /__ingest`). Every bit of real logic — addresses, chunk sizing,
   dedupe, classification, cursor, atomic writes — stays server-side; this
   client is a dumb proxy.
2. With `--tick` it then POSTs `/__tick`, running the rest of a normal
   collector tick (snapshots, detectors, alerts).

Both endpoints require a bearer token, supplied as the
`PEGPROOF_TRIGGER_TOKEN` repository secret. Nothing in this repo is
sensitive on its own; a run without the secret does nothing.

Run it anywhere with Node >= 20:

```sh
WORKER_URL=https://pegproof-collector.xplowdiaka.workers.dev \
DEBUG_TRIGGER_TOKEN=<token> \
node ingest-relay.mjs --tick
```
