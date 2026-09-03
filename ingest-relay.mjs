#!/usr/bin/env node
// Ingest relay client — a "dumb proxy" that runs on an IP class the public RH RPC does not
// rate-limit (a residential connection, a GitHub Actions runner, etc.), fetching eth_getLogs
// traffic on the pegproof-collector Worker's behalf while every bit of actual ingest logic
// (addresses, treasury topics, chunk sizing, the cursor itself, dedupe, classification, the
// atomic D1 write) stays entirely server-side. Rationale: RH RPC 429s Cloudflare Workers' shared egress IPs almost permanently,
// while the identical RPC works fine from here.
//
// Usage:
//   WORKER_URL=https://pegproof-collector.<subdomain>.workers.dev \
//   DEBUG_TRIGGER_TOKEN=<same ops secret /__tick and /__probe use> \
//   node ingest-relay.mjs [--tick]
//
// Env:
//   WORKER_URL           required — the deployed Worker's base URL.
//   DEBUG_TRIGGER_TOKEN  required — same ops bearer token as /__tick, /__probe, /__ingest*.
//   RPC_URL              default: https://rpc.mainnet.chain.robinhood.com
//   MAX_CHUNKS           default: 50 — caps how many <=6000-block chunks one run relays.
//   PACE_MS              default: 250 — pause between consecutive chain (RPC_URL) calls.
//
// --tick: once the main relay loop finishes NORMALLY (upToDate, noCursor, or MAX_CHUNKS
// reached — never after an abandoned/failed run, see main()'s doc comment), also POST /__tick
// with the same bearer token, so one invocation both catches the event cursor up AND runs the
// rest of a normal tick (snapshots, detectors, alerts).
//
// Node >=20, zero dependencies — only the platform's native fetch/process globals.

const WORKER_URL = process.env.WORKER_URL;
const TOKEN = process.env.DEBUG_TRIGGER_TOKEN;
const RPC_URL = process.env.RPC_URL || 'https://rpc.mainnet.chain.robinhood.com';
const MAX_CHUNKS = process.env.MAX_CHUNKS ? Number(process.env.MAX_CHUNKS) : 50;
const PACE_MS = process.env.PACE_MS ? Number(process.env.PACE_MS) : 250;
const DO_TICK = process.argv.includes('--tick');

if (!WORKER_URL || !TOKEN) {
  process.stderr.write('[ingest-relay] WORKER_URL and DEBUG_TRIGGER_TOKEN are required env vars\n');
  process.exit(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function workerUrl(path) {
  return WORKER_URL.replace(/\/$/, '') + path;
}

/**
 * One call against the worker's own guarded ops routes (`/__ingest/next`, `/__ingest`,
 * `/__tick`). Never retried here — a worker-side failure (network blip reaching the Worker
 * itself, a non-JSON body, etc.) propagates straight to `main()`'s top-level catch and abandons
 * the run; only the chain RPC calls in `rpcCall` below get the "one retry after 5s"
 * treatment, since those are the calls this whole relay exists to work around rate-limiting on.
 */
async function callWorker(path, init = {}) {
  const response = await fetch(workerUrl(path), {
    ...init,
    headers: { Authorization: `Bearer ${TOKEN}`, ...(init.headers ?? {}) },
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`worker ${path} returned non-JSON (status ${response.status}): ${text.slice(0, 200)}`);
  }
  return { status: response.status, body };
}

let chainCalledOnce = false;
/** Paces consecutive chain RPC calls PACE_MS apart — skips the wait before the very first chain
 * call of the whole run (nothing to pace against yet). */
async function pace() {
  if (chainCalledOnce) await sleep(PACE_MS);
  chainCalledOnce = true;
}

/**
 * A single raw JSON-RPC POST to RPC_URL. Throws on a non-2xx HTTP status (429 called out
 * explicitly in the message, since that's the failure mode this whole relay exists to route
 * around), a JSON-RPC error body, or a non-JSON response — `rpcCall` below is what applies the
 * documented retry policy on top of this.
 */
async function rpcCallOnce(method, params) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const text = await response.text();
  if (response.status === 429) {
    throw new Error(`${method}: HTTP 429 rate limited`);
  }
  if (!response.ok) {
    throw new Error(`${method}: HTTP ${response.status}: ${text.slice(0, 200)}`);
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${method}: non-JSON response: ${text.slice(0, 200)}`);
  }
  if (body.error) {
    throw new Error(`${method}: RPC error ${body.error.code}: ${body.error.message}`);
  }
  return body.result;
}

/**
 * One paced, retried chain RPC call: on failure, wait 5s and try exactly once more; a second
 * failure abandons the WHOLE run (thrown up through `fetchChunk`/the main loop to `main()`'s
 * top-level `.catch()`, which prints the message and exits 1) — never a third attempt, and this
 * one policy covers every failure shape (a plain 429, a different HTTP error, a JSON-RPC error
 * body, a network blip) alike — any failure shape gets the same single-retry treatment.
 */
async function rpcCall(method, params) {
  await pace();
  try {
    return await rpcCallOnce(method, params);
  } catch (e) {
    process.stderr.write(`[ingest-relay] ${method} failed (${e.message}), retrying in 5s...\n`);
    await sleep(5000);
    try {
      return await rpcCallOnce(method, params);
    } catch (e2) {
      throw new Error(`${method} failed twice — abandoning run: ${e2.message}`);
    }
  }
}

function toHex(decimalStr) {
  return '0x' + BigInt(decimalStr).toString(16);
}

/**
 * Fetches one chunk's raw logs for a `GET /__ingest/next` response (`next`): runs every query
 * in `next.queries` verbatim as `eth_getLogs` against `next.addresses`/`next.fromBlock`/
 * `next.toBlock` (server-decided — this client never invents its own range or filters), then
 * resolves `toBlock`'s hash via `eth_getBlockByNumber` — skipping that call entirely when
 * `toBlock` IS the anchor, whose hash was already handed to us in `next.anchor.hash` (mirrors
 * ingest.ts's own `fetchChunk`'s identical optimization). Query results are concatenated
 * as-is — no client-side dedupe; the worker's `writeChunk` does that (see the module doc
 * comments for why: a log matched by two of the 2-4 queries is expected and handled server-side).
 */
async function fetchChunk(next) {
  const fromHex = toHex(next.fromBlock);
  const toHexValue = toHex(next.toBlock);

  const logs = [];
  for (const topics of next.queries) {
    const result = await rpcCall('eth_getLogs', [
      { address: next.addresses, topics, fromBlock: fromHex, toBlock: toHexValue },
    ]);
    logs.push(...result);
  }

  const toBlockHash =
    next.toBlock === next.anchor.number
      ? next.anchor.hash
      : (await rpcCall('eth_getBlockByNumber', [toHexValue, false])).hash;

  return { logs, toBlockHash };
}

/**
 * Main relay loop, bounded at MAX_CHUNKS iterations (an iteration that gets a 409 stale response
 * still counts against this bound — see the doc comment at that branch below): GET
 * `/__ingest/next`, stop on `noCursor`/`upToDate`, otherwise fetch that chunk's logs and POST
 * them back, looping on a stale response rather than treating it as fatal.
 *
 * Only a thrown error (an abandoned chain RPC call, or any other unexpected failure) skips
 * straight past the `--tick` call and the summary print below, all the way to `main().catch()` —
 * a deliberate choice: `--tick` firing a real tick against a cursor this run failed to fully
 * advance would run detectors over a state this run itself couldn't validate as complete.
 */
async function main() {
  let chunksSent = 0;
  let totalInserted = 0;
  let lastCursor = null;
  let finalMessage = null;

  for (let i = 0; i < MAX_CHUNKS; i++) {
    const { status, body: next } = await callWorker('/__ingest/next');
    if (status !== 200) {
      throw new Error(`GET /__ingest/next returned ${status}: ${JSON.stringify(next)}`);
    }

    if (next.noCursor) {
      finalMessage = 'no cursor row yet — cursor initialization is the scheduled tick\'s job, not this relay\'s';
      break;
    }
    if (next.upToDate) {
      lastCursor = next.cursor;
      finalMessage = `up to date at cursor ${next.cursor} — nothing to relay`;
      break;
    }

    const { logs, toBlockHash } = await fetchChunk(next);

    const { status: postStatus, body: postResult } = await callWorker('/__ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fromBlock: next.fromBlock, toBlock: next.toBlock, toBlockHash, logs }),
    });

    if (postStatus === 409 && postResult.stale) {
      // Cursor moved out from under us (a concurrent scheduled tick, most likely) — re-GET
      // rather than abandon. Still counts as one of this run's MAX_CHUNKS iterations, which
      // bounds even a pathological repeated-stale scenario.
      process.stderr.write(`[ingest-relay] stale range (cursor now ${postResult.cursor}), re-fetching next range\n`);
      continue;
    }
    if (postStatus !== 200) {
      throw new Error(`POST /__ingest returned ${postStatus}: ${JSON.stringify(postResult)}`);
    }

    chunksSent += 1;
    totalInserted += postResult.inserted;
    lastCursor = postResult.cursor;
  }

  if (DO_TICK) {
    const { status, body } = await callWorker('/__tick', { method: 'POST' });
    process.stdout.write(`[ingest-relay] /__tick -> status ${status} ok=${body.ok} note="${body.note}"\n`);
  }

  if (finalMessage) process.stdout.write(`[ingest-relay] ${finalMessage}\n`);
  process.stdout.write(
    `[ingest-relay] summary: chunks sent=${chunksSent} events inserted=${totalInserted} final cursor=${lastCursor ?? 'n/a'}\n`
  );
}

main().catch((e) => {
  process.stderr.write(`[ingest-relay] ${e.message}\n`);
  process.exit(1);
});
