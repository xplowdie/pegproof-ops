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
// rest of a normal tick (snapshots, detectors, alerts) — GATED by the tick-lag guard (opsfix,
// Val A1) below.
//
// TICK-LAG GUARD (opsfix, Val A1 — production incident): gaps.ts's assessStall escalates a
// stall to a PERMANENT 'gap-declared' once the cursor falls STALL_GAP_CEILING_BLOCKS=1,500,000
// blocks behind anchor (see gaps.ts's own doc comment). A sustained chain-RPC outage (>43h, per
// this relay's own observed 429 patterns) combined with ticks that keep firing regardless would
// walk the cursor's lag straight past that ceiling and declare the span permanently lost. This
// guard reads the CURRENT anchor/cursor gap right after the relay loop finishes (a dedicated,
// final `GET /__ingest/next` call — see evaluateTickLagGuard's own doc comment for why a fresh
// read, not the loop's own earlier reads, is used) and, if the lag already exceeds
// TICK_SKIP_LAG_CEILING_BLOCKS, skips the `--tick` POST entirely rather than risk being the run
// that pushes it over gaps.ts's own (larger) ceiling. PARTIAL GUARD, BY DESIGN (documented, not
// hidden): this only covers ticks fired THROUGH THIS RELAY. TWO OTHER paths fire ticks on this
// Worker entirely independently of anything this script decides, both unguarded by this check:
// Cloudflare's own cron trigger, AND the separately-deployed `pinger` worker (its own cron,
// unconditional POST /__tick, no lag awareness at all — see the SDD ledger's post-A review M2
// finding for how it was rediscovered: a forgotten fixture from 2 Sep, still live, still ticking).
// This guard narrows the risk window, it does not close it — a genuine fix (uniform,
// server-side lag awareness across every tick trigger) is scheduled for Plan 3/C1, not here.
//
// Node >=20, zero dependencies — only the platform's native fetch/process globals.

import { fileURLToPath } from 'node:url';
import path from 'node:path';

const WORKER_URL = process.env.WORKER_URL;
const TOKEN = process.env.DEBUG_TRIGGER_TOKEN;
const RPC_URL = process.env.RPC_URL || 'https://rpc.mainnet.chain.robinhood.com';
const MAX_CHUNKS = process.env.MAX_CHUNKS ? Number(process.env.MAX_CHUNKS) : 50;
const PACE_MS = process.env.PACE_MS ? Number(process.env.PACE_MS) : 250;

/**
 * U3 (Val C2, 2026-09-10 — WAF on GitHub Actions runners): RH RPC intermittently serves a
 * Cloudflare challenge page (HTTP 403 "Just a moment...") to GH Actions runner IPs specifically —
 * observed correlated with a missing/generic default User-Agent (python's `urllib` default UA was
 * outright blocked; Node's own `fetch` default UA gets through today, but is one CF ruleset tweak
 * away from the same fate). Cheap mitigation: an explicit, identifying UA is more stable against
 * WAF heuristics than relying on whatever the runtime's default happens to be. This does NOT
 * replace the existing safety net — a persistent 403 (WAF or otherwise) still falls through
 * `rpcCallOnce`'s generic `!response.ok` branch into `rpcCall`'s ordinary retry-then-soft-fail
 * path (see that function's own doc comment) exactly as before; this only reduces how OFTEN that
 * path has to be exercised for THIS specific cause.
 */
const RELAY_USER_AGENT = 'pegproof-relay/1.0 (+github-actions)';
const DO_TICK = process.argv.includes('--tick');

/**
 * Deliberately SMALLER than gaps.ts's own STALL_GAP_CEILING_BLOCKS (1,500,000) — this guard is
 * meant to trip BEFORE the worker's own permanent-gap ceiling is at risk, not at the exact same
 * line. 1,000,000 blocks leaves real headroom (~500,000 blocks, comfortably more than one more
 * relay run's worth of catch-up) between "this relay declines to tick" and "the worker itself
 * would declare the span permanently lost".
 */
export const TICK_SKIP_LAG_CEILING_BLOCKS = 1_000_000n;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Pure decision, given the exact JSON body `GET /__ingest/next` returns (index.ts's
 * `handleIngestNext`): should firing `--tick` right now be skipped to avoid risking gaps.ts's
 * permanent gap-declaration ceiling? `noCursor` (ingest has never run — nothing to gate; cursor
 * initialization is the tick's own bootstrap job) and `upToDate: true` (cursor already at/past
 * anchor — zero lag by definition) both mean "nothing to gate here", regardless of lag — only
 * the `upToDate: false` shape carries `anchor.number`/`fromBlock` (decimal strings, per
 * `handleIngestNext`'s own wire format), from which `cursor = fromBlock - 1n` (mirrors this
 * script's `fetchChunk`/`relayLoop` treatment of the same fields elsewhere in this file).
 */
export function evaluateTickLagGuard(nextResponseBody) {
  if (nextResponseBody.noCursor || nextResponseBody.upToDate) {
    return { skip: false, lag: 0n };
  }
  const anchorNumber = BigInt(nextResponseBody.anchor.number);
  const cursor = BigInt(nextResponseBody.fromBlock) - 1n;
  const lag = anchorNumber - cursor;
  return { skip: lag > TICK_SKIP_LAG_CEILING_BLOCKS, lag };
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
    headers: { 'Content-Type': 'application/json', 'User-Agent': RELAY_USER_AGENT },
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
      // Marked as a SOFT failure: upstream chain-RPC throttling/unavailability is an expected
      // environmental condition, not a relay defect — main() turns it into exit 0 (with the
      // --tick still fired and a partial summary printed) so scheduled runners (GitHub Actions)
      // don't paint the run red and email the operator for a condition the system already
      // handles honestly (the worker's stall bookkeeping is the durable record; the next
      // scheduled run simply retries). Worker-side failures stay HARD (exit 1) — those mean
      // the relay itself couldn't do its job for a reason that needs eyes.
      const err = new Error(`${method} failed twice — abandoning chunk loop: ${e2.message}`);
      err.chainSoftFail = true;
      throw err;
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
 *
 * C3 (registry growth discovery): `next.discoveryQuery`, when present, is run as ONE MORE
 * `eth_getLogs` call — deliberately WITHOUT an `address` field at all (unlike every query in
 * `next.queries`, which are always scoped to `next.addresses`) — the whole point being to match
 * mint events from contracts this worker doesn't track yet. Its logs are concatenated into the
 * SAME `logs` array and POSTed back like everything else; the worker's own `/__ingest` handler
 * (index.ts's `recordDiscoveryCandidates`) is what tells an unknown-address log apart from a
 * known-registry one — this client has no registry awareness of its own, by design.
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
  if (next.discoveryQuery) {
    const result = await rpcCall('eth_getLogs', [
      { topics: next.discoveryQuery.topics, fromBlock: fromHex, toBlock: toHexValue },
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
 * Failure semantics (revised after a week of scheduled-runner operation): a chain-RPC
 * abandonment (`chainSoftFail`, see `rpcCall`) stops the chunk loop but is NOT a run failure —
 * the `--tick` still fires (a tick is self-contained: its detectors process only `ingest_dirty`
 * markers for chunks that actually landed, so a partially-advanced cursor is a perfectly valid
 * state to tick over — the worker does exactly that on its own cron ticks too), the partial
 * summary still prints, and the process exits 0. Only worker-side failures (a non-200 from
 * `/__ingest*` that isn't a stale-409, `/__tick` unreachable, auth) escape to `main().catch()`
 * and exit 1 — those are the ones a red run/notification should exist for.
 */
async function main() {
  if (!WORKER_URL || !TOKEN) {
    process.stderr.write('[ingest-relay] WORKER_URL and DEBUG_TRIGGER_TOKEN are required env vars\n');
    process.exit(1);
  }

  let chunksSent = 0;
  let totalInserted = 0;
  let lastCursor = null;
  let finalMessage = null;

  try {
    await relayLoop();
  } catch (e) {
    if (!e.chainSoftFail) throw e;
    finalMessage = `soft-fail (chain RPC): ${e.message} — next scheduled run retries`;
  }

  if (DO_TICK) {
    // Dedicated, fresh GET (opsfix, Val A1) — deliberately NOT reusing whichever GET the loop
    // above last happened to make: that response may be a whole run's worth of chunks stale by
    // now, and this call is to our OWN worker (never the rate-limited chain RPC_URL), so the
    // extra round trip costs nothing worth optimizing away.
    const { status: guardStatus, body: guardBody } = await callWorker('/__ingest/next');
    if (guardStatus !== 200) {
      throw new Error(`GET /__ingest/next (tick-lag guard) returned ${guardStatus}: ${JSON.stringify(guardBody)}`);
    }
    const guard = evaluateTickLagGuard(guardBody);
    if (guard.skip) {
      process.stdout.write(
        `[ingest-relay] tick skipped: cursor lags anchor by ${guard.lag} blocks — avoiding gap declaration ` +
          `(this relay's own ceiling is ${TICK_SKIP_LAG_CEILING_BLOCKS} blocks; see this file's TICK-LAG GUARD ` +
          `doc comment). NOTE: this guard only covers ticks fired through this relay — Cloudflare's own cron ` +
          `trigger and the separate pinger worker both still fire scheduled ticks on this Worker independently.\n`
      );
    } else {
      const { status, body } = await callWorker('/__tick', { method: 'POST' });
      process.stdout.write(`[ingest-relay] /__tick -> status ${status} ok=${body.ok} note="${body.note}"\n`);
    }
  }

  if (finalMessage) process.stdout.write(`[ingest-relay] ${finalMessage}\n`);
  process.stdout.write(
    `[ingest-relay] summary: chunks sent=${chunksSent} events inserted=${totalInserted} final cursor=${lastCursor ?? 'n/a'}\n`
  );

  async function relayLoop() {
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
  }
}

// Only run main() when executed directly (`node ingest-relay.mjs ...`) — not when imported for
// its pure functions (evaluateTickLagGuard) by tests. Same guard, same reasoning, as
// attribute-emission.mjs's identical pattern.
if (path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1] ?? '')) {
  main().catch((e) => {
    process.stderr.write(`[ingest-relay] ${e.message}\n`);
    process.exit(1);
  });
}
