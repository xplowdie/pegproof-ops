#!/usr/bin/env node
// Ingest relay client — a "dumb proxy" that runs on an IP class the public RH RPC does not
// rate-limit (a residential connection, a GitHub Actions runner, etc.), fetching eth_getLogs
// traffic on the pegproof-collector Worker's behalf while every bit of actual ingest logic
// (addresses, treasury topics, chunk sizing, the cursor itself, dedupe, classification, the
// atomic D1 write) stays entirely server-side. See the module doc comments below for the full
// architecture rationale: RH RPC 429s Cloudflare Workers' shared egress IPs almost permanently,
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
// rest of a normal tick (snapshots, detectors, alerts) — fired UNCONDITIONALLY (Plan 3a Task 8):
// the worker's own `runTick` now carries the uniform ingest lag guard this relay used to apply
// only to itself (its old TICK_SKIP_LAG_CEILING_BLOCKS/evaluateTickLagGuard, removed here — see
// collector/src/index.ts's TICK_INGEST_LAG_CEILING_BLOCKS doc comment for the full replacement
// rationale). That old guard was PARTIAL by construction — it only covered ticks fired through
// THIS relay, never Cloudflare's own cron trigger or the (now-retirable) `pinger` worker's cron —
// so moving the check server-side, where every tick source shares it, is a strict improvement,
// not a relocation of an already-complete guard. This relay no longer needs to make its own
// judgment call about whether firing `--tick` is safe; the worker decides.
//
// Node >=20, zero dependencies — only the platform's native fetch/process globals.

import { fileURLToPath } from 'node:url';
import path from 'node:path';

const WORKER_URL = process.env.WORKER_URL;
const TOKEN = process.env.DEBUG_TRIGGER_TOKEN;
// Exported (code-review finding 6 testability): WORKER_URL/RPC_URL/TOKEN are captured from
// process.env at module-load time — a test that needs a specific WORKER_URL/RPC_URL must set the
// env var(s) BEFORE this module is first imported (a dynamic `await import(...)` after setting
// `process.env.*`, in its own test file so vitest's per-file module isolation gives it a fresh
// module instance — see registry/test/ingest-relay-client.test.ts). Tests that only need the
// DEFAULT RPC_URL (no WORKER_URL/TOKEN at all) can use a plain static import instead, matching
// this file's other pure-function tests (e.g. `isTransientRpcErrorMessage`, `rpcCall`).
export const RPC_URL = process.env.RPC_URL || 'https://rpc.mainnet.chain.robinhood.com';
const MAX_CHUNKS = process.env.MAX_CHUNKS ? Number(process.env.MAX_CHUNKS) : 50;
const PACE_MS = process.env.PACE_MS ? Number(process.env.PACE_MS) : 250;

/**
 * (2026-09-10 — WAF on GitHub Actions runners): RH RPC intermittently serves a
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
 * Code-review finding 6: distinguishes a JSON-RPC error body that is a genuinely TRANSIENT
 * condition (some providers report rate-limiting/capacity issues this way instead of an HTTP 429)
 * from a DETERMINISTIC one — the default for everything else a JSON-RPC error body can mean
 * (a malformed request, an unsupported method, or — the case this finding exists for — a query
 * whose RANGE is simply too wide, e.g. "logs matched exceeds 10000"). A deterministic error
 * retried unchanged fails unchanged; only messages that look like a transient capacity/rate signal
 * get the transient classification.
 */
export function isTransientRpcErrorMessage(message) {
  return /rate.?limit|too many requests|capacit(y|ies)|overloaded|temporarily unavailable|try again/i.test(message ?? '');
}

/**
 * Code-review finding 6: identifies the ONE specific deterministic shape this file has a real
 * remedy for — an `eth_getLogs` range with too many matching logs for the provider to return in a
 * single call (the exact production example: "logs matched exceeds 10000"). Distinct from
 * `isTransientRpcErrorMessage` — this is still a DETERMINISTIC failure (retrying the identical
 * range fails identically), but `fetchChunk`'s halving retry (see its own doc comment) can turn it
 * into a smaller range that might succeed, unlike every other deterministic error, which just
 * hard-fails with no retry at all.
 */
export function isTooManyLogsMessage(message) {
  return /logs matched exceeds|query returned more than|exceeded the (log|result) (count|limit)|too many (logs|results)/i.test(
    message ?? ''
  );
}

/**
 * A single raw JSON-RPC POST to RPC_URL. Throws on a network-level failure, a non-2xx HTTP
 * status, a JSON-RPC error body, or a non-JSON response — every thrown error carries a
 * `transient` boolean (code-review finding 6) so `rpcCall` below can apply the right policy
 * instead of treating every failure alike:
 *   - network error (fetch() itself threw — DNS, connection reset, timeout): transient.
 *   - HTTP 429, 403 (RH RPC's own WAF intermittently challenges GH Actions runner IPs this way —
 *     see this file's own U3 doc comment; NOT the query's fault), or 5xx: transient.
 *   - any OTHER non-2xx status (400, 404, ...): deterministic — the request itself, not the
 *     server's load, is the problem.
 *   - non-JSON body despite a 2xx status: transient (an edge/proxy glitch is more likely than a
 *     genuinely broken endpoint for an otherwise-valid request).
 *   - a JSON-RPC error body: transient only if `isTransientRpcErrorMessage` matches; deterministic
 *     otherwise. A deterministic `eth_getLogs` "too many logs" error additionally carries
 *     `tooManyLogsError: true` (see `isTooManyLogsMessage`) so `fetchChunk` can attempt its
 *     halving retry before this becomes fatal.
 */
async function rpcCallOnce(method, params) {
  let response;
  try {
    response = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': RELAY_USER_AGENT },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
  } catch (e) {
    const err = new Error(`${method}: network error: ${e instanceof Error ? e.message : String(e)}`);
    err.transient = true;
    throw err;
  }
  const text = await response.text();
  if (response.status === 429 || response.status === 403 || response.status >= 500) {
    const err = new Error(`${method}: HTTP ${response.status}${response.status === 429 ? ' rate limited' : ''}: ${text.slice(0, 200)}`);
    err.transient = true;
    throw err;
  }
  if (!response.ok) {
    const err = new Error(`${method}: HTTP ${response.status}: ${text.slice(0, 200)}`);
    err.transient = false;
    throw err;
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    const err = new Error(`${method}: non-JSON response: ${text.slice(0, 200)}`);
    err.transient = true;
    throw err;
  }
  if (body.error) {
    const err = new Error(`${method}: RPC error ${body.error.code}: ${body.error.message}`);
    err.transient = isTransientRpcErrorMessage(body.error.message);
    if (!err.transient && method === 'eth_getLogs' && isTooManyLogsMessage(body.error.message)) {
      err.tooManyLogsError = true;
    }
    throw err;
  }
  return body.result;
}

/**
 * One paced chain RPC call. Code-review finding 6 (REPLACES the old "wait 5s, retry once, any
 * second failure is soft" policy, which treated a DETERMINISTIC failure — e.g. an `eth_getLogs`
 * range with "too many logs matched" — exactly like a transient one: soft-failed, exit 0, green
 * CI, and the NEXT scheduled run retries the SAME range and hits the SAME deterministic error
 * again, forever, walking the cursor's lag toward gaps.ts's own permanent-gap ceiling with no
 * operator ever seeing a red run):
 *   - TRANSIENT failure (`rpcCallOnce`'s own classification): wait 5s, try exactly once more —
 *     unchanged from before. If the retry ALSO fails, it is re-classified independently (a
 *     transient-then-deterministic pair is possible, e.g. a 429 followed by a genuinely malformed
 *     response) — only a transient-then-transient pair is soft-failed (`chainSoftFail`, main()
 *     turns it into exit 0 with a partial summary — an expected, self-healing environmental
 *     condition, not a relay defect).
 *   - DETERMINISTIC failure: no "wait 5s and try the identical call again" step at all — retrying
 *     an impossible query changes nothing, so it propagates on the FIRST attempt already. This
 *     surfaces as a HARD failure (main()'s top-level catch exits 1 with a clear message) UNLESS
 *     the caller (`fetchChunk`) has its own halving retry for the specific `tooManyLogsError`
 *     shape — see that function's own doc comment.
 */
export async function rpcCall(method, params) {
  await pace();
  try {
    return await rpcCallOnce(method, params);
  } catch (e) {
    if (!e.transient) throw e; // deterministic -- no pointless identical retry, propagate immediately
    process.stderr.write(`[ingest-relay] ${method} failed (${e.message}), retrying in 5s...\n`);
    await sleep(5000);
    try {
      return await rpcCallOnce(method, params);
    } catch (e2) {
      if (!e2.transient) throw e2; // deterministic on the retry -- still hard, never softened
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
 * Runs every query in `next.queries` verbatim as `eth_getLogs` against `next.addresses`/
 * `next.fromBlock`/`next.toBlock` (server-decided — this client never invents its own range or
 * filters), then resolves `toBlock`'s hash via `eth_getBlockByNumber` — skipping that call
 * entirely when `toBlock` IS the anchor, whose hash was already handed to us in
 * `next.anchor.hash` (mirrors ingest.ts's own `fetchChunk`'s identical optimization). Query
 * results are concatenated as-is — no client-side dedupe; the worker's `writeChunk` does that
 * (see the module doc comments for why: a log matched by two of the 2-4 queries is expected
 * and handled server-side).
 *
 * C3 (registry growth discovery): `next.discoveryQuery`, when present, is run as ONE MORE
 * `eth_getLogs` call — deliberately WITHOUT an `address` field at all (unlike every query in
 * `next.queries`, which are always scoped to `next.addresses`) — the whole point being to match
 * mint events from contracts this worker doesn't track yet. Its logs are concatenated into the
 * SAME `logs` array and POSTed back like everything else; the worker's own `/__ingest` handler
 * (index.ts's `recordDiscoveryCandidates`) is what tells an unknown-address log apart from a
 * known-registry one — this client has no registry awareness of its own, by design.
 *
 * A `tooManyLogsError` thrown by any `eth_getLogs` call here propagates uncaught — `fetchChunk`
 * (below) is what catches it and attempts the halving retry; this function itself never retries.
 */
async function fetchChunkOnce(next) {
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
 * HALVING RETRY (code-review finding 6): wraps `fetchChunkOnce` to catch a deterministic
 * `eth_getLogs` "too many logs" error (`tooManyLogsError` — see `rpcCallOnce`'s own doc comment)
 * and retry EXACTLY ONCE against a NEW, HALVED chunk fetched from the server: `GET
 * /__ingest/next?max_blocks=N`, `N` = half this chunk's own block count. The SERVER, not this
 * client, owns chunk-size decisions (this file's own module doc comment: "the source of truth …
 * stays entirely server-side"), so "retry smaller" means asking the server for a smaller chunk —
 * never locally slicing `next.toBlock`. Every other error (any error without `tooManyLogsError`,
 * including a run of transient failures that became `chainSoftFail`, or ANY other deterministic
 * failure) propagates unchanged — this mechanism exists to absorb exactly one occurrence of a
 * too-wide default chunk size, not to generically retry every failure shape.
 *
 * Returns `next` alongside `logs`/`toBlockHash` because a halving retry fetches a DIFFERENT range
 * than the one passed in — the caller (`relayLoop`) must POST the range that was ACTUALLY
 * fetched, never the original request.
 */
export async function fetchChunk(next) {
  try {
    const result = await fetchChunkOnce(next);
    return { ...result, next };
  } catch (e) {
    if (!e.tooManyLogsError) throw e;

    const currentSize = BigInt(next.toBlock) - BigInt(next.fromBlock) + 1n;
    const halved = currentSize / 2n;
    if (halved < 1n) throw e; // already as small as possible -- nothing left to halve, propagate as hard failure

    process.stderr.write(
      `[ingest-relay] deterministic "too many logs" error on range [${next.fromBlock}, ${next.toBlock}] ` +
        `(${e.message}) — retrying once with max_blocks=${halved}\n`
    );
    const { status, body: retryNext } = await callWorker(`/__ingest/next?max_blocks=${halved}`);
    if (status !== 200) {
      throw new Error(`GET /__ingest/next?max_blocks=${halved} (too-many-logs retry) returned ${status}: ${JSON.stringify(retryNext)}`);
    }
    if (retryNext.noCursor || retryNext.upToDate) {
      // The cursor moved out from under us between the two GETs (a concurrent tick) — nothing
      // useful left to retry against; surface the ORIGINAL error so this chunk's failure
      // semantics (hard-fail on a deterministic error) still apply, rather than silently
      // swallowing a real failure as if it were a no-op.
      throw e;
    }

    const retryResult = await fetchChunkOnce(retryNext); // an uncaught failure here IS the hard failure -- no further retry
    return { ...retryResult, next: retryNext };
  }
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
 * `/__ingest*` that isn't a stale-409, `/__tick` unreachable, a 5xx FROM `/__tick` itself — hardening,
 * D6, external audit finding N7 — or auth) escape to `main().catch()` and exit 1 — those are the
 * ones a red run/notification should exist for.
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
    // Fired UNCONDITIONALLY (Plan 3a Task 8) — no lag guard here anymore; the worker's own
    // `runTick` now carries it (collector/src/index.ts's TICK_INGEST_LAG_CEILING_BLOCKS), applied
    // uniformly to every tick source, this relay included. See this file's own module doc comment
    // (the `--tick` paragraph) for the full rationale.
    const { status, body } = await callWorker('/__tick', { method: 'POST' });
    // (hardening): a 5xx here means the WORKER ITSELF errored
    // (an uncaught exception/crash reaching Cloudflare's own error page — e.g. 1101/1102 — never
    // something runTick's own exception-safety try/catch would produce, since that always
    // returns a normal 200 body with `ok: false` and a truthful note for a HANDLED failure like
    // an honest ingest stall OR a deliberate lag-ceiling skip). This is a worker defect, not the
    // "environmental, self-healing" condition this relay's own chain-RPC soft-fail policy
    // (rpcCall's own doc comment) exists for — we WANT a red run here, so a human notices. Thrown
    // up to main()'s top-level catch, same as every other worker-side failure in this file.
    if (status >= 500) {
      throw new Error(`POST /__tick returned ${status} (worker-side failure, not an honest tick outcome): ${JSON.stringify(body)}`);
    }
    process.stdout.write(`[ingest-relay] /__tick -> status ${status} ok=${body.ok} note="${body.note}"\n`);
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

    // `actualNext` may differ from `next` (code-review finding 6's halving retry fetched a
    // smaller, DIFFERENT range from the server after a deterministic "too many logs" error) — the
    // POST below must declare the range that was ACTUALLY fetched, never the original request.
    const { logs, toBlockHash, next: actualNext } = await fetchChunk(next);

    const { status: postStatus, body: postResult } = await callWorker('/__ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fromBlock: actualNext.fromBlock, toBlock: actualNext.toBlock, toBlockHash, logs }),
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
// its pure functions (isTransientRpcErrorMessage, isTooManyLogsMessage, rpcCall, fetchChunk) by
// tests. Same guard, same reasoning, as attribute-emission.mjs's identical pattern.
if (path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1] ?? '')) {
  main().catch((e) => {
    process.stderr.write(`[ingest-relay] ${e.message}\n`);
    process.exit(1);
  });
}
