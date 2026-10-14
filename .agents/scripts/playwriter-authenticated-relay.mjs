#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025-2026 Marcus Quinn

import { execFileSync, spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

// Reviewed pin (GH#34549). Bump only after re-proving the /version, token
// challenge, loopback and telemetry opt-out contract against the release.
const PLAYWRITER_VERSION = "0.8.0";
const PLAYWRITER_PACKAGE = `playwriter@${PLAYWRITER_VERSION}`;
const RELAY_HOST = "127.0.0.1";
const RELAY_PORT = 19988;
const START_TIMEOUT_MS = 5_000;
const STOP_TIMEOUT_MS = 750;
const STATE_SCHEMA = "aidevops-playwriter-relay/v1";

const delay = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));

function fixedError(message) {
  return new Error(`Authenticated Playwriter relay: ${message}`);
}

export function validatePlaywriterCommand(command) {
  if (!Array.isArray(command) || command.some((part) => typeof part !== "string" || !part)) {
    throw fixedError("invalid package-runner command");
  }
  const runner = basename(command[0]);
  const args = command.slice(1);
  const npxShape = runner === "npx"
    && (args.length === 1 || (args.length === 2 && args[0] === "-y"))
    && args.at(-1) === PLAYWRITER_PACKAGE;
  const bunShape = runner === "bun"
    && args.length === 2
    && args[0] === "x"
    && args[1] === PLAYWRITER_PACKAGE;
  if (!npxShape && !bunShape) {
    throw fixedError("command is not the reviewed Playwriter package shape");
  }
  return [...command];
}

/**
 * Playwriter >= 0.8.0 relays send anonymous usage telemetry unless opted out.
 * Default it off before any relay or MCP process starts; an operator who set
 * PLAYWRITER_TELEMETRY explicitly keeps that choice.
 */
export function withTelemetryOptOut(environment) {
  if (environment.PLAYWRITER_TELEMETRY !== undefined) return { ...environment };
  return {
    ...environment,
    PLAYWRITER_TELEMETRY: "0",
    DO_NOT_TRACK: environment.DO_NOT_TRACK ?? "1",
  };
}

function requireToken(environment) {
  const token = environment.PLAYWRITER_TOKEN;
  if (typeof token !== "string" || token.length < 32) {
    throw fixedError("PLAYWRITER_TOKEN must be injected through the environment and contain at least 32 characters");
  }
  return token;
}

function privateDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stats = lstatSync(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw fixedError("private runtime path is not a regular directory");
  }
  chmodSync(path, 0o700);
}

export function createPrivateRuntime(tempRoot, ownerToken = randomUUID()) {
  if (!isAbsolute(tempRoot)) throw fixedError("AIDEVOPS_TEMP_DIR must be absolute");
  privateDirectory(tempRoot);
  const physicalTempRoot = realpathSync(tempRoot);
  const parent = resolve(tempRoot, "mcp", "playwriter", "authenticated-relay");
  privateDirectory(parent);
  const physicalParent = realpathSync(parent);
  const relativeParent = relative(physicalTempRoot, physicalParent);
  if (relativeParent.startsWith("..") || isAbsolute(relativeParent)) {
    throw fixedError("private runtime path escapes AIDEVOPS_TEMP_DIR");
  }
  const directory = join(physicalParent, `session-${process.pid}-${randomUUID()}`);
  mkdirSync(directory, { mode: 0o700 });
  const markerPath = join(directory, ".aidevops-owned-relay");
  writeFileSync(markerPath, ownerToken, { flag: "wx", mode: 0o600 });
  return {
    directory,
    markerPath,
    ownerToken,
    logPath: join(directory, "relay.log"),
    statePath: join(directory, "state.json"),
  };
}

export function cleanupPrivateRuntime(runtime) {
  const stats = lstatSync(runtime.directory);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw fixedError("refusing cleanup of a non-regular runtime directory");
  }
  if (readFileSync(runtime.markerPath, "utf8") !== runtime.ownerToken) {
    throw fixedError("refusing cleanup without matching ownership evidence");
  }
  rmSync(runtime.directory, { recursive: true, force: false });
}

function relayUrl(path, port = RELAY_PORT) {
  return `http://${RELAY_HOST}:${port}${path}`;
}

async function boundedFetch(fetchImpl, url, options = {}) {
  return fetchImpl(url, {
    redirect: "error",
    signal: AbortSignal.timeout(1_000),
    ...options,
  });
}

export async function probeAuthenticatedRelay({
  token,
  port = RELAY_PORT,
  fetchImpl = fetch,
  signal,
} = {}) {
  const request = (url) => boundedFetch(fetchImpl, url, signal ? {
    signal: AbortSignal.any([signal, AbortSignal.timeout(1_000)]),
  } : {});
  try {
    const versionResponse = await request(relayUrl("/version", port));
    if (!versionResponse.ok) return { reachable: true, ready: false };
    const versionPayload = await versionResponse.json();
    if (versionPayload?.version !== PLAYWRITER_VERSION) return { reachable: true, ready: false };

    const wrongToken = randomUUID();
    const wrongResponse = await request(
      relayUrl(`/cdp/aidevops-proof?token=${encodeURIComponent(wrongToken)}`, port),
    );
    const rightResponse = await request(
      relayUrl(`/cdp/aidevops-proof?token=${encodeURIComponent(token)}`, port),
    );
    return {
      reachable: true,
      ready: wrongResponse.status === 401 && rightResponse.status === 404,
    };
  } catch {
    return { reachable: false, ready: false };
  }
}

export function spawnRelay(command, environment, runtime) {
  const logDescriptor = openSync(runtime.logPath, "a", 0o600);
  chmodSync(runtime.logPath, 0o600);
  try {
    const child = spawn(command[0], [...command.slice(1), "serve", "--host", RELAY_HOST], {
      env: environment,
      shell: false,
      // Own a separate group, including npm/bun's relay descendants. Never unref.
      detached: true,
      stdio: ["ignore", logDescriptor, logDescriptor],
    });
    child.spawnFailed = false;
    child.once("error", () => { child.spawnFailed = true; });
    return child;
  } finally {
    closeSync(logDescriptor);
  }
}

async function waitForRelay(token, child, signal) {
  const deadline = Date.now() + START_TIMEOUT_MS;
  do {
    if (signal.aborted) return { reachable: false, ready: false };
    const proof = await probeAuthenticatedRelay({ token, signal });
    if (proof.ready) return proof;
    if (proof.reachable || child.spawnFailed || child.exitCode !== null || child.signalCode !== null) return proof;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  } while (Date.now() < deadline);
  return { reachable: false, ready: false };
}

function signalProcess(pid, signal) {
  try {
    process.kill(pid, signal);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
}

/** Only call with a group created by this launcher or validated owned state. */
export async function terminateProcessGroup(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw fixedError("invalid owned process-group PID");
  if (!signalProcess(-pid, "SIGTERM")) return;
  const deadline = Date.now() + STOP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!signalProcess(-pid, 0)) return;
    await delay(25);
  }
  // Check the group, not the runner's exitCode: the leader can exit first.
  signalProcess(-pid, "SIGKILL");
  await delay(50);
}

function processIdentity(pid) {
  try {
    const output = execFileSync("ps", ["-o", "pgid=,lstart=,command=", "-p", String(pid)], {
      encoding: "utf8", timeout: 500, stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    const match = /^(\d+)\s+(\S+\s+\S+\s+\d+\s+\S+\s+\d+)\s+(.+)$/.exec(output);
    return match ? { pgid: Number(match[1]), startedAt: match[2], command: match[3] } : null;
  } catch {
    return null;
  }
}

function reviewedRelayProcess(command) {
  const parts = command.trim().split(/\s+/);
  if (parts.slice(-3).join(" ") !== `serve --host ${RELAY_HOST}`) return false;
  const runner = parts.slice(0, -3);
  // npm replaces the npx process title with this exact command on POSIX.
  if (runner.length === 3 && basename(runner[0]) === "npm"
      && runner[1] === "exec" && runner[2] === PLAYWRITER_PACKAGE) return true;
  if (basename(runner[0] || "") === "node" && /[/\\]npx-cli\.js$/.test(runner[1] || "")) {
    runner.splice(0, 2, "npx");
  }
  try { validatePlaywriterCommand(runner); return true; } catch { return false; }
}

function privateOwnedPath(path, directory = false) {
  const stats = lstatSync(path);
  return !stats.isSymbolicLink() && (directory ? stats.isDirectory() : stats.isFile())
    && (stats.mode & 0o077) === 0 && stats.uid === process.getuid();
}

export async function reconcileOwnedRelays(runtime) {
  const parent = resolve(runtime.directory, "..");
  for (const entry of readdirSync(parent, { withFileTypes: true })) {
    if (!entry.name.startsWith("session-") || !entry.isDirectory()) continue;
    const directory = join(parent, entry.name);
    if (directory === runtime.directory) continue;
    const markerPath = join(directory, ".aidevops-owned-relay");
    const statePath = join(directory, "state.json");
    let state;
    let ownerToken;
    try {
      if (![privateOwnedPath(directory, true), privateOwnedPath(markerPath), privateOwnedPath(statePath)].every(Boolean)) continue;
      ownerToken = readFileSync(markerPath, "utf8");
      if (!/^[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}$/i.test(ownerToken)) continue;
      state = JSON.parse(readFileSync(statePath, "utf8"));
      if (state.schema !== STATE_SCHEMA || state.owned !== true || state.host !== RELAY_HOST
          || state.port !== RELAY_PORT || state.version !== PLAYWRITER_VERSION
          || !Number.isSafeInteger(state.supervisorPid) || state.supervisorPid <= 1
          || !Number.isSafeInteger(state.relayPid) || state.relayPid <= 1) continue;
      if (signalProcess(state.supervisorPid, 0)) continue;
    } catch {
      // Missing, symlinked, inaccessible or malformed evidence is never authority.
      continue;
    }
    if (signalProcess(state.relayPid, 0)) {
      // A marker records historical ownership, not the identity of a reused PID.
      // Legacy/missing birth evidence cannot authorize signaling or silent reuse.
      if (typeof state.relayStartedAt !== "string" || !state.relayStartedAt) {
        throw fixedError("stale owned relay has no recorded process identity; refusing reuse");
      }
      const identity = processIdentity(state.relayPid);
      if (!identity) throw fixedError("could not verify stale owned relay process identity; refusing reuse");
      if (state.relayStartedAt !== identity.startedAt) continue;
      if (identity.pgid !== state.relayPid || !reviewedRelayProcess(identity.command)) {
        throw fixedError("could not verify stale owned relay process group; refusing reuse");
      }
      await terminateProcessGroup(state.relayPid);
    } else {
      // Without a live leader we cannot authenticate a possibly surviving group.
      if (signalProcess(-state.relayPid, 0)) {
        throw fixedError("leaderless owned relay group remains; refusing unauthenticated cleanup or reuse");
      }
    }
    cleanupPrivateRuntime({ directory, markerPath, ownerToken });
  }
}

async function ensureRelay(command, environment, runtime, token, relay, signal) {
  await reconcileOwnedRelays(runtime);
  const existing = await probeAuthenticatedRelay({ token, signal });
  if (signal.aborted) throw fixedError("startup cancelled");
  if (existing.ready) return;
  if (existing.reachable) {
    throw fixedError("port 19988 is occupied without matching token and version proof");
  }

  const child = spawnRelay(command, environment, runtime);
  relay.child = child;
  relay.owned = true;
  // Record ownership before waiting, so forced supervisor death is recoverable.
  writeState(runtime, relay);
  const proof = await waitForRelay(token, child, signal);
  if (!proof.ready) {
    throw fixedError("could not prove the localhost relay version and token contract");
  }
  if (child.exitCode !== null || child.signalCode !== null || child.spawnFailed) {
    throw fixedError("owned relay package runner exited during startup");
  }
}

function writeState(runtime, relay) {
  const state = {
    schema: STATE_SCHEMA,
    host: RELAY_HOST,
    port: RELAY_PORT,
    version: PLAYWRITER_VERSION,
    supervisorPid: process.pid,
    relayPid: relay.owned ? relay.child.pid : null,
    relayStartedAt: relay.owned ? processIdentity(relay.child.pid)?.startedAt : null,
    owned: relay.owned,
  };
  writeFileSync(runtime.statePath, `${JSON.stringify(state)}\n`, { flag: "wx", mode: 0o600 });
}

async function supervise(command, environment) {
  const token = requireToken(environment);
  const tempRoot = environment.AIDEVOPS_TEMP_DIR
    || join(homedir(), ".aidevops", ".agent-workspace", "tmp");
  const runtime = createPrivateRuntime(tempRoot);
  const relay = { child: null, owned: false };
  let mcp = null;
  let stopping = false;
  const controller = new AbortController();
  let resolveStop;
  const stopped = new Promise((resolvePromise) => { resolveStop = resolvePromise; });
  const stop = () => {
    if (stopping) return;
    stopping = true;
    controller.abort();
    resolveStop({ code: 1, signal: null });
  };
  const signals = ["SIGINT", "SIGTERM", "SIGHUP"];
  for (const signal of signals) process.on(signal, stop);
  try {
    await ensureRelay(command, environment, runtime, token, relay, controller.signal);
    if (stopping) return 1;
    if (!relay.owned) writeState(runtime, relay);
    mcp = spawn(command[0], command.slice(1), {
      env: {
        ...environment,
        PLAYWRITER_HOST: RELAY_HOST,
      },
      shell: false,
      detached: true,
      stdio: "inherit",
    });

    if (relay.owned) {
      relay.child.once("exit", stop);
    }

    const exited = new Promise((resolvePromise) => {
      mcp.once("error", () => resolvePromise({ code: 1, signal: null }));
      mcp.once("exit", (code, signal) => resolvePromise({ code, signal }));
    });
    const result = await Promise.race([exited, stopped]);
    stopping = true;
    return result.code ?? (result.signal ? 1 : 0);
  } finally {
    stopping = true;
    controller.abort();
    try {
      await Promise.all([
        mcp?.pid ? terminateProcessGroup(mcp.pid) : null,
        relay.owned && relay.child?.pid ? terminateProcessGroup(relay.child.pid) : null,
      ]);
      cleanupPrivateRuntime(runtime);
    } finally {
      for (const signal of signals) process.removeListener(signal, stop);
    }
  }
}

export async function main(argv = process.argv.slice(2), environment = process.env) {
  if (environment.AIDEVOPS_PLAYWRITER_AUTHENTICATED_RELAY !== "1") {
    throw fixedError("opt-in environment flag is not enabled");
  }
  const command = validatePlaywriterCommand(argv);
  return supervise(command, withTelemetryOptOut(environment));
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath && fileURLToPath(import.meta.url) === invokedPath) {
  main()
    .then((code) => { process.exitCode = code; })
    .catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.message : "Authenticated Playwriter relay failed"}\n`);
      process.exitCode = 1;
    });
}
