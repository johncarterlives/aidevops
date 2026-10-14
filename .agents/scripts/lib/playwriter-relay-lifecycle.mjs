// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Marcus Quinn

import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const delay = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
const failure = (message) => new Error(`Authenticated Playwriter relay: ${message}`);

function signalProcess(pid, signal) {
  try {
    process.kill(pid, signal);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
}

/** Only call with a group created by the launcher or validated owned state. */
export async function terminateProcessGroup(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw failure("invalid owned process-group PID");
  if (!signalProcess(-pid, "SIGTERM")) return;
  const deadline = Date.now() + 750;
  while (Date.now() < deadline) {
    if (!signalProcess(-pid, 0)) return;
    await delay(25);
  }
  // Check the group, not the runner's exitCode: the leader can exit first.
  signalProcess(-pid, "SIGKILL");
  await delay(50);
}

export function processIdentity(pid) {
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

function reviewedRelayProcess(command, contract) {
  const parts = command.trim().split(/\s+/);
  if (parts.slice(-3).join(" ") !== `serve --host ${contract.expected.host}`) return false;
  const runner = parts.slice(0, -3);
  // npm replaces the npx process title with this exact command on POSIX.
  if (runner.length === 3 && basename(runner[0]) === "npm"
      && runner[1] === "exec" && runner[2] === contract.packageName) return true;
  if (basename(runner[0] || "") === "node" && /[/\\]npx-cli\.js$/.test(runner[1] || "")) {
    runner.splice(0, 2, "npx");
  }
  try { contract.validateCommand(runner); return true; } catch { return false; }
}

function privateOwnedPath(path, directory = false) {
  const stats = lstatSync(path);
  return !stats.isSymbolicLink() && (directory ? stats.isDirectory() : stats.isFile())
    && (stats.mode & 0o077) === 0 && stats.uid === process.getuid();
}

function validOwnedState(state, expected) {
  return Object.entries(expected).every(([key, value]) => state[key] === value)
    && [state.supervisorPid, state.relayPid].every((pid) => Number.isSafeInteger(pid) && pid > 1);
}

function readStaleOwnedRuntime(directory, expected) {
  const markerPath = join(directory, ".aidevops-owned-relay");
  const statePath = join(directory, "state.json");
  try {
    if (![privateOwnedPath(directory, true), privateOwnedPath(markerPath), privateOwnedPath(statePath)].every(Boolean)) return null;
    const ownerToken = readFileSync(markerPath, "utf8");
    if (!/^[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}$/i.test(ownerToken)) return null;
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    if (!validOwnedState(state, expected) || signalProcess(state.supervisorPid, 0)) return null;
    return { state, runtime: { directory, markerPath, ownerToken } };
  } catch {
    // Missing, symlinked, inaccessible or malformed evidence is never authority.
    return null;
  }
}

async function recoverOwnedGroup(state, contract) {
  if (!signalProcess(state.relayPid, 0)) {
    // Without a live leader we cannot authenticate a possibly surviving group.
    if (signalProcess(-state.relayPid, 0)) {
      throw failure("leaderless owned relay group remains; refusing unauthenticated cleanup or reuse");
    }
    return true;
  }
  // A marker records historical ownership, not the identity of a reused PID.
  // Legacy/missing birth evidence cannot authorize signaling or silent reuse.
  if (typeof state.relayStartedAt !== "string" || !state.relayStartedAt) {
    throw failure("stale owned relay has no recorded process identity; refusing reuse");
  }
  const identity = processIdentity(state.relayPid);
  if (!identity) throw failure("could not verify stale owned relay process identity; refusing reuse");
  if (state.relayStartedAt !== identity.startedAt) return false;
  if (identity.pgid !== state.relayPid || !reviewedRelayProcess(identity.command, contract)) {
    throw failure("could not verify stale owned relay process group; refusing reuse");
  }
  await terminateProcessGroup(state.relayPid);
  return true;
}

export async function reconcileRuntime(runtime, contract) {
  const parent = resolve(runtime.directory, "..");
  for (const entry of readdirSync(parent, { withFileTypes: true })) {
    if (!entry.name.startsWith("session-") || !entry.isDirectory()) continue;
    const directory = join(parent, entry.name);
    if (directory === runtime.directory) continue;
    const stale = readStaleOwnedRuntime(directory, contract.expected);
    if (stale && await recoverOwnedGroup(stale.state, contract)) contract.cleanupRuntime(stale.runtime);
  }
}
