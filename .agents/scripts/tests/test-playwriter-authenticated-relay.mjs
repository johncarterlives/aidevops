// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025-2026 Marcus Quinn

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  cleanupPrivateRuntime,
  createPrivateRuntime,
  probeAuthenticatedRelay,
  reconcileOwnedRelays,
  spawnRelay,
  terminateProcessGroup,
  validatePlaywriterCommand,
  withTelemetryOptOut,
} from "../playwriter-authenticated-relay.mjs";

test("accepts only reviewed Playwriter package-runner commands", () => {
  assert.deepEqual(validatePlaywriterCommand(["npx", "playwriter@0.8.0"]), [
    "npx", "playwriter@0.8.0",
  ]);
  assert.deepEqual(validatePlaywriterCommand(["bun", "x", "playwriter@0.8.0"]), [
    "bun", "x", "playwriter@0.8.0",
  ]);
  for (const unreviewed of ["playwriter@latest", "playwriter@0.5.0"]) {
    assert.throws(
      () => validatePlaywriterCommand(["npx", unreviewed]),
      /reviewed Playwriter package shape/,
    );
  }
  assert.throws(
    () => validatePlaywriterCommand(["sh", "-c", "playwriter@0.8.0"]),
    /reviewed Playwriter package shape/,
  );
});

test("defaults Playwriter telemetry off but keeps an explicit operator choice", () => {
  assert.deepEqual(withTelemetryOptOut({ PATH: "/bin" }), {
    PATH: "/bin", PLAYWRITER_TELEMETRY: "0", DO_NOT_TRACK: "1",
  });
  assert.deepEqual(withTelemetryOptOut({ PLAYWRITER_TELEMETRY: "1" }), {
    PLAYWRITER_TELEMETRY: "1",
  });
});

test("proves both relay version and token enforcement", async (t) => {
  const token = "a".repeat(32);
  const server = createServer((request, response) => {
    if (request.url === "/version") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"version":"0.8.0"}');
      return;
    }
    const url = new URL(request.url, "http://127.0.0.1");
    response.writeHead(url.searchParams.get("token") === token ? 404 : 401);
    response.end();
  });
  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  t.after(() => server.close());
  const address = server.address();

  assert.deepEqual(
    await probeAuthenticatedRelay({ token, port: address.port }),
    { reachable: true, ready: true },
  );
  assert.deepEqual(
    await probeAuthenticatedRelay({ token: "b".repeat(32), port: address.port }),
    { reachable: true, ready: false },
  );
});

test("removes only runtime directories with matching ownership evidence", (t) => {
  const tempRoot = mkdtempSync(join(tmpdir(), "aidevops-playwriter-relay-"));
  const runtime = createPrivateRuntime(tempRoot, "owned-token");
  t.after(() => {
    try { cleanupPrivateRuntime(runtime); } catch {}
  });
  assert.equal(readFileSync(runtime.markerPath, "utf8"), "owned-token");
  writeFileSync(runtime.markerPath, "foreign-token");
  assert.throws(() => cleanupPrivateRuntime(runtime), /matching ownership evidence/);
  writeFileSync(runtime.markerPath, "owned-token");
  cleanupPrivateRuntime(runtime);
});

const pause = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
const launcherPath = fileURLToPath(new URL("../playwriter-authenticated-relay.mjs", import.meta.url));

async function eventually(check, milliseconds = 5_000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    if (await check()) return;
    await pause(20);
  }
  assert.fail("synthetic lifecycle did not reach the expected state before its deadline");
}

function fixture(t) {
  const workspaceTemp = join(homedir(), ".aidevops", ".agent-workspace", "tmp");
  const root = mkdtempSync(join(process.env.AIDEVOPS_TEMP_DIR || (existsSync(workspaceTemp) ? workspaceTemp : tmpdir()), "playwriter-lifecycle-"));
  const cleanups = [];
  t.after(async () => {
    try { for (const cleanup of cleanups.reverse()) await cleanup(); }
    finally { rmSync(root, { recursive: true, force: true }); }
  });
  const infoPath = join(root, "listener.json");
  const runnerPath = join(root, "npx");
  // Synthetic reviewed runner shape; no package install, browser, or port 19988.
  writeFileSync(runnerPath, `#!${process.execPath}
const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
if (process.argv.includes("serve")) {
  process.title = "npm exec playwriter@0.8.0 serve --host 127.0.0.1";
  if (process.env.TEST_RUNNER_STUBBORN === "1") process.on("SIGTERM", () => {});
  const child = spawn(process.execPath, ["-e", \`
    const { createServer } = require("node:http");
    process.on("SIGTERM", () => {});
    const server = createServer((request, response) => {
      if (request.url === "/version") {
        if (process.env.TEST_HANG_PROBE === "1") return;
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"version":"0.8.0"}');
      } else {
        const supplied = new URL(request.url, "http://127.0.0.1").searchParams.get("token");
        response.writeHead(supplied === process.env.PLAYWRITER_TOKEN ? 404 : 401);
        response.end();
      }
    });
    server.listen(0, "127.0.0.1", () => process.send({ pid: process.pid, port: server.address().port }));
  \`], { stdio: ["ignore", "ignore", "ignore", "ipc"] });
  child.once("message", (info) => writeFileSync(process.env.TEST_INFO_PATH, JSON.stringify({ ...info, runnerPid: process.pid })));
} else {
  writeFileSync(process.env.TEST_MCP_PATH, String(process.pid));
  process.on("SIGTERM", () => {});
  process.stdin.on("end", () => process.exit(0));
  process.stdin.on("data", (data) => {
    if (data.toString().trim() === "exit") process.exit(0);
    process.stdout.write("synthetic-stdio-ready\\n");
  });
}
`, { mode: 0o700 });
  return { root, runnerPath, infoPath, cleanups, environment: {
    ...process.env,
    AIDEVOPS_TEMP_DIR: root,
    AIDEVOPS_PLAYWRITER_AUTHENTICATED_RELAY: "1",
    PLAYWRITER_TOKEN: randomUUID(),
    TEST_INFO_PATH: infoPath,
    TEST_MCP_PATH: join(root, "mcp.pid"),
  } };
}

async function ownedRunner(t, f, environment = f.environment) {
  const runtime = createPrivateRuntime(f.root);
  const runner = spawnRelay(validatePlaywriterCommand([f.runnerPath, "playwriter@0.8.0"]), environment, runtime);
  f.cleanups.push(async () => {
    await terminateProcessGroup(runner.pid);
    if (existsSync(runtime.directory)) cleanupPrivateRuntime(runtime);
  });
  await eventually(() => existsSync(f.infoPath));
  const info = JSON.parse(readFileSync(f.infoPath, "utf8"));
  const topology = execFileSync("ps", ["-o", "pid=,ppid=,pgid=,command=", "-p", `${runner.pid},${info.pid}`], { encoding: "utf8" });
  t.diagnostic(`Synthetic package-runner topology:\n${topology.trim()}`);
  for (const line of topology.trim().split("\n")) {
    assert.equal(Number(line.trim().split(/\s+/)[2]), runner.pid);
  }
  return { runtime, runner, info };
}

async function assertListenerClosed(info) {
  await eventually(async () => {
    try { await fetch(`http://127.0.0.1:${info.port}/version`, { signal: AbortSignal.timeout(100) }); return false; }
    catch { return true; }
  });
  await assertProcessStopped(info.pid);
}

async function assertProcessStopped(pid) {
  await eventually(() => {
    try {
      const status = execFileSync("ps", ["-o", "stat=", "-p", String(pid)], {
        encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
      }).trim();
      return !status || status.startsWith("Z");
    } catch { return true; }
  });
}

function processBirth(pid) {
  return execFileSync("ps", ["-o", "lstart=", "-p", String(pid)], { encoding: "utf8" }).trim();
}

test("single-PID teardown leaks a runner descendant; owned group teardown removes it", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  const { runner, info } = await ownedRunner(t, f);
  runner.kill("SIGTERM");
  await eventually(() => runner.signalCode !== null);
  assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
  await terminateProcessGroup(runner.pid);
  await assertListenerClosed(info);
});

test("stale marked dead-supervisor state reconciles the reviewed owned runner group", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  const { runtime, runner, info } = await ownedRunner(t, f);
  const dead = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  await new Promise((resolvePromise) => dead.once("exit", resolvePromise));
  writeFileSync(runtime.statePath, JSON.stringify({
    schema: "aidevops-playwriter-relay/v1", owned: true, host: "127.0.0.1", port: 19988,
    version: "0.8.0", supervisorPid: dead.pid, relayPid: runner.pid,
    relayStartedAt: processBirth(runner.pid),
  }), { mode: 0o600 });
  const current = createPrivateRuntime(f.root);
  await reconcileOwnedRelays(current);
  assert.equal(existsSync(runtime.directory), false);
  assert.equal(existsSync(current.directory), true);
  await assertListenerClosed(info);
});

test("reconciliation preserves live supervisors, invalid evidence, and reused PID identities", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  const { runtime, runner, info } = await ownedRunner(t, f);
  const current = createPrivateRuntime(f.root);
  const state = {
    schema: "aidevops-playwriter-relay/v1", owned: true, host: "127.0.0.1", port: 19988,
    version: "0.8.0", supervisorPid: process.pid, relayPid: runner.pid,
    relayStartedAt: processBirth(runner.pid),
  };
  const dead = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  await new Promise((resolvePromise) => dead.once("exit", resolvePromise));
  for (const change of [{}, { supervisorPid: dead.pid, owned: false },
    { supervisorPid: dead.pid, version: "0.5.0" },
    { supervisorPid: dead.pid, relayStartedAt: "a different process birth" }]) {
    writeFileSync(runtime.statePath, JSON.stringify({ ...state, ...change }), { mode: 0o600 });
    await reconcileOwnedRelays(current);
    assert.equal(existsSync(runtime.directory), true);
    assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
  }
  writeFileSync(runtime.statePath, JSON.stringify({ ...state, supervisorPid: dead.pid }));
  chmodSync(runtime.markerPath, 0o644);
  await reconcileOwnedRelays(current);
  chmodSync(runtime.markerPath, 0o600);
  const marker = readFileSync(runtime.markerPath, "utf8");
  rmSync(runtime.markerPath);
  const foreignMarker = join(f.root, "foreign-marker");
  writeFileSync(foreignMarker, marker, { mode: 0o600 });
  symlinkSync(foreignMarker, runtime.markerPath);
  await reconcileOwnedRelays(current);
  assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
  rmSync(runtime.markerPath);
  writeFileSync(runtime.markerPath, marker, { mode: 0o600 });
});

test("missing recorded birth identity never authorizes killing a matching independent runner", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  const { runtime, runner, info } = await ownedRunner(t, f);
  const dead = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  await new Promise((resolvePromise) => dead.once("exit", resolvePromise));
  writeFileSync(runtime.statePath, JSON.stringify({
    schema: "aidevops-playwriter-relay/v1", owned: true, host: "127.0.0.1", port: 19988,
    version: "0.8.0", supervisorPid: dead.pid, relayPid: runner.pid,
  }), { mode: 0o600 });
  const current = createPrivateRuntime(f.root);
  await assert.rejects(reconcileOwnedRelays(current), /recorded process identity/);
  assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
  assert.equal(existsSync(runtime.directory), true);
});

async function supervisor(t, f, ready = true) {
  const source = `
    const { readFileSync } = await import("node:fs");
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (url, options) => {
      const target = new URL(url);
      if (target.hostname !== "127.0.0.1" || target.port !== "19988") throw new Error("unexpected test fetch");
      try { target.port = String(JSON.parse(readFileSync(process.env.TEST_INFO_PATH)).port); }
      catch { return Promise.reject(new Error("synthetic relay not yet started")); }
      return originalFetch(target, options);
    };
    const { main } = await import(${JSON.stringify(launcherPath)});
    main([${JSON.stringify(f.runnerPath)}, "playwriter@0.8.0"]).then(code => { process.exitCode = code; })
      .catch(() => { process.exitCode = 1; });
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", source], {
    env: f.environment, stdio: ["pipe", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", data => { output += data; });
  child.stderr.resume();
  f.cleanups.push(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    if (existsSync(f.environment.TEST_MCP_PATH)) await terminateProcessGroup(Number(readFileSync(f.environment.TEST_MCP_PATH, "utf8")));
    if (existsSync(f.infoPath)) await terminateProcessGroup(JSON.parse(readFileSync(f.infoPath)).runnerPid);
  });
  await eventually(() => existsSync(f.infoPath));
  if (ready) {
    child.stdin.write("handshake\n");
    await eventually(() => output.includes("synthetic-stdio-ready"));
  }
  return child;
}

for (const shutdown of ["stdio-exit", "stdio-eof", "SIGINT", "SIGTERM", "SIGHUP"]) {
  test(`supervisor ${shutdown} cleans stubborn runner groups and owned state within host grace`, { timeout: 10_000 }, async (t) => {
    const f = fixture(t);
    f.environment.TEST_RUNNER_STUBBORN = "1";
    const child = await supervisor(t, f);
    const info = JSON.parse(readFileSync(f.infoPath));
    const started = Date.now();
    if (shutdown === "stdio-exit") child.stdin.write("exit\n");
    else if (shutdown === "stdio-eof") child.stdin.end();
    else {
      child.kill(shutdown);
      await pause(100);
      child.kill(shutdown);
    }
    await eventually(() => child.exitCode !== null || child.signalCode !== null);
    assert.equal(child.signalCode, null, "repeated signals must not skip finally");
    assert.ok(Date.now() - started < 2_000, "concurrent cleanup must fit the host's 2s grace");
    await assertListenerClosed(info);
    await assertProcessStopped(Number(readFileSync(f.environment.TEST_MCP_PATH, "utf8")));
    const sessions = readdirSync(join(f.root, "mcp", "playwriter", "authenticated-relay"));
    assert.deepEqual(sessions, []);
  });
}

test("cancellation during a hanging startup probe still tears down the owned group", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  f.environment.TEST_HANG_PROBE = "1";
  const child = await supervisor(t, f, false);
  const info = JSON.parse(readFileSync(f.infoPath));
  const started = Date.now();
  child.kill("SIGTERM");
  await pause(100);
  child.kill("SIGTERM");
  await eventually(() => child.exitCode !== null || child.signalCode !== null);
  assert.equal(child.signalCode, null);
  assert.ok(Date.now() - started < 2_000);
  await assertListenerClosed(info);
  assert.deepEqual(readdirSync(join(f.root, "mcp", "playwriter", "authenticated-relay")), []);
});

test("a new supervisor reconciles a forcibly killed supervisor's owned relay before reuse", { timeout: 15_000 }, async (t) => {
  const f = fixture(t);
  const first = await supervisor(t, f);
  const previous = JSON.parse(readFileSync(f.infoPath));
  first.kill("SIGKILL");
  await eventually(() => first.signalCode !== null);
  assert.equal((await fetch(`http://127.0.0.1:${previous.port}/version`)).status, 200);
  // Stop only the synthetic MCP orphan; this test targets relay reconciliation.
  await terminateProcessGroup(Number(readFileSync(f.environment.TEST_MCP_PATH, "utf8")));
  rmSync(f.infoPath);
  const second = await supervisor(t, f);
  const replacement = JSON.parse(readFileSync(f.infoPath));
  assert.notEqual(replacement.runnerPid, previous.runnerPid);
  await assertListenerClosed(previous);
  second.stdin.end();
  await eventually(() => second.exitCode !== null);
  await assertListenerClosed(replacement);
  assert.deepEqual(readdirSync(join(f.root, "mcp", "playwriter", "authenticated-relay")), []);
});

test("interrupted group teardown fails closed instead of adopting an owned leaderless relay as external", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  const first = await supervisor(t, f);
  const info = JSON.parse(readFileSync(f.infoPath));
  first.kill("SIGTERM");
  await assertProcessStopped(info.runnerPid);
  first.kill("SIGKILL");
  await eventually(() => first.signalCode !== null);
  assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
  const current = createPrivateRuntime(f.root);
  await assert.rejects(reconcileOwnedRelays(current), /leaderless owned relay/);
  const second = await supervisor(t, f, false);
  await eventually(() => second.exitCode !== null);
  assert.equal(second.exitCode, 1, "startup must report incomplete owned-relay recovery");
  assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
});

test("supervisor reuses but never terminates an external authenticated listener", { timeout: 10_000 }, async (t) => {
  const f = fixture(t);
  const { runner, info } = await ownedRunner(t, f);
  // Remove the synthetic ownership evidence, making this listener external.
  const parent = join(f.root, "mcp", "playwriter", "authenticated-relay");
  for (const entry of readdirSync(parent)) rmSync(join(parent, entry), { recursive: true });
  const child = await supervisor(t, f);
  child.stdin.write("exit\n");
  await eventually(() => child.exitCode !== null);
  assert.equal(runner.exitCode, null);
  assert.equal((await fetch(`http://127.0.0.1:${info.port}/version`)).status, 200);
  assert.deepEqual(readdirSync(parent), []);
});
