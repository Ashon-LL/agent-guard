import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = path.join(repoRoot, "adapters", "dsh", "lib", "index.js");
let source = await fs.readFile(sourcePath, "utf8");
source = source.replace(
  'import { defineTool } from "@deepseek-ai/dsh-tools";',
  "const defineTool = (definition) => definition;"
);

const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "agent-guard-dsh-smoke-"));
const modulePath = path.join(scratch, "index.mjs");
await fs.writeFile(modulePath, source);

try {
  const adapter = await import(pathToFileURL(modulePath).href);
  const registered = [];
  const handlers = [];
  const sections = [];
  const requests = [];
  let cleanup;

  const shell = {
    resolve: (request) => request,
    run: async (request) => {
      requests.push(request);
      const report = request.command.includes("check.py")
        ? {
            decision: "BLOCK",
            code: "BLOCK_PROTECTED_PATH",
            explanation: "protected workspace root",
            reasons: ["protected: workspace-root (.)"],
          }
        : {};
      return {
        stdout: { text: JSON.stringify(report) },
        stderr: { text: "" },
        exitCode: 0,
      };
    },
  };
  const systemPrompt = {
    section: (value) => {
      sections.push(value);
      return () => {};
    },
  };
  const ctx = {
    tools: {
      register: (tool) => {
        registered.push(tool);
        return () => {};
      },
    },
    get: (name) => ({ shell, systemPrompt }[name]),
    on: (name, handler) => {
      handlers.push({ name, handler });
      return () => {};
    },
    effect: (factory) => {
      cleanup = factory();
    },
  };

  adapter.apply(ctx, {
    repoRoot,
    defaultCwd: "",
    promptSection: true,
    sectionOrder: 105,
  });

  assert.equal(registered.length, 3);
  assert.deepEqual(
    registered.map((tool) => tool.name).sort(),
    ["agent_guard_restore", "agent_guard_safe_delete", "agent_guard_status"]
  );
  assert.equal(handlers.length, 1);
  assert.equal(handlers[0].name, "tools/pre-execute");
  assert.equal(sections.length, 1);
  assert.match(sections[0].text, /Never circumvent the guard/);

  let continued = 0;
  const next = () => {
    continued += 1;
    return { kind: "continued" };
  };
  const benign = await handlers[0].handler(
    { name: "bash", arguments: { command: "git status" } },
    next
  );
  assert.equal(benign.kind, "continued");
  const blocked = await handlers[0].handler(
    { name: "bash", arguments: { command: "rm -rf ." } },
    next
  );
  assert.equal(blocked.kind, "deny");
  assert.match(blocked.reason, /BLOCK_PROTECTED_PATH/);
  assert.equal(continued, 1);
  assert.equal(requests.length, 1);
  assert.match(requests[0].command, /check\.py/);

  const statusTool = registered.find(
    (tool) => tool.name === "agent_guard_status"
  );
  const toolResult = await statusTool.execute({}, {});
  assert.equal(toolResult.ok, true);
  assert.equal(toolResult.exitCode, 0);
  assert.equal(requests.length, 2);
  assert.match(requests[1].command, /status\.py/);
  assert.equal(typeof cleanup, "function");
  cleanup();
  console.log("DSH adapter smoke test passed");
} finally {
  await fs.rm(scratch, { recursive: true, force: true });
}
