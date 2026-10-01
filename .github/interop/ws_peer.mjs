// A foreign WebSocket peer for the interop check: the global WebSocket client of Node 22 and
// later (the WHATWG API of undici), with no package. It speaks the WebSocket binding of the
// SDK against a running server: the subprotocol mcp, one JSON-RPC message per text message.
// It lists the tools, calls one tool with progress, sends a request that the server
// refuses, and closes with the code 1000.
//
// Usage: node ws_peer.mjs <port> [tool]
const port = Number(process.argv[2] ?? "3001");
const tool = process.argv[3] ?? "test_tool_with_progress";
const meta = (extra = {}) => ({
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": { name: "ws-peer", version: "1" },
  "io.modelcontextprotocol/clientCapabilities": {},
  ...extra,
});

function fail(message) {
  console.error(`ws peer failed: ${message}`);
  process.exit(1);
}

const timer = setTimeout(() => fail("no result within 20 seconds"), 20000);

const ws = new WebSocket(`ws://127.0.0.1:${port}/mcp`, ["mcp"]);
const pending = new Map();
const notifications = [];

ws.addEventListener("error", (e) => fail(`connection error: ${e.message ?? e.type}`));
ws.addEventListener("message", (event) => {
  if (typeof event.data !== "string") fail("the server sent a binary message");
  const message = JSON.parse(event.data);
  if (message.id !== undefined && pending.has(message.id)) {
    pending.get(message.id)(message);
    pending.delete(message.id);
  } else if (message.method) {
    notifications.push(message);
  } else {
    fail(`a message for no request: ${event.data}`);
  }
});

let nextId = 1;
function request(method, params) {
  const id = nextId++;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
  });
}

ws.addEventListener("open", async () => {
  try {
    if (ws.protocol !== "mcp") fail(`the server chose the subprotocol "${ws.protocol}"`);
    if (ws.extensions !== "") fail(`the server accepted the extensions "${ws.extensions}"`);

    // Two requests at the same time on one connection.
    const [discover, tools] = await Promise.all([
      request("server/discover", { _meta: meta() }),
      request("tools/list", { _meta: meta() }),
    ]);
    if (!discover.result?.supportedVersions?.includes("2026-07-28")) fail(`server/discover: ${JSON.stringify(discover)}`);
    const names = tools.result?.tools?.map((t) => t.name) ?? [];
    if (!names.includes(tool)) fail(`tools/list has no ${tool}: ${names.join(", ")}`);

    const call = await request("tools/call", { name: tool, arguments: {}, _meta: meta({ progressToken: "p1" }) });
    if (call.error || !Array.isArray(call.result?.content)) fail(`tools/call: ${JSON.stringify(call)}`);
    const progress = notifications.filter((n) => n.method === "notifications/progress" && n.params?.progressToken === "p1");
    console.log(`ws peer: ${names.length} tools, ${tool} gave ${call.result.content.length} content block(s) and ${progress.length} progress notification(s)`);

    // A request without _meta gets a JSON-RPC error, and the connection stays open.
    const refused = await request("tools/list", {});
    if (refused.error?.code !== -32602) fail(`expected -32602, got ${JSON.stringify(refused)}`);

    ws.addEventListener("close", (event) => {
      clearTimeout(timer);
      if (event.code !== 1000) fail(`the server answered the close with ${event.code}`);
      console.log("ws peer: discover, tools/list, tools/call, error and close OK");
      process.exit(0);
    });
    ws.close(1000, "done");
  } catch (e) {
    fail(e.stack ?? String(e));
  }
});
