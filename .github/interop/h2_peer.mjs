// A foreign gRPC peer for the interop check, built on the http2 module of Node only.
// It speaks the JSON-RPC tunnel of proto/mcp_zig_transport_v1.proto against a running SDK
// server: server/discover, tools/list and a subscriptions/listen stream.
//
// Usage: node h2_peer.mjs <port>
import http2 from "node:http2";

const port = Number(process.argv[2] ?? "50051");
const path = "/mcp.zig.transport.v1.Mcp/Call";
const meta = {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": { name: "h2-peer", version: "1" },
  "io.modelcontextprotocol/clientCapabilities": {},
};

function varint(n) {
  const out = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return Buffer.from(out);
}

// JsonRpcMessage { bytes jsonrpc = 1; } inside a length-prefixed gRPC message.
function encode(message) {
  const text = Buffer.from(JSON.stringify(message), "utf8");
  const proto = Buffer.concat([Buffer.from([0x0a]), varint(text.length), text]);
  const prefix = Buffer.alloc(5);
  prefix[0] = 0;
  prefix.writeUInt32BE(proto.length, 1);
  return Buffer.concat([prefix, proto]);
}

function decodeVarint(buf, pos) {
  let value = 0;
  let shift = 0;
  for (;;) {
    const b = buf[pos++];
    value |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [value, pos];
    shift += 7;
  }
}

// Split a stream of length-prefixed messages and decode the JSON-RPC text of each.
function* decodeAll(buf) {
  let pos = 0;
  while (pos + 5 <= buf.length) {
    const len = buf.readUInt32BE(pos + 1);
    const proto = buf.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (proto[0] !== 0x0a) throw new Error("expected field 1");
    const [textLen, start] = decodeVarint(proto, 1);
    yield JSON.parse(proto.subarray(start, start + textLen).toString("utf8"));
  }
}

function call(session, method, params, extra = {}, onMessage = null) {
  return new Promise((resolve, reject) => {
    const req = session.request({
      ":method": "POST",
      ":path": path,
      "content-type": "application/grpc+proto",
      te: "trailers",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": method,
      ...extra,
    });
    const chunks = [];
    let headers = null;
    let trailers = null;
    req.on("response", (h) => {
      headers = h;
    });
    req.on("data", (chunk) => {
      chunks.push(chunk);
      if (onMessage) {
        const all = Buffer.concat(chunks);
        for (const message of decodeAll(all)) onMessage(message, req);
        chunks.length = 0;
      }
    });
    req.on("trailers", (t) => {
      trailers = t;
    });
    req.on("error", (e) => reject(e));
    req.on("close", () => {
      const messages = [...decodeAll(Buffer.concat(chunks))];
      resolve({ headers, trailers: trailers ?? headers, messages });
    });
    req.end(encode({ jsonrpc: "2.0", id: 1, method, params: { ...params, _meta: meta } }));
  });
}

const session = http2.connect(`http://127.0.0.1:${port}`);
session.on("error", (e) => {
  console.error("session error", e);
  process.exit(1);
});

try {
  const discover = await call(session, "server/discover", {});
  if (discover.trailers["grpc-status"] !== "0") throw new Error(`discover status ${discover.trailers["grpc-status"]}`);
  const result = discover.messages.at(-1).result;
  if (!result.supportedVersions.includes("2026-07-28")) throw new Error("no 2026-07-28 in supportedVersions");

  const tools = await call(session, "tools/list", {});
  if (tools.messages.at(-1).result.resultType !== "complete") throw new Error("tools/list resultType");

  // Missing mcp-name on tools/call: the error travels in the trailers.
  const bad = await call(session, "tools/call", { name: "no-such-tool", arguments: {} });
  if (bad.trailers["grpc-status"] !== "3" || bad.trailers["mcp-error-code"] !== "-32020") {
    throw new Error(`expected -32020 in the trailers, got ${JSON.stringify(bad.trailers)}`);
  }

  // A listen stream: the acknowledgement arrives first, then the client cancels.
  let acked = false;
  const listen = await call(session, "subscriptions/listen", { notifications: { toolsListChanged: true } }, {}, (message, req) => {
    if (message.method === "notifications/subscriptions/acknowledged") {
      acked = true;
      req.close(http2.constants.NGHTTP2_CANCEL);
    }
  });
  if (!acked) throw new Error(`no acknowledgement on the listen stream: ${JSON.stringify(listen.messages)}`);
  console.log("h2 peer: discover, tools/list, error trailers and listen OK");
  session.close();
} catch (e) {
  console.error("h2 peer failed:", e);
  session.close();
  process.exit(1);
}
