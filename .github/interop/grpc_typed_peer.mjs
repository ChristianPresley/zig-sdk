// A foreign gRPC client for the interop check of the typed binding. It loads the vendored
// proto files of test/fixtures/google_mcp_grpc_proto with @grpc/proto-loader and calls the
// typed service model_context_protocol.Mcp of a running SDK server with @grpc/grpc-js:
// ListTools and CallTool, then the other six RPCs, the error trailers and a multi
// round-trip tool call.
//
// Usage: node grpc_typed_peer.mjs <port> [directory with node_modules]
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.argv[2] ?? "50051");
const deps = path.resolve(process.argv[3] ?? here);
const require = createRequire(path.join(deps, "package.json"));
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");

const protoDir = path.resolve(here, "../../test/fixtures/google_mcp_grpc_proto");
const definition = protoLoader.loadSync(path.join(protoDir, "mcp.proto"), {
  includeDirs: [protoDir],
  keepCase: true,
  longs: String,
  enums: String,
  defaults: false,
  oneofs: true,
});
const mcp = grpc.loadPackageDefinition(definition).model_context_protocol;
const client = new mcp.Mcp(`127.0.0.1:${port}`, grpc.credentials.createInsecure());

// google.protobuf.Struct and Value in the object form of proto-loader. protobufjs has its
// own definitions of the well-known types, with camelCase field names also with keepCase.
function toValue(v) {
  if (v === null) return { nullValue: "NULL_VALUE" };
  if (Array.isArray(v)) return { listValue: { values: v.map(toValue) } };
  switch (typeof v) {
    case "number":
      return { numberValue: v };
    case "string":
      return { stringValue: v };
    case "boolean":
      return { boolValue: v };
    default:
      return { structValue: toStruct(v) };
  }
}

function toStruct(o) {
  return { fields: Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toValue(v)])) };
}

function fromValue(v) {
  switch (v.kind) {
    case "nullValue":
      return null;
    case "numberValue":
      return v.numberValue;
    case "stringValue":
      return v.stringValue;
    case "boolValue":
      return v.boolValue;
    case "structValue":
      return fromStruct(v.structValue);
    case "listValue":
      return (v.listValue.values ?? []).map(fromValue);
    default:
      throw new Error(`a Value without a kind: ${JSON.stringify(v)}`);
  }
}

function fromStruct(s) {
  return Object.fromEntries(Object.entries(s?.fields ?? {}).map(([k, v]) => [k, fromValue(v)]));
}

const common = {
  metadata: toStruct({
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": { name: "grpc-typed-peer", version: "1" },
    "io.modelcontextprotocol/clientCapabilities": { elicitation: {}, sampling: {}, roots: {} },
  }),
};

function call(method, request, extra = {}) {
  const metadata = new grpc.Metadata();
  metadata.set("mcp-protocol-version", "2026-07-28");
  for (const [k, v] of Object.entries(extra)) metadata.set(k, v);
  return new Promise((resolve, reject) => {
    client[method](request, metadata, { deadline: Date.now() + 10000 }, (err, response) => {
      if (err) reject(err);
      else resolve(response);
    });
  });
}

async function expectError(method, request, extra, code, mcpCode) {
  try {
    await call(method, request, extra);
  } catch (err) {
    const got = err.metadata?.get("mcp-error-code")?.[0];
    if (err.code !== code || got !== mcpCode) {
      throw new Error(`${method}: expected status ${code} and ${mcpCode}, got ${err.code} and ${got}: ${err.details}`);
    }
    return;
  }
  throw new Error(`${method}: expected an error`);
}

function check(condition, what) {
  if (!condition) throw new Error(`check failed: ${what}`);
}

const pngBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

try {
  // ListTools and CallTool: the required part of the check.
  const tools = await call("ListTools", { common });
  const names = tools.tools.map((t) => t.name);
  check(names.includes("test_simple_text"), "ListTools has test_simple_text");
  const schema = fromStruct(tools.tools.find((t) => t.name === "json_schema_2020_12_tool").input_schema);
  check(schema.type === "object" && schema.properties.name.type === "string", "the input schema is a JSON object");
  check(tools.common.result_type === "RESULT_TYPE_COMPLETE", "ListTools result type");
  check(tools.ttl != null && tools.cache_scope?.startsWith("CACHE_SCOPE_"), "ListTools ttl and cache scope");
  const serverInfo = fromStruct(tools.common.metadata)["io.modelcontextprotocol/serverInfo"];
  check(serverInfo.name === "mcp-conformance-test-server", "the server info in the metadata");

  const text = await call("CallTool", { common, request: { name: "test_simple_text", arguments: toStruct({}) } }, { mcp_tool: "test_simple_text" });
  check(text.content[0].text.text === "This is a simple text response", "CallTool text");

  // The bytes field has the base64 text, as in the reference transport.
  const image = await call("CallTool", { common, request: { name: "test_image_content" } }, { mcp_tool: "test_image_content" });
  check(Buffer.from(image.content[0].image.data).toString("latin1") === pngBase64, "CallTool image bytes");
  check(image.content[0].image.mime_type === "image/png", "CallTool image MIME type");

  // Errors: the JSON-RPC code in the trailers.
  await expectError("CallTool", { common, request: { name: "no_such_tool" } }, {}, grpc.status.INVALID_ARGUMENT, "-32602");
  await expectError("CallTool", { common, request: { name: "test_simple_text" } }, { mcp_tool: "other" }, grpc.status.INVALID_ARGUMENT, "-32020");

  // The other six RPCs. A call without common gets the defaults of the server.
  const resources = await call("ListResources", {});
  check(resources.resources.some((r) => r.uri === "test://static-text"), "ListResources");
  const read = await call("ReadResource", { common, uri: "test://static-text" }, { mcp_resource: "test://static-text" });
  check(read.resource[0].text === "This is a static text resource", "ReadResource text");
  const blob = await call("ReadResource", { common, uri: "test://static-binary" });
  check(Buffer.from(blob.resource[0].blob).toString("latin1") === pngBase64, "ReadResource blob");
  const templates = await call("ListResourceTemplates", { common });
  check(templates.resource_templates[0].uri_template === "test://template/{id}/data", "ListResourceTemplates");
  const prompts = await call("ListPrompts", { common });
  check(prompts.prompts.some((p) => p.name === "test_prompt_with_arguments"), "ListPrompts");
  const prompt = await call("GetPrompt", { common, name: "test_prompt_with_arguments", arguments: { arg1: "a", arg2: "b" } }, { mcp_prompt: "test_prompt_with_arguments" });
  check(prompt.messages[0].text.text === "Prompt with arg1=a and arg2=b", "GetPrompt");
  const completion = await call("Complete", { common, prompt_reference: { name: "test_prompt_with_arguments" }, argument: { name: "arg1", value: "x" } }, { mcp_resource: "test_prompt_with_arguments" });
  check(Array.isArray(completion.values ?? []), "Complete");

  // A multi round-trip tool call: the input request, then the call again with the answer.
  const first = await call("CallTool", { common, request: { name: "test_input_required_result_elicitation" } });
  check(first.common.result_type === "RESULT_TYPE_INPUT_REQUIRED", "input required result type");
  const question = first.common.input_requests.user_name.elicit_request;
  check(question.message === "What is your name?", "elicitation message");
  check(question.requested_schema.name.string_schema.description === "Your name", "the requested schema");
  check(question.required_fields.includes("name"), "the required fields");
  const answer = {
    ...common,
    input_responses: { user_name: { elicit_result: { type: "TYPE_ACCEPT", content: toStruct({ name: "Ada" }) } } },
    request_state: first.common.request_state,
  };
  const second = await call("CallTool", { common: answer, request: { name: "test_input_required_result_elicitation" } });
  check(second.content[0].text.text === "Hello, Ada!", "the second round");

  // Sampling and roots as input requests.
  const sampling = await call("CallTool", { common, request: { name: "test_input_required_result_sampling" } });
  const sample = sampling.common.input_requests.capital_question.sampling_create_message;
  check(sample.messages[0].text.text === "What is the capital of France?" && sample.max_tokens === 100, "the sampling request");
  const sampled = await call("CallTool", {
    common: {
      ...common,
      input_responses: { capital_question: { sampling_create_message_result: { message: { role: "ROLE_ASSISTANT", text: { text: "Paris" } }, model: "m1" } } },
      request_state: sampling.common.request_state,
    },
    request: { name: "test_input_required_result_sampling" },
  });
  check(sampled.content[0].text.text === "The model (m1) said: Paris", "the sampling answer");
  const roots = await call("CallTool", { common, request: { name: "test_input_required_result_list_roots" } });
  check(roots.common.input_requests.client_roots.list_roots_request != null, "the roots request");
  const listed = await call("CallTool", {
    common: {
      ...common,
      input_responses: { client_roots: { root_list_result: { roots: [{ uri: "file:///work", name: "work" }] } } },
      request_state: roots.common.request_state,
    },
    request: { name: "test_input_required_result_list_roots" },
  });
  check(listed.content[0].text.text === "The client has 1 root(s)", "the roots answer");

  console.log("grpc typed peer: ListTools, CallTool, the other six RPCs, error trailers and multi round-trip calls OK");
  client.close();
} catch (e) {
  console.error("grpc typed peer failed:", e);
  client.close();
  process.exit(1);
}
