# The gRPC binding

`mcp_zig_transport_v1.proto` is the service definition of the gRPC transport of this SDK. The transport is a custom transport in the sense of the specification: it keeps the JSON-RPC message format, the request patterns and the per-request metadata.

- One `Call` carries one JSON-RPC request in a `JsonRpcMessage`. The response stream carries the notifications related to the request, then the one response.
- The request metadata mirrors the Streamable HTTP headers in lowercase: `mcp-protocol-version`, `mcp-method`, `mcp-name` and `mcp-param-*`.
- A JSON-RPC error that ends a call before any message travels in the trailers: `grpc-status`, `grpc-message`, `mcp-error-code` and `mcp-error-bin`.

The SDK does not generate code from this file. The message has one `bytes` field, and `src/grpc/protobuf/messages.zig` encodes and decodes it by hand. The file is for other implementations.
