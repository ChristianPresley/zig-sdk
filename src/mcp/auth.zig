//! Authorization: the OAuth 2.1 client of the HTTP client transport, the authorization
//! extensions, the resource server helpers of the HTTP server, and an authorization server.
const std = @import("std");
const types = @import("protocol/types.zig");

pub const common = @import("auth/common.zig");
/// The interface through which the HTTP client transport gets tokens.
pub const Provider = common.Provider;
/// How a client authenticates at a token endpoint.
pub const ClientAuth = common.ClientAuth;
pub const oauth_client = @import("auth/oauth_client.zig");
pub const OAuthClient = oauth_client.Client;
/// Storages for the registration and the tokens of `OAuthClient`.
pub const token_storage = @import("auth/token_storage.zig");
pub const TokenStorage = token_storage.TokenStorage;
pub const MemoryTokenStorage = token_storage.MemoryTokenStorage;
pub const FileTokenStorage = token_storage.FileTokenStorage;
/// Token storage in the keychain of the host: the Credential Manager, Keychain Services or
/// the Secret Service.
pub const keychain = @import("auth/keychain.zig");
pub const KeychainTokenStorage = keychain.KeychainTokenStorage;
/// The OAuth Client Credentials extension.
pub const client_credentials = @import("auth/client_credentials.zig");
pub const ClientCredentials = client_credentials.ClientCredentials;
/// The Enterprise-Managed Authorization extension.
pub const enterprise = @import("auth/enterprise.zig");
pub const EnterpriseClient = enterprise.EnterpriseClient;
pub const IdJagValidator = enterprise.IdJagValidator;
/// DPoP (RFC 9449): access tokens that only the holder of a key can use.
pub const dpop = @import("auth/dpop.zig");
pub const DpopProver = dpop.Prover;
/// Workload identity federation: a workload JWT as an authorization grant.
pub const workload_identity = @import("auth/workload_identity.zig");
pub const WorkloadIdentity = workload_identity.WorkloadIdentity;
pub const WorkloadJwtValidator = workload_identity.WorkloadJwtValidator;
pub const jwt = @import("auth/jwt.zig");
pub const resource_server = @import("auth/resource_server.zig");
pub const ResourceServer = resource_server.ResourceServer;
pub const Principal = resource_server.Principal;
pub const JwtVerifier = resource_server.JwtVerifier;
pub const DpopPolicy = resource_server.DpopPolicy;
/// The OAuth 2.1 authorization server for MCP deployments.
pub const authorization_server = @import("auth/authorization_server.zig");
pub const AuthorizationServer = authorization_server.AuthorizationServer;
/// The storage interface of the authorization server and its memory store.
pub const authorization_store = @import("auth/authorization_store.zig");
/// The fetcher of client ID metadata documents and of the JWK sets of clients.
pub const client_metadata = @import("auth/client_metadata.zig");

/// Return a copy of `capabilities` that declares the extension `id` under `extensions`. The
/// copy keeps the extensions that `capabilities` declares already. The new map is in `arena`.
pub fn withExtension(arena: std.mem.Allocator, capabilities: types.ClientCapabilities, id: []const u8) std.mem.Allocator.Error!types.ClientCapabilities {
    var ext: std.json.ObjectMap = .empty;
    if (capabilities.extensions) |existing| if (existing == .object) {
        var it = existing.object.iterator();
        while (it.next()) |kv| try ext.put(arena, kv.key_ptr.*, kv.value_ptr.*);
    };
    if (ext.get(id) == null) try ext.put(arena, id, .{ .object = .empty });
    var out = capabilities;
    out.extensions = .{ .object = ext };
    return out;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("auth/extensions_test.zig");
    _ = @import("auth/authorization_server_test.zig");
}

test "declare an extension" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const first = try withExtension(arena, .{ .roots = .{} }, client_credentials.extension_id);
    const both = try withExtension(arena, first, enterprise.extension_id);
    try std.testing.expect(both.hasExtension(client_credentials.extension_id));
    try std.testing.expect(both.hasExtension(enterprise.extension_id));
    try std.testing.expect(both.roots != null);
    try std.testing.expect(!first.hasExtension(enterprise.extension_id));
}
