//! Authorization: the OAuth 2.1 client of the HTTP client transport, and the resource server
//! helpers of the HTTP server.
pub const oauth_client = @import("auth/oauth_client.zig");
pub const OAuthClient = oauth_client.Client;
pub const jwt = @import("auth/jwt.zig");
pub const resource_server = @import("auth/resource_server.zig");
pub const ResourceServer = resource_server.ResourceServer;
pub const Principal = resource_server.Principal;
pub const JwtVerifier = resource_server.JwtVerifier;

test {
    @import("std").testing.refAllDecls(@This());
}
