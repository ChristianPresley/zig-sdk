//! Authorization: the OAuth 2.1 client used by the HTTP client transport.
pub const oauth_client = @import("auth/oauth_client.zig");
pub const OAuthClient = oauth_client.Client;

test {
    @import("std").testing.refAllDecls(@This());
}
