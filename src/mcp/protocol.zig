//! Protocol layer: version table, schema types, method table, errors and `_meta` handling.
pub const version = @import("protocol/version.zig");
pub const types = @import("protocol/types.zig");
pub const errors = @import("protocol/errors.zig");
pub const meta = @import("protocol/meta.zig");
pub const methods = @import("protocol/methods.zig");
pub const export_map = @import("protocol/export_map.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
