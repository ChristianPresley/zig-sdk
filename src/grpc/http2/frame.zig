//! HTTP/2 frame headers, types, flags, error codes and settings identifiers (RFC 9113
//! sections 4, 6 and 7).
const std = @import("std");
const Io = std.Io;

pub const header_len = 9;
pub const default_max_frame_size: u32 = 16384;
pub const max_allowed_frame_size: u32 = (1 << 24) - 1;
pub const default_initial_window: u32 = 65535;
pub const max_window: u32 = (1 << 31) - 1;
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const Type = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const Flags = struct {
    pub const end_stream: u8 = 0x1;
    pub const ack: u8 = 0x1;
    pub const end_headers: u8 = 0x4;
    pub const padded: u8 = 0x8;
    pub const priority: u8 = 0x20;
};

pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

pub const Header = struct {
    length: u24,
    type: Type,
    flags: u8,
    stream_id: u31,

    pub fn parse(bytes: *const [header_len]u8) Header {
        return .{
            .length = std.mem.readInt(u24, bytes[0..3], .big),
            .type = @enumFromInt(bytes[3]),
            .flags = bytes[4],
            .stream_id = @truncate(std.mem.readInt(u32, bytes[5..9], .big) & 0x7fff_ffff),
        };
    }

    pub fn encode(self: Header) [header_len]u8 {
        var out: [header_len]u8 = undefined;
        std.mem.writeInt(u24, out[0..3], self.length, .big);
        out[3] = @intFromEnum(self.type);
        out[4] = self.flags;
        std.mem.writeInt(u32, out[5..9], self.stream_id, .big);
        return out;
    }

    pub fn has(self: Header, flag: u8) bool {
        return self.flags & flag != 0;
    }
};

/// One setting on the wire.
pub const Setting = struct {
    id: u16,
    value: u32,

    pub fn encode(self: Setting) [6]u8 {
        var out: [6]u8 = undefined;
        std.mem.writeInt(u16, out[0..2], self.id, .big);
        std.mem.writeInt(u32, out[2..6], self.value, .big);
        return out;
    }
};

/// The settings of one side, with the defaults of RFC 9113 section 6.5.2.
pub const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: ?u32 = null,
    initial_window_size: u32 = default_initial_window,
    max_frame_size: u32 = default_max_frame_size,
    max_header_list_size: ?u32 = null,

    pub const ApplyError = error{ FlowControlError, ProtocolError };

    /// Apply one received setting.
    pub fn apply(self: *Settings, setting: Setting) ApplyError!void {
        switch (@as(SettingId, @enumFromInt(setting.id))) {
            .header_table_size => self.header_table_size = setting.value,
            .enable_push => {
                if (setting.value > 1) return error.ProtocolError;
                self.enable_push = setting.value == 1;
            },
            .max_concurrent_streams => self.max_concurrent_streams = setting.value,
            .initial_window_size => {
                if (setting.value > max_window) return error.FlowControlError;
                self.initial_window_size = setting.value;
            },
            .max_frame_size => {
                if (setting.value < default_max_frame_size or setting.value > max_allowed_frame_size) return error.ProtocolError;
                self.max_frame_size = setting.value;
            },
            .max_header_list_size => self.max_header_list_size = setting.value,
            _ => {}, // unknown settings are ignored
        }
    }
};

test "header round trip" {
    const h: Header = .{ .length = 300, .type = .headers, .flags = Flags.end_headers | Flags.end_stream, .stream_id = 7 };
    const bytes = h.encode();
    const back = Header.parse(&bytes);
    try std.testing.expectEqual(h, back);
    try std.testing.expect(back.has(Flags.end_stream));
    try std.testing.expect(!back.has(Flags.padded));
    // The reserved bit is dropped.
    var with_reserved = bytes;
    with_reserved[5] |= 0x80;
    try std.testing.expectEqual(7, Header.parse(&with_reserved).stream_id);
}

test "settings limits" {
    var s: Settings = .{};
    try s.apply(.{ .id = 4, .value = 1 << 20 });
    try std.testing.expectEqual(1 << 20, s.initial_window_size);
    try std.testing.expectError(error.FlowControlError, s.apply(.{ .id = 4, .value = 1 << 31 }));
    try std.testing.expectError(error.ProtocolError, s.apply(.{ .id = 5, .value = 100 }));
    try std.testing.expectError(error.ProtocolError, s.apply(.{ .id = 2, .value = 2 }));
    try s.apply(.{ .id = 0x99, .value = 5 });
}
