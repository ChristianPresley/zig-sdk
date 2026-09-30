//! The examples of RFC 7541 appendix C, extracted from the RFC text under the IETF Trust
//! Legal Provisions, see THIRD_PARTY_LICENSES.md. Each sequence shares one decoder. The
//! response sequences run with a table size of 256.
pub const Header = struct { name: []const u8, value: []const u8 };
pub const TableEntry = struct { size: u32, name: []const u8, value: []const u8 };
pub const Example = struct {
    section: []const u8,
    hex: []const u8,
    headers: []const Header,
    table: []const TableEntry,
    table_size: u32,
};
pub const examples = [_]Example{
    .{
        .section = "C.2.1",
        .hex = "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
        .headers = &.{
            .{ .name = "custom-key", .value = "custom-header" },
        },
        .table = &.{
            .{ .size = 55, .name = "custom-key", .value = "custom-header" },
        },
        .table_size = 55,
    },
    .{
        .section = "C.2.2",
        .hex = "040c2f73616d706c652f70617468",
        .headers = &.{
            .{ .name = ":path", .value = "/sample/path" },
        },
        .table = &.{},
        .table_size = 0,
    },
    .{
        .section = "C.2.3",
        .hex = "100870617373776f726406736563726574",
        .headers = &.{
            .{ .name = "password", .value = "secret" },
        },
        .table = &.{},
        .table_size = 0,
    },
    .{
        .section = "C.2.4",
        .hex = "82",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
        },
        .table = &.{},
        .table_size = 0,
    },
    .{
        .section = "C.3.1",
        .hex = "828684410f7777772e6578616d706c652e636f6d",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table = &.{
            .{ .size = 57, .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 57,
    },
    .{
        .section = "C.3.2",
        .hex = "828684be58086e6f2d6361636865",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "cache-control", .value = "no-cache" },
        },
        .table = &.{
            .{ .size = 53, .name = "cache-control", .value = "no-cache" },
            .{ .size = 57, .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 110,
    },
    .{
        .section = "C.3.3",
        .hex = "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "custom-key", .value = "custom-value" },
        },
        .table = &.{
            .{ .size = 54, .name = "custom-key", .value = "custom-value" },
            .{ .size = 53, .name = "cache-control", .value = "no-cache" },
            .{ .size = 57, .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 164,
    },
    .{
        .section = "C.4.1",
        .hex = "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
        .table = &.{
            .{ .size = 57, .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 57,
    },
    .{
        .section = "C.4.2",
        .hex = "828684be5886a8eb10649cbf",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "cache-control", .value = "no-cache" },
        },
        .table = &.{
            .{ .size = 53, .name = "cache-control", .value = "no-cache" },
            .{ .size = 57, .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 110,
    },
    .{
        .section = "C.4.3",
        .hex = "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        .headers = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "custom-key", .value = "custom-value" },
        },
        .table = &.{
            .{ .size = 54, .name = "custom-key", .value = "custom-value" },
            .{ .size = 53, .name = "cache-control", .value = "no-cache" },
            .{ .size = 57, .name = ":authority", .value = "www.example.com" },
        },
        .table_size = 164,
    },
    .{
        .section = "C.5.1",
        .hex = "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        .headers = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .size = 63, .name = "location", .value = "https://www.example.com" },
            .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .size = 52, .name = "cache-control", .value = "private" },
            .{ .size = 42, .name = ":status", .value = "302" },
        },
        .table_size = 222,
    },
    .{
        .section = "C.5.2",
        .hex = "4803333037c1c0bf",
        .headers = &.{
            .{ .name = ":status", .value = "307" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .size = 42, .name = ":status", .value = "307" },
            .{ .size = 63, .name = "location", .value = "https://www.example.com" },
            .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .size = 52, .name = "cache-control", .value = "private" },
        },
        .table_size = 222,
    },
    .{
        .section = "C.5.3",
        .hex = "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        .headers = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
        },
        .table = &.{
            .{ .size = 98, .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
            .{ .size = 52, .name = "content-encoding", .value = "gzip" },
            .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        },
        .table_size = 215,
    },
    .{
        .section = "C.6.1",
        .hex = "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        .headers = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .size = 63, .name = "location", .value = "https://www.example.com" },
            .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .size = 52, .name = "cache-control", .value = "private" },
            .{ .size = 42, .name = ":status", .value = "302" },
        },
        .table_size = 222,
    },
    .{
        .section = "C.6.2",
        .hex = "4883640effc1c0bf",
        .headers = &.{
            .{ .name = ":status", .value = "307" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
        .table = &.{
            .{ .size = 42, .name = ":status", .value = "307" },
            .{ .size = 63, .name = "location", .value = "https://www.example.com" },
            .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .size = 52, .name = "cache-control", .value = "private" },
        },
        .table_size = 222,
    },
    .{
        .section = "C.6.3",
        .hex = "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        .headers = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
        },
        .table = &.{
            .{ .size = 98, .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
            .{ .size = 52, .name = "content-encoding", .value = "gzip" },
            .{ .size = 65, .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        },
        .table_size = 215,
    },
};
