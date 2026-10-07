//! Newline-delimited message framing over `std.Io.Reader`, as used by the stdio transport
//! and by custom byte-stream transports.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Error = error{
    /// A line exceeded the configured maximum.
    LineTooLong,
    /// The line contains bytes that are not valid UTF-8.
    InvalidUtf8,
    /// The line contains a control character outside a JSON string context.
    ControlCharacter,
    ReadFailed,
    EndOfStream,
    OutOfMemory,
};

pub const Framer = struct {
    reader: *Io.Reader,
    max_line_bytes: usize,
    /// The top-level members of the last line that `next` dropped with `error.LineTooLong` or
    /// `error.InvalidUtf8`. The framer reads the whole line, also the part after the limit. A
    /// client uses it to find the request of the line.
    dropped: TopLevelScanner = .{},

    /// Read the next non-blank line into `arena`. The reader removes a trailing `\r`. Returns
    /// `error.EndOfStream` when the stream ended without a complete line.
    pub fn next(self: *Framer, arena: Allocator) Error![]u8 {
        self.dropped = .{};
        while (true) {
            const raw = try self.readLine(arena);
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (isBlank(line)) continue;
            if (!std.unicode.utf8ValidateSlice(line)) {
                self.dropped.feed(line);
                return error.InvalidUtf8;
            }
            return @constCast(line);
        }
    }

    fn readLine(self: *Framer, arena: Allocator) Error![]u8 {
        // Fast path: the whole line is already in (or fits into) the reader buffer.
        if (self.reader.takeDelimiterExclusive('\n')) |line| {
            if (line.len > self.max_line_bytes) {
                self.dropped.feed(line);
                return error.LineTooLong;
            }
            // At the end of the stream the last line comes without its delimiter.
            if (self.reader.bufferedLen() > 0 and self.reader.buffered()[0] == '\n') self.reader.toss(1);
            return try arena.dupe(u8, line);
        } else |e| switch (e) {
            error.StreamTooLong => {},
            error.EndOfStream => {
                // The stream ended without a newline. Accept the remaining bytes as a line.
                const rest = self.reader.buffered();
                if (rest.len == 0) return error.EndOfStream;
                const copy = try arena.dupe(u8, rest);
                self.reader.toss(rest.len);
                return copy;
            },
            error.ReadFailed => return error.ReadFailed,
        }
        // Slow path: accumulate into a growing buffer bounded by the limit.
        var aw: Io.Writer.Allocating = .init(arena);
        const limit: Io.Limit = .limited(self.max_line_bytes + 1);
        _ = self.reader.streamDelimiterLimit(&aw.writer, '\n', limit) catch |e| switch (e) {
            error.StreamTooLong => {
                // Skip the rest of the line. Else its tail becomes the next frame.
                self.dropped.feed(aw.written());
                try self.skipLine();
                return error.LineTooLong;
            },
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
        };
        // Either the delimiter is next, or the stream ended.
        if (self.reader.peekByte()) |_| {
            self.reader.toss(1);
        } else |_| {
            if (aw.written().len == 0) return error.EndOfStream;
        }
        if (aw.written().len > self.max_line_bytes) {
            self.dropped.feed(aw.written());
            return error.LineTooLong;
        }
        return aw.written();
    }

    /// Discard the bytes up to the next newline and the newline. `dropped` reads them in the
    /// reader buffer, thus the memory does not grow with the length of the line.
    fn skipLine(self: *Framer) error{ReadFailed}!void {
        while (true) {
            const bytes = self.reader.buffered();
            if (std.mem.findScalar(u8, bytes, '\n')) |end| {
                self.dropped.feed(bytes[0..end]);
                self.reader.toss(end + 1);
                return;
            }
            self.dropped.feed(bytes);
            self.reader.tossBuffered();
            self.reader.fillMore() catch |e| switch (e) {
                error.EndOfStream => return,
                error.ReadFailed => return error.ReadFailed,
            };
        }
    }

    fn isBlank(line: []const u8) bool {
        for (line) |c| if (c != ' ' and c != '\t') return false;
        return true;
    }
};

/// Finds the top-level members "id", "method", "result" and "error" of a JSON object. It
/// reads the text in parts with fixed memory, thus it can read a line of any length. A client
/// uses it to find the request of a frame that it cannot parse.
///
/// The scanner does not check the syntax or the UTF-8 of the text. A key with an escape
/// sequence does not count. When the text is not an object, or when the scanner finds a
/// syntax error, it stops and keeps the members that it found before.
pub const TopLevelScanner = struct {
    /// True when the object has a top-level "method" member.
    method: bool = false,
    /// True when the object has a top-level "result" or "error" member.
    response: bool = false,
    id_buf: [max_id_bytes]u8 = undefined,
    id_len: usize = 0,
    id_state: IdState = .absent,
    state: State = .start,
    key_buf: [max_key_bytes]u8 = undefined,
    key_len: usize = 0,
    /// True when the current key has an escape sequence or more than `max_key_bytes` bytes.
    key_other: bool = false,
    /// True when the current value is the value of "id".
    capture: bool = false,
    /// True after a backslash in a string.
    escape: bool = false,
    /// True in a string of a nested value.
    nested_string: bool = false,
    /// The nesting depth in a value of the top level.
    depth: u32 = 0,

    /// The longest "id" value that the scanner keeps.
    pub const max_id_bytes = 128;
    const max_key_bytes = 8;

    const IdState = enum { absent, partial, found, unusable };
    const State = enum { start, key, key_string, colon, value, string_value, scalar_value, nested, after_value, done, stopped };

    /// The raw text of the top-level "id" value, for example `7`, `"a"` or `null`. It is null
    /// when the object has no such member, or when the value is an object, an array, longer
    /// than `max_id_bytes`, or not complete.
    pub fn id(self: *const TopLevelScanner) ?[]const u8 {
        return if (self.id_state == .found) self.id_buf[0..self.id_len] else null;
    }

    /// Read the next part of the text.
    pub fn feed(self: *TopLevelScanner, bytes: []const u8) void {
        for (bytes) |c| switch (self.state) {
            .done, .stopped => return,
            .start => switch (c) {
                ' ', '\t', '\r', '\n' => {},
                '{' => self.state = .key,
                else => self.state = .stopped,
            },
            .key => switch (c) {
                ' ', '\t', '\r', '\n', ',' => {},
                '"' => {
                    self.key_len = 0;
                    self.key_other = false;
                    self.state = .key_string;
                },
                '}' => self.state = .done,
                else => self.state = .stopped,
            },
            .key_string => if (self.escape) {
                self.escape = false;
            } else switch (c) {
                '\\' => {
                    self.escape = true;
                    self.key_other = true;
                },
                '"' => self.state = .colon,
                else => if (self.key_len < max_key_bytes) {
                    self.key_buf[self.key_len] = c;
                    self.key_len += 1;
                } else {
                    self.key_other = true;
                },
            },
            .colon => switch (c) {
                ' ', '\t', '\r', '\n' => {},
                ':' => {
                    self.startValue();
                    self.state = .value;
                },
                else => self.state = .stopped,
            },
            .value => switch (c) {
                ' ', '\t', '\r', '\n' => {},
                '"' => {
                    self.keep(c);
                    self.state = .string_value;
                },
                '{', '[' => {
                    if (self.capture) self.id_state = .unusable;
                    self.capture = false;
                    self.depth = 1;
                    self.state = .nested;
                },
                ',', ':', '}', ']' => self.state = .stopped,
                else => {
                    self.keep(c);
                    self.state = .scalar_value;
                },
            },
            .string_value => {
                self.keep(c);
                if (self.escape) {
                    self.escape = false;
                } else if (c == '\\') {
                    self.escape = true;
                } else if (c == '"') {
                    self.endValue();
                    self.state = .after_value;
                }
            },
            .scalar_value => switch (c) {
                ' ', '\t', '\r', '\n' => {
                    self.endValue();
                    self.state = .after_value;
                },
                ',' => {
                    self.endValue();
                    self.state = .key;
                },
                '}' => {
                    self.endValue();
                    self.state = .done;
                },
                else => self.keep(c),
            },
            .nested => if (self.nested_string) {
                if (self.escape) {
                    self.escape = false;
                } else if (c == '\\') {
                    self.escape = true;
                } else if (c == '"') {
                    self.nested_string = false;
                }
            } else switch (c) {
                '"' => self.nested_string = true,
                '{', '[' => self.depth +|= 1,
                '}', ']' => {
                    self.depth -= 1;
                    if (self.depth == 0) self.state = .after_value;
                },
                else => {},
            },
            .after_value => switch (c) {
                ' ', '\t', '\r', '\n' => {},
                ',' => self.state = .key,
                '}' => self.state = .done,
                else => self.state = .stopped,
            },
        };
    }

    fn startValue(self: *TopLevelScanner) void {
        if (self.key_other) return;
        const key = self.key_buf[0..self.key_len];
        if (std.mem.eql(u8, key, "id")) {
            // A later "id" member replaces an earlier one, as in the parser.
            self.capture = true;
            self.id_len = 0;
            self.id_state = .partial;
        } else if (std.mem.eql(u8, key, "method")) {
            self.method = true;
        } else if (std.mem.eql(u8, key, "result") or std.mem.eql(u8, key, "error")) {
            self.response = true;
        }
    }

    fn keep(self: *TopLevelScanner, c: u8) void {
        if (!self.capture) return;
        if (self.id_len == max_id_bytes) {
            self.id_state = .unusable;
            self.capture = false;
            return;
        }
        self.id_buf[self.id_len] = c;
        self.id_len += 1;
    }

    fn endValue(self: *TopLevelScanner) void {
        if (self.capture) self.id_state = .found;
        self.capture = false;
    }
};

/// Write one framed message: `text` followed by a newline. `text` must not contain a raw
/// newline. Minified JSON never does.
pub fn writeFrame(writer: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    std.debug.assert(std.mem.findScalar(u8, text, '\n') == null);
    try writer.writeAll(text);
    try writer.writeByte('\n');
    try writer.flush();
}

test "framer reads lines, skips blanks, strips CR" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var reader: Io.Reader = .fixed("{\"a\":1}\r\n\n  \n{\"b\":2}\nlast");
    var framer: Framer = .{ .reader = &reader, .max_line_bytes = 1024 };
    try std.testing.expectEqualStrings("{\"a\":1}", try framer.next(arena));
    try std.testing.expectEqualStrings("{\"b\":2}", try framer.next(arena));
    try std.testing.expectEqualStrings("last", try framer.next(arena));
    try std.testing.expectError(error.EndOfStream, framer.next(arena));
}

test "framer enforces the line limit on both paths" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const long = "x" ** 300;
    var small_buf: [16]u8 = undefined;
    var fixed: Io.Reader = .fixed(long ++ "\nok\n");
    // Route through a limited reader with a small buffer so the slow path is taken.
    var limited = fixed.limited(.unlimited, &small_buf);
    var framer: Framer = .{ .reader = &limited.interface, .max_line_bytes = 100 };
    try std.testing.expectError(error.LineTooLong, framer.next(arena));
}

test "framer skips the whole oversize line" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const long = "x" ** 300;
    var small_buf: [16]u8 = undefined;
    var fixed: Io.Reader = .fixed(long ++ "\nok\n" ++ long);
    var limited = fixed.limited(.unlimited, &small_buf);
    var framer: Framer = .{ .reader = &limited.interface, .max_line_bytes = 100 };
    try std.testing.expectError(error.LineTooLong, framer.next(arena));
    try std.testing.expectEqualStrings("ok", try framer.next(arena));
    try std.testing.expectError(error.LineTooLong, framer.next(arena));
    try std.testing.expectError(error.EndOfStream, framer.next(arena));
}

test "framer rejects invalid UTF-8" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var reader: Io.Reader = .fixed("\xff\xfe\n");
    var framer: Framer = .{ .reader = &reader, .max_line_bytes = 1024 };
    try std.testing.expectError(error.InvalidUtf8, framer.next(arena));
}

test "the scanner finds the top-level id after the result, in parts of any size" {
    const text = "{\"jsonrpc\":\"2.0\",\"result\":{\"id\":99,\"items\":[{\"id\":\"x\"},\"}\\\"{\"]},\"id\":7}";
    for (1..text.len + 1) |part| {
        var scanner: TopLevelScanner = .{};
        var rest: []const u8 = text;
        while (rest.len > 0) {
            const n = @min(part, rest.len);
            scanner.feed(rest[0..n]);
            rest = rest[n..];
        }
        try std.testing.expectEqualStrings("7", scanner.id().?);
        try std.testing.expect(scanner.response);
        try std.testing.expect(!scanner.method);
    }
}

test "the scanner keeps a string id with its quotes and escape sequences" {
    var scanner: TopLevelScanner = .{};
    scanner.feed("{ \"id\" : \"a\\\"b\" , \"error\":{\"code\":-32603,\"message\":\"x\"} }");
    try std.testing.expectEqualStrings("\"a\\\"b\"", scanner.id().?);
    try std.testing.expect(scanner.response);

    scanner = .{};
    scanner.feed("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{}}");
    try std.testing.expectEqualStrings("null", scanner.id().?);
}

test "the scanner finds the method and no id of a notification" {
    var scanner: TopLevelScanner = .{};
    scanner.feed("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"id\":1,\"progressToken\":1}}");
    try std.testing.expect(scanner.method);
    try std.testing.expect(!scanner.response);
    try std.testing.expect(scanner.id() == null);
}

test "the scanner gives no id for a value that it cannot keep" {
    const cases = [_][]const u8{
        // An object or an array.
        "{\"id\":{\"a\":1},\"result\":{}}",
        "{\"id\":[1],\"result\":{}}",
        // Longer than the buffer.
        "{\"id\":\"" ++ "x" ** TopLevelScanner.max_id_bytes ++ "\",\"result\":{}}",
        // The text ends in the value.
        "{\"result\":{},\"id\":12",
        // A key with an escape sequence does not count.
        "{\"\\" ++ "u0069d\":1,\"result\":{}}",
        // The text is not an object.
        "[{\"id\":1,\"result\":{}}]",
        "server started",
    };
    for (cases) |text| {
        var scanner: TopLevelScanner = .{};
        scanner.feed(text);
        try std.testing.expect(scanner.id() == null);
    }
    // A syntax error stops the scanner. The members before the error count.
    var scanner: TopLevelScanner = .{};
    scanner.feed("{\"id\":3,\"result\":{} \"id\":4}");
    try std.testing.expectEqualStrings("3", scanner.id().?);
    try std.testing.expect(scanner.response);
}

test "framer finds the id of a dropped line on both paths and of a line that is not UTF-8" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const long = "{\"jsonrpc\":\"2.0\",\"result\":{\"text\":\"" ++ "x" ** 300 ++ "\"},\"id\":42}";
    const input = long ++ "\n{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"text\":\"\xff\"}}\nok\n";

    // The fast path: the whole line is in the reader buffer.
    var fixed: Io.Reader = .fixed(input);
    var framer: Framer = .{ .reader = &fixed, .max_line_bytes = 100 };
    try std.testing.expectError(error.LineTooLong, framer.next(arena));
    try std.testing.expectEqualStrings("42", framer.dropped.id().?);
    try std.testing.expectError(error.InvalidUtf8, framer.next(arena));
    try std.testing.expectEqualStrings("5", framer.dropped.id().?);
    try std.testing.expectEqualStrings("ok", try framer.next(arena));
    try std.testing.expect(framer.dropped.id() == null);

    // The slow path: the scanner reads the tail of the line in the small reader buffer.
    var small_buf: [16]u8 = undefined;
    var source: Io.Reader = .fixed(input);
    var limited = source.limited(.unlimited, &small_buf);
    framer = .{ .reader = &limited.interface, .max_line_bytes = 100 };
    try std.testing.expectError(error.LineTooLong, framer.next(arena));
    try std.testing.expectEqualStrings("42", framer.dropped.id().?);
    try std.testing.expect(framer.dropped.response);
    try std.testing.expectError(error.InvalidUtf8, framer.next(arena));
    try std.testing.expectEqualStrings("5", framer.dropped.id().?);
    try std.testing.expectEqualStrings("ok", try framer.next(arena));
    try std.testing.expectError(error.EndOfStream, framer.next(arena));
}
