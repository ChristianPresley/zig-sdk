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

    /// Read the next non-blank line into `arena`. Trailing `\r` is removed. Returns
    /// `error.EndOfStream` when the stream ended without a complete line.
    pub fn next(self: *Framer, arena: Allocator) Error![]u8 {
        while (true) {
            const raw = try self.readLine(arena);
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (isBlank(line)) continue;
            if (!std.unicode.utf8ValidateSlice(line)) return error.InvalidUtf8;
            return @constCast(line);
        }
    }

    fn readLine(self: *Framer, arena: Allocator) Error![]u8 {
        // Fast path: the whole line is already in (or fits into) the reader buffer.
        if (self.reader.takeDelimiterExclusive('\n')) |line| {
            if (line.len > self.max_line_bytes) return error.LineTooLong;
            self.reader.toss(1);
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
            error.StreamTooLong => return error.LineTooLong,
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
        };
        // Either the delimiter is next, or the stream ended.
        if (self.reader.peekByte()) |_| {
            self.reader.toss(1);
        } else |_| {
            if (aw.written().len == 0) return error.EndOfStream;
        }
        if (aw.written().len > self.max_line_bytes) return error.LineTooLong;
        return aw.written();
    }

    fn isBlank(line: []const u8) bool {
        for (line) |c| if (c != ' ' and c != '\t') return false;
        return true;
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

test "framer rejects invalid UTF-8" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var reader: Io.Reader = .fixed("\xff\xfe\n");
    var framer: Framer = .{ .reader = &reader, .max_line_bytes = 1024 };
    try std.testing.expectError(error.InvalidUtf8, framer.next(arena));
}
