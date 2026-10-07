//! Server-sent events: an incremental parser per the WHATWG HTML standard and an event writer.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const content_type = "text/event-stream";

/// Write one event whose data is `data`. `data` must not contain a raw newline.
pub fn writeEvent(writer: *Io.Writer, data: []const u8) Io.Writer.Error!void {
    try writer.writeAll("event: message\ndata: ");
    try writer.writeAll(data);
    try writer.writeAll("\n\n");
}

/// Write a comment line, used as keep-alive.
pub fn writeComment(writer: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    try writer.writeAll(": ");
    try writer.writeAll(text);
    try writer.writeAll("\n\n");
}

pub const Event = struct {
    event: []const u8,
    data: []const u8,
    id: ?[]const u8,
};

/// Incremental parser. Feed bytes with `feed`, take events with `next`.
pub const Parser = struct {
    gpa: Allocator,
    /// Maximum bytes of the event that the parser reads, across all calls of `feed`. The bytes
    /// are the line that the parser reads with its field name, and the data and the event type
    /// of the event. Only the event that the parser reads counts, thus a stream of many small
    /// events and comments has no limit. Overflow: `feed` returns `error.EventTooLarge`.
    max_event_bytes: usize = 4 << 20,
    pending: std.ArrayList(u8) = .empty,
    data: std.ArrayList(u8) = .empty,
    event_type: std.ArrayList(u8) = .empty,
    last_id: std.ArrayList(u8) = .empty,
    bom_checked: bool = false,
    saw_cr: bool = false,
    ready: std.ArrayList(Event) = .empty,

    pub fn init(gpa: Allocator) Parser {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Parser) void {
        self.pending.deinit(self.gpa);
        self.data.deinit(self.gpa);
        self.event_type.deinit(self.gpa);
        self.last_id.deinit(self.gpa);
        for (self.ready.items) |e| self.freeEvent(e);
        self.ready.deinit(self.gpa);
    }

    fn freeEvent(self: *Parser, e: Event) void {
        self.gpa.free(e.event);
        self.gpa.free(e.data);
        if (e.id) |id| self.gpa.free(id);
    }

    /// The errors of `feed`.
    pub const FeedError = Allocator.Error || error{
        /// The event that the parser reads has more than `max_event_bytes`.
        EventTooLarge,
    };

    /// Feed a chunk of bytes. Complete events become available through `next`. When an event
    /// gets more than `max_event_bytes`, `feed` returns `error.EventTooLarge`. The events
    /// before it stay available through `next`. Do not feed more bytes after an error.
    pub fn feed(self: *Parser, bytes: []const u8) FeedError!void {
        var input = bytes;
        if (!self.bom_checked) {
            self.bom_checked = true;
            if (std.mem.startsWith(u8, input, "\xEF\xBB\xBF")) input = input[3..];
        }
        for (input) |c| {
            if (self.saw_cr) {
                self.saw_cr = false;
                if (c == '\n') continue;
            }
            if (c == '\r' or c == '\n') {
                if (c == '\r') self.saw_cr = true;
                try self.processLine();
                self.pending.clearRetainingCapacity();
            } else {
                // The end of a line makes the event shorter: the data and the event type get
                // fewer bytes than the line. Thus this check keeps the event in the limit.
                if (self.eventBytes() >= self.max_event_bytes) return error.EventTooLarge;
                try self.pending.append(self.gpa, c);
            }
        }
    }

    /// The bytes of the event that the parser reads.
    fn eventBytes(self: *const Parser) usize {
        return self.pending.items.len + self.data.items.len + self.event_type.items.len;
    }

    /// Take the next complete event. The caller owns the returned slices and frees them with
    /// `release`.
    pub fn next(self: *Parser) ?Event {
        if (self.ready.items.len == 0) return null;
        return self.ready.orderedRemove(0);
    }

    pub fn release(self: *Parser, e: Event) void {
        self.freeEvent(e);
    }

    fn processLine(self: *Parser) Allocator.Error!void {
        const line = self.pending.items;
        if (line.len == 0) return self.dispatch();
        if (line[0] == ':') return;
        var field = line;
        var value: []const u8 = "";
        if (std.mem.findScalar(u8, line, ':')) |i| {
            field = line[0..i];
            value = line[i + 1 ..];
            if (value.len > 0 and value[0] == ' ') value = value[1..];
        }
        if (std.mem.eql(u8, field, "event")) {
            self.event_type.clearRetainingCapacity();
            try self.event_type.appendSlice(self.gpa, value);
        } else if (std.mem.eql(u8, field, "data")) {
            try self.data.appendSlice(self.gpa, value);
            try self.data.append(self.gpa, '\n');
        } else if (std.mem.eql(u8, field, "id")) {
            if (std.mem.findScalar(u8, value, 0) == null) {
                self.last_id.clearRetainingCapacity();
                try self.last_id.appendSlice(self.gpa, value);
            }
        }
        // `retry` and unknown fields are ignored: MCP does not use resumption.
    }

    fn dispatch(self: *Parser) Allocator.Error!void {
        if (self.data.items.len == 0) {
            self.event_type.clearRetainingCapacity();
            return;
        }
        var data = self.data.items;
        if (data[data.len - 1] == '\n') data = data[0 .. data.len - 1];
        const event_name: []const u8 = if (self.event_type.items.len == 0) "message" else self.event_type.items;
        const e: Event = .{
            .event = try self.gpa.dupe(u8, event_name),
            .data = try self.gpa.dupe(u8, data),
            .id = if (self.last_id.items.len > 0) try self.gpa.dupe(u8, self.last_id.items) else null,
        };
        try self.ready.append(self.gpa, e);
        self.data.clearRetainingCapacity();
        self.event_type.clearRetainingCapacity();
    }
};

test "parser joins data lines, strips one space, handles CRLF split across feeds" {
    const gpa = std.testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    try p.feed("\xEF\xBB\xBF: comment\r");
    try p.feed("\ndata: a\r\ndata:b\n\nevent: custom\ndata: x\n\n");
    const first = p.next().?;
    defer p.release(first);
    try std.testing.expectEqualStrings("message", first.event);
    try std.testing.expectEqualStrings("a\nb", first.data);
    const second = p.next().?;
    defer p.release(second);
    try std.testing.expectEqualStrings("custom", second.event);
    try std.testing.expectEqualStrings("x", second.data);
    try std.testing.expect(p.next() == null);
}

test "empty data produces no event" {
    const gpa = std.testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    try p.feed("event: ping\n\nid: 7\ndata: y\n\n");
    const e = p.next().?;
    defer p.release(e);
    try std.testing.expectEqualStrings("y", e.data);
    try std.testing.expectEqualStrings("7", e.id.?);
}

test "parser rejects an event over max_event_bytes that comes in many feeds" {
    const gpa = std.testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    p.max_event_bytes = 16;
    // An event of 16 bytes is in the limit.
    try p.feed("data: 0123456789\n\n");
    // The event type counts: 8 bytes of type and the 8 bytes of "data: 01" are in the limit.
    try p.feed("event: abcdefgh\ndata: 01\n\n");
    try p.feed("data: 01234");
    try p.feed("56789\n");
    // The data has 11 bytes now ("0123456789\n"), thus the sixth byte of the next line is over
    // the limit.
    try std.testing.expectError(error.EventTooLarge, p.feed("data: x"));
    // The complete events before the large event stay available.
    const first = p.next().?;
    defer p.release(first);
    try std.testing.expectEqualStrings("0123456789", first.data);
    const second = p.next().?;
    defer p.release(second);
    try std.testing.expectEqualStrings("abcdefgh", second.event);
    try std.testing.expectEqualStrings("01", second.data);
    try std.testing.expect(p.next() == null);

    // The same event type with one more byte of data is over the limit.
    var q: Parser = .init(gpa);
    defer q.deinit();
    q.max_event_bytes = 16;
    try std.testing.expectError(error.EventTooLarge, q.feed("event: abcdefgh\ndata: 012"));
}

test "parser accepts many small events and comments with more bytes than max_event_bytes in total" {
    const gpa = std.testing.allocator;
    var p: Parser = .init(gpa);
    defer p.deinit();
    p.max_event_bytes = 32;
    const count = 1000;
    var got: usize = 0;
    for (0..count) |i| {
        var buf: [64]u8 = undefined;
        const chunk = try std.fmt.bufPrint(&buf, ": keepalive\n\nevent: message\ndata: {d}\n\n", .{i});
        // Two feeds for each chunk, thus the lines split across feeds.
        try p.feed(chunk[0 .. chunk.len / 2]);
        try p.feed(chunk[chunk.len / 2 ..]);
        while (p.next()) |e| {
            defer p.release(e);
            var want: [16]u8 = undefined;
            try std.testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{d}", .{got}), e.data);
            got += 1;
        }
    }
    try std.testing.expectEqual(count, got);
}

test "writer output" {
    const gpa = std.testing.allocator;
    var aw: Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeEvent(&aw.writer, "{\"a\":1}");
    try writeComment(&aw.writer, "keepalive");
    try std.testing.expectEqualStrings("event: message\ndata: {\"a\":1}\n\n: keepalive\n\n", aw.written());
}
