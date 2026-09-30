//! RFC 6570 URI templates, the subset used by MCP resource templates: simple `{var}` and
//! reserved `{+var}` expressions with sequential, non-backtracking matching.
//! Path-based operators (`{/var}`, `{.var}`, `{#var}`, `{?var}`, `{&var}`) are parsed and
//! matched with their prefix literal. Explode and prefix modifiers are rejected.
const std = @import("std");
const Allocator = std.mem.Allocator;

const UriTemplate = @This();

pub const Operator = enum(u8) {
    simple = 0,
    reserved = '+',
    fragment = '#',
    label = '.',
    path = '/',
    query = '?',
    continuation = '&',

    fn prefix(self: Operator) []const u8 {
        return switch (self) {
            .simple, .reserved => "",
            .fragment => "#",
            .label => ".",
            .path => "/",
            .query => "?",
            .continuation => "&",
        };
    }
};

pub const Segment = union(enum) {
    literal: []const u8,
    expression: Expression,
};

pub const Expression = struct {
    operator: Operator,
    name: []const u8,
};

segments: []const Segment,
source: []const u8,

pub const ParseError = error{
    UnterminatedExpression,
    EmptyExpression,
    UnsupportedModifier,
    UnsupportedOperator,
    InvalidVariableName,
    TooManyExpressions,
    OutOfMemory,
};

pub fn parse(gpa: Allocator, source: []const u8, max_expressions: usize) ParseError!UriTemplate {
    var segments: std.ArrayList(Segment) = .empty;
    errdefer segments.deinit(gpa);
    var expressions: usize = 0;
    var i: usize = 0;
    var literal_start: usize = 0;
    while (i < source.len) {
        if (source[i] != '{') {
            i += 1;
            continue;
        }
        if (i > literal_start) try segments.append(gpa, .{ .literal = source[literal_start..i] });
        const close = std.mem.findScalarPos(u8, source, i, '}') orelse return error.UnterminatedExpression;
        var body = source[i + 1 .. close];
        if (body.len == 0) return error.EmptyExpression;
        var operator: Operator = .simple;
        switch (body[0]) {
            '+' => operator = .reserved,
            '#' => operator = .fragment,
            '.' => operator = .label,
            '/' => operator = .path,
            '?' => operator = .query,
            '&' => operator = .continuation,
            ';', '=', ',', '!', '@', '|' => return error.UnsupportedOperator,
            else => {},
        }
        if (operator != .simple) body = body[1..];
        if (body.len == 0) return error.EmptyExpression;
        if (std.mem.findScalar(u8, body, ',') != null) return error.UnsupportedModifier;
        if (std.mem.findScalar(u8, body, '*') != null or std.mem.findScalar(u8, body, ':') != null) return error.UnsupportedModifier;
        for (body) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '%')) return error.InvalidVariableName;
        }
        expressions += 1;
        if (expressions > max_expressions) return error.TooManyExpressions;
        try segments.append(gpa, .{ .expression = .{ .operator = operator, .name = body } });
        i = close + 1;
        literal_start = i;
    }
    if (literal_start < source.len) try segments.append(gpa, .{ .literal = source[literal_start..] });
    return .{ .segments = try segments.toOwnedSlice(gpa), .source = source };
}

pub fn deinit(self: *UriTemplate, gpa: Allocator) void {
    gpa.free(self.segments);
    self.* = undefined;
}

pub const Variable = struct {
    name: []const u8,
    value: []const u8,
};

/// Match `uri` against the template. On success the variables are filled from `uri` (slices
/// into `uri`, percent-encoded as they appear) and appended to `out`.
pub fn match(self: UriTemplate, uri: []const u8, out: *std.ArrayList(Variable), gpa: Allocator) Allocator.Error!bool {
    const start_len = out.items.len;
    errdefer out.shrinkRetainingCapacity(start_len);
    var pos: usize = 0;
    var i: usize = 0;
    while (i < self.segments.len) : (i += 1) {
        switch (self.segments[i]) {
            .literal => |lit| {
                if (!std.mem.startsWith(u8, uri[pos..], lit)) {
                    out.shrinkRetainingCapacity(start_len);
                    return false;
                }
                pos += lit.len;
            },
            .expression => |expr| {
                const prefix = expr.operator.prefix();
                if (prefix.len > 0) {
                    if (!std.mem.startsWith(u8, uri[pos..], prefix)) {
                        out.shrinkRetainingCapacity(start_len);
                        return false;
                    }
                    pos += prefix.len;
                }
                // The value ends at the next literal (or the end of the URI). Simple
                // expressions never consume the reserved characters they cannot encode.
                const next_literal: ?[]const u8 = if (i + 1 < self.segments.len and self.segments[i + 1] == .literal) self.segments[i + 1].literal else null;
                var end = uri.len;
                if (next_literal) |lit| {
                    end = std.mem.findPos(u8, uri, pos, lit) orelse {
                        out.shrinkRetainingCapacity(start_len);
                        return false;
                    };
                }
                const value = uri[pos..end];
                if (expr.operator == .simple or expr.operator == .label or expr.operator == .path) {
                    // Simple expansion stops at '/' (and '.' for labels).
                    for (value) |c| {
                        if (c == '/' or c == '?' or c == '#' or (expr.operator == .label and c == '.')) {
                            out.shrinkRetainingCapacity(start_len);
                            return false;
                        }
                    }
                }
                try out.append(gpa, .{ .name = expr.name, .value = value });
                pos = end;
            },
        }
    }
    if (pos != uri.len) {
        out.shrinkRetainingCapacity(start_len);
        return false;
    }
    return true;
}

/// True when the template has no expressions.
pub fn isLiteral(self: UriTemplate) bool {
    for (self.segments) |s| if (s == .expression) return false;
    return true;
}

test "parse and match simple templates" {
    const gpa = std.testing.allocator;
    var t = try parse(gpa, "test://template/{id}/data", 16);
    defer t.deinit(gpa);
    var vars: std.ArrayList(Variable) = .empty;
    defer vars.deinit(gpa);
    try std.testing.expect(try t.match("test://template/123/data", &vars, gpa));
    try std.testing.expectEqual(1, vars.items.len);
    try std.testing.expectEqualStrings("id", vars.items[0].name);
    try std.testing.expectEqualStrings("123", vars.items[0].value);
    try std.testing.expect(!try t.match("test://template/1/2/data", &vars, gpa));
    try std.testing.expect(!try t.match("test://template/123/other", &vars, gpa));
    try std.testing.expect(!try t.match("test://template/123/data/x", &vars, gpa));
}

test "reserved expansion accepts slashes" {
    const gpa = std.testing.allocator;
    var t = try parse(gpa, "file:///{+path}", 16);
    defer t.deinit(gpa);
    var vars: std.ArrayList(Variable) = .empty;
    defer vars.deinit(gpa);
    try std.testing.expect(try t.match("file:///a/b/c.txt", &vars, gpa));
    try std.testing.expectEqualStrings("a/b/c.txt", vars.items[0].value);
}

test "rejects unsupported modifiers" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedModifier, parse(gpa, "x/{a,b}", 16));
    try std.testing.expectError(error.UnsupportedModifier, parse(gpa, "x/{a*}", 16));
    try std.testing.expectError(error.UnsupportedOperator, parse(gpa, "x/{;a}", 16));
    try std.testing.expectError(error.UnterminatedExpression, parse(gpa, "x/{a", 16));
}
