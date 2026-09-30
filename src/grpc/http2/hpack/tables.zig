//! The HPACK static table and Huffman code of RFC 7541 (appendices A and B). Extracted
//! from the RFC text. The tables are IETF Trust material under the IETF Trust Legal
//! Provisions, see THIRD_PARTY_LICENSES.md.
pub const StaticEntry = struct { name: []const u8, value: []const u8 };
/// Index 1 is `static_table[0]`.
pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub const HuffmanCode = struct { code: u32, len: u5 };
/// Index 256 is the end-of-string symbol.
pub const huffman_codes = [_]HuffmanCode{
    .{ .code = 0x1ff8, .len = 13 }, // 0
    .{ .code = 0x7fffd8, .len = 23 }, // 1
    .{ .code = 0xfffffe2, .len = 28 }, // 2
    .{ .code = 0xfffffe3, .len = 28 }, // 3
    .{ .code = 0xfffffe4, .len = 28 }, // 4
    .{ .code = 0xfffffe5, .len = 28 }, // 5
    .{ .code = 0xfffffe6, .len = 28 }, // 6
    .{ .code = 0xfffffe7, .len = 28 }, // 7
    .{ .code = 0xfffffe8, .len = 28 }, // 8
    .{ .code = 0xffffea, .len = 24 }, // 9
    .{ .code = 0x3ffffffc, .len = 30 }, // 10
    .{ .code = 0xfffffe9, .len = 28 }, // 11
    .{ .code = 0xfffffea, .len = 28 }, // 12
    .{ .code = 0x3ffffffd, .len = 30 }, // 13
    .{ .code = 0xfffffeb, .len = 28 }, // 14
    .{ .code = 0xfffffec, .len = 28 }, // 15
    .{ .code = 0xfffffed, .len = 28 }, // 16
    .{ .code = 0xfffffee, .len = 28 }, // 17
    .{ .code = 0xfffffef, .len = 28 }, // 18
    .{ .code = 0xffffff0, .len = 28 }, // 19
    .{ .code = 0xffffff1, .len = 28 }, // 20
    .{ .code = 0xffffff2, .len = 28 }, // 21
    .{ .code = 0x3ffffffe, .len = 30 }, // 22
    .{ .code = 0xffffff3, .len = 28 }, // 23
    .{ .code = 0xffffff4, .len = 28 }, // 24
    .{ .code = 0xffffff5, .len = 28 }, // 25
    .{ .code = 0xffffff6, .len = 28 }, // 26
    .{ .code = 0xffffff7, .len = 28 }, // 27
    .{ .code = 0xffffff8, .len = 28 }, // 28
    .{ .code = 0xffffff9, .len = 28 }, // 29
    .{ .code = 0xffffffa, .len = 28 }, // 30
    .{ .code = 0xffffffb, .len = 28 }, // 31
    .{ .code = 0x14, .len = 6 }, // 32
    .{ .code = 0x3f8, .len = 10 }, // 33
    .{ .code = 0x3f9, .len = 10 }, // 34
    .{ .code = 0xffa, .len = 12 }, // 35
    .{ .code = 0x1ff9, .len = 13 }, // 36
    .{ .code = 0x15, .len = 6 }, // 37
    .{ .code = 0xf8, .len = 8 }, // 38
    .{ .code = 0x7fa, .len = 11 }, // 39
    .{ .code = 0x3fa, .len = 10 }, // 40
    .{ .code = 0x3fb, .len = 10 }, // 41
    .{ .code = 0xf9, .len = 8 }, // 42
    .{ .code = 0x7fb, .len = 11 }, // 43
    .{ .code = 0xfa, .len = 8 }, // 44
    .{ .code = 0x16, .len = 6 }, // 45
    .{ .code = 0x17, .len = 6 }, // 46
    .{ .code = 0x18, .len = 6 }, // 47
    .{ .code = 0x0, .len = 5 }, // 48
    .{ .code = 0x1, .len = 5 }, // 49
    .{ .code = 0x2, .len = 5 }, // 50
    .{ .code = 0x19, .len = 6 }, // 51
    .{ .code = 0x1a, .len = 6 }, // 52
    .{ .code = 0x1b, .len = 6 }, // 53
    .{ .code = 0x1c, .len = 6 }, // 54
    .{ .code = 0x1d, .len = 6 }, // 55
    .{ .code = 0x1e, .len = 6 }, // 56
    .{ .code = 0x1f, .len = 6 }, // 57
    .{ .code = 0x5c, .len = 7 }, // 58
    .{ .code = 0xfb, .len = 8 }, // 59
    .{ .code = 0x7ffc, .len = 15 }, // 60
    .{ .code = 0x20, .len = 6 }, // 61
    .{ .code = 0xffb, .len = 12 }, // 62
    .{ .code = 0x3fc, .len = 10 }, // 63
    .{ .code = 0x1ffa, .len = 13 }, // 64
    .{ .code = 0x21, .len = 6 }, // 65
    .{ .code = 0x5d, .len = 7 }, // 66
    .{ .code = 0x5e, .len = 7 }, // 67
    .{ .code = 0x5f, .len = 7 }, // 68
    .{ .code = 0x60, .len = 7 }, // 69
    .{ .code = 0x61, .len = 7 }, // 70
    .{ .code = 0x62, .len = 7 }, // 71
    .{ .code = 0x63, .len = 7 }, // 72
    .{ .code = 0x64, .len = 7 }, // 73
    .{ .code = 0x65, .len = 7 }, // 74
    .{ .code = 0x66, .len = 7 }, // 75
    .{ .code = 0x67, .len = 7 }, // 76
    .{ .code = 0x68, .len = 7 }, // 77
    .{ .code = 0x69, .len = 7 }, // 78
    .{ .code = 0x6a, .len = 7 }, // 79
    .{ .code = 0x6b, .len = 7 }, // 80
    .{ .code = 0x6c, .len = 7 }, // 81
    .{ .code = 0x6d, .len = 7 }, // 82
    .{ .code = 0x6e, .len = 7 }, // 83
    .{ .code = 0x6f, .len = 7 }, // 84
    .{ .code = 0x70, .len = 7 }, // 85
    .{ .code = 0x71, .len = 7 }, // 86
    .{ .code = 0x72, .len = 7 }, // 87
    .{ .code = 0xfc, .len = 8 }, // 88
    .{ .code = 0x73, .len = 7 }, // 89
    .{ .code = 0xfd, .len = 8 }, // 90
    .{ .code = 0x1ffb, .len = 13 }, // 91
    .{ .code = 0x7fff0, .len = 19 }, // 92
    .{ .code = 0x1ffc, .len = 13 }, // 93
    .{ .code = 0x3ffc, .len = 14 }, // 94
    .{ .code = 0x22, .len = 6 }, // 95
    .{ .code = 0x7ffd, .len = 15 }, // 96
    .{ .code = 0x3, .len = 5 }, // 97
    .{ .code = 0x23, .len = 6 }, // 98
    .{ .code = 0x4, .len = 5 }, // 99
    .{ .code = 0x24, .len = 6 }, // 100
    .{ .code = 0x5, .len = 5 }, // 101
    .{ .code = 0x25, .len = 6 }, // 102
    .{ .code = 0x26, .len = 6 }, // 103
    .{ .code = 0x27, .len = 6 }, // 104
    .{ .code = 0x6, .len = 5 }, // 105
    .{ .code = 0x74, .len = 7 }, // 106
    .{ .code = 0x75, .len = 7 }, // 107
    .{ .code = 0x28, .len = 6 }, // 108
    .{ .code = 0x29, .len = 6 }, // 109
    .{ .code = 0x2a, .len = 6 }, // 110
    .{ .code = 0x7, .len = 5 }, // 111
    .{ .code = 0x2b, .len = 6 }, // 112
    .{ .code = 0x76, .len = 7 }, // 113
    .{ .code = 0x2c, .len = 6 }, // 114
    .{ .code = 0x8, .len = 5 }, // 115
    .{ .code = 0x9, .len = 5 }, // 116
    .{ .code = 0x2d, .len = 6 }, // 117
    .{ .code = 0x77, .len = 7 }, // 118
    .{ .code = 0x78, .len = 7 }, // 119
    .{ .code = 0x79, .len = 7 }, // 120
    .{ .code = 0x7a, .len = 7 }, // 121
    .{ .code = 0x7b, .len = 7 }, // 122
    .{ .code = 0x7ffe, .len = 15 }, // 123
    .{ .code = 0x7fc, .len = 11 }, // 124
    .{ .code = 0x3ffd, .len = 14 }, // 125
    .{ .code = 0x1ffd, .len = 13 }, // 126
    .{ .code = 0xffffffc, .len = 28 }, // 127
    .{ .code = 0xfffe6, .len = 20 }, // 128
    .{ .code = 0x3fffd2, .len = 22 }, // 129
    .{ .code = 0xfffe7, .len = 20 }, // 130
    .{ .code = 0xfffe8, .len = 20 }, // 131
    .{ .code = 0x3fffd3, .len = 22 }, // 132
    .{ .code = 0x3fffd4, .len = 22 }, // 133
    .{ .code = 0x3fffd5, .len = 22 }, // 134
    .{ .code = 0x7fffd9, .len = 23 }, // 135
    .{ .code = 0x3fffd6, .len = 22 }, // 136
    .{ .code = 0x7fffda, .len = 23 }, // 137
    .{ .code = 0x7fffdb, .len = 23 }, // 138
    .{ .code = 0x7fffdc, .len = 23 }, // 139
    .{ .code = 0x7fffdd, .len = 23 }, // 140
    .{ .code = 0x7fffde, .len = 23 }, // 141
    .{ .code = 0xffffeb, .len = 24 }, // 142
    .{ .code = 0x7fffdf, .len = 23 }, // 143
    .{ .code = 0xffffec, .len = 24 }, // 144
    .{ .code = 0xffffed, .len = 24 }, // 145
    .{ .code = 0x3fffd7, .len = 22 }, // 146
    .{ .code = 0x7fffe0, .len = 23 }, // 147
    .{ .code = 0xffffee, .len = 24 }, // 148
    .{ .code = 0x7fffe1, .len = 23 }, // 149
    .{ .code = 0x7fffe2, .len = 23 }, // 150
    .{ .code = 0x7fffe3, .len = 23 }, // 151
    .{ .code = 0x7fffe4, .len = 23 }, // 152
    .{ .code = 0x1fffdc, .len = 21 }, // 153
    .{ .code = 0x3fffd8, .len = 22 }, // 154
    .{ .code = 0x7fffe5, .len = 23 }, // 155
    .{ .code = 0x3fffd9, .len = 22 }, // 156
    .{ .code = 0x7fffe6, .len = 23 }, // 157
    .{ .code = 0x7fffe7, .len = 23 }, // 158
    .{ .code = 0xffffef, .len = 24 }, // 159
    .{ .code = 0x3fffda, .len = 22 }, // 160
    .{ .code = 0x1fffdd, .len = 21 }, // 161
    .{ .code = 0xfffe9, .len = 20 }, // 162
    .{ .code = 0x3fffdb, .len = 22 }, // 163
    .{ .code = 0x3fffdc, .len = 22 }, // 164
    .{ .code = 0x7fffe8, .len = 23 }, // 165
    .{ .code = 0x7fffe9, .len = 23 }, // 166
    .{ .code = 0x1fffde, .len = 21 }, // 167
    .{ .code = 0x7fffea, .len = 23 }, // 168
    .{ .code = 0x3fffdd, .len = 22 }, // 169
    .{ .code = 0x3fffde, .len = 22 }, // 170
    .{ .code = 0xfffff0, .len = 24 }, // 171
    .{ .code = 0x1fffdf, .len = 21 }, // 172
    .{ .code = 0x3fffdf, .len = 22 }, // 173
    .{ .code = 0x7fffeb, .len = 23 }, // 174
    .{ .code = 0x7fffec, .len = 23 }, // 175
    .{ .code = 0x1fffe0, .len = 21 }, // 176
    .{ .code = 0x1fffe1, .len = 21 }, // 177
    .{ .code = 0x3fffe0, .len = 22 }, // 178
    .{ .code = 0x1fffe2, .len = 21 }, // 179
    .{ .code = 0x7fffed, .len = 23 }, // 180
    .{ .code = 0x3fffe1, .len = 22 }, // 181
    .{ .code = 0x7fffee, .len = 23 }, // 182
    .{ .code = 0x7fffef, .len = 23 }, // 183
    .{ .code = 0xfffea, .len = 20 }, // 184
    .{ .code = 0x3fffe2, .len = 22 }, // 185
    .{ .code = 0x3fffe3, .len = 22 }, // 186
    .{ .code = 0x3fffe4, .len = 22 }, // 187
    .{ .code = 0x7ffff0, .len = 23 }, // 188
    .{ .code = 0x3fffe5, .len = 22 }, // 189
    .{ .code = 0x3fffe6, .len = 22 }, // 190
    .{ .code = 0x7ffff1, .len = 23 }, // 191
    .{ .code = 0x3ffffe0, .len = 26 }, // 192
    .{ .code = 0x3ffffe1, .len = 26 }, // 193
    .{ .code = 0xfffeb, .len = 20 }, // 194
    .{ .code = 0x7fff1, .len = 19 }, // 195
    .{ .code = 0x3fffe7, .len = 22 }, // 196
    .{ .code = 0x7ffff2, .len = 23 }, // 197
    .{ .code = 0x3fffe8, .len = 22 }, // 198
    .{ .code = 0x1ffffec, .len = 25 }, // 199
    .{ .code = 0x3ffffe2, .len = 26 }, // 200
    .{ .code = 0x3ffffe3, .len = 26 }, // 201
    .{ .code = 0x3ffffe4, .len = 26 }, // 202
    .{ .code = 0x7ffffde, .len = 27 }, // 203
    .{ .code = 0x7ffffdf, .len = 27 }, // 204
    .{ .code = 0x3ffffe5, .len = 26 }, // 205
    .{ .code = 0xfffff1, .len = 24 }, // 206
    .{ .code = 0x1ffffed, .len = 25 }, // 207
    .{ .code = 0x7fff2, .len = 19 }, // 208
    .{ .code = 0x1fffe3, .len = 21 }, // 209
    .{ .code = 0x3ffffe6, .len = 26 }, // 210
    .{ .code = 0x7ffffe0, .len = 27 }, // 211
    .{ .code = 0x7ffffe1, .len = 27 }, // 212
    .{ .code = 0x3ffffe7, .len = 26 }, // 213
    .{ .code = 0x7ffffe2, .len = 27 }, // 214
    .{ .code = 0xfffff2, .len = 24 }, // 215
    .{ .code = 0x1fffe4, .len = 21 }, // 216
    .{ .code = 0x1fffe5, .len = 21 }, // 217
    .{ .code = 0x3ffffe8, .len = 26 }, // 218
    .{ .code = 0x3ffffe9, .len = 26 }, // 219
    .{ .code = 0xffffffd, .len = 28 }, // 220
    .{ .code = 0x7ffffe3, .len = 27 }, // 221
    .{ .code = 0x7ffffe4, .len = 27 }, // 222
    .{ .code = 0x7ffffe5, .len = 27 }, // 223
    .{ .code = 0xfffec, .len = 20 }, // 224
    .{ .code = 0xfffff3, .len = 24 }, // 225
    .{ .code = 0xfffed, .len = 20 }, // 226
    .{ .code = 0x1fffe6, .len = 21 }, // 227
    .{ .code = 0x3fffe9, .len = 22 }, // 228
    .{ .code = 0x1fffe7, .len = 21 }, // 229
    .{ .code = 0x1fffe8, .len = 21 }, // 230
    .{ .code = 0x7ffff3, .len = 23 }, // 231
    .{ .code = 0x3fffea, .len = 22 }, // 232
    .{ .code = 0x3fffeb, .len = 22 }, // 233
    .{ .code = 0x1ffffee, .len = 25 }, // 234
    .{ .code = 0x1ffffef, .len = 25 }, // 235
    .{ .code = 0xfffff4, .len = 24 }, // 236
    .{ .code = 0xfffff5, .len = 24 }, // 237
    .{ .code = 0x3ffffea, .len = 26 }, // 238
    .{ .code = 0x7ffff4, .len = 23 }, // 239
    .{ .code = 0x3ffffeb, .len = 26 }, // 240
    .{ .code = 0x7ffffe6, .len = 27 }, // 241
    .{ .code = 0x3ffffec, .len = 26 }, // 242
    .{ .code = 0x3ffffed, .len = 26 }, // 243
    .{ .code = 0x7ffffe7, .len = 27 }, // 244
    .{ .code = 0x7ffffe8, .len = 27 }, // 245
    .{ .code = 0x7ffffe9, .len = 27 }, // 246
    .{ .code = 0x7ffffea, .len = 27 }, // 247
    .{ .code = 0x7ffffeb, .len = 27 }, // 248
    .{ .code = 0xffffffe, .len = 28 }, // 249
    .{ .code = 0x7ffffec, .len = 27 }, // 250
    .{ .code = 0x7ffffed, .len = 27 }, // 251
    .{ .code = 0x7ffffee, .len = 27 }, // 252
    .{ .code = 0x7ffffef, .len = 27 }, // 253
    .{ .code = 0x7fffff0, .len = 27 }, // 254
    .{ .code = 0x3ffffee, .len = 26 }, // 255
    .{ .code = 0x3fffffff, .len = 30 }, // 256
};
