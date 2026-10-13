//! The forwarding stage (ADR-0005). A UDP query that only an upstream server
//! can answer goes to one of a fixed pool of slots, so the workers that
//! receive queries never wait for an upstream server. Each slot has a task of
//! its own; when every slot is busy, `submit` waits for one to come free.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const Resolver = @import("resolver.zig").Resolver;

const log = std.log.scoped(.server);

/// Larger queries are dropped by the server before they get here; real
/// queries are well under 512 bytes.
pub const max_query_len = 4096;

pub const Forwarder = struct {
    io: Io,
    gpa: Allocator,
    resolver: *Resolver,
    slots: []Slot,
    /// Idle slots, and slots holding a query for a task. Each slot is in at
    /// most one of them, and both can hold every slot, so putting one back
    /// never blocks.
    free: Io.Queue(*Slot),
    work: Io.Queue(*Slot),
    queue_buffer: []*Slot,
    group: Io.Group = .init,

    /// One query with its answer. Owns copies of everything it needs, so it
    /// outlives the worker's buffers.
    const Slot = struct {
        query: [max_query_len]u8,
        query_len: usize,
        response: [dns.max_message_len]u8,
        client: net.IpAddress,
        /// The socket the query came in on; the server keeps it open until
        /// `deinit` has stopped every slot.
        socket: *const net.Socket,
        arrived: ?Io.Clock.Timestamp,
    };

    /// Starts `slot_count` tasks. `forwarder` must not move afterwards.
    pub fn init(forwarder: *Forwarder, io: Io, gpa: Allocator, resolver: *Resolver, slot_count: u16) !void {
        std.debug.assert(slot_count > 0);
        const slots = try allocSlots(gpa, slot_count);
        errdefer freeSlots(gpa, slots);
        const queue_buffer = try gpa.alloc(*Slot, 2 * @as(usize, slot_count));
        errdefer gpa.free(queue_buffer);
        forwarder.* = .{
            .io = io,
            .gpa = gpa,
            .resolver = resolver,
            .slots = slots,
            .free = .init(queue_buffer[0..slot_count]),
            .work = .init(queue_buffer[slot_count..]),
            .queue_buffer = queue_buffer,
        };
        for (slots) |*slot| forwarder.release(slot);
        // Tasks that did start must stop before the memory goes.
        errdefer forwarder.group.cancel(io);
        for (slots) |_| try forwarder.group.concurrent(io, serve, .{forwarder});
    }

    /// Stops every slot, also in the middle of an exchange.
    pub fn deinit(forwarder: *Forwarder) void {
        forwarder.group.cancel(forwarder.io);
        forwarder.gpa.free(forwarder.queue_buffer);
        freeSlots(forwarder.gpa, forwarder.slots);
        forwarder.* = undefined;
    }

    /// Without the 0xAA fill that `alloc` does in safe builds: it would make
    /// all of the slots' memory resident at once (4.4 MB for 64), although
    /// most answers use a few hundred bytes. A slot's bytes are always
    /// written before they are read: `submit` fills a slot before a task
    /// sees it, and only the query and answer it wrote are used.
    fn allocSlots(gpa: Allocator, count: usize) Allocator.Error![]Slot {
        const len = std.math.mul(usize, @sizeOf(Slot), count) catch return error.OutOfMemory;
        const bytes = gpa.rawAlloc(len, .of(Slot), @returnAddress()) orelse return error.OutOfMemory;
        const slots: [*]Slot = @ptrCast(@alignCast(bytes));
        return slots[0..count];
    }

    fn freeSlots(gpa: Allocator, slots: []Slot) void {
        gpa.rawFree(std.mem.sliceAsBytes(slots), .of(Slot), @returnAddress());
    }

    /// Answers `query`, which came from `client` on `socket`, once an upstream
    /// server has: copies it into a free slot, waiting while there is none.
    pub fn submit(forwarder: *Forwarder, socket: *const net.Socket, client: net.IpAddress, query: []const u8, arrived: ?Io.Clock.Timestamp) Io.Cancelable!void {
        if (query.len > max_query_len) return;
        const slot = forwarder.free.getOne(forwarder.io) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.Closed => unreachable, // the queues are never closed
        };
        @memcpy(slot.query[0..query.len], query);
        slot.query_len = query.len;
        slot.client = client;
        slot.socket = socket;
        slot.arrived = arrived;
        // Room for every slot: this never blocks.
        forwarder.work.putOneUncancelable(forwarder.io, slot) catch unreachable;
    }

    fn serve(forwarder: *Forwarder) Io.Cancelable!void {
        const io = forwarder.io;
        while (true) {
            const slot = forwarder.work.getOne(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                error.Closed => unreachable,
            };
            defer forwarder.release(slot);
            const response = try forwarder.resolver.forward(slot.query[0..slot.query_len], &slot.response, slot.client, .udp, slot.arrived) orelse continue;
            slot.socket.send(io, &slot.client, response) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => log.debug("udp send to {f}: {t}", .{ slot.client, err }),
            };
        }
    }

    fn release(forwarder: *Forwarder, slot: *Slot) void {
        // Room for every slot: this never blocks.
        forwarder.free.putOneUncancelable(forwarder.io, slot) catch unreachable;
    }
};
