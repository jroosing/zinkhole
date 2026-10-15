//! A fixed pool of slots that tasks hand to each other: a receiving task
//! `take`s a free slot, fills it and `submit`s it; a serving task gets it
//! with `next` and `release`s it when done. Used by the forwarding slots
//! (ADR-0005) and the TCP connection slots.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// A pool of `Slot`s. Each slot is always in exactly one state, and every
/// hand-over checks it: a slot released twice, or served by two tasks at
/// once, panics instead of sharing its buffers or blocking a queue.
pub fn SlotPool(comptime Slot: type) type {
    return struct {
        const Pool = @This();

        pub const State = enum(u8) {
            /// In `free`.
            free,
            /// Returned by `take`; the taker fills it.
            taken,
            /// In `work`, waiting for `next`.
            submitted,
            /// Returned by `next` or `unserved`; the server uses it.
            serving,
        };

        slots: []Slot,
        states: []std.atomic.Value(State),
        /// Free slots, and submitted ones. A slot is in at most one of them,
        /// and both can hold every slot, so putting one back never blocks.
        free: Io.Queue(*Slot),
        work: Io.Queue(*Slot),
        queue_buffer: []*Slot,

        /// `count` free slots. `pool` must not move afterwards.
        pub fn init(pool: *Pool, io: Io, gpa: Allocator, count: usize) Allocator.Error!void {
            std.debug.assert(count > 0);
            const slots = try allocUnfilled(Slot, gpa, count);
            errdefer freeUnfilled(Slot, gpa, slots);
            const states = try gpa.alloc(std.atomic.Value(State), count);
            errdefer gpa.free(states);
            @memset(states, .init(.free));
            const queue_buffer = try gpa.alloc(*Slot, 2 * count);
            pool.* = .{
                .slots = slots,
                .states = states,
                .free = .init(queue_buffer[0..count]),
                .work = .init(queue_buffer[count..]),
                .queue_buffer = queue_buffer,
            };
            for (slots) |*slot| put(io, &pool.free, slot);
        }

        /// The tasks using the slots must have stopped.
        pub fn deinit(pool: *Pool, gpa: Allocator) void {
            gpa.free(pool.queue_buffer);
            gpa.free(pool.states);
            freeUnfilled(Slot, gpa, pool.slots);
            pool.* = undefined;
        }

        /// A free slot for the caller to fill, or null at once when every
        /// slot is busy. Never blocks.
        pub fn take(pool: *Pool, io: Io) ?*Slot {
            var taken: [1]*Slot = undefined;
            const count = pool.free.getUncancelable(io, &taken, 0) catch unreachable; // never closed
            if (count == 0) return null;
            pool.move(taken[0], &.{.free}, .taken);
            return taken[0];
        }

        /// Hands a slot from `take`, filled, to a task in `next`. Never blocks.
        pub fn submit(pool: *Pool, io: Io, slot: *Slot) void {
            pool.move(slot, &.{.taken}, .submitted);
            put(io, &pool.work, slot);
        }

        /// Waits for a submitted slot to serve.
        pub fn next(pool: *Pool, io: Io) Io.Cancelable!*Slot {
            const slot = pool.work.getOne(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                error.Closed => unreachable, // never closed
            };
            pool.move(slot, &.{.submitted}, .serving);
            return slot;
        }

        /// A slot that was submitted but never served, if any: for cleaning
        /// up after the serving tasks stopped. Release it when done.
        pub fn unserved(pool: *Pool, io: Io) ?*Slot {
            var left: [1]*Slot = undefined;
            const count = pool.work.getUncancelable(io, &left, 0) catch unreachable; // never closed
            if (count == 0) return null;
            pool.move(left[0], &.{.submitted}, .serving);
            return left[0];
        }

        /// Makes a slot from `take`, `next` or `unserved` free again. Never
        /// blocks.
        pub fn release(pool: *Pool, io: Io, slot: *Slot) void {
            pool.move(slot, &.{ .taken, .serving }, .free);
            put(io, &pool.free, slot);
        }

        fn move(pool: *Pool, slot: *Slot, comptime from: []const State, to: State) void {
            const index = pool.indexOf(slot);
            const was = pool.states[index].swap(to, .acq_rel);
            inline for (from) |expected| {
                if (was == expected) return;
            }
            std.debug.panic("slot {d} is {t}, but must be one of {any} to become {t}", .{ index, was, from, to });
        }

        fn indexOf(pool: *const Pool, slot: *const Slot) usize {
            const offset = @intFromPtr(slot) -% @intFromPtr(pool.slots.ptr);
            const index = offset / @sizeOf(Slot);
            if (offset % @sizeOf(Slot) != 0 or index >= pool.slots.len) std.debug.panic("not a slot of this pool", .{});
            return index;
        }

        /// Room for every slot in both queues: this never blocks.
        fn put(io: Io, queue: *Io.Queue(*Slot), slot: *Slot) void {
            const count = queue.putUncancelable(io, &.{slot}, 0) catch unreachable; // never closed
            if (count != 1) std.debug.panic("slot queue full", .{});
        }
    };
}

/// Slots with buffers, without the 0xAA fill that `alloc` does in safe
/// builds: it would make all of their memory resident at once (4.4 MB for
/// 64 forwarding slots), although most answers use a few hundred bytes. The
/// taker writes a slot's bytes before the server reads them, and only what
/// was written is read.
fn allocUnfilled(comptime T: type, gpa: Allocator, count: usize) Allocator.Error![]T {
    const len = std.math.mul(usize, @sizeOf(T), count) catch return error.OutOfMemory;
    const bytes = gpa.rawAlloc(len, .of(T), @returnAddress()) orelse return error.OutOfMemory;
    const items: [*]T = @ptrCast(@alignCast(bytes));
    return items[0..count];
}

fn freeUnfilled(comptime T: type, gpa: Allocator, items: []T) void {
    gpa.rawFree(std.mem.sliceAsBytes(items), .of(T), @returnAddress());
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const TestSlot = struct { value: u32 };

test "each slot is handed out once until it is released; with none free, take answers null at once" {
    const io = testing.io;
    var pool: SlotPool(TestSlot) = undefined;
    try pool.init(io, testing.allocator, 2);
    defer pool.deinit(testing.allocator);

    const a = pool.take(io).?;
    const b = pool.take(io).?;
    try testing.expect(a != b);
    try testing.expectEqual(null, pool.take(io));

    pool.release(io, a);
    try testing.expectEqual(a, pool.take(io).?);
}

test "a submitted slot reaches the task waiting in next, with what was written into it" {
    const io = testing.io;
    var pool: SlotPool(TestSlot) = undefined;
    try pool.init(io, testing.allocator, 1);
    defer pool.deinit(testing.allocator);

    const slot = pool.take(io).?;
    slot.value = 42;
    pool.submit(io, slot);
    const served = try pool.next(io);
    try testing.expectEqual(slot, served);
    try testing.expectEqual(42, served.value);
    pool.release(io, served);
    try testing.expect(pool.take(io) != null);
}

test "slots submitted but never served can be collected, for cleanup after the tasks stopped" {
    const io = testing.io;
    var pool: SlotPool(TestSlot) = undefined;
    try pool.init(io, testing.allocator, 3);
    defer pool.deinit(testing.allocator);

    pool.submit(io, pool.take(io).?);
    pool.submit(io, pool.take(io).?);
    var collected: usize = 0;
    while (pool.unserved(io)) |slot| {
        collected += 1;
        pool.release(io, slot);
    }
    try testing.expectEqual(2, collected);
}
