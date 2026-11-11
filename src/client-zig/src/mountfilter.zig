//! Which mounts are the user's storage: the one rule behind the volume monitor and its
//! integration test, so the two cannot drift (F01b). It follows GLib 2.84
//! g_unix_mount_entry_guess_should_display() (gio/gunixmounts.c), the rule the stock
//! volume monitors use, so the opt-in Gungnir monitor shows what a stock desktop shows.
//!
//! Pure string checks on what /proc/self/mountinfo says; nothing here touches the mount
//! (AGENTS.md: no call may block on a broken mount). GLib's rule ends in an access/stat
//! tail for mounts under /media/ and /run/media/$USER/: g_access() on a /media/ parent,
//! and g_stat() of a block device then g_access() on the mount path. That tail can block
//! on a hung or network mount, so it is not run here: a mount that reaches it is KEPT
//! (D-093). This is a known, documented difference from GLib: a mount there that the
//! user cannot read is still listed (and fails on use) where GLib would hide it.

const std = @import("std");

/// One line of /proc/self/mountinfo with the fields the rule needs, octal escapes
/// (\040 and friends) decoded. The slices point into the buffer given to `parseLine`.
pub const Entry = struct {
    /// Field 4: the path inside the filesystem that is mounted; "/" unless a bind
    /// mount or a btrfs subvolume.
    root: []const u8,
    /// Field 5: where it is mounted.
    mount_point: []const u8,
    /// After the "-" separator: the filesystem type, then the source (device path).
    fstype: []const u8,
    source: []const u8,
};

/// The user the rule is evaluated for. GLib reads these from the process; they are
/// passed in so the rule stays pure and testable.
pub const User = struct {
    name: []const u8,
    home: []const u8,
    is_root: bool,
};

/// Decodes mountinfo's octal escapes (`\ooo`, as the kernel writes space, tab,
/// newline and backslash) into `out`. Stops when `out` is full; an escape that is not
/// three octal digits naming a byte is copied as is.
pub fn unescape(input: []const u8, out: []u8) []const u8 {
    var i: usize = 0;
    var n: usize = 0;
    while (i < input.len and n < out.len) {
        if (input[i] == '\\' and i + 3 < input.len) {
            const d = input[i + 1 .. i + 4];
            if (isOctal(d[0]) and isOctal(d[1]) and isOctal(d[2])) {
                const v: u16 = @as(u16, d[0] - '0') * 64 + @as(u16, d[1] - '0') * 8 + @as(u16, d[2] - '0');
                if (v <= 255) {
                    out[n] = @truncate(v);
                    n += 1;
                    i += 4;
                    continue;
                }
            }
        }
        out[n] = input[i];
        n += 1;
        i += 1;
    }
    return out[0..n];
}

fn isOctal(b: u8) bool {
    return b >= '0' and b <= '7';
}

/// Scratch space for one parsed line: one decoded field each.
pub const LineBuf = struct {
    root: [1024]u8 = undefined,
    mount_point: [1024]u8 = undefined,
    source: [1024]u8 = undefined,
};

/// Parses one mountinfo line, or null for a malformed one. `fstype` points into
/// `line` (the kernel never escapes it); the other fields are decoded into `buf`.
/// Format (proc(5)): id parent major:minor root mount-point options [optional...] - fstype source super-options
/// Fields are split on single spaces: an empty source is a real field (the kernel
/// escapes spaces inside fields, so " - " only ever appears as the separator).
pub fn parseLine(line: []const u8, buf: *LineBuf) ?Entry {
    const sep = std.mem.indexOf(u8, line, " - ") orelse return null;
    var it = std.mem.splitScalar(u8, line[0..sep], ' ');
    _ = it.next() orelse return null; // mount id
    _ = it.next() orelse return null; // parent id
    _ = it.next() orelse return null; // major:minor
    const root_raw = it.next() orelse return null;
    const mp_raw = it.next() orelse return null;
    if (root_raw.len == 0 or mp_raw.len == 0) return null;
    var post = std.mem.splitScalar(u8, line[sep + 3 ..], ' ');
    const fstype = post.next() orelse return null;
    if (fstype.len == 0) return null;
    const source_raw = post.next() orelse "";
    return .{
        .root = unescape(root_raw, &buf.root),
        .mount_point = unescape(mp_raw, &buf.mount_point),
        .fstype = fstype,
        .source = unescape(source_raw, &buf.source),
    };
}

// ---- GLib 2.84.4 classifiers, copied list for list ---------------------------------

/// g_unix_is_system_fs_type().
const system_fs_types = [_][]const u8{
    "adfs",       "afs",        "auto",      "autofs",   "autofs4", "cgroup",
    "configfs",   "cxfs",       "debugfs",   "devfs",    "devpts",  "devtmpfs",
    "ecryptfs",   "fdescfs",    "fusectl",   "gfs",      "gfs2",    "gpfs",
    "hugetlbfs",  "kernfs",     "linprocfs", "linsysfs", "lustre",  "lustre_lite",
    "mfs",        "mqueue",     "ncpfs",     "nfsd",     "nullfs",  "ocfs2",
    "overlay",    "proc",       "procfs",    "pstore",   "ptyfs",   "rootfs",
    "rpc_pipefs", "securityfs", "selinuxfs", "sysfs",    "tmpfs",   "usbfs",
};

/// g_unix_is_system_device_path(). Whole-string matches, as in GLib: "/dev/loop" is
/// listed but /dev/loop0 is not caught by it.
const system_devices = [_][]const u8{ "none", "sunrpc", "devpts", "nfsd", "/dev/loop", "/dev/vn" };

/// g_unix_is_mount_path_system_internal(), with GLIB_LOCALSTATEDIR = /var and
/// GLIB_RUNSTATEDIR = /run as GLib is built on Linux distributions.
const system_mount_paths = [_][]const u8{
    "/",                 "/bin",       "/boot",      "/compat/linux/proc",
    "/compat/linux/sys", "/dev",       "/etc",       "/home",
    "/lib",              "/lib64",     "/libexec",   "/live/cow",
    "/live/image",       "/media",     "/mnt",       "/opt",
    "/rescue",           "/root",      "/sbin",      "/srv",
    "/tmp",              "/usr",       "/usr/X11R6", "/usr/local",
    "/usr/obj",          "/usr/ports", "/usr/src",   "/usr/xobj",
    "/var",              "/var/crash", "/var/local", "/var/log",
    "/var/log/audit",    "/var/mail",  "/var/run",   "/run",
    "/var/tmp",          "/proc",      "/net",       "/sys",
};

fn isIn(value: []const u8, set: []const []const u8) bool {
    for (set) |s| {
        if (std.mem.eql(u8, value, s)) return true;
    }
    return false;
}

pub fn isSystemFsType(fstype: []const u8) bool {
    return isIn(fstype, &system_fs_types);
}

pub fn isSystemDevicePath(source: []const u8) bool {
    return isIn(source, &system_devices);
}

pub fn isSystemMountPath(mp: []const u8) bool {
    if (isIn(mp, &system_mount_paths)) return true;
    if (std.mem.startsWith(u8, mp, "/dev/") or std.mem.startsWith(u8, mp, "/proc/") or std.mem.startsWith(u8, mp, "/sys/")) return true;
    return std.mem.endsWith(u8, mp, "/.gvfs");
}

/// GLib's guess_system_internal(): a system filesystem, device or path, or a mount of
/// something other than a filesystem's root (bind mounts, btrfs subvolumes), which
/// duplicate another mount.
pub fn isSystemInternal(e: Entry) bool {
    // GLib's classifiers return FALSE for an empty type or device (g_return_val_if_fail).
    if (e.fstype.len != 0 and isSystemFsType(e.fstype)) return true;
    if (e.source.len != 0 and isSystemDevicePath(e.source)) return true;
    if (isSystemMountPath(e.mount_point)) return true;
    return !std.mem.eql(u8, e.root, "/");
}

/// g_unix_mount_entry_guess_should_display(), without the access/stat tail (see the
/// file comment): true if the mount is user storage that a file manager should list.
pub fn shouldDisplay(e: Entry, user: User) bool {
    if (isSystemInternal(e)) return false;
    const mp = e.mount_point;
    // A mount inside a dot path was hidden on purpose.
    if (std.mem.indexOf(u8, mp, "/.") != null) return false;

    const run_media = "/run/media/";
    var in_runtime_dir = false;
    if (std.mem.startsWith(u8, mp, run_media)) {
        if (user.is_root) {
            in_runtime_dir = true;
        } else {
            const rest = mp[run_media.len..];
            in_runtime_dir = user.name.len != 0 and std.mem.startsWith(u8, rest, user.name) and
                rest.len > user.name.len and rest[user.name.len] == '/';
        }
    }
    // GLib checks access here (needs_access); D-093 resolves it to KEEP.
    if (in_runtime_dir or std.mem.startsWith(u8, mp, "/media/")) return true;

    const home = user.home;
    return home.len != 0 and std.mem.startsWith(u8, mp, home) and mp.len > home.len and mp[home.len] == '/';
}

// ---- Tests ------------------------------------------------------------------------

const t = std.testing;
const desk: User = .{ .name = "user", .home = "/home/user", .is_root = false };

fn entry(fstype: []const u8, mp: []const u8, source: []const u8, root: []const u8) Entry {
    return .{ .fstype = fstype, .mount_point = mp, .source = source, .root = root };
}

fn show(fstype: []const u8, mp: []const u8) bool {
    return shouldDisplay(entry(fstype, mp, "/dev/sdb1", "/"), desk);
}

test "system mounts are never displayed" {
    try t.expect(!show("proc", "/proc"));
    try t.expect(!show("sysfs", "/sys"));
    try t.expect(!show("cgroup2", "/sys/fs/cgroup"));
    try t.expect(!show("selinuxfs", "/sys/fs/selinux"));
    try t.expect(!show("tmpfs", "/run/user/1000"));
    try t.expect(!show("tmpfs", "/dev/shm"));
    try t.expect(!show("overlay", "/var/lib/docker/overlay2/x/merged"));
    try t.expect(!show("ext4", "/run/credentials/x"));
    try t.expect(!show("nsfs", "/run/docker/netns/default"));
    try t.expect(!show("fuse.portal", "/run/user/1000/doc"));
    try t.expect(!show("fuse.gvfsd-fuse", "/run/user/1000/gvfs"));
    try t.expect(!show("squashfs", "/snap/core/1"));
}

test "the root, FHS directories and their parents are system internal" {
    // The F01b oracle: 33054a2 listed / /media /mnt where GLib lists none of them.
    try t.expect(!show("btrfs", "/"));
    try t.expect(!show("btrfs", "/home"));
    try t.expect(!show("ext4", "/boot"));
    try t.expect(!show("tmpfs", "/media"));
    try t.expect(!show("tmpfs", "/mnt"));
    try t.expect(!show("tmpfs", "/tmp"));
    try t.expect(!show("ext4", "/var"));
    try t.expect(!show("ext4", "/.gvfs"));
    try t.expect(!show("ext4", "/srv/x/.gvfs"));
}

test "tmpfs is never displayed, wherever it is mounted" {
    try t.expect(!show("tmpfs", "/media/ram"));
    try t.expect(!show("tmpfs", "/run/media/user/ram"));
    try t.expect(!show("tmpfs", "/home/user/ram"));
}

test "removable media under /media and /run/media/$USER are displayed" {
    try t.expect(show("vfat", "/run/media/user/STICK"));
    try t.expect(show("exfat", "/media/STICK"));
    // ramfs is not a system type in GLib: the F01b fixtures are ramfs.
    try t.expect(show("ramfs", "/media/stick"));
    try t.expect(show("ext4", "/media/user/disk"));
}

test "/run/media of another user is not displayed, except to root" {
    try t.expect(!show("vfat", "/run/media/other/STICK"));
    try t.expect(!show("vfat", "/run/media/username/STICK"));
    try t.expect(!show("vfat", "/run/media/user"));
    const root: User = .{ .name = "root", .home = "/root", .is_root = true };
    try t.expect(shouldDisplay(entry("vfat", "/run/media/other/STICK", "/dev/sdb1", "/"), root));
}

test "mounts below the home directory are displayed" {
    try t.expect(show("ramfs", "/home/user/own-store"));
    try t.expect(show("fuse.sshfs", "/home/user/remote"));
    try t.expect(!show("ext4", "/home/user"));
    try t.expect(!show("ext4", "/home/username/x"));
    try t.expect(!show("ext4", "/home/other/x"));
}

test "mounts elsewhere are not displayed" {
    try t.expect(!show("nfs", "/mnt/share"));
    try t.expect(!show("ramfs", "/mnt/data"));
    try t.expect(!show("ext4", "/data"));
    try t.expect(!show("ext4", "/snapshots"));
    try t.expect(!show("ext4", "/developer"));
    try t.expect(!show("fuse.agent-store", "/cursor/stores"));
    try t.expect(!show("tmpfs", "/mediafoo"));
}

test "a mount inside a dot path is hidden" {
    try t.expect(!show("ramfs", "/home/user/.hidden-store"));
    try t.expect(!show("vfat", "/media/.x/STICK"));
    try t.expect(!show("fuse.sshfs", "/home/user/a/.cache/m"));
}

test "bind mounts and subvolumes (root other than /) are hidden" {
    try t.expect(!shouldDisplay(entry("ramfs", "/home/user/bindview", "none2", "/sub"), desk));
    try t.expect(!shouldDisplay(entry("btrfs", "/media/disk", "/dev/sdb1", "/@data"), desk));
    try t.expect(shouldDisplay(entry("btrfs", "/media/disk", "/dev/sdb1", "/"), desk));
}

test "system devices are hidden; GLib matches them as whole strings" {
    try t.expect(!shouldDisplay(entry("ramfs", "/media/stick", "none", "/"), desk));
    try t.expect(!shouldDisplay(entry("ext4", "/media/img", "/dev/loop", "/"), desk));
    try t.expect(shouldDisplay(entry("ext4", "/media/img", "/dev/loop0", "/"), desk));
    // GLib ignores an empty type or source instead of matching it.
    try t.expect(shouldDisplay(entry("ramfs", "/media/stick", "", "/"), desk));
}

test "an empty user name or home matches nothing" {
    const none: User = .{ .name = "", .home = "", .is_root = false };
    try t.expect(!shouldDisplay(entry("vfat", "/run/media/x/STICK", "/dev/sdb1", "/"), none));
    try t.expect(!shouldDisplay(entry("vfat", "/srv2/x", "/dev/sdb1", "/"), none));
    try t.expect(shouldDisplay(entry("vfat", "/media/x", "/dev/sdb1", "/"), none));
}

test "parseLine reads root, mount point, type and source, decoding escapes" {
    var buf: LineBuf = .{};
    const line = "36 35 98:0 /mnt1 /home/user/my\\040disk rw,noatime master:1 - ext3 /dev/my\\040dev rw,errors=continue";
    const got = parseLine(line, &buf) orelse return error.TestUnexpectedResult;
    try t.expectEqualStrings("/mnt1", got.root);
    try t.expectEqualStrings("/home/user/my disk", got.mount_point);
    try t.expectEqualStrings("ext3", got.fstype);
    try t.expectEqualStrings("/dev/my dev", got.source);
    // An empty source stays empty instead of taking the super options.
    const empty = parseLine("40 1 0:50 / /media/x rw - ramfs  rw", &buf) orelse return error.TestUnexpectedResult;
    try t.expectEqualStrings("ramfs", empty.fstype);
    try t.expectEqualStrings("", empty.source);
    try t.expect(parseLine("1 2 3:4 / /x rw", &buf) == null);
    try t.expect(parseLine("1 2 3:4", &buf) == null);
    try t.expect(parseLine("", &buf) == null);
}

test "unescape decodes octal and keeps what is not an escape" {
    var buf: [64]u8 = undefined;
    try t.expectEqualStrings("a b", unescape("a\\040b", &buf));
    try t.expectEqualStrings("a\\b", unescape("a\\134b", &buf));
    try t.expectEqualStrings("x\\04", unescape("x\\04", &buf));
    try t.expectEqualStrings("x\\777", unescape("x\\777", &buf));
    try t.expectEqualStrings("x\\08y", unescape("x\\08y", &buf));
    var small: [3]u8 = undefined;
    try t.expectEqualStrings("abc", unescape("abcdef", &small));
}
