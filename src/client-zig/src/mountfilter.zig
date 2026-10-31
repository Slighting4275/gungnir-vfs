//! Which mounts are the user's storage: the one list behind the volume monitor and its
//! integration test, so the two cannot drift (F01b). Pure string checks on what
//! /proc/self/mountinfo says; nothing here touches the mount.

const std = @import("std");

/// Filesystem types that never hold user storage, wherever they are mounted.
const ignored_types = [_][]const u8{
    "proc",      "sysfs",       "devpts",      "cgroup",          "cgroup2",
    "pstore",    "bpf",         "autofs",      "hugetlbfs",       "mqueue",
    "debugfs",   "tracefs",     "securityfs",  "configfs",        "fusectl",
    "devtmpfs",  "binfmt_misc", "efivarfs",    "nsfs",            "rpc_pipefs",
    "selinuxfs", "ramfs",       "fuse.portal", "fuse.gvfsd-fuse",
};

/// Trees of the system's own mounts: kernel interfaces, per-session runtime state,
/// and the layers of containers and snaps.
const system_trees = [_][]const u8{
    "/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containers", "/var/lib/snapd", "/snap",
};

/// Where a tmpfs is something the user put files on.
const user_tmpfs_trees = [_][]const u8{ "/tmp", "/media", "/mnt", "/run/media" };

/// `path` is `tree` or below it, by whole path components: /mediafoo is not under /media.
fn isUnder(path: []const u8, tree: []const u8) bool {
    if (!std.mem.startsWith(u8, path, tree)) return false;
    return path.len == tree.len or path[tree.len] == '/';
}

pub fn isStorageFs(fstype: []const u8, mount_point: []const u8) bool {
    for (ignored_types) |ig| {
        if (std.mem.eql(u8, fstype, ig)) return false;
    }
    // Removable media live below /run on most desktops.
    if (isUnder(mount_point, "/run/media")) return true;
    for (system_trees) |tree| {
        if (isUnder(mount_point, tree)) return false;
    }
    if (std.mem.eql(u8, fstype, "tmpfs")) {
        for (user_tmpfs_trees) |tree| {
            if (isUnder(mount_point, tree)) return true;
        }
        return false;
    }
    return true;
}

test "isStorageFs keeps storage and drops system mounts" {
    const t = std.testing;
    try t.expect(!isStorageFs("proc", "/proc"));
    try t.expect(!isStorageFs("selinuxfs", "/sys/fs/selinux"));
    try t.expect(!isStorageFs("nsfs", "/run/docker/netns/default"));
    try t.expect(!isStorageFs("fuse.portal", "/run/user/1000/doc"));
    try t.expect(!isStorageFs("fuse.gvfsd-fuse", "/run/user/1000/gvfs"));
    try t.expect(!isStorageFs("overlay", "/var/lib/docker/rootfs/overlayfs/33e2"));
    try t.expect(!isStorageFs("overlay", "/var/lib/containers/storage/overlay/x/merged"));
    try t.expect(!isStorageFs("squashfs", "/snap/core/1"));
    try t.expect(!isStorageFs("ext4", "/run/credentials/x"));
    try t.expect(!isStorageFs("tmpfs", "/run/user/1000"));
    try t.expect(!isStorageFs("tmpfs", "/dev/shm"));
    try t.expect(!isStorageFs("tmpfs", "/mediafoo"));
    try t.expect(isStorageFs("btrfs", "/"));
    try t.expect(isStorageFs("btrfs", "/home"));
    try t.expect(isStorageFs("vfat", "/run/media/user/STICK"));
    try t.expect(isStorageFs("nfs", "/mnt/share"));
    try t.expect(isStorageFs("tmpfs", "/tmp"));
    try t.expect(isStorageFs("tmpfs", "/mnt/ram"));
    try t.expect(isStorageFs("ext4", "/snapshots"));
    try t.expect(isStorageFs("ext4", "/developer"));
}
