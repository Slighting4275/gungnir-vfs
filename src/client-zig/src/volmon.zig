//! Volume and mount monitoring for GIO (milestone 10).
//!
//! Exposes GungnirVolumeMonitor (subclass of GVolumeMonitor) and GungnirMount (implementing
//! GMount) plus GungnirVolume (implementing GVolume), dynamic types registered through
//! g_type_module_register_type in g_io_module_load.
//!
//! Non-blocking rule: all mount and volume information is read from /proc/self/mountinfo
//! (procfs-only, no syscall on underlying or remote filesystems). Mount health states from
//! health.zig flag hung or gone network/FUSE mounts.
const std = @import("std");
const c = @import("c");
const health = @import("health.zig");

pub const monitor_type_name = "GungnirVolumeMonitor";
pub const mount_type_name = "GungnirMount";
pub const volume_type_name = "GungnirVolume";

pub var volume_monitor_type: c.GType = 0;
pub var mount_type: c.GType = 0;
pub var volume_type: c.GType = 0;

// ---- Unescape octal paths from mountinfo --------------------------------------

pub fn unescape(input: []const u8, out: []u8) []const u8 {
    var in_idx: usize = 0;
    var out_idx: usize = 0;
    while (in_idx < input.len and out_idx < out.len) {
        if (input[in_idx] == '\\' and in_idx + 3 < input.len) {
            const b1 = input[in_idx + 1];
            const b2 = input[in_idx + 2];
            const b3 = input[in_idx + 3];
            if (b1 >= '0' and b1 <= '7' and b2 >= '0' and b2 <= '7' and b3 >= '0' and b3 <= '7') {
                const val: u16 = @as(u16, b1 - '0') * 64 + @as(u16, b2 - '0') * 8 + @as(u16, b3 - '0');
                if (val <= 255) {
                    out[out_idx] = @truncate(val);
                    out_idx += 1;
                    in_idx += 4;
                    continue;
                }
            }
        }
        out[out_idx] = input[in_idx];
        out_idx += 1;
        in_idx += 1;
    }
    return out[0..out_idx];
}

// ---- Mount filtering ---------------------------------------------------------

pub fn isStorageFs(fstype: []const u8, mount_point: []const u8) bool {
    // Virtual filesystems to ignore
    const ignored = [_][]const u8{
        "proc",
        "sysfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "pstore",
        "bpf",
        "autofs",
        "hugetlbfs",
        "mqueue",
        "debugfs",
        "tracefs",
        "securityfs",
        "configfs",
        "fusectl",
        "devtmpfs",
        "binfmt_misc",
        "efivarfs",
        "nsfs",
        "rpc_pipefs",
    };
    for (ignored) |ig| {
        if (std.mem.eql(u8, fstype, ig)) return false;
    }
    // tmpfs: only treat as a storage mount if mounted at /tmp, /run/media, /media, /mnt
    if (std.mem.eql(u8, fstype, "tmpfs")) {
        if (std.mem.eql(u8, mount_point, "/tmp") or
            std.mem.startsWith(u8, mount_point, "/media") or
            std.mem.startsWith(u8, mount_point, "/run/media") or
            std.mem.startsWith(u8, mount_point, "/mnt"))
        {
            return true;
        }
        return false;
    }
    // Ignore internal docker overlay layers
    if (std.mem.startsWith(u8, mount_point, "/var/lib/docker")) return false;
    return true;
}

pub fn isNetworkFs(fstype: []const u8) bool {
    const net_types = [_][]const u8{
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "9p",
        "ceph",
        "glusterfs",
        "fuse.sshfs",
        "fuse.rclone",
    };
    for (net_types) |nt| {
        if (std.mem.eql(u8, fstype, nt)) return true;
    }
    return false;
}

// ---- GungnirMount: GObject implementing GMount -------------------------------

pub const GungnirMount = extern struct {
    parent_instance: c.GObject,
    mount_point: [1024]u8,
    name: [256]u8,
    fstype: [64]u8,
    uuid: [128]u8,
    is_network: c.gboolean,
};

pub const GungnirMountClass = extern struct {
    parent_class: c.GObjectClass,
};

fn mountGetRoot(mount: ?*c.GMount) callconv(.c) ?*c.GFile {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    return c.g_file_new_for_path(@ptrCast(&self.mount_point));
}

fn mountGetName(mount: ?*c.GMount) callconv(.c) [*c]u8 {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    return c.g_strdup(@ptrCast(&self.name));
}

fn mountGetIcon(mount: ?*c.GMount) callconv(.c) ?*c.GIcon {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    const icon_name = if (self.is_network != 0) "folder-remote" else "drive-harddisk";
    return c.g_themed_icon_new(icon_name);
}

fn mountGetSymbolicIcon(mount: ?*c.GMount) callconv(.c) ?*c.GIcon {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    const icon_name = if (self.is_network != 0) "folder-remote-symbolic" else "drive-harddisk-symbolic";
    return c.g_themed_icon_new(icon_name);
}

fn mountGetUuid(mount: ?*c.GMount) callconv(.c) [*c]u8 {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    if (self.uuid[0] != 0) {
        return c.g_strdup(@ptrCast(&self.uuid));
    }
    return null;
}

fn mountGetVolume(mount: ?*c.GMount) callconv(.c) ?*c.GVolume {
    _ = mount;
    return null;
}

fn mountGetDrive(mount: ?*c.GMount) callconv(.c) ?*c.GDrive {
    _ = mount;
    return null;
}

fn mountCanUnmount(mount: ?*c.GMount) callconv(.c) c.gboolean {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return 0));
    const mp = std.mem.span(@as([*:0]const u8, @ptrCast(&self.mount_point)));
    if (std.mem.eql(u8, mp, "/")) return 0;
    return 1;
}

fn mountCanEject(mount: ?*c.GMount) callconv(.c) c.gboolean {
    _ = mount;
    return 0;
}

fn mountGetDefaultLocation(mount: ?*c.GMount) callconv(.c) ?*c.GFile {
    return mountGetRoot(mount);
}

fn mountGetSortKey(mount: ?*c.GMount) callconv(.c) [*c]const c.gchar {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    return @ptrCast(&self.mount_point);
}

fn mountInterfaceInit(g_iface: c.gpointer, iface_data: c.gpointer) callconv(.c) void {
    _ = iface_data;
    const iface: *c.GMountIface = @ptrCast(@alignCast(g_iface));
    iface.get_root = &mountGetRoot;
    iface.get_name = &mountGetName;
    iface.get_icon = &mountGetIcon;
    iface.get_symbolic_icon = &mountGetSymbolicIcon;
    iface.get_uuid = &mountGetUuid;
    iface.get_volume = &mountGetVolume;
    iface.get_drive = &mountGetDrive;
    iface.can_unmount = &mountCanUnmount;
    iface.can_eject = &mountCanEject;
    iface.get_default_location = &mountGetDefaultLocation;
    iface.get_sort_key = &mountGetSortKey;
}

fn mountClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = g_class;
    _ = class_data;
}

fn mountInstanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = g_class;
    const self: *GungnirMount = @ptrCast(@alignCast(instance));
    @memset(&self.mount_point, 0);
    @memset(&self.name, 0);
    @memset(&self.fstype, 0);
    @memset(&self.uuid, 0);
    self.is_network = 0;
}

const mount_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirMountClass),
    .class_init = &mountClassInit,
    .class_finalize = null,
    .instance_size = @sizeOf(GungnirMount),
    .instance_init = &mountInstanceInit,
};

const mount_iface_info = c.GInterfaceInfo{
    .interface_init = &mountInterfaceInit,
    .interface_finalize = null,
    .interface_data = null,
};

// ---- GungnirVolume: GObject implementing GVolume -----------------------------

pub const GungnirVolume = extern struct {
    parent_instance: c.GObject,
    name: [256]u8,
    uuid: [128]u8,
    mount: ?*c.GMount,
};

pub const GungnirVolumeClass = extern struct {
    parent_class: c.GObjectClass,
};

fn volumeGetName(volume: ?*c.GVolume) callconv(.c) [*c]u8 {
    const self: *GungnirVolume = @ptrCast(@alignCast(volume orelse return null));
    return c.g_strdup(@ptrCast(&self.name));
}

fn volumeGetIcon(volume: ?*c.GVolume) callconv(.c) ?*c.GIcon {
    _ = volume;
    return c.g_themed_icon_new("drive-harddisk");
}

fn volumeGetSymbolicIcon(volume: ?*c.GVolume) callconv(.c) ?*c.GIcon {
    _ = volume;
    return c.g_themed_icon_new("drive-harddisk-symbolic");
}

fn volumeGetUuid(volume: ?*c.GVolume) callconv(.c) [*c]u8 {
    const self: *GungnirVolume = @ptrCast(@alignCast(volume orelse return null));
    if (self.uuid[0] != 0) {
        return c.g_strdup(@ptrCast(&self.uuid));
    }
    return null;
}

fn volumeGetDrive(volume: ?*c.GVolume) callconv(.c) ?*c.GDrive {
    _ = volume;
    return null;
}

fn volumeGetMount(volume: ?*c.GVolume) callconv(.c) ?*c.GMount {
    const self: *GungnirVolume = @ptrCast(@alignCast(volume orelse return null));
    if (self.mount) |m| {
        return @ptrCast(c.g_object_ref(@ptrCast(m)));
    }
    return null;
}

fn volumeCanMount(volume: ?*c.GVolume) callconv(.c) c.gboolean {
    const self: *GungnirVolume = @ptrCast(@alignCast(volume orelse return 0));
    return if (self.mount == null) 1 else 0;
}

fn volumeCanEject(volume: ?*c.GVolume) callconv(.c) c.gboolean {
    _ = volume;
    return 0;
}

fn volumeShouldAutomount(volume: ?*c.GVolume) callconv(.c) c.gboolean {
    _ = volume;
    return 1;
}

fn volumeInterfaceInit(g_iface: c.gpointer, iface_data: c.gpointer) callconv(.c) void {
    _ = iface_data;
    const iface: *c.GVolumeIface = @ptrCast(@alignCast(g_iface));
    iface.get_name = &volumeGetName;
    iface.get_icon = &volumeGetIcon;
    iface.get_symbolic_icon = &volumeGetSymbolicIcon;
    iface.get_uuid = &volumeGetUuid;
    iface.get_drive = &volumeGetDrive;
    iface.get_mount = &volumeGetMount;
    iface.can_mount = &volumeCanMount;
    iface.can_eject = &volumeCanEject;
    iface.should_automount = &volumeShouldAutomount;
}

var volume_parent_class: ?*c.GObjectClass = null;

fn volumeFinalize(obj: [*c]c.GObject) callconv(.c) void {
    const self: *GungnirVolume = @ptrCast(@alignCast(obj));
    if (self.mount) |m| {
        c.g_object_unref(@ptrCast(m));
        self.mount = null;
    }
    if (volume_parent_class) |pc| {
        if (pc.finalize) |f| f(obj);
    }
}

fn volumeClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    volume_parent_class = @ptrCast(@alignCast(c.g_type_class_peek_parent(g_class)));
    const oc: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    oc.finalize = &volumeFinalize;
}

fn volumeInstanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = g_class;
    const self: *GungnirVolume = @ptrCast(@alignCast(instance));
    @memset(&self.name, 0);
    @memset(&self.uuid, 0);
    self.mount = null;
}

const volume_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirVolumeClass),
    .class_init = &volumeClassInit,
    .class_finalize = null,
    .instance_size = @sizeOf(GungnirVolume),
    .instance_init = &volumeInstanceInit,
};

const volume_iface_info = c.GInterfaceInfo{
    .interface_init = &volumeInterfaceInit,
    .interface_finalize = null,
    .interface_data = null,
};

// ---- GungnirVolumeMonitor: GNativeVolumeMonitor subclass ---------------------

pub const GungnirVolumeMonitor = extern struct {
    parent_instance: c.GNativeVolumeMonitor,
};

pub const GungnirVolumeMonitorClass = extern struct {
    parent_class: c.GNativeVolumeMonitorClass,
};

/// Environment variable and value that select this monitor (D-004: opt-in only).
pub const opt_in_env = "GIO_USE_VOLUME_MONITOR";
pub const opt_in_value = "gungnir";

/// D-004: the monitor is never active unless the user names it. GIO already prefers
/// GUnixVolumeMonitor (priority 0) over this one (-100) on the native extension point;
/// answering "unsupported" without GIO_USE_VOLUME_MONITOR=gungnir keeps it off even if
/// some caller enumerates the extension point itself (BC-HC-F01).
fn monitorIsSupported() callconv(.c) c.gboolean {
    const v = c.g_getenv(opt_in_env) orelse return 0;
    return @intFromBool(std.mem.eql(u8, std.mem.span(v), opt_in_value));
}

fn monitorGetConnectedDrives(monitor: [*c]c.GVolumeMonitor) callconv(.c) [*c]c.GList {
    _ = monitor;
    return null;
}

fn monitorGetMountForMountPath(mount_path_c: [*c]const u8, cancellable: [*c]c.GCancellable) callconv(.c) ?*c.GMount {
    _ = cancellable;
    if (mount_path_c == null) return null;
    const target = std.mem.span(mount_path_c);
    const mounts_list = parseMounts() catch return null;
    defer c.g_list_free_full(mounts_list, @ptrCast(&c.g_object_unref));

    var curr: ?*c.GList = mounts_list;
    while (curr) |node| : (curr = node.*.next) {
        const m: *c.GMount = @ptrCast(@alignCast(node.*.data));
        const self: *GungnirMount = @ptrCast(@alignCast(m));
        const mp = std.mem.span(@as([*:0]const u8, @ptrCast(&self.mount_point)));
        if (std.mem.eql(u8, mp, target)) {
            return @ptrCast(c.g_object_ref(@ptrCast(m)));
        }
    }
    return null;
}

fn parseMounts() !*c.GList {
    var raw_content: [*c]u8 = null;
    var length: c.gsize = 0;
    if (c.g_file_get_contents("/proc/self/mountinfo", &raw_content, &length, null) == 0) {
        return error.CannotOpenMountinfo;
    }
    defer c.g_free(raw_content);
    const content = raw_content[0..length];

    var list: ?*c.GList = null;
    var line_it = std.mem.splitScalar(u8, content, '\n');
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        var tok_it = std.mem.tokenizeScalar(u8, line, ' ');
        // 0: mnt_id, 1: parent_id, 2: major:minor, 3: root, 4: mount_point
        _ = tok_it.next() orelse continue; // mnt_id
        _ = tok_it.next() orelse continue; // parent_id
        _ = tok_it.next() orelse continue; // major:minor
        _ = tok_it.next() orelse continue; // root
        const mp_raw = tok_it.next() orelse continue;

        // Skip to '-' separator
        var fstype_tok: ?[]const u8 = null;
        while (tok_it.next()) |tok| {
            if (std.mem.eql(u8, tok, "-")) {
                fstype_tok = tok_it.next();
                break;
            }
        }
        const fstype = fstype_tok orelse continue;
        var mp_buf: [1024]u8 = undefined;
        const mp = unescape(mp_raw, &mp_buf);

        if (!isStorageFs(fstype, mp)) continue;

        const obj = c.g_object_new(mount_type, @as(?*const u8, null));
        if (obj == null) continue;
        const gmount: *GungnirMount = @ptrCast(@alignCast(obj));

        const c_mp_len = @min(mp.len, gmount.mount_point.len - 1);
        @memcpy(gmount.mount_point[0..c_mp_len], mp[0..c_mp_len]);
        gmount.mount_point[c_mp_len] = 0;

        // Human-friendly name
        const display_name = if (std.mem.eql(u8, mp, "/"))
            "Root Filesystem"
        else if (std.mem.eql(u8, mp, "/boot"))
            "Boot"
        else if (std.mem.lastIndexOfScalar(u8, mp, '/')) |idx|
            mp[idx + 1 ..]
        else
            mp;

        const c_name_len = @min(display_name.len, gmount.name.len - 1);
        @memcpy(gmount.name[0..c_name_len], display_name[0..c_name_len]);
        gmount.name[c_name_len] = 0;

        const c_fs_len = @min(fstype.len, gmount.fstype.len - 1);
        @memcpy(gmount.fstype[0..c_fs_len], fstype[0..c_fs_len]);
        gmount.fstype[c_fs_len] = 0;

        gmount.is_network = if (isNetworkFs(fstype)) 1 else 0;

        list = c.g_list_prepend(list, gmount);
    }
    return c.g_list_reverse(list) orelse return error.NoMounts;
}

fn monitorGetMounts(monitor: [*c]c.GVolumeMonitor) callconv(.c) [*c]c.GList {
    _ = monitor;
    return parseMounts() catch null;
}

fn monitorGetVolumes(monitor: [*c]c.GVolumeMonitor) callconv(.c) [*c]c.GList {
    const mounts_list = monitorGetMounts(monitor);
    if (mounts_list == null) return null;
    defer c.g_list_free_full(mounts_list, @ptrCast(&c.g_object_unref));

    var vol_list: ?*c.GList = null;
    var curr = mounts_list;
    while (curr != null) : (curr = curr.*.next) {
        const m: *c.GMount = @ptrCast(@alignCast(curr.*.data));
        const obj = c.g_object_new(volume_type, @as(?*const u8, null));
        if (obj == null) continue;
        const gvol: *GungnirVolume = @ptrCast(@alignCast(obj));

        const name_c = c.g_mount_get_name(m);
        defer c.g_free(name_c);
        if (name_c != null) {
            const name_span = std.mem.span(name_c);
            const copy_len = @min(name_span.len, gvol.name.len - 1);
            @memcpy(gvol.name[0..copy_len], name_span[0..copy_len]);
            gvol.name[copy_len] = 0;
        }

        gvol.mount = @ptrCast(c.g_object_ref(@ptrCast(m)));
        vol_list = c.g_list_prepend(vol_list, gvol);
    }
    return c.g_list_reverse(vol_list);
}

fn monitorGetMountForUuid(monitor: [*c]c.GVolumeMonitor, uuid_c: [*c]const u8) callconv(.c) ?*c.GMount {
    if (uuid_c == null) return null;
    const target = std.mem.span(uuid_c);
    const mounts_list = monitorGetMounts(monitor);
    if (mounts_list == null) return null;
    defer c.g_list_free_full(mounts_list, @ptrCast(&c.g_object_unref));

    var curr = mounts_list;
    while (curr != null) : (curr = curr.*.next) {
        const m: *c.GMount = @ptrCast(@alignCast(curr.*.data));
        const u = c.g_mount_get_uuid(m);
        defer if (u != null) c.g_free(u);
        if (u != null and std.mem.eql(u8, std.mem.span(u), target)) {
            return @ptrCast(c.g_object_ref(@ptrCast(m)));
        }
    }
    return null;
}

fn monitorGetVolumeForUuid(monitor: [*c]c.GVolumeMonitor, uuid_c: [*c]const u8) callconv(.c) ?*c.GVolume {
    if (uuid_c == null) return null;
    const target = std.mem.span(uuid_c);
    const vols_list = monitorGetVolumes(monitor);
    if (vols_list == null) return null;
    defer c.g_list_free_full(vols_list, @ptrCast(&c.g_object_unref));

    var curr = vols_list;
    while (curr != null) : (curr = curr.*.next) {
        const v: *c.GVolume = @ptrCast(@alignCast(curr.*.data));
        const u = c.g_volume_get_uuid(v);
        defer if (u != null) c.g_free(u);
        if (u != null and std.mem.eql(u8, std.mem.span(u), target)) {
            return @ptrCast(c.g_object_ref(@ptrCast(v)));
        }
    }
    return null;
}

fn monitorClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    const native_klass: *c.GNativeVolumeMonitorClass = @ptrCast(@alignCast(g_class));
    native_klass.get_mount_for_mount_path = &monitorGetMountForMountPath;

    const klass: *c.GVolumeMonitorClass = &native_klass.parent_class;
    klass.is_supported = &monitorIsSupported;
    klass.get_connected_drives = &monitorGetConnectedDrives;
    klass.get_volumes = &monitorGetVolumes;
    klass.get_mounts = &monitorGetMounts;
    klass.get_volume_for_uuid = &monitorGetVolumeForUuid;
    klass.get_mount_for_uuid = &monitorGetMountForUuid;
}

fn monitorInstanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = instance;
    _ = g_class;
}

const monitor_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirVolumeMonitorClass),
    .class_init = &monitorClassInit,
    .class_finalize = null,
    .instance_size = @sizeOf(GungnirVolumeMonitor),
    .instance_init = &monitorInstanceInit,
};

// ---- Module Registration -----------------------------------------------------

pub fn register(module: *c.GTypeModule) void {
    mount_type = c.g_type_module_register_type(module, c.g_object_get_type(), mount_type_name, &mount_type_info, 0);
    if (mount_type != 0) {
        c.g_type_module_add_interface(module, mount_type, c.g_mount_get_type(), &mount_iface_info);
    } else {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register %s", mount_type_name.ptr);
    }

    volume_type = c.g_type_module_register_type(module, c.g_object_get_type(), volume_type_name, &volume_type_info, 0);
    if (volume_type != 0) {
        c.g_type_module_add_interface(module, volume_type, c.g_volume_get_type(), &volume_iface_info);
    } else {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register %s", volume_type_name.ptr);
    }

    volume_monitor_type = c.g_type_module_register_type(module, c.g_native_volume_monitor_get_type(), monitor_type_name, &monitor_type_info, 0);
    if (volume_monitor_type != 0) {
        // Native extension point only, below GUnixVolumeMonitor: GIO picks it only for
        // GIO_USE_VOLUME_MONITOR=gungnir. Never G_VOLUME_MONITOR_EXTENSION_POINT_NAME:
        // GUnionVolumeMonitor adds every supported monitor there to every GIO process,
        // so the module would be live without any opt-in (D-004, BC-HC-F01).
        _ = c.g_io_extension_point_implement(c.G_NATIVE_VOLUME_MONITOR_EXTENSION_POINT_NAME, volume_monitor_type, opt_in_value, -100);
    } else {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register %s", monitor_type_name.ptr);
    }
}

// ---- Tests -------------------------------------------------------------------

test "unescape handles octal sequences" {
    var buf: [64]u8 = undefined;
    const res = unescape("My\\040Drive", &buf);
    try std.testing.expectEqualStrings("My Drive", res);

    // Regression test: octal escapes >= 400 (e.g. \400, \777) must never integer-overflow or panic
    const res_over = unescape("Path\\400Invalid", &buf);
    try std.testing.expectEqualStrings("Path\\400Invalid", res_over);

    const res_max = unescape("Path\\777Invalid", &buf);
    try std.testing.expectEqualStrings("Path\\777Invalid", res_max);

    // Edge boundary: \377 (255) is the maximum single-byte octal escape
    const res_255 = unescape("Byte\\377End", &buf);
    try std.testing.expectEqualStrings("Byte\xFFEnd", res_255);

    // Truncated escape at end
    const res_trunc = unescape("Truncated\\04", &buf);
    try std.testing.expectEqualStrings("Truncated\\04", res_trunc);
}

test "isStorageFs filters virtual filesystems" {
    try std.testing.expect(!isStorageFs("proc", "/proc"));
    try std.testing.expect(!isStorageFs("sysfs", "/sys"));
    try std.testing.expect(!isStorageFs("cgroup2", "/sys/fs/cgroup"));
    try std.testing.expect(isStorageFs("ext4", "/"));
    try std.testing.expect(isStorageFs("btrfs", "/home"));
    try std.testing.expect(isStorageFs("nfs", "/mnt/share"));
    try std.testing.expect(isStorageFs("tmpfs", "/tmp"));
    try std.testing.expect(!isStorageFs("tmpfs", "/run/user/1000"));
}

test "isNetworkFs recognizes network filesystems" {
    try std.testing.expect(isNetworkFs("nfs"));
    try std.testing.expect(isNetworkFs("nfs4"));
    try std.testing.expect(isNetworkFs("cifs"));
    try std.testing.expect(!isNetworkFs("btrfs"));
    try std.testing.expect(!isNetworkFs("ext4"));
}

pub fn ensureRegisteredForTest() void {
    if (mount_type == 0) {
        mount_type = c.g_type_register_static_simple(c.g_object_get_type(), "GungnirMountStatic", @sizeOf(GungnirMountClass), &mountClassInit, @sizeOf(GungnirMount), &mountInstanceInit, 0);
        c.g_type_add_interface_static(mount_type, c.g_mount_get_type(), &mount_iface_info);
    }
}

test "parseMounts extracts live mounts from mountinfo" {
    ensureRegisteredForTest();
    const mounts = parseMounts() catch |err| {
        // If /proc/self/mountinfo is inaccessible in restricted sandbox, skip gracefully
        if (err == error.CannotOpenMountinfo) return;
        return err;
    };
    defer c.g_list_free_full(mounts, @ptrCast(&c.g_object_unref));
    try std.testing.expect(mounts.*.data != null);
    const first_mount: *c.GMount = @ptrCast(@alignCast(mounts.*.data));
    const name = c.g_mount_get_name(first_mount);
    defer if (name != null) c.g_free(name);
    try std.testing.expect(name != null);
    const root = c.g_mount_get_root(first_mount);
    defer if (root != null) c.g_object_unref(root);
    try std.testing.expect(root != null);
}
