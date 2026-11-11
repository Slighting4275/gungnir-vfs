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
const mountfilter = @import("mountfilter.zig");
const health = @import("health.zig");

pub const monitor_type_name = "GungnirVolumeMonitor";
pub const mount_type_name = "GungnirMount";
pub const volume_type_name = "GungnirVolume";

pub var volume_monitor_type: c.GType = 0;
pub var mount_type: c.GType = 0;
pub var volume_type: c.GType = 0;

// ---- Unescape octal paths from mountinfo --------------------------------------

pub const unescape = mountfilter.unescape;

// ---- Mount filtering ---------------------------------------------------------

pub const shouldDisplay = mountfilter.shouldDisplay;

/// The user the display rule is evaluated for, as GLib reads it: the user name, the home
/// directory and whether the process runs as root. No syscall on any mount.
pub fn processUser() mountfilter.User {
    const name = c.g_get_user_name();
    const home = c.g_get_home_dir();
    return .{
        .name = if (name != null) std.mem.span(@as([*:0]const u8, @ptrCast(name))) else "",
        .home = if (home != null) std.mem.span(@as([*:0]const u8, @ptrCast(home))) else "",
        .is_root = std.os.linux.getuid() == 0,
    };
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
    /// Its GungnirVolume (strong; the volume points back weakly, so no cycle).
    volume: ?*c.GVolume,
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

/// The mount's volume, a new reference (DIB-F016: NULL here made Nemo and `gio mount -l`
/// list every mount twice, once under its volume and once as a volume-less mount).
fn mountGetVolume(mount: ?*c.GMount) callconv(.c) ?*c.GVolume {
    const self: *GungnirMount = @ptrCast(@alignCast(mount orelse return null));
    const v = self.volume orelse return null;
    return @ptrCast(c.g_object_ref(@ptrCast(v)));
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

var mount_parent_class: ?*c.GObjectClass = null;

fn mountFinalize(obj: [*c]c.GObject) callconv(.c) void {
    const self: *GungnirMount = @ptrCast(@alignCast(obj));
    if (self.volume) |v| {
        self.volume = null;
        c.g_object_unref(@ptrCast(v));
    }
    if (mount_parent_class) |pc| {
        if (pc.finalize) |f| f(obj);
    }
}

fn mountClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    mount_parent_class = @ptrCast(@alignCast(c.g_type_class_peek_parent(g_class)));
    const oc: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    oc.finalize = &mountFinalize;
}

fn mountInstanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = g_class;
    const self: *GungnirMount = @ptrCast(@alignCast(instance));
    @memset(&self.mount_point, 0);
    @memset(&self.name, 0);
    @memset(&self.fstype, 0);
    @memset(&self.uuid, 0);
    self.is_network = 0;
    self.volume = null;
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
    /// Its GungnirMount, weakly: the mount owns the volume.
    mount: c.GWeakRef,
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

/// The volume's mount, a new reference, or NULL once the mount is gone.
fn volumeGetMount(volume: ?*c.GVolume) callconv(.c) ?*c.GMount {
    const self: *GungnirVolume = @ptrCast(@alignCast(volume orelse return null));
    return @ptrCast(@alignCast(c.g_weak_ref_get(&self.mount)));
}

fn volumeCanMount(volume: ?*c.GVolume) callconv(.c) c.gboolean {
    const m = volumeGetMount(volume) orelse return 1;
    c.g_object_unref(@ptrCast(m));
    return 0;
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
    c.g_weak_ref_clear(&self.mount);
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
    c.g_weak_ref_init(&self.mount, null);
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
    /// Guards the fields below; get_mounts/get_volumes may come from any thread.
    lock: c.GMutex,
    /// The mounts (strong refs; each owns its volume) parsed from `last`, so the same
    /// mountinfo gives the same objects and a volume's mount stays alive.
    mounts: ?*c.GList,
    last: [*c]u8,
    last_len: c.gsize,
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
    return mountsFrom(raw_content[0..length]);
}

/// A new GungnirVolume for `gmount`, owned by it; the volume points back weakly.
fn attachVolume(gmount: *GungnirMount) void {
    if (volume_type == 0) return;
    const obj = c.g_object_new(volume_type, @as(?*const u8, null)) orelse return;
    const gvol: *GungnirVolume = @ptrCast(@alignCast(obj));
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(&gmount.name)));
    const n = @min(name.len, gvol.name.len - 1);
    @memcpy(gvol.name[0..n], name[0..n]);
    gvol.name[n] = 0;
    @memcpy(&gvol.uuid, &gmount.uuid);
    c.g_weak_ref_set(&gvol.mount, @ptrCast(gmount));
    gmount.volume = @ptrCast(@alignCast(obj));
}

/// One GungnirMount (with its volume) per accepted mount point of `content`. A mount
/// point mounted over again appears once, as its topmost (last) mount.
fn mountsFrom(content: []const u8) !*c.GList {
    var list: ?*c.GList = null;
    const user = processUser();
    var line_it = std.mem.splitScalar(u8, content, '\n');
    while (line_it.next()) |line| {
        var line_buf: mountfilter.LineBuf = .{};
        const entry = mountfilter.parseLine(line, &line_buf) orelse continue;
        if (!shouldDisplay(entry, user)) continue;
        const mp = entry.mount_point;
        const fstype = entry.fstype;

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
        attachVolume(gmount);

        // Over-mounted: drop the earlier mount at the same point.
        var it: ?*c.GList = list;
        while (it) |node| : (it = node.*.next) {
            const old: *GungnirMount = @ptrCast(@alignCast(node.*.data));
            if (std.mem.eql(u8, std.mem.sliceTo(&old.mount_point, 0), std.mem.sliceTo(&gmount.mount_point, 0))) {
                list = c.g_list_delete_link(list, node);
                c.g_object_unref(@ptrCast(old));
                break;
            }
        }
        list = c.g_list_prepend(list, gmount);
    }
    return c.g_list_reverse(list) orelse return error.NoMounts;
}

fn refObject(src: c.gconstpointer, data: c.gpointer) callconv(.c) c.gpointer {
    _ = data;
    return c.g_object_ref(@constCast(src));
}

/// The monitor's mounts for the current mountinfo, as a new list of new references:
/// the cached objects while mountinfo is unchanged, else freshly parsed ones.
fn currentMounts(monitor: [*c]c.GVolumeMonitor) ?*c.GList {
    const self: *GungnirVolumeMonitor = @ptrCast(@alignCast(monitor orelse return null));
    var raw: [*c]u8 = null;
    var len: c.gsize = 0;
    if (c.g_file_get_contents("/proc/self/mountinfo", &raw, &len, null) == 0) return null;
    c.g_mutex_lock(&self.lock);
    defer c.g_mutex_unlock(&self.lock);
    if (self.last != null and self.last_len == len and std.mem.eql(u8, self.last[0..self.last_len], raw[0..len])) {
        c.g_free(raw);
    } else {
        const fresh = mountsFrom(raw[0..len]) catch null;
        c.g_list_free_full(self.mounts, @ptrCast(&c.g_object_unref));
        c.g_free(self.last);
        self.mounts = fresh;
        self.last = raw;
        self.last_len = len;
    }
    return c.g_list_copy_deep(self.mounts, &refObject, null);
}

fn monitorGetMounts(monitor: [*c]c.GVolumeMonitor) callconv(.c) [*c]c.GList {
    return currentMounts(monitor);
}

/// Each mount's own volume (mount and volume point at each other, DIB-F016).
fn monitorGetVolumes(monitor: [*c]c.GVolumeMonitor) callconv(.c) [*c]c.GList {
    const mounts_list = currentMounts(monitor) orelse return null;
    defer c.g_list_free_full(mounts_list, @ptrCast(&c.g_object_unref));

    var vol_list: ?*c.GList = null;
    var curr: ?*c.GList = mounts_list;
    while (curr) |node| : (curr = node.*.next) {
        const gm: *GungnirMount = @ptrCast(@alignCast(node.*.data));
        const v = gm.volume orelse continue;
        vol_list = c.g_list_prepend(vol_list, c.g_object_ref(@ptrCast(v)));
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

var monitor_parent_class: ?*c.GObjectClass = null;

fn monitorFinalize(obj: [*c]c.GObject) callconv(.c) void {
    const self: *GungnirVolumeMonitor = @ptrCast(@alignCast(obj));
    c.g_list_free_full(self.mounts, @ptrCast(&c.g_object_unref));
    self.mounts = null;
    c.g_free(self.last);
    self.last = null;
    c.g_mutex_clear(&self.lock);
    if (monitor_parent_class) |pc| {
        if (pc.finalize) |f| f(obj);
    }
}

fn monitorClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    monitor_parent_class = @ptrCast(@alignCast(c.g_type_class_peek_parent(g_class)));
    const oc: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    oc.finalize = &monitorFinalize;
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
    _ = g_class;
    const self: *GungnirVolumeMonitor = @ptrCast(@alignCast(instance));
    c.g_mutex_init(&self.lock);
    self.mounts = null;
    self.last = null;
    self.last_len = 0;
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

test "mountsFrom lists only what the display rule keeps, each mount point once" {
    ensureRegisteredForTest();
    const user = processUser();
    // The fixture writes the home directory into mountinfo unescaped.
    if (user.home.len < 2 or std.mem.indexOfAny(u8, user.home, " \t\n\\") != null or std.mem.indexOf(u8, user.home, "/.") != null)
        return error.SkipZigTest;
    var path_buf: [1100]u8 = undefined;
    const own = std.fmt.bufPrint(&path_buf, "{s}/own-store", .{user.home}) catch return error.SkipZigTest;
    var info_buf: [4096]u8 = undefined;
    const info = std.fmt.bufPrint(&info_buf,
        \\1 0 0:1 / / rw - btrfs /dev/sda2 rw
        \\2 1 0:2 / /proc rw - proc proc rw
        \\3 1 0:3 / /media rw - tmpfs tmpfs rw
        \\4 3 0:4 / /media/stick rw - ramfs none2 rw
        \\5 3 0:5 / /media/stick rw - vfat /dev/sdb1 rw
        \\6 1 0:6 / {s} rw - ramfs none3 rw
        \\7 1 0:7 /sub /media/bind rw - ext4 /dev/sdc1 rw
        \\8 1 0:8 / /cursor/stores rw - fuse.agent-store agent rw
        \\
    , .{own}) catch return error.SkipZigTest;
    const list = try mountsFrom(info);
    defer c.g_list_free_full(list, @ptrCast(&c.g_object_unref));
    try std.testing.expectEqual(@as(c.guint, 2), c.g_list_length(list));
    const first: *GungnirMount = @ptrCast(@alignCast(list.*.data));
    const second: *GungnirMount = @ptrCast(@alignCast(list.*.next.*.data));
    // The stick was mounted over: only the topmost (vfat) mount is listed.
    try std.testing.expectEqualStrings("/media/stick", std.mem.sliceTo(&first.mount_point, 0));
    try std.testing.expectEqualStrings("vfat", std.mem.sliceTo(&first.fstype, 0));
    try std.testing.expectEqualStrings(own, std.mem.sliceTo(&second.mount_point, 0));
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
    if (volume_type == 0) {
        volume_type = c.g_type_register_static_simple(c.g_object_get_type(), "GungnirVolumeStatic", @sizeOf(GungnirVolumeClass), &volumeClassInit, @sizeOf(GungnirVolume), &volumeInstanceInit, 0);
        c.g_type_add_interface_static(volume_type, c.g_volume_get_type(), &volume_iface_info);
    }
}

test "a mount and its volume point at each other and are freed together (DIB-F016)" {
    ensureRegisteredForTest();
    const text = "22 1 0:21 / /media/disk rw - ext4 /dev/sda1 rw\n" ++
        "23 22 0:22 / /media/home rw - btrfs /dev/sda2 rw\n" ++
        "24 22 0:23 / /media/home rw - btrfs /dev/sda3 rw\n" ++
        "25 22 0:24 / /proc rw - proc proc rw\n";
    const list = try mountsFrom(text);
    // /media/home mounted twice appears once (the top one); /proc is filtered out.
    try std.testing.expectEqual(@as(c.guint, 2), c.g_list_length(list));
    var vol_gone: c.gpointer = null;
    var mount_gone: c.gpointer = null;
    {
        const m: *c.GMount = @ptrCast(@alignCast(list.*.next.*.data));
        const v = c.g_mount_get_volume(m) orelse return error.NoVolume;
        const back = c.g_volume_get_mount(v) orelse return error.NoMount;
        try std.testing.expect(back == m);
        c.g_object_unref(back);
        const name = c.g_volume_get_name(v);
        defer c.g_free(name);
        try std.testing.expectEqualStrings("home", std.mem.span(name));
        vol_gone = @ptrCast(v);
        mount_gone = @ptrCast(m);
        c.g_object_add_weak_pointer(@ptrCast(@alignCast(v)), &vol_gone);
        c.g_object_add_weak_pointer(@ptrCast(@alignCast(m)), &mount_gone);
        // Hold only the volume: the mount stays (the list owns it); once the list is
        // freed the mount goes, and the volume reports no mount.
        c.g_list_free_full(list, @ptrCast(&c.g_object_unref));
        try std.testing.expect(mount_gone == null);
        try std.testing.expect(vol_gone != null);
        try std.testing.expect(c.g_volume_get_mount(v) == null);
        c.g_object_unref(@ptrCast(v));
    }
    try std.testing.expect(vol_gone == null);
}

test "parseMounts extracts live mounts from mountinfo" {
    ensureRegisteredForTest();
    const mounts = parseMounts() catch |err| {
        // If /proc/self/mountinfo is inaccessible in restricted sandbox, skip gracefully.
        // A machine may also have no storage the display rule keeps (F01b: GLib hides
        // /, /home and /boot); the fixtures above cover the rule itself.
        if (err == error.CannotOpenMountinfo or err == error.NoMounts) return error.SkipZigTest;
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
