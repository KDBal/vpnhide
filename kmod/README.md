# vpnhide -- Kernel module

kretprobe-based kernel module that hides VPN interfaces from selected apps. Part of [vpnhide](../README.md).

Zero footprint in the target app's process -- no modified function prologues, no framework classes, no anonymous memory regions. Invisible to aggressive anti-tamper SDKs.

## What it hooks

| kretprobe target | What it filters | Detection path covered |
|---|---|---|
| `dev_ioctl` | `SIOCGIFFLAGS`, `SIOCGIFNAME`: returns `-ENODEV` for VPN interfaces | Direct `ioctl()` calls from native code (Flutter/Dart, JNI, C/C++) |
| `dev_ifconf` | `SIOCGIFCONF`: compacts VPN entries out of the returned interface array | Interface enumeration via `ioctl(SIOCGIFCONF)` |
| `rtnl_fill_ifinfo` | Returns `-EMSGSIZE` for VPN devices during RTM_NEWLINK netlink dumps, causing the kernel to skip them | `getifaddrs()` (which uses netlink internally), any netlink-based interface enumeration |
| `inet6_fill_ifaddr` | Trims VPN entries from RTM_GETADDR IPv6 responses via `skb_trim` | IPv6 address enumeration over netlink |
| `inet_fill_ifaddr` | Trims VPN entries from RTM_GETADDR IPv4 responses via `skb_trim` | IPv4 address enumeration over netlink |
| `fib_route_seq_show` | Forward-scans for VPN lines and compacts them out with `memmove` | `/proc/net/route` reads |

All filtering is **per-UID**: only processes whose UID appears in `/proc/vpnhide_targets` see the filtered view. Everyone else (system services, VPN client, NFC subsystem) sees the real data.

## Why kernel-level?

Some anti-tamper SDKs read `/proc/self/maps` via raw `svc #0` syscalls (bypassing any libc hook) and check ELF relocation integrity. No userspace interposition can hide from them.

Kernel kretprobes modify kernel function behavior, not userspace code. The target app's process memory, ELF tables, and `/proc/self/maps` are completely untouched.

## GKI compatibility

All symbols used (`register_kretprobe`, `proc_create`, `seq_read`, etc.) are part of the stable GKI KMI, so the same `Module.symvers` CRCs work across all devices running the same GKI generation. The C source is identical across generations -- only the kernel headers and CRCs differ.

KernelSU bypasses the kernel's vermagic check, so no runtime patching is needed. `post-fs-data.sh` simply runs `insmod` directly.

CI builds are provided for all 7 GKI generations: `android12-5.10` through `android16-6.12`.

## Build

See [BUILDING.md](BUILDING.md) for the full guide (DDK Docker build, kernel source preparation, toolchain setup, `Module.symvers` generation).

```bash
cd kmod && ./build-zip.sh
```

## Install

1. `adb push vpnhide-kmod.zip /sdcard/Download/`
2. KernelSU-Next manager -> Modules -> Install from storage
3. Reboot

On boot:
- `post-fs-data.sh` runs `insmod` to load the kernel module
- `service.sh` resolves package names from `targets.txt` to UIDs via `pm list packages -U` and writes them to `/proc/vpnhide_targets`

### Target management

**WebUI (recommended):** open the module in KernelSU-Next manager and tap the WebUI entry. Select apps, save. The WebUI writes to **three places** simultaneously:
1. `targets.txt` -- persistent package names (survives module updates)
2. `/proc/vpnhide_targets` -- resolved UIDs for the kernel module
3. `/data/system/vpnhide_uids.txt` -- resolved UIDs for the [lsposed](../lsposed/) module's system_server hooks (live reload via inotify)

All changes apply immediately -- no reboot needed.

**Shell:**
```bash
# Write package names to the persistent config
adb shell su -c 'echo "com.example.targetapp" > /data/adb/vpnhide_kmod/targets.txt'

# Or write UIDs directly to the kernel module
adb shell su -c 'echo 10423 > /proc/vpnhide_targets'
```

## Combined use with system_server hooks

For apps with aggressive anti-tamper SDKs, full VPN hiding requires covering both native and Java API detection paths -- without placing any hooks in the target app's process:

- **vpnhide-kmod** (this module) covers the native side: `ioctl`, `getifaddrs()` (netlink), `/proc/net/route`, and netlink address enumeration.
- **[lsposed](../lsposed/)** hooks `writeToParcel()` on `NetworkCapabilities`, `NetworkInfo`, `LinkProperties` inside `system_server` -- stripping VPN data before Binder serialization reaches the app.

Together they provide complete VPN hiding without any hooks in the target app's process.

### Setup

1. Install **vpnhide-kmod** as a KSU module (this module).
2. Install **[lsposed](../lsposed/)** as an LSPosed/Vector module and add **"System Framework"** to its scope (no other apps in scope).
3. Pick target apps in vpnhide-kmod's WebUI -- it manages targets for both the kernel module and the system_server hooks.

## Architecture notes

### Why kretprobes work here

kretprobes instrument kernel functions by replacing their return address on the stack. Unlike userspace inline hooks (which modify instruction bytes), kretprobes:

- Don't modify the target function's code in a way visible to userspace -- `/proc/self/maps` and the function's ELF bytes are unchanged
- Can't be detected by the target app -- the app can only inspect its own process memory, not kernel data structures
- Work on any function visible in `/proc/kallsyms`, including static (non-exported) functions

### dev_ioctl calling convention (GKI 6.1, arm64)

```c
int dev_ioctl(struct net *net,       // x0
              unsigned int cmd,       // x1
              struct ifreq *ifr,      // x2 -- KERNEL pointer
              void __user *data,      // x3 -- userspace pointer
              bool *need_copyout)     // x4
```

**Important:** `x2` is a kernel-space pointer (the caller already did `copy_from_user`). Using `copy_from_user` on it will EFAULT on ARM64 with PAN enabled. The return handler reads via direct pointer dereference.

### rtnl_fill_ifinfo trick

To skip a VPN interface during a netlink dump without corrupting the message stream, the return handler sets the return value to `-EMSGSIZE`. The dump iterator interprets this as "skb too small for this entry" and moves to the next device without adding the current one -- effectively skipping it. The entry is never seen by userspace.

## License

MIT. See [LICENSE](../LICENSE).

The compiled module declares `MODULE_LICENSE("GPL")` as required by the Linux kernel to resolve `EXPORT_SYMBOL_GPL` symbols (`register_kretprobe`, `proc_create`, etc.) at runtime.
