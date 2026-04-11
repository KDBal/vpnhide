package dev.okhsunrog.vpnhide

import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import android.os.Binder
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader

/**
 * VpnHide — hide VPN presence from apps via system_server Binder hooks.
 *
 * Hooks writeToParcel() on NetworkCapabilities, NetworkInfo, and
 * LinkProperties inside system_server. When the Binder caller is a
 * target UID, VPN-related data is stripped before serialization —
 * the app receives clean data without any in-process hooks.
 *
 * This covers all Java API detection paths:
 *   - NetworkCapabilities: hasTransport(VPN), hasCapability(NOT_VPN),
 *     getTransportTypes(), getTransportInfo(), toString()
 *   - NetworkInfo: getType(), getTypeName()
 *   - ConnectivityManager: all methods that return NetworkCapabilities,
 *     NetworkInfo, or LinkProperties over Binder
 *   - LinkProperties: getInterfaceName(), getRoutes(), getDnsServers()
 *
 * Native detection paths (getifaddrs, ioctl, /proc/net) are covered
 * by vpnhide-kmod (kernel module) or vpnhide-zygisk (in-process hooks).
 *
 * Only "System Framework" needs to be in LSPosed scope.
 */
class HookEntry : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        // Only hook system_server. handleLoadPackage fires multiple times
        // in system_server (once per hosted package / APEX), so we use a
        // flag to install hooks exactly once.
        val inSystemServer = isSystemServer ||
            lpparam.processName == "android" ||
            android.os.Process.myUid() == 1000

        if (!inSystemServer) return

        if (!isSystemServer) {
            isSystemServer = true
            XposedBridge.log("VpnHide: system_server detected, installing Binder hooks")
            installSystemServerHooks()
        }
    }

    @Volatile private var isSystemServer = false

    private inline fun tryHook(name: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            XposedBridge.log("VpnHide: $name hook failed: ${t::class.java.simpleName}: ${t.message}")
        }
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private fun isVpnInterfaceName(name: String): Boolean {
        if (name.isEmpty()) return false
        val n = name.lowercase()
        return n.startsWith("tun") ||
            n.startsWith("ppp") ||
            n.startsWith("tap") ||
            n.startsWith("wg") ||
            n.startsWith("ipsec") ||
            n.startsWith("xfrm") ||
            n.startsWith("utun") ||
            n.startsWith("l2tp") ||
            n.startsWith("gre") ||
            n.contains("vpn")
    }

    // ==================================================================
    //  system_server hooks — per-UID Binder filtering
    // ==================================================================

    @Volatile private var systemServerTargetUids: Set<Int>? = null
    @Volatile private var targetUidsFileObserver: android.os.FileObserver? = null

    private fun loadTargetUids(): Set<Int> {
        systemServerTargetUids?.let { return it }

        val uids = mutableSetOf<Int>()

        // Read pre-resolved numeric UIDs written by vpnhide-kmod's
        // service.sh into /data/system/vpnhide_uids.txt.
        // system_server can read /data/system/ (SELinux: system_data_file).
        try {
            val file = File("/data/system/vpnhide_uids.txt")
            if (file.exists()) {
                file.readLines().forEach { line ->
                    line.trim().toIntOrNull()?.let { uids.add(it) }
                }
            }
        } catch (t: Throwable) {
            XposedBridge.log("VpnHide: failed to read UIDs: ${t.message}")
        }

        if (uids.isNotEmpty()) {
            XposedBridge.log("VpnHide: system_server loaded ${uids.size} target UIDs: $uids")
            systemServerTargetUids = uids
        }
        return uids
    }

    private fun isTargetCaller(): Boolean {
        val uid = Binder.getCallingUid()
        return loadTargetUids().contains(uid)
    }

    private fun invalidateTargetUids() {
        systemServerTargetUids = null
    }

    private fun installSystemServerHooks() {
        tryHook("NC.writeToParcel") { hookNCWriteToParcel() }
        tryHook("NI.writeToParcel") { hookNIWriteToParcel() }
        tryHook("LP.writeToParcel") { hookLPWriteToParcel() }
        tryHook("FileObserver")     { watchTargetUidsFile() }
    }

    /**
     * Watch /data/system/vpnhide_uids.txt for changes via inotify.
     * When modified (e.g. by vpnhide-kmod's WebUI), invalidate the
     * cached UID set so the next writeToParcel call re-reads it.
     */
    private fun watchTargetUidsFile() {
        val dir = "/data/system"
        val filename = "vpnhide_uids.txt"
        val observer = object : android.os.FileObserver(
            File(dir),
            CREATE or CLOSE_WRITE or MOVED_TO or MODIFY
        ) {
            override fun onEvent(event: Int, path: String?) {
                if (path == filename) {
                    XposedBridge.log("VpnHide: $filename changed (event=$event), invalidating UID cache")
                    systemServerTargetUids = null
                }
            }
        }
        targetUidsFileObserver = observer
        observer.startWatching()
        XposedBridge.log("VpnHide: watching $dir for $filename changes (inotify)")
    }

    /**
     * Hook NetworkCapabilities.writeToParcel in system_server.
     * Before serialization, strip VPN transport if the Binder caller
     * is a target UID. Saves and restores original values to avoid
     * corrupting ConnectivityService's internal state.
     */
    private fun hookNCWriteToParcel() {
        XposedHelpers.findAndHookMethod(
            NetworkCapabilities::class.java, "writeToParcel",
            android.os.Parcel::class.java, Integer.TYPE,
            object : XC_MethodHook() {
                private val savedTransport = ThreadLocal<Long>()
                private val savedCaps = ThreadLocal<Long>()
                private val savedTi = ThreadLocal<Any?>()

                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (!loadTargetUids().contains(Binder.getCallingUid())) return

                    val nc = param.thisObject
                    try {
                        val transportTypes = XposedHelpers.getLongField(nc, "mTransportTypes")
                        val vpnBit = 1L shl TRANSPORT_VPN
                        if (transportTypes and vpnBit == 0L) return

                        savedTransport.set(transportTypes)
                        val caps = XposedHelpers.getLongField(nc, "mNetworkCapabilities")
                        savedCaps.set(caps)
                        val ti = try { XposedHelpers.getObjectField(nc, "mTransportInfo") } catch (_: Throwable) { null }
                        savedTi.set(ti)

                        XposedHelpers.setLongField(nc, "mTransportTypes", transportTypes and vpnBit.inv())
                        XposedHelpers.setLongField(nc, "mNetworkCapabilities", caps or (1L shl NET_CAPABILITY_NOT_VPN))
                        if (ti != null && ti.javaClass.name == "android.net.VpnTransportInfo") {
                            XposedHelpers.setObjectField(nc, "mTransportInfo", null)
                        }
                    } catch (t: Throwable) {
                        XposedBridge.log("VpnHide: NC.writeToParcel before error: ${t.message}")
                    }
                }

                override fun afterHookedMethod(param: MethodHookParam) {
                    val origTransport = savedTransport.get() ?: return
                    savedTransport.remove()
                    val nc = param.thisObject
                    try {
                        XposedHelpers.setLongField(nc, "mTransportTypes", origTransport)
                        savedCaps.get()?.let { XposedHelpers.setLongField(nc, "mNetworkCapabilities", it) }
                        savedCaps.remove()
                        XposedHelpers.setObjectField(nc, "mTransportInfo", savedTi.get())
                        savedTi.remove()
                    } catch (_: Throwable) {}
                }
            }
        )
        XposedBridge.log("VpnHide: hooked NetworkCapabilities.writeToParcel")
    }

    /**
     * Hook NetworkInfo.writeToParcel — skip VPN NetworkInfo for target callers.
     */
    private fun hookNIWriteToParcel() {
        XposedHelpers.findAndHookMethod(
            NetworkInfo::class.java, "writeToParcel",
            android.os.Parcel::class.java, Integer.TYPE,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (!isTargetCaller()) return
                    val info = param.thisObject as NetworkInfo
                    @Suppress("DEPRECATION")
                    if (info.type == TYPE_VPN) {
                        param.result = null
                    }
                }
            }
        )
        XposedBridge.log("VpnHide: hooked NetworkInfo.writeToParcel")
    }

    /**
     * Hook LinkProperties.writeToParcel — null out VPN-interface LPs
     * for target callers.
     */
    private fun hookLPWriteToParcel() {
        XposedHelpers.findAndHookMethod(
            LinkProperties::class.java, "writeToParcel",
            android.os.Parcel::class.java, Integer.TYPE,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (!isTargetCaller()) return
                    val lp = param.thisObject as LinkProperties
                    val ifname = lp.interfaceName ?: return
                    if (isVpnInterfaceName(ifname)) {
                        param.result = null
                    }
                }
            }
        )
        XposedBridge.log("VpnHide: hooked LinkProperties.writeToParcel")
    }

    companion object {
        private const val TRANSPORT_VPN = 4
        private const val NET_CAPABILITY_NOT_VPN = 15
        private const val TYPE_VPN = 17
    }
}
