package dev.okhsunrog.vpnhide

import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.IBinder
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface

/**
 * Runs all diagnostics checks in a separate process (`:checks`).
 * This process is clean — no Vector/LSPosed runtime injected — so
 * native checks (ioctl, socket) behave exactly like a normal app.
 *
 * Results are broadcast back to the main process as a JSON string.
 */
class CheckRunnerService : Service() {
    companion object {
        const val ACTION_RUN = "dev.okhsunrog.vpnhide.RUN_CHECKS"
        const val ACTION_RESULT = "dev.okhsunrog.vpnhide.CHECK_RESULTS"
        const val EXTRA_RESULTS_JSON = "results_json"
        private const val TAG = "VPNHideTest"
        private val VPN_PREFIXES = listOf("tun", "wg", "ppp", "tap", "ipsec", "xfrm")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        if (intent?.action == ACTION_RUN) {
            val cm = getSystemService(ConnectivityManager::class.java)
            val results = runAllChecks(cm)
            val json = resultsToJson(results)

            sendBroadcast(
                Intent(ACTION_RESULT).apply {
                    setPackage(packageName)
                    putExtra(EXTRA_RESULTS_JSON, json)
                },
            )
        }
        stopSelf(startId)
        return START_NOT_STICKY
    }

    private data class Result(
        val name: String,
        val passed: Boolean?,
        val detail: String,
    )

    private fun resultsToJson(results: List<Pair<String, List<Result>>>): String {
        val sb = StringBuilder()
        sb.append("{")
        results.forEachIndexed { si, (section, checks) ->
            if (si > 0) sb.append(",")
            sb.append("\"$section\":[")
            checks.forEachIndexed { ci, r ->
                if (ci > 0) sb.append(",")
                val passedStr =
                    when (r.passed) {
                        true -> "true"
                        false -> "false"
                        null -> "null"
                    }
                sb.append("{\"name\":\"${jsonEscape(r.name)}\",\"passed\":$passedStr,\"detail\":\"${jsonEscape(r.detail)}\"}")
            }
            sb.append("]")
        }
        sb.append("}")
        return sb.toString()
    }

    private fun jsonEscape(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

    private fun runAllChecks(cm: ConnectivityManager): List<Pair<String, List<Result>>> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "=== VPNHide — starting all checks (separate process) ===")
        Log.i(TAG, "========================================")

        val res = resources

        val native =
            listOf(
                nativeCheck(res.getString(R.string.check_ioctl_flags)) { NativeChecks.checkIoctlSiocgifflags() },
                nativeCheck(res.getString(R.string.check_ioctl_mtu)) { NativeChecks.checkIoctlSiocgifmtu() },
                nativeCheck(res.getString(R.string.check_ioctl_conf)) { NativeChecks.checkIoctlSiocgifconf() },
                nativeCheck(res.getString(R.string.check_getifaddrs)) { NativeChecks.checkGetifaddrs() },
                nativeCheck(res.getString(R.string.check_netlink_getlink)) { NativeChecks.checkNetlinkGetlink() },
                nativeCheck(res.getString(R.string.check_netlink_getroute)) { NativeChecks.checkNetlinkGetroute() },
                nativeCheck(res.getString(R.string.check_proc_route)) { NativeChecks.checkProcNetRoute() },
                nativeCheck(res.getString(R.string.check_proc_ipv6_route)) { NativeChecks.checkProcNetIpv6Route() },
                nativeCheck(res.getString(R.string.check_proc_if_inet6)) { NativeChecks.checkProcNetIfInet6() },
                nativeCheck(res.getString(R.string.check_proc_tcp)) { NativeChecks.checkProcNetTcp() },
                nativeCheck(res.getString(R.string.check_proc_tcp6)) { NativeChecks.checkProcNetTcp6() },
                nativeCheck(res.getString(R.string.check_proc_udp)) { NativeChecks.checkProcNetUdp() },
                nativeCheck(res.getString(R.string.check_proc_udp6)) { NativeChecks.checkProcNetUdp6() },
                nativeCheck(res.getString(R.string.check_proc_dev)) { NativeChecks.checkProcNetDev() },
                nativeCheck(res.getString(R.string.check_proc_fib_trie)) { NativeChecks.checkProcNetFibTrie() },
                nativeCheck(res.getString(R.string.check_sys_class_net)) { NativeChecks.checkSysClassNet() },
                checkNetworkInterfaceEnum(res.getString(R.string.check_net_iface_enum)),
                checkProcNetRouteJava(res.getString(R.string.check_proc_route_java)),
            )

        val java =
            listOf(
                checkHasTransportVpn(cm, res.getString(R.string.check_has_transport_vpn)),
                checkHasCapabilityNotVpn(cm, res.getString(R.string.check_has_capability_not_vpn)),
                checkTransportInfo(cm, res.getString(R.string.check_transport_info)),
                checkAllNetworksVpn(cm, res.getString(R.string.check_all_networks_vpn)),
                checkActiveNetworkVpn(cm, res.getString(R.string.check_active_network_vpn)),
                checkLinkPropertiesIfname(cm, res.getString(R.string.check_link_properties)),
                checkLinkPropertiesRoutes(cm, res.getString(R.string.check_link_properties_routes)),
                checkProxyHost(res.getString(R.string.check_proxy_host)),
            )

        val all = native + java
        val scored = all.filter { it.passed != null }
        val passed = scored.count { it.passed == true }
        Log.i(TAG, "=== SUMMARY: $passed/${scored.size} passed ===")

        return listOf("native" to native, "java" to java)
    }

    private fun nativeCheck(
        name: String,
        block: () -> String,
    ): Result =
        try {
            val raw = block()
            val passed =
                when {
                    raw.startsWith("PASS") -> true

                    raw.startsWith("NETWORK_BLOCKED:") -> null

                    // not a real failure
                    else -> false
                }
            Log.i(
                TAG,
                "[$name] ${if (passed == true) {
                    "PASS"
                } else if (passed == null) {
                    "BLOCKED"
                } else {
                    "FAIL"
                }}: $raw",
            )
            Result(name, passed, raw)
        } catch (e: Exception) {
            val detail = "FAIL: exception: ${e.message}"
            Log.e(TAG, "[$name] $detail", e)
            Result(name, false, detail)
        }

    private fun checkHasTransportVpn(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val net = cm.activeNetwork ?: return Result(name, true, "PASS: no active network")
        val caps = cm.getNetworkCapabilities(net) ?: return Result(name, true, "PASS: no capabilities")
        val hasVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        val hasWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        val hasCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        val detail =
            if (!hasVpn) {
                "PASS: hasTransport(VPN)=false, WIFI=$hasWifi, CELLULAR=$hasCellular"
            } else {
                "FAIL: hasTransport(VPN)=true, WIFI=$hasWifi, CELLULAR=$hasCellular"
            }
        return Result(name, !hasVpn, detail)
    }

    private fun checkHasCapabilityNotVpn(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val net = cm.activeNetwork ?: return Result(name, true, "PASS: no active network")
        val caps = cm.getNetworkCapabilities(net) ?: return Result(name, true, "PASS: no capabilities")
        val notVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        val detail = if (notVpn) "PASS: NOT_VPN capability present" else "FAIL: NOT_VPN capability MISSING"
        return Result(name, notVpn, detail)
    }

    private fun checkTransportInfo(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val net = cm.activeNetwork ?: return Result(name, true, "PASS: no active network")
        val caps = cm.getNetworkCapabilities(net) ?: return Result(name, true, "PASS: no capabilities")
        val info = caps.transportInfo
        val className = info?.javaClass?.name ?: "null"
        val isVpn = className.contains("VpnTransportInfo")
        val detail = if (!isVpn) "PASS: transportInfo=$className" else "FAIL: VpnTransportInfo: $info"
        return Result(name, !isVpn, detail)
    }

    private fun checkNetworkInterfaceEnum(name: String): Result =
        try {
            val ifaces =
                NetworkInterface.getNetworkInterfaces()
                    ?: return Result(name, true, "PASS: returned null")
            val allNames = mutableListOf<String>()
            val vpnNames = mutableListOf<String>()
            for (iface in ifaces) {
                allNames.add(iface.name)
                if (VPN_PREFIXES.any { iface.name.startsWith(it) }) vpnNames.add(iface.name)
            }
            val detail =
                if (vpnNames.isEmpty()) {
                    "PASS: ${allNames.size} ifaces [${allNames.joinToString()}], no VPN"
                } else {
                    "FAIL: VPN [${vpnNames.joinToString()}] in [${allNames.joinToString()}]"
                }
            Result(name, vpnNames.isEmpty(), detail)
        } catch (e: Exception) {
            Result(name, false, "FAIL: ${e.message}")
        }

    @Suppress("DEPRECATION")
    private fun checkAllNetworksVpn(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val networks = cm.allNetworks
        if (networks.isEmpty()) return Result(name, true, "PASS: no networks")
        val vpnNetworks =
            networks.filter { net ->
                cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        val detail =
            if (vpnNetworks.isEmpty()) {
                "PASS: ${networks.size} networks, none have TRANSPORT_VPN"
            } else {
                "FAIL: ${vpnNetworks.size} network(s) with TRANSPORT_VPN"
            }
        return Result(name, vpnNetworks.isEmpty(), detail)
    }

    private fun checkActiveNetworkVpn(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val net = cm.activeNetwork ?: return Result(name, true, "PASS: no active network")
        val caps = cm.getNetworkCapabilities(net) ?: return Result(name, true, "PASS: no capabilities")
        val transports = mutableListOf<String>()
        mapOf(
            NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR",
            NetworkCapabilities.TRANSPORT_WIFI to "WIFI",
            NetworkCapabilities.TRANSPORT_BLUETOOTH to "BLUETOOTH",
            NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET",
            NetworkCapabilities.TRANSPORT_VPN to "VPN",
            NetworkCapabilities.TRANSPORT_WIFI_AWARE to "WIFI_AWARE",
        ).forEach { (id, label) -> if (caps.hasTransport(id)) transports.add(label) }
        val hasVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        val detail =
            if (!hasVpn) {
                "PASS: transports=[${transports.joinToString()}], no VPN"
            } else {
                "FAIL: transports include VPN: [${transports.joinToString()}]"
            }
        return Result(name, !hasVpn, detail)
    }

    private fun checkLinkPropertiesIfname(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val net = cm.activeNetwork ?: return Result(name, true, "PASS: no active network")
        val lp = cm.getLinkProperties(net) ?: return Result(name, true, "PASS: no link properties")
        val ifname = lp.interfaceName ?: "(null)"
        val routes = lp.routes.map { "${it.destination} via ${it.gateway} dev ${it.`interface`}" }
        val dns = lp.dnsServers.map { it.hostAddress ?: "?" }
        val isVpn = VPN_PREFIXES.any { ifname.startsWith(it) }
        val detail =
            if (!isVpn) {
                "PASS: ifname=$ifname, ${routes.size} routes, dns=[${dns.joinToString()}]"
            } else {
                "FAIL: ifname=$ifname is a VPN interface"
            }
        return Result(name, !isVpn, detail)
    }

    private fun checkLinkPropertiesRoutes(
        cm: ConnectivityManager,
        name: String,
    ): Result {
        val net = cm.activeNetwork ?: return Result(name, true, "PASS: no active network")
        val lp = cm.getLinkProperties(net) ?: return Result(name, true, "PASS: no link properties")
        val routes = lp.routes
        val vpnRoutes =
            routes.filter { route ->
                val iface = route.`interface` ?: return@filter false
                VPN_PREFIXES.any { iface.startsWith(it) }
            }
        val detail =
            if (vpnRoutes.isEmpty()) {
                "PASS: ${routes.size} routes, none via VPN interfaces"
            } else {
                "FAIL: ${vpnRoutes.size} route(s) via VPN"
            }
        return Result(name, vpnRoutes.isEmpty(), detail)
    }

    private fun checkProxyHost(name: String): Result {
        val httpHost = System.getProperty("http.proxyHost")
        val socksHost = System.getProperty("socksProxyHost")
        val hasProxy = !httpHost.isNullOrEmpty() || !socksHost.isNullOrEmpty()
        val detail =
            if (!hasProxy) {
                "PASS: no proxy (http=$httpHost, socks=$socksHost)"
            } else {
                val httpPort = System.getProperty("http.proxyPort")
                val socksPort = System.getProperty("socksProxyPort")
                "FAIL: proxy found — http=$httpHost:$httpPort, socks=$socksHost:$socksPort"
            }
        return Result(name, !hasProxy, detail)
    }

    private fun checkProcNetRouteJava(name: String): Result =
        try {
            val allLines = mutableListOf<String>()
            val vpnLines = mutableListOf<String>()
            BufferedReader(InputStreamReader(java.io.FileInputStream("/proc/net/route"))).use { br ->
                var line: String?
                while (br.readLine().also { line = it } != null) {
                    allLines.add(line!!)
                    if (VPN_PREFIXES.any { line!!.startsWith(it) }) vpnLines.add(line!!.take(60))
                }
            }
            val detail =
                if (vpnLines.isEmpty()) {
                    "PASS: ${allLines.size} lines, no VPN entries"
                } else {
                    "FAIL: ${vpnLines.size} VPN lines"
                }
            Result(name, vpnLines.isEmpty(), detail)
        } catch (e: Exception) {
            val msg = e.message ?: ""
            if (msg.contains("EACCES") || msg.contains("Permission denied")) {
                Result(name, true, "PASS: access denied by SELinux")
            } else {
                Result(name, false, "FAIL: ${e.message}")
            }
        }
}
