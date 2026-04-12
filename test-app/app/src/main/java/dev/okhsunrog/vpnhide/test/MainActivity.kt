package dev.okhsunrog.vpnhide.test

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            VpnHideTestApp()
        }
    }
}

private const val TAG = "VPNHideTest"
private val VPN_PREFIXES = listOf("tun", "wg", "ppp", "tap", "ipsec", "xfrm")

data class CheckResult(
    val name: String,
    val passed: Boolean?, // null = informational
    val detail: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnHideTestApp() {
    val darkTheme = isSystemInDarkTheme()
    val colorScheme =
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        } else {
            if (darkTheme) darkColorScheme() else lightColorScheme()
        }

    MaterialTheme(colorScheme = colorScheme) {
        val context = LocalContext.current
        val cm = context.getSystemService(ConnectivityManager::class.java)
        var results by remember { mutableStateOf<List<CheckResult>>(emptyList()) }
        val summaryRunning = stringResource(R.string.summary_running)
        var summary by remember { mutableStateOf(summaryRunning) }
        val summaryFmt = stringResource(R.string.summary_format)

        LaunchedEffect(Unit) {
            val r = runAllChecks(cm, context)
            results = r
            val scored = r.filter { it.passed != null }
            val passed = scored.count { it.passed == true }
            summary = String.format(summaryFmt, passed, scored.size)
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.toolbar_title)) },
                    colors =
                        TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        ),
                )
            },
        ) { innerPadding ->
            Column(
                modifier =
                    Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                        .padding(horizontal = 16.dp),
            ) {
                Spacer(Modifier.height(8.dp))

                // Banner: target list warning
                Card(
                    shape = RoundedCornerShape(8.dp),
                    colors =
                        CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                        ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = stringResource(R.string.banner_target_warning),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                        modifier = Modifier.padding(12.dp),
                    )
                }

                Spacer(Modifier.height(8.dp))

                Text(
                    text = summary,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp),
                )

                Button(
                    onClick = {
                        summary = summaryRunning
                        val r = runAllChecks(cm, context)
                        results = r
                        val scored = r.filter { it.passed != null }
                        val passed = scored.count { it.passed == true }
                        summary = String.format(summaryFmt, passed, scored.size)
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.btn_run_all))
                }

                Spacer(Modifier.height(8.dp))

                Column(
                    modifier =
                        Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    for (r in results) {
                        CheckCard(r)
                    }
                    Spacer(Modifier.height(16.dp))
                }
            }
        }
    }
}

@Composable
fun CheckCard(r: CheckResult) {
    val darkTheme = isSystemInDarkTheme()
    val actualColor =
        if (darkTheme) {
            when (r.passed) {
                true -> Color(0xFF1B5E20).copy(alpha = 0.3f)
                false -> Color(0xFFB71C1C).copy(alpha = 0.3f)
                null -> MaterialTheme.colorScheme.surfaceVariant
            }
        } else {
            when (r.passed) {
                true -> Color(0xFFE8F5E9)
                false -> Color(0xFFFFEBEE)
                null -> MaterialTheme.colorScheme.surfaceVariant
            }
        }

    val badgeText =
        stringResource(
            when (r.passed) {
                true -> R.string.badge_pass
                false -> R.string.badge_fail
                null -> R.string.badge_info
            },
        )

    val badgeColor =
        when (r.passed) {
            true -> Color(0xFF2E7D32)
            false -> Color(0xFFC62828)
            null -> MaterialTheme.colorScheme.onSurfaceVariant
        }

    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = actualColor),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = r.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = badgeText,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = badgeColor,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                text = r.detail,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
            )
        }
    }
}

private fun runAllChecks(
    cm: ConnectivityManager,
    context: android.content.Context,
): List<CheckResult> {
    Log.i(TAG, "========================================")
    Log.i(TAG, "=== VPNHide Test — starting all checks ===")
    Log.i(TAG, "========================================")

    val results = mutableListOf<CheckResult>()
    val res = context.resources

    // Native checks — kmod/zygisk detection vectors
    results.add(nativeCheck(res.getString(R.string.check_ioctl_flags)) { NativeChecks.checkIoctlSiocgifflags() })
    results.add(nativeCheck(res.getString(R.string.check_ioctl_conf)) { NativeChecks.checkIoctlSiocgifconf() })
    results.add(nativeCheck(res.getString(R.string.check_getifaddrs)) { NativeChecks.checkGetifaddrs() })
    results.add(nativeCheck(res.getString(R.string.check_netlink_getlink)) { NativeChecks.checkNetlinkGetlink() })
    results.add(nativeCheck(res.getString(R.string.check_netlink_getroute)) { NativeChecks.checkNetlinkGetroute() })
    results.add(nativeCheck(res.getString(R.string.check_proc_route)) { NativeChecks.checkProcNetRoute() })
    results.add(nativeCheck(res.getString(R.string.check_proc_ipv6_route)) { NativeChecks.checkProcNetIpv6Route() })
    results.add(nativeCheck(res.getString(R.string.check_proc_if_inet6)) { NativeChecks.checkProcNetIfInet6() })

    // SELinux-blocked vectors
    results.add(nativeCheck(res.getString(R.string.check_proc_tcp)) { NativeChecks.checkProcNetTcp() })
    results.add(nativeCheck(res.getString(R.string.check_proc_tcp6)) { NativeChecks.checkProcNetTcp6() })
    results.add(nativeCheck(res.getString(R.string.check_proc_udp)) { NativeChecks.checkProcNetUdp() })
    results.add(nativeCheck(res.getString(R.string.check_proc_udp6)) { NativeChecks.checkProcNetUdp6() })
    results.add(nativeCheck(res.getString(R.string.check_proc_dev)) { NativeChecks.checkProcNetDev() })
    results.add(nativeCheck(res.getString(R.string.check_proc_fib_trie)) { NativeChecks.checkProcNetFibTrie() })
    results.add(nativeCheck(res.getString(R.string.check_sys_class_net)) { NativeChecks.checkSysClassNet() })

    // Java checks — LSPosed/Binder detection vectors
    results.add(checkHasTransportVpn(cm, res.getString(R.string.check_has_transport_vpn)))
    results.add(checkHasCapabilityNotVpn(cm, res.getString(R.string.check_has_capability_not_vpn)))
    results.add(checkTransportInfo(cm, res.getString(R.string.check_transport_info)))
    results.add(checkNetworkInterfaceEnum(res.getString(R.string.check_net_iface_enum)))
    results.add(checkAllNetworksVpn(cm, res.getString(R.string.check_all_networks_vpn)))
    results.add(checkActiveNetworkVpn(cm, res.getString(R.string.check_active_network_vpn)))
    results.add(checkLinkPropertiesIfname(cm, res.getString(R.string.check_link_properties)))
    results.add(checkProxyHost(res.getString(R.string.check_proxy_host)))
    results.add(checkProcNetRouteJava(res.getString(R.string.check_proc_route_java)))

    val scored = results.filter { it.passed != null }
    val passed = scored.count { it.passed == true }
    Log.i(TAG, "========================================")
    Log.i(TAG, "=== SUMMARY: $passed/${scored.size} passed ===")
    Log.i(TAG, "========================================")

    return results
}

private fun nativeCheck(
    name: String,
    block: () -> String,
): CheckResult =
    try {
        val raw = block()
        val passed = raw.startsWith("PASS")
        Log.i(TAG, "[$name] ${if (passed) "PASS" else "FAIL"}: $raw")
        CheckResult(name, passed, raw)
    } catch (e: Exception) {
        val detail = "FAIL: exception: ${e.message}"
        Log.e(TAG, "[$name] $detail", e)
        CheckResult(name, false, detail)
    }

private fun checkHasTransportVpn(
    cm: ConnectivityManager,
    name: String,
): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    val net = cm.activeNetwork
    if (net == null) return CheckResult(name, true, "PASS: no active network").also { Log.i(TAG, "[$name] ${it.detail}") }
    val caps =
        cm.getNetworkCapabilities(net)
            ?: return CheckResult(name, true, "PASS: no capabilities").also { Log.i(TAG, "[$name] ${it.detail}") }
    val hasVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    val hasWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    val hasCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    val detail =
        if (!hasVpn) {
            "PASS: hasTransport(VPN)=false, WIFI=$hasWifi, CELLULAR=$hasCellular"
        } else {
            "FAIL: hasTransport(VPN)=true, WIFI=$hasWifi, CELLULAR=$hasCellular"
        }
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, !hasVpn, detail)
}

private fun checkHasCapabilityNotVpn(
    cm: ConnectivityManager,
    name: String,
): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    val net =
        cm.activeNetwork
            ?: return CheckResult(name, true, "PASS: no active network").also { Log.i(TAG, "[$name] ${it.detail}") }
    val caps =
        cm.getNetworkCapabilities(net)
            ?: return CheckResult(name, true, "PASS: no capabilities").also { Log.i(TAG, "[$name] ${it.detail}") }
    val notVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    val detail = if (notVpn) "PASS: NOT_VPN capability present" else "FAIL: NOT_VPN capability MISSING"
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, notVpn, detail)
}

private fun checkTransportInfo(
    cm: ConnectivityManager,
    name: String,
): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    val net =
        cm.activeNetwork
            ?: return CheckResult(name, true, "PASS: no active network").also { Log.i(TAG, "[$name] ${it.detail}") }
    val caps =
        cm.getNetworkCapabilities(net)
            ?: return CheckResult(name, true, "PASS: no capabilities").also { Log.i(TAG, "[$name] ${it.detail}") }
    val info = caps.transportInfo
    val className = info?.javaClass?.name ?: "null"
    val isVpn = className.contains("VpnTransportInfo")
    val detail = if (!isVpn) "PASS: transportInfo=$className" else "FAIL: VpnTransportInfo: $info"
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, !isVpn, detail)
}

private fun checkNetworkInterfaceEnum(name: String): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    return try {
        val ifaces =
            NetworkInterface.getNetworkInterfaces()
                ?: return CheckResult(name, true, "PASS: returned null").also { Log.i(TAG, "[$name] ${it.detail}") }
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
        Log.i(TAG, "[$name] $detail")
        CheckResult(name, vpnNames.isEmpty(), detail)
    } catch (e: Exception) {
        val detail = "FAIL: ${e.message}"
        Log.e(TAG, "[$name] $detail", e)
        CheckResult(name, false, detail)
    }
}

@Suppress("DEPRECATION")
private fun checkAllNetworksVpn(
    cm: ConnectivityManager,
    name: String,
): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    val networks = cm.allNetworks
    if (networks.isEmpty()) {
        return CheckResult(name, true, "PASS: no networks").also { Log.i(TAG, "[$name] ${it.detail}") }
    }
    val vpnNetworks = mutableListOf<String>()
    for (net in networks) {
        val caps = cm.getNetworkCapabilities(net) ?: continue
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpnNetworks.add(net.toString())
    }
    val detail =
        if (vpnNetworks.isEmpty()) {
            "PASS: ${networks.size} networks, none have TRANSPORT_VPN"
        } else {
            "FAIL: ${vpnNetworks.size} network(s) with TRANSPORT_VPN"
        }
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, vpnNetworks.isEmpty(), detail)
}

private fun checkActiveNetworkVpn(
    cm: ConnectivityManager,
    name: String,
): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    val net =
        cm.activeNetwork
            ?: return CheckResult(name, true, "PASS: no active network").also { Log.i(TAG, "[$name] ${it.detail}") }
    val caps =
        cm.getNetworkCapabilities(net)
            ?: return CheckResult(name, true, "PASS: no capabilities").also { Log.i(TAG, "[$name] ${it.detail}") }
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
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, !hasVpn, detail)
}

private fun checkLinkPropertiesIfname(
    cm: ConnectivityManager,
    name: String,
): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    val net =
        cm.activeNetwork
            ?: return CheckResult(name, true, "PASS: no active network").also { Log.i(TAG, "[$name] ${it.detail}") }
    val lp =
        cm.getLinkProperties(net)
            ?: return CheckResult(name, true, "PASS: no link properties").also { Log.i(TAG, "[$name] ${it.detail}") }
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
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, !isVpn, detail)
}

private fun checkProxyHost(name: String): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
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
    Log.i(TAG, "[$name] $detail")
    return CheckResult(name, !hasProxy, detail)
}

private fun checkProcNetRouteJava(name: String): CheckResult {
    Log.i(TAG, "=== CHECK: $name ===")
    return try {
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
                "FAIL: ${vpnLines.size} VPN lines:\n${vpnLines.joinToString("\n") { "  $it" }}"
            }
        Log.i(TAG, "[$name] $detail")
        CheckResult(name, vpnLines.isEmpty(), detail)
    } catch (e: Exception) {
        val msg = e.message ?: ""
        if (msg.contains("EACCES") || msg.contains("Permission denied")) {
            val detail = "PASS: access denied by SELinux"
            Log.i(TAG, "[$name] $detail")
            return CheckResult(name, true, detail)
        }
        val detail = "FAIL: ${e.message}"
        Log.e(TAG, "[$name] $detail", e)
        CheckResult(name, false, detail)
    }
}
