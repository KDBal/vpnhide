package dev.okhsunrog.vpnhide

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

private const val TAG = "VPNHideTest"
private val VPN_PREFIXES = listOf("tun", "wg", "ppp", "tap", "ipsec", "xfrm")

data class CheckResult(
    val name: String,
    val passed: Boolean?,
    val detail: String,
)

private data class CheckResults(
    val native: List<CheckResult>,
    val java: List<CheckResult>,
) {
    val all get() = native + java
}

/** Check if VPN tunnel is active via root (bypasses our own filtering). */
private suspend fun isVpnActive(): Boolean =
    withContext(Dispatchers.IO) {
        val (exitCode, output) = suExec("ls /sys/class/net/ 2>/dev/null")
        if (exitCode != 0) return@withContext false
        val vpnIfaces =
            output
                .lines()
                .map { it.trim() }
                .filter { name ->
                    name.isNotEmpty() && VPN_PREFIXES.any { name.startsWith(it) }
                }
        if (vpnIfaces.isEmpty()) return@withContext false
        vpnIfaces.any { iface ->
            val (_, state) =
                suExec("cat /sys/class/net/$iface/operstate 2>/dev/null")
            state.trim() == "unknown" || state.trim() == "up"
        }
    }

/** Check if our own package is in a target list. */
private suspend fun isSelfInTargetList(packageName: String): Boolean =
    withContext(Dispatchers.IO) {
        val (exitCode, output) =
            suExec(
                "cat $KMOD_TARGETS 2>/dev/null || cat $ZYGISK_TARGETS 2>/dev/null || true",
            )
        if (exitCode != 0) return@withContext false
        output.lines().any { it.trim() == packageName }
    }

/** Add our own package to all target lists + resolve UID. */
private suspend fun addSelfToTargetList(packageName: String): Boolean =
    withContext(Dispatchers.IO) {
        val (_, existing) =
            suExec(
                "cat $KMOD_TARGETS 2>/dev/null || cat $ZYGISK_TARGETS 2>/dev/null || true",
            )
        val packages =
            existing
                .lines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .toMutableSet()
        packages.add(packageName)

        val body =
            "# Managed by VPN Hide app\n" +
                packages.sorted().joinToString("\n") + "\n"
        val b64 =
            android.util.Base64.encodeToString(
                body.toByteArray(),
                android.util.Base64.NO_WRAP,
            )

        val cmd =
            buildString {
                append("if [ -d /data/adb/vpnhide_kmod ]; then echo '$b64' | base64 -d > $KMOD_TARGETS && chmod 644 $KMOD_TARGETS; fi")
                append(
                    " ; if [ -d /data/adb/vpnhide_zygisk ]; then echo '$b64' | base64 -d > $ZYGISK_TARGETS && chmod 644 $ZYGISK_TARGETS; fi",
                )
                append(" ; cp $ZYGISK_TARGETS $ZYGISK_MODULE_TARGETS 2>/dev/null; true")
                append(" ; ALL_PKGS=\"\$(pm list packages -U 2>/dev/null)\"; UIDS=\"\"")
                for (pkg in packages.sorted()) {
                    append(
                        " ; U=\$(echo \"\$ALL_PKGS\" | grep '^package:$pkg ' | sed 's/.*uid://')",
                    )
                    append(
                        " ; if [ -n \"\$U\" ]; then if [ -z \"\$UIDS\" ]; then UIDS=\"\$U\"; else UIDS=\"\$UIDS\n\$U\"; fi; fi",
                    )
                }
                append(
                    " ; if [ -n \"\$UIDS\" ]; then echo \"\$UIDS\" > $PROC_TARGETS 2>/dev/null; echo \"\$UIDS\" > $SS_UIDS_FILE; else echo > $PROC_TARGETS 2>/dev/null; echo > $SS_UIDS_FILE; fi",
                )
                append(
                    " ; chmod 644 $SS_UIDS_FILE 2>/dev/null; chcon u:object_r:system_data_file:s0 $SS_UIDS_FILE 2>/dev/null",
                )
            }

        val (exitCode, _) = suExec(cmd)
        exitCode == 0
    }

private sealed class SelfTargetState {
    data object Checking : SelfTargetState()

    data object Ready : SelfTargetState()

    data object Adding : SelfTargetState()

    data object NeedsRestart : SelfTargetState()
}

private fun parseResultsJson(json: String): CheckResults {
    val obj = JSONObject(json)

    fun parseSection(key: String): List<CheckResult> {
        val arr = obj.optJSONArray(key) ?: return emptyList()
        return (0 until arr.length()).map { i ->
            val item = arr.getJSONObject(i)
            CheckResult(
                name = item.getString("name"),
                passed = if (item.isNull("passed")) null else item.getBoolean("passed"),
                detail = item.getString("detail"),
            )
        }
    }
    return CheckResults(
        native = parseSection("native"),
        java = parseSection("java"),
    )
}

@Composable
fun DiagnosticsScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val packageName = context.packageName

    var vpnDetected by remember { mutableStateOf<Boolean?>(null) }
    var selfTargetState by remember { mutableStateOf<SelfTargetState>(SelfTargetState.Checking) }
    var results by remember { mutableStateOf<CheckResults?>(null) }
    var networkBlocked by remember { mutableStateOf(false) }
    val summaryRunning = stringResource(R.string.summary_running)
    var summary by remember { mutableStateOf(summaryRunning) }
    val summaryFmt = stringResource(R.string.summary_format)

    fun updateSummary(r: CheckResults) {
        val scored = r.all.filter { it.passed != null }
        val passed = scored.count { it.passed == true }
        summary = String.format(summaryFmt, passed, scored.size)
    }

    // Register broadcast receiver for results from :checks process
    DisposableEffect(Unit) {
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(
                    ctx: Context,
                    intent: Intent,
                ) {
                    val json = intent.getStringExtra(CheckRunnerService.EXTRA_RESULTS_JSON) ?: return
                    Log.i(TAG, "Received results from :checks process")
                    val r = parseResultsJson(json)
                    results = r
                    networkBlocked = r.all.any { it.detail.startsWith("NETWORK_BLOCKED:") }
                    updateSummary(r)
                }
            }
        val filter = IntentFilter(CheckRunnerService.ACTION_RESULT)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        onDispose { context.unregisterReceiver(receiver) }
    }

    fun runChecks() {
        summary = summaryRunning
        results = null
        context.startService(
            Intent(context, CheckRunnerService::class.java).apply {
                action = CheckRunnerService.ACTION_RUN
            },
        )
    }

    // On first load: check VPN status, auto-add self, then run checks
    LaunchedEffect(Unit) {
        vpnDetected = isVpnActive()

        if (isSelfInTargetList(packageName)) {
            selfTargetState = SelfTargetState.Ready
        } else {
            selfTargetState = SelfTargetState.Adding
            val ok = addSelfToTargetList(packageName)
            selfTargetState =
                if (ok) SelfTargetState.NeedsRestart else SelfTargetState.Ready
        }

        runChecks()
    }

    Column(
        modifier =
            modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
    ) {
        Spacer(Modifier.height(8.dp))

        // Status banners
        when {
            selfTargetState == SelfTargetState.Adding -> {
                StatusBanner(
                    text = stringResource(R.string.banner_adding_self),
                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                )
            }

            selfTargetState == SelfTargetState.NeedsRestart -> {
                StatusBanner(
                    text = stringResource(R.string.banner_added_self),
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                )
            }

            vpnDetected == false -> {
                StatusBanner(
                    text = stringResource(R.string.banner_no_vpn),
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                )
            }

            vpnDetected == true && selfTargetState == SelfTargetState.Ready -> {
                StatusBanner(
                    text = stringResource(R.string.banner_ready),
                    containerColor = Color(0xFF1B5E20).copy(alpha = 0.15f),
                    contentColor = MaterialTheme.colorScheme.onSurface,
                )
            }
        }

        if (networkBlocked) {
            Spacer(Modifier.height(6.dp))
            StatusBanner(
                text = stringResource(R.string.banner_network_blocked),
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
            )
        }

        Spacer(Modifier.height(12.dp))

        Text(
            text = summary,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )

        Spacer(Modifier.height(8.dp))

        Button(
            onClick = { runChecks() },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.btn_run_all))
        }

        results?.let { r ->
            Spacer(Modifier.height(16.dp))

            SectionHeader(stringResource(R.string.section_native))
            Spacer(Modifier.height(6.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                for (check in r.native) {
                    CheckCard(check)
                }
            }

            Spacer(Modifier.height(16.dp))

            SectionHeader(stringResource(R.string.section_java))
            Spacer(Modifier.height(6.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                for (check in r.java) {
                    CheckCard(check)
                }
            }
        }

        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun StatusBanner(
    text: String,
    containerColor: Color,
    contentColor: Color,
) {
    Card(
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = contentColor,
            modifier = Modifier.padding(12.dp),
        )
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary,
    )
}

@Composable
private fun CheckCard(r: CheckResult) {
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
