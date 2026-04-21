package dev.okhsunrog.vpnhide

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Process
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Common per-installed-app fields used by every Protection screen
 * (Tun targets, App hiding, Ports). The three screens merge this with
 * their own per-screen toggle state at render time.
 */
internal data class AppSummary(
    val packageName: String,
    val label: String,
    val icon: Drawable?,
    val isSystem: Boolean,
    val userIds: List<Int> = emptyList(),
)

/**
 * App-scoped cache for the installed-app list. Loaded asynchronously
 * at startup; Protection screens subscribe to `apps` and render
 * instantly on tab switch.
 *
 * [refreshCounter] increments on every refresh — screens that maintain
 * their own per-screen state (targets.txt / observer files etc.) key
 * their reload `LaunchedEffect` on it, so the TopBar refresh button
 * rehydrates *everything*, not just the package+icon cache.
 */
internal object AppListCache {
    private val _apps = MutableStateFlow<List<AppSummary>?>(null)
    val apps: StateFlow<List<AppSummary>?> = _apps.asStateFlow()

    private val _refreshCounter = MutableStateFlow(0)
    val refreshCounter: StateFlow<Int> = _refreshCounter.asStateFlow()

    private val _loading = MutableStateFlow(false)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()

    private var inflight: Job? = null

    /** Kick off an initial load if not already loaded or loading. */
    fun ensureLoaded(
        scope: CoroutineScope,
        context: Context,
    ) {
        if (_apps.value != null || inflight?.isActive == true) return
        inflight = scope.launch { reload(context.applicationContext) }
    }

    /** Force a reload and bump the refresh counter so screens re-read
     * their per-screen state (targets.txt / observer files etc.) too.
     */
    fun refresh(
        scope: CoroutineScope,
        context: Context,
    ) {
        inflight?.cancel()
        inflight = scope.launch { reload(context.applicationContext) }
    }

    private suspend fun reload(appContext: Context) {
        _loading.value = true
        try {
            val loaded =
                withContext(Dispatchers.IO) {
                    val pm = appContext.packageManager
                    val allUserPackages = loadAllUserPackageNamesViaRoot()
                    val allUserIdsByPackage = loadAllUserIdsByPackageViaRoot()
                    val allUserApkPaths = loadAllUserApkPathsViaRoot()
                    if (allUserPackages.isNotEmpty()) {
                        allUserPackages
                            .map { pkg ->
                                val info = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull()
                                val userIds = allUserIdsByPackage[pkg] ?: emptyList()
                                val archiveInfo =
                                    if (info == null) loadArchiveApplicationInfo(pm, allUserApkPaths[pkg]) else null
                                val effectiveInfo = info ?: archiveInfo

                                AppSummary(
                                    packageName = pkg,
                                    label = effectiveInfo?.loadLabel(pm)?.toString() ?: pkg,
                                    icon = effectiveInfo?.let { runCatching { pm.getApplicationIcon(it) }.getOrNull() },
                                    isSystem = effectiveInfo?.let { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 } ?: false,
                                    userIds = userIds,
                                )
                            }.sortedBy { it.label.lowercase() }
                    } else {
                        // Fallback: current-profile only (legacy behavior)
                        pm
                            .getInstalledApplications(0)
                            .map { info ->
                                AppSummary(
                                    packageName = info.packageName,
                                    label = info.loadLabel(pm).toString(),
                                    icon = runCatching { pm.getApplicationIcon(info) }.getOrNull(),
                                    isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                                    userIds = listOf(Process.myUid() / 100000),
                                )
                            }.sortedBy { it.label.lowercase() }
                    }
                }

            _apps.value = loaded
            _refreshCounter.value = _refreshCounter.value + 1
        } finally {
            _loading.value = false
        }
    }

    private fun loadAllUserIdsByPackageViaRoot(): Map<String, List<Int>> {
        val (exitCode, raw) = suExec("pm list packages -U --user all 2>/dev/null")
        if (exitCode != 0) return emptyMap()
        val out = LinkedHashMap<String, List<Int>>()
        raw
            .lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("package:") }
            .forEach { line ->
                val pkg = line.substringAfter("package:").substringBefore(" uid:").trim()
                if (pkg.isEmpty()) return@forEach
                val uidPart = line.substringAfter("uid:", "").trim()
                if (uidPart.isEmpty()) {
                    out[pkg] = emptyList()
                    return@forEach
                }

                val userIds =
                    uidPart
                        .split(',')
                        .mapNotNull { it.trim().toIntOrNull() }
                        .map { it / 100000 }
                        .distinct()
                        .sorted()
                out[pkg] = userIds
            }
        return out
    }

    private fun loadAllUserPackageNamesViaRoot(): List<String> {
        val (exitCode, raw) = suExec("pm list packages --user all 2>/dev/null")
        if (exitCode != 0) return emptyList()
        return raw
            .lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("package:") }
            .map { it.removePrefix("package:").trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .toList()
    }

    private fun loadAllUserApkPathsViaRoot(): Map<String, String> {
        val (exitCode, raw) = suExec("pm list packages -f --user all 2>/dev/null")
        if (exitCode != 0) return emptyMap()
        val out = LinkedHashMap<String, String>()
        raw
            .lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("package:") }
            .forEach { line ->
                val body = line.removePrefix("package:")
                val eq = body.lastIndexOf('=')
                if (eq <= 0 || eq >= body.lastIndex) return@forEach
                val apkPath = body.substring(0, eq).trim()
                val pkg = body.substring(eq + 1).trim()
                if (apkPath.isNotEmpty() && pkg.isNotEmpty() && out[pkg] == null) {
                    out[pkg] = apkPath
                }
            }
        return out
    }

    @Suppress("DEPRECATION")
    private fun loadArchiveApplicationInfo(
        pm: PackageManager,
        apkPath: String?,
    ): ApplicationInfo? {
        if (apkPath.isNullOrBlank()) return null
        val pkgInfo = runCatching { pm.getPackageArchiveInfo(apkPath, 0) }.getOrNull() ?: return null
        val appinfo = pkgInfo.applicationInfo ?: return null
        appinfo.sourceDir = apkPath
        appinfo.publicSourceDir = apkPath
        return appinfo
    }
}
