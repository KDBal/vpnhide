package dev.okhsunrog.vpnhide

/**
 * Known Russian company package prefixes that don't start with "ru.".
 * Sorted alphabetically for readability. Each entry is matched via startsWith().
 */
private val KNOWN_RUSSIAN_PREFIXES =
    listOf(
        "com.alfabank",
        "com.avito",
        "com.drweb",
        "com.idamob.tinkoff",
        "com.kaspersky",
        "com.kontur",
        "com.mtsbank",
        "com.punicapp.whoosh",
        "com.raiffeisen",
        "com.rosbank",
        "com.sberbank",
        "com.tcsbank",
        "com.tinkoff",
        "com.vk.",
        "com.vkontakte",
        "com.wildberries",
        "com.yandex",
        "io.ozon",
        "me.sovcombank",
    )

/**
 * Detect Russian apps by package name.
 *
 * Checks:
 * 1. Package starts with "ru." — strong signal (ru.nspk.mirpay, ru.gosuslugi, etc.)
 * 2. Package matches a known Russian company prefix
 *
 * Does NOT use Cyrillic label detection — too many false positives from
 * localized international apps (Google, Samsung, etc.).
 */
fun isRussianApp(
    packageName: String,
    @Suppress("UNUSED_PARAMETER") label: String,
): Boolean {
    if (packageName.startsWith("ru.")) return true
    if (KNOWN_RUSSIAN_PREFIXES.any { packageName.startsWith(it) }) return true
    return false
}
