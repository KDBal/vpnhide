package dev.okhsunrog.vpnhide

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RussianAppFilterTest {
    // ── Package prefix "ru." ──

    @Test
    fun `ru dot prefix is Russian`() {
        assertTrue(isRussianApp("ru.nspk.mirpay", "Mir Pay"))
        assertTrue(isRussianApp("ru.gosuslugi.app", "Gosuslugi"))
        assertTrue(isRussianApp("ru.sberbank.sberbankid", "Sber ID"))
        assertTrue(isRussianApp("ru.mail.cloud", "Mail.ru Cloud"))
    }

    // ── Known Russian company prefixes ──

    @Test
    fun `Sberbank is Russian`() {
        assertTrue(isRussianApp("com.sberbank.sberbankid", "Sber ID"))
    }

    @Test
    fun `Tinkoff is Russian`() {
        assertTrue(isRussianApp("com.tinkoff.investing", "Tinkoff Investing"))
        assertTrue(isRussianApp("com.tcsbank.c2c", "T-Bank"))
    }

    @Test
    fun `Yandex is Russian`() {
        assertTrue(isRussianApp("com.yandex.browser", "Yandex Browser"))
        assertTrue(isRussianApp("com.yandex.maps", "Yandex Maps"))
    }

    @Test
    fun `VK is Russian`() {
        assertTrue(isRussianApp("com.vkontakte.android", "VK"))
        assertTrue(isRussianApp("com.vk.im", "VK Messenger"))
    }

    @Test
    fun `other known Russian companies`() {
        assertTrue(isRussianApp("com.kaspersky.security.cloud", "Kaspersky"))
        assertTrue(isRussianApp("com.wildberries.client", "Wildberries"))
        assertTrue(isRussianApp("io.ozon.android", "Ozon"))
        assertTrue(isRussianApp("com.avito.android", "Avito"))
        assertTrue(isRussianApp("com.alfabank.mobile.android", "Alfa-Bank"))
        assertTrue(isRussianApp("me.sovcombank.halva", "Halva"))
        assertTrue(isRussianApp("com.drweb.pro", "Dr.Web"))
        assertTrue(isRussianApp("com.punicapp.whoosh", "Whoosh"))
        assertTrue(isRussianApp("com.mtsbank.app", "MTS Bank"))
        assertTrue(isRussianApp("com.rosbank.android", "Rosbank"))
        assertTrue(isRussianApp("com.raiffeisen.rmobile", "Raiffeisen"))
        assertTrue(isRussianApp("com.kontur.extern", "Kontur"))
    }

    // ── Non-Russian apps (must NOT match) ──

    @Test
    fun `Telegram is NOT matched`() {
        assertFalse(isRussianApp("org.telegram.messenger", "Telegram"))
    }

    @Test
    fun `Google apps are not Russian`() {
        assertFalse(isRussianApp("com.google.android.apps.maps", "Google Maps"))
        assertFalse(isRussianApp("com.google.android.gm", "Gmail"))
        assertFalse(isRussianApp("com.google.android.apps.photos", "Фото"))
        assertFalse(isRussianApp("com.google.android.apps.docs", "Диск"))
    }

    @Test
    fun `localized system apps are not Russian`() {
        assertFalse(isRussianApp("android.autoinstalls.config.google.nexus", "Конфигурация"))
        assertFalse(isRussianApp("com.android.calendar", "Календарь"))
    }

    @Test
    fun `international apps are not Russian`() {
        assertFalse(isRussianApp("com.whatsapp", "WhatsApp"))
        assertFalse(isRussianApp("com.instagram.android", "Instagram"))
        assertFalse(isRussianApp("com.spotify.music", "Spotify"))
        assertFalse(isRussianApp("com.netflix.mediaclient", "Netflix"))
    }

    @Test
    fun `Samsung apps are not Russian`() {
        assertFalse(isRussianApp("com.samsung.android.calendar", "Samsung Calendar"))
    }

    // ── Edge cases ──

    @Test
    fun `empty label and non-Russian package`() {
        assertFalse(isRussianApp("com.example.app", ""))
    }

    @Test
    fun `Cyrillic-only label without Russian package does NOT match`() {
        assertFalse(isRussianApp("com.example.app", "Госуслуги"))
    }
}
