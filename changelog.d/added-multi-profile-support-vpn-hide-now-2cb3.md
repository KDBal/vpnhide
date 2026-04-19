_2026-04-20_

## English

Multi-profile support: VPN Hide now targets every instance of a selected app across user profiles (work profile, MIUI Second Space, Private Space, secondary users). Previously hooks only matched the app in your primary profile — a work-profile Ozon would still see the VPN. Package-to-UID resolution at boot + at Save time now uses 'pm list packages -U --user all' and writes every UID to targets, so all profiles are covered automatically without any UI changes. Fixes the work-profile request in issue #15.

## Русский

Поддержка мультипрофилей: VPN Hide теперь скрывает VPN во всех профилях, где установлено выбранное приложение (рабочий профиль, MIUI Second Space, Private Space, вторичные пользователи). Раньше хуки срабатывали только для копии в основном профиле — Ozon в рабочем профиле продолжал видеть VPN. Резолв имён пакетов в UID при загрузке и при сохранении теперь использует 'pm list packages -U --user all' и пишет все UID-ы в таргеты — все профили покрываются автоматически, UI не меняется. Закрывает запрос про work profile из issue #15.
