# Changelog — PySec-Auditor

## v10.3
- Supabase-backed premium key management (admin upload & user validation).
- Admin helper `src/supabase_key_service.py` to generate & upload keys.
- Premium features expanded and enforced via server-side registration.

# Changelog — PySec-Auditor

## v10.2
- Added premium key system with local key storage (`key.json`).
- Added Telegram helper to issue keys via bot (script: src/telegram_key_service.py).
- Premium unlocks extended subdomain discovery, deeper scans, and CI-friendly behaviors.

## v10.1
- TLS fallback and documentation updates.

## v10.0
- Major features: WHOIS, TLS, Nuclei/Nikto integration, PDF reports, CI mode.

## v10.4
- Admin device enforcement: only devices listed in admin_tools/admin_devices.json may upload keys to Supabase.
- Admin tool will generate local key but refuse upload if device not authorized.

## v10.5
- Admin devices list encryption using passphrase (admin_device_manager.py).
- admin_tools/admin_devices.enc and admin_devices.salt used for secure storage.
