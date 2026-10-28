# PHP2Shell Auditor & Remediation Tool (`php2shell-check.sh`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![BSI Criticality: Orange](https://img.shields.io/badge/BSI%20Criticality-3%20of%204%20(Orange)-orange.svg)](https://www.bsi.bund.de)
[![CVSS: 9.2](https://img.shields.io/badge/CVSS-9.2%20(Critical)-red.svg)](https://nvd.nist.gov)
[![Version: 1.3.1](https://img.shields.io/badge/Release-v1.3.1-green.svg)](https://github.com/it-reinbek/php2shell-auditor/releases)

Language / Sprache: **[🇬🇧 English](#-english-version)** | **[🇩🇪 Deutsch](#-deutsche-version)**

---

## 🇬🇧 English Version

Interactive open-source Bash audit and emergency remediation tool designed to detect and mitigate the critical PHP vulnerabilities **CVE-2026-109618** (Out-of-Memory RCE / Memory Leak) and **CVE-2026-109619** (Use-after-free via stale global state) ("PHP2Shell").

Developed by [IT-Reinbek](https://it-reinbek.de/php2shell-auditor/) · Documentation & Online Check: [it-reinbek.de/php2shell-auditor](https://it-reinbek.de/php2shell-auditor/)

### 🔍 Key Features (v1.3.1)

* **Host & Live Container Audit:** Checks CLI binaries, active PHP-FPM pools, Apache `mod_php`, and running Docker containers.
* **Distro Backport Detection:** Automatically identifies official upstream patches (>= 8.5.12, 8.4.27, 8.3.36, 8.2.35) and backports for EOL branches (7.4, 8.0, 8.1) across Debian, Ubuntu, RHEL, Plesk, and Remi.
* **Extended Runtime Inspections (CERT-EU / BSI / CISA):**
  * Audits `session.upload_progress.enabled` (active attack surface for CVE-2026-109619).
  * Detects emergency workarounds (`memory_limit = -1`) and prompts administrators to restore finite limits after patching.
  * Inspects `fatal_error_backtraces` on PHP 8.5.
  * Audits `display_errors` (prevents address leaks and ASLR bypasses) and `session.use_strict_mode` (prevents session fixation and malicious session IDs).
* **100% Reversible Mitigations (TUI):** One-key toggle for BSI/CERT-EU configuration drop-ins (`99-php2shell-mitigation.ini`) and systemd cgroup memory limits (`MemoryMax=2G`).
* **Safe Docker-Compose Workflow:** Shuts down stacks safely via `docker compose down` (releasing file/db locks), archives mounts, tags rollback images, and pulls patched versions.
* **Forensic Heuristics:** Detects heap-spraying session artifacts (> 512 KB) and crash waves (ASLR brute-forcing) in syslog and journalctl.
* **Bilingual Support (DE/EN):** Auto-detects system locale (`LANG`/`LC_ALL`), switchable at runtime via `--lang <de|en>` or key `[l]` in the TUI menu.

### 📋 Minimum Required Versions

| PHP Branch | Minimum Safe Version | Notes |
| :--- | :--- | :--- |
| **8.5** | **8.5.12** | Official emergency update (Oct 21, 2026) |
| **8.4** | **8.4.27** | Official emergency update (Oct 21, 2026) |
| **8.3** | **8.3.36** | Official emergency update (Oct 21, 2026) |
| **8.2** | **8.2.35** | Official emergency update (End-of-Life: Dec 31, 2026) |
| **8.1, 8.0, 7.4** | **Distro Backport** | Source backports via distributions (build date ≥ Oct 21, 2026) |

### 🚀 Quick Start

Run the following commands on your Linux host as root (or with `sudo`):

```bash
git clone https://github.com/it-reinbek/php2shell-auditor.git
cd php2shell-auditor
chmod +x php2shell-check.sh
sudo ./php2shell-check.sh
```

### ⚙️ Command-Line Options (CLI)

```text
Usage: sudo ./php2shell-check.sh [OPTIONS]
```

| Option | Description |
| :--- | :--- |
| `--lang <de\|en>` | Forces interface and report language (default: auto-detected). |
| `--no-menu` | Executes a full scan, outputs the results table, saves the report, and exits without interactive menu. |
| `--versions-only` | Minimal scan only checking PHP versions across host and containers. |
| `--accept-disclaimer` | Acknowledges the legal disclaimer non-interactively (required for cron/CI automation). |
| `-h`, `--help` | Displays the help menu. |

### 🤖 Automation Examples

```bash
# Automated daily security audit via cron (English forced)
0 3 * * * root /root/php2shell-auditor/php2shell-check.sh --lang en --no-menu --accept-disclaimer > /var/log/php2shell-cron.log 2>&1

# Rapid container & version check in CI pipelines
sudo ./php2shell-check.sh --versions-only --accept-disclaimer
```

---

## 🇩🇪 Deutsche Version

Interaktives Open-Source-Bash-Audit- und Notfall-Remediation-Tool zur Erkennung und Absicherung gegen die kritischen Sicherheitslücken **CVE-2026-109618** (Out-of-Memory RCE / Memory Leak) und **CVE-2026-109619** (Use-after-free via stale global state) in PHP-Umgebungen („PHP2Shell“).

Entwickelt von [IT-Reinbek](https://it-reinbek.de/php2shell-auditor/) · Dokumentation & Online-Check: [it-reinbek.de/php2shell-auditor](https://it-reinbek.de/php2shell-auditor/)

### 🔍 Wichtigste Funktionen (v1.3.1)

* **Host- & Live-Docker-Inspektion:** Prüft installierte CLI-Binaries, aktive PHP-FPM-Dienste, Apache `mod_php` sowie alle laufenden Docker-Container auf verwundbare PHP-Versionen.
* **Erkennung von Distro-Backports:** Erkennt offizielle Upstream-Patches sowie Distribution-Backports (Debian LTS, Ubuntu Pro, RHEL, Plesk, Remi, Sury) für PHP 7.4, 8.0 und 8.1 anhand von Paket-Changelogs und Build-Daten.
* **Erweiterte Runtime-Inspektion (BSI / CERT-EU / CISA):**
  * Prüft, ob `session.upload_progress.enabled` aktiv ist (Angriffsfläche für CVE-2026-109619).
  * Erkennt Notfall-Workarounds (`memory_limit = -1`) und erinnert Administratoren an das Zurücksetzen nach dem Patch.
  * Prüft `fatal_error_backtraces` unter PHP 8.5.
  * Warnt bei aktivem `display_errors` (Adress-Leaks / ASLR-Bypass) sowie inaktivem `session.use_strict_mode` (Session-Fixation / bösartige Session-IDs).
* **100 % rückabwickelbare Workarounds (Toggle On / Off):**
  * BSI-Konfigurations-Drop-in (`99-php2shell-mitigation.ini`) mit einem Tastendruck menügeführt aktivieren und rückstandslos wieder entfernen.
  * systemd-cgroup-Speicherlimits (`MemoryMax=2G`) für PHP-FPM und Webserver einrichten.
* **Sicherer Docker-Compose-Workflow:** Beendet betroffene Stacks vor dem Backup via `docker compose down` (löst Datei-/DB-Locks), archiviert Verzeichnisse, vergibt Rollback-Tags und pullt das gepatchte Image.
* **Forensische Heuristik:** Sucht nach ungewöhnlich großen Session-Dateien (> 512 KB, Heap-Spraying) und auffälligen OOM-/Segfault-Crashes in den System-Logs (ASLR-Brute-Force-Indikatoren).
* **Zweisprachig (DE/EN):** Automatische Erkennung der System-Sprache (`LANG`/`LC_ALL`), umschaltbar per `--lang <de|en>` oder Taste `[l]` in der TUI.

### 📋 Mindestversionen im Überblick

| PHP-Zweig | Mindestens erforderlich | Status & Anmerkung |
| :--- | :--- | :--- |
| **8.5** | **8.5.12** | Offizielles Notfall-Update vom 21.10.2026 |
| **8.4** | **8.4.27** | Offizielles Notfall-Update vom 21.10.2026 |
| **8.3** | **8.3.36** | Offizielles Notfall-Update vom 21.10.2026 |
| **8.2** | **8.2.35** | Offizielles Notfall-Update (End-of-Life: 31.12.2026) |
| **8.1, 8.0, 7.4** | **Distro-Backport** | Quellcode-Patches über Distributionen (Revisionsdatum ≥ 21.10.2026) |

### 🚀 Schnellstart

Auf dem Linux-Host als root (oder mit `sudo`) ausführen:

```bash
git clone https://github.com/it-reinbek/php2shell-auditor.git
cd php2shell-auditor
chmod +x php2shell-check.sh
sudo ./php2shell-check.sh
```

### ⚙️ Befehlszeilen-Optionen (CLI)

```text
Verwendung: sudo ./php2shell-check.sh [OPTIONEN]
```

| Option | Beschreibung |
| :--- | :--- |
| `--lang <de\|en>` | Legt die Sprache für Terminal und Berichte fest (Standard: automatische Erkennung). |
| `--no-menu` | Führt den Scan durch, gibt die formatierte Tabelle aus, speichert das Protokoll und beendet sich ohne TUI-Menü. |
| `--versions-only` | Reduziert die Prüfung auf Host- und Docker-PHP-Versionen. |
| `--accept-disclaimer` | Akzeptiert den rechtlichen Haftungsausschluss ohne interaktive Abfrage (für Cron/CI). |
| `-h`, `--help` | Zeigt die Hilfe im Terminal an. |

### 🤖 Automatisierungsbeispiele

```bash
# Automatisiertes tägliches Sicherheits-Audit per Cron (Sprache: Deutsch)
0 3 * * * root /root/php2shell-auditor/php2shell-check.sh --lang de --no-menu --accept-disclaimer > /var/log/php2shell-cron.log 2>&1

# Schneller Container- & Versions-Check in CI-Pipelines
sudo ./php2shell-check.sh --versions-only --accept-disclaimer
```

---

## ⚖️ License & Disclaimer / Lizenz

This project is licensed under the [MIT License](LICENSE).

**Usage is strictly at your own risk.** Prior to executing upgrades or configuration changes on production systems, taking full system and database backups is strongly recommended.

Die Nutzung erfolgt **ausschließlich auf eigene Gefahr**. Vor Upgrades oder Konfigurationsänderungen auf Produktivsystemen werden vollständige System- und Datenbank-Backups dringend empfohlen.
