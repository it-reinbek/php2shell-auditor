# PHP2Shell Auditor & Remediation Tool (`php2shell-check.sh`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![BSI Criticality: Orange](https://img.shields.io/badge/BSI%20Criticality-3%20of%204%20(Orange)-orange.svg)](https://www.bsi.bund.de)
[![CVSS: 9.2](https://img.shields.io/badge/CVSS-9.2%20(Critical)-red.svg)](https://nvd.nist.gov)
[![Version: 1.7.0](https://img.shields.io/badge/Release-v1.7.0-green.svg)](https://github.com/it-reinbek/php2shell-auditor/releases)

Language / Sprache: **[🇬🇧 English](#-english-version)** | **[🇩🇪 Deutsch](#-deutsche-version)**

---

## 🇬🇧 English Version

Interactive open-source Bash audit and emergency remediation tool designed to detect and mitigate the critical PHP vulnerabilities:
- **CVE-2026-109618** (Out-of-Memory RCE / Memory Leak) & **CVE-2026-109619** (Use-after-free via stale global state) ("PHP2Shell")
- **CVE-2026-126714** ("phpAfterShell" / Direct session upload follow-up vector via torn-writes in `session.save_handler = files`)
- **CVE-2026-115560** & **CVE-2026-129481** (Addressed in the official November 19, 2026 PHP security releases: 8.5.13, 8.4.28, 8.3.37, 8.2.36, 8.6.0+)

Developed by [IT-Reinbek](https://it-reinbek.de/php2shell-auditor/) · Documentation & Online Check: [it-reinbek.de/php2shell-auditor](https://it-reinbek.de/php2shell-auditor/)

### 🔍 Key Features (v1.7.0)

* **Two-Tier Patch Baseline & phpAfterShell Detection:**
  * **Fully Patched (`SAFE` / Green):** >= 8.5.13, 8.4.28, 8.3.37, 8.2.36, 8.6.0+ or distro backports with changelog date >= 2026-11-19.
  * **October Patch Level (`OCT_FIX` / Warning):** Systems running 8.5.12, 8.4.27, 8.3.36, 8.2.35 or backports built between 2026-10-21 and 2026-11-18 are protected against PHP2Shell, but are flagged as `WARNING` due to vulnerability against **phpAfterShell (`CVE-2026-126714`)** and `CVE-2026-129481`.
  * Elevates to `CRITICAL` if `session.save_handler = files` and `session.upload_progress.enabled = 1` are detected simultaneously on unpatched PHP.
* **`session.save_handler` & PHP-FPM Mitigation Auditing:**
  * Audits `session.save_handler` on host and inside containers for torn-write risks under versions < .13/.28/.37/.36 and verifies `session.upload_progress.enabled = 0`.
  * Checks FPM pool configs and recommends `pm.max_requests = 1` on unpatched PHP-FPM to mitigate worker-state poisoning (`CVE-2026-129481`).
* **4-Layer Process-Tree & Subprocess Heuristics (v1.6.0/v1.6.1):**
  * Dynamically scans worker parent-child process trees (`sh`, `bash`, `curl`, interpreters) under PHP-FPM and web servers, resolving Docker/OCI container scopes and detecting double-forked orphans.
* **4-Step Full-Screen Box TUI:** Unified wizard & split-box TUI (Step 1/4 Legal Disclaimer, Step 2/4 System Audit & Findings, Step 3/4 Telegram Bot & Notifications, Step 4/4 Interactive Remediation Menu 1–18) preserving color-coded state markers (`[x]` Active, `[+]` New, `[-]` Rollback, `[ ]` Inactive).
* **ClamAV Malware & Webshell Protection (Real-Time vs. Cronjob):**
  * Analyzes available RAM and recommends **Real-Time On-Access (`clamd` + `clamonacc`)** (>= 3500 MB free) or **Nightly Scheduled Scan (`clamav-scan.timer` / cronjob at 03:30)** (>= 1800 MB free).
* **Host & Live Container Audit:** Checks CLI binaries, active PHP-FPM pools, Apache `mod_php`, and running Docker containers.
* **Distro Backport Detection:** Automatically identifies official upstream patches and backports for EOL branches (7.4, 8.0, 8.1) across Debian, Ubuntu, RHEL, Plesk, and Remi.
* **100% Reversible Mitigations (TUI):** One-key toggle for BSI/CERT-EU configuration drop-ins (`99-php2shell-mitigation.ini`) and systemd cgroup memory limits (`MemoryMax=2G`).
* **Safe Docker-Compose Workflow:** Shuts down stacks safely via `docker compose down` (releasing file/db locks), archives mounts, tags rollback images, and pulls patched versions.
* **Bilingual Support (DE/EN):** Auto-detects system locale (`LANG`/`LC_ALL`), switchable at runtime via `--lang <de|en>` or key `[l]` in the TUI menu.

### 📋 Minimum Required Versions

| PHP Branch | Fully Safe Version (Nov 19, 2026) | October Patch Level (PHP2Shell only) | Notes |
| :--- | :--- | :--- | :--- |
| **8.6** | **8.6.0+** | N/A | Fully safe |
| **8.5** | **8.5.13** | 8.5.12 | Vulnerable to phpAfterShell if < 8.5.13 |
| **8.4** | **8.4.28** | 8.4.27 | Vulnerable to phpAfterShell if < 8.4.28 |
| **8.3** | **8.3.37** | 8.3.36 | Vulnerable to phpAfterShell if < 8.3.37 |
| **8.2** | **8.2.36** | 8.2.35 | EOL: Dec 31, 2026. Vulnerable to phpAfterShell if < 8.2.36 |
| **8.1, 8.0, 7.4** | **Distro Backport (≥ 19.11.2026)** | Backport (≥ 21.10.2026) | Source backports via distributions |

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

Interaktives Open-Source-Bash-Audit- und Notfall-Remediation-Tool zur Erkennung und Absicherung gegen die kritischen Sicherheitslücken:
- **CVE-2026-109618** (Out-of-Memory RCE / Memory Leak) & **CVE-2026-109619** (Use-after-free via stale global state) („PHP2Shell“)
- **CVE-2026-126714** („phpAfterShell“ / Direkter Session-Upload-Folgevektor via Torn-Write in `session.save_handler = files`)
- **CVE-2026-115560** & **CVE-2026-129481** (Behoben in den offiziellen PHP-Sicherheits-Releases vom 19.11.2026: 8.5.13, 8.4.28, 8.3.37, 8.2.36, 8.6.0+)

Entwickelt von [IT-Reinbek](https://it-reinbek.de/php2shell-auditor/) · Dokumentation & Online-Check: [it-reinbek.de/php2shell-auditor](https://it-reinbek.de/php2shell-auditor/)

### 🔍 Wichtigste Funktionen (v1.7.0)

* **Zweistufige Patch-Baseline & phpAfterShell-Erkennung:**
  * **Vollständig gepatcht (`SAFE` / Grün):** >= 8.5.13, 8.4.28, 8.3.37, 8.2.36, 8.6.0+ bzw. Distro-Backports ab 19.11.2026.
  * **Oktober-Patch-Stand (`OCT_FIX` / Warnung):** Systeme auf 8.5.12, 8.4.27, 8.3.36, 8.2.35 bzw. Backports vom 21.10. bis 18.11.2026 sind gegen PHP2Shell geschützt, werden jedoch wegen **phpAfterShell (`CVE-2026-126714`)** und `CVE-2026-129481` mit `WARNUNG` bewertet.
  * Eskaliert zu `KRITISCH`, falls `session.save_handler = files` und `session.upload_progress.enabled = 1` zeitgleich auf ungepatchtem PHP aktiv sind.
* **`session.save_handler` & PHP-FPM-Mitigation-Prüfung:**
  * Prüft `session.save_handler` auf Host und in Containern auf Torn-Write-Risiken unter Versionen < .13/.28/.37/.36 und stellt sicher, dass `session.upload_progress.enabled = 0` aktiv ist.
  * Prüft FPM-Pools und empfiehlt `pm.max_requests = 1` auf ungepatchtem PHP-FPM als Schutz vor Worker-State-Poisoning (`CVE-2026-129481`).
* **4-schichtige Prozessbaum- & Subprozess-Heuristik (v1.6.0/v1.6.1):**
  * Erkennt verdächtige Kindprozesse (`sh`, `bash`, `curl`, Interpreter) unter PHP-FPM und Webservern, löst Docker-Container-Namen auf und identifiziert verwaiste Prozesse (Double-Fork-Orphans).
* **4-stufiges Vollbild-Box-TUI:** Durchgängiges Box-TUI im IT-Reinbek-Design (Schritt 1/4 Rechtlicher Hinweis, Schritt 2/4 Systemprüfung & Befund-Screen, Schritt 3/4 Telegram-Bot & Bausteine, Schritt 4/4 Split-Box-Maßnahmen-Menü 1–18) mit farbcodierten Statusmarkern (`[x]` Aktiv, `[+]` Neu, `[-]` Rückbau, `[ ]` Inaktiv).
* **ClamAV Malware- & Webshell-Schutz (Echtzeit vs. Cronjob):**
  * Automatische RAM-Analyse mit Empfehlung für **Echtzeit-Überwachung (`clamd` + `clamonacc`)** (ab 3500 MB frei) oder **Zeitplan-/Cronjob-Scan (`clamav-scan.timer` täglich 03:30 Uhr)** (ab 1800 MB frei).
* **Host- & Live-Docker-Inspektion:** Prüft installierte CLI-Binaries, aktive PHP-FPM-Dienste, Apache `mod_php` sowie alle laufenden Docker-Container auf verwundbare PHP-Versionen.
* **Erkennung von Distro-Backports:** Erkennt Upstream-Patches sowie Distribution-Backports (Debian LTS, Ubuntu Pro, RHEL, Plesk, Remi, Sury) für PHP 7.4, 8.0 und 8.1 anhand von Paket-Changelogs und Build-Daten.
* **100 % rückabwickelbare Workarounds (Toggle On / Off):**
  * BSI-Konfigurations-Drop-in (`99-php2shell-mitigation.ini`) mit einem Tastendruck menügeführt aktivieren und rückstandslos wieder entfernen.
  * systemd-cgroup-Speicherlimits (`MemoryMax=2G`) für PHP-FPM und Webserver einrichten.
* **Sicherer Docker-Compose-Workflow:** Beendet betroffene Stacks vor dem Backup via `docker compose down` (löst Datei-/DB-Locks), archiviert Verzeichnisse, vergibt Rollback-Tags und pullt das gepatchte Image.
* **Zweisprachig (DE/EN):** Automatische Erkennung der System-Sprache (`LANG`/`LC_ALL`), umschaltbar per `--lang <de|en>` oder Taste `[l]` in der TUI.

### 📋 Mindestversionen im Überblick

| PHP-Zweig | Vollständig sicher (19.11.2026) | Oktober-Stand (nur PHP2Shell) | Status & Anmerkung |
| :--- | :--- | :--- | :--- |
| **8.6** | **8.6.0+** | N/A | Vollständig sicher |
| **8.5** | **8.5.13** | 8.5.12 | Anfällig für phpAfterShell wenn < 8.5.13 |
| **8.4** | **8.4.28** | 8.4.27 | Anfällig für phpAfterShell wenn < 8.4.28 |
| **8.3** | **8.3.37** | 8.3.36 | Anfällig für phpAfterShell wenn < 8.3.37 |
| **8.2** | **8.2.36** | 8.2.35 | EOL: 31.12.2026. Anfällig für phpAfterShell wenn < 8.2.36 |
| **8.1, 8.0, 7.4** | **Distro-Backport (≥ 19.11.2026)** | Backport (≥ 21.10.2026) | Quellcode-Patches über Distributionen |

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
