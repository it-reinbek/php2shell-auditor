# PHP2Shell Auditor & Remediation Tool (`php2shell-check.sh`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![BSI Criticality: Orange](https://img.shields.io/badge/BSI%20Criticality-3%20of%204%20(Orange)-orange.svg)](https://www.bsi.bund.de)
[![CVSS: 9.2](https://img.shields.io/badge/CVSS-9.2%20(Critical)-red.svg)](https://nvd.nist.gov)
[![Version: 1.2.0](https://img.shields.io/badge/Release-v1.2.0-green.svg)](https://github.com/it-reinbek/php2shell-auditor/releases)

Interaktives Open-Source Bash-Audit- und Notfall-Remediation-Tool zur Erkennung und Absicherung gegen die kritischen Sicherheitslücken **CVE-2026-109618** (Out-of-Memory RCE / Memory Leak) und **CVE-2026-109619** (Use-after-free via stale global state) in PHP-Umgebungen („PHP2Shell“).

Entwickelt von [IT-Reinbek](https://it-reinbek.de/php2shell-auditor/) · Dokumentation & Online-Check: [it-reinbek.de/php2shell-auditor](https://it-reinbek.de/php2shell-auditor/)

---

## 🔍 Wichtigste Funktionen (v1.2.0)

* **Host & Live-Docker Inspektion:** Prüft installierte CLI-Binaries, aktive PHP-FPM-Dienste, Apache `mod_php` sowie alle laufenden Docker-Container auf verwundbare PHP-Versionen.
* **Erkennung von Distro-Backports:** Erkennt offizielle Upstream-Patches sowie Distribution-Backports (Debian LTS, Ubuntu Pro, RHEL, Plesk, Remi, Sury) für PHP 7.4, 8.0 und 8.1 anhand von Paket-Changelogs.
* **Erweiterte Runtime-Inspektion (Neu in v1.2.0):**
  * Prüft, ob `session.upload_progress.enabled` aktiv ist (Angriffsvektor für CVE-2026-109619).
  * Erkennt temporäre Notfall-Workarounds (`memory_limit = -1`) und erinnert Administratoren an das Zurücksetzen nach dem Patch.
  * Prüft `fatal_error_backtraces` unter PHP 8.5.
* **100 % Rückabwickelbare Workarounds (Toggle On / Off):**
  * BSI/CERT-EU-Konfigurations-Drop-in (`99-php2shell-mitigation.ini`) mit einem Tastendruck menügeführt aktivieren und rückstandslos wieder entfernen.
  * systemd cgroup-Speicherlimits (`MemoryMax=2G`) für PHP-FPM und Webserver-Dienste einrichten.
* **Sicherer Docker-Compose Workflow:** Beendet betroffene Stacks vor dem Backup via `docker compose down`, legt ein Archiv an, vergibt Rollback-Tags (`pre-php2shell-rollback`) und pullt das gepatchte Image.
* **Forensische Heuristik:** Sucht nach ungewöhnlich großen Session-Dateien (> 512 KB, Heap-Spraying) und auffälligen OOM-/Segfault-Crashes in den System-Logs (ASLR-Brute-Force Indikatoren).
* **Revisionssicherer Ausdruck:** Erstellt abhakbare Compliance-Prüfberichte und unterstützt den Direktdruck via CUPS/`lp`.

---

## 📋 Mindestversionen im Überblick

| PHP-Zweig | Mindestens erforderlich | Status & Anmerkung |
| :--- | :--- | :--- |
| **8.5** | **8.5.12** | Offizielles Notfall-Update vom 21.10.2026 |
| **8.4** | **8.4.27** | Offizielles Notfall-Update vom 21.10.2026 |
| **8.3** | **8.3.36** | Offizielles Notfall-Update vom 21.10.2026 |
| **8.2** | **8.2.35** | Offizielles Notfall-Update (End-of-Life: 31.12.2026) |
| **8.1, 8.0, 7.4** | **Distro-Backport** | Quellcode-Patches über Distributionen (Revisionsdatum $\ge$ 21.10.2026) |

> **Wichtiger Hinweis zu Docker:** Ein `apt upgrade` auf dem Host aktualisiert **keine** Container! Container-Images müssen separat neu gepullt oder neu gebaut werden.

---

## 🚀 Schnellstart

Führen Sie die folgenden Befehle auf Ihrem Linux-Server als `root` (mit `sudo`) aus:

```bash
git clone [https://github.com/it-reinbek/php2shell-auditor.git](https://github.com/it-reinbek/php2shell-auditor.git)
cd php2shell-auditor
chmod +x php2shell-check.sh
sudo ./php2shell-check.sh
