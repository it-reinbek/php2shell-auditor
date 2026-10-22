# PHP2Shell Audit & Remediation Tool (`php2shell-check.sh`)

Ein interaktives Bash-Audit- und Incident-Response-Werkzeug zur Erkennung, Eindämmung und Behebung der Schwachstellen **CVE-2026-109618** und **CVE-2026-109619** („PHP2Shell“).

Entwickelt unter Berücksichtigung des **BSI-IT-Sicherheitshinweises (BITS-H Nr. 2026-297981-1132, Version 1.1 vom 21.10.2026)** sowie aktueller Threat-Intelligence-Analysen (Armis, Abstract Security, Datadog, Sansec, Corelight, IT-Administrator).

---

## 🔍 Wichtigste Funktionen

* **Umfassende Versions- und Backport-Prüfung:**
  * Prüft Host-Installationen (CLI, FPM, Apache `mod_php`, FrankenPHP, LiteSpeed) und **laufende Docker-Container**.
  * Erkennt Notfall-Patches (`8.5.12`, `8.4.27`, `8.3.36`, `8.2.35`) sowie offizielle EOL-Backports (`7.4`, `8.0`, `8.1`) von Distributionen und Repositories (Debian, Ubuntu, Plesk, Remi, Sury).
* **Tagesaktuelle IOC-Erkennung (Heuristik & Forensik):**
  * Erkennt Spuren von Heap-Corruption (`zend_mm_heap`), Segfaults und Worker-Crashes.
  * Scannt Session-Dateien auf `upload_progress_`-Präfixe und binäre Steuerzeichen / Null-Bytes (PHPSESSID-Memory-Disclosure-Vektor).
  * Erkennt persistente Datei-Locks (`flock`) auf Session-Dateien und überwacht ASLR-Brute-Force-Muster in Webserver-Logs.
* **Zustandsbasierte Split-Screen-TUI (16 Punkte ohne Zähllücken):**
  * Links Checkboxen mit Live-Statusanzeige:
    * `[x]` (Grün) = Bereits aktiv / konfiguriert
    * `[ ]` (Weiß) = Inaktiv
    * `[+]` (Gelb) = Zur Aktivierung vorgemerkt
    * `[-]` (Rot) = **Zur Rückabwicklung vorgemerkt**
  * Rechts dynamische Erklärung zu Eingriffstiefe, Risiken, Auswirkungen und Rollback-Mechanismen.
* **100 % Rückabwickelbar (Undo-Funktion):**
  * Konfigurationsänderungen, BSI-Drop-ins, `memory_limit`-Overrides, Quarantäne-Dateien und `auditd`-Regeln können durch einfaches Abwählen der Checkbox sauber rückabgewickelt werden.
* **Docker-Compose-Workflow:**
  * Verhindert Backup-Blockaden durch sauberes Stoppen via `docker compose down` (gibt Sockets und SQLite-/Volume-Locks frei), automatische DB-Dumps und Rollback-Tags.
* **Revisionssicherer Druck & Export:**
  * Erstellt eine abhakbare BSI-Notfall-Checkliste und exportiert auf Tastendruck (`[r]`) den gesamten Revisionsbericht.
  * Unterstützt direkten Ausdruck über automatisch erkannte CUPS-, LPR- oder USB-Drucker.

---

## 🚀 Schnelleinstieg

### Voraussetzungen
* Linux (Debian, Ubuntu, RHEL, AlmaLinux, Rocky, CentOS)
* Root-Rechte (`sudo`)
* Bash 4.4+

### Installation & Start

```bash
# Repository klonen
git clone [https://github.com/it-reinbek/php2shell-auditor.git](https://github.com/it-reinbek/php2shell-auditor.git)
cd php2shell-auditor

# Skript ausführbar machen
chmod +x php2shell-check.sh

# Audit starten (erfordert Root-Rechte)
sudo ./php2shell-check.sh
