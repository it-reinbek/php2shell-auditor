#!/usr/bin/env bash
# ==============================================================================
# PHP2Shell Auditor & Remediation Tool (php2shell-check.sh)
# CVE-2026-109618 (OOM RCE / Memory Leak) & CVE-2026-109619 (Stale State UAF)
#
# Entwickelt von: IT-Reinbek (https://it-reinbek.de/php2shell-auditor/)
# Repository:     https://github.com/it-reinbek/php2shell-auditor
# Lizenz:         MIT License
# Version:        1.2.0 (Stand: 23.10.2026)
# ==============================================================================

set -uo pipefail

VERSION="1.2.0"
ADVISORY_DATE="2026-10-21"
REPORT_DIR="/root/php2shell-audit-$(date +%Y%m%d-%H%M%S)"
STATE_DIR="/var/backups/php2shell-auditor"
LOG_FILE="${REPORT_DIR}/audit.log"
CHECKLIST_FILE="${REPORT_DIR}/compliance-checklist.txt"
MITIGATION_INI_NAME="99-php2shell-mitigation.ini"
SYSTEMD_DROPIN_NAME="99-php2shell-limits.conf"

# CLI Flags
NO_MENU=0
VERSIONS_ONLY=0
ACCEPT_DISCLAIMER=0

# Farben & Formatierung
if [[ -t 1 ]]; then
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
    C_RED="\033[1;31m"
    C_GREEN="\033[1;32m"
    C_YELLOW="\033[1;33m"
    C_BLUE="\033[1;36m"
    C_MUTED="\033[0;90m"
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MUTED=""
fi

# Globale Ergebnis-Arrays
declare -a AUDIT_ROWS=()
declare -a FINDINGS=()
declare -a CONTAINERS_VULN=()
VULN_COUNT=0
WARN_COUNT=0
SAFE_COUNT=0

# ==============================================================================
# Hilfsfunktionen & Parameter
# ==============================================================================

usage() {
    cat <<EOF
PHP2Shell Auditor v${VERSION} - IT-Reinbek (https://it-reinbek.de)
Verwendung: sudo $0 [OPTIONEN]

Optionen:
  --no-menu             Nur lesenden Scan ausführen, kein interaktives TUI-Menü
  --versions-only       Nur PHP-Versionen (Host & Docker) tabellarisch prüfen
  --accept-disclaimer   Rechtlichen Hinweis für Cronjobs/Automatisierung bestätigen
  -h, --help            Diese Hilfe anzeigen
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-menu) NO_MENU=1; shift ;;
        --versions-only) VERSIONS_ONLY=1; NO_MENU=1; shift ;;
        --accept-disclaimer) ACCEPT_DISCLAIMER=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unbekannte Option: $1"; usage; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}[FEHLER] Bitte führen Sie dieses Skript mit root-Rechten (sudo) aus.${C_RESET}"
    exit 1
fi

mkdir -p "$REPORT_DIR" "$STATE_DIR"
chmod 700 "$REPORT_DIR" "$STATE_DIR"

log() {
    local msg="$1"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$LOG_FILE"
}

show_disclaimer() {
    if [[ $ACCEPT_DISCLAIMER -eq 1 ]]; then
        return 0
    fi
    clear
    echo -e "${C_BLUE}==============================================================================${C_RESET}"
    echo -e "${C_BOLD}  PHP2Shell Auditor & Remediation Tool v${VERSION} – IT-Reinbek${C_RESET}"
    echo -e "  Prüfung auf CVE-2026-109618 & CVE-2026-109619 (BSI / CERT-EU / CISA Vorgaben)"
    echo -e "${C_BLUE}==============================================================================${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}RECHTLICHER HINWEIS & HAFTUNGSAUSSCHLUSS:${C_RESET}"
    echo "1. Dieses Open-Source-Werkzeug (MIT-Lizenz) dient der Sicherheitsanalyse eigener"
    echo "   oder ausdrücklich autorisierter Server- und Container-Systeme."
    echo "2. Der initiale Scan erfolgt zu 100 % lesend. Änderungen an Konfigurationen,"
    echo "   Diensten oder Containern erfolgen erst nach expliziter Auswahl im Menü."
    echo "3. Die Nutzung erfolgt auf eigene Gefahr. Vor produktiven Eingriffen wird ein"
    echo "   vollständiges System-Backup empfohlen."
    echo ""
    read -r -p "Stimmen Sie diesen Bedingungen zu? [j/N]: " resp
    if [[ ! "$resp" =~ ^[jJyY]$ ]]; then
        echo "Abbruch durch Benutzer."
        exit 0
    fi
}

# ==============================================================================
# Versions- & Backport-Prüfung
# ==============================================================================

# Prüft, ob eine PHP-Version gepatcht ist
# Rückgabe: "SAFE", "VULNERABLE" oder "EOL_CHECK_BACKPORT"
check_version_status() {
    local ver="$1"
    local clean_ver
    clean_ver=$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)

    if [[ -z "$clean_ver" ]]; then
        echo "UNKNOWN"
        return
    fi

    local major_minor
    major_minor=$(echo "$clean_ver" | cut -d. -f1,2)
    local patch
    patch=$(echo "$clean_ver" | cut -d. -f3)

    case "$major_minor" in
        8.5)
            [[ $patch -ge 12 ]] && echo "SAFE" || echo "VULNERABLE"
            ;;
        8.4)
            [[ $patch -ge 27 ]] && echo "SAFE" || echo "VULNERABLE"
            ;;
        8.3)
            [[ $patch -ge 36 ]] && echo "SAFE" || echo "VULNERABLE"
            ;;
        8.2)
            [[ $patch -ge 35 ]] && echo "SAFE" || echo "VULNERABLE"
            ;;
        8.1|8.0|7.4|7.*|5.*)
            echo "EOL_CHECK_BACKPORT"
            ;;
        *)
            echo "UNKNOWN"
            ;;
    esac
}

# Prüft Distributions-Changelogs (Debian/Ubuntu/RHEL/Plesk) auf Backport-Patches
check_distro_backport() {
    local pkg_hint="${1:-php}"
    if command -v dpkg-query >/dev/null 2>&1; then
        local changelogs
        changelogs=$(find /usr/share/doc -maxdepth 2 -name "changelog.Debian.gz" 2>/dev/null | grep -E "php" || true)
        if [[ -n "$changelogs" ]]; then
            if zgrep -qiE "CVE-2026-109618|CVE-2026-109619" $changelogs 2>/dev/null; then
                echo "BACKPORT_FOUND"
                return
            fi
        fi
    elif command -v rpm >/dev/null 2>&1; then
        local rpm_pkgs
        rpm_pkgs=$(rpm -qa | grep -E '^php' || true)
        if [[ -n "$rpm_pkgs" ]]; then
            if rpm -q --changelog $rpm_pkgs 2>/dev/null | grep -qiE "CVE-2026-109618|CVE-2026-109619"; then
                echo "BACKPORT_FOUND"
                return
            fi
        fi
    fi
    echo "NO_BACKPORT"
}

# ==============================================================================
# Scan-Module (Host, INI-Direktiven, Docker, Forensik)
# ==============================================================================

scan_host_php() {
    AUDIT_ROWS=()
    FINDINGS=()
    CONTAINERS_VULN=()
    VULN_COUNT=0
    WARN_COUNT=0
    SAFE_COUNT=0

    log "Starte Host-PHP-Prüfung..."

    # 1. PHP CLI Binaries finden
    local php_bins
    php_bins=$(which -a php php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 2>/dev/null | sort -u || true)

    if [[ -z "$php_bins" ]]; then
        AUDIT_ROWS+=("Host CLI|Nicht installiert|-|${C_GREEN}KEIN PHP${C_RESET}")
    else
        for bin in $php_bins; do
            [[ ! -x "$bin" ]] && continue
            local full_v
            full_v=$("$bin" -v 2>/dev/null | head -n1 | awk '{print $2}' || echo "Unbekannt")
            local status
            status=$(check_version_status "$full_v")
            local bp_state
            bp_state=$(check_distro_backport "$bin")

            if [[ "$status" == "SAFE" ]]; then
                AUDIT_ROWS+=("Host CLI ($bin)|$full_v|Offizieller Patch|${C_GREEN}SICHER${C_RESET}")
                ((SAFE_COUNT++))
            elif [[ "$bp_state" == "BACKPORT_FOUND" ]]; then
                AUDIT_ROWS+=("Host CLI ($bin)|$full_v|Distro-Backport aktiv|${C_GREEN}SICHER (Backport)${C_RESET}")
                ((SAFE_COUNT++))
            elif [[ "$status" == "EOL_CHECK_BACKPORT" ]]; then
                AUDIT_ROWS+=("Host CLI ($bin)|$full_v|EOL ohne Backport-Nachweis|${C_RED}KRITISCH (EOL)${C_RESET}")
                FINDINGS+=("Host PHP ($bin) nutzt EOL-Version $full_v ohne nachgewiesenen Backport.")
                ((VULN_COUNT++))
            else
                AUDIT_ROWS+=("Host CLI ($bin)|$full_v|Update erforderlich|${C_RED}VERWUNDBAR${C_RESET}")
                FINDINGS+=("Host PHP ($bin) Version $full_v ist verwundbar gegen PHP2Shell.")
                ((VULN_COUNT++))
            fi
        done
    fi

    # 2. PHP-FPM Prozesse prüfen
    local fpm_bins
    fpm_bins=$(find /usr/sbin /usr/local/sbin -name "php-fpm*" 2>/dev/null | sort -u || true)
    for fbin in $fpm_bins; do
        [[ ! -x "$fbin" ]] && continue
        local fv
        fv=$("$fbin" -v 2>/dev/null | head -n1 | awk '{print $2}' || echo "Unbekannt")
        local fstat
        fstat=$(check_version_status "$fv")
        local fbp
        fbp=$(check_distro_backport "$fbin")

        if [[ "$fstat" == "SAFE" || "$fbp" == "BACKPORT_FOUND" ]]; then
            AUDIT_ROWS+=("PHP-FPM ($fbin)|$fv|Gepatcht|${C_GREEN}SICHER${C_RESET}")
            ((SAFE_COUNT++))
        else
            AUDIT_ROWS+=("PHP-FPM ($fbin)|$fv|Ungepatcht|${C_RED}VERWUNDBAR${C_RESET}")
            FINDINGS+=("PHP-FPM Dienst ($fbin) läuft mit ungepatchter Version $fv.")
            ((VULN_COUNT++))
        fi
    done

    # 3. Apache mod_php prüfen
    if command -v apache2ctl >/dev/null 2>&1; then
        if apache2ctl -M 2>/dev/null | grep -qi "php"; then
            AUDIT_ROWS+=("Apache2 mod_php|Aktiv|Hohes Risiko laut BSI|${C_YELLOW}PRÜFEN${C_RESET}")
            FINDINGS+=("Apache mod_php ist aktiv. BSI stuft mod_php als besonders gefährdet ein.")
            ((WARN_COUNT++))
        fi
    elif command -v httpd >/dev/null 2>&1; then
        if httpd -M 2>/dev/null | grep -qi "php"; then
            AUDIT_ROWS+=("Apache httpd mod_php|Aktiv|Hohes Risiko laut BSI|${C_YELLOW}PRÜFEN${C_RESET}")
            FINDINGS+=("Apache mod_php ist aktiv. BSI stuft mod_php als besonders gefährdet ein.")
            ((WARN_COUNT++))
        fi
    fi
}

# Neu in v1.2.0: Prüft aktiv die Laufzeit-Konfigurationen laut BSI/CERT-EU/CISA
scan_php_runtime_mitigations() {
    [[ $VERSIONS_ONLY -eq 1 ]] && return 0
    if ! command -v php >/dev/null 2>&1; then
        return 0
    fi

    log "Prüfe aktive PHP-Konfigurationsparameter (upload_progress, memory_limit, post_max_size)..."

    local up_prog
    up_prog=$(php -r "echo ini_get('session.upload_progress.enabled');" 2>/dev/null || echo "")
    local mem_lim
    mem_lim=$(php -r "echo ini_get('memory_limit');" 2>/dev/null || echo "")
    local post_max
    post_max=$(php -r "echo ini_get('post_max_size');" 2>/dev/null || echo "")
    local backtraces
    backtraces=$(php -r "echo ini_get('fatal_error_backtraces');" 2>/dev/null || echo "")

    # 1. session.upload_progress.enabled
    if [[ "$up_prog" == "1" || "${up_prog,,}" == "on" ]]; then
        AUDIT_ROWS+=("INI: session.upload_progress|Aktiv (1)|CVE-2026-109619 Angriffsfläche|${C_YELLOW}OFFEN${C_RESET}")
        FINDINGS+=("session.upload_progress.enabled ist aktiv (1). Empfehlung: Auf 0 setzen.")
        ((WARN_COUNT++))
    else
        AUDIT_ROWS+=("INI: session.upload_progress|Deaktiviert (0)|Gehärtet gegen CVE-2026-109619|${C_GREEN}GEHÄRTET${C_RESET}")
    fi

    # 2. memory_limit = -1 Warnung (Notfall-Workaround Check)
    if [[ "$mem_lim" == "-1" ]]; then
        AUDIT_ROWS+=("INI: memory_limit|-1 (Unbegrenzt)|Notfall-Workaround aktiv!|${C_YELLOW}WARNUNG (Nach Patch zurücksetzen!)${C_RESET}")
        FINDINGS+=("HINWEIS: memory_limit steht auf -1 (temporärer OOM-Workaround). Nach dem Einspielen des Patches zwingend wieder auf endlichen Wert (z.B. 256M) begrenzen!")
        ((WARN_COUNT++))
    else
        AUDIT_ROWS+=("INI: memory_limit|${mem_lim:-Standard}|Reguläres Speicherlimit|${C_BLUE}INFO (post_max_size: ${post_max:-Standard})${C_RESET}")
    fi

    # 3. PHP 8.5 fatal_error_backtraces
    local php_maj_min
    php_maj_min=$(php -r "echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;" 2>/dev/null || echo "")
    if [[ "$php_maj_min" == "8.5" && "$backtraces" == "1" ]]; then
        AUDIT_ROWS+=("INI: fatal_error_backtraces|Aktiv (PHP 8.5)|Sollte auf 0 stehen|${C_YELLOW}OFFEN${C_RESET}")
        FINDINGS+=("Auf PHP 8.5 sollte fatal_error_backtraces = 0 gesetzt werden.")
        ((WARN_COUNT++))
    fi
}

scan_docker_containers() {
    if ! command -v docker >/dev/null 2>&1; then
        return 0
    fi

    log "Prüfe laufende Docker-Container..."
    local c_list
    c_list=$(docker ps --format '{{.Names}}' 2>/dev/null || true)

    if [[ -z "$c_list" ]]; then
        AUDIT_ROWS+=("Docker-Umgebung|Keine Container aktiv|-|${C_GREEN}OK${C_RESET}")
        return 0
    fi

    while IFS= read -r cname; do
        [[ -z "$cname" ]] && continue
        local c_php_ver
        c_php_ver=$(docker exec "$cname" php -v 2>/dev/null | head -n1 | awk '{print $2}' || true)

        if [[ -z "$c_php_ver" ]]; then
            AUDIT_ROWS+=("Docker: $cname|Kein PHP|-|${C_MUTED}NICHT BETROFFEN${C_RESET}")
            continue
        fi

        local c_stat
        c_stat=$(check_version_status "$c_php_ver")
        local c_up_prog
        c_up_prog=$(docker exec "$cname" php -r "echo ini_get('session.upload_progress.enabled');" 2>/dev/null || echo "")

        if [[ "$c_stat" == "SAFE" ]]; then
            AUDIT_ROWS+=("Docker: $cname|$c_php_ver|Image aktuell|${C_GREEN}SICHER${C_RESET}")
            ((SAFE_COUNT++))
        else
            local extra_note="Image veraltet"
            [[ "$c_up_prog" == "1" ]] && extra_note="Image veraltet + upload_progress=1"
            AUDIT_ROWS+=("Docker: $cname|$c_php_ver|$extra_note|${C_RED}VERWUNDBAR${C_RESET}")
            FINDINGS+=("Docker-Container '$cname' nutzt PHP $c_php_ver ($extra_note). Image neu pullen/bauen!")
            CONTAINERS_VULN+=("$cname")
            ((VULN_COUNT++))
        fi
    done <<< "$c_list"
}

scan_forensics() {
    [[ $VERSIONS_ONLY -eq 1 ]] && return 0
    log "Starte forensische Heuristik (Logs & Session-Pfade)..."

    # 1. Suche nach verdächtigen PHP-Session-Dateien (PHP_SESSION_UPLOAD_PROGRESS Artefakte)
    local sess_dirs=("/var/lib/php/sessions" "/var/lib/php/session" "/tmp")
    local suspicious_sessions=0
    for sdir in "${sess_dirs[@]}"; do
        if [[ -d "$sdir" ]]; then
            local count
            count=$(find "$sdir" -maxdepth 1 -name "sess_*" -size +512k 2>/dev/null | wc -l || echo 0)
            if [[ $count -gt 0 ]]; then
                ((suspicious_sessions += count))
            fi
        fi
    done

    if [[ $suspicious_sessions -gt 0 ]]; then
        AUDIT_ROWS+=("Forensik: Session-Dateien|$suspicious_sessions ungewöhnlich groß (>512KB)|Verdacht auf Heap/OOM-Spray|${C_RED}AUFFÄLLIG${C_RESET}")
        FINDINGS+=("$suspicious_sessions ungewöhnlich große Session-Dateien gefunden (mögliches OOM/UAF-Spraying).")
        ((VULN_COUNT++))
    else
        AUDIT_ROWS+=("Forensik: Session-Dateien|Unauffällig|Keine großen Spray-Sessions|${C_GREEN}UNAUFFÄLLIG${C_RESET}")
    fi

    # 2. Suche nach FPM/Apache OOM-Crashes oder Segfaults in den letzten 48 Stunden (ASLR Brute-Force Indikator)
    local segfaults=0
    if command -v journalctl >/dev/null 2>&1; then
        segfaults=$(journalctl --since "48 hours ago" 2>/dev/null | grep -ciE "php.*(segfault|oom-kill|out of memory)" || true)
    elif [[ -f /var/log/syslog ]]; then
        segfaults=$(grep -ciE "php.*(segfault|oom-kill|out of memory)" /var/log/syslog 2>/dev/null || true)
    fi

    if [[ $segfaults -gt 5 ]]; then
        AUDIT_ROWS+=("Forensik: System-Logs|$segfaults PHP-Crashes/OOMs (48h)|Mögliches ASLR-Brute-Forcing|${C_RED}WARNUNG${C_RESET}")
        FINDINGS+=("$segfaults PHP-Segfaults/OOM-Ereignisse in den Logs gefunden. Mögliche Exploit-Versuche!")
        ((WARN_COUNT++))
    else
        AUDIT_ROWS+=("Forensik: System-Logs|$segfaults PHP-Crashes (48h)|Keine Crash-Wellen erkannt|${C_GREEN}UNAUFFÄLLIG${C_RESET}")
    fi
}

run_full_audit() {
    scan_host_php
    scan_php_runtime_mitigations
    scan_docker_containers
    scan_forensics
    generate_checklist
}

# ==============================================================================
# Ausgabe & Tabellen-Darstellung
# ==============================================================================

print_audit_table() {
    clear
    echo -e "${C_BLUE}====================================================================================${C_RESET}"
    echo -e "${C_BOLD}  PHP2Shell Audit-Ergebnis (CVE-2026-109618 / CVE-2026-109619) - Stand: $(date '+%d.%m.%Y %H:%M')${C_RESET}"
    echo -e "${C_BLUE}====================================================================================${C_RESET}"
    printf "${C_BOLD}%-32s | %-18s | %-28s | %-15s${C_RESET}\n" "KOMPONENTE / PRÜFPUNKT" "VERSION / WERT" "DETAILS" "STATUS"
    echo "------------------------------------------------------------------------------------"

    for row in "${AUDIT_ROWS[@]}"; do
        IFS='|' read -r col1 col2 col3 col4 <<< "$row"
        printf "%-32s | %-18s | %-28s | %b\n" "${col1:0:32}" "${col2:0:18}" "${col3:0:28}" "$col4"
    done

    echo "------------------------------------------------------------------------------------"
    echo -e "Zusammenfassung: ${C_RED}${VULN_COUNT} Kritisch/Verwundbar${C_RESET} | ${C_YELLOW}${WARN_COUNT} Hinweise${C_RESET} | ${C_GREEN}${SAFE_COUNT} Sicher${C_RESET}"
    echo -e "Protokoll & Checkliste gespeichert unter: ${C_BOLD}${REPORT_DIR}${C_RESET}"
    echo ""
}

# ==============================================================================
# 100% Reversible Schutzmaßnahmen (Toggle On / Off)
# ==============================================================================

is_mitigation_ini_active() {
    local found
    found=$(find /etc/php -name "$MITIGATION_INI_NAME" 2>/dev/null | head -n1 || true)
    [[ -n "$found" ]] && return 0 || return 1
}

toggle_mitigation_ini() {
    if is_mitigation_ini_active; then
        echo -e "${C_YELLOW}Entferne temporäre BSI/CERT-EU PHP-Workarounds (Rollback)...${C_RESET}"
        find /etc/php -name "$MITIGATION_INI_NAME" -exec rm -f {} + 2>/dev/null || true
        reload_php_services
        log "Rollback: $MITIGATION_INI_NAME entfernt und Dienste neu geladen."
        echo -e "${C_GREEN}✓ Workaround-Konfiguration rückstandsfrei entfernt.${C_RESET}"
    else
        echo -e "${C_BLUE}Aktiviere BSI/CERT-EU Workarounds in allen /etc/php/*/conf.d Verzeichnissen...${C_RESET}"
        local conf_dirs
        conf_dirs=$(find /etc/php -type d -name "conf.d" 2>/dev/null || true)
        if [[ -z "$conf_dirs" ]]; then
            echo -e "${C_RED}Keine /etc/php/*/conf.d Verzeichnisse gefunden.${C_RESET}"
            return 1
        fi
        for dir in $conf_dirs; do
            cat <<EOF > "${dir}/${MITIGATION_INI_NAME}"
; =====================================================================
; Automatisch erstellt durch IT-Reinbek PHP2Shell Auditor v${VERSION}
; Temporäre Härtung gegen CVE-2026-109618 & CVE-2026-109619
; Zum Rückgängigmachen im Skript-Menü erneut auswählen.
; =====================================================================
session.upload_progress.enabled = 0
post_max_size = 16M
max_input_vars = 1000
fatal_error_backtraces = 0
expose_php = Off
EOF
        done
        reload_php_services
        log "Mitigation aktiviert: $MITIGATION_INI_NAME in conf.d ausgerollt."
        echo -e "${C_GREEN}✓ BSI/CERT-EU Workarounds aktiviert und PHP-Dienste neu geladen.${C_RESET}"
    fi
}

is_systemd_limit_active() {
    local found
    found=$(find /etc/systemd/system -name "$SYSTEMD_DROPIN_NAME" 2>/dev/null | head -n1 || true)
    [[ -n "$found" ]] && return 0 || return 1
}

toggle_systemd_cgroup_limit() {
    if is_systemd_limit_active; then
        echo -e "${C_YELLOW}Entferne systemd cgroup Speicherlimits (MemoryMax=2G)...${C_RESET}"
        find /etc/systemd/system -name "$SYSTEMD_DROPIN_NAME" -exec rm -f {} + 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        reload_php_services
        log "Rollback: systemd cgroup Limits entfernt."
        echo -e "${C_GREEN}✓ systemd cgroup Limits rückstandsfrei entfernt.${C_RESET}"
    else
        echo -e "${C_BLUE}Richte systemd cgroup MemoryMax=2G für PHP-FPM/Apache Dienste ein...${C_RESET}"
        local units
        units=$(systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -E '^(php.*fpm|apache2|httpd)\.service$' || true)
        for u in $units; do
            local drop_dir="/etc/systemd/system/${u}.d"
            mkdir -p "$drop_dir"
            cat <<EOF > "${drop_dir}/${SYSTEMD_DROPIN_NAME}"
[Service]
MemoryAccounting=true
MemoryMax=2G
EOF
        done
        systemctl daemon-reload 2>/dev/null || true
        reload_php_services
        log "Mitigation aktiviert: systemd cgroup MemoryMax=2G gesetzt."
        echo -e "${C_GREEN}✓ systemd cgroup Speicherlimits aktiviert.${C_RESET}"
    fi
}

reload_php_services() {
    local units
    units=$(systemctl list-units --type=service --state=running 2>/dev/null | awk '{print $1}' | grep -E '^(php.*fpm|apache2|httpd|nginx)\.service$' || true)
    for u in $units; do
        systemctl reload-or-restart "$u" 2>/dev/null || true
    done
}

# ==============================================================================
# Paket-Updates & Sicherer Docker-Compose-Workflow
# ==============================================================================

run_host_package_update() {
    echo -e "${C_BLUE}Prüfe und installiere verfügbare PHP-Sicherheitsupdates auf dem Host...${C_RESET}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install --only-upgrade -y $(dpkg -l | awk '/^ii.*php/ {print $2}')
    elif command -v dnf >/dev/null 2>&1; then
        dnf upgrade -y 'php*'
    elif command -v yum >/dev/null 2>&1; then
        yum update -y 'php*'
    else
        echo -e "${C_RED}Kein unterstützter Paketmanager (apt/dnf/yum) gefunden.${C_RESET}"
        return 1
    fi
    reload_php_services
    log "Host-PHP-Pakete aktualisiert und Dienste neu gestartet."
    echo -e "${C_GREEN}✓ Host-Updates abgeschlossen und PHP-Dienste neu gestartet.${C_RESET}"
}

run_docker_safe_workflow() {
    if [[ ${#CONTAINERS_VULN[@]} -eq 0 ]]; then
        echo -e "${C_GREEN}Keine verwundbaren Docker-Container erkannt.${C_RESET}"
        return 0
    fi

    echo -e "${C_YELLOW}Verwundbare Container erkannt: ${CONTAINERS_VULN[*]}${C_RESET}"
    for cname in "${CONTAINERS_VULN[@]}"; do
        local comp_dir
        comp_dir=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' "$cname" 2>/dev/null || true)
        local img
        img=$(docker inspect --format '{{.Config.Image}}' "$cname" 2>/dev/null || true)

        echo ""
        echo -e "Container: ${C_BOLD}$cname${C_RESET} (Image: $img)"
        if [[ -n "$comp_dir" && -d "$comp_dir" ]]; then
            echo "Erkanntes Compose-Verzeichnis: $comp_dir"
            read -r -p "Stack sauber herunterfahren (compose down), Backup erstellen & neu pullen? [j/N]: " dresp
            if [[ "$dresp" =~ ^[jJyY]$ ]]; then
                (
                    cd "$comp_dir" || exit 1
                    docker tag "$img" "${img%:*}:pre-php2shell-rollback" 2>/dev/null || true
                    docker compose down
                    tar -czf "${STATE_DIR}/compose-backup-${cname}-$(date +%Y%m%d-%H%M%S).tar.gz" .
                    docker compose pull
                    docker compose up -d
                )
                log "Docker-Compose Stack in $comp_dir aktualisiert (Rollback-Tag erstellt)."
                echo -e "${C_GREEN}✓ Stack $cname erfolgreich aktualisiert.${C_RESET}"
            fi
        else
            echo "Kein automatisches Compose-Verzeichnis ermittelt. Bitte Image '$img' manuell neu pullen und Container neu starten."
        fi
    done
}

# ==============================================================================
# Compliance-Checkliste & Druckfunktion (CUPS / lp)
# ==============================================================================

generate_checklist() {
    cat <<EOF > "$CHECKLIST_FILE"
================================================================================
IT-REINBEK - REVISIONSNACHWEIS & NOTFALL-CHECKLISTE (PHP2Shell)
Schwachstellen: CVE-2026-109618 / CVE-2026-109619 (BSI-Warnstufe Orange / CVSS 9.2)
Server / Host:  $(hostname -f 2>/dev/null || hostname)
Prüfzeitpunkt:  $(date '+%d.%m.%Y %H:%M:%S %Z')
Prüfwerkzeug:   PHP2Shell Auditor v${VERSION}
================================================================================

1. AUTOMATISCHE BESTANDSAUFNAHME
--------------------------------------------------------------------------------
EOF
    for row in "${AUDIT_ROWS[@]}"; do
        IFS='|' read -r c1 c2 c3 c4 <<< "$row"
        # ANSI-Farben für Textdatei entfernen
        local clean_c4
        clean_c4=$(echo -e "$c4" | sed 's/\x1b\[[0-9;]*m//g')
        printf "%-32s | %-18s | %-28s | %s\n" "${c1:0:32}" "${c2:0:18}" "${c3:0:28}" "$clean_c4" >> "$CHECKLIST_FILE"
    done

    cat <<EOF >> "$CHECKLIST_FILE"

2. FESTGESTELLTER HANDLUNGSBEDARF
--------------------------------------------------------------------------------
EOF
    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        echo "[✓] Keine ungepatchten Komponenten oder kritischen Abweichungen festgestellt." >> "$CHECKLIST_FILE"
    else
        for f in "${FINDINGS[@]}"; do
            echo "[!] $f" >> "$CHECKLIST_FILE"
        done
    fi

    cat <<EOF >> "$CHECKLIST_FILE"

3. MANUELLE COMPLIANCE-CHECKLISTE FÜR ADMINISTRATOREN
--------------------------------------------------------------------------------
[ ] Host-PHP-Pakete auf >= 8.5.12, 8.4.27, 8.3.36, 8.2.35 oder Distro-Backport gebracht
[ ] Alle PHP-FPM-Dienste und Webserver (Apache/Nginx) nach dem Update neu gestartet
[ ] Laufende Docker-Container separat neu gebaut / gepullt und neu gestartet
[ ] Falls memory_limit = -1 als Notfall-Workaround genutzt wurde: Nach Patch wieder begrenzt!
[ ] Aktive PHP-Sitzungen bereinigt und kritische API-Keys / Passwörter bei Verdacht rotiert

Geprüft durch (Name / Unterschrift): ___________________________________________
EOF
}

print_checklist_cups() {
    generate_checklist
    echo -e "${C_BLUE}Revisionsbericht erstellt: ${CHECKLIST_FILE}${C_RESET}"
    if command -v lpstat >/dev/null 2>&1 && command -v lp >/dev/null 2>&1; then
        local printers
        printers=$(lpstat -a 2>/dev/null | awk '{print $1}' || true)
        if [[ -n "$printers" ]]; then
            echo "Verfügbare Drucker:"
            echo "$printers"
            read -r -p "Bericht jetzt auf dem Standarddrucker ausdrucken? [j/N]: " presp
            if [[ "$presp" =~ ^[jJyY]$ ]]; then
                lp "$CHECKLIST_FILE"
                echo -e "${C_GREEN}✓ Druckauftrag wurde an CUPS übergeben.${C_RESET}"
            fi
        else
            echo "Kein aktiver CUPS-Drucker konfiguriert. Sie können die Datei direkt aus ${CHECKLIST_FILE} kopieren."
        fi
    else
        echo "Kein lokales Drucksystem (lp/CUPS) installiert. Bericht liegt als Textdatei bereit under: ${CHECKLIST_FILE}"
    fi
}

# ==============================================================================
# Interaktives TUI-Hauptmenü
# ==============================================================================

interactive_menu() {
    while true; do
        print_audit_table

        local ini_status="${C_MUTED}[ INAKTIV ]${C_RESET}"
        is_mitigation_ini_active && ini_status="${C_GREEN}[ AKTIV - Anklicken zum Rückgängigmachen ]${C_RESET}"

        local sysd_status="${C_MUTED}[ INAKTIV ]${C_RESET}"
        is_systemd_limit_active && sysd_status="${C_GREEN}[ AKTIV - Anklicken zum Rückgängigmachen ]${C_RESET}"

        echo -e "${C_BOLD}MASSNAHMEN & REMEDIATION MENÜ (100 % Rückabwickelbar):${C_RESET}"
        echo -e "  [1] 🔄 Erneuten Komplett-Scan ausführen"
        echo -e "  [2] 🛡️  BSI/CERT-EU INI-Workarounds umschalten (upload_progress=0, post_max_size)  $ini_status"
        echo -e "  [3] ⚙️  systemd cgroup Speicherlimit (MemoryMax=2G) umschalten                    $sysd_status"
        echo -e "  [4] 📦 Offizielle Host-PHP-Updates über Paketmanager (apt/dnf) einspielen"
        echo -e "  [5] 🐳 Docker-Compose Safe-Update & Backup-Workflow starten"
        echo -e "  [6] 🖨️  Revisionssichere Compliance-Checkliste anzeigen / drucken"
        echo -e "  [q] 🚪 Beenden"
        echo ""
        read -r -p "Auswahl [1-6, q]: " choice

        case "$choice" in
            1) run_full_audit ;;
            2) toggle_mitigation_ini; sleep 2; run_full_audit ;;
            3) toggle_systemd_cgroup_limit; sleep 2; run_full_audit ;;
            4) run_host_package_update; read -r -p "Weiter mit Enter..."; run_full_audit ;;
            5) run_docker_safe_workflow; read -r -p "Weiter mit Enter..."; run_full_audit ;;
            6) less "$CHECKLIST_FILE" 2>/dev/null || cat "$CHECKLIST_FILE"; print_checklist_cups; read -r -p "Weiter mit Enter..." ;;
            q|Q) echo "Beende PHP2Shell Auditor. Bleiben Sie sicher!"; exit 0 ;;
            *) ;;
        esac
    done
}

# ==============================================================================
# Programmstart
# ==============================================================================

show_disclaimer
run_full_audit

if [[ $NO_MENU -eq 1 ]]; then
    print_audit_table
    exit 0
else
    interactive_menu
fi
