#!/usr/bin/env bash
#
# php2shell-check.sh  (v1.5.0 - Stateful TUI, Reversible Config & Emergency-Patch Edition)
# Prüft PHP auf CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) & CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) ("PHP2Shell"),
# berücksichtigt den BSI-IT-Sicherheitshinweis BITS-H Nr. 2026-297981-1132 (Version 1.1 vom 21.10.2026),
# die Notfall-Updates (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 + EOL-Backports für 7.4 / 8.0 / 8.1)
# sowie tagesaktuelle Analysen/IOCs (Armis, Abstract Security, Datadog, Sansec, Corelight, IT-Administrator).
#
# Neu in v1.5.0:
# - Vorab-Abfrage & vollständige Telegram-Bot-Integration (Schritt 3/4 & Maßnahme #18):
#     * Fragt vor dem Maßnahmen-Menü ab, ob Sicherheits-Infos via Telegram-Bot gesendet werden sollen,
#       sammelt Bot-Token (verdeckte Eingabe), Chat-ID & Server-Label inkl. lesender API-Prüfung (getMe/getChat).
#     * Legt die Zugangsdaten gegen unerlaubten Zugriff geschützt ab (/etc/it-reinbek 0700 root:root,
#       /etc/it-reinbek/telegram.conf atomar per mktemp mit 0600 root:root, /usr/local/sbin/it-reinbek-notify
#       mit 0750 root:root und Token-Übergabe per curl -K - Stdin ohne Sichtbarkeit in ps / /proc).
#     * Hält die Einstellungen zentral für rkhunter, fail2ban, ClamAV und auditd vor (100% kompatibel mit
#       dem IT-Reinbek Linux-Härtungsskript) und fragt bei der Konfiguration von auditd (#13, auch wenn
#       bereits aktiv!) und ClamAV (#17) immer explizit ab, ob die Telegram-Benachrichtigung gewünscht ist.
# - 4-stufiges Vollbild-Box-TUI analog zum IT-Reinbek-Härtungsskript (Schritt 1/4: Rechtlicher Hinweis,
#   Schritt 2/4: Systemprüfung & Befund-Screen, Schritt 3/4: Telegram-Bot & Bausteine, Schritt 4/4:
#   Split-Box-Maßnahmen-Menü 1-18) unter Beibehaltung der Original-Farben & Marker ([x] Grün, [+] Gelb, [-] Rot).
# - ClamAV Malwareschutz (#17) mit automatischer RAM-Analyse & Empfehlung (Echtzeit clamd + clamonacc
#   On-Access ab 3500 MB frei vs. täglicher Zeitplan-/Cronjob-Scan um 03:30 Uhr ab 1800 MB frei).
# - Erweiterte Runtime-Inspektion & Drop-in-Härtung um display_errors (Schutz vor Adress-Leaks / ASLR-Bypass)
#   und session.use_strict_mode (Schutz vor Session-Fixation / bösartigen Session-IDs).
# - Erweiterte Runtime-Inspektion in check_runtime (session.upload_progress.enabled, memory_limit=-1,
#   fatal_error_backtraces unter PHP 8.5).
# - Mehrsprachigkeit (Deutsch/Englisch): Auto-Erkennung über LANG/LC_ALL, CLI-Parameter --lang <de|en>
#   sowie Live-Umschaltung im interaktiven TUI-Menü über die Taste [l].
# - Robuster Terminal-/FD-Mechanismus (exec 3>&1 4>&2): Öffnet die Split-Screen-TUI zuverlässig
#   auch nach der Hintergrund-Aufzeichnung (tee) unter sudo, SSH und Tabby.
# - Erweiterte Erkennung der Notfall-Backports für PHP 7.4, 8.0 und 8.1 (Changelog + Build-Datum >= 21.10.2026).
# - Vorgeschalteter rechtlicher Haftungsausschluss (Disclaimer zur Nutzung in Eigenverantwortung).
# - Zustandsbasierte Split-Screen-TUI (Links Checkboxen 1-18 ohne Zähllücken, rechts Live-Erklärung):
#     * [x] (Grün)  = Maßnahme/Konfiguration ist bereits auf dem System AKTIV / angewendet
#     * [ ] (Weiß)  = Maßnahme/Konfiguration ist NICHT aktiv
#     * [+] (Gelb)  = Neu ausgewählt -> wird beim Ausführen [Enter] AKTIVIERT / installiert
#     * [-] (Rot)   = War aktiv [x] und wurde abgewählt -> wird beim Ausführen [Enter] RÜCKABGEWICKELT!
# - Druckfunktion für Checkliste [p] SOWIE kompletten Revisions-Bericht (Scan-Report + Checkliste) [r].
#
# Aufruf (als root):
#   sudo ./php2shell-check.sh [--since YYYY-MM-DD] [--webroot DIR]...
#                             [--report DATEI] [--versions-only] [--no-menu] [--accept-disclaimer]
#                             [--lang <de|en>]
#
# Exit-Codes: 0 = sauber, 1 = Warnungen, 2 = verwundbar/Verdachtsfälle
#
set -uo pipefail

VERSION="1.5.0"
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SINCE="2026-10-17"
REPORT=""
DO_SCAN=1
NO_MENU=0
ACCEPT_DISCLAIMER=0

if [[ "${LC_ALL:-${LANG:-}}" == de* ]]; then
  UI_LANG="de"
else
  UI_LANG="en"
fi

# Originale Terminal-File-Descriptoren sichern (vor jeglicher tee-Umleitung)
exec 3>&1 4>&2
HAS_TTY=0
if [ -t 0 ] || [ -t 1 ] || [ -t 2 ]; then
  HAS_TTY=1
elif ( : </dev/tty ) 2>/dev/null; then
  HAS_TTY=1
fi

WEBROOTS=()
NEED_UPDATE=()
FOUND_FILES=()
FOUND_CONF=()
CRIT=0
WARN=0
COMP=0
ATT=0
STALE=0
EVIDENCE_DONE=0
PROBE_ASKED=0
UPG_OLD=""
UPG_TGT=""
PROBE_URLS=()
RISKS=()
MIGRATED_FILES=()
SNAP_SVCS=()
SNAP_PORTS=""
SNAP_PROBE=""
LAST_STATE=""
DK_OK=0
DK_ALL=()
DK_VULN=()
DKR_HINT=0
DKR_NEWER=0
COMPOSE=()
CARGS=()
DKR_NEWTAGS=""
PC_ID=""
PC_VER=""
HIDDEN_EXCL=(! -name '.php-cs-fixer*.php' ! -name '.php_cs*' ! -name '.phpstorm.meta.php' ! -name '.phpunit*.php' ! -name '.psalm*.php')
declare -A DK_IMG=() DK_PROJ=() DK_SVC=() DK_DIR=() DK_FILES=() DK_PHPV=() DK_REGHINT=() DK_REGNEWER=() DK_NEWTAGS=()
BACKUP_DIR=""
QUAR_DIR=""
STATE_DIR="/root/.php2shell-state"
SCAN_CAPTURED="/root/.php2shell-last-scan.txt"
LOGFILE="/root/php2shell-actions.log"
MARK_INI="99-php2shell-mitigation.ini"
MARK_MEM="php2shell-managed"
AUDIT_RULE="/etc/audit/rules.d/99-php2shell.rules"
SNIPPET_DIR="/root/php2shell-snippets"

R_LABEL=(); R_VER=(); R_NEED=(); R_STATE=(); MSGS=()

# Offizielle PHP Notfall-Updates vom 21.10.2026 (16:00 MESZ / 14:00 UTC)
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )
# EOL-Branches, für die das PHP Security Team Quellcode-Backports bereitgestellt hat
declare -A EOL_BACKPORT_BRANCHES=( [8.1]=8.1.34 [8.0]=8.0.30 [7.4]=7.4.33 )
RECOMMENDED_BRANCH="8.4"

# Muster mit hoher Trefferqualität
P_EVAL='eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\('
P_SUPER='(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
P_DYN='\$_(GET|POST|REQUEST|COOKIE)\s*\[[^]]+\]\s*\('
P_NAMES='(c99shell|r57shell|FilesMan|b374k|WSOshell|wso_version|AlfaShell|IndoXploit)'
P_PREG="preg_replace\\s*\\(\\s*['\"]/[^'\"]*/e['\"]"

usage() {
  if [ "${UI_LANG:-de}" = "en" ]; then
    cat <<'EOF'
Usage: php2shell-check.sh [Options]
  --since YYYY-MM-DD     Timestamp from which changes are considered suspicious (Default: 2026-10-17)
  --webroot DIR          Specify webroot explicitly (can be used multiple times; otherwise autodetect)
  --report FILE          Additionally write output to file (without colors)
  --versions-only        Check versions only, skip compromise scan
  --no-menu              Skip interactive remediation menu (e.g. for cron/CI)
  --accept-disclaimer    Accept legal disclaimer in advance (for automated runs)
  --lang <de|en>         Set interface language (Default: autodetect via LANG/LC_ALL)
  -h, --help             Show this help
EOF
  else
    cat <<'EOF'
Verwendung: php2shell-check.sh [Optionen]
  --since YYYY-MM-DD     Zeitpunkt, ab dem Änderungen verdächtig sind (Standard: 2026-10-17)
  --webroot DIR          Webroot explizit angeben (mehrfach möglich; sonst Autodetect)
  --report DATEI         Ausgabe zusätzlich in Datei schreiben (ohne Farben)
  --versions-only        Nur Versionsprüfung, kein Kompromittierungs-Scan
  --no-menu              Kein interaktives Maßnahmenmenü (z. B. für Cron/CI)
  --accept-disclaimer    Haftungsausschluss vorab akzeptieren (für automatisierte Läufe)
  --lang <de|en>         Sprache festlegen (Standard: Auto-Erkennung über LANG/LC_ALL)
  -h, --help             Diese Hilfe
EOF
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --since)             SINCE="${2:-}"; shift 2 ;;
    --webroot)           WEBROOTS+=("${2:-}"); shift 2 ;;
    --report)            REPORT="${2:-}"; shift 2 ;;
    --versions-only)     DO_SCAN=0; shift ;;
    --no-menu)           NO_MENU=1; shift ;;
    --accept-disclaimer) ACCEPT_DISCLAIMER=1; shift ;;
    --lang)
      case "${2:-}" in
        de|DE) UI_LANG="de" ;;
        en|EN) UI_LANG="en" ;;
        *) echo "Ungültige Sprache / Invalid language: ${2:-} (erlaubt/allowed: de|en)" >&2; usage >&2; exit 64 ;;
      esac
      shift 2 ;;
    --lang=*)
      case "${1#*=}" in
        de|DE) UI_LANG="de" ;;
        en|EN) UI_LANG="en" ;;
        *) echo "Ungültige Sprache / Invalid language: ${1#*=} (erlaubt/allowed: de|en)" >&2; usage >&2; exit 64 ;;
      esac
      shift ;;
    -h|--help)           usage; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

date -d "$SINCE" >/dev/null 2>&1 || { echo "Ungültiges Datum: $SINCE" >&2; exit 64; }

if [ "$HAS_TTY" -eq 1 ] && [ -z "$REPORT" ]; then
  R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; C=$'\e[36m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  R=''; Y=''; G=''; C=''; B=''; D=''; N=''
fi

hdr()    { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
ok()     { printf '%s[ OK ]%s %s\n' "$G" "$N" "$*"; }
info()   { printf '[INFO] %s\n' "$*"; }
warn()   { printf '%s[WARN]%s %s\n' "$Y" "$N" "$*"; WARN=$((WARN+1)); }
crit()   { printf '%s[CRIT]%s %s\n' "$R" "$N" "$*"; CRIT=$((CRIT+1)); }
susp()   { crit "$@"; COMP=$((COMP+1)); }
indent() { sed 's/^/        /'; }
alog()   { umask 077; printf '%s  %s\n' "$(date '+%F %T')" "$*" >> "$LOGFILE" 2>/dev/null || true; }
strip_ansi() { sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g'; }

tty_read() {
  if [ -t 0 ]; then
    read "$@"
  elif ( : </dev/tty ) 2>/dev/null; then
    read "$@" </dev/tty
  else
    read "$@" <&3
  fi
}

ensure_state_dir() {
  [ "$(id -u)" -eq 0 ] || return 0
  mkdir -p "$STATE_DIR" 2>/dev/null && chmod 700 "$STATE_DIR" 2>/dev/null || true
}

# ======================================================= Rechtlicher Disclaimer

tui_topbar() {
  local cols="$1" left="$2" right="$3" pad
  pad=$(( cols - ${#left} - ${#right} ))
  [ "$pad" -lt 1 ] && pad=1
  printf '\e[44;97;1m%s%*s%s\e[0m\n' "$left" "$pad" "" "$right"
}

tui_single_box_top() {
  local cols="$1" title="$2" more_up="${3:-0}" inner fill up_str=""
  inner=$(( cols - 2 ))
  if [ "$more_up" -eq 1 ]; then
    if [ "$UI_LANG" = "en" ]; then up_str=" ^more "; else up_str=" ^mehr "; fi
  fi
  fill=$(( inner - ${#title} - ${#up_str} - 4 ))
  [ "$fill" -lt 1 ] && fill=1
  printf '%s+-- %s%s%s %s%s%s%s+%s\n' "$C" "$C$B" "$title" "$N$C" "$(printf '%*s' "$fill" '' | tr ' ' '-')" "$Y" "$up_str" "$C" "$N"
}

tui_single_box_bot() {
  local cols="$1" more_dn="${2:-0}" inner fill dn_str=""
  inner=$(( cols - 2 ))
  if [ "$more_dn" -eq 1 ]; then
    if [ "$UI_LANG" = "en" ]; then dn_str=" PgDn v more "; else dn_str=" Bild v mehr "; fi
  fi
  fill=$(( inner - ${#dn_str} ))
  [ "$fill" -lt 1 ] && fill=1
  printf '%s+%s%s%s%s+%s\n' "$C" "$(printf '%*s' "$fill" '' | tr ' ' '-')" "$Y" "$dn_str" "$C" "$N"
}

show_legal_disclaimer() {
  [ "$ACCEPT_DISCLAIMER" -eq 1 ] && return 0
  [ "$NO_MENU" -eq 1 ] && return 0
  [ "$HAS_TTY" -eq 1 ] || return 0

  local scroll=0 key k2 k3
  while true; do
    local cols rows box_h text_w
    cols=$(tput cols 2>/dev/null || echo 118)
    rows=$(tput lines 2>/dev/null || echo 34)
    [ "$cols" -lt 80 ] && cols=80
    [ "$rows" -lt 22 ] && rows=22
    box_h=$(( rows - 5 ))
    text_w=$(( cols - 6 ))

    local raw_disc step_title box_title status_line key_line
    if [ "$UI_LANG" = "en" ]; then
      step_title="Step 1/4 - Legal Disclaimer "
      box_title="Disclaimer & Terms of Use (BSI Advisory)"
      status_line=" Please read carefully. Press [Enter] or [y] to accept and start the read-only system audit."
      key_line=" Up/Down/PgDn: scroll | Enter/y: I ACCEPT (Start Audit) | l: Language (DE/EN) | q: Quit"
      raw_disc=$(cat <<EOF
${R}${B}IMPORTANT LEGAL NOTICE & DISCLAIMER OF LIABILITY${N}

This tool (${B}IT-Reinbek PHP2Shell-Auditor v${VERSION}${N}) is designed for security auditing and assisted containment/remediation of ${B}CVE-2026-109618${N} and ${B}CVE-2026-109619 ("PHP2Shell")${N}.

${C}${B}1. Provided "AS IS" & Sole Responsibility${N}
This script is provided free of charge and used at the sole risk and full responsibility of the user/operator. No warranty of any kind is given regarding accuracy, completeness, timeliness, absence of errors, or fitness for purpose.

${C}${B}2. No Guarantee of Detection or Complete Protection${N}
A scan with zero findings ("0 CRIT / 0 WARN") is NOT proof that the system has not been compromised. Temporary workarounds per BSI (BITS-H 2026-297981-1132) do not replace official security patches.

${C}${B}3. System Modifications, Rollback & Operational Risks${N}
The initial scan (Step 2/4) is strictly read-only. However, if you actively enable or revert remediation steps in the subsequent TUI menu (Steps 3/4 & 4/4: Telegram bot, package updates, PHP branch switch, Docker Compose stop/recreate, config changes, quarantine), the script modifies the live system. Despite built-in backups and rollback mechanisms, service interruptions, incompatibilities, or data loss may occur.

${C}${B}4. Limitation of Liability (pursuant to German law, §§ 521, 599, 276 BGB)${N}
Any liability of the authors or contributors for direct or indirect damages, consequential damages, data loss, or system downtime is excluded, unless caused by intent, gross negligence, or mandatory statutory liability.

${C}${B}5. Authorization & Backups${N}
By pressing ${G}${B}[Enter]${N} or ${G}${B}[y]${N}, you confirm that you are authorized to audit and administer this system, that current external backups exist, and that you accept this disclaimer.
EOF
)
    else
      step_title="Schritt 1/4 - Rechtlicher Hinweis "
      box_title="Haftungsausschluss & Nutzungsbedingungen (Disclaimer)"
      status_line=" Bitte sorgfaeltig lesen. Mit [Enter] oder [j] akzeptieren Sie und starten die lesende Systempruefung."
      key_line=" Pfeile/Bild: scrollen | Enter/j: ICH AKZEPTIERE (Scan starten) | l: Sprache (DE/EN) | q: Abbruch"
      raw_disc=$(cat <<EOF
${R}${B}WICHTIGER RECHTLICHER HINWEIS & HAFTUNGSAUSSCHLUSS (DISCLAIMER)${N}

Dieses Werkzeug (${B}IT-Reinbek PHP2Shell-Auditor v${VERSION}${N}) dient der Sicherheitsanalyse sowie der unterstuetzten Eindaemmung und Behebung der Schwachstellen ${B}CVE-2026-109618${N} und ${B}CVE-2026-109619 ("PHP2Shell")${N}.

${C}${B}1. Bereitstellung ohne Gewaehr ("AS IS") & Eigenverantwortung${N}
Die Bereitstellung und Nutzung dieses Skripts erfolgt unentgeltlich und auf alleinige Gefahr sowie in voller Eigenverantwortung des Anwenders/Betreibers. Es wird keinerlei Gewaehrleistung fuer Richtigkeit, Vollstaendigkeit, Aktualitaet, Fehlerfreiheit oder die Eignung fuer einen bestimmten Zweck uebernommen.

${C}${B}2. Keine Garantie auf Erkennung oder vollstaendigen Schutz${N}
Ein Scan ohne Treffer ("0 CRIT / 0 WARN") ist KEIN Beweis dafuer, dass das System nicht kompromittiert wurde. Ebenso ersetzen temporaere Workarounds laut BSI (BITS-H Nr. 2026-297981-1132) keinen offiziellen Sicherheits-Patch.

${C}${B}3. Systemeingriffe, Rueckabwicklung & Betriebsrisiken${N}
Der initiale Scan (Schritt 2/4) arbeitet rein lesend. Wenn Sie im anschliessenden TUI-Menue (Schritt 3/4 & 4/4) jedoch aktiv Massnahmen aktivieren oder deaktivieren (z. B. Telegram-Bot, Paket-Updates, PHP-Branch-Wechsel, Docker-Compose-Stopp/Recreate, Konfigurationsaenderungen, Quarantaene oder deren Rueckabwicklung), greift das Skript tief in das laufende System ein. Trotz integrierter Backups und Rollback-Mechanismen kann es zu Dienstunterbrechungen, Inkompatibilitaeten oder Datenverlust kommen.

${C}${B}4. Haftungsbeschraenkung (gemaess deutschem Recht, §§ 521, 599, 276 BGB)${N}
Jegliche Haftung der Autoren, Bereitsteller oder Mitwirkenden fuer direkte oder indirekte Schaeden, Folgeschaeden, Datenverlust, Systemausfaelle oder entgangenen Gewinn ist ausgeschlossen, soweit diese nicht auf Vorsatz oder grober Fahrlaessigkeit beruhen oder eine zwingende gesetzliche Haftung besteht.

${C}${B}5. Autorisierung & Bestaetigung${N}
Mit Druck auf ${G}${B}[Enter]${N} oder ${G}${B}[j]${N} bestaetigen Sie, dass Sie berechtigt sind, dieses System zu pruefen und ggf. administrativ zu veraendern, dass aktuelle externe Backups vorliegen und dass Sie diesen Haftungsausschluss in Eigenverantwortung akzeptieren.
EOF
)
    fi

    local -a dlines=("")
    local rline wline
    while IFS= read -r rline; do
      if [ -z "$rline" ]; then
        dlines+=("")
      else
        while IFS= read -r wline; do
          dlines+=("$wline")
        done < <(printf '%s\n' "$rline" | fold -s -w "$text_w")
      fi
    done <<< "$raw_disc"

    local total="${#dlines[@]}"
    local max_scroll=$(( total - box_h ))
    [ "$max_scroll" -lt 0 ] && max_scroll=0
    [ "$scroll" -gt "$max_scroll" ] && scroll="$max_scroll"
    [ "$scroll" -lt 0 ] && scroll=0

    local more_up=0 more_dn=0
    [ "$scroll" -gt 0 ] && more_up=1
    [ $(( scroll + box_h )) -lt "$total" ] && more_dn=1

    printf '\e[H\e[2J'
    tui_topbar "$cols" " IT-Reinbek PHP2Shell-Auditor v${VERSION}" "$step_title"
    tui_single_box_top "$cols" "$box_title" "$more_up"

    local idx line plain plen pad
    for (( idx=0; idx<box_h; idx++ )); do
      line="${dlines[$(( scroll + idx ))]:-}"
      plain=$(printf '%s' "$line" | sed $'s/\e\\[[0-9;]*[a-zA-Z]//g')
      plen="${#plain}"
      pad=$(( cols - 4 - plen ))
      [ "$pad" -lt 0 ] && pad=0
      printf '%s|%s %s%*s %s|%s\n' "$C" "$N" "$line" "$pad" "" "$C" "$N"
    done

    tui_single_box_bot "$cols" "$more_dn"
    printf '%s%s%s\n' "$C" "${status_line:0:$cols}" "$N"
    printf '%s%s%s' "$B" "${key_line:0:$cols}" "$N"

    IFS= tty_read -rsn1 key || exit 1
    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) scroll=$(( scroll - 1 )) ;;
          B) scroll=$(( scroll + 1 )) ;;
          5) IFS= tty_read -rsn1 -t 0.02 _ || true; scroll=$(( scroll - box_h / 2 )) ;;
          6) IFS= tty_read -rsn1 -t 0.02 _ || true; scroll=$(( scroll + box_h / 2 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) scroll=$(( scroll - 1 )) ;;
      " ") scroll=$(( scroll + box_h / 2 )) ;;
      l|L)
        if [ "$UI_LANG" = "de" ]; then UI_LANG="en"; else UI_LANG="de"; fi
        load_menu_texts 2>/dev/null || true
        ;;
      ""|j|J|y|Y)
        clear
        if [ "$UI_LANG" = "en" ]; then
          alog "Legal disclaimer accepted by user ($(id -un))."
          printf '%sDisclaimer accepted. Starting system audit ...%s\n\n' "$G" "$N"
        else
          alog "Haftungsausschluss vom Benutzer ($(id -un)) akzeptiert."
          printf '%sHaftungsausschluss akzeptiert. Starte Systemprüfung ...%s\n\n' "$G" "$N"
        fi
        break
        ;;
      q|Q)
        clear
        if [ "$UI_LANG" = "en" ]; then
          printf '\n%sDisclaimer not accepted. Exiting without changes.%s\n' "$Y" "$N"
        else
          printf '\n%sHaftungsausschluss nicht akzeptiert. Skript wird ohne Änderungen beendet.%s\n' "$Y" "$N"
        fi
        exit 1
        ;;
    esac
  done
}

# ---------------------------------------------------------------- Versionslogik

ver_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

distro_path() {
  case "$1" in /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*|/usr/libexec/*|/opt/plesk/php/*|/opt/alt/php*/*|/opt/cpanel/ea-php*/*|/opt/remi/php*/*) return 0 ;; esac
  return 1
}

backport_fix_present() { # Prüft Distro-/LTS-Backports (insb. für 7.4, 8.0, 8.1 sowie Enterprise-Linux)
  local f="$1" pkg="" cl bdate pver
  if command -v dpkg >/dev/null 2>&1; then
    pkg=$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1)
    if [ -n "$pkg" ]; then
      for cl in /usr/share/doc/"$pkg"/changelog*.gz; do
        if [ -f "$cl" ] && zgrep -qE 'CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp' "$cl" 2>/dev/null; then return 0; fi
      done
      # Sury/Ondrej PPA & Debian LTS kennzeichnen Backports oft im Paket-Versionsstring mit Datum >= 20261021
      pver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
      if [[ "$pver" =~ 2026(102[1-9]|103[01]|1[12][0-9]{2}) ]]; then return 0; fi
    fi
  fi
  if command -v rpm >/dev/null 2>&1; then
    pkg=$(rpm -qf "$f" 2>/dev/null | head -n1)
    if [ -n "$pkg" ] && rpm -q --changelog "$pkg" 2>/dev/null | grep -qE 'CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp'; then return 0; fi
  fi
  # Build-Datum im PHP-Binary prüfen (Plesk, CloudLinux, Remi, Sury Backports für 7.4/8.0/8.1 gebaut ab 21.10.2026)
  if [ -x "$f" ]; then
    bdate=$("$f" -v 2>/dev/null | head -n1 | sed -n 's/.*(built: \([^)]*\)).*/\1/p')
    if [ -n "$bdate" ] && [ "$(date -d "$bdate" +%Y%m%d 2>/dev/null || echo 0)" -ge 20261021 ] 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

get_pkg_version() {
  local f="$1" pkg="" v=""
  if command -v dpkg-query >/dev/null 2>&1; then
    pkg=$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1)
    if [ -n "$pkg" ]; then v=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null); fi
  elif command -v rpm >/dev/null 2>&1; then
    v=$(rpm -qf --qf '%{VERSION}' "$f" 2>/dev/null)
  fi
  echo "${v#*:}"
}

add_row() {
  R_LABEL+=("$1"); R_VER+=("$2"); R_NEED+=("$3"); R_STATE+=("$4")
}

assess() {
  local label="$1" ver="$2" path="$3" branch fixed bp=1
  LAST_STATE=UNKNOWN
  if ! [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    add_row "$label" "$ver" "?" UNKNOWN
    MSGS+=("warn|$label: Version nicht lesbar ('$ver') - bitte manuell prüfen")
    return
  fi
  branch="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
  ver="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
  fixed="${FIXED[$branch]:-}"
  if distro_path "$path" && backport_fix_present "$path"; then bp=0; fi

  if [ -n "$fixed" ] && ver_ge "$ver" "$fixed"; then
    add_row "$label" "$ver" ">= $fixed" SAFE; LAST_STATE=SAFE
    if [ "$branch" = "8.2" ]; then
      MSGS+=("info|$label: Notfall-Update ($ver) ist installiert, ABER Branch 8.2 erreicht am 31.12.2026 EOL (BSI-Empfehlung: Migration auf >= 8.4 planen)")
    fi
  elif [ "$bp" -eq 0 ]; then
    add_row "$label" "$ver" "(Backport >=21.10.)" BACKPORT; LAST_STATE=BACKPORT
  elif [ -n "$fixed" ]; then
    add_row "$label" "$ver" ">= $fixed" VULN; LAST_STATE=VULN
    MSGS+=("crit|$label: PHP $ver ist VERWUNDBAR -> Notfall-Update auf mindestens $fixed nötig!")
    [ "$path" = "/container" ] || NEED_UPDATE+=("$branch")
  elif ver_ge "$ver" "8.6.0"; then
    add_row "$label" "$ver" "?" UNKNOWN
    MSGS+=("info|$label: PHP $ver - neuer als die bekannten Branches, Fix-Stand bitte selbst prüfen")
  else
    add_row "$label" "$ver" "Backport / >= ${RECOMMENDED_BRANCH}.x" EOL; LAST_STATE=EOL
    if [ -n "${EOL_BACKPORT_BRANCHES[$branch]:-}" ]; then
      MSGS+=("crit|$label: PHP $ver ist EOL und ungepatcht -> Distro/LTS-Backport einspielen (Quellcode-Backport für $branch existiert!) oder Upgrade auf Branch $RECOMMENDED_BRANCH (>= ${FIXED[$RECOMMENDED_BRANCH]})")
    else
      MSGS+=("crit|$label: PHP $ver ist EOL (verwundbar ab mind. PHP 5) -> Upgrade auf Branch $RECOMMENDED_BRANCH (>= ${FIXED[$RECOMMENDED_BRANCH]})")
    fi
    [ "$path" = "/container" ] || NEED_UPDATE+=("$branch")
  fi
}

print_table() {
  [ "${#R_LABEL[@]}" -gt 0 ] || return 0
  local i c st
  printf '%s%-46s %-10s %-18s %s%s\n' "$B" "INSTALLATION" "VERSION" "SICHER AB" "STATUS" "$N"
  for i in "${!R_LABEL[@]}"; do
    case "${R_STATE[$i]}" in
      SAFE)     c="$G"; st="SICHER (Notfall-Update aktiv)" ;;
      BACKPORT) c="$G"; st="SICHER (Distro/LTS-Backport)" ;;
      VULN)     c="$R"; st="UNSICHER - Notfall-Update nötig" ;;
      EOL)      c="$R"; st="UNSICHER - EOL (Backport/Upgrade nötig)" ;;
      *)        c="$Y"; st="UNKLAR - manuell prüfen" ;;
    esac
    printf '%-46s %s%-10s%s %-18s %s%s%s\n' "${R_LABEL[$i]}" "$c" "${R_VER[$i]}" "$N" "${R_NEED[$i]}" "$c" "$st" "$N"
  done
  local m
  for m in ${MSGS[@]+"${MSGS[@]}"}; do
    case "${m%%|*}" in
      crit) crit "${m#*|}" ;;
      warn) warn "${m#*|}" ;;
      *)    info "${m#*|}" ;;
    esac
  done
}

find_php_binaries() {
  {
    command -v php php-cgi php-fpm lsphp 2>/dev/null
    ls /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
       /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
       /opt/plesk/php/*/bin/php /opt/cpanel/ea-php*/root/usr/bin/php \
       /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php \
       /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/bin/lsphp 2>/dev/null
  } | grep -E '/(lsphp|php|php-cgi|php-fpm)[0-9.]*$' | while read -r b; do
    [ -x "$b" ] && [ -f "$(readlink -f "$b")" ] && readlink -f "$b"
  done | sort -u
}

dk_available() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }
dk_inspect() { docker inspect -f "$1" "$2" 2>/dev/null; }
dk_label() { docker inspect -f "{{index .Config.Labels \"$1\"}}" "$2" 2>/dev/null; }

check_docker() {
  dk_available || return 0
  DK_OK=1
  local c v img
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    DK_ALL+=("$c")
    img=$(dk_inspect '{{.Config.Image}}' "$c")
    DK_IMG[$c]="$img"
    DK_PROJ[$c]=$(dk_label com.docker.compose.project "$c")
    DK_SVC[$c]=$(dk_label com.docker.compose.service "$c")
    DK_DIR[$c]=$(dk_label com.docker.compose.project.working_dir "$c")
    DK_FILES[$c]=$(dk_label com.docker.compose.project.config_files "$c")
    v=$(docker exec "$c" sh -c 'php -r "echo PHP_VERSION;" 2>/dev/null || php-fpm -v 2>/dev/null | head -n1' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    if [ -n "$v" ]; then
      DK_PHPV[$c]="$v"
      assess "Container $c ($img)" "$v" "/container"
      if [ "$LAST_STATE" = "VULN" ] || [ "$LAST_STATE" = "EOL" ]; then DK_VULN+=("$c"); fi
    fi
  done
}

check_versions() {
  hdr "1) PHP-Versionen & Notfall-Updates (grün = sicher, rot = unsicher)"
  local found=0 b v lib fp
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    v=$("$b" -v 2>/dev/null | head -n1 | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d' ' -f2)
    [ -n "$v" ] || continue
    found=1; assess "$b" "$v" "$b"
  done < <(find_php_binaries)

  fp=$(command -v frankenphp || true)
  if [ -n "$fp" ]; then
    v=$("$fp" version 2>/dev/null | head -n1 | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d' ' -f2)
    found=1
    if [ -n "$v" ]; then assess "FrankenPHP ($fp)" "$v" "$fp"
    else MSGS+=("warn|FrankenPHP gefunden ($fp), eingebettete PHP-Version nicht lesbar - bitte manuell prüfen"); fi
  fi

  while IFS= read -r lib; do
    [ -n "$lib" ] || continue
    found=1
    MSGS+=("warn|mod_php gefunden ($lib): laut BSI & PHP Security Team das HÖCHSTE Risiko (unauthentifizierter RCE-Exploit vor jeglichem Anwendungscode demonstriert!)")
    v=$(get_pkg_version "$lib")
    if [ -n "$v" ]; then assess "mod_php ($lib)" "$v" "$lib"
    else MSGS+=("warn|mod_php-Version nicht ermittelbar - bitte manuell prüfen"); fi
  done < <(find /usr/lib/apache2/modules /usr/lib64/httpd/modules /usr/lib/httpd/modules \
                /usr/local/apache2/modules -maxdepth 1 -name 'libphp*.so' 2>/dev/null | sort -u)

  check_docker
  if [ "$found" -eq 0 ] && [ "${#R_LABEL[@]}" -eq 0 ]; then
    info "Keine PHP-Binaries gefunden (nur Container? Webhosting ohne Shell?)"
  fi
  print_table
}

# --------------------------------------------------------- Update-Empfehlungen

repo_candidate() {
  command -v apt-cache >/dev/null 2>&1 || return 0
  local cand up
  cand=$(apt-cache policy "php$1-cli" 2>/dev/null | awk '/Candidate:/{print $2}')
  [ -n "$cand" ] && [ "$cand" != "(none)" ] || { info "Repo: php$1-cli nicht im Repo (Sury/Ondrej nötig?)"; return 0; }
  if [[ "$cand" =~ ^([0-9]+:)?([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    up="${BASH_REMATCH[2]}"
    if [ -n "${FIXED[$1]:-}" ] && ver_ge "$up" "${FIXED[$1]}"; then
      info "Repo-Kandidat für $1: $cand -> enthält das Notfall-Update (${FIXED[$1]})"
    elif [[ "$cand" =~ 2026(102[1-9]|103[01]|1[12][0-9]{2}) ]]; then
      info "Repo-Kandidat für $1: $cand -> enthält den Distro/Sury-Backport (>= 21.10.2026)"
    else
      info "Repo-Kandidat für $1: $cand -> evtl. Distro-Backport (prüfen: apt changelog php$1-cli | grep -E 'CVE-2026-10961[89]')"
    fi
  fi
}

uniq_branches() {
  [ "${#NEED_UPDATE[@]}" -gt 0 ] || return 0
  printf '%s\n' "${NEED_UPDATE[@]}" | sort -u
}

suggest_install() {
  [ "${#NEED_UPDATE[@]}" -gt 0 ] || return 0
  hdr "Update-Ziele (Notfall-Updates vom 21.10.2026)"
  local id like branch tgt
  id=$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")
  like=$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")
  for branch in $(uniq_branches); do
    if [ -n "${FIXED[$branch]:-}" ]; then tgt="$branch"; else tgt="$RECOMMENDED_BRANCH"; fi
    printf '%sPHP %s -> Ziel: %s (mind. %s)%s\n' "$B" "$branch" "$tgt" "${FIXED[$tgt]}" "$N"
    if [[ "$id $like" == *debian* || "$id $like" == *ubuntu* ]]; then
      repo_candidate "$branch"
      [ "$tgt" != "$branch" ] && repo_candidate "$tgt"
    fi
  done
  info "Konkrete Schritte bietet das interaktive TUI-Menü am Ende (mit Dry-Run, Backup und Rückabwicklung)."
}

# ----------------------------------------------------- Laufzeit, BSI-Checks & Mitigationen

check_runtime() {
  hdr "2) Laufende Prozesse, Systemhärtung & BSI-Mitigationen"
  local pid exe php up ml pms umf feb expose rlim
  for pid in $(pgrep -f 'php-fpm: master|apache2 -k|httpd|frankenphp|lshttpd|lsphp' 2>/dev/null); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    if [[ "$exe" == *"(deleted)"* ]] || grep -qE 'libphp.*\(deleted\)' "/proc/$pid/maps" 2>/dev/null; then
      warn "PID $pid ($(ps -o comm= -p "$pid" 2>/dev/null)) läuft noch mit ersetztem Binary/Modul -> Dienst zwingend neu starten!"
      STALE=1
    fi
    if [ -r "/proc/$pid/limits" ]; then
      rlim=$( awk '/Max address space|Max data size/ && $4 != "unlimited" {print $1" "$2" "$3"="$4}' "/proc/$pid/limits" 2>/dev/null | tr '\n' ' ')
      if [ -n "$rlim" ]; then
        warn "PID $pid hat endliches RLIMIT_AS/RLIMIT_DATA ($rlim): Laut BSI/PHP-Advisory NICHT verwenden, da dies den verwundbaren Speicherfehler (CVE-2026-109618) erst auslösen kann! Stattdessen cgroup-Limits nutzen."
      fi
    fi
  done
  [ "$STALE" -eq 0 ] && ok "Keine Prozesse mit veraltetem PHP-Binary im Speicher gefunden"

  php=$(command -v php || true)
  if [ -n "$php" ]; then
    local php_branch de_err strict_mode
    php_branch=$("$php" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)
    up=$("$php" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
    ml=$("$php" -r 'echo ini_get("memory_limit");' 2>/dev/null)
    pms=$("$php" -r 'echo ini_get("post_max_size");' 2>/dev/null)
    umf=$("$php" -r 'echo ini_get("upload_max_filesize");' 2>/dev/null)
    feb=$("$php" -r 'echo ini_get("fatal_error_backtraces");' 2>/dev/null)
    expose=$("$php" -r 'echo ini_get("expose_php");' 2>/dev/null)
    de_err=$("$php" -r 'echo ini_get("display_errors");' 2>/dev/null)
    strict_mode=$("$php" -r 'echo ini_get("session.use_strict_mode");' 2>/dev/null)
    info "CLI-Konfig: upload_progress=${up:-0}, memory_limit=${ml:-?}, post_max_size=${pms:-?}, upload_max_filesize=${umf:-?}, fatal_error_backtraces=${feb:-n/a}, expose_php=${expose:-0}, display_errors=${de_err:-0}, use_strict_mode=${strict_mode:-0} (FPM/Apache können abweichen!)"
    if [ "${up:-0}" = "1" ]; then
      warn "session.upload_progress.enabled=1 ist aktiv: Ermöglicht das Manipulieren von Session-Daten ohne Upload-Skript und dient als primärer Angriffsvektor für CVE-2026-109619 (BSI/CERT-EU-Empfehlung: auf 0 setzen)."
    fi
    if [ "${ml:-}" = "-1" ]; then
      warn "memory_limit=-1 aktiv: Dies ist ein temporärer Notfall-Workaround (DoS-Risiko!), der nach dem Patch zwingend wieder auf ein reguläres Limit (z. B. 256M) zurückgesetzt werden muss."
    fi
    if [ "$php_branch" = "8.5" ] && [ "${feb:-0}" = "1" ]; then
      warn "PHP 8.5 mit fatal_error_backtraces=1 aktiv: Begünstigt CVE-2026-109619 bei Speicherfehlern (BSI/PHP-Advisory: fatal_error_backtraces=0 setzen)."
    fi
    if [ "${expose:-0}" = "1" ]; then
      warn "expose_php=1 aktiv: Server verrät seine PHP-Version im HTTP-Header 'X-Powered-By' an Angreifer/Scanner (Corelight-Hinweis)."
    fi
    case "${de_err,,}" in
      1|on|true)
        warn "WARNUNG: display_errors ist aktiv! Ermöglicht Angreifern Adress-Leaks und ASLR-Bypasses."
        ;;
    esac
    case "${strict_mode,,}" in
      ""|0|off)
        warn "WARNUNG: session.use_strict_mode=0 (inaktiv)! Erleichtert Session-Fixation und Einschleusen bösartiger Session-IDs."
        ;;
    esac
  fi

  local mem_unlim_files
  mem_unlim_files=$(grep -rlE '^[[:space:]]*(php_admin_value\[memory_limit\]|memory_limit)[[:space:]]*=[[:space:]]*-1\b' \
    /etc/php/*/fpm /etc/php/*/apache2 /etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d 2>/dev/null | tr '\n' ' ' || true)
  if [ -n "$mem_unlim_files" ] && [ "${ml:-}" != "-1" ]; then
    warn "memory_limit=-1 in FPM/Webserver-Konfiguration gefunden ($mem_unlim_files): Dies ist ein temporärer Notfall-Workaround, der nach dem Patch wieder auf ein reguläres Limit (z. B. 256M) zurückgesetzt werden muss."
  fi

  local b start_warn b_branch b_feb
  for b in $(find_php_binaries); do
    if [ "$b" != "${php:-}" ]; then
      b_branch=$("$b" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)
      if [ "$b_branch" = "8.5" ]; then
        b_feb=$("$b" -r 'echo ini_get("fatal_error_backtraces");' 2>/dev/null || true)
        if [ "${b_feb:-0}" = "1" ]; then
          warn "$b (PHP 8.5) hat fatal_error_backtraces=1 aktiv: Begünstigt CVE-2026-109619 (auf 0 setzen)."
        fi
      fi
    fi
    start_warn=$("$b" -v 2>&1 | grep -Ei 'PHP (Warning|Deprecated|Fatal error|Notice):|Unknown:' || true)
    if [ -n "$start_warn" ]; then
      warn "$b erzeugt Diagnosemeldungen beim Start (laut BSI/PHP-Advisory gefährlich für CVE-2026-109619 - Einstellungen bereinigen!):"
      printf '%s\n' "$start_warn" | head -n 5 | indent
    fi
  done

  if command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null; then
    ok "MAC-Härtung (BSI-Empfehlung): AppArmor ist aktiv"
  elif command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    ok "MAC-Härtung (BSI-Empfehlung): SELinux ist im Modus 'Enforcing'"
  else
    info "BSI-Empfehlung (Update 1): Weder AppArmor noch SELinux (Enforcing) aktiv erkannt - zur Begrenzung von RCE-Auswirkungen empfohlen."
  fi

  if find /etc/php /etc/php.d /usr/local/etc/php /etc/php-fpm.d -name "$MARK_INI" 2>/dev/null | grep -q .; then
    info "Mitigation-Datei $MARK_INI ist aktiv (in TUI als [x] markiert; Abwählen startet Rückabwicklung)."
  fi
  info "BSI-Hinweis: Workarounds bieten KEINEN vollständigen Schutz. Nur Patchen oder vorübergehende Trennung vom Internet schützt vollständig."
}

# ------------------------------------------------- Kompromittierungs-Scan

detect_webroots() {
  [ "${#WEBROOTS[@]}" -gt 0 ] && return 0
  local all=() r o skip d
  mapfile -t all < <(
    {
      for d in /var/www /srv/www /srv/http /usr/share/nginx/html /var/www/vhosts \
               /home/*/public_html /home/*/www /home/*/htdocs; do
        [ -d "$d" ] && echo "$d"
      done
      grep -rhoE '^[[:space:]]*(root|DocumentRoot)[[:space:]]+"?[^ ;"]+' \
        /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | awk '{print $2}' | tr -d '";'
    } | awk 'NF && $0 != "/" && $0 !~ /\$/' | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done
  )
  for r in ${all[@]+"${all[@]}"}; do
    skip=0
    for o in "${all[@]}"; do
      if [ "$r" != "$o" ] && [[ "$r" == "$o"/* ]]; then skip=1; fi
    done
    [ "$skip" -eq 0 ] && WEBROOTS+=("$r")
  done
}

add_found() {
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$1" = "files" ]; then FOUND_FILES+=("$f"); else FOUND_CONF+=("${f%%:*}"); fi
  done <<< "$2"
}

scan_files() {
  hdr "3) Dateisystem (Webroots: ${WEBROOTS[*]})"
  local out f n

  out=$(timeout 300 grep -rIlsE \
        --include='*.php' --include='*.phtml' --include='*.phar' --include='*.inc' --include='*.php[3-8]' \
        -e "$P_EVAL" -e "$P_SUPER" -e "$P_DYN" -e "$P_NAMES" -e "$P_PREG" \
        "${WEBROOTS[@]}" 2>/dev/null | head -n 200)
  if [ -n "$out" ]; then
    n=$(printf '%s\n' "$out" | wc -l)
    susp "$n PHP-Datei(en) mit typischen Webshell-/Obfuskations-Mustern:"
    add_found files "$out"
    printf '%s\n' "$out" | head -n 30 | while read -r f; do
      printf '%s\n' "$f" | indent
      grep -nE -m1 -e "$P_EVAL" -e "$P_SUPER" -e "$P_DYN" -e "$P_NAMES" -e "$P_PREG" "$f" 2>/dev/null \
        | cut -c1-140 | sed 's/^/            /'
    done
  else
    ok "Keine Dateien mit bekannten Webshell-Mustern"
  fi

  out=$(find "${WEBROOTS[@]}" -type f \
        \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[3-8]' \) \
        \( -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/cache/*' -o -path '*/tmp/*' \
           -o -path '*/temp/*' -o -path '*/images/*' -o -path '*/media/*' -o -path '*/files/*' \) \
        ! \( -name 'index.php' -size -100c \) -printf '%TY-%Tm-%Td %u %p\n' 2>/dev/null | head -n 50)
  if [ -n "$out" ]; then
    warn "PHP-Dateien in Upload-/Cache-/Temp-Verzeichnissen (selten legitim):"
    printf '%s\n' "$out" | indent
  else
    ok "Keine PHP-Dateien in Upload-/Cache-/Temp-Verzeichnissen"
  fi

  out=$(find "${WEBROOTS[@]}" -type f -name '.*.php' "${HIDDEN_EXCL[@]}" 2>/dev/null | head -n 30)
  if [ -n "$out" ]; then susp "Versteckte PHP-Dateien (.name.php):"; printf '%s\n' "$out" | indent; add_found files "$out"
  else ok "Keine versteckten PHP-Dateien"; fi

  out=$(timeout 300 grep -rlsa --include='*.jpg' --include='*.jpeg' --include='*.png' \
        --include='*.gif' --include='*.ico' -E '<\?php' "${WEBROOTS[@]}" 2>/dev/null | head -n 30)
  if [ -n "$out" ]; then susp "Bilddateien mit eingebettetem <?php:"; printf '%s\n' "$out" | indent; add_found files "$out"
  else ok "Keine Bilddateien mit eingebettetem PHP-Code"; fi

  out=$(find "${WEBROOTS[@]}" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.inc' \) \
        -newermt "$SINCE" -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort | tail -n 40)
  if [ -n "$out" ]; then
    info "PHP-Dateien geändert seit $SINCE (bitte gegen eigene Deployments/Updates abgleichen):"
    printf '%s\n' "$out" | indent
  else
    ok "Keine PHP-Dateien seit $SINCE geändert"
  fi

  out=$(find "${WEBROOTS[@]}" -type f \( -name '.user.ini' -o -name '.htaccess' \) -print0 2>/dev/null \
        | xargs -0 -r grep -HniE \
          'auto_(prepend|append)_file|(AddType|AddHandler|SetHandler)[[:space:]]+(application/x-httpd-php|php[0-9-]*-script)[[:space:]]+\.(jpe?g|png|gif|ico|txt|css|js)' \
          2>/dev/null | head -n 20)
  if [ -n "$out" ]; then
    susp ".user.ini/.htaccess mit Prepend/Append oder PHP-Handler auf Nicht-PHP-Endungen:"
    printf '%s\n' "$out" | indent; add_found conf "$out"
  else ok "Keine verdächtigen .user.ini/.htaccess-Direktiven"; fi

  out=$(grep -rEn '^[[:space:]]*auto_(prepend|append)_file[[:space:]]*=[[:space:]]*[^ ;]' \
        /etc/php* /usr/local/etc/php* /etc/php-fpm.d 2>/dev/null | head -n 10)
  if [ -n "$out" ]; then warn "auto_prepend/append_file in globaler PHP-Konfig gesetzt (legitim? prüfen):"; printf '%s\n' "$out" | indent
  else ok "Kein auto_prepend/append_file in globaler PHP-Konfig"; fi

  out=$(find /tmp /var/tmp /dev/shm -type f \( -name '*.php' -o -perm /111 \) -newermt "$SINCE" \
        -printf '%TY-%Tm-%Td %u %m %p\n' 2>/dev/null | head -n 30)
  if [ -n "$out" ]; then warn "Neue PHP-/ausführbare Dateien in /tmp, /var/tmp, /dev/shm:"; printf '%s\n' "$out" | indent
  else ok "Keine neuen PHP-/ausführbaren Dateien in Temp-Verzeichnissen"; fi

  if command -v wp >/dev/null 2>&1; then
    local wpc
    while IFS= read -r wpc; do
      f=$(dirname "$wpc")
      if timeout 120 wp core verify-checksums --path="$f" --allow-root >/dev/null 2>&1; then
        ok "WordPress-Core-Checksummen stimmen: $f"
      else
        warn "WordPress-Core-Checksummen weichen ab (oder Prüfung nicht möglich): $f"
        timeout 120 wp core verify-checksums --path="$f" --allow-root 2>&1 | head -n 10 | indent
      fi
    done < <(find "${WEBROOTS[@]}" -maxdepth 3 -name wp-config.php 2>/dev/null | head -n 20)
  fi
}

session_dirs() {
  local p="" php
  php=$(command -v php || true)
  if [ -n "$php" ]; then p=$("$php" -r 'echo ini_get("session.save_path");' 2>/dev/null); fi
  p="${p##*;}"
  { [ -n "$p" ] && echo "$p"; echo /var/lib/php/sessions; echo /var/lib/php/session; echo /var/lib/php5; } \
    | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done
}

scan_php_internals() {
  hdr "4) PHP-Interna (Sessions, Locks, Non-Printable Payloads, Extensions)"
  local d total recent out php extdir f owned lsof_locks bin_sess
  php=$(command -v php || true)

  for d in $(session_dirs); do
    total=$(find "$d" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | wc -l)
    recent=$(find "$d" -maxdepth 1 -type f -name 'sess_*' -newermt "$SINCE" 2>/dev/null | wc -l)
    info "Session-Pfad $d: $total Dateien, davon $recent seit $SINCE geändert"
    out=$(timeout 120 grep -rlsaE --include='sess_*' '<\?php|<\?=|upload_progress_' "$d" 2>/dev/null | head -n 20)
    if [ -n "$out" ]; then susp "Session-Dateien mit PHP-Code oder upload_progress_-Präfix (Armis/Sansec-IOC):"; printf '%s\n' "$out" | indent
    else ok "Keine Session-Dateien mit PHP-Code oder upload_progress_-Präfix in $d"; fi

    bin_sess=$(find "$d" -maxdepth 1 -type f -name 'sess_*' -size +0c 2>/dev/null | head -n 500 | xargs -r grep -lP '[\x00\x01-\x08\x0b\x0c\x0e-\x1f\x7f]' 2>/dev/null | head -n 20 || true)
    if [ -n "$bin_sess" ]; then
      warn "Session-Dateien mit binären Steuerzeichen/Null-Bytes in $d (Hinweis auf Heap-/Memory-Leak über PHPSESSID oder binäre Serialisierung):"
      printf '%s\n' "$bin_sess" | indent
    fi
  done

  if command -v lsof >/dev/null 2>&1; then
    lsof_locks=$(lsof +D /var/lib/php 2>/dev/null | grep -E 'sess_.*([0-9]+[rwu][WRL])' || true)
    if [ -n "$lsof_locks" ]; then
      warn "Aktive Datei-Locks (flock) auf Session-Dateien erkannt (laut Armis möglicher Hinweis auf hängende Exploit-Worker):"
      printf '%s\n' "$lsof_locks" | head -n 15 | indent
    fi
  fi

  if [ -n "$php" ]; then
    extdir=$("$php" -r 'echo ini_get("extension_dir");' 2>/dev/null)
    if [ -n "$extdir" ] && [ -d "$extdir" ]; then
      out=""
      while IFS= read -r f; do
        owned=1
        if command -v dpkg >/dev/null 2>&1; then dpkg -S "$f" >/dev/null 2>&1 && owned=0; fi
        if [ "$owned" -ne 0 ] && command -v rpm >/dev/null 2>&1; then rpm -qf "$f" >/dev/null 2>&1 && owned=0; fi
        [ "$owned" -ne 0 ] && out+="$f"$'\n'
      done < <(find "$extdir" -maxdepth 1 -type f -name '*.so' 2>/dev/null)
      if [ -n "$out" ]; then
        if find "$extdir" -maxdepth 1 -type f -name '*.so' -newermt "$SINCE" 2>/dev/null | grep -q .; then
          susp "PHP-Extension(s) ohne Paketzuordnung, Verzeichnis seit $SINCE verändert:"
        else
          info "PHP-Extensions ohne Paketzuordnung (bei PECL/Eigenbau normal, Herkunft prüfen):"
        fi
        printf '%s' "$out" | indent
      else
        ok "Alle PHP-Extensions gehören zu Paketen"
      fi
    fi
  fi
}

scan_persistence() {
  hdr "5) Persistenz & Prozesse"
  local out wu='www-data|apache|nginx|http|nobody|www|wwwrun'

  if [ -e /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    susp "/etc/ld.so.preload ist gesetzt:"; indent < /etc/ld.so.preload
  else ok "/etc/ld.so.preload leer/nicht vorhanden"; fi

  out=$(find /var/spool/cron -type f 2>/dev/null | grep -E "/($wu)\$")
  if [ -n "$out" ]; then susp "Crontab für Webserver-User vorhanden:"; printf '%s\n' "$out" | indent
  else ok "Keine Crontabs für Webserver-User"; fi

  out=$(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/systemd/system \
        -type f -newermt "$SINCE" 2>/dev/null | head -n 20)
  if [ -n "$out" ]; then warn "Cron-/systemd-Dateien seit $SINCE geändert:"; printf '%s\n' "$out" | indent
  else ok "Keine Cron-/systemd-Änderungen seit $SINCE"; fi

  if [ "$(find /etc/passwd /etc/shadow -newermt "$SINCE" 2>/dev/null | wc -l)" -gt 0 ]; then
    warn "/etc/passwd oder /etc/shadow seit $SINCE geändert (neue User? Passwortwechsel?)"
  else ok "Keine neuen User-Änderungen seit $SINCE"; fi

  out=$(find /root /home /var/www -maxdepth 3 -name 'authorized_keys*' -newermt "$SINCE" 2>/dev/null)
  if [ -n "$out" ]; then susp "authorized_keys seit $SINCE geändert:"; printf '%s\n' "$out" | indent
  else ok "Keine authorized_keys-Änderungen seit $SINCE"; fi

  out=$(ps -eo user:20,pid,ppid,etime,args --no-headers 2>/dev/null \
        | awk -v re="^($wu)\$" '$1 ~ re' \
        | grep -E ' sh -c |/bin/(ba|da)?sh|\bnc\b|ncat|socat|curl |wget |python|perl |xmrig|minerd|kdevtmpfsi|kinsing|whoami|uname -a|/dev/tcp|mkfifo' \
        | cut -c1-200)
  if [ -n "$out" ]; then susp "Prozesse des Webserver-Users, die nach Shell/Downloader/Miner/Aufklärung aussehen:"; printf '%s\n' "$out" | indent
  else ok "Keine auffälligen Prozesse unter Webserver-Usern"; fi

  if command -v ss >/dev/null 2>&1; then
    out=$(ss -tnp state established 2>/dev/null \
          | grep -E 'users:\(\("(sh|bash|dash|nc|ncat|socat|curl|wget|python[0-9.]*|perl)"' | head -n 10)
    if [ -n "$out" ]; then warn "Ausgehende Verbindungen von Shells/Downloadern (Reverse-Shell?):"; printf '%s\n' "$out" | indent
    else ok "Keine Shell-/Downloader-Verbindungen aktiv"; fi
  fi
}

scan_logs() {
  hdr "6) Logs (Tagesaktuelle IOCs: Armis, Abstract Security, Datadog, Sansec)"
  local pat='SIGSEGV|signal 11|signal 6|Segmentation fault|segfault|Out of memory|Allowed memory size|Maximum execution time|zend_mm_heap corrupted|munmap_chunk\(\): invalid pointer|free\(\): invalid pointer'
  local logs=() acc=() f n out

  mapfile -t logs < <(find /var/log -maxdepth 3 -type f \
      \( -name '*fpm*.log*' -o -name 'error*log*' -o -name 'php*error*log*' \) \
      -newermt "$SINCE" 2>/dev/null)
  for f in ${logs[@]+"${logs[@]}"}; do
    n=$(zgrep -Eic "$pat" "$f" 2>/dev/null || true); n=${n:-0}
    if [ "$n" -gt 0 ] 2>/dev/null; then
      warn "$f: $n Treffer für Segfault/OOM/Timeout/Heap-Corruption (Zeitstempel ab $SINCE prüfen - Exploit-Versuche crashen/korrumpieren Worker)"
      zgrep -Ei "$pat" "$f" 2>/dev/null | tail -n 3 | cut -c1-200 | indent
    fi
    n=$(zgrep -Eic 'tried to allocate.*in Unknown on line 0|session_start\(\).*illegal|session_id\(\).*illegal|PHP Startup:.*in Unknown on line 0' "$f" 2>/dev/null || true); n=${n:-0}
    if [ "$n" -gt 0 ] 2>/dev/null; then
      warn "$f: $n x 'in Unknown on line 0' (OOM/Startup vor App-Code) oder illegale Session-IDs -> hohe Wahrscheinlichkeit für PHP2Shell-Angriffsversuch!"
      ATT=$((ATT+1))
    fi
    n=$(zgrep -c 'AH00052' "$f" 2>/dev/null || true); n=${n:-0}
    if [ "$n" -gt 0 ] 2>/dev/null; then
      warn "$f: $n x AH00052 (Apache-Child durch Signal beendet - laut Abstract Security typisch für die ASLR-Brute-Force-Phase)"
      ATT=$((ATT+1))
    fi
  done

  if command -v journalctl >/dev/null 2>&1; then
    n=$(journalctl -k --since "$SINCE" --no-pager -q 2>/dev/null | grep -Eic '(php|apache2|httpd).*segfault' || true)
    n=${n:-0}
    if [ "$n" -gt 0 ] 2>/dev/null; then
      warn "Kernel-Log: $n Segfault-Meldungen von PHP/Apache seit $SINCE:"
      journalctl -k --since "$SINCE" --no-pager -q 2>/dev/null | grep -Ei '(php|apache2|httpd).*segfault' | tail -n 3 | cut -c1-200 | indent
      ATT=$((ATT+1))
    else
      ok "Kernel-Log: keine PHP/Apache-Segfaults seit $SINCE"
    fi
  fi

  mapfile -t acc < <(find /var/log /var/www/vhosts/*/logs -maxdepth 4 -type f -name '*access*log*' \
      ! -name '*.xz' ! -name '*.bz2' ! -name '*.zst' 2>/dev/null)
  if [ "${#acc[@]}" -gt 0 ]; then
    out=$(zcat -f "${acc[@]}" 2>/dev/null \
          | awk '$6=="\"POST" && $9 ~ /^5[0-9][0-9]$/ {c[$1]++} END{for(i in c) if(c[i]>=10) printf "%6d  %s\n", c[i], i}' \
          | sort -rn | head -n 10)
    if [ -n "$out" ]; then warn "IPs mit >=10 POST-Requests mit 5xx-Antwort (OOM-Trigger / Exploit-Versuche):"; printf '%s\n' "$out" | indent; ATT=$((ATT+1))
    else ok "Keine IPs mit gehäuften POST->5xx"; fi

    out=$(zcat -f "${acc[@]}" 2>/dev/null \
          | awk '$6=="\"POST" {c[$1]++} END{for(i in c) if(c[i]>=150) printf "%6d  %s\n", c[i], i}' \
          | sort -rn | head -n 10)
    if [ -n "$out" ]; then warn "IPs mit >=150 POST-Requests insgesamt (Abstract Security IOC: ASLR-Brute-Force sendet ~590 große POSTs pro IP - bitte prüfen):"; printf '%s\n' "$out" | indent; fi

    out=$(zcat -f "${acc[@]}" 2>/dev/null \
          | grep -E '"(GET|POST) [^" ?]*/(uploads|upload|cache|tmp|images|media|files)/[^" ?]+\.(php|phtml|phar)[ ?"]' \
          | grep -E '" (200|206|500) ' | head -n 20 | cut -c1-200)
    if [ -n "$out" ]; then susp "Erfolgreiche Aufrufe von PHP-Dateien in Upload-/Cache-Pfaden:"; printf '%s\n' "$out" | indent
    else ok "Keine erfolgreichen PHP-Aufrufe in Upload-/Cache-Pfaden"; fi
  else
    info "Keine Access-Logs gefunden"
  fi
}

# ======================================================= Docker-Container prüfen

NET_STATE=""

net_check() {
  [ "$NET_STATE" = "ok" ] && return 0
  local h pinged="" code
  for h in 1.1.1.1 8.8.8.8; do
    if command -v ping >/dev/null 2>&1 && ping -c1 -W2 "$h" >/dev/null 2>&1; then pinged="$h"; break; fi
  done
  if [ -n "$pinged" ]; then info "Netzwerk: Ping zu $pinged erfolgreich."
  else info "Netzwerk: Ping zu 1.1.1.1/8.8.8.8 nicht beantwortet (ICMP evtl. gesperrt) - prüfe HTTPS ..."; fi
  code=000
  if command -v curl >/dev/null 2>&1; then code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://hub.docker.com 2>/dev/null); fi
  if [ -n "$code" ] && [ "$code" != "000" ]; then ok "Netzwerk: hub.docker.com per HTTPS erreichbar (HTTP $code)."; NET_STATE=ok; return 0; fi
  warn "Kein Zugriff auf hub.docker.com (DNS/Firewall/Proxy/curl fehlt?) - Online-Recherche und Image-Download sind nicht möglich."
  NET_STATE=offline
  return 1
}

dk_hint_compose() {
  local img="${DK_IMG[$1]%%:*}" f
  for f in $(find /home /opt /srv /root /var/www -maxdepth 4 \( -name 'docker-compose.y*ml' -o -name 'compose.y*ml' \) 2>/dev/null | head -n 50); do
    if grep -q "$img" "$f" 2>/dev/null; then echo "$f"; return 0; fi
  done
  return 1
}

dk_parse_ref() {
  local r="${1%%@*}" first
  P_TAG="latest"
  case "${r##*/}" in *:*) P_TAG="${r##*:}"; r="${r%:*}" ;; esac
  first="${r%%/*}"
  if [[ "$r" == */* ]] && { [[ "$first" == *.* ]] || [[ "$first" == *:* ]] || [ "$first" = "localhost" ]; }; then
    P_REG="$first"; r="${r#*/}"
  else
    P_REG="docker.io"
  fi
  if [[ "$r" == */* ]]; then P_NS="${r%%/*}"; P_REPO="${r#*/}"; else P_NS="library"; P_REPO="$r"; fi
}

jget() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get(sys.argv[1],"") or "")
except Exception: pass' "$2"
  elif command -v jq >/dev/null 2>&1; then
    printf '%s' "$1" | jq -r --arg k "$2" '.[$k] // empty'
  fi
}

hub_newtags() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); cur=sys.argv[1]; out=[]
    for t in d.get("results",[]):
        n=t.get("name",""); lu=(t.get("last_updated") or "")[:19]
        if n and n!=cur and lu>"2026-10-21T14:00:00": out.append(n)
    print(" ".join(out[:8]))
except Exception: pass' "$2"
  elif command -v jq >/dev/null 2>&1; then
    printf '%s' "$1" | jq -r --arg c "$2" '[.results[]? | select(.name != $c and ((.last_updated // "")[0:19] > "2026-10-21T14:00:00")) | .name] | .[0:8] | join(" ")'
  fi
}

hub_cands() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c 'import sys,json,re
try:
    d=json.load(sys.stdin); cur=sys.argv[1]
    key=lambda s:[int(x) for x in re.findall(r"\d+",s)]
    ver=re.compile(r"^\d+(\.\d+){1,3}$")
    ck=key(cur) if ver.match(cur) else None
    after=[]; newer=[]
    for t in d.get("results",[]):
        n=t.get("name",""); lu=(t.get("last_updated") or "")[:19]
        if not n or n==cur: continue
        if lu>"2026-10-21T14:00:00": after.append(n)
        if ck is not None and ver.match(n) and key(n)>ck: newer.append(n)
    newer.sort(key=key,reverse=True)
    out=[]
    for n in newer+after:
        if n not in out: out.append(n)
    print(" ".join(out[:10]))
except Exception: pass' "$2"
  else
    hub_newtags "$1" "$2"
  fi
}

DK_FIXRE='CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp|php2shell|PHP 8\.5\.12|PHP 8\.4\.27|PHP 8\.3\.36|PHP 8\.2\.35|8\.5\.12|8\.4\.27|8\.3\.36|8\.2\.35'

dk_registry_info() {
  local c="$1" ref="${DK_IMG[$1]}" rj tj desc lu dig ldig hits src gh rel
  DKR_HINT=0; DKR_NEWER=0
  dk_parse_ref "$ref"
  command -v curl >/dev/null 2>&1 || { info "curl fehlt - Registry-Abfrage übersprungen."; return 0; }
  case "$P_REG" in
    docker.io|index.docker.io|registry-1.docker.io) ;;
    *) info "Registry $P_REG: automatische Abfrage nur für Docker Hub - Image-Hinweise bitte manuell prüfen."; return 0 ;;
  esac
  rj=$(curl -fsS --max-time 15 "https://hub.docker.com/v2/repositories/$P_NS/$P_REPO/" 2>/dev/null)
  tj=$(curl -fsS --max-time 15 "https://hub.docker.com/v2/repositories/$P_NS/$P_REPO/tags/$P_TAG" 2>/dev/null)
  if [ -z "$rj" ] && [ -z "$tj" ]; then info "Docker Hub nicht erreichbar oder Image nicht öffentlich ($P_NS/$P_REPO)."; return 0; fi
  lu=$(jget "$tj" last_updated); dig=$(jget "$tj" digest)
  ldig=$(docker image inspect -f '{{join .RepoDigests " "}}' "$ref" 2>/dev/null)
  if [ -n "$lu" ]; then
    if [[ "${lu:0:19}" > "2026-10-21T14:00:00" ]]; then
      ok "Tag '$P_TAG' wurde NACH dem PHP-Release (21.10. 14:00 UTC) aktualisiert: $lu"; DKR_HINT=1
    else
      warn "Tag '$P_TAG' zuletzt aktualisiert: $lu - VOR dem PHP-Release, enthält vermutlich noch altes PHP."
    fi
  fi
  if [ -n "$dig" ]; then
    case "$ldig" in
      *"$dig"*) info "Remote-Digest entspricht dem lokalen Image: unter diesem Tag liegt KEIN neueres Image." ;;
      *) ok "Remote-Digest weicht vom lokalen Image ab: unter diesem Tag liegt ein NEUERES Image."; DKR_NEWER=1 ;;
    esac
  fi
  desc=$(jget "$rj" full_description)
  hits=$(printf '%s\n' "$desc" | grep -oiE ".{0,60}($DK_FIXRE).{0,60}" | head -n 3)
  if [ -n "$hits" ]; then ok "README auf Docker Hub erwähnt Fix-relevantes:"; printf '%s\n' "$hits" | indent; DKR_HINT=1
  else info "README auf Docker Hub: kein Hinweis auf CVE-2026-109618/PHP2Shell oder eine gepatchte PHP-Version."; fi
  src=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.source"}}' "$ref" 2>/dev/null)
  if [[ "$src" =~ github\.com[/:]([^/]+)/([^/.]+) ]]; then
    gh="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    rel=$(curl -fsS --max-time 15 "https://api.github.com/repos/$gh/releases?per_page=5" 2>/dev/null)
    hits=$(printf '%s\n' "$rel" | grep -oiE ".{0,60}($DK_FIXRE).{0,60}" | head -n 3)
    if [ -n "$hits" ]; then ok "GitHub-Releases von $gh erwähnen Fix-relevantes:"; printf '%s\n' "$hits" | indent; DKR_HINT=1
    else info "GitHub-Releases von $gh: kein Hinweis auf den Fix in den letzten 5 Releases."; fi
  fi
  if [[ "$P_TAG" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; then
    info "Gepinnter Versions-Tag '$P_TAG' erkannt: ein solcher Tag wird normalerweise nicht neu gebaut - der Fix kommt als neuer Tag oder über 'latest'."
  fi
  DKR_NEWTAGS=$(hub_cands "$(curl -fsS --max-time 15 "https://hub.docker.com/v2/repositories/$P_NS/$P_REPO/tags/?page_size=100" 2>/dev/null)" "$P_TAG")
  case " $DKR_NEWTAGS " in *" latest "*) ;; *) [ "$P_TAG" = "latest" ] || DKR_NEWTAGS="${DKR_NEWTAGS:+$DKR_NEWTAGS }latest" ;; esac
  if [ -n "$DKR_NEWTAGS" ]; then ok "Update-Kandidaten (neuere Tags/Versionen, 'latest'): $DKR_NEWTAGS"
  else info "Keine Update-Kandidaten gefunden (keine neueren Tags nach dem PHP-Release)."; fi
  info "Hinweis: README/Release-Texte sind nur Indizien. Maßgeblich ist die PHP-Version IM neuen Image (wird beim Update-Schritt geprüft)."
}

dk_scan_container() {
  local c="$1" since="${SINCE}T00:00:00" root out
  root=$(docker exec "$c" sh -c 'for d in /var/www/app /var/www/html /app /var/www /srv/www /usr/share/nginx/html; do [ -d "$d" ] && { echo "$d"; break; }; done' 2>/dev/null)
  printf '\n%s[Container %s]%s PHP %s, Webroot im Container: %s\n' "$B" "$c" "$N" "${DK_PHPV[$c]}" "${root:-nicht gefunden}"
  if [ -n "$root" ] && docker exec "$c" sh -c 'command -v grep >/dev/null && command -v find >/dev/null' >/dev/null 2>&1; then
    out=$(timeout 300 docker exec "$c" grep -rIlsE --exclude-dir=node_modules --include='*.php' --include='*.phtml' --include='*.phar' --include='*.inc' \
          -e "$P_EVAL" -e "$P_SUPER" -e "$P_DYN" -e "$P_NAMES" -e "$P_PREG" "$root" 2>/dev/null | head -n 100)
    if [ -n "$out" ]; then susp "Container $c: PHP-Dateien mit Webshell-/Obfuskations-Mustern:"; printf '%s\n' "$out" | head -n 20 | indent
    else ok "Container $c: keine Dateien mit bekannten Webshell-Mustern"; fi
    out=$(docker exec "$c" find "$root" -type f -name '.*.php' "${HIDDEN_EXCL[@]}" 2>/dev/null | head -n 20)
    if [ -n "$out" ]; then susp "Container $c: versteckte PHP-Dateien:"; printf '%s\n' "$out" | indent
    else ok "Container $c: keine versteckten PHP-Dateien"; fi
    out=$(docker exec "$c" find "$root" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) \
          \( -path '*/uploads/*' -o -path '*/storage/app/*' -o -path '*/public/storage/*' -o -path '*/media/*' \) 2>/dev/null | head -n 20)
    if [ -n "$out" ]; then warn "Container $c: PHP-Dateien in Upload-/Storage-Pfaden (selten legitim):"; printf '%s\n' "$out" | indent
    else ok "Container $c: keine PHP-Dateien in Upload-/Storage-Pfaden"; fi
    out=$(timeout 300 docker exec "$c" grep -rlsa --include='*.jpg' --include='*.jpeg' --include='*.png' --include='*.gif' --include='*.ico' -E '<\?php' "$root" 2>/dev/null | head -n 20)
    if [ -n "$out" ]; then susp "Container $c: Bilddateien mit eingebettetem <?php:"; printf '%s\n' "$out" | indent
    else ok "Container $c: keine Bilddateien mit eingebettetem PHP-Code"; fi
  else
    info "Container $c: Dateiscan nicht möglich (kein Webroot gefunden oder grep/find fehlen im Container)."
  fi
  out=$(docker diff "$c" 2>/dev/null | grep -E '^[AC] .*\.(php|phtml|phar)$' \
        | grep -vE '/storage/framework/(views|cache)/|/bootstrap/cache/|/storage/logs/' | cut -c1-200 | head -n 30)
  if [ -n "$out" ]; then warn "Container $c: seit Containerstart neue/geänderte PHP-Dateien (Container weicht vom Image ab):"; printf '%s\n' "$out" | indent
  else ok "Container $c: keine neuen/geänderten PHP-Dateien gegenüber dem Image (ohne Laravel-Caches)"; fi
  out=$(docker top "$c" -eo pid,ppid,user,args 2>/dev/null | grep -E '\b(nc|ncat|socat|xmrig|minerd|kinsing|kdevtmpfsi)\b|/dev/tcp|mkfifo|whoami|uname -a' | cut -c1-200)
  if [ -n "$out" ]; then susp "Container $c: verdächtige Prozesse:"; printf '%s\n' "$out" | indent
  else ok "Container $c: keine auffälligen Prozesse"; fi
  out=$(docker logs --since "$since" "$c" 2>&1 | grep -Ei 'tried to allocate.*in Unknown on line 0|session_start\(\).*illegal|session_id\(\).*illegal' | tail -n 3 | cut -c1-200)
  if [ -n "$out" ]; then warn "Container $c: Log-Signatur des Exploits ('in Unknown on line 0' / illegale Session-ID) - Angriffsversuch wahrscheinlich:"; printf '%s\n' "$out" | indent; ATT=$((ATT+1))
  else ok "Container $c: keine Exploit-Signatur ('in Unknown on line 0') in den Logs"; fi
  out=$(docker logs --since "$since" "$c" 2>&1 | grep -Eic 'segfault|signal 11|exited on signal|Allowed memory size|Maximum execution time|zend_mm_heap corrupted')
  if [ "${out:-0}" -gt 0 ] 2>/dev/null; then warn "Container $c: $out Log-Zeilen mit Segfault/Signal/Memory-Limit/Timeout seit $SINCE (Zeitstempel prüfen)"; ATT=$((ATT+1)); fi
}

dk_scan_weblog() {
  local c="$1" out
  out=$(docker logs --since "${SINCE}T00:00:00" "$c" 2>&1 \
        | awk '$6=="\"POST" && $9 ~ /^5[0-9][0-9]$/ {n[$1]++} END{for(i in n) if(n[i]>=10) printf "%6d  %s\n", n[i], i}' | sort -rn | head -n 10)
  if [ -n "$out" ]; then warn "Container $c: IPs mit >=10 POST-Requests mit 5xx-Antwort:"; printf '%s\n' "$out" | indent; ATT=$((ATT+1))
  else ok "Container $c: keine IPs mit gehäuften POST->5xx"; fi
}

scan_docker() {
  [ "$DK_OK" -eq 1 ] || return 0
  hdr "7) Docker-Container (Image, Compose, Prüfung im Container)"
  [ "${#DK_ALL[@]}" -gt 0 ] || { info "Keine laufenden Container."; return 0; }
  local c comp f
  printf '%s%-24s %-40s %-26s %s%s\n' "$B" "CONTAINER" "IMAGE" "COMPOSE (Projekt/Dienst)" "PHP" "$N"
  for c in "${DK_ALL[@]}"; do
    comp="-"; [ -n "${DK_PROJ[$c]:-}" ] && comp="${DK_PROJ[$c]}/${DK_SVC[$c]:-?}"
    printf '%-24s %-40s %-26s %s\n' "$c" "${DK_IMG[$c]:0:40}" "$comp" "${DK_PHPV[$c]:--}"
  done
  for c in "${DK_ALL[@]}"; do
    if [ -z "${DK_PROJ[$c]:-}" ]; then
      f=$(dk_hint_compose "$c") && info "Container $c hat keine Compose-Labels; mögliche Compose-Datei: $f (automatisches Update nur bei Compose-Labels)."
    fi
  done
  for c in "${DK_ALL[@]}"; do
    [ -n "${DK_PHPV[$c]:-}" ] && dk_scan_container "$c"
    case "${DK_IMG[$c]}" in *nginx*|*httpd*|*apache*|*caddy*|*traefik*) dk_scan_weblog "$c" ;; esac
  done
  if [ "${#DK_VULN[@]}" -gt 0 ]; then
    printf '\n%s[Netzwerk-Check für die Online-Recherche]%s\n' "$B" "$N"
    if net_check; then
      for c in "${DK_VULN[@]}"; do
        printf '\n%s[Image-Recherche für %s: %s]%s\n' "$B" "$c" "${DK_IMG[$c]}" "$N"
        dk_registry_info "$c"
        DK_REGHINT[$c]=$DKR_HINT; DK_REGNEWER[$c]=$DKR_NEWER; DK_NEWTAGS[$c]=$DKR_NEWTAGS
      done
    else
      info "Online-Recherche übersprungen (kein Netz) - bitte später erneut ausführen."
    fi
  fi
}

# ======================================================== Interaktive Maßnahmen & Einzel-Rückabwicklung

confirm() {
  local a
  tty_read -r -p "$1 [j/N] " a || return 1
  case "$a" in j|J|ja|Ja|JA|y|Y) return 0 ;; *) return 1 ;; esac
}

confirm_word() {
  local a
  tty_read -r -p "$1 (zur Bestätigung exakt '$2' tippen) " a || return 1
  [ "$a" = "$2" ]
}

explain() {
  local c="$G"
  case "$2" in mittel*) c="$Y" ;; hoch*|HOCH*) c="$R" ;; esac
  printf '\n%s%s%s\n' "$B" "$1" "$N"
  printf '  Eingriffstiefe: %s%s%s\n' "$c" "$2" "$N"
  printf '  Was passiert:   %s\n' "$3"
  printf '  Folgen:         %s\n' "$4"
  printf '  Rückgängig:     %s\n' "$5"
}

web_users() {
  local u
  for u in www-data apache nginx www wwwrun http nobody; do id -u "$u" >/dev/null 2>&1 && echo "$u"; done
}

confd_dirs() {
  local d
  for d in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cgi/conf.d /etc/php.d \
           /usr/local/etc/php/conf.d /opt/remi/php*/root/etc/php.d /etc/opt/remi/php*/php.d; do
    [ -d "$d" ] && echo "$d"
  done
}

pool_files() {
  local f
  for f in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf; do
    [ -f "$f" ] && echo "$f"
  done
}

ensure_backup() {
  [ -n "$BACKUP_DIR" ] && return 0
  ensure_state_dir
  local ts p paths=() rc
  ts=$(date +%Y%m%d-%H%M%S)
  BACKUP_DIR="/root/php2shell-backup-$ts"
  mkdir -p "$BACKUP_DIR" || { crit "Backup-Verzeichnis nicht anlegbar"; BACKUP_DIR=""; return 1; }
  chmod 700 "$BACKUP_DIR"
  for p in /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.conf /etc/php-fpm.d /usr/local/etc/php \
           /usr/local/etc/php-fpm.d /etc/opt/remi /etc/nginx /etc/apache2 /etc/httpd \
           /etc/audit/rules.d /usr/local/lsws/conf /etc/frankenphp /etc/caddy /etc/apt; do
    [ -e "$p" ] && paths+=("$p")
  done
  if [ "${#paths[@]}" -gt 0 ]; then
    tar czf "$BACKUP_DIR/configs.tar.gz" "${paths[@]}" 2>/dev/null; rc=$?
    if [ "$rc" -le 1 ] && tar tzf "$BACKUP_DIR/configs.tar.gz" >/dev/null 2>&1; then
      ok "Config-Backup angelegt: $BACKUP_DIR/configs.tar.gz (${#paths[@]} Pfade)"
    else
      crit "Config-Backup fehlgeschlagen - es werden KEINE Änderungen vorgenommen."
      BACKUP_DIR=""; return 1
    fi
  else
    info "Keine Konfigurationspfade auf dem Host gefunden - Backup enthält Paket-/Containerstand."
  fi
  { dpkg-query -W -f='${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null
    rpm -qa 'php*' 2>/dev/null; } > "$BACKUP_DIR/packages.txt"
  { for p in $(find_php_binaries); do echo "== $p"; "$p" -v 2>/dev/null | head -n1; "$p" -m 2>/dev/null | tr '\n' ' '; echo; done; } \
    > "$BACKUP_DIR/php-versions-modules.txt" 2>/dev/null
  cat > "$BACKUP_DIR/RESTORE.txt" <<EOF
Wiederherstellung der Konfiguration (erstellt $ts):
  1. Dienste ggf. stoppen:   systemctl stop php*-fpm apache2 httpd nginx
  2. Zurückspielen:          tar xzf $BACKUP_DIR/configs.tar.gz -C /
  3. Konfig testen:          nginx -t ; apachectl configtest ; php-fpm -t
  4. Dienste starten.
Paketstände vor Änderungen: $BACKUP_DIR/packages.txt
EOF
  chmod 600 "$BACKUP_DIR"/* 2>/dev/null
  echo "$BACKUP_DIR" > "$STATE_DIR/last_backup_dir" 2>/dev/null || true
  alog "Backup angelegt: $BACKUP_DIR"
  return 0
}

ensure_quar() {
  ensure_state_dir
  if [ -z "$QUAR_DIR" ] && [ -f "$STATE_DIR/last_quar_dir" ]; then
    local q
    q=$(cat "$STATE_DIR/last_quar_dir" 2>/dev/null || true)
    [ -n "$q" ] && [ -d "$q" ] && QUAR_DIR="$q"
  fi
  [ -n "$QUAR_DIR" ] && return 0
  QUAR_DIR="/root/php2shell-quarantine-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$QUAR_DIR" && chmod 700 "$QUAR_DIR"
  echo "$QUAR_DIR" > "$STATE_DIR/last_quar_dir" 2>/dev/null || true
}

# --- Maßnahme 1: Beweise sichern & Rückabwicklung ---
act_evidence() {
  ensure_state_dir
  explain "Beweise sichern (VOR Patch/Neustart!)" "keine (nur lesend, legt Verzeichnis in /root an)" \
    "Prozessliste, Verbindungen, Datei-Locks (/proc/locks), Logs, Crontabs, authorized_keys, Dateiliste, Session-Liste, Hashes verdächtiger Dateien; optional Worker-Speicherabbild" \
    "Ein Neustart/Patch löscht den Speicherzustand, den CVE-2026-109619 ausnutzt - danach lässt sich vieles nicht mehr rekonstruieren. Das Verzeichnis kann Secrets enthalten (700)." \
    "Checkbox [1] wieder abwählen (löscht das Beweis-Archiv) oder Verzeichnis manuell löschen"
  confirm "Beweise jetzt sichern?" || return 0
  local d pid f
  d="/root/php2shell-evidence-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$d" && chmod 700 "$d" || { crit "Verzeichnis nicht anlegbar"; return 0; }
  ps -eo pid,ppid,user,lstart,args --forest > "$d/processes.txt" 2>/dev/null
  ss -tanp > "$d/connections.txt" 2>/dev/null
  [ -r /proc/locks ] && cp /proc/locks "$d/proc-locks.txt" 2>/dev/null
  command -v lsof >/dev/null 2>&1 && { lsof -nP -i > "$d/lsof-network.txt" 2>/dev/null; lsof +D /var/lib/php > "$d/lsof-php-sessions.txt" 2>/dev/null; }
  find /var/log -maxdepth 4 -type f \( -name '*access*log*' -o -name 'error*log*' -o -name '*fpm*log*' -o -name 'php*log*' \) -print0 2>/dev/null \
    | tar czf "$d/logs.tar.gz" --null -T - 2>/dev/null
  command -v journalctl >/dev/null 2>&1 && journalctl --since "$SINCE" --no-pager 2>/dev/null | head -c 50000000 > "$d/journal.txt"
  tar czf "$d/persistence.tar.gz" /var/spool/cron /etc/cron.d /etc/crontab 2>/dev/null
  find /root /home /var/www -maxdepth 3 -name 'authorized_keys*' -print0 2>/dev/null | tar czf "$d/authorized_keys.tar.gz" --null -T - 2>/dev/null
  if [ "${#WEBROOTS[@]}" -gt 0 ]; then
    find "${WEBROOTS[@]}" -type f -newermt "$SINCE" -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null | sort > "$d/recent-files.txt"
  fi
  for f in $(session_dirs); do ls -la "$f" > "$d/sessions-$(basename "$f").txt" 2>/dev/null; done
  if [ "${#FOUND_FILES[@]}" -gt 0 ]; then sha256sum -- "${FOUND_FILES[@]}" > "$d/suspicious-hashes.txt" 2>/dev/null; fi
  if command -v gcore >/dev/null 2>&1; then
    if confirm "Speicherabbild von bis zu 3 PHP-Workern erstellen (enthält Secrets, pausiert Worker kurz)?"; then
      for pid in $(pgrep -f 'php-fpm: pool|apache2|httpd' 2>/dev/null | head -n 3); do gcore -o "$d/gcore" "$pid" >/dev/null 2>&1; done
      chmod 600 "$d"/gcore* 2>/dev/null
    fi
  else
    info "gcore nicht installiert (Paket gdb) - Speicherabbild übersprungen."
  fi
  (cd "$d" && sha256sum -- * > SHA256SUMS 2>/dev/null)
  chmod 600 "$d"/* 2>/dev/null
  EVIDENCE_DONE=1
  echo "$d" > "$STATE_DIR/last_evidence_dir" 2>/dev/null || true
  ok "Beweise gesichert in $d (Integrität: SHA256SUMS)"
  alog "Beweise gesichert: $d"
}

undo_evidence() {
  local dirs=()
  mapfile -t dirs < <(ls -d /root/php2shell-evidence-* 2>/dev/null || true)
  [ "${#dirs[@]}" -gt 0 ] || { info "Keine Beweis-Verzeichnisse vorhanden."; return 0; }
  explain "Rückabwicklung #1: Gesicherte Beweis-Archive entfernen" "niedrig" \
    "Löscht die angelegten Beweis-Ordner (${dirs[*]}) aus /root" \
    "Forensische Abbilder (inkl. evtl. darin enthaltener Secrets/RAM-Dumps) werden unwiderruflich vom System gelöscht." \
    "Erneut über Maßnahme 1 anlegen"
  confirm "Beweis-Verzeichnisse (${#dirs[@]}) jetzt entfernen?" || return 0
  rm -rf -- "${dirs[@]}" "$STATE_DIR/last_evidence_dir" 2>/dev/null
  EVIDENCE_DONE=0
  ok "Beweis-Verzeichnisse entfernt."
  alog "Rückabwicklung #1: Beweis-Verzeichnisse gelöscht (${dirs[*]})"
}

# --- Maßnahme 2: Konfig-Backup anlegen & Rückabwicklung (Restore) ---
act_backup() {
  explain "Konfig-Backup anlegen" "keine (nur Kopie)" \
    "tar.gz aller PHP-/Webserver-/audit-Konfigs plus Paketliste und Modulübersicht nach /root" \
    "Speicherbedarf klein; Backup enthält Konfigs (evtl. Zugangsdaten) -> Rechte 700/600" \
    "Abwählen in der TUI spielt das Konfig-Backup auf Wunsch zurück oder löscht es"
  confirm "Backup jetzt anlegen?" && ensure_backup
}

undo_backup() {
  local bdir=""
  [ -f "$STATE_DIR/last_backup_dir" ] && bdir=$(cat "$STATE_DIR/last_backup_dir" 2>/dev/null || true)
  [ -z "$bdir" ] && bdir=$(ls -dt /root/php2shell-backup-* 2>/dev/null | head -n1 || true)
  [ -n "$bdir" ] && [ -d "$bdir" ] || { info "Kein Backup-Verzeichnis gefunden."; return 0; }
  explain "Rückabwicklung #2: Konfigurations-Backup zurückspielen (Restore) oder löschen" "mittel-hoch" \
    "Spielt wahlweise '$bdir/configs.tar.gz' nach / zurück (stellt alle /etc/php, nginx, apache2 Konfigs auf den Stand vor den Skript-Eingriffen zurück) ODER entfernt das Backup-Archiv." \
    "Beim Zurückspielen werden seitdem gemachte Konfig-Änderungen überschrieben." \
    "Nicht nötig"
  local choice
  tty_read -r -p "Aktion wählen: [r] Konfig-Backup nach / zurückspielen (Restore) | [d] Backup-Ordner löschen | [Enter] Abbruch: " choice || return 0
  case "$choice" in
    r|R)
      if [ -f "$bdir/configs.tar.gz" ] && confirm_word "Konfigurationen aus $bdir/configs.tar.gz jetzt nach / zurückspielen?" "RESTORE"; then
        tar xzf "$bdir/configs.tar.gz" -C / && ok "Konfigurationen aus $bdir/configs.tar.gz erfolgreich wiederhergestellt."
        alog "Rückabwicklung #2: Config-Restore aus $bdir/configs.tar.gz"
        info "Bitte prüfe die Konfiguration und starte die Dienste neu (Maßnahme 10)."
      fi
      ;;
    d|D)
      if confirm "Backup-Ordner $bdir wirklich löschen?"; then
        rm -rf -- "$bdir" "$STATE_DIR/last_backup_dir"
        BACKUP_DIR=""
        ok "Backup-Ordner $bdir gelöscht."
        alog "Rückabwicklung #2: Backup-Ordner gelöscht ($bdir)"
      fi
      ;;
    *) info "Abgebrochen." ;;
  esac
}

# ------------------------------------------------ Sicherheitsrahmen für Updates

risk() { RISKS+=("$1"); }

confirm_risky() {
  if [ "${#RISKS[@]}" -gt 0 ]; then
    printf '\n%s!! WARNUNG: Dieser Schritt kann Funktionen oder Dienste beeinträchtigen !!%s\n' "$R" "$N"
    printf '  - %s\n' "${RISKS[@]}"
    confirm_word "Trotz dieser Risiken fortfahren?" "JA"
  else
    printf '%sVorabprüfung: keine Risiken erkannt%s (geprüft: Paketänderungen, Konfigtests, Speicherplatz; NICHT geprüft: Anwendungslogik).\n' "$G" "$N"
    confirm "$1"
  fi
}

relevant_services() {
  systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' \
    | grep -E '^(php[0-9.]*-fpm|php-fpm|apache2|httpd|nginx|frankenphp|lshttpd|lsws|caddy)\.service$'
}

listening_ports() {
  ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' '
}

ask_probe_urls() {
  [ "$PROBE_ASKED" -eq 0 ] || return 0
  PROBE_ASKED=1
  local line u
  tty_read -r -p "Test-URLs deiner wichtigen Seiten (Leerzeichen getrennt, z. B. https://example.org/; Enter = nur localhost): " line || return 0
  for u in $line; do
    case "$u" in
      http://*|https://*) PROBE_URLS+=("$u") ;;
      *) warn "Ignoriere '$u' (keine http(s)-URL)" ;;
    esac
  done
}

probe_all() {
  command -v curl >/dev/null 2>&1 || return 0
  local ports u c
  ports=" $(listening_ports) "
  { case "$ports" in *" 80 "*) echo "http://127.0.0.1/" ;; esac
    case "$ports" in *" 443 "*) echo "https://127.0.0.1/" ;; esac
    if [ "${#PROBE_URLS[@]}" -gt 0 ]; then printf '%s\n' "${PROBE_URLS[@]}"; fi; } \
  | while read -r u; do
      [ -n "$u" ] || continue
      c=$(curl -k -s -o /dev/null -L --max-redirs 3 -w '%{http_code}' --max-time 8 "$u" 2>/dev/null)
      echo "$u ${c:-000}"
    done
}

snapshot_state() {
  mapfile -t SNAP_SVCS < <(relevant_services)
  SNAP_PORTS=$(listening_ports)
  SNAP_PROBE=$(probe_all)
}

config_tests() {
  local bad=0 b
  if command -v nginx >/dev/null 2>&1; then nginx -t >/dev/null 2>&1 || { echo "nginx -t fehlgeschlagen"; bad=1; }; fi
  if command -v apachectl >/dev/null 2>&1; then apachectl configtest >/dev/null 2>&1 || { echo "apachectl configtest fehlgeschlagen"; bad=1; }
  elif command -v httpd >/dev/null 2>&1; then httpd -t >/dev/null 2>&1 || { echo "httpd -t fehlgeschlagen"; bad=1; }; fi
  for b in $(find_php_binaries | grep -E 'php-fpm'); do "$b" -t >/dev/null 2>&1 || { echo "$b -t fehlgeschlagen"; bad=1; }; done
  return $bad
}

verify_once() {
  local bad=0 s p u c0 c1 now cfg
  for s in ${SNAP_SVCS[@]+"${SNAP_SVCS[@]}"}; do
    systemctl is-active --quiet "$s" || { crit "Dienst $s läuft nicht mehr"; bad=1; }
  done
  now=" $(listening_ports) "
  for p in $SNAP_PORTS; do
    case "$now" in *" $p "*) ;; *) crit "Port $p lauscht nicht mehr"; bad=1 ;; esac
  done
  now=$(probe_all)
  while read -r u c0; do
    [ -n "$u" ] || continue
    c1=$(printf '%s\n' "$now" | awk -v u="$u" '$1==u{print $2}')
    if [ "${c0:0:1}" != "5" ] && [ "$c0" != "000" ] && { [ "${c1:-000}" = "000" ] || [ "${c1:0:1}" = "5" ]; }; then
      crit "HTTP-Probe $u: vorher $c0, jetzt ${c1:-000}"; bad=1
    fi
  done <<< "$SNAP_PROBE"
  cfg=$(config_tests) || { crit "Konfigtest: $cfg"; bad=1; }
  return $bad
}

verify_state() {
  sleep 2
  if verify_once; then return 0; fi
  warn "Erste Prüfung negativ - warte kurz und prüfe erneut ..."
  sleep 5
  verify_once
}

deb_cache_file() {
  local v="${2//:/%3a}"
  ls /var/cache/apt/archives/"$1"_"$v"_*.deb 2>/dev/null | head -n1
}

rollback_possible() {
  local pv n v bad=0
  for pv in "$@"; do
    n="${pv%%=*}"; v="${pv#*=}"
    if [ -n "$(deb_cache_file "$n" "$v")" ]; then continue; fi
    if apt-cache madison "$n" 2>/dev/null | awk '{print $3}' | grep -qxF "$v"; then continue; fi
    bad=1
  done
  return $bad
}

secure_old_debs() {
  mkdir -p "$BACKUP_DIR/debs"
  local pv n v f miss=0
  for pv in "$@"; do
    n="${pv%%=*}"; v="${pv#*=}"
    f=$(deb_cache_file "$n" "$v")
    if [ -n "$f" ]; then cp -p "$f" "$BACKUP_DIR/debs/"
    elif ! (cd "$BACKUP_DIR/debs" && apt-get download "$n=$v" >/dev/null 2>&1); then miss=1; fi
  done
  return $miss
}

rollback_pkgs() {
  if ls "$BACKUP_DIR"/debs/*.deb >/dev/null 2>&1; then
    dpkg --force-confold -i "$BACKUP_DIR"/debs/*.deb
  else
    apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "$@"
  fi
}

cand_ok() {
  local c
  c=$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{print $2}')
  [ -n "$c" ] && [ "$c" != "(none)" ]
}

common_risks() {
  local free
  if [ "$COMP" -gt 0 ] && [ "$EVIDENCE_DONE" -eq 0 ]; then
    risk "Verdacht auf Befall, Beweise noch NICHT gesichert - Update/Neustart vernichtet Spuren (zuerst Maßnahme 1)."
  fi
  config_tests >/dev/null 2>&1 || risk "Webserver-/PHP-Konfiguration ist schon JETZT fehlerhaft (Konfigtest schlägt fehl) - die Nachprüfung wäre nicht aussagekräftig."
  free=$(df -Pk / /var 2>/dev/null | awk 'NR>1{print $4}' | sort -n | head -n1)
  if [ -n "$free" ] && [ "$free" -lt 307200 ]; then risk "Wenig freier Speicher (< 300 MB) - eine Installation könnte halb fertig abbrechen."; fi
}

has_branch() {
  local b
  for b in $(uniq_branches); do
    if [ "$1" = "fixed" ] && [ -n "${FIXED[$b]:-}" ]; then return 0; fi
    if [ "$1" = "eol" ] && [ -z "${FIXED[$b]:-}" ]; then return 0; fi
  done
  return 1
}

# --- Maßnahme 3: Update im gleichen Branch (Notfall-Updates & EOL-Backports) & Rückabwicklung ---

act_update() {
  ensure_state_dir
  if [ "${#NEED_UPDATE[@]}" -eq 0 ]; then
    info "Laut Scan sind aktuell keine verwundbaren Host-PHP-Branches vermerkt."
    confirm "Trotzdem nach Paket-Updates für installierte PHP-Pakete suchen?" || return 0
  fi
  local b pkgs=() one=() branches=() dry inst remv other pairs=() p v nrem
  for b in $(uniq_branches); do branches+=("$b"); done
  RISKS=()
  if command -v apt-get >/dev/null 2>&1; then
    if [ "${#branches[@]}" -gt 0 ]; then
      for b in "${branches[@]}"; do
        mapfile -t one < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' "php${b}*" "libapache2-mod-php${b}" 2>/dev/null | awk '$1=="ii"{print $2}')
        pkgs+=(${one[@]+"${one[@]}"})
      done
    else
      mapfile -t pkgs < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '$1=="ii"{print $2}')
    fi
    if [ "${#pkgs[@]}" -eq 0 ]; then
      warn "Keine zugehörigen Debian-Pakete auf dem Host gefunden (läuft PHP ausschließlich im Docker-Container -> Maßnahme 6?)."
      return 0
    fi
    info "Vorabprüfung (nichts wird geändert) ..."
    apt-get update -qq 2>/dev/null
    dry=$(apt-get -s install --only-upgrade "${pkgs[@]}" 2>/dev/null)
    inst=$(printf '%s\n' "$dry" | grep '^Inst' | cut -c1-150)
    if [ -z "$inst" ]; then
      warn "Das Repo liefert aktuell KEIN Paket-Update für diese PHP-Pakete. Falls du einen EOL-Branch ohne Distro-Backport nutzt, wähle Maßnahme 4 (Branch-Upgrade)."
      return 0
    fi
    printf '%s\n' "$inst" | indent
    remv=$(printf '%s\n' "$dry" | grep '^Remv' | awk '{print $2}' | tr '\n' ' ')
    if [ -n "$remv" ]; then risk "apt würde Pakete ENTFERNEN: $remv"; fi
    other=$(printf '%s\n' "$inst" | awk '{print $2}' | grep -vE '^(php|libapache2-mod-php)' | tr '\n' ' ')
    if [ -n "$other" ]; then risk "Zusätzlich werden NICHT-PHP-Pakete aktualisiert: $other"; fi
    if dpkg-query -W -f='${db:Status-Abbrev}\n' 'libapache2-mod-php*' 2>/dev/null | grep -q '^ii'; then
      risk "mod_php aktiv: Apache muss neu starten - alle virtuellen Hosts sind dabei kurz offline."
    fi
    if apt-mark showhold 2>/dev/null | grep -qE '^php'; then info "Hinweis: einige PHP-Pakete sind per apt-mark 'hold' gesperrt und werden nicht aktualisiert."; fi
    for p in "${pkgs[@]}"; do
      v=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null); [ -n "$v" ] && pairs+=("$p=$v")
    done
    if ! rollback_possible "${pairs[@]}"; then
      risk "Die aktuell installierten Paketversionen sind NICHT mehr beschaffbar - ein automatischer Rollback der Pakete wäre nicht möglich."
    fi
    common_risks
    explain "PHP-Notfall-Updates im gleichen Branch einspielen (inkl. Distro-/LTS-Backports für 7.4/8.0/8.1)" "mittel" \
      "apt-get install --only-upgrade für ${#pkgs[@]} Pakete; bestehende Konfig-Dateien bleiben (force-confold). Vorher: Backup, alte .deb-Dateien sichern, Zustand von Diensten/Ports/HTTP festhalten. Nachher: Konfigtests + Vergleich; bei Regression automatischer Rollback." \
      "PHP-FPM/Apache werden vom Paket meist selbst neu gestartet -> kurze Unterbrechung, laufende Requests brechen ab, Opcache wird geleert." \
      "Checkbox [3] in der TUI wieder abwählen (spielt die gesicherten .deb-Pakete zurück)"
    confirm_risky "Update jetzt durchführen?" || return 0
    ensure_backup || return 0
    ask_probe_urls
    if ! secure_old_debs "${pairs[@]}"; then warn "Nicht alle alten Paketversionen konnten gesichert werden - Rollback eingeschränkt."; fi
    printf '%s\n' "${pairs[@]}" > "$STATE_DIR/pkg_update_pairs"
    echo "$BACKUP_DIR" > "$STATE_DIR/pkg_update_bdir"
    snapshot_state
    alog "Update gestartet: ${pkgs[*]}"
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold "${pkgs[@]}"; then
      alog "Update installiert, Nachprüfung läuft"
      if verify_state; then
        ok "Nachprüfung bestanden: Konfigtests ok, Dienste/Ports unverändert, HTTP-Antworten unverändert."
        alog "Update erfolgreich verifiziert"
        NEED_UPDATE=()
        bash "$SELF" --versions-only --no-menu --accept-disclaimer 2>&1 | sed -n '/1) PHP-Versionen/,/Zusammenfassung/p'
        info "Falls Prozesse noch alten Code halten: Maßnahme 10 'Dienste neu starten'."
      else
        crit "Nachprüfung NEGATIV - starte automatischen Rollback der Pakete (das stellt auch die verwundbare Version wieder her!)."
        alog "Update Regression -> Rollback"
        if rollback_pkgs "${pairs[@]}"; then
          if verify_state; then warn "Rollback erfolgreich, System läuft wie vorher (PHP weiterhin UNGEPATCHT). Ursache prüfen, bevor erneut aktualisiert wird."
          else crit "Auch nach Rollback weicht der Zustand ab - bitte manuell prüfen. Backup: $BACKUP_DIR"; fi
        else crit "Rollback fehlgeschlagen - bitte manuell: dpkg -i $BACKUP_DIR/debs/*.deb. Backup: $BACKUP_DIR"; fi
      fi
    else
      crit "apt-get meldete einen Fehler - Zustand prüfen (dpkg --audit). Backup: $BACKUP_DIR"
      alog "Update FEHLGESCHLAGEN"
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dry=$(dnf -y --assumeno upgrade 'php*' 2>&1)
    nrem=$(printf '%s\n' "$dry" | grep -cE '^ *Removing|^Remove ' || true)
    if [ "${nrem:-0}" -gt 0 ]; then risk "dnf würde Pakete ENTFERNEN (siehe 'dnf --assumeno upgrade php*')."; fi
    if ! printf '%s\n' "$dry" | grep -qiE 'Upgrading|Upgrade '; then warn "dnf liefert aktuell kein PHP-Update."; return 0; fi
    common_risks
    explain "PHP-Pakete aktualisieren (dnf)" "mittel" "dnf upgrade --refresh 'php*', danach Konfigtests und Vergleich Dienste/Ports/HTTP" \
      "Dienste ggf. kurz unterbrochen; bei Regression: automatisches 'dnf history undo last'." \
      "Checkbox [3] in der TUI abwählen ('dnf history undo last')"
    confirm_risky "Update jetzt durchführen?" || return 0
    ensure_backup || return 0
    ask_probe_urls
    snapshot_state
    alog "dnf upgrade gestartet"
    if dnf -y upgrade --refresh 'php*' && verify_state; then
      echo "dnf" > "$STATE_DIR/pkg_update_bdir"
      NEED_UPDATE=()
      ok "Nachprüfung bestanden."
      bash "$SELF" --versions-only --no-menu --accept-disclaimer 2>&1 | sed -n '/1) PHP-Versionen/,/Zusammenfassung/p'
    else
      crit "Update oder Nachprüfung fehlgeschlagen - Rollback per 'dnf history undo last' ..."
      dnf -y history undo last && verify_state && warn "Rollback durchgeführt (PHP weiterhin UNGEPATCHT)."
    fi
  else
    warn "Kein apt/dnf gefunden - bitte Pakete manuell aktualisieren."
  fi
}

undo_update() {
  local bdir="" pairs=()
  [ -f "$STATE_DIR/pkg_update_bdir" ] && bdir=$(cat "$STATE_DIR/pkg_update_bdir" 2>/dev/null || true)
  [ -f "$STATE_DIR/pkg_update_pairs" ] && mapfile -t pairs < "$STATE_DIR/pkg_update_pairs"
  if [ -z "$bdir" ] && [ "${#pairs[@]}" -eq 0 ]; then
    warn "Keine durch dieses Skript gesicherten Vorversionen (.deb / dnf-Historie) für ein Paket-Downgrade gefunden."
    return 0
  fi
  explain "Rückabwicklung #3: PHP-Paket-Update auf vorherige Versionen zurückrollen (Downgrade)" "hoch" \
    "Spielt die vor dem Update gesicherten Paketversionen aus $bdir/debs zurück (bzw. 'dnf history undo last')" \
    "WARNUNG: Das System läuft danach wieder mit der UNGEPATCHTEN, verwundbaren PHP-Version!" \
    "Erneut über Maßnahme 3 aktualisieren"
  confirm_word "Wirklich auf die ungepatchten PHP-Pakete zurückrollen?" "DOWNGRADE" || return 0
  if [ "$bdir" = "dnf" ] && command -v dnf >/dev/null 2>&1; then
    dnf -y history undo last && ok "dnf Rollback durchgeführt."
  else
    BACKUP_DIR="$bdir"
    if rollback_pkgs "${pairs[@]}"; then
      ok "Paket-Downgrade erfolgreich durchgeführt."
      alog "Rückabwicklung #3: Paket-Downgrade durchgeführt"
    else
      crit "Paket-Downgrade fehlgeschlagen."
    fi
  fi
}

# --- Maßnahme 4: Branch-Upgrade (EOL) Stufe 1 & Rückabwicklung ---

act_branchplan() {
  cat <<EOF

  Manuelles Vorgehen (z. B. ohne apt):
   1. Backup (Maßnahme 2) und Anwendungs-/DB-Backup anlegen.
   2. Neue PHP-Version PARALLEL installieren (nicht die alte ersetzen), Module nachinstallieren.
   3. Anwendung mit der neuen Version testen (Staging), Fehlerlog beobachten.
   4. Pool-/php.ini-Einstellungen übernehmen, Webserver/FPM erst nach erfolgreichem Test umstellen.
   5. Alte Version erst entfernen, wenn alles stabil läuft.
EOF
}

offer_sury() {
  local id like
  id=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
  like=$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")
  RISKS=("Ein Drittanbieter-Repository wird eingebunden: dessen Pakete laufen bei der Installation als root und können künftig auch Systembibliotheken ersetzen.")
  explain "Drittanbieter-Repository für PHP $1 einbinden (Sury/Ondřej)" "hoch" \
    "Fügt ein externes APT-Repository hinzu (Ubuntu: PPA ondrej/php, Debian: packages.sury.org), danach 'apt-get update'." \
    "Vertrauensentscheidung. Bei Problemen: Quellen-Datei entfernen und 'apt-get update'." \
    "/etc/apt/sources.list.d/php.list (Debian) bzw. PPA-Eintrag entfernen; /etc/apt liegt im Backup"
  confirm_risky "Repository einbinden?" || return 1
  ensure_backup || return 1
  if [[ "$id $like" == *ubuntu* ]]; then
    command -v add-apt-repository >/dev/null 2>&1 || apt-get install -y software-properties-common
    add-apt-repository -y ppa:ondrej/php || return 1
  elif [[ "$id $like" == *debian* ]]; then
    apt-get install -y ca-certificates curl lsb-release || return 1
    curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb || return 1
    dpkg -i /tmp/debsuryorg-archive-keyring.deb || return 1
    echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
  else
    warn "Distribution nicht unterstützt - Repo bitte manuell einbinden."; return 1
  fi
  apt-get update -qq || return 1
  alog "Sury-Repo eingebunden"
  return 0
}

compat_report() {
  local newphp="/usr/bin/php$2" oldphp="/usr/bin/php$1" missing out roots=("${WEBROOTS[@]}")
  hdr "Kompatibilitätsbericht PHP $1 -> $2 (Hinweis: Lint prüft nur Syntax, KEINE Laufzeit-Kompatibilität)"
  if [ ! -x "$newphp" ]; then warn "$newphp nicht gefunden - Bericht übersprungen."; return 0; fi
  if [ -x "$oldphp" ]; then
    missing=$(comm -23 <("$oldphp" -m 2>/dev/null | grep -E '^[A-Za-z]' | sort -u) <("$newphp" -m 2>/dev/null | grep -E '^[A-Za-z]' | sort -u) | tr '\n' ' ')
    if [ -n "$missing" ]; then warn "Module in $1 vorhanden, in $2 NICHT geladen: $missing"; else ok "Alle PHP-Module der alten Version sind auch in $2 vorhanden."; fi
  fi
  if [ "${#roots[@]}" -eq 0 ]; then detect_webroots; roots=("${WEBROOTS[@]}"); fi
  if [ "${#roots[@]}" -gt 0 ]; then
    out=$(timeout 300 find "${roots[@]}" -type f -name '*.php' 2>/dev/null | head -n 5000 \
          | xargs -r -P4 -n1 "$newphp" -l 2>&1 | grep -E 'Parse error|Fatal error|Deprecated' | cut -c1-200 | head -n 30)
    if [ -n "$out" ]; then warn "Lint mit PHP $2 meldet Probleme (erste 30):"; printf '%s\n' "$out" | indent
    else ok "Lint mit PHP $2: keine Syntaxfehler/Deprecations in den (bis zu 5000) geprüften PHP-Dateien."; fi
  else
    info "Keine Webroots für den Lint gefunden (--webroot angeben)."
  fi
  info "Teste die neue Version zusätzlich mit deiner Anwendung (Staging) - dieser Bericht ersetzt das nicht."
}

act_branch_upgrade() {
  ensure_state_dir
  local old="" tgt="" b p m new a cur ba dry inst remv other n
  for b in $(uniq_branches); do if [ -z "${FIXED[$b]:-}" ]; then old="$b"; break; fi; done
  if [ -z "$old" ]; then
    tty_read -r -p "Aktueller PHP-Branch auf dem Host, von dem migriert werden soll (z. B. 8.1 oder 8.2): " old || return 0
    [ -n "$old" ] || return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then warn "Automatisches Branch-Upgrade nur für Debian/Ubuntu (apt)."; act_branchplan; return 0; fi
  local oldpkgs=() newpkgs=() missing=() known_skip=" json " newset=() beforeset afterset
  mapfile -t oldpkgs < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' "php${old}-*" 2>/dev/null | awk '$1=="ii"{print $2}')
  if [ "${#oldpkgs[@]}" -eq 0 ]; then warn "Keine Debian-Pakete für PHP $old gefunden (PHP im Docker-Container -> Maßnahme 6?) - manuell migrieren."; act_branchplan; return 0; fi
  tty_read -r -p "Zielbranch [${RECOMMENDED_BRANCH}] (möglich: ${!FIXED[*]}): " tgt || return 0
  tgt="${tgt:-$RECOMMENDED_BRANCH}"
  if [ -z "${FIXED[$tgt]:-}" ] || [ "$tgt" = "$old" ] || ! ver_ge "$tgt" "$old"; then warn "Ungültiger Zielbranch '$tgt'."; return 0; fi
  if ! cand_ok "php${tgt}-cli"; then
    info "php${tgt}-cli ist in den eingebundenen Repositories nicht verfügbar."
    offer_sury "$tgt" || { info "Abgebrochen - nichts wurde geändert."; return 0; }
    cand_ok "php${tgt}-cli" || { warn "Auch nach Repo-Einbindung nicht verfügbar - Abbruch (außer dem Repo wurde nichts geändert)."; return 0; }
  fi
  for p in "${oldpkgs[@]}"; do
    m="${p#php"${old}"-}"
    [ "$m" = "dbg" ] && continue
    new="php${tgt}-${m}"
    if cand_ok "$new"; then newpkgs+=("$new")
    else case "$known_skip" in *" $m "*) ;; *) missing+=("$m") ;; esac; fi
  done
  RISKS=()
  if [ "${#missing[@]}" -gt 0 ]; then risk "Diese Module gibt es für PHP $tgt nicht (Funktionen können fehlen): ${missing[*]}"; fi
  if dpkg-query -W -f='${db:Status-Abbrev}\n' "libapache2-mod-php${old}" 2>/dev/null | grep -q '^ii'; then
    risk "Apache nutzt mod_php $old: Es wird nur CLI/FPM der neuen Version installiert; das Umschalten von mod_php ist NICHT automatisiert (manuell: a2dismod php$old; a2enmod php$tgt)."
  fi
  dry=$(apt-get -s install "${newpkgs[@]}" 2>/dev/null)
  inst=$(printf '%s\n' "$dry" | grep '^Inst' | awk '{print $2}')
  remv=$(printf '%s\n' "$dry" | grep '^Remv' | awk '{print $2}' | tr '\n' ' ')
  if [ -n "$remv" ]; then risk "Die Installation würde Pakete ENTFERNEN: $remv"; fi
  other=$(printf '%s\n' "$inst" | grep -vE "^php${tgt}-|^php-" | tr '\n' ' ')
  if [ -n "$other" ]; then risk "Zusätzlich werden andere Pakete installiert/aktualisiert: $other"; fi
  common_risks
  n=$(printf '%s\n' "$inst" | grep -c . || true)
  explain "Stufe 1: PHP $tgt PARALLEL zu PHP $old installieren (schaltet NICHTS um)" "mittel" \
    "Installiert ${#newpkgs[@]} passende Pakete (cli, fpm, Module wie bei PHP $old), insgesamt $n Pakete. Vorher: Backup, Zustand festhalten. Danach: die 'php'-Kommandozeilen-Alternativen werden auf die alte Version zurückgesetzt, Nachprüfung, Kompatibilitätsbericht." \
    "Webseiten laufen weiter mit PHP $old. Ein zusätzlicher PHP-FPM-Dienst für $tgt startet (eigener Socket). Umgeschaltet wird erst in Stufe 2 (Maßnahme 5)." \
    "Checkbox [4] wieder abwählen (entfernt die parallel installierten php${tgt}-*-Pakete wieder)"
  confirm_risky "PHP $tgt jetzt parallel installieren?" || return 0
  ensure_backup || return 0
  ask_probe_urls
  local -A alt_before=()
  for a in php phar phar.phar php-config phpize phpdbg php-cgi; do
    if [ -e "/etc/alternatives/$a" ]; then alt_before[$a]=$(readlink -f "/etc/alternatives/$a"); fi
  done
  beforeset=$(dpkg-query -W -f='${Package}\n' 'php*' 2>/dev/null | sort)
  snapshot_state
  alog "Branch-Upgrade Stufe 1: $old -> $tgt (${newpkgs[*]})"
  restore_alts() {
    for a in "${!alt_before[@]}"; do
      cur=$(readlink -f "/etc/alternatives/$a" 2>/dev/null || true)
      ba="${alt_before[$a]}"
      if [ -n "$cur" ] && [ "$cur" != "$ba" ]; then update-alternatives --set "$a" "$ba" >/dev/null 2>&1 && info "Alternative '$a' zurückgesetzt auf $ba"; fi
    done
  }
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold "${newpkgs[@]}"; then
    crit "Installation meldete einen Fehler - prüfe 'dpkg --audit'. Es wurde nichts umgeschaltet. Backup: $BACKUP_DIR"
    restore_alts
    return 0
  fi
  restore_alts
  afterset=$(dpkg-query -W -f='${Package}\n' 'php*' 2>/dev/null | sort)
  mapfile -t newset < <(comm -13 <(printf '%s\n' "$beforeset") <(printf '%s\n' "$afterset"))
  if verify_state; then
    ok "Nachprüfung bestanden: bestehende Dienste/Ports/HTTP-Antworten unverändert."
    UPG_OLD="$old"; UPG_TGT="$tgt"
    echo "$old" > "$STATE_DIR/upg_old"
    echo "$tgt" > "$STATE_DIR/upg_tgt"
    printf '%s\n' "${newset[@]}" > "$STATE_DIR/branch_newpkgs"
    alog "Branch-Upgrade Stufe 1 erfolgreich"
    compat_report "$old" "$tgt"
    info "Nächster Schritt (separat, mit Warnung und Rollback): Maßnahme 5 'Auf PHP $tgt umschalten (Stufe 2)'."
  else
    crit "Nachprüfung NEGATIV - entferne die neu installierten Pakete wieder."
    alog "Branch-Upgrade Regression -> Entfernen"
    if [ "${#newset[@]}" -gt 0 ] && apt-get remove -y "${newset[@]}"; then
      restore_alts
      if verify_state; then warn "Zustand wiederhergestellt, System läuft wie vorher."; else crit "Abweichung bleibt - bitte manuell prüfen. Backup: $BACKUP_DIR"; fi
    else
      crit "Entfernen fehlgeschlagen - bitte manuell: apt-get remove ${newset[*]:-php${tgt}-*}"
    fi
  fi
}

undo_branch_upgrade() {
  local pkgs=() tgt=""
  [ -f "$STATE_DIR/upg_tgt" ] && tgt=$(cat "$STATE_DIR/upg_tgt" 2>/dev/null || true)
  [ -f "$STATE_DIR/branch_newpkgs" ] && mapfile -t pkgs < "$STATE_DIR/branch_newpkgs"
  if [ "${#pkgs[@]}" -eq 0 ]; then
    warn "Keine durch Maßnahme 4 protokollierten Parallel-Pakete zum Entfernen gefunden."
    return 0
  fi
  if [ -f "$STATE_DIR/switch_active" ]; then
    warn "Der Webserver ist aktuell noch auf PHP $tgt umgeschaltet (Maßnahme 5 ist aktiv). Bitte zuerst Maßnahme 5 abwählen/rückabwickeln!"
    return 0
  fi
  explain "Rückabwicklung #4: Parallel installierte PHP-$tgt-Pakete wieder entfernen" "mittel" \
    "Führt 'apt-get remove -y' für die in Stufe 1 neu installierten Pakete (${#pkgs[@]} Pakete) aus" \
    "Der parallele PHP-$tgt-FPM-Dienst wird gestoppt und deinstalliert. Die alte PHP-Version bleibt unberührt." \
    "Erneut über Maßnahme 4 installieren"
  confirm "Parallel installierte PHP-$tgt-Pakete jetzt entfernen?" || return 0
  if DEBIAN_FRONTEND=noninteractive apt-get remove -y "${pkgs[@]}"; then
    rm -f "$STATE_DIR/branch_newpkgs" "$STATE_DIR/upg_old" "$STATE_DIR/upg_tgt"
    UPG_OLD=""; UPG_TGT=""
    ok "Parallel installierte PHP-$tgt-Pakete wurden entfernt."
    alog "Rückabwicklung #4: PHP-$tgt-Pakete entfernt"
  else
    crit "Entfernen der Pakete meldete einen Fehler."
  fi
}

# --- Maßnahme 5: Branch-Upgrade (EOL) Stufe 2: Umschalten & Rückabwicklung ---

clean_ini() {
  sed -e 's/;.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]]*=[[:space:]]*/ = /' "$1" | grep -E '^[A-Za-z_.]+ = '
}

migrate_ini() {
  local sapi fo fn out dest
  for sapi in fpm cli; do
    fo="/etc/php/$1/$sapi/php.ini"; fn="/etc/php/$2/$sapi/php.ini"
    [ -f "$fo" ] && [ -f "$fn" ] || continue
    out=$(grep -vxFf <(clean_ini "$fn") <(clean_ini "$fo") | grep -vE '^(extension|zend_extension) ')
    if [ -z "$out" ]; then info "php.ini ($sapi): keine abweichenden Einstellungen zu übernehmen."; continue; fi
    printf '\n  Abweichende Einstellungen in %s (gegenüber der Standard-php.ini von PHP %s):\n' "$fo" "$2"
    printf '%s\n' "$out" | head -n 40 | indent
    if confirm "Diese Einstellungen für PHP $2 ($sapi) als Drop-in übernehmen? (sonst gelten dort die Standardwerte, z. B. upload_max_filesize!)"; then
      dest="/etc/php/$2/$sapi/conf.d/98-php2shell-migrated.ini"
      { echo "; php2shell-check.sh: übernommen aus $fo"; printf '%s\n' "$out"; } > "$dest"
      MIGRATED_FILES+=("$dest")
      ok "Drop-in geschrieben: $dest"
    fi
  done
}

act_switch() {
  ensure_state_dir
  command -v apt-get >/dev/null 2>&1 || { warn "Umschalten ist nur für Debian/Ubuntu (apt, /etc/php/<ver>) automatisiert."; act_branchplan; return 0; }
  local old="${UPG_OLD:-$(cat "$STATE_DIR/upg_old" 2>/dev/null || true)}"
  local tgt="${UPG_TGT:-$(cat "$STATE_DIR/upg_tgt" 2>/dev/null || true)}"
  local b f dest fl listen tcp sock files=() ws changed=() created=() bad=0 i
  MIGRATED_FILES=()
  if [ -z "$old" ]; then for b in $(uniq_branches); do if [ -z "${FIXED[$b]:-}" ]; then old="$b"; break; fi; done; fi
  tty_read -r -p "Von PHP-Branch [${old:-?}]: " b || return 0; old="${b:-$old}"
  tty_read -r -p "Auf PHP-Branch [${tgt:-$RECOMMENDED_BRANCH}]: " b || return 0; tgt="${b:-${tgt:-$RECOMMENDED_BRANCH}}"
  if [ -z "$old" ] || [ -z "${FIXED[$tgt]:-}" ] || [ "$old" = "$tgt" ]; then warn "Ungültige Angaben."; return 0; fi
  for b in "$old" "$tgt"; do
    dpkg-query -W -f='${db:Status-Abbrev}\n' "php${b}-fpm" 2>/dev/null | grep -q '^ii' || { warn "php${b}-fpm ist nicht installiert - zuerst Stufe 1 (Maßnahme 4)."; return 0; }
  done
  tcp=$(grep -hE '^[[:space:]]*listen[[:space:]]*=' /etc/php/"$old"/fpm/pool.d/*.conf 2>/dev/null | grep -vE '=[[:space:]]*/' || true)
  if [ -n "$tcp" ]; then
    warn "Alte Pools lauschen per TCP ($tcp). Parallelbetrieb würde den Port doppelt belegen - Umschalten ist hier NICHT automatisiert (sonst Ausfall). Bitte manuell planen."
    return 0
  fi
  mapfile -t files < <(grep -rlE "php${old}-fpm" /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | sort -u)
  RISKS=("Das Umschalten ändert die PHP-Version ALLER darüber laufenden Seiten. Anwendungen können mit PHP $tgt anders reagieren; der Lint beweist keine Kompatibilität.")
  if [ "${#files[@]}" -eq 0 ]; then risk "Es wurden keine Webserver-Konfigurationen gefunden, die php${old}-fpm referenzieren (mod_php? andere Anbindung?). Es würde NICHTS umgestellt."; fi
  common_risks
  explain "Stufe 2: Webserver von PHP $old auf PHP $tgt umschalten" "hoch" \
    "1) FPM-Pools von $old nach $tgt übernehmen (Socket-Namen angepasst, Originale gesichert) 2) abweichende php.ini-Einstellungen anzeigen/übernehmen 3) 'php-fpm$tgt -t', neuen FPM starten, Sockets prüfen 4) Webserver-Konfigs auf den neuen Socket umstellen (${#files[@]} Dateien, vorher gesichert), Konfigtest, Reload 5) Nachprüfung inkl. deiner Test-URLs." \
    "Reload statt Neustart (kurze, meist unmerkliche Umschaltung). Alte PHP-Version und ihr FPM bleiben installiert und laufen weiter." \
    "Checkbox [5] in der TUI wieder abwählen (stellt Webserver-Konfigs & Pools auf PHP $old zurück)"
  confirm_word "Auf PHP $tgt umschalten? (Warnungen oben gelesen)" "JA" || return 0
  ensure_backup || return 0
  mkdir -p "$BACKUP_DIR/switch"
  ask_probe_urls
  for f in /etc/php/"$old"/fpm/pool.d/*.conf; do
    [ -f "$f" ] || continue
    dest="/etc/php/$tgt/fpm/pool.d/$(basename "$f")"
    fl="${dest//\//_}"
    if [ -f "$dest" ]; then cp -p "$dest" "$BACKUP_DIR/switch/pool-$fl"; changed+=("$dest"); else created+=("$dest"); fi
    { echo "; php2shell-check.sh: übernommen aus $f"; sed "s/php${old}/php${tgt}/g" "$f"; } > "$dest"
  done
  rollback_pools() {
    for dest in ${changed[@]+"${changed[@]}"}; do cp -p "$BACKUP_DIR/switch/pool-${dest//\//_}" "$dest"; done
    for dest in ${created[@]+"${created[@]}"}; do rm -f -- "$dest"; done
    for dest in ${MIGRATED_FILES[@]+"${MIGRATED_FILES[@]}"}; do rm -f -- "$dest"; done
  }
  migrate_ini "$old" "$tgt"
  if ! "php-fpm$tgt" -t >/dev/null 2>&1; then
    crit "php-fpm$tgt -t fehlgeschlagen - Änderungen werden zurückgenommen, nichts umgeschaltet."
    rollback_pools; return 0
  fi
  if ! systemctl restart "php${tgt}-fpm"; then
    crit "php${tgt}-fpm startet nicht - zurückgenommen."; rollback_pools; systemctl restart "php${tgt}-fpm" >/dev/null 2>&1; return 0
  fi
  for listen in $(grep -hE '^[[:space:]]*listen[[:space:]]*=' /etc/php/"$tgt"/fpm/pool.d/*.conf 2>/dev/null | sed 's/.*=[[:space:]]*//'); do
    sock="$listen"; bad=1
    for i in 1 2 3 4 5; do if [ -S "$sock" ]; then bad=0; break; fi; sleep 1; done
    if [ "$bad" -eq 1 ]; then crit "Socket $sock existiert nicht - zurückgenommen."; rollback_pools; systemctl restart "php${tgt}-fpm" >/dev/null 2>&1; return 0; fi
  done
  ok "PHP $tgt FPM läuft, Sockets vorhanden."
  snapshot_state
  for f in ${files[@]+"${files[@]}"}; do
    cp -p "$f" "$BACKUP_DIR/switch/ws-${f//\//_}"
    sed -i "s/php${old}-fpm/php${tgt}-fpm/g" "$f"
  done
  revert_ws() {
    for f in ${files[@]+"${files[@]}"}; do cp -p "$BACKUP_DIR/switch/ws-${f//\//_}" "$f"; done
    for ws in nginx apache2 httpd; do systemctl is-active --quiet "$ws" 2>/dev/null && systemctl reload "$ws"; done
  }
  if [ "${#files[@]}" -gt 0 ]; then
    if ! config_tests >/dev/null 2>&1; then
      crit "Webserver-Konfigtest nach Umstellung fehlgeschlagen - stelle zurück."
      for f in "${files[@]}"; do cp -p "$BACKUP_DIR/switch/ws-${f//\//_}" "$f"; done
      return 0
    fi
    for ws in nginx apache2 httpd; do systemctl is-active --quiet "$ws" 2>/dev/null && systemctl reload "$ws"; done
    alog "Umgeschaltet: PHP $old -> $tgt (${files[*]})"
    if verify_state; then
      echo "$BACKUP_DIR/switch" > "$STATE_DIR/switch_bdir"
      echo "$old|$tgt" > "$STATE_DIR/switch_active"
      printf '%s\n' "${files[@]}" > "$STATE_DIR/switch_ws_files"
      printf '%s\n' "${changed[@]+"${changed[@]}"}" > "$STATE_DIR/switch_pool_changed"
      printf '%s\n' "${created[@]+"${created[@]}"}" > "$STATE_DIR/switch_pool_created"
      printf '%s\n' "${MIGRATED_FILES[@]+"${MIGRATED_FILES[@]}"}" > "$STATE_DIR/switch_migrated"
      ok "Umschaltung erfolgreich verifiziert. PHP $old bleibt installiert und aktiv als Rückfallebene."
      info "Prüfe jetzt selbst deine wichtigen Seiten (Login, Formulare, Uploads) und beobachte die Fehlerlogs."
    else
      crit "Nachprüfung NEGATIV - schalte automatisch auf PHP $old zurück."
      alog "Umschaltung Regression -> zurück"
      revert_ws
      if verify_state; then warn "Zurückgeschaltet, System läuft wie vorher (weiterhin mit ungepatchtem PHP $old)."; else crit "Abweichung bleibt - manuell prüfen. Sicherungen: $BACKUP_DIR/switch"; fi
    fi
  fi
}

undo_switch() {
  [ -f "$STATE_DIR/switch_active" ] || { info "Keine aktive Umschaltung (Stufe 2) vermerkt."; return 0; }
  local pair old tgt sdir ws f files=() changed=() created=() migrated=()
  pair=$(cat "$STATE_DIR/switch_active" 2>/dev/null || true)
  old="${pair%%|*}"; tgt="${pair#*|}"
  sdir=$(cat "$STATE_DIR/switch_bdir" 2>/dev/null || true)
  [ -f "$STATE_DIR/switch_ws_files" ] && mapfile -t files < "$STATE_DIR/switch_ws_files"
  [ -f "$STATE_DIR/switch_pool_changed" ] && mapfile -t changed < "$STATE_DIR/switch_pool_changed"
  [ -f "$STATE_DIR/switch_pool_created" ] && mapfile -t created < "$STATE_DIR/switch_pool_created"
  [ -f "$STATE_DIR/switch_migrated" ] && mapfile -t migrated < "$STATE_DIR/switch_migrated"

  explain "Rückabwicklung #5: Webserver von PHP $tgt zurück auf PHP $old schalten" "hoch" \
    "Stellt die gesicherten Webserver-Konfigurationen (${#files[@]} Dateien) und FPM-Pools aus $sdir wieder her und lädt nginx/Apache sowie php${tgt}-fpm neu." \
    "WARNUNG: Die Webseiten laufen danach wieder mit der alten PHP-Version ($old)!" \
    "Erneut über Maßnahme 5 auf PHP $tgt umschalten"
  confirm_word "Webserver jetzt auf PHP $old zurückschalten?" "ZURUECK" || return 0
  for f in ${files[@]+"${files[@]}"}; do
    [ -n "$f" ] && [ -f "$sdir/ws-${f//\//_}" ] && cp -p "$sdir/ws-${f//\//_}" "$f"
  done
  for f in ${changed[@]+"${changed[@]}"}; do
    [ -n "$f" ] && [ -f "$sdir/pool-${f//\//_}" ] && cp -p "$sdir/pool-${f//\//_}" "$f"
  done
  for f in ${created[@]+"${created[@]}"}; do [ -n "$f" ] && rm -f -- "$f"; done
  for f in ${migrated[@]+"${migrated[@]}"}; do [ -n "$f" ] && rm -f -- "$f"; done
  systemctl restart "php${tgt}-fpm" >/dev/null 2>&1 || true
  for ws in nginx apache2 httpd; do systemctl is-active --quiet "$ws" 2>/dev/null && systemctl reload "$ws"; done
  rm -f "$STATE_DIR/switch_active" "$STATE_DIR/switch_bdir" "$STATE_DIR/switch_ws_files" "$STATE_DIR/switch_pool_changed" "$STATE_DIR/switch_pool_created" "$STATE_DIR/switch_migrated"
  ok "Webserver erfolgreich auf PHP $old zurückgeschaltet."
  alog "Rückabwicklung #5: Webserver zurück auf PHP $old geschaltet"
}

# --- Maßnahme 6: Docker-Container Update (Compose) & Rückabwicklung ---

ver_fixed() {
  local v="$1" b f
  [[ "$v" =~ ^([0-9]+)\.([0-9]+)\. ]] || return 1
  b="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"; f="${FIXED[$b]:-}"
  if [ -n "$f" ]; then ver_ge "$v" "$f"; return; fi
  ver_ge "$v" "8.6.0"
}

dk_image_php() {
  local out
  out=$(docker run --rm --entrypoint php "$1" -r 'echo PHP_VERSION;' 2>/dev/null) \
    || out=$(docker run --rm --entrypoint php-fpm "$1" -v 2>/dev/null | head -n1)
  printf '%s' "$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

dk_compose_setup() {
  local c="$1" f cf=()
  if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then COMPOSE=(docker-compose)
  else return 1; fi
  CARGS=(--project-directory "${DK_DIR[$c]}" -p "${DK_PROJ[$c]}")
  IFS=',' read -ra cf <<< "${DK_FILES[$c]}"
  for f in "${cf[@]}"; do
    [ -f "$f" ] || return 1
    CARGS+=(-f "$f")
  done
  return 0
}

dk_project_states() {
  docker ps -a --filter "label=com.docker.compose.project=$1" --format '{{.Names}} {{.State}}' 2>/dev/null | sort
}

dk_wait_ready() {
  local c="$1" st h t=0 max="${DK_WAIT:-90}"
  while [ "$t" -le "$max" ]; do
    st=$(dk_inspect '{{.State.Status}}' "$c")
    h=$(dk_inspect '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c")
    if [ "$st" = "running" ] && { [ -z "$h" ] || [ "$h" = "healthy" ]; }; then return 0; fi
    sleep 3; t=$((t+3))
  done
  return 1
}

dk_db_dump() {
  local d="$1" out="$2" img
  img=$(dk_inspect '{{.Config.Image}}' "$d")
  case "$img" in
    *mysql*|*mariadb*)
      docker exec "$d" sh -c 'D=$(command -v mysqldump || command -v mariadb-dump) || exit 1; P="${MYSQL_ROOT_PASSWORD:-$MARIADB_ROOT_PASSWORD}"; "$D" --all-databases --single-transaction -uroot -p"$P"' > "$out" 2>/dev/null ;;
    *postgres*)
      docker exec "$d" sh -c 'pg_dumpall -U "${POSTGRES_USER:-postgres}"' > "$out" 2>/dev/null ;;
    *) return 2 ;;
  esac
  chmod 600 "$out"
  tail -n 5 "$out" 2>/dev/null | grep -qiE 'dump complete'
}

dk_mount_backup() {
  local c="$1" bd="$2" m name rc=0
  while IFS= read -r m; do
    [ -n "$m" ] && [ -e "$m" ] || continue
    case "$m" in
      /|/etc/*|/proc*|/sys*|/dev*|/run*|/var/run*) continue ;;
    esac
    name=$(printf '%s' "$m" | sed 's|^/||; s|/|_|g')
    info "Sichere Container-Mount '$m' nach $bd/mount-$name.tar.gz ..."
    if ! tar czf "$bd/mount-$name.tar.gz" "$m" 2>/dev/null; then
      warn "Mount-Backup für '$m' meldete Fehler (ggf. Berechtigungen/Sonderdateien)."
      rc=1
    fi
  done < <(docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null)
  return $rc
}

dk_verify() {
  local c="$1" proj="$2" before="$3" bad=0 v l after
  if ! dk_wait_ready "$c"; then crit "Container $c wird nicht 'running'/'healthy' (Wartezeit ${DK_WAIT:-90}s)."; bad=1; fi
  v=$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null)
  if ! ver_fixed "$v"; then crit "PHP im Container $c ist '${v:-?}' (nicht gepatcht oder nicht lesbar)."; bad=1; fi
  after=$(dk_project_states "$proj")
  while read -r l; do
    [ -n "$l" ] || continue
    case "$l" in *" running") printf '%s\n' "$after" | grep -qxF "$l" || { crit "Projekt-Container nicht mehr running: ${l% *}"; bad=1; } ;; esac
  done <<< "$before"
  verify_state || bad=1
  return $bad
}

dk_rollback() {
  local c="$1" ref="$2" rb="$3" svc="$4"
  warn "Rollback: Stack wird mit docker compose down gestoppt, Tag '${ref%%@*}' auf das alte Image gesetzt und Projekt neu gestartet."
  "${COMPOSE[@]}" "${CARGS[@]}" down >/dev/null 2>&1 || true
  docker tag "$rb" "${ref%%@*}" || { crit "Rückfall-Tag nicht setzbar - manuell: docker tag $rb ${ref%%@*}"; return 1; }
  "${COMPOSE[@]}" "${CARGS[@]}" up -d || return 1
  dk_wait_ready "$c"
}

dk_pull_check() {
  PC_ID=""; PC_VER=""
  docker pull "$1" || return 2
  PC_ID=$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null)
  PC_VER=$(dk_image_php "$PC_ID")
  [ -n "$PC_VER" ] && ver_fixed "$PC_VER"
}

dk_tag_files() {
  local c="$1" r="$2" f cf=()
  IFS=',' read -ra cf <<< "${DK_FILES[$c]}"
  for f in "${cf[@]}" "${DK_DIR[$c]}/.env"; do
    if [ -f "$f" ] && grep -qF "$r" "$f"; then echo "$f"; fi
  done
}

dk_rollback_switch() {
  local c="$1" svc="$2" bd="$3" f
  shift 3
  warn "Rollback: Stack wird mit docker compose down gestoppt, Compose-Dateien werden zurückgesetzt und Projekt mit altem Tag neu gestartet."
  "${COMPOSE[@]}" "${CARGS[@]}" down >/dev/null 2>&1 || true
  for f in "$@"; do cp -p "$bd/orig-${f//\//_}" "$f"; done
  "${COMPOSE[@]}" "${CARGS[@]}" up -d || return 1
  dk_wait_ready "$c"
}

dk_recheck() {
  local c="$1" v
  hdr "Erneute Prüfung nach dem Update: $c"
  v=$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null)
  DK_PHPV[$c]="$v"
  if ver_fixed "$v"; then ok "PHP im Container $c: $v - SICHER (Fix ab ${FIXED[${v%.*}]:-neueren Branches})"
  else crit "PHP im Container $c: ${v:-?} - weiterhin NICHT sicher"; fi
  dk_scan_container "$c"
}

dk_unvuln() {
  local c="$1" x keep=()
  for x in "${DK_VULN[@]}"; do [ "$x" = "$c" ] || keep+=("$x"); done
  DK_VULN=()
  if [ "${#keep[@]}" -gt 0 ]; then DK_VULN=("${keep[@]}"); fi
}

dk_update_one() {
  ensure_state_dir
  local c="$1" ref="${DK_IMG[$1]}" proj="${DK_PROJ[$1]:-}" svc="${DK_SVC[$1]:-}" managed=0
  local ts oldid newid rb newver oldlab newlab st h sib d bd f before dumpfail=0 cf=() DBS=()
  local tgtref="$ref" switch=0 base nt t n tfiles=() old_e new_e rc rbok=1 stack_down=0
  hdr "Container $c  (Image $ref)"
  info "PHP im Container: ${DK_PHPV[$c]}"
  if [ -n "$proj" ] && [ -n "$svc" ] && [ -n "${DK_FILES[$c]:-}" ]; then
    managed=1
    info "Compose-Projekt '$proj', Dienst '$svc', Verzeichnis ${DK_DIR[$c]}"
  else
    warn "Keine Compose-Labels: automatisches Update nicht möglich (nur Prüfung und Anleitung)."
  fi
  if [ -n "${DK_REGHINT[$c]+x}" ]; then
    info "Image-Recherche (aus dem Scan): neueres Image unter dem Tag: $([ "${DK_REGNEWER[$c]}" = 1 ] && echo ja || echo 'nein/unbekannt'); Fix-Hinweis: $([ "${DK_REGHINT[$c]}" = 1 ] && echo ja || echo nein); neuere Tags: ${DK_NEWTAGS[$c]:-keine}."
  else
    dk_registry_info "$c"; DK_NEWTAGS[$c]="$DKR_NEWTAGS"
  fi
  if ! net_check; then warn "Ohne Internetzugang sind Recherche und Image-Download nicht möglich - nichts geändert."; return 0; fi
  explain "Neues Image herunterladen und prüfen (der laufende Container bleibt noch unberührt)" "niedrig" \
    "Legt zuerst einen lokalen Rückfall-Tag für das aktuelle Image an, lädt dann '$ref' neu und liest die PHP-Version aus dem neuen Image (docker run --rm, ohne Volumes und Ports)." \
    "Download (Speicher/Traffic). Der lokale Tag '$ref' zeigt danach auf das neue Image; der laufende Container nutzt weiter das alte, bis er neu erzeugt wird." \
    "docker tag <Rückfall-Tag> $ref"
  confirm "Neues Image jetzt laden und prüfen?" || return 0
  ts=$(date +%Y%m%d-%H%M%S)
  oldid=$(dk_inspect '{{.Image}}' "$c")
  rb="php2shell-rollback/${c,,}:$ts"
  docker tag "$oldid" "$rb" || { crit "Rückfall-Tag konnte nicht angelegt werden - Abbruch."; return 0; }
  info "Rückfall-Tag angelegt: $rb  (-> $oldid)"
  alog "Docker: Rückfall-Tag $rb für $c ($ref)"
  dk_pull_check "$ref"; rc=$?
  if [ "$rc" -eq 2 ]; then crit "docker pull fehlgeschlagen - nichts geändert."; return 0; fi
  newid="$PC_ID"; newver="$PC_VER"
  if [ -z "$newid" ] || [ "$newid" = "$oldid" ]; then
    if [ "$managed" -eq 1 ] && [ -n "${DK_NEWTAGS[$c]:-}" ]; then
      info "Unter dem Tag '${ref##*:}' liegt kein neueres Image. Update-Kandidaten: ${DK_NEWTAGS[$c]}"
      tty_read -r -p "Tag eingeben | l = latest | a = die ersten 3 Kandidaten nacheinander prüfen | Enter = abbrechen: " nt || nt=""
      if [ "$nt" = "l" ]; then nt="latest"; fi
      base="${ref%%@*}"; case "${base##*/}" in *:*) base="${base%:*}" ;; esac
      if [ "$nt" = "a" ]; then
        nt=""; n=0
        for t in ${DK_NEWTAGS[$c]}; do
          n=$((n+1)); [ "$n" -le 3 ] || break
          info "Prüfe Kandidat $base:$t ..."
          dk_pull_check "$base:$t"; rc=$?
          if [ "$rc" -eq 0 ] && [ "$PC_ID" != "$oldid" ]; then nt="$t"; break; fi
          if [ "$rc" -eq 2 ]; then warn "Pull von $t fehlgeschlagen."
          elif [ "$PC_ID" = "$oldid" ]; then info "Kandidat $t: identisch mit dem aktuellen Image."
          else info "Kandidat $t: PHP ${PC_VER:-unbekannt} - nicht gepatcht."; fi
        done
        if [ -z "$nt" ]; then
          info "Keiner der geprüften Kandidaten enthält ein gepatchtes PHP - nichts geändert."
          docker rmi "$rb" >/dev/null 2>&1
          return 0
        fi
        tgtref="$base:$nt"; switch=1; newid="$PC_ID"; newver="$PC_VER"
      elif [ -n "$nt" ] && [[ " ${DK_NEWTAGS[$c]} " == *" $nt "* ]]; then
        tgtref="$base:$nt"; switch=1
        dk_pull_check "$tgtref"; rc=$?
        if [ "$rc" -eq 2 ]; then crit "docker pull von $tgtref fehlgeschlagen - nichts geändert."; return 0; fi
        newid="$PC_ID"; newver="$PC_VER"
        if [ "$newid" = "$oldid" ]; then
          info "'$tgtref' ist identisch mit dem aktuellen Image - nichts zu aktualisieren."
          docker rmi "$rb" >/dev/null 2>&1
          return 0
        fi
      else
        info "Kein gültiger Kandidat gewählt - nichts geändert."
        docker rmi "$rb" >/dev/null 2>&1
        return 0
      fi
    else
      info "Kein neueres Image verfügbar. Später erneut versuchen."
      docker rmi "$rb" >/dev/null 2>&1
      return 0
    fi
  fi
  if [ -z "$newver" ]; then warn "PHP-Version im neuen Image ($tgtref) nicht ermittelbar - Update wird nicht angeboten. Rückfall-Tag: $rb"; return 0; fi
  if ! ver_fixed "$newver"; then
    warn "Das neue Image ($tgtref) enthält PHP $newver - weiterhin NICHT gepatcht. Container bleibt unverändert."
    return 0
  fi
  ok "Gepatchtes Image verfügbar ($tgtref): PHP $newver"

  if [ "$managed" -ne 1 ]; then
    cat <<EOF | indent
Manuelles Update (kein Compose-Label gefunden):
  1. Container stoppen (verhindert Datei-Locks beim Backup): docker stop $c
  2. Backup der Volumes/Datenbank anlegen.
  3. Startoptionen sichern: docker inspect $c > $c-inspect.json
  4. docker rename $c ${c}-alt
  5. Container mit denselben Optionen neu aus '$tgtref' starten.
  6. Prüfen, danach ${c}-alt entfernen. Rückfall: Image-Tag $rb.
EOF
    return 0
  fi
  if ! dk_compose_setup "$c"; then
    warn "Compose nicht nutzbar - bitte manuell aktualisieren."
    return 0
  fi
  if [ "$switch" -eq 1 ]; then
    mapfile -t tfiles < <(dk_tag_files "$c" "$ref")
    if [ "${#tfiles[@]}" -eq 0 ]; then
      warn "Der Tag '$ref' steht nicht wörtlich in den Compose-Dateien/.env. Bitte Tag selbst auf '${tgtref##*:}' ändern und 'docker compose down && docker compose up -d' ausführen."
      return 0
    fi
  fi

  RISKS=()
  oldlab=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$oldid" 2>/dev/null)
  newlab=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$newid" 2>/dev/null)
  if [ -n "$oldlab" ] && [ "$oldlab" = "$newlab" ]; then
    info "Image-Version laut Label unverändert ($oldlab) - reiner PHP-/Basis-Update."
  else
    risk "Die App-/Image-Version ändert sich (alt: ${oldlab:-${ref##*:}} -> neu: ${newlab:-${tgtref##*:}}). Eine neue App-Version kann DB-Migrationen ausführen."
  fi
  if [ "$switch" -eq 1 ]; then risk "Der gepinnte Tag wird in deiner Compose-Konfiguration geändert (${tfiles[*]}): '$ref' -> '$tgtref' (Originale werden gesichert)."; fi
  if [ "$switch" -eq 1 ] && [ "${tgtref##*:}" = "latest" ]; then
    risk "'latest' ist ein BEWEGLICHER Tag."
  fi
  "${COMPOSE[@]}" "${CARGS[@]}" config -q >/dev/null 2>&1 || risk "Die Compose-Konfiguration ist schon JETZT nicht gültig ('config' schlägt fehl)."
  st=$(dk_inspect '{{.State.Status}}' "$c"); h=$(dk_inspect '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c")
  if [ "$st" != "running" ] || { [ -n "$h" ] && [ "$h" != "healthy" ]; }; then
    risk "Der Container ist schon JETZT nicht gesund (Status $st${h:+, Health $h})."
  fi
  sib=$(docker ps --filter "label=com.docker.compose.project=$proj" --format '{{.Names}}' 2>/dev/null)
  for d in $sib; do
    case "$(dk_inspect '{{.Config.Image}}' "$d")" in *mysql*|*mariadb*|*postgres*) DBS+=("$d") ;; esac
  done
  if [ "${#DBS[@]}" -gt 0 ]; then info "Datenbank-Container im Projekt: ${DBS[*]} - vor dem Stoppen wird ein Online-Dump versucht."
  else info "Kein MySQL/MariaDB/PostgreSQL-Container erkannt - Datenbank/Files (z. B. SQLite) werden nach 'docker compose down' über das Mount-Backup gesichert."; fi
  common_risks
  explain "Container '$c' (Compose-Projekt '$proj') mit 'docker compose down' sichern & updaten" "mittel-hoch" \
    "1) Zustand festhalten & Online-DB-Dump 2) 'docker compose down' (beendet Container sauber, gibt alle Datei-/DB-Locks frei) 3) Konsistentes Backup der Compose-Dateien, .env und Container-Mounts/Volumes 4) $([ "$switch" -eq 1 ] && echo "Tag ändern -> ")'docker compose up -d' 5) Nachprüfung -> bei Regression automatisch zurück." \
    "Durch 'docker compose down' ist das Compose-Projekt während des Backups und Neustarts kurzzeitig gestoppt." \
    "Checkbox [6] in der TUI wieder abwählen (stellt altes Image/Compose-Tag wieder her)"
  confirm_risky "Container jetzt mit 'docker compose down' stoppen, sichern und umstellen?" || { info "Nichts geändert. Rückfall-Tag $rb bleibt bestehen."; return 0; }

  ensure_backup || return 0
  bd="$BACKUP_DIR/docker/$proj"
  mkdir -p "$bd" && chmod 700 "$BACKUP_DIR/docker" "$bd"
  ask_probe_urls

  snapshot_state
  before=$(dk_project_states "$proj")
  docker inspect "$c" > "$bd/inspect-$c.json" 2>/dev/null
  for d in ${DBS[@]+"${DBS[@]}"}; do
    if dk_db_dump "$d" "$bd/db-$d.sql"; then ok "Online-DB-Dump von $d: $bd/db-$d.sql ($(stat -c %s "$bd/db-$d.sql") Bytes)"
    else warn "Online-DB-Dump von $d fehlgeschlagen - führe gleich nach 'docker compose down' ein kaltes Backup der gemounteten Verzeichnisse durch."; dumpfail=1; fi
  done

  info "Stoppe Compose-Projekt '$proj' mit '${COMPOSE[*]} down', um Datei-Locks für Backup und Update freizugeben ..."
  alog "Docker: '${COMPOSE[*]} down' für Projekt $proj (Container $c)"
  if "${COMPOSE[@]}" "${CARGS[@]}" down; then
    stack_down=1
    ok "Compose-Projekt '$proj' sauber beendet."
  else
    warn "'${COMPOSE[*]} down' meldete einen Fehler - versuche Container '$c' direkt zu stoppen ..."
    docker stop "$c" >/dev/null 2>&1 || true
  fi

  IFS=',' read -ra cf <<< "${DK_FILES[$c]}"
  for f in "${cf[@]}"; do cp -p "$f" "$bd/"; done
  for f in ${tfiles[@]+"${tfiles[@]}"}; do cp -p "$f" "$bd/orig-${f//\//_}"; done
  if [ -f "${DK_DIR[$c]}/.env" ]; then cp -p "${DK_DIR[$c]}/.env" "$bd/dot-env"; fi
  dk_mount_backup "$c" "$bd" || dumpfail=1

  printf 'Rückfall-Tag: %s\nAlte Image-ID: %s\nImage-Referenz: %s (Ziel: %s)\nManuell zurück: docker compose --project-directory %s -p %s down && docker tag %s %s && docker compose --project-directory %s -p %s up -d\n' \
    "$rb" "$oldid" "$ref" "$tgtref" "${DK_DIR[$c]}" "$proj" "$rb" "${ref%%@*}" "${DK_DIR[$c]}" "$proj" > "$bd/ROLLBACK.txt"
  chmod 600 "$bd"/* 2>/dev/null

  if [ "$dumpfail" -eq 1 ]; then
    if ! confirm_word "Ein Teil des Backups war unvollständig. Trotzdem mit dem Update fortfahren?" "OHNE-BACKUP"; then
      info "Abgebrochen - starte das unveränderte Compose-Projekt wieder ..."
      [ "$stack_down" -eq 1 ] && "${COMPOSE[@]}" "${CARGS[@]}" up -d
      return 0
    fi
  fi

  if [ "$switch" -eq 1 ]; then
    old_e=$(printf '%s' "$ref" | sed 's/[][\.*^$|/&]/\\&/g'); new_e=$(printf '%s' "$tgtref" | sed 's/[&|\\]/\\&/g')
    for f in "${tfiles[@]}"; do sed -i "s|$old_e|$new_e|g" "$f"; done
    if ! "${COMPOSE[@]}" "${CARGS[@]}" config -q >/dev/null 2>&1; then
      crit "Compose-Konfiguration nach der Tag-Änderung ungültig - Dateien werden zurückgesetzt und alter Stand wieder gestartet."
      for f in "${tfiles[@]}"; do cp -p "$bd/orig-${f//\//_}" "$f"; done
      "${COMPOSE[@]}" "${CARGS[@]}" up -d
      return 0
    fi
    info "Tag in ${tfiles[*]} geändert: $ref -> $tgtref"
  fi

  alog "Docker-Update gestartet: $c ($ref -> $tgtref) -> $newid (PHP $newver)"
  info "Starte Compose-Projekt '$proj' mit dem aktualisierten Image ('${COMPOSE[*]} up -d') ..."
  if "${COMPOSE[@]}" "${CARGS[@]}" up -d && dk_verify "$c" "$proj" "$before"; then
    ok "Nachprüfung bestanden: Container läuft mit PHP $newver, Projekt-Container, Ports und HTTP-Antworten unverändert."
    alog "Docker-Update erfolgreich: $c"
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$c" "$ref" "$rb" "$svc" "$switch" "$bd" "${tfiles[*]:-}" >> "$STATE_DIR/docker_updated"
    DK_IMG[$c]="$tgtref"
    dk_recheck "$c"
    dk_unvuln "$c"
  else
    crit "Update oder Nachprüfung NEGATIV - Rollback auf das alte Image."
    alog "Docker-Update Regression -> Rollback: $c"
    if [ "$switch" -eq 1 ]; then dk_rollback_switch "$c" "$svc" "$bd" "${tfiles[@]}" && rbok=0
    else dk_rollback "$c" "$ref" "$rb" "$svc" && rbok=0; fi
    if [ "$rbok" -eq 0 ] && dk_verify_rollback "$c" "$proj" "$before"; then
      warn "Rollback erfolgreich, Zustand wie vorher (PHP weiterhin UNGEPATCHT)."
    else
      crit "Auch nach dem Rollback weicht der Zustand ab - bitte manuell prüfen. Sicherungen: $bd"
    fi
  fi
}

dk_verify_rollback() {
  local c="$1" proj="$2" before="$3" bad=0 l after
  dk_wait_ready "$c" || { crit "Container $c wird nach dem Rollback nicht 'running'/'healthy'."; bad=1; }
  after=$(dk_project_states "$proj")
  while read -r l; do
    [ -n "$l" ] || continue
    case "$l" in *" running") printf '%s\n' "$after" | grep -qxF "$l" || { crit "Projekt-Container nicht mehr running: ${l% *}"; bad=1; } ;; esac
  done <<< "$before"
  verify_state || bad=1
  return $bad
}

act_docker_update() {
  dk_available || { info "Docker nicht verfügbar."; return 0; }
  if [ "${#DK_VULN[@]}" -eq 0 ]; then info "Alle laufenden PHP-Container sind bereits auf einem sicheren Stand (Notfall-Update aktiv)."; return 0; fi
  local c
  for c in "${DK_VULN[@]}"; do dk_update_one "$c"; done
}

undo_docker_update() {
  [ -f "$STATE_DIR/docker_updated" ] || { info "Kein durch dieses Skript durchgeführtes Docker-Update zum Zurückrollen protokolliert (Container lief bereits vorher auf der aktuellen Version)."; return 0; }
  explain "Rückabwicklung #6: Aktualisierte Docker-Container auf das alte Image zurückrollen" "hoch" \
    "Stoppt das Compose-Projekt mit 'docker compose down', stellt den gesicherten Rollback-Tag bzw. die originalen Compose-Dateien wieder her und startet den Stack neu." \
    "WARNUNG: Der Container läuft danach wieder mit dem alten, ungepatchten PHP-Image!" \
    "Erneut über Maßnahme 6 aktualisieren"
  confirm_word "Container-Update wirklich auf das ungepatchte Image zurückrollen?" "ROLLBACK" || return 0
  local line c ref rb svc switch bd tf_str tfiles=()
  while IFS='|' read -r c ref rb svc switch bd tf_str; do
    [ -n "$c" ] || continue
    if dk_compose_setup "$c"; then
      if [ "$switch" = "1" ] && [ -n "$tf_str" ]; then
        read -ra tfiles <<< "$tf_str"
        dk_rollback_switch "$c" "$svc" "$bd" "${tfiles[@]}" && ok "Container $c erfolgreich auf alten Stand zurückgerollt."
      else
        dk_rollback "$c" "$ref" "$rb" "$svc" && ok "Container $c erfolgreich auf $rb zurückgerollt."
      fi
      alog "Rückabwicklung #6: Docker-Container $c zurückgerollt auf $rb"
    else
      warn "Compose-Setup für $c nicht möglich - siehe $bd/ROLLBACK.txt"
    fi
  done < "$STATE_DIR/docker_updated"
  rm -f "$STATE_DIR/docker_updated"
}

# --- Maßnahme 7: BSI-Drop-in (upload_progress, fatal_error_backtraces, post_max_size) & Rückabwicklung ---

act_mitig_bsi_ini() {
  local dirs=() d mode pms="32M" umf="16M"
  mapfile -t dirs < <(confd_dirs)
  if [ "${#dirs[@]}" -eq 0 ]; then warn "Keine conf.d-Verzeichnisse auf dem Host gefunden (läuft PHP ausschließlich im Docker-Container?)."; return 0; fi
  explain "BSI-Workaround-Paket (php.ini Drop-in: upload_progress, fatal_error_backtraces, post_max_size)" "niedrig-mittel" \
    "Legt $MARK_INI in ${#dirs[@]} conf.d-Verzeichnis(sen) an:
     - session.upload_progress.enabled = 0  (BSI-Workaround für CVE-2026-109619)
     - fatal_error_backtraces = 0           (BSI-Workaround für CVE-2026-109619 unter PHP 8.5)
     - post_max_size = 8M (ohne Uploads) bzw. 32M (mit Uploads) + angepasstes upload_max_filesize (BSI-Workaround für CVE-2026-109618)
     - expose_php = 0                       (verhindert Versions-Leak über X-Powered-By Header)
     - display_errors = Off                 (verhindert Adress-Leaks und ASLR-Bypasses)
     - session.use_strict_mode = 1          (verhindert Session-Fixation und uninitialisierte Session-IDs)" \
    "Upload-Fortschrittsbalken über Sessions sind deaktiviert; Request-Body-Größe wird auf 8M bzw. 32M begrenzt. Wirksam erst nach Dienst-Neustart." \
    "Checkbox [7] in der TUI wieder abwählen (entfernt $MARK_INI wieder)"
  tty_read -r -p "Benötigen deine Webanwendungen Datei-Uploads? [J/n] (j = post_max_size 32M, n = post_max_size 8M laut BSI): " mode || return 0
  case "$mode" in
    n|N|nein|Nein) pms="8M"; umf="4M" ;;
    *)             pms="32M"; umf="16M" ;;
  esac
  confirm "BSI-Workaround-Drop-in (post_max_size=$pms) jetzt anlegen?" || return 0
  ensure_backup || return 0
  for d in "${dirs[@]}"; do
    cat > "$d/$MARK_INI" <<EOF
; php2shell-check.sh: temporäre BSI-Notmaßnahme (CVE-2026-109618 / CVE-2026-109619), nach Patch entfernen
session.upload_progress.enabled = 0
fatal_error_backtraces = 0
post_max_size = $pms
upload_max_filesize = $umf
expose_php = 0
display_errors = Off
session.use_strict_mode = 1
EOF
    chmod 644 "$d/$MARK_INI"
    info "angelegt: $d/$MARK_INI"
  done
  alog "BSI-Mitigation ($MARK_INI, post_max_size=$pms) angelegt in: ${dirs[*]}"
  info "WICHTIG (BSI): Jetzt alle PHP-/Webserver-Worker neu starten (Maßnahme 10), sonst greift die Änderung nicht."
}

undo_mitig_bsi_ini() {
  local files=() f
  mapfile -t files < <(find /etc/php /etc/php.d /usr/local/etc/php /etc/opt/remi /opt/remi -name "$MARK_INI" 2>/dev/null || true)
  [ "${#files[@]}" -gt 0 ] || { info "Keine $MARK_INI-Dateien vorhanden."; return 0; }
  explain "Rückabwicklung #7: BSI-Drop-in ($MARK_INI) wieder entfernen" "niedrig-mittel" \
    "Löscht ${#files[@]} Drop-in-Datei(en): ${files[*]}" \
    "Die temporären Einschränkungen (upload_progress=0, post_max_size, fatal_error_backtraces=0) entfallen nach dem nächsten Dienst-Neustart." \
    "Checkbox [7] wieder aktivieren"
  confirm "BSI-Drop-in ($MARK_INI) jetzt entfernen?" || return 0
  for f in "${files[@]}"; do rm -f -- "$f" && ok "entfernt: $f"; done
  alog "Rückabwicklung #7: $MARK_INI entfernt (${files[*]})"
  if confirm "PHP-/Webserver-Dienste jetzt direkt neu starten, damit die Rückabwicklung wirksam wird?"; then act_restart; fi
}

# --- Maßnahme 8: BSI-Workaround memory_limit = -1 & Rückabwicklung ---

act_mitig_mem() {
  local files=() f
  mapfile -t files < <(pool_files)
  if [ "${#files[@]}" -eq 0 ]; then warn "Keine FPM-Pool-Dateien auf dem Host gefunden."; return 0; fi
  explain "BSI-Workaround für CVE-2026-109618: php_admin_value[memory_limit] = -1 in ${#files[@]} Pool-Datei(en)" "hoch" \
    "Trägt in jeden FPM-Pool 'php_admin_value[memory_limit] = -1' ein (Markierung $MARK_MEM), sodass Anwendungen kein endliches Limit setzen können." \
    "BSI-WARNUNG: Verhindert den kontrollierbaren PHP-Speicherlimit-Überlauf (CVE-2026-109618), ABER ein einzelner Request kann den gesamten RAM belegen (DoS). Laut BSI mit cgroup-Limits kombinieren (NICHT RLIMIT_AS/RLIMIT_DATA nutzen!)." \
    "Checkbox [8] in der TUI wieder abwählen (bereinigt die FPM-Pool-Dateien wieder)"
  confirm_word "Wirklich fortfahren?" "JA" || return 0
  ensure_backup || return 0
  mkdir -p "$BACKUP_DIR/pools"
  for f in "${files[@]}"; do
    grep -q "$MARK_MEM" "$f" 2>/dev/null && continue
    cp -p "$f" "$BACKUP_DIR/pools/${f//\//_}"
    sed -i "/^\[[^]]\+\]\$/a ; $MARK_MEM\nphp_admin_value[memory_limit] = -1" "$f"
  done
  local b bad=0
  for b in $(find_php_binaries | grep -E 'php-fpm'); do
    "$b" -t >/dev/null 2>&1 || { bad=1; crit "Konfigtest fehlgeschlagen für $b"; }
  done
  if [ "$bad" -eq 1 ]; then
    for f in "${files[@]}"; do [ -f "$BACKUP_DIR/pools/${f//\//_}" ] && cp -p "$BACKUP_DIR/pools/${f//\//_}" "$f"; done
    crit "Änderung automatisch zurückgerollt (Konfigtest fehlgeschlagen)."
    alog "memory_limit-Mitigation zurückgerollt"
    return 0
  fi
  alog "memory_limit=-1 gesetzt in: ${files[*]}"
  ok "Pool-Dateien angepasst, Konfigtest ok. Dienste neu starten (Maßnahme 10), damit es greift."
}

undo_mitig_mem() {
  local pools=() pf
  for pf in $(pool_files); do grep -q "$MARK_MEM" "$pf" 2>/dev/null && pools+=("$pf"); done
  [ "${#pools[@]}" -gt 0 ] || { info "Keine $MARK_MEM-Einträge in FPM-Pools gefunden."; return 0; }
  explain "Rückabwicklung #8: memory_limit = -1 aus FPM-Pool-Dateien entfernen" "niedrig-mittel" \
    "Entfernt die Zeile '; $MARK_MEM' und das folgende 'php_admin_value[memory_limit] = -1' aus ${#pools[@]} Pool-Datei(en): ${pools[*]}" \
    "Es gilt wieder das reguläre memory_limit aus der php.ini bzw. dem Pool." \
    "Checkbox [8] wieder aktivieren"
  confirm "memory_limit=-1 jetzt aus den FPM-Pools entfernen?" || return 0
  ensure_backup || return 0
  for pf in "${pools[@]}"; do
    sed -i "/^; $MARK_MEM\$/,+1d" "$pf" && ok "bereinigt: $pf"
  done
  alog "Rückabwicklung #8: memory_limit=-1 aus FPM-Pools entfernt (${pools[*]})"
  if confirm "PHP-/Webserver-Dienste jetzt direkt neu starten, damit die Rückabwicklung wirksam wird?"; then act_restart; fi
}

# --- Maßnahme 9: Webserver-/cgroup-Snippets erzeugen & Rückabwicklung ---

act_snippets() {
  explain "Webserver-/Proxy-&-cgroup-Snippets erzeugen (BSI / Abstract Security / Sansec)" "keine (nur Dateien, KEINE Änderung am laufenden System)" \
    "Schreibt Vorlagen nach $SNIPPET_DIR:
     1) nginx/Apache: Request-Größen, Header-Limits & optional multipart/form-data blocken (auch für Chunked-Requests ohne Content-Length!)
     2) Rate-Limiting gegen die ASLR-Brute-Force-Phase (~590 große POSTs pro IP)
     3) systemd cgroup-Speicherbegrenzung (MemoryMax/OOMPolicy) gemäß BSI-Empfehlung zu memory_limit=-1" \
    "Reine Vorlagendateien in $SNIPPET_DIR; Einbau und Test machst du bewusst selbst." \
    "Checkbox [9] wieder abwählen (löscht $SNIPPET_DIR)"
  confirm "Snippets jetzt erzeugen?" || return 0
  mkdir -p "$SNIPPET_DIR" && chmod 700 "$SNIPPET_DIR"
  cat > "$SNIPPET_DIR/nginx-php2shell-mitigation.conf" <<'EOF'
# === BSI & Abstract Security Empfehlungen für nginx ===
limit_req_zone $binary_remote_addr zone=php2shell_post:10m rate=10r/m;

# In JEDEN server{}-Block einfügen, der PHP bedient:
client_max_body_size 8m;         # Auf 32m erhöhen, falls Datei-Uploads zwingend nötig sind (BSI)
client_body_buffer_size 128k;
large_client_header_buffers 4 8k;

# Optional (Notmaßnahme laut Sansec, falls gar keine Uploads/Multipart-Formulare benötigt werden):
# if ($http_content_type ~* "multipart/form-data") {
#     return 403;
# }
EOF
  cat > "$SNIPPET_DIR/apache-php2shell-mitigation.conf" <<'EOF'
# === BSI & Abstract Security Empfehlungen für Apache httpd ===
LimitRequestBody 8388608
LimitRequestFields 100
LimitRequestFieldSize 8190

# Falls mod_php genutzt wird, empfiehlt das BSI für CVE-2026-109618 zusätzlich:
# php_admin_value memory_limit -1
EOF
  cat > "$SNIPPET_DIR/systemd-cgroup-fpm.conf" <<'EOF'
# === BSI-Empfehlung zu CVE-2026-109618 (Kompensation für memory_limit = -1) ===
# Ablage z. B. unter: /etc/systemd/system/php8.4-fpm.service.d/php2shell-cgroup.conf
# WICHTIG (BSI): NICHT LimitAS= oder LimitDATA= (RLIMIT_AS/RLIMIT_DATA) nutzen!
[Service]
MemoryMax=2G
OOMPolicy=continue
EOF
  ok "Snippets und BSI-Konfigurationsvorlagen liegen in $SNIPPET_DIR"
  alog "Snippets erzeugt: $SNIPPET_DIR"
}

undo_snippets() {
  [ -d "$SNIPPET_DIR" ] || { info "Verzeichnis $SNIPPET_DIR ist nicht vorhanden."; return 0; }
  explain "Rückabwicklung #9: Erzeugte Snippet-Vorlagen ($SNIPPET_DIR) löschen" "keine" \
    "Entfernt den Vorlagen-Ordner $SNIPPET_DIR" \
    "Falls du Teile daraus manuell in /etc/nginx oder /etc/apache2 kopiert hast, bitte dort ebenfalls entfernen." \
    "Checkbox [9] wieder aktivieren"
  confirm "Ordner $SNIPPET_DIR jetzt löschen?" || return 0
  rm -rf -- "$SNIPPET_DIR"
  ok "Snippet-Ordner $SNIPPET_DIR entfernt."
  alog "Rückabwicklung #9: $SNIPPET_DIR gelöscht"
}

# --- Maßnahme 10: Dienste neu starten ---

act_restart() {
  local svcs=() s v bin
  mapfile -t svcs < <(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -E '^(php[0-9.]*-fpm|php-fpm|apache2|httpd|frankenphp|lshttpd|lsws)')
  if [ "${#svcs[@]}" -eq 0 ]; then info "Keine laufenden PHP-/Webserver-Dienste per systemd auf dem Host gefunden (Services laufen im Docker-Container)."; return 0; fi
  explain "Dienste neu starten" "mittel" "Konfigtest, dann 'systemctl restart' für: ${svcs[*]}" \
    "Kurze Downtime (ca. 1-3 s), laufende Requests/Uploads brechen ab, Opcache wird geleert. Nötig, damit gepatchte Binaries und Mitigationen wirklich laufen." \
    "Nicht nötig - bei Fehlern Konfig aus Backup zurückspielen und erneut starten"
  if [ "$COMP" -gt 0 ]; then warn "Verdacht auf Befall: erst 'Beweise sichern' (Maßnahme 1) - ein Neustart löscht den Speicherzustand!"; fi
  confirm "Dienste jetzt neu starten?" || return 0
  for s in "${svcs[@]}"; do
    case "$s" in
      php-fpm.service) bin="php-fpm" ;;
      php*-fpm.service) v="${s#php}"; v="${v%-fpm.service}"; bin="php-fpm$v" ;;
      apache2.service) bin="apachectl" ;;
      httpd.service)   bin="httpd" ;;
      *) bin="" ;;
    esac
    case "$s" in
      apache2.service) apachectl configtest >/dev/null 2>&1 || { crit "Konfigtest für $s fehlgeschlagen - NICHT neu gestartet"; continue; } ;;
      httpd.service)   httpd -t >/dev/null 2>&1 || { crit "Konfigtest für $s fehlgeschlagen - NICHT neu gestartet"; continue; } ;;
      php*fpm*)        command -v "$bin" >/dev/null 2>&1 && { "$bin" -t >/dev/null 2>&1 || { crit "Konfigtest für $s fehlgeschlagen - NICHT neu gestartet"; continue; }; } ;;
    esac
    if systemctl restart "$s"; then ok "$s neu gestartet"; alog "Neustart $s"; else crit "Neustart von $s fehlgeschlagen"; fi
  done
  STALE=0
}

# --- Maßnahme 11: Session-Dateien in Quarantäne & Rückabwicklung ---

act_sessions() {
  local d n total=0
  for d in $(session_dirs); do
    n=$(find "$d" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | wc -l)
    total=$((total+n))
    info "$d: $n Session-Dateien"
  done
  [ "$total" -gt 0 ] || { info "Keine Session-Dateien auf dem Host gefunden."; return 0; }
  explain "Session-Dateien in Quarantäne verschieben" "mittel" \
    "Verschiebt alle sess_*-Dateien ($total) nach /root/php2shell-quarantine-*/sessions (inkl. Pfad-Index für Rückabwicklung)" \
    "ALLE Benutzer werden abgemeldet; Warenkörbe/Formularzustände in Sessions gehen verloren. Entzieht vorab eingeschleusten Session-Dateien die Wirkung." \
    "Checkbox [11] in der TUI wieder abwählen (stellt die Session-Dateien am Originalort wieder her)"
  confirm "Sessions verschieben?" || return 0
  ensure_quar
  mkdir -p "$QUAR_DIR/sessions" && chmod 700 "$QUAR_DIR/sessions"
  local f base
  for d in $(session_dirs); do
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      base=$(basename "$f")
      mv -- "$f" "$QUAR_DIR/sessions/$base" && printf '%s|%s\n' "$QUAR_DIR/sessions/$base" "$f" >> "$QUAR_DIR/sessions-index.txt"
    done < <(find "$d" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null)
  done
  ok "Sessions verschoben nach $QUAR_DIR/sessions"
  alog "Sessions in Quarantäne: $QUAR_DIR/sessions ($total)"
}

undo_sessions() {
  ensure_quar
  local qdir="" idx="" count=0 src dst
  for qdir in $(ls -dt /root/php2shell-quarantine-* 2>/dev/null); do
    if [ -f "$qdir/sessions-index.txt" ]; then idx="$qdir/sessions-index.txt"; break; fi
  done
  [ -n "$idx" ] || { info "Keine verschobenen Session-Dateien in der Quarantäne gefunden."; return 0; }
  explain "Rückabwicklung #11: Session-Dateien aus Quarantäne wiederherstellen" "mittel" \
    "Verschiebt die in $idx verzeichneten Session-Dateien zurück in ihr ursprüngliches Session-Verzeichnis." \
    "WARNUNG: Nur ausführen, wenn die Session-Dateien geprüft wurden und keine Angreifer-Payloads enthalten!" \
    "Checkbox [11] wieder aktivieren"
  confirm "Session-Dateien jetzt aus der Quarantäne zurückschieben?" || return 0
  while IFS='|' read -r src dst; do
    if [ -f "$src" ] && [ -n "$dst" ]; then
      mv -- "$src" "$dst" && count=$((count+1))
    fi
  done < "$idx"
  rm -f -- "$idx"
  ok "$count Session-Datei(en) wiederhergestellt."
  alog "Rückabwicklung #11: $count Session-Dateien aus Quarantäne wiederhergestellt"
}

# --- Maßnahme 12: Verdächtige Dateien in Quarantäne & Rückabwicklung ---

act_quarantine() {
  if [ "${#FOUND_FILES[@]}" -eq 0 ]; then info "Keine verdächtigen Dateien aus dem Scan vorhanden."; return 0; fi
  printf '\nVerdächtige Dateien:\n'; printf '%s\n' "${FOUND_FILES[@]}" | indent
  explain "Verdächtige Dateien in Quarantäne verschieben" "mittel" \
    "Verschiebt die gelisteten Dateien (Pfad bleibt erhalten) nach /root/php2shell-quarantine-*/files, Rechte 000, Index mit Hash/Besitzer/Rechten" \
    "Bei Fehlalarm bricht die betroffene Seite/Funktion." \
    "Checkbox [12] in der TUI wieder abwählen (stellt Dateien inkl. Originalrechten & Besitzer wieder her)"
  if [ "$ATT" -gt 0 ] || [ "$COMP" -gt 0 ]; then warn "Hast du vorher 'Beweise sichern' (Maßnahme 1) ausgeführt? Erst danach verschieben."; fi
  confirm "Alle gelisteten Dateien verschieben?" || return 0
  ensure_quar
  mkdir -p "$QUAR_DIR/files" && chmod 700 "$QUAR_DIR/files"
  local f dest mode owner sha
  for f in "${FOUND_FILES[@]}"; do
    [ -f "$f" ] || continue
    dest="$QUAR_DIR/files$f"
    mkdir -p "$(dirname "$dest")"
    sha=$(sha256sum "$f" | cut -d' ' -f1)
    owner=$(stat -c '%U:%G' "$f")
    mode=$(stat -c '%a' "$f")
    printf '%s|%s|%s|%s|%s\n' "$dest" "$f" "$mode" "$owner" "$sha" >> "$QUAR_DIR/quarantine-restore.idx"
    printf '%s  %s %s  %s -> %s\n' "$sha" "$owner" "$mode" "$f" "$dest" >> "$QUAR_DIR/quarantine-index.txt"
    mv -- "$f" "$dest" && chmod 000 "$dest" && ok "verschoben: $f"
  done
  if [ "${#FOUND_CONF[@]}" -gt 0 ]; then
    warn "Diese .htaccess/.user.ini-Dateien wurden NICHT verschoben (Seite würde brechen) - verdächtige Zeilen bitte manuell prüfen:"
    printf '%s\n' "${FOUND_CONF[@]}" | sort -u | indent
  fi
  alog "Dateien in Quarantäne: $QUAR_DIR/files"
}

undo_quarantine() {
  local qdir="" idx="" src dst mode owner sha count=0
  for qdir in $(ls -dt /root/php2shell-quarantine-* 2>/dev/null); do
    if [ -f "$qdir/quarantine-restore.idx" ]; then idx="$qdir/quarantine-restore.idx"; break; fi
  done
  [ -n "$idx" ] || { info "Keine wiederherstellbaren Quarantäne-Dateien gefunden."; return 0; }
  explain "Rückabwicklung #12: Dateien aus Quarantäne an ihren Originalort zurückstellen" "hoch" \
    "Stellt die in $idx protokollierten Dateien inkl. ursprünglichen Dateirechten (chmod) und Besitzer (chown) am Originalpfad wieder her:" \
    "WARNUNG: Nur bei bestätigtem Fehlalarm (False Positive) ausführen! Echte Webshells wären danach wieder aktiv aufrufbar." \
    "Checkbox [12] wieder aktivieren"
  awk -F'|' '{printf "  %s (Rechte %s, %s)\n", $2, $3, $4}' "$idx"
  confirm_word "Quarantäne-Dateien wirklich an den Originalort zurückschieben?" "RESTORE" || return 0
  while IFS='|' read -r src dst mode owner sha; do
    if [ -f "$src" ] && [ -n "$dst" ]; then
      mkdir -p "$(dirname "$dst")"
      mv -- "$src" "$dst"
      chmod "$mode" "$dst" 2>/dev/null || true
      chown "$owner" "$dst" 2>/dev/null || true
      ok "wiederhergestellt: $dst ($owner, $mode)"
      FOUND_FILES+=("$dst")
      count=$((count+1))
    fi
  done < "$idx"
  rm -f -- "$idx"
  alog "Rückabwicklung #12: $count Datei(en) aus Quarantäne wiederhergestellt"
}

# --- Maßnahme 13: auditd-Überwachung & Rückabwicklung (inkl. Telegram-Option) ---

AUDIT_TG_WANT=""

act_auditd() {
  if ! command -v auditctl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1 && confirm "auditd ist noch nicht installiert. Jetzt via apt-get installieren?"; then
      apt-get update -qq 2>/dev/null || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y auditd audispd-plugins || return 1
    else
      warn "auditd ist nicht installiert (Debian/Ubuntu: apt install auditd). Danach erneut wählen."
      return 0
    fi
  fi
  local u uid users=()
  mapfile -t users < <(web_users)
  [ "${#users[@]}" -gt 0 ] || { warn "Keine Webserver-User gefunden."; return 0; }

  if [ ! -f "$AUDIT_RULE" ]; then
    explain "Überwachung: Prozessstarts durch Webserver-User mit auditd protokollieren" "niedrig-mittel" \
      "Legt $AUDIT_RULE an (execve b64 & b32 durch: ${users[*]}) und lädt die Regeln" \
      "Erkennt Shell-Starts durch PHP - das wichtigste verhaltensbasierte Signal. Rein beobachtend, blockiert nichts." \
      "Checkbox [13] in der TUI wieder abwählen (löscht $AUDIT_RULE und lädt Regeln neu)"
    confirm "Audit-Regel ($AUDIT_RULE) anlegen?" || return 0
    ensure_backup || return 0
    { echo "## php2shell-check.sh: Prozessstarts durch Webserver-User (Schlüssel php2shell_exec)"
      for u in "${users[@]}"; do
        uid=$(id -u "$u")
        echo "-a always,exit -F arch=b64 -S execve -F uid=$uid -k php2shell_exec"
        echo "-a always,exit -F arch=b32 -S execve -F uid=$uid -k php2shell_exec"
      done; } > "$AUDIT_RULE"
    if augenrules --load >/dev/null 2>&1 || auditctl -R "$AUDIT_RULE" >/dev/null 2>&1; then
      ok "Audit-Regel aktiv ($AUDIT_RULE)"
      alog "auditd-Regel angelegt"
    else
      warn "Regel geschrieben, aber augenrules --load meldete einen Fehler - 'auditctl -l' prüfen."
    fi
  else
    ok "Audit-Regel ($AUDIT_RULE) ist bereits eingerichtet."
  fi

  # Immer abfragen bzw. umsetzen, ob für auditd eine Telegram-Benachrichtigung gewünscht ist (auch wenn auditd schon aktiv war!)
  local want_tg="${AUDIT_TG_WANT:-}"
  if [ -z "$want_tg" ]; then
    if confirm "Sollen verdächtige Prozessstarts (auditd php2shell_exec) per Telegram-Bot gemeldet werden?"; then
      want_tg="1"
    else
      want_tg="0"
    fi
  fi

  if [ "$want_tg" = "1" ]; then
    TG_AUDIT=1
    if ! tg_is_configured && [ -z "$TG_TOKEN_IN" ]; then
      info "Für die auditd-Telegram-Benachrichtigung werden noch Bot-Token & Chat-ID benötigt:"
      tui_telegram_prompt_cli
    fi
    if [ -n "$TG_TOKEN_IN" ] || tg_is_configured; then
      TG_ON=1
      TG_AUDIT=1
      act_telegram
      tg_auditwatch_install
    else
      warn "Telegram ist nicht konfiguriert - auditd protokolliert vorerst nur lokal in /var/log/audit/audit.log."
    fi
  else
    TG_AUDIT=0
    tg_auditwatch_remove
    if [ -r "$TG_CONF" ]; then
      tg_conf_write "$(tg_conf_get TG_TOKEN)" "$(tg_conf_get TG_CHAT_ID)" "$(tg_conf_get TG_LABEL)" \
        "$(tg_conf_get TG_FAIL2BAN)" "$(tg_conf_get TG_RKHUNTER)" "$(tg_conf_get TG_CLAMAV)" "0"
    fi
    info "auditd-Telegram-Benachrichtigung deaktiviert (lokale Protokollierung in /var/log/audit/audit.log aktiv)."
  fi
  AUDIT_TG_WANT=""
}

undo_auditd() {
  [ -f "$AUDIT_RULE" ] || { info "Keine Audit-Regel ($AUDIT_RULE) vorhanden."; return 0; }
  explain "Rückabwicklung #13: auditd-Überwachungsregel ($AUDIT_RULE) entfernen" "niedrig" \
    "Löscht $AUDIT_RULE, stoppt ggf. it-reinbek-auditwatch und lädt die Audit-Regeln neu (augenrules --load / auditctl -D -k php2shell_exec)" \
    "Prozessstarts durch Webserver-User werden nicht mehr gesondert unter 'php2shell_exec' protokolliert." \
    "Checkbox [13] wieder aktivieren"
  confirm "Audit-Regel ($AUDIT_RULE) jetzt entfernen?" || return 0
  tg_auditwatch_remove
  rm -f -- "$AUDIT_RULE"
  auditctl -D -k php2shell_exec >/dev/null 2>&1 || true
  command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1 || true
  ok "Audit-Regel $AUDIT_RULE entfernt und entladen."
  alog "Rückabwicklung #13: $AUDIT_RULE entfernt"
}

# --- Maßnahme 14: Alle temporären Skript-Workarounds gesammelt entfernen ---

act_undo() {
  local f files=() pf
  mapfile -t files < <(find /etc/php /etc/php.d /usr/local/etc/php /etc/opt/remi /opt/remi -name "$MARK_INI" 2>/dev/null)
  [ -f "$AUDIT_RULE" ] && files+=("$AUDIT_RULE")
  local pools=()
  for pf in $(pool_files); do grep -q "$MARK_MEM" "$pf" 2>/dev/null && pools+=("$pf"); done
  if [ "${#files[@]}" -eq 0 ] && [ "${#pools[@]}" -eq 0 ]; then info "Keine von diesem Skript angelegten Mitigationen (#7, #8, #13) aktiv."; return 0; fi
  explain "Alle temporären Workarounds (#7, #8, #13) gesammelt zurücknehmen" "niedrig-mittel" \
    "Entfernt: ${files[*]:-} ${pools[*]:-} (nur von diesem Skript angelegte Einträge)" \
    "Schutz durch die Zwischenlösung entfällt - nur zurücknehmen, wenn PHP gepatcht ist. Dienste danach neu starten." \
    "Einzelne Checkboxen [7], [8] oder [13] wieder aktivieren"
  confirm "Alle genannten Workarounds jetzt zurücknehmen?" || return 0
  ensure_backup || return 0
  tg_auditwatch_remove
  for f in ${files[@]+"${files[@]}"}; do rm -f -- "$f" && info "entfernt: $f"; done
  for pf in ${pools[@]+"${pools[@]}"}; do sed -i "/^; $MARK_MEM\$/,+1d" "$pf" && info "bereinigt: $pf"; done
  auditctl -D -k php2shell_exec >/dev/null 2>&1 || true
  command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1
  alog "Alle temporären Workarounds zurückgenommen"
  if confirm "PHP-/Webserver-Dienste jetzt direkt neu starten (Maßnahme 10)?"; then act_restart; fi
}

# --- Maßnahme 18: Telegram-Bot & sichere Baustein-Benachrichtigungen (fail2ban, rkhunter, ClamAV, auditd) ---

TG_CONF="${TG_CONF:-/etc/it-reinbek/telegram.conf}"
TG_NOTIFY="${TG_NOTIFY:-/usr/local/sbin/it-reinbek-notify}"
TG_ON=0
TG_CUR=0
TG_ASKED_UPFRONT=0
TG_TOKEN_IN=""
TG_CHAT_IN=""
TG_LABEL_IN=""
TG_F2B=1
TG_RKH=1
TG_CLAM=1
TG_AUDIT=1
TG_VERIFY=""
TG_HTTP=""
TG_BODY=""

tg_valid_token() { [[ "$1" =~ ^[0-9]{6,12}:[A-Za-z0-9_-]{30,50}$ ]]; }
tg_valid_chat() { [[ "$1" =~ ^(-?[0-9]+|@[A-Za-z0-9_]{5,})$ ]]; }
tg_valid_label() { local re='^[A-Za-z0-9._ -]{0,40}$'; [[ "$1" =~ $re ]]; }
tg_conf_get() { [ -r "$TG_CONF" ] || return 0; sed -n "s/^$1=\(.*\)$/\1/p" "$TG_CONF" 2>/dev/null | head -n 1; }

tg_is_configured() {
  [ -r "$TG_CONF" ] && [ -x "$TG_NOTIFY" ] && tg_valid_token "$(tg_conf_get TG_TOKEN)" && tg_valid_chat "$(tg_conf_get TG_CHAT_ID)"
}

tg_cat_text() {
  local t=""
  [ "${1:-0}" = "1" ] && t="fail2ban"
  [ "${2:-0}" = "1" ] && t="${t:+$t, }rkhunter"
  [ "${3:-0}" = "1" ] && t="${t:+$t, }clamav"
  [ "${4:-0}" = "1" ] && t="${t:+$t, }auditd"
  if [ "$UI_LANG" = "en" ]; then
    echo "${t:-none}"
  else
    echo "${t:-keine}"
  fi
}

tg_api() {
  local tok="$1" meth="$2" out
  shift 2
  TG_HTTP=""; TG_BODY=""
  command -v curl >/dev/null 2>&1 || return 1
  out="$(printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$tok" "$meth" \
    | curl -sS --max-time 10 --proto '=https' --tlsv1.2 -K - -w '\n%{http_code}' "$@" 2>/dev/null)" || return 1
  TG_HTTP="${out##*$'\n'}"
  TG_BODY="${out%$'\n'*}"
  return 0
}

tg_check_token() {
  tg_api "$1" getMe || return 2
  case "$TG_HTTP" in
    200) case "$TG_BODY" in *'"ok":true'*) return 0 ;; esac; return 1 ;;
    401|404) return 1 ;;
    *) return 2 ;;
  esac
}

tg_check_chat() {
  tg_api "$1" getChat --data-urlencode "chat_id=$2" || return 2
  case "$TG_HTTP" in
    200) case "$TG_BODY" in *'"ok":true'*) return 0 ;; esac; return 1 ;;
    400|403|404) return 1 ;;
    *) return 2 ;;
  esac
}

tg_init() {
  TG_CUR=0
  if [ -r "$TG_CONF" ]; then
    local tok chat
    tok="$(tg_conf_get TG_TOKEN)"
    chat="$(tg_conf_get TG_CHAT_ID)"
    if tg_valid_token "$tok" && tg_valid_chat "$chat"; then
      TG_CUR=1
      TG_ON=1
    fi
    [ -z "$TG_TOKEN_IN" ] && TG_TOKEN_IN="$tok"
    [ -z "$TG_CHAT_IN" ] && TG_CHAT_IN="$chat"
    [ -z "$TG_LABEL_IN" ] && TG_LABEL_IN="$(tg_conf_get TG_LABEL)"
    local cf cr cc ca
    cf="$(tg_conf_get TG_FAIL2BAN)"; [ -n "$cf" ] && TG_F2B="$cf"
    cr="$(tg_conf_get TG_RKHUNTER)"; [ -n "$cr" ] && TG_RKH="$cr"
    cc="$(tg_conf_get TG_CLAMAV)";   [ -n "$cc" ] && TG_CLAM="$cc"
    ca="$(tg_conf_get TG_AUDITD)";   [ -n "$ca" ] && TG_AUDIT="$ca"
  else
    [ -z "$TG_TOKEN_IN" ] && TG_TOKEN_IN="${TELEGRAM_BOT_TOKEN:-}"
    [ -z "$TG_CHAT_IN" ] && TG_CHAT_IN="${TELEGRAM_CHAT_ID:-}"
    [ -z "$TG_LABEL_IN" ] && TG_LABEL_IN="${TELEGRAM_LABEL:-$(hostname 2>/dev/null || echo server)}"
    if [ -n "$TG_TOKEN_IN" ] && [ -n "$TG_CHAT_IN" ]; then TG_ON=1; fi
  fi
  [ -z "$TG_LABEL_IN" ] && TG_LABEL_IN="$(hostname 2>/dev/null || echo server)"
  [ -z "$TG_F2B" ] && TG_F2B=1
  [ -z "$TG_RKH" ] && TG_RKH=1
  [ -z "$TG_CLAM" ] && TG_CLAM=1
  [ -z "$TG_AUDIT" ] && TG_AUDIT=1
}

tg_conf_write() {
  # $1=token $2=chat $3=label $4=fail2ban $5=rkhunter $6=clamav $7=auditd
  # Gegen unerlaubten Zugriff geschuetzt: Ordner 700 (root:root), Datei atomar mit umask 077 & chmod 600 (root:root)
  local tmp dir
  dir="$(dirname "$TG_CONF")"
  install -d -m 700 "$dir"
  chown root:root "$dir" 2>/dev/null || true
  chmod 700 "$dir" 2>/dev/null || true
  tmp="$(umask 077; mktemp "${TG_CONF}.XXXXXX")"
  cat > "$tmp" << TGCONF_EOF
# IT-Reinbek Telegram-Benachrichtigung (verwaltet von php2shell-check.sh & it-reinbek-haertung.sh, Rechte 600, nur root)
TG_TOKEN=$1
TG_CHAT_ID=$2
TG_LABEL=$3
TG_FAIL2BAN=${4:-1}
TG_RKHUNTER=${5:-1}
TG_CLAMAV=${6:-1}
TG_AUDITD=${7:-1}
TGCONF_EOF
  chmod 600 "$tmp"
  chown root:root "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$TG_CONF"
  chmod 600 "$TG_CONF" 2>/dev/null || true
}

tg_notify_install() {
  install -d -m 755 "$(dirname "$TG_NOTIFY")"
  cat > "$TG_NOTIFY" << 'NOTIFY_EOF'
#!/usr/bin/env bash
# IT-Reinbek: Zentrale Telegram-Benachrichtigung (für fail2ban, rkhunter, clamav, auditd, php2shell).
# Aufruf: it-reinbek-notify <fail2ban|rkhunter|clamav|auditd|php2shell|test> <Text ...>
# Sicherheit: Liest /etc/it-reinbek/telegram.conf (0600 root:root) und übergibt den Bot-Token
# ausschließlich per stdin (curl -K -) – der Token taucht niemals in ps / /proc/*/cmdline auf!
# Rate-Limit: Gleiche Meldung max. alle 2 Min., max. 30 Meldungen pro Stunde & Kategorie.
set -u
CONF="__CONF__"
RUN="/run/it-reinbek-notify"
MAX_PER_HOUR=30
DEDUP_SEC=120

cat_arg="${1:-}"; shift || true
text="$*"
[ -r "$CONF" ] || exit 0
get() { sed -n "s/^$1=\(.*\)$/\1/p" "$CONF" | head -n 1; }
token="$(get TG_TOKEN)"; chat="$(get TG_CHAT_ID)"; label="$(get TG_LABEL)"
case "$cat_arg" in
  fail2ban)  [ "$(get TG_FAIL2BAN)" = "1" ] || exit 0 ;;
  rkhunter)  [ "$(get TG_RKHUNTER)" = "1" ] || exit 0 ;;
  clamav)    [ "$(get TG_CLAMAV)" = "1" ] || exit 0 ;;
  auditd)    [ "$(get TG_AUDITD)" = "1" ] || exit 0 ;;
  php2shell) ;;
  test)      ;;
  *) echo "Aufruf: $0 <fail2ban|rkhunter|clamav|auditd|php2shell|test> <Text>" >&2; exit 2 ;;
esac
re_tok='^[0-9]{6,12}:[A-Za-z0-9_-]{30,50}$'; re_chat='^(-?[0-9]+|@[A-Za-z0-9_]{5,})$'
[[ "$token" =~ $re_tok ]] || exit 0
[[ "$chat" =~ $re_chat ]] || exit 0
[ -n "$text" ] || exit 0
now="$(date +%s)"
if [ "$cat_arg" != "test" ]; then
  mkdir -p "$RUN"; chmod 700 "$RUN"
  h="$(printf '%s' "$text" | md5sum | cut -d' ' -f1)"
  if [ -r "$RUN/$cat_arg.last" ]; then
    read -r lh lt < "$RUN/$cat_arg.last" || true
    if [ "${lh:-}" = "$h" ] && [ $((now - ${lt:-0})) -lt "$DEDUP_SEC" ]; then exit 0; fi
  fi
  printf '%s %s\n' "$h" "$now" > "$RUN/$cat_arg.last"
  recent="$(awk -v n="$now" '$1 > n-3600' "$RUN/$cat_arg.log" 2>/dev/null | wc -l)"
  if [ "$recent" -ge "$MAX_PER_HOUR" ]; then
    [ "$recent" -eq "$MAX_PER_HOUR" ] || exit 0
    text="Limit von $MAX_PER_HOUR Meldungen pro Stunde erreicht - weitere Meldungen dieser Art werden bis zur vollen Stunde unterdrueckt."
  fi
  { awk -v n="$now" '$1 > n-3600' "$RUN/$cat_arg.log" 2>/dev/null; echo "$now"; } > "$RUN/$cat_arg.log.new" \
    && mv -f "$RUN/$cat_arg.log.new" "$RUN/$cat_arg.log"
fi
msg="[${label:-$(hostname)}] $cat_arg: $text"
tmp="$(umask 077; mktemp)"; chmod 600 "$tmp"; trap 'rm -f "$tmp"' EXIT
printf '%s' "$msg" | LC_ALL=C tr -d '\000-\010\013-\037\177' | head -c 3500 > "$tmp"
code="$(printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$token" \
  | curl -sS --max-time 15 --proto '=https' --tlsv1.2 -K - -o /dev/null -w '%{http_code}' \
      --data-urlencode "chat_id=$chat" --data-urlencode "text@$tmp" 2>/dev/null || true)"
if [ "$code" != "200" ]; then
  logger -t it-reinbek-notify "Telegram-Versand fehlgeschlagen (HTTP ${code:-keine Antwort})"
  exit 1
fi
exit 0
NOTIFY_EOF
  sed -i "s#__CONF__#${TG_CONF}#g" "$TG_NOTIFY"
  chmod 750 "$TG_NOTIFY"
  chown root:root "$TG_NOTIFY" 2>/dev/null || true
}

rkhunter_wrapper_install() {
  cat > /usr/local/sbin/it-reinbek-rkhunter << 'RKW_EOF'
#!/usr/bin/env bash
# IT-Reinbek: taeglicher rkhunter-Lauf. Meldet Warnungen/Fehler per Telegram, wenn eingerichtet.
set -uo pipefail
LOG=/var/log/rkhunter_cron.log
NOTIFY="__NOTIFY__"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
/usr/bin/rkhunter --check --sk > "$TMP" 2>&1; rc=$?
cat "$TMP" >> "$LOG"
if [ "$rc" -ne 0 ] && [ -x "$NOTIFY" ]; then
  W="$(grep -i 'warning' "$TMP" | head -n 15 | cut -c1-200)"
  "$NOTIFY" rkhunter "rkhunter meldet Warnung oder Fehler (Exit $rc). ${W:-Details: /var/log/rkhunter.log}" || true
fi
exit 0
RKW_EOF
  sed -i "s#__NOTIFY__#${TG_NOTIFY}#g" /usr/local/sbin/it-reinbek-rkhunter
  chmod 750 /usr/local/sbin/it-reinbek-rkhunter
  chown root:root /usr/local/sbin/it-reinbek-rkhunter 2>/dev/null || true
  if command -v rkhunter >/dev/null 2>&1; then
    cat > /etc/cron.d/rkhunter-daily << 'RK_EOF'
0 3 * * * root /usr/local/sbin/it-reinbek-rkhunter
RK_EOF
    chmod 644 /etc/cron.d/rkhunter-daily
  fi
}

tg_f2b_remove() {
  local had=0
  if [ -e /etc/fail2ban/action.d/it-reinbek-notify.conf ] || [ -e /etc/fail2ban/jail.d/it-reinbek-notify.local ]; then had=1; fi
  rm -f /etc/fail2ban/action.d/it-reinbek-notify.conf /etc/fail2ban/jail.d/it-reinbek-notify.local
  if [ "$had" = "1" ] && systemctl is-active --quiet fail2ban 2>/dev/null; then systemctl restart fail2ban 2>/dev/null || true; fi
}

tg_f2b_install() {
  command -v fail2ban-client >/dev/null 2>&1 || return 0
  install -d /etc/fail2ban/action.d /etc/fail2ban/jail.d
  cat > /etc/fail2ban/action.d/it-reinbek-notify.conf << 'F2BA_EOF'
# IT-Reinbek: Telegram-Meldung bei jeder Sperre
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = __NOTIFY__ fail2ban "Ban <ip> (Jail <name>, <failures> Fehlversuche)"
actionunban =
F2BA_EOF
  sed -i "s#__NOTIFY__#${TG_NOTIFY}#g" /etc/fail2ban/action.d/it-reinbek-notify.conf
  cat > /etc/fail2ban/jail.d/it-reinbek-notify.local << 'F2BJ_EOF'
# IT-Reinbek: Telegram-Meldung bei jeder Sperre (gilt fuer alle Jails ohne eigene action-Zeile)
[DEFAULT]
action = %(action_)s
         it-reinbek-notify
F2BJ_EOF
  if ! fail2ban-client -t >/dev/null 2>&1; then
    tg_f2b_remove
    warn "fail2ban-Konfigurationstest fehlgeschlagen - Telegram-Aktion für fail2ban wurde wieder entfernt."
    return 1
  fi
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    systemctl restart fail2ban 2>/dev/null || true
    sleep 1
    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
      tg_f2b_remove
      systemctl restart fail2ban 2>/dev/null || true
      warn "fail2ban startete mit Telegram-Aktion nicht - wurde zurückgenommen."
      return 1
    fi
  fi
  ok "fail2ban-Telegram-Benachrichtigung aktiv (/etc/fail2ban/action.d/it-reinbek-notify.conf)."
}

tg_clamwatch_remove() {
  systemctl disable --now it-reinbek-clamwatch >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/it-reinbek-clamwatch.service /usr/local/sbin/it-reinbek-clamwatch
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
}

tg_clamwatch_install() {
  cat > /usr/local/sbin/it-reinbek-clamwatch << 'CW_EOF'
#!/usr/bin/env bash
# IT-Reinbek: meldet ClamAV-Funde (On-Access und clamd) per Telegram. Laeuft als root und liest nur die Logdateien.
set -u
NOTIFY="__NOTIFY__"
LOGS=(/var/log/clamav/clamonacc.log)
cl="$(awk '$1=="LogFile"{print $2; exit}' /etc/clamav/clamd.conf 2>/dev/null)"
if [ -n "$cl" ]; then LOGS+=("$cl"); fi
mkdir -p /var/log/clamav 2>/dev/null || true
touch /var/log/clamav/clamonacc.log 2>/dev/null || true
tail -q -n 0 -F "${LOGS[@]}" 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    *" FOUND"*) "$NOTIFY" clamav "Fund: ${line:0:300}" || true ;;
  esac
done
CW_EOF
  sed -i "s#__NOTIFY__#${TG_NOTIFY}#g" /usr/local/sbin/it-reinbek-clamwatch
  chmod 750 /usr/local/sbin/it-reinbek-clamwatch
  chown root:root /usr/local/sbin/it-reinbek-clamwatch 2>/dev/null || true
  cat > /etc/systemd/system/it-reinbek-clamwatch.service << 'CWU_EOF'
[Unit]
Description=IT-Reinbek: ClamAV-Funde per Telegram melden
After=clamav-daemon.service

[Service]
ExecStart=/usr/local/sbin/it-reinbek-clamwatch
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
CWU_EOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable --now it-reinbek-clamwatch >/dev/null 2>&1 || warn "it-reinbek-clamwatch konnte nicht gestartet werden."
}

tg_auditwatch_remove() {
  systemctl disable --now it-reinbek-auditwatch >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/it-reinbek-auditwatch.service /usr/local/sbin/it-reinbek-auditwatch
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
}

tg_auditwatch_install() {
  [ -f /var/log/audit/audit.log ] || mkdir -p /var/log/audit 2>/dev/null || true
  cat > /usr/local/sbin/it-reinbek-auditwatch << 'AW_EOF'
#!/usr/bin/env bash
# IT-Reinbek: Überwacht /var/log/audit/audit.log auf php2shell_exec (Shell-/Prozessstarts durch Webserver-User)
# und meldet Treffer sofort per Telegram-Bot (läuft als root, Token bleibt in 0600 /etc/it-reinbek/telegram.conf).
set -u
NOTIFY="__NOTIFY__"
ALOG="/var/log/audit/audit.log"
[ -e "$ALOG" ] || touch "$ALOG" 2>/dev/null || true
tail -q -n 0 -F "$ALOG" 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    *'key="php2shell_exec"'*)
      case "$line" in
        *'exe="/usr/sbin/php-fpm'*|*'exe="/usr/bin/php'*) continue ;;
      esac
      "$NOTIFY" auditd "Verdächtiger Prozessstart durch Webserver-User (php2shell_exec): ${line:0:320}" || true
      ;;
  esac
done
AW_EOF
  sed -i "s#__NOTIFY__#${TG_NOTIFY}#g" /usr/local/sbin/it-reinbek-auditwatch
  chmod 750 /usr/local/sbin/it-reinbek-auditwatch
  chown root:root /usr/local/sbin/it-reinbek-auditwatch 2>/dev/null || true
  cat > /etc/systemd/system/it-reinbek-auditwatch.service << 'AWU_EOF'
[Unit]
Description=IT-Reinbek: auditd php2shell_exec Prozessstarts per Telegram melden
After=auditd.service

[Service]
ExecStart=/usr/local/sbin/it-reinbek-auditwatch
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
AWU_EOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable --now it-reinbek-auditwatch >/dev/null 2>&1 || warn "it-reinbek-auditwatch konnte nicht gestartet werden."
  ok "auditd-Telegram-Wächter (it-reinbek-auditwatch.service) aktiviert."
}

tui_telegram_prompt_cli() {
  tg_init
  local tok="$TG_TOKEN_IN" chat="$TG_CHAT_IN" label="${TG_LABEL_IN:-$(hostname)}"
  printf '\n%s--- Telegram-Bot Zugangsdaten (werden geschützt mit chmod 600 in %s abgelegt) ---%s\n' "$B$C" "$TG_CONF" "$N"
  tty_read -r -p "Bot-Token (von @BotFather, z.B. 123456789:AA...)${tok:+ [$tok]}: " input_tok || return 1
  tok="${input_tok:-$tok}"
  tok="${tok//[[:space:]]/}"
  if ! tg_valid_token "$tok"; then
    warn "Ungültiges Bot-Token-Format."
    return 1
  fi
  tty_read -r -p "Chat-ID (Zahl, bei Gruppe mit Minus, z.B. -100...)${chat:+ [$chat]}: " input_chat || return 1
  chat="${input_chat:-$chat}"
  chat="${chat//[[:space:]]/}"
  if ! tg_valid_chat "$chat"; then
    warn "Ungültiges Chat-ID-Format."
    return 1
  fi
  tty_read -r -p "Server-Name in Meldungen [$label]: " input_lbl || return 1
  label="${input_lbl:-$label}"
  TG_TOKEN_IN="$tok"
  TG_CHAT_IN="$chat"
  TG_LABEL_IN="$label"
  TG_ON=1
  return 0
}

act_telegram() {
  tg_init
  local tok chat label f2b rkh clam aud
  if [ -n "$TG_TOKEN_IN" ] && [ -n "$TG_CHAT_IN" ]; then
    tok="$TG_TOKEN_IN"
    chat="$TG_CHAT_IN"
    label="${TG_LABEL_IN:-$(hostname)}"
    f2b="${TG_F2B:-1}"
    rkh="${TG_RKH:-1}"
    clam="${TG_CLAM:-1}"
    aud="${TG_AUDIT:-1}"
  elif [ -r "$TG_CONF" ]; then
    tok="$(tg_conf_get TG_TOKEN)"
    chat="$(tg_conf_get TG_CHAT_ID)"
    label="$(tg_conf_get TG_LABEL)"
    f2b="$(tg_conf_get TG_FAIL2BAN)"
    rkh="$(tg_conf_get TG_RKHUNTER)"
    clam="$(tg_conf_get TG_CLAMAV)"
    aud="$(tg_conf_get TG_AUDITD)"
  else
    tui_telegram_prompt_cli || return 1
    tok="$TG_TOKEN_IN"; chat="$TG_CHAT_IN"; label="$TG_LABEL_IN"
    f2b="${TG_F2B:-1}"; rkh="${TG_RKH:-1}"; clam="${TG_CLAM:-1}"; aud="${TG_AUDIT:-1}"
  fi

  tg_valid_token "$tok" || { crit "Telegram: Bot-Token hat ein ungültiges Format."; return 1; }
  tg_valid_chat "$chat" || { crit "Telegram: Chat-ID hat ein ungültiges Format."; return 1; }
  tg_valid_label "$label" || label="$(hostname)"

  if ! command -v curl >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates || true
  fi

  tg_conf_write "$tok" "$chat" "$label" "${f2b:-1}" "${rkh:-1}" "${clam:-1}" "${aud:-1}"
  tg_notify_install
  ok "Telegram-Konfiguration sicher gespeichert in $TG_CONF (Ordner 0700, Datei 0600 root:root) & $TG_NOTIFY (0750)."
  info "Einstellungen für fail2ban (TG_FAIL2BAN=${f2b:-1}) und rkhunter (TG_RKHUNTER=${rkh:-1}) sind für alle Skripte vorgehalten."

  # Bausteine direkt anbinden, falls installiert/aktiv
  if [ "${f2b:-1}" = "1" ] && command -v fail2ban-client >/dev/null 2>&1; then
    tg_f2b_install
  else
    tg_f2b_remove
  fi

  rkhunter_wrapper_install

  clam_mode_detect
  if [ "${clam:-1}" = "1" ] && [ "$CLAM_MODE_CUR" = "live" ]; then
    tg_clamwatch_install
  else
    tg_clamwatch_remove
  fi
  if [ "$CLAM_MODE_CUR" = "cron" ] || [ -x /usr/local/sbin/clamav-scan.sh ]; then
    clam_write_scan_script
  fi

  if [ "${aud:-1}" = "1" ] && [ -f "$AUDIT_RULE" ]; then
    tg_auditwatch_install
  else
    tg_auditwatch_remove
  fi

  if "$TG_NOTIFY" test "PHP2Shell-Auditor & Server-Schutz: Benachrichtigungen aktiv fuer $(tg_cat_text "${f2b:-1}" "${rkh:-1}" "${clam:-1}" "${aud:-1}") (CRIT:$CRIT WARN:$WARN)"; then
    ok "Telegram: Testnachricht erfolgreich gesendet - bitte im Chat prüfen!"
  else
    warn "Telegram: Testnachricht konnte nicht gesendet werden (bitte Token, Chat-ID, /start beim Bot und Internetzugang prüfen)."
  fi
  TG_CUR=1
  TG_ON=1
  alog "Telegram-Benachrichtigungen eingerichtet für: $(tg_cat_text "${f2b:-1}" "${rkh:-1}" "${clam:-1}" "${aud:-1}")"
}

undo_telegram() {
  explain "Rückabwicklung #18: Telegram-Benachrichtigungen & gespeicherte Zugangsdaten entfernen" "niedrig" \
    "Stoppt it-reinbek-clamwatch & it-reinbek-auditwatch, entfernt die fail2ban-Action und löscht $TG_CONF sowie $TG_NOTIFY." \
    "Es werden keine Telegram-Meldungen mehr für fail2ban, rkhunter, ClamAV oder auditd versendet." \
    "Checkbox [18] wieder aktivieren"
  confirm "Telegram-Benachrichtigungen und Zugangsdaten ($TG_CONF) jetzt entfernen?" || return 0
  tg_f2b_remove
  tg_clamwatch_remove
  tg_auditwatch_remove
  rm -f "$TG_CONF" "$TG_NOTIFY"
  rm -rf /run/it-reinbek-notify
  TG_CUR=0
  TG_ON=0
  ok "Telegram-Benachrichtigungen und Zugangsdaten ($TG_CONF) vollständig entfernt."
  alog "Rückabwicklung #18: Telegram entfernt"
}

# --- Maßnahme 17: ClamAV Malwareschutz (Echtzeit clamd+clamonacc vs. Zeitplan/Cronjob) ---

CLAMAV_MODE="${CLAMAV_MODE:-}"                   # live | cron | none (leer = Vorschlag nach Arbeitsspeicher)
CLAMAV_LIVE_MIN_MB="${CLAMAV_LIVE_MIN_MB:-3500}" # Schwellenwert (MB frei) fuer Echtzeit-Vorschlag (clamd + clamonacc)
CLAMAV_CRON_MIN_MB="${CLAMAV_CRON_MIN_MB:-1800}" # Schwellenwert (MB frei) fuer Zeitplan-/Cronjob-Scan
CLAM_MODE_WANT=""
CLAM_MODE_CUR="none"
CLAM_REC="none"
CLAM_REC_WHY=""
CLAM_RAM_TXT=""
CLAM_EFF_MB=0
CLAM_TG_WANT=""

mem_mb() {
  awk -v k="$1:" '$1==k {printf "%d", $2/1024; f=1; exit} END{if(!f) print 0}' /proc/meminfo 2>/dev/null
}

clam_rss_mb() {
  ps -C clamd -o rss= 2>/dev/null | awk '{s+=$1} END{printf "%d", s/1024}'
}

clam_recommend() {
  local tot avail swap rss eff
  tot="$(mem_mb MemTotal)"
  avail="$(mem_mb MemAvailable)"
  swap="$(mem_mb SwapTotal)"
  rss="$(clam_rss_mb)"
  eff=$(( avail + ${rss:-0} ))
  CLAM_EFF_MB="$eff"

  if [ "$UI_LANG" = "en" ]; then
    CLAM_RAM_TXT="Total RAM ${tot} MB, effectively available ~${eff} MB (incl. running clamd), Swap ${swap} MB"
    if [ "$eff" -ge "$CLAMAV_LIVE_MIN_MB" ]; then
      CLAM_REC="live"
      CLAM_REC_WHY="${eff} MB available (real-time threshold: ${CLAMAV_LIVE_MIN_MB} MB). Continuous clamd + On-Access daemon (~1.5 GB RAM, briefly more during signature reload) fits comfortably."
    elif [ "$eff" -ge "$CLAMAV_CRON_MIN_MB" ]; then
      CLAM_REC="cron"
      CLAM_REC_WHY="${eff} MB available: sufficient for a scheduled daily scan (~1.5 GB only during scan run), but too tight for continuous real-time daemon (threshold ${CLAMAV_LIVE_MIN_MB} MB)."
    elif [ $(( eff + swap )) -ge "$CLAMAV_CRON_MIN_MB" ]; then
      CLAM_REC="cron"
      CLAM_REC_WHY="Only ${eff} MB RAM free - combined with Swap (${swap} MB) it is just enough for a nightly cron/timer scan. Real-time daemon would risk OOM."
    else
      CLAM_REC="none"
      CLAM_REC_WHY="Only ${eff} MB RAM free (Swap ${swap} MB): even a scheduled scan (~1.5 GB) could cause out-of-memory issues on this host."
    fi
  else
    CLAM_RAM_TXT="Arbeitsspeicher gesamt ${tot} MB, frei nutzbar ca. ${eff} MB (inkl. laufendem clamd), Swap ${swap} MB"
    if [ "$eff" -ge "$CLAMAV_LIVE_MIN_MB" ]; then
      CLAM_REC="live"
      CLAM_REC_WHY="Es sind ${eff} MB frei (Schwelle fuer Echtzeit: ${CLAMAV_LIVE_MIN_MB} MB). Der Dauerbetrieb von clamd + On-Access (ca. 1,5 GB RAM, beim Signatur-Reload kurzzeitig mehr) passt problemlos."
    elif [ "$eff" -ge "$CLAMAV_CRON_MIN_MB" ]; then
      CLAM_REC="cron"
      CLAM_REC_WHY="Es sind ${eff} MB frei: genug fuer einen geplanten Scan per Cron/Timer (ca. 1,5 GB nur waehrend des Laufs), aber zu knapp fuer den Echtzeit-Daemon (Schwelle ${CLAMAV_LIVE_MIN_MB} MB)."
    elif [ $(( eff + swap )) -ge "$CLAMAV_CRON_MIN_MB" ]; then
      CLAM_REC="cron"
      CLAM_REC_WHY="Nur ${eff} MB RAM frei - zusammen mit Swap (${swap} MB) reicht es knapp fuer einen naechtlichen Cron-/Timer-Scan. Echtzeit waere zu viel."
    else
      CLAM_REC="none"
      CLAM_REC_WHY="Nur ${eff} MB RAM frei (Swap ${swap} MB): schon ein einzelner Scan (ca. 1,5 GB) wuerde den Server in Speichernot (OOM) bringen."
    fi
  fi
}

clam_mode_detect() {
  CLAM_MODE_CUR="none"
  command -v clamscan >/dev/null 2>&1 || return 0
  if systemctl is-active --quiet clamav-daemon 2>/dev/null && { systemctl is-active --quiet clamav-clamonacc 2>/dev/null || systemctl is-active --quiet clamav-onacc 2>/dev/null; }; then
    CLAM_MODE_CUR="live"
  elif systemctl is-enabled --quiet clamav-scan.timer 2>/dev/null || [ -f /etc/cron.d/clamav-scan ] || [ -x /usr/local/sbin/clamav-scan.sh ]; then
    CLAM_MODE_CUR="cron"
  fi
}

clam_write_scan_script() {
  mkdir -p /var/log/clamav 2>/dev/null || true
  cat > /usr/local/sbin/clamav-scan.sh << 'CLS_EOF'
#!/usr/bin/env bash
# IT-Reinbek: geplanter ClamAV-Scan fuer Webroots & Systempfade (ohne Dauer-Daemon).
# Exit 0 = sauber, 1 = Fund, 2 = Fehler.
set -uo pipefail
LOG=/var/log/clamav/scan.log
FOUND=/var/log/clamav/last-infected.txt
OKSTAMP=/var/log/clamav/last-scan-ok
NOTIFY="__NOTIFY__"

tg() {
  [ -x "$NOTIFY" ] || return 0
  "$NOTIFY" clamav "$1" 2>/dev/null || true
}

PATHS=()
for p in /var/www /home /root /opt /srv /tmp /var/tmp /var/lib/docker/volumes; do
  [ -d "$p" ] && PATHS+=("$p")
done
[ "${#PATHS[@]}" -gt 0 ] || exit 0

mkdir -p /var/log/clamav 2>/dev/null || true
echo "=== $(date -Is) Scan-Start ===" >> "$LOG"
TMP="$(mktemp)"
clamscan --recursive --infected \
  --max-filesize=100M --max-scansize=300M \
  --exclude-dir='/var/lib/docker/volumes/[^/]*(mysql|mariadb|postgres|redis)' \
  --log="$LOG" "${PATHS[@]}" > "$TMP" 2>&1
rc=$?

case "$rc" in
  0)
    date -Is > "$OKSTAMP"
    rm -f "$FOUND" "$TMP"
    exit 0
    ;;
  1)
    mv "$TMP" "$FOUND"
    chmod 640 "$FOUND"
    logger -p auth.crit -t clamav-scan "INFECTED FILES FOUND - siehe $FOUND"
    hits="$(grep -E 'FOUND$' "$FOUND" 2>/dev/null | head -n 15)"
    tg "$(printf 'Viren-/Webshell-Fund beim geplanten ClamAV-Scan!\nLog: %s\n\n%s' "$FOUND" "$hits")"
    exit 1
    ;;
  *)
    logger -p auth.err -t clamav-scan "clamscan Fehler (Exit $rc) - siehe $LOG"
    rm -f "$TMP"
    exit 2
    ;;
esac
CLS_EOF
  sed -i "s|__NOTIFY__|${TG_NOTIFY}|g" /usr/local/sbin/clamav-scan.sh
  chmod 750 /usr/local/sbin/clamav-scan.sh
}

clam_setup_cron() {
  clam_write_scan_script
  cat > /etc/systemd/system/clamav-scan.service << 'CSS_EOF'
[Unit]
Description=ClamAV Zeitplan-Scan (IT-Reinbek PHP2Shell)
After=clamav-freshclam.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/clamav-scan.sh
Nice=19
IOSchedulingClass=idle
MemoryMax=2500M
TimeoutStartSec=4h
CSS_EOF
  cat > /etc/systemd/system/clamav-scan.timer << 'CST_EOF'
[Unit]
Description=Taeglicher ClamAV-Scan (IT-Reinbek PHP2Shell)

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
CST_EOF
  cat > /etc/logrotate.d/clamav-scan << 'CSL_EOF'
/var/log/clamav/scan.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
CSL_EOF
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    rm -f /etc/cron.d/clamav-scan
    systemctl daemon-reload
    systemctl enable --now clamav-scan.timer >/dev/null 2>&1 || warn "clamav-scan.timer konnte nicht aktiviert werden."
  else
    cat > /etc/cron.d/clamav-scan << 'CSC_EOF'
# IT-Reinbek: Taeglicher ClamAV-Scan um 03:30 Uhr
30 3 * * * root /usr/local/sbin/clamav-scan.sh >/dev/null 2>&1
CSC_EOF
    chmod 644 /etc/cron.d/clamav-scan
  fi
  ok "ClamAV Zeitplan-/Cronjob-Scan eingerichtet (täglich 03:30 Uhr, Skript: /usr/local/sbin/clamav-scan.sh)."
  info "Erster Test-Scan jederzeit möglich mit: sudo systemctl start clamav-scan.service (Log: /var/log/clamav/scan.log)"
}

clam_stop_cron() {
  systemctl disable --now clamav-scan.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/clamav-scan.timer /etc/systemd/system/clamav-scan.service /etc/logrotate.d/clamav-scan /etc/cron.d/clamav-scan /usr/local/sbin/clamav-scan.sh
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
}

clam_setup_live() {
  local d clamonacc onacc_unit conf="/etc/clamav/clamd.conf"
  [ ! -f "$conf" ] && [ -f /etc/clamd.d/scan.conf ] && conf="/etc/clamd.d/scan.conf"

  if [ -f "$conf" ] && ! grep -qsE '^OnAccessIncludePath' "$conf"; then
    [ -f "${conf}.bak-php2shell" ] || cp -a "$conf" "${conf}.bak-php2shell"
    {
      echo ""
      echo "# --- IT-Reinbek PHP2Shell On-Access (nur Benachrichtigung/Log, blockiert nichts) ---"
      for d in /var/www /home /opt /srv; do
        if [ -d "$d" ]; then echo "OnAccessIncludePath $d"; fi
      done
      for d in "${WEBROOTS[@]:-}"; do
        if [ -n "$d" ] && [ -d "$d" ]; then
          case "$d" in /var/www*|/home*|/opt*|/srv*) ;; *) echo "OnAccessIncludePath $d" ;; esac
        fi
      done
      echo "OnAccessExcludeUname clamav"
      echo "OnAccessPrevention no"
      echo "OnAccessExtraScanning yes"
    } >> "$conf"
  fi

  systemctl enable clamav-daemon >/dev/null 2>&1 || true
  systemctl restart clamav-daemon || warn "clamav-daemon Start fehlgeschlagen: journalctl -u clamav-daemon -n 30"

  clamonacc="$(command -v clamonacc || echo /usr/sbin/clamonacc)"
  mkdir -p /var/log/clamav 2>/dev/null || true
  if systemctl cat clamav-clamonacc.service >/dev/null 2>&1; then
    install -d /etc/systemd/system/clamav-clamonacc.service.d
    cat > /etc/systemd/system/clamav-clamonacc.service.d/override.conf << ONACC_EOF
[Service]
ExecStartPre=
ExecStartPre=/bin/bash -c 'for i in {1..60}; do [ -S /run/clamav/clamd.ctl ] || [ -S /var/run/clamav/clamd.ctl ] && exit 0; sleep 1; done; exit 1'
ExecStart=
ExecStart=${clamonacc} -F --fdpass --log=/var/log/clamav/clamonacc.log
ONACC_EOF
    onacc_unit="clamav-clamonacc"
    if [ -f /etc/systemd/system/clamav-onacc.service ]; then
      systemctl disable --now clamav-onacc >/dev/null 2>&1 || true
      mv -f /etc/systemd/system/clamav-onacc.service /etc/systemd/system/clamav-onacc.service.bak-php2shell
    fi
  else
    cat > /etc/systemd/system/clamav-onacc.service << ONACC2_EOF
[Unit]
Description=ClamAV On-Access Scanner (Echtzeitueberwachung IT-Reinbek)
Requires=clamav-daemon.service
After=clamav-daemon.service

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'for i in {1..60}; do [ -S /run/clamav/clamd.ctl ] || [ -S /var/run/clamav/clamd.ctl ] && exit 0; sleep 1; done; exit 1'
ExecStart=${clamonacc} -F --fdpass --log=/var/log/clamav/clamonacc.log
Restart=on-failure

[Install]
WantedBy=multi-user.target
ONACC2_EOF
    onacc_unit="clamav-onacc"
  fi
  systemctl daemon-reload
  systemctl enable "$onacc_unit" >/dev/null 2>&1 || true
  systemctl restart "$onacc_unit" || warn "$onacc_unit nicht gestartet (journalctl -u $onacc_unit -n 30)."
  ok "ClamAV Echtzeit-Überwachung (clamd + $onacc_unit On-Access) aktiviert."
}

clam_stop_live() {
  local u
  for u in clamav-clamonacc clamav-onacc clamav-daemon clamav-daemon.socket; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
  rm -rf /etc/systemd/system/clamav-clamonacc.service.d
  rm -f /etc/systemd/system/clamav-onacc.service
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
}

act_clamav() {
  clam_recommend
  clam_mode_detect
  local mode="${CLAM_MODE_WANT:-${CLAMAV_MODE:-}}"
  if [ -z "$mode" ] || [ "$mode" = "none" ]; then
    mode="$CLAM_REC"
    [ "$mode" = "none" ] && mode="cron"
  fi

  local mode_label
  if [ "$mode" = "live" ]; then
    mode_label="Echtzeit-Überwachung (clamd + clamonacc On-Access)"
  else
    mode_label="Zeitplan / Cronjob (täglicher Scan um 03:30 Uhr, ohne Dauer-Daemon)"
  fi

  explain "Maßnahme #17: ClamAV Malwareschutz einrichten ($mode_label)" "niedrig-mittel" \
    "Installiert bei Bedarf ClamAV, aktualisiert die Signaturen (freshclam) und richtet die gewählte Betriebsart '$mode' ein ($CLAM_RAM_TXT)." \
    "Echtzeit (live) benötigt dauerhaft ca. 1,5 GB RAM; Zeitplan/Cronjob (cron) belegt den Speicher nur kurz nachts während des Scans." \
    "Checkbox [17] abwählen oder im ClamAV-Dialog 'Kein ClamAV' wählen"

  local i fresh_ok=0
  if command -v apt-get >/dev/null 2>&1; then
    local pk="clamav clamav-freshclam"
    [ "$mode" = "live" ] && pk="clamav clamav-daemon clamav-freshclam"
    info "Installiere/prüfe Pakete: $pk ..."
    apt-get update -qq 2>/dev/null || true
    # shellcheck disable=SC2086
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold $pk; then
      crit "Paketinstallation ($pk) fehlgeschlagen."
      return 1
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y clamav clamd clamav-update || return 1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y clamav clamd clamav-update || return 1
  elif ! command -v clamscan >/dev/null 2>&1; then
    crit "ClamAV ist nicht installiert und kein unterstützter Paketmanager (apt/dnf/yum) wurde gefunden."
    return 1
  fi

  systemctl stop clamav-freshclam 2>/dev/null || true
  info "Aktualisiere ClamAV-Virensignaturen (freshclam) ..."
  for i in 1 2 3; do
    if freshclam >/dev/null 2>&1; then fresh_ok=1; break; fi
    sleep 3
  done
  [ "$fresh_ok" -ne 1 ] && warn "freshclam-Update meldete keinen direkten Erfolg (läuft ggf. bereits über Dienst)."
  systemctl enable --now clamav-freshclam >/dev/null 2>&1 || warn "clamav-freshclam konnte nicht gestartet werden."

  case "$mode" in
    live)
      clam_stop_cron
      clam_setup_live
      ;;
    cron)
      clam_stop_live
      clam_setup_cron
      ;;
  esac
  CLAM_MODE_CUR="$mode"
  CLAM_MODE_WANT="$mode"

  # Immer abfragen bzw. umsetzen, ob für ClamAV eine Telegram-Benachrichtigung gewünscht ist
  local want_tg="${CLAM_TG_WANT:-}"
  if [ -z "$want_tg" ]; then
    if confirm "Sollen Viren-/Webshell-Funde von ClamAV per Telegram-Bot gemeldet werden?"; then
      want_tg="1"
    else
      want_tg="0"
    fi
  fi

  if [ "$want_tg" = "1" ]; then
    TG_CLAM=1
    if ! tg_is_configured && [ -z "$TG_TOKEN_IN" ]; then
      info "Für die ClamAV-Telegram-Benachrichtigung werden noch Bot-Token & Chat-ID benötigt:"
      tui_telegram_prompt_cli
    fi
    if [ -n "$TG_TOKEN_IN" ] || tg_is_configured; then
      TG_ON=1
      TG_CLAM=1
      act_telegram
      if [ "$mode" = "live" ]; then
        tg_clamwatch_install
      else
        tg_clamwatch_remove
      fi
    else
      warn "Telegram ist nicht konfiguriert - ClamAV protokolliert vorerst nur lokal in /var/log/clamav."
    fi
  else
    TG_CLAM=0
    tg_clamwatch_remove
    if [ -r "$TG_CONF" ]; then
      tg_conf_write "$(tg_conf_get TG_TOKEN)" "$(tg_conf_get TG_CHAT_ID)" "$(tg_conf_get TG_LABEL)" \
        "$(tg_conf_get TG_FAIL2BAN)" "$(tg_conf_get TG_RKHUNTER)" "0" "$(tg_conf_get TG_AUDITD)"
    fi
    info "ClamAV-Telegram-Benachrichtigung deaktiviert (lokale Protokollierung in /var/log/clamav aktiv)."
  fi
  CLAM_TG_WANT=""
  alog "ClamAV eingerichtet in Betriebsart: $mode (Telegram: $TG_CLAM)"
}

undo_clamav() {
  explain "Rückabwicklung #17: ClamAV Echtzeit- & Cronjob-Überwachung deaktivieren" "niedrig" \
    "Stoppt und deaktiviert clamd, clamonacc, it-reinbek-clamwatch sowie den täglichen clamav-scan.timer/Cronjob und stellt clamd.conf wieder her (Pakete bleiben installiert)." \
    "Es findet keine automatische ClamAV-Überwachung auf Webshells/Malware mehr statt." \
    "Checkbox [17] wieder aktivieren"
  confirm "ClamAV-Dienste und Zeitplan-Scans jetzt deaktivieren?" || return 0
  tg_clamwatch_remove
  clam_stop_live
  clam_stop_cron
  systemctl disable --now clamav-freshclam >/dev/null 2>&1 || true
  if [ -f /etc/clamav/clamd.conf.bak-php2shell ]; then
    cp -a /etc/clamav/clamd.conf.bak-php2shell /etc/clamav/clamd.conf
  fi
  CLAM_MODE_CUR="none"
  CLAM_MODE_WANT="none"
  ok "ClamAV gestoppt und deaktiviert (Pakete bleiben installiert)."
  alog "Rückabwicklung #17: ClamAV deaktiviert"
}

# ======================================================= Checkliste, Scan-Report & Drucker-Erkennung

generate_checklist_text() {
  cat <<EOF
================================================================================
PHP2SHELL (CVE-2026-109618 / CVE-2026-109619) - NOTFALL- & SECRETS-CHECKLISTE
Referenz: BSI BITS-H Nr. 2026-297981-1132 (Version 1.1 vom 21.10.2026)
Host: $(hostname)   |   Erstellt am: $(date '+%F %T %Z')
Scan-Befund: CRIT=$CRIT | WARN=$WARN | Kompromittierungs-Verdacht=$COMP | Angriffs-Spuren=$ATT
================================================================================

WARUM DIESE CHECKLISTE WICHTIG IST:
CVE-2026-109618 kann laut Sansec/Datadog freigegebenen Worker-Heap-Speicher
direkt in einem PHPSESSID-Response-Cookie an Angreifer zurückliefern
(Heartbleed-ähnlicher Memory-Leak!). Darin können Passwörter, Session-Tokens,
API-Keys und private TLS-Schlüssel anderer Requests im Klartext enthalten sein.

WICHTIGE REIHENFOLGE:
Erst Notfall-Update einspielen (oder System vom Internet trennen) & Dienste neu
starten, DANN Zugangsdaten rotieren - sonst landet das neue Secret sofort wieder
im verwundbaren/kompromittierten Prozess!

1. SYSTEM-ISOLATION & NOTFALL-UPDATES (BSI-Empfehlung)
   [ ] Alle PHP-Instanzen auf Notfall-Update >= 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
       gepatcht (bzw. Distro/LTS-Backport für 7.4 / 8.0 / 8.1 installiert)
   [ ] Falls Patch nicht sofort möglich: System vorübergehend vom Internet
       getrennt ODER alle BSI-Workarounds kombiniert aktiviert
   [ ] Alle PHP-FPM-Pools, Apache/httpd-, FrankenPHP- und LiteSpeed-Prozesse
       nach dem Update neu gestartet (keine "(deleted)" Binaries in /proc)
   [ ] Laufende Docker-Container auf gepatchte PHP-Images aktualisiert

2. ROTATION VON ZUGANGSDATEN & SECRETS (nach dem Patch!)
   [ ] Datenbank-Passwörter (MySQL/MariaDB, PostgreSQL, Redis) geändert und
       in den Anwendungskonfigurationen (.env, wp-config.php etc.) angepasst
   [ ] API-Keys, Webhook-Secrets, OAuth-Tokens, Payment-/Shop-Schlüssel
       (Stripe, PayPal etc.) und Cloud-Credentials (AWS/S3) neu generiert
   [ ] SMTP-/Mail-Zugangsdaten der Webanwendungen rotiert
   [ ] WordPress / CMS / Frameworks (z. B. InvoiceNinja / Laravel):
       - Salts & Security-Keys in wp-config.php bzw. APP_KEY (.env) geprüft/erneuert
       - Passwörter aller Administrator- und Benutzer-Konten zurückgesetzt
   [ ] SSH-Schlüssel (/root/.ssh/authorized_keys, /home/*/.ssh/authorized_keys)
       sowie Passwörter lokaler System-User geprüft und ggf. rotiert
   [ ] TLS/SSL-Zertifikate mit NEUEM Private Key neu ausgestellt (Rekeying),
       falls das System ungepatcht exponiert war oder Angriffs-Spuren vorliegen
   [ ] Alle aktiven PHP-Sessions (sess_* / Redis-Sessions) invalidiert / geleert

3. PROPRIETÄRE APPLIANCES, NACHKONTROLLE & MELDEPFLICHTEN
   [ ] Eigene Appliances mit eingebettetem PHP geprüft (z. B. pfSense, OPNsense,
       Nextcloud, Monitoring-Tools; siehe https://github.com/NCSC-NL/php2shell)
   [ ] Crontabs, systemd-Units und Webroots auf unbekannte/neue Dateien geprüft
   [ ] Temporäre BSI-Workarounds (z. B. memory_limit=-1) nach erfolgreichem
       Patch wieder zurückgenommen und Dienste neu gestartet
   [ ] Bei bestätigter Kompromittierung oder Datenabfluss: Gesetzliche
       Meldepflichten geprüft (BSI-Meldestelle gemäß NIS-2 / BSIG, DSGVO Art. 33)

Unterschrift / Geprüft durch: _______________________   Datum: ______________
================================================================================
EOF
}

detect_printers() {
  local p=() name
  if command -v lpstat >/dev/null 2>&1; then
    while IFS= read -r name; do
      [ -n "$name" ] && p+=("cups:$name")
    done < <(lpstat -e 2>/dev/null || lpstat -p 2>/dev/null | awk '/^printer /{print $2}')
  fi
  if [ "${#p[@]}" -eq 0 ] && [ -r /etc/printcap ]; then
    while IFS= read -r name; do
      [ -n "$name" ] && p+=("lpr:$name")
    done < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/printcap 2>/dev/null | cut -d'|' -f1 | cut -d: -f1 | awk 'NF')
  fi
  for dev in /dev/usb/lp* /dev/lp*; do
    [ -e "$dev" ] && [ -w "$dev" ] && p+=("dev:$dev")
  done
  printf '%s\n' "${p[@]}" | awk 'NF' | sort -u
}

send_file_to_printer() {
  local file_to_print="$1" job_title="${2:-PHP2Shell-Dokument}"
  local printers=() def_prn="" i sel prn_type prn_name
  mapfile -t printers < <(detect_printers)
  if command -v lpstat >/dev/null 2>&1; then
    def_prn=$(lpstat -d 2>/dev/null | awk -F': ' 'NF>1{print $2}' | tr -d ' ')
  fi

  if [ "${#printers[@]}" -eq 0 ]; then
    info "Kein lokaler oder Netzwerk-Drucker (CUPS/lpstat/lpr) auf diesem Host erkannt."
    info "Du kannst die gespeicherte Datei '$file_to_print' per SCP/Tabby herunterladen und lokal ausdrucken."
    return 0
  fi

  printf '\n%sErkannte Drucker auf diesem System:%s\n' "$B" "$N"
  for i in "${!printers[@]}"; do
    prn_name="${printers[$i]#*:}"
    prn_type="${printers[$i]%%:*}"
    if [ -n "$def_prn" ] && [ "$prn_name" = "$def_prn" ]; then
      printf '  [%d] %s (%s) %s<- Standarddrucker%s\n' "$((i+1))" "$prn_name" "$prn_type" "$G" "$N"
    else
      printf '  [%d] %s (%s)\n' "$((i+1))" "$prn_name" "$prn_type"
    fi
  done

  if ! confirm "'$job_title' ($file_to_print) jetzt auf einem der erkannten Drucker ausdrucken?"; then
    return 0
  fi

  sel=1
  if [ "${#printers[@]}" -gt 1 ]; then
    tty_read -r -p "Drucker-Nummer wählen [1-${#printers[@]}, Enter = 1]: " sel || return 0
    sel="${sel:-1}"
  fi
  if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "${#printers[@]}" ]; then
    warn "Ungültige Druckerauswahl."
    return 0
  fi

  local chosen="${printers[$((sel-1))]}"
  prn_type="${chosen%%:*}"
  prn_name="${chosen#*:}"

  case "$prn_type" in
    cups)
      if command -v lp >/dev/null 2>&1 && lp -d "$prn_name" -t "$job_title" "$file_to_print"; then
        ok "Druckauftrag '$job_title' erfolgreich an CUPS-Drucker '$prn_name' gesendet."
        alog "Gedruckt ($job_title) auf CUPS:$prn_name ($file_to_print)"
      elif command -v lpr >/dev/null 2>&1 && lpr -P "$prn_name" "$file_to_print"; then
        ok "Druckauftrag '$job_title' per lpr an '$prn_name' gesendet."
        alog "Gedruckt ($job_title) per lpr:$prn_name ($file_to_print)"
      else
        crit "Druckauftrag an '$prn_name' fehlgeschlagen (CUPS-Dienst läuft?)."
      fi
      ;;
    lpr)
      if command -v lpr >/dev/null 2>&1 && lpr -P "$prn_name" "$file_to_print"; then
        ok "Druckauftrag '$job_title' per lpr an '$prn_name' gesendet."
        alog "Gedruckt ($job_title) per lpr:$prn_name ($file_to_print)"
      else
        crit "Druckauftrag per lpr an '$prn_name' fehlgeschlagen."
      fi
      ;;
    dev)
      if cat "$file_to_print" > "$prn_name" 2>/dev/null; then
        ok "'$job_title' direkt an Druckergerät '$prn_name' gesendet."
        alog "Gedruckt ($job_title) auf Gerät $prn_name ($file_to_print)"
      else
        crit "Schreiben auf Druckergerät '$prn_name' fehlgeschlagen."
      fi
      ;;
  esac
}

act_rotate() {
  ensure_state_dir
  local ts chk_file
  ts=$(date +%Y%m%d-%H%M%S)
  chk_file="/root/php2shell-checkliste-$ts.txt"
  umask 077
  generate_checklist_text > "$chk_file"
  echo "$chk_file" > "$STATE_DIR/last_checklist_file" 2>/dev/null || true
  printf '\n'
  cat "$chk_file"
  printf '\n'
  ok "Checkliste als Textdatei gespeichert unter: $chk_file"
  send_file_to_printer "$chk_file" "PHP2Shell-Checkliste"
}

act_print_full_report() {
  ensure_state_dir
  local ts rep_file
  ts=$(date +%Y%m%d-%H%M%S)
  rep_file="/root/php2shell-revisionsbericht-$ts.txt"
  umask 077
  {
    echo "================================================================================"
    echo "PHP2SHELL - VOLLSTÄNDIGER REVISIONSBERICHT (SCAN-REPORT + BSI-CHECKLISTE)"
    echo "Host: $(hostname)   |   Erstellt am: $(date '+%F %T %Z')"
    echo "================================================================================"
    echo ""
    if [ -f "$SCAN_CAPTURED" ]; then
      strip_ansi < "$SCAN_CAPTURED"
    else
      echo "[Scan-Ausgabe nicht im Zwischenspeicher - führe Kurz-Scan aus]"
      bash "$SELF" --versions-only --no-menu --accept-disclaimer 2>&1 | strip_ansi
    fi
    echo ""
    generate_checklist_text
  } > "$rep_file"
  echo "$rep_file" > "$STATE_DIR/last_checklist_file" 2>/dev/null || true
  ok "Vollständiger Revisionsbericht (Scan-Report + Checkliste) gespeichert unter: $rep_file"
  send_file_to_printer "$rep_file" "PHP2Shell-Revisionsbericht"
}

undo_rotate() {
  local files=()
  mapfile -t files < <(ls /root/php2shell-checkliste-*.txt /root/php2shell-revisionsbericht-*.txt 2>/dev/null || true)
  [ "${#files[@]}" -gt 0 ] || { info "Keine gespeicherten Checklisten-/Berichtsdateien in /root gefunden."; return 0; }
  if confirm "Gespeicherte Checklisten-/Revisionsberichts-Dateien (${#files[@]}) aus /root löschen?"; then
    rm -f -- "${files[@]}" "$STATE_DIR/last_checklist_file"
    ok "Checklisten-/Berichtsdateien gelöscht."
  fi
}

# ======================================================= Zustandsbasierte Split-Screen TUI

declare -a M_TITLE=() M_CAT=() M_RISK=() M_WHAT=() M_IMPACT=() M_UNDO=() M_ACTIVE=() M_SEL=() M_REVERSIBLE=()

detect_live_states() {
  local i pf
  for i in {1..18}; do M_ACTIVE[$i]=0; done

  ls -d /root/php2shell-evidence-* >/dev/null 2>&1 && M_ACTIVE[1]=1
  ls -d /root/php2shell-backup-* >/dev/null 2>&1 && M_ACTIVE[2]=1

  if [ -f "$STATE_DIR/pkg_update_bdir" ] || { [ "${#R_LABEL[@]}" -gt 0 ] && [ "${#NEED_UPDATE[@]}" -eq 0 ]; }; then
    M_ACTIVE[3]=1
  fi

  [ -f "$STATE_DIR/branch_newpkgs" ] && [ -s "$STATE_DIR/branch_newpkgs" ] && M_ACTIVE[4]=1
  [ -f "$STATE_DIR/switch_active" ] && M_ACTIVE[5]=1

  if [ -f "$STATE_DIR/docker_updated" ] || { [ "$DK_OK" -eq 1 ] && [ "${#DK_ALL[@]}" -gt 0 ] && [ "${#DK_VULN[@]}" -eq 0 ]; }; then
    M_ACTIVE[6]=1
  fi

  find /etc/php /etc/php.d /usr/local/etc/php /etc/opt/remi /opt/remi -name "$MARK_INI" 2>/dev/null | grep -q . && M_ACTIVE[7]=1

  for pf in $(pool_files); do
    if grep -q "$MARK_MEM" "$pf" 2>/dev/null; then M_ACTIVE[8]=1; break; fi
  done

  [ -d "$SNIPPET_DIR" ] && M_ACTIVE[9]=1
  [ "$STALE" -eq 0 ] && [ "${#R_LABEL[@]}" -gt 0 ] && M_ACTIVE[10]=1
  ls /root/php2shell-quarantine-*/sessions-index.txt >/dev/null 2>&1 && M_ACTIVE[11]=1
  ls /root/php2shell-quarantine-*/quarantine-restore.idx >/dev/null 2>&1 && M_ACTIVE[12]=1
  [ -f "$AUDIT_RULE" ] && M_ACTIVE[13]=1
  M_ACTIVE[14]=0
  ls /root/php2shell-checkliste-*.txt /root/php2shell-revisionsbericht-*.txt >/dev/null 2>&1 && M_ACTIVE[15]=1
  M_ACTIVE[16]=0

  clam_recommend
  clam_mode_detect
  if [ "$CLAM_MODE_CUR" = "live" ] || [ "$CLAM_MODE_CUR" = "cron" ]; then
    M_ACTIVE[17]=1
    [ -z "$CLAM_MODE_WANT" ] && CLAM_MODE_WANT="$CLAM_MODE_CUR"
  else
    [ -z "$CLAM_MODE_WANT" ] && CLAM_MODE_WANT="$CLAM_REC"
  fi

  tg_init
  if [ "$TG_CUR" -eq 1 ]; then
    M_ACTIVE[18]=1
  fi
}

sync_selection_with_active() {
  local i
  detect_live_states
  for i in {1..18}; do
    M_SEL[$i]="${M_ACTIVE[$i]}"
  done
  [ "$TG_ON" -eq 1 ] && M_SEL[18]=1
  load_menu_texts 2>/dev/null || true
}

load_menu_texts() {
  clam_recommend
  clam_mode_detect
  local clam_mode_lbl clam_rec_lbl aud_tg_lbl tg_stat_lbl
  if [ "$UI_LANG" = "en" ]; then
    case "${CLAM_MODE_WANT:-$CLAM_MODE_CUR}" in
      live) clam_mode_lbl="Real-time (clamd)" ;;
      cron) clam_mode_lbl="Cronjob/Timer" ;;
      *)    clam_mode_lbl="Configure" ;;
    esac
    case "$CLAM_REC" in
      live) clam_rec_lbl="Real-time (live)" ;;
      cron) clam_rec_lbl="Scheduled/Cron (cron)" ;;
      *)    clam_rec_lbl="No ClamAV (low RAM)" ;;
    esac
    if systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null || [ "${AUDIT_TG_WANT:-}" = "1" ]; then
      aud_tg_lbl=" + TG"
    else
      aud_tg_lbl=""
    fi
    if [ "$TG_ON" -eq 1 ] || [ "$TG_CUR" -eq 1 ]; then
      tg_stat_lbl="$(tg_cat_text "${TG_F2B:-1}" "${TG_RKH:-1}" "${TG_CLAM:-1}" "${TG_AUDIT:-1}")"
    else
      tg_stat_lbl="Configure [t]"
    fi
  else
    case "${CLAM_MODE_WANT:-$CLAM_MODE_CUR}" in
      live) clam_mode_lbl="Echtzeit (clamd)" ;;
      cron) clam_mode_lbl="Cronjob/Timer" ;;
      *)    clam_mode_lbl="Konfigurieren" ;;
    esac
    case "$CLAM_REC" in
      live) clam_rec_lbl="Echtzeit (live)" ;;
      cron) clam_rec_lbl="Zeitplan/Cronjob (cron)" ;;
      *)    clam_rec_lbl="Kein ClamAV (wenig RAM)" ;;
    esac
    if systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null || [ "${AUDIT_TG_WANT:-}" = "1" ]; then
      aud_tg_lbl=" + TG"
    else
      aud_tg_lbl=""
    fi
    if [ "$TG_ON" -eq 1 ] || [ "$TG_CUR" -eq 1 ]; then
      tg_stat_lbl="$(tg_cat_text "${TG_F2B:-1}" "${TG_RKH:-1}" "${TG_CLAM:-1}" "${TG_AUDIT:-1}")"
    else
      tg_stat_lbl="Einrichten [t]"
    fi
  fi

  if [ "$UI_LANG" = "en" ]; then
    M_CAT[1]="I. Forensics & Backup"; M_TITLE[1]="Capture evidence (Logs/RAM/Locks)"
    M_RISK[1]="NO CHANGE (read-only, creates folder in /root)"
    M_WHAT[1]="Captures running processes, network connections, active file locks (/proc/locks & lsof), web/PHP logs, crontabs, authorized_keys, hashes of suspicious files, and optionally up to 3 PHP worker core dumps (gcore) to /root/php2shell-evidence-*."
    M_IMPACT[1]="Patching or restarting services wipes RAM exploited by CVE-2026-109619. If compromise is suspected, run this step BEFORE any other action."
    M_UNDO[1]="Uncheck [x] -> [ ] and press [Enter]: Deletes the created evidence archives in /root."

    M_CAT[2]="I. Forensics & Backup"; M_TITLE[2]="Config backup (/etc/php, Webserver)"
    M_RISK[2]="NO CHANGE (creates backup archive in /root)"
    M_WHAT[2]="Creates a tar.gz archive of all PHP, FPM, Apache, nginx, and auditd config paths plus a list of installed PHP packages and modules under /root/php2shell-backup-*."
    M_IMPACT[2]="Zero impact on operations. Also executed automatically before any modifying action."
    M_UNDO[2]="Uncheck [x] -> [ ] and press [Enter]: Offers restoring configs.tar.gz to / or deleting the backup."

    M_CAT[3]="II. Patching & Upgrades"; M_TITLE[3]="PHP emergency updates (same branch)"
    M_RISK[3]="MEDIUM (with pre-flight dry-run & automatic rollback)"
    M_WHAT[3]="Installs the official PHP emergency updates (8.2.35, 8.3.36, 8.4.27, 8.5.12 and distro/LTS backports for 7.4, 8.0, 8.1). Backs up old .deb packages beforehand and verifies services, ports, and HTTP responses afterwards."
    M_IMPACT[3]="PHP-FPM/Apache restart briefly during package update (1-3 sec interruption). If already patched, the checkbox is green [x]."
    M_UNDO[3]="Uncheck [x] -> [ ] and press [Enter]: Reinstalls the previously backed-up .deb packages (downgrade)."

    M_CAT[4]="II. Patching & Upgrades"; M_TITLE[4]="EOL-PHP Stage 1: Parallel install"
    M_RISK[4]="MEDIUM (installs new PHP version alongside, no switch yet)"
    M_WHAT[4]="For unpatched EOL branches (e.g. PHP <= 8.1 without backport or migrating from 8.2): Installs the recommended target branch (default: PHP 8.4) with matching modules in parallel, resets CLI alternatives, and generates a syntax/module compatibility report."
    M_IMPACT[4]="Running websites remain untouched on the old PHP version. An additional FPM service runs ready."
    M_UNDO[4]="Uncheck [x] -> [ ] and press [Enter]: Uninstalls the parallel-installed php<target>-* packages."

    M_CAT[5]="II. Patching & Upgrades"; M_TITLE[5]="EOL-PHP Stage 2: Switch webserver"
    M_RISK[5]="HIGH (switches webserver to new PHP version, with rollback)"
    M_WHAT[5]="Migrates FPM pools and custom php.ini directives from the old to the new PHP version (from Action 4), updates socket paths in nginx/Apache, reloads the webserver, and verifies all services and test URLs."
    M_IMPACT[5]="All FPM-backed websites subsequently run on the new PHP version."
    M_UNDO[5]="Uncheck [x] -> [ ] and press [Enter]: Restores original webserver configs & FPM pools and switches back to the old PHP version."

    M_CAT[6]="II. Patching & Upgrades"; M_TITLE[6]="Docker: compose down, Backup & Update"
    M_RISK[6]="MEDIUM-HIGH (cleanly stops stack for consistent backup)"
    M_WHAT[6]="Checks vulnerable PHP containers for patched images. Creates an online DB dump first, cleanly stops the project via 'docker compose down' (releases all file/DB locks!), backs up bind mounts/volumes, and restarts via 'docker compose up -d'."
    M_IMPACT[6]="Brief downtime of the Compose project during backup and restart. If all containers are already safe, checkbox is green [x]."
    M_UNDO[6]="Uncheck [x] -> [ ] and press [Enter]: Stops the stack via 'docker compose down', reverts image/Compose file to the rollback tag, and restarts."

    M_CAT[7]="III. BSI Workarounds"; M_TITLE[7]="BSI drop-in (upload_progress/post_max)"
    M_RISK[7]="LOW-MEDIUM (temporary workaround per BSI v1.1)"
    M_WHAT[7]="Creates 99-php2shell-mitigation.ini: sets session.upload_progress.enabled=0 and fatal_error_backtraces=0 (against CVE-2026-109619), limits post_max_size to 8M or 32M (against CVE-2026-109618), and sets expose_php=0."
    M_IMPACT[7]="Session upload progress bars are disabled; oversized POST requests are rejected. Marked [x] when file is present."
    M_UNDO[7]="Uncheck [x] -> [ ] and press [Enter]: Removes 99-php2shell-mitigation.ini from all conf.d folders and offers service restart."

    M_CAT[8]="III. BSI Workarounds"; M_TITLE[8]="BSI workaround: memory_limit = -1"
    M_RISK[8]="HIGH (prevents PHP OOM trigger, but RAM DoS risk)"
    M_WHAT[8]="Sets 'php_admin_value[memory_limit] = -1' in all FPM pool configs so no controllable PHP memory_limit overflow (CVE-2026-109618) can be triggered."
    M_IMPACT[8]="A single request can consume all server RAM. Per BSI, MUST be combined with cgroup limits (see Action 9) and reset (e.g. 256M) after patching!"
    M_UNDO[8]="Uncheck [x] -> [ ] and press [Enter]: Removes 'php_admin_value[memory_limit] = -1' from all FPM pools."

    M_CAT[9]="III. BSI Workarounds"; M_TITLE[9]="Generate webserver & cgroup snippets"
    M_RISK[9]="NO CHANGE (generates config templates in /root)"
    M_WHAT[9]="Generates ready-to-use templates in /root/php2shell-snippets for nginx & Apache (body/header limits including chunked requests, ASLR brute-force rate limit, multipart block) and systemd cgroup memory limits (MemoryMax/OOMPolicy)."
    M_IMPACT[9]="No direct impact since only template files are generated."
    M_UNDO[9]="Uncheck [x] -> [ ] and press [Enter]: Deletes the /root/php2shell-snippets folder."

    M_CAT[10]="III. BSI Workarounds"; M_TITLE[10]="Restart PHP & webserver services"
    M_RISK[10]="MEDIUM (config test + controlled restart)"
    M_WHAT[10]="Runs a configuration test for each running service (php-fpm, apache2, httpd, nginx) beforehand and restarts services only if configuration is valid."
    M_IMPACT[10]="Brief interruption (1-3 sec). Marked [x] when all running processes use current binaries; [ ] if stale '(deleted)' binaries are active."
    M_UNDO[10]="One-time action (a service restart cannot be undone)."

    M_CAT[11]="IV. Cleanup & Print"; M_TITLE[11]="Quarantine session files"
    M_RISK[11]="MEDIUM (logs out active web users)"
    M_WHAT[11]="Moves all existing session files (sess_*) from PHP session directories into a protected quarantine folder under /root/php2shell-quarantine-*/sessions."
    M_IMPACT[11]="All logged-in users are signed out. Immediately neutralizes pre-planted session payloads."
    M_UNDO[11]="Uncheck [x] -> [ ] and press [Enter]: Moves session files back to their original paths using the index."

    M_CAT[12]="IV. Cleanup & Print"; M_TITLE[12]="Quarantine suspicious files"
    M_RISK[12]="MEDIUM (isolates detected webshells/backdoors)"
    M_WHAT[12]="Moves all files flagged as suspicious during filesystem scan (currently: ${#FOUND_FILES[@]} hits) to /root/php2shell-quarantine-*/files, strips permissions (chmod 000), and records owner/mode/SHA256 in the restore index."
    M_IMPACT[12]="In case of a false positive, the affected file stops working until restored."
    M_UNDO[12]="Uncheck [x] -> [ ] and press [Enter]: Restores all quarantined files with original permissions and ownership."

    M_CAT[13]="IV. Cleanup & Print"; M_TITLE[13]="auditd monitoring${aud_tg_lbl}"
    M_RISK[13]="LOW (logging only, blocks nothing; optional Telegram alert)"
    M_WHAT[13]="Configures an auditd rule (/etc/audit/rules.d/99-php2shell.rules) logging all program/shell executions (execve 64-bit & 32-bit) by webserver users (www-data, apache, nginx) under key 'php2shell_exec'. Press [Space] on #13 to choose whether Telegram alerts (it-reinbek-auditwatch) should be active - even if auditd is already enabled!"
    M_IMPACT[13]="Writes audit log entries when PHP spawns processes (inspect via: ausearch -k php2shell_exec) and optionally sends immediate Telegram notifications."
    M_UNDO[13]="Press [Space] on #13 (or uncheck) and press [Enter]: Allows disabling Telegram alerts or removing /etc/audit/rules.d/99-php2shell.rules completely."

    M_CAT[14]="IV. Cleanup & Print"; M_TITLE[14]="Revert all temporary workarounds"
    M_RISK[14]="LOW-MEDIUM (restores original config for #7, #8, #13)"
    M_WHAT[14]="Convenience action: Removes in one step all temporary workarounds created by this script (99-php2shell-mitigation.ini, memory_limit=-1 in FPM pools, and the auditd rule)."
    M_IMPACT[14]="Only execute AFTER PHP has been fully patched!"
    M_UNDO[14]="Re-select individual items (#7, #8, #13)."

    M_CAT[15]="IV. Cleanup & Print"; M_TITLE[15]="PRINT checklist & audit reports"
    M_RISK[15]="NO CHANGE (display, file export & CUPS/LPR print)"
    M_WHAT[15]="Generates the emergency & secrets rotation checklist (or press [r] for the full audit report including scan tables) and optionally prints it directly via auto-detected printers."
    M_IMPACT[15]="No system changes."
    M_UNDO[15]="Uncheck [x] -> [ ] and press [Enter]: Deletes the saved checklist/report text files in /root."

    M_CAT[16]="IV. Cleanup & Print"; M_TITLE[16]="Verification: Re-run version scan"
    M_RISK[16]="NO CHANGE (read-only)"
    M_WHAT[16]="Re-runs the PHP version and backport check (host & Docker containers) to immediately verify after an update that all installations report GREEN (SAFE)."
    M_IMPACT[16]="Zero impact on operations."
    M_UNDO[16]="Not required (read-only)."

    M_CAT[17]="IV. Cleanup & Print"; M_TITLE[17]="ClamAV protection ($clam_mode_lbl)"
    M_RISK[17]="LOW-MEDIUM (report-only On-Access or nightly Cron/Timer)"
    M_WHAT[17]="Configures ClamAV malware/webshell scanning in either Real-time mode (clamd + clamonacc On-Access for /var/www, /home, /opt, /srv) or Scheduled Cron/Timer mode (03:30 daily without resident daemon), including optional Telegram alerts. Press [Space] or [c] to open the mode selector!"
    M_IMPACT[17]="${CLAM_RAM_TXT}. RAM-based recommendation: ${clam_rec_lbl} (${CLAM_REC_WHY})"
    M_UNDO[17]="Uncheck [x] -> [ ] (or choose 'No ClamAV' in dialog) and press [Enter]: Stops and disables clamd, clamonacc, it-reinbek-clamwatch, and clamav-scan.timer."

    M_CAT[18]="IV. Cleanup & Print"; M_TITLE[18]="Telegram Bot ($tg_stat_lbl)"
    M_RISK[18]="LOW (outbound HTTPS to api.telegram.org only)"
    M_WHAT[18]="Stores Telegram Bot credentials (Token, Chat-ID, Server Label) and per-component notification flags for fail2ban, rkhunter, ClamAV, and auditd in /etc/it-reinbek/telegram.conf (mode 0600 root:root in 0700 dir) and installs /usr/local/sbin/it-reinbek-notify (0750, token passed via curl stdin). Press [Space] or [t] to configure!"
    M_IMPACT[18]="Credentials are protected against unauthorized access and shared with the IT-Reinbek Linux Hardening script (fail2ban/rkhunter/ClamAV/auditd)."
    M_UNDO[18]="Uncheck [x] -> [ ] (or disable in [t] dialog) and press [Enter]: Removes /etc/it-reinbek/telegram.conf, /usr/local/sbin/it-reinbek-notify, and all notification watchers."
  else
    M_CAT[1]="I. Forensik & Sicherung"; M_TITLE[1]="Beweise sichern (Logs/RAM/Locks)"
    M_RISK[1]="KEINE ÄNDERUNG (nur lesend, legt Ordner in /root an)"
    M_WHAT[1]="Sichert laufende Prozesse, Netzwerkverbindungen, aktive Datei-Locks (/proc/locks & lsof), Webserver-/PHP-Logs, Crontabs, authorized_keys, Hashes verdächtiger Dateien sowie optional bis zu 3 PHP-Worker-Speicherabbilder (gcore) nach /root/php2shell-evidence-*."
    M_IMPACT[1]="Ein Patch oder Dienst-Neustart löscht den Arbeitsspeicher, den CVE-2026-109619 ausnutzt. Bei Verdacht auf Befall MUSS dieser Schritt vor allen anderen Maßnahmen ausgeführt werden."
    M_UNDO[1]="Haken [x] -> [ ] abwählen und [Enter] drücken: Löscht die angelegten Beweis-Archive in /root wieder."

    M_CAT[2]="I. Forensik & Sicherung"; M_TITLE[2]="Konfig-Backup (/etc/php, Webserver)"
    M_RISK[2]="KEINE ÄNDERUNG (legt Backup-Archiv in /root an)"
    M_WHAT[2]="Erstellt ein tar.gz-Archiv aller PHP-, FPM-, Apache-, nginx- und auditd-Konfigurationspfade sowie eine Liste aller installierten PHP-Pakete und Module unter /root/php2shell-backup-*."
    M_IMPACT[2]="Keine Auswirkung auf den Betrieb. Wird vor jeder ändernden Maßnahme auch automatisch ausgeführt."
    M_UNDO[2]="Haken [x] -> [ ] abwählen und [Enter] drücken: Bietet das Zurückspielen (Restore) von configs.tar.gz nach / oder das Löschen des Backups an."

    M_CAT[3]="II. Patchen & Upgrades"; M_TITLE[3]="PHP-Notfall-Updates (gleicher Branch)"
    M_RISK[3]="MITTEL (mit Vorab-Dry-Run & automatischem Rollback)"
    M_WHAT[3]="Installiert die offiziellen PHP-Notfall-Updates (8.2.35, 8.3.36, 8.4.27, 8.5.12 sowie Distro-/LTS-Backports für 7.4, 8.0 und 8.1). Sichert vorher die alten .deb-Pakete und prüft nachher Dienste, Ports und HTTP-Antworten."
    M_IMPACT[3]="PHP-FPM/Apache werden beim Paketupdate kurz neu gestartet (1-3 Sek. Unterbrechung). Ist bereits alles sicher gepatcht, steht die Checkbox grün auf [x]."
    M_UNDO[3]="Haken [x] -> [ ] abwählen und [Enter] drücken: Spielt die vor dem Update gesicherten .deb-Pakete wieder ein (Downgrade)."

    M_CAT[4]="II. Patchen & Upgrades"; M_TITLE[4]="EOL-PHP Stufe 1: Parallel-Install"
    M_RISK[4]="MITTEL (installiert neue PHP-Version parallel, schaltet nichts um)"
    M_WHAT[4]="Für ungepatchte EOL-Branches (z. B. PHP <= 8.1 ohne Backport oder Wechsel von 8.2): Installiert den empfohlenen Zielbranch (Standard: PHP 8.4) inkl. passender Module parallel zur alten Version, setzt CLI-Alternativen zurück und erstellt einen Syntax-/Modul-Kompatibilitätsbericht."
    M_IMPACT[4]="Laufende Webseiten bleiben unberührt auf der alten PHP-Version. Ein zusätzlicher FPM-Dienst läuft bereit."
    M_UNDO[4]="Haken [x] -> [ ] abwählen und [Enter] drücken: Deinstalliert die parallel installierten php<zielbranch>-*-Pakete wieder."

    M_CAT[5]="II. Patchen & Upgrades"; M_TITLE[5]="EOL-PHP Stufe 2: Webserver umschalten"
    M_RISK[5]="HOCH (stellt Webserver auf neue PHP-Version um, mit Rollback)"
    M_WHAT[5]="Übernimmt FPM-Pools und abweichende php.ini-Direktiven von der alten in die neue PHP-Version (aus Maßnahme 4), stellt die Socket-Pfade in nginx/Apache um, lädt den Webserver neu und prüft alle Dienste sowie deine Test-URLs."
    M_IMPACT[5]="Alle über FPM eingebundenen Webseiten laufen danach mit der neuen PHP-Version."
    M_UNDO[5]="Haken [x] -> [ ] abwählen und [Enter] drücken: Stellt die originalen Webserver-Konfigs & FPM-Pools wieder her und schaltet auf die alte PHP-Version zurück."

    M_CAT[6]="II. Patchen & Upgrades"; M_TITLE[6]="Docker: compose down, Backup & Update"
    M_RISK[6]="MITTEL-HOCH (stoppt Stack sauber für konsistentes Backup)"
    M_WHAT[6]="Prüft für verwundbare PHP-Container, ob ein gepatchtes Image vorliegt. Erstellt zuerst einen Online-DB-Dump, fährt das Projekt dann mit 'docker compose down' sauber herunter (löst alle Datei-/DB-Locks!), sichert alle Bind-Mounts/Volumes und startet mit 'docker compose up -d' neu."
    M_IMPACT[6]="Kurze Downtime des Compose-Projekts während des Backups und Neustarts. Sind alle Container bereits sicher (wie dein InvoiceNinja mit PHP 8.5.12), steht die Checkbox grün auf [x]."
    M_UNDO[6]="Haken [x] -> [ ] abwählen und [Enter] drücken: Stoppt den Stack per 'docker compose down', setzt das Image/Compose-File auf den Rollback-Tag zurück und startet neu."

    M_CAT[7]="III. BSI-Workarounds"; M_TITLE[7]="BSI-Drop-in (upload_progress/post_max)"
    M_RISK[7]="NIEDRIG-MITTEL (temporärer Workaround gemäß BSI v1.1)"
    M_WHAT[7]="Legt 99-php2shell-mitigation.ini an: setzt session.upload_progress.enabled=0 und fatal_error_backtraces=0 (gegen CVE-2026-109619), begrenzt post_max_size auf 8M bzw. 32M (gegen CVE-2026-109618) und setzt expose_php=0."
    M_IMPACT[7]="Upload-Fortschrittsbalken über Sessions sind deaktiviert; übergroße POST-Requests werden abgelehnt. Ist die Datei vorhanden, ist [x] gesetzt."
    M_UNDO[7]="Haken [x] -> [ ] abwählen und [Enter] drücken: Entfernt 99-php2shell-mitigation.ini aus allen conf.d-Ordnern und bietet Dienst-Neustart an."

    M_CAT[8]="III. BSI-Workarounds"; M_TITLE[8]="BSI-Workaround: memory_limit = -1"
    M_RISK[8]="HOCH (verhindert PHP-OOM-Trigger, aber DoS-Risiko für RAM)"
    M_WHAT[8]="Setzt 'php_admin_value[memory_limit] = -1' in allen FPM-Pool-Konfigurationen, damit kein kontrollierbarer PHP-Speicherlimit-Überlauf (CVE-2026-109618) ausgelöst werden kann."
    M_IMPACT[8]="Ein einzelner Request kann den gesamten Server-RAM verbrauchen. Laut BSI zwingend mit cgroup-Limits (siehe Maßnahme 9) kombinieren!"
    M_UNDO[8]="Haken [x] -> [ ] abwählen und [Enter] drücken: Entfernt 'php_admin_value[memory_limit] = -1' wieder aus allen FPM-Pools."

    M_CAT[9]="III. BSI-Workarounds"; M_TITLE[9]="Webserver- & cgroup-Snippets erzeugen"
    M_RISK[9]="KEINE ÄNDERUNG (erzeugt Konfigurationsvorlagen in /root)"
    M_WHAT[9]="Erzeugt fertige Vorlagen unter /root/php2shell-snippets für nginx & Apache (Body-/Header-Limits auch für Chunked-Requests ohne Content-Length, ASLR-Brute-Force Rate-Limit, Multipart-Sperre) sowie systemd cgroup-Speicherlimits (MemoryMax/OOMPolicy)."
    M_IMPACT[9]="Keine direkte Auswirkung, da nur Textdateien erzeugt werden."
    M_UNDO[9]="Haken [x] -> [ ] abwählen und [Enter] drücken: Löscht den Ordner /root/php2shell-snippets wieder."

    M_CAT[10]="III. BSI-Workarounds"; M_TITLE[10]="PHP- & Webserver-Dienste neu starten"
    M_RISK[10]="MITTEL (Konfigtest + kontrollierter Neustart)"
    M_WHAT[10]="Führt vorab für jeden laufenden Dienst (php-fpm, apache2, httpd, nginx) einen Konfigurationstest durch und startet die Dienste nur bei fehlerfreier Konfiguration neu."
    M_IMPACT[10]="Kurze Unterbrechung (1-3 Sek.). Steht auf [x], wenn alle laufenden Prozesse aktuellen Code im Speicher nutzen; steht auf [ ], wenn veraltete '(deleted)' Binaries laufen."
    M_UNDO[10]="Einmalige Aktion (ein Dienst-Neustart bedarf keiner Rückabwicklung)."

    M_CAT[11]="IV. Bereinigung & Druck"; M_TITLE[11]="Session-Dateien in Quarantäne"
    M_RISK[11]="MITTEL (loggt aktive Web-Benutzer aus)"
    M_WHAT[11]="Verschiebt alle vorhandenen Session-Dateien (sess_*) aus den PHP-Session-Verzeichnissen in einen geschützten Quarantäne-Ordner unter /root/php2shell-quarantine-*/sessions."
    M_IMPACT[11]="Alle eingeloggten Nutzer werden abgemeldet. Entzieht vorab eingeschleusten Session-Payloads sofort die Wirkung."
    M_UNDO[11]="Haken [x] -> [ ] abwählen und [Enter] drücken: Schiebt die Session-Dateien anhand des Index wieder an ihren Originalort zurück."

    M_CAT[12]="IV. Bereinigung & Druck"; M_TITLE[12]="Verdächtige Dateien in Quarantäne"
    M_RISK[12]="MITTEL (isoliert erkannte Webshells/Backdoors)"
    M_WHAT[12]="Verschiebt alle beim Dateisystem-Scan als verdächtig markierten Dateien (aktuell: ${#FOUND_FILES[@]} Treffer) nach /root/php2shell-quarantine-*/files, entzieht die Rechte (chmod 000) und sichert Besitzer/Rechte/SHA256 im Restore-Index."
    M_IMPACT[12]="Bei einem Fehlalarm (False Positive) funktioniert die betroffene Datei nicht mehr, bis sie zurückverschoben wird."
    M_UNDO[12]="Haken [x] -> [ ] abwählen und [Enter] drücken: Stellt alle verschobenen Dateien inkl. Originalrechten und Besitzer wieder am Ursprungsort her."

    M_CAT[13]="IV. Bereinigung & Druck"; M_TITLE[13]="auditd-Überwachung${aud_tg_lbl}"
    M_RISK[13]="NIEDRIG (rein protokollierend, optional mit Telegram-Alarm)"
    M_WHAT[13]="Richtet eine auditd-Regel (/etc/audit/rules.d/99-php2shell.rules) ein, die alle Programm-/Shell-Starts (execve 64-Bit & 32-Bit) durch Webserver-Benutzer (www-data, apache, nginx) mit dem Schlüssel 'php2shell_exec' protokolliert. Mit [Leertaste] auf #13 immer wählbar, ob Telegram-Benachrichtigung (it-reinbek-auditwatch) aktiv sein soll - auch wenn auditd bereits eingerichtet ist!"
    M_IMPACT[13]="Erzeugt Audit-Log-Einträge bei Prozessstarts durch PHP (Auswertung mit: ausearch -k php2shell_exec) und meldet Treffer auf Wunsch sofort per Telegram."
    M_UNDO[13]="Mit [Leertaste] auf #13 (oder Abwählen) & [Enter]: Telegram-Meldung zu-/abschalten oder /etc/audit/rules.d/99-php2shell.rules komplett entfernen."

    M_CAT[14]="IV. Bereinigung & Druck"; M_TITLE[14]="Sammel-Rücknahme aller Workarounds"
    M_RISK[14]="NIEDRIG-MITTEL (stellt Original-Konfig für #7, #8, #13 her)"
    M_WHAT[14]="Komfort-Aktion: Entfernt in einem Schritt alle von diesem Skript angelegten temporären Workarounds (99-php2shell-mitigation.ini, memory_limit=-1 in FPM-Pools sowie die auditd-Regel)."
    M_IMPACT[14]="Erst ausführen, nachdem PHP vollständig gepatcht wurde!"
    M_UNDO[14]="Einzelne Punkte (#7, #8, #13) wieder anwählen."

    M_CAT[15]="IV. Bereinigung & Druck"; M_TITLE[15]="Checkliste & Berichte DRUCKEN"
    M_RISK[15]="KEINE ÄNDERUNG (Anzeige, Datei-Export & CUPS/LPR-Druck)"
    M_WHAT[15]="Erstellt die Notfall- und Secrets-Rotations-Checkliste (bzw. mit Taste [r] den gesamten Revisionsbericht inkl. Scan-Tabellen) und druckt sie auf Wunsch direkt über automatisch erkannte Drucker aus."
    M_IMPACT[15]="Keine Systemänderung."
    M_UNDO[15]="Haken [x] -> [ ] abwählen und [Enter] drücken: Löscht die in /root abgelegten Checklisten-/Berichts-Textdateien."

    M_CAT[16]="IV. Bereinigung & Druck"; M_TITLE[16]="Verifikation: Erneuter Versions-Scan"
    M_RISK[16]="KEINE ÄNDERUNG (nur lesend)"
    M_WHAT[16]="Führt die PHP-Versions- und Backport-Prüfung (Host & Docker-Container) erneut aus, um nach einem Update sofort zu kontrollieren, ob alle Installationen auf GRÜN (SICHER) stehen."
    M_IMPACT[16]="Keine Auswirkung auf den Betrieb."
    M_UNDO[16]="Nicht erforderlich (rein lesend)."

    M_CAT[17]="IV. Bereinigung & Druck"; M_TITLE[17]="ClamAV Malwareschutz ($clam_mode_lbl)"
    M_RISK[17]="NIEDRIG-MITTEL (On-Access nur meldend od. Cronjob nachts)"
    M_WHAT[17]="Richtet ClamAV-Malware-/Webshell-Überwachung wahlweise in Echtzeit (clamd + clamonacc On-Access für /var/www, /home, /opt, /srv) oder als täglichen Cronjob/Timer (03:30 Uhr ohne Dauer-Daemon) inkl. optionaler Telegram-Meldung ein. Mit [Leertaste] oder [c] Betriebsart & Telegram-Option wählen!"
    M_IMPACT[17]="${CLAM_RAM_TXT}. Vorschlag nach RAM: ${clam_rec_lbl} (${CLAM_REC_WHY})"
    M_UNDO[17]="Haken [x] -> [ ] abwählen (oder im Dialog 'Kein ClamAV' wählen) und [Enter] drücken: Stoppt und deaktiviert clamd, clamonacc, it-reinbek-clamwatch und clamav-scan.timer."

    M_CAT[18]="IV. Bereinigung & Druck"; M_TITLE[18]="Telegram-Bot ($tg_stat_lbl)"
    M_RISK[18]="NIEDRIG (nur ausgehend HTTPS an api.telegram.org)"
    M_WHAT[18]="Fragt Bot-Token, Chat-ID und Server-Label ab und speichert sie inkl. Baustein-Auswahl für fail2ban, rkhunter, ClamAV und auditd zugriffsgeschützt in /etc/it-reinbek/telegram.conf (Ordner 0700, Datei 0600 root:root) sowie /usr/local/sbin/it-reinbek-notify (0750, Token per Stdin). Mit [Leertaste] oder [t] konfigurieren!"
    M_IMPACT[18]="Zugangsdaten sind gegen unbefugtes Auslesen geschützt (kein Token in ps/proc) und sofort auch für fail2ban & rkhunter im IT-Reinbek-Härtungsskript vorgehalten."
    M_UNDO[18]="Haken [x] -> [ ] abwählen (oder im [t]-Dialog deaktivieren) und [Enter] drücken: Entfernt /etc/it-reinbek/telegram.conf, /usr/local/sbin/it-reinbek-notify und alle Watcher."
  fi
}

init_menu_data() {
  local i
  for i in {1..18}; do M_REVERSIBLE[$i]=1; done
  M_REVERSIBLE[10]=0
  M_REVERSIBLE[14]=0
  M_REVERSIBLE[16]=0

  sync_selection_with_active
}

apply_action_by_id() {
  case "$1" in
    1)  act_evidence ;;
    2)  act_backup ;;
    3)  act_update ;;
    4)  act_branch_upgrade ;;
    5)  act_switch ;;
    6)  act_docker_update ;;
    7)  act_mitig_bsi_ini ;;
    8)  act_mitig_mem ;;
    9)  act_snippets ;;
    10) act_restart ;;
    11) act_sessions ;;
    12) act_quarantine ;;
    13) act_auditd ;;
    14) act_undo ;;
    15) act_rotate ;;
    16) bash "$SELF" --versions-only --no-menu --accept-disclaimer 2>&1 | sed -n '/1) PHP-Versionen/,/Zusammenfassung/p' ;;
    17) act_clamav ;;
    18) act_telegram ;;
  esac
}

revert_action_by_id() {
  case "$1" in
    1)  undo_evidence ;;
    2)  undo_backup ;;
    3)  undo_update ;;
    4)  undo_branch_upgrade ;;
    5)  undo_switch ;;
    6)  undo_docker_update ;;
    7)  undo_mitig_bsi_ini ;;
    8)  undo_mitig_mem ;;
    9)  undo_snippets ;;
    10) info "Ein Dienst-Neustart (#10) ist ein einmaliger Vorgang und kann nicht rückabgewickelt werden." ;;
    11) undo_sessions ;;
    12) undo_quarantine ;;
    13) undo_auditd ;;
    14) info "Punkt #14 ist bereits die Sammel-Rückabwicklung." ;;
    15) undo_rotate ;;
    16) info "Ein lesender Scan (#16) bedarf keiner Rückabwicklung." ;;
    17) undo_clamav ;;
    18) undo_telegram ;;
  esac
}

tui_clamav_screen() {
  clam_recommend
  clam_mode_detect
  tg_init
  local sel=1 iscroll=0 key k2 k3
  if [ "$CLAM_MODE_WANT" = "live" ]; then sel=1
  elif [ "$CLAM_MODE_WANT" = "cron" ]; then sel=2
  elif [ "$CLAM_MODE_WANT" = "none" ] && [ "${M_SEL[17]:-0}" -eq 0 ] && [ "$CLAM_MODE_CUR" != "none" ]; then sel=3
  elif [ "$CLAM_REC" = "live" ]; then sel=1
  elif [ "$CLAM_REC" = "cron" ]; then sel=2
  else sel=2
  fi

  local chosen="$sel"
  local want_tg="${CLAM_TG_WANT:-$TG_CLAM}"
  [ -z "$want_tg" ] && want_tg=1

  while true; do
    clam_recommend
    clam_mode_detect
    local cols rows lw rw box_h r_inner
    cols=$(tput cols 2>/dev/null || echo 118)
    rows=$(tput lines 2>/dev/null || echo 34)
    [ "$cols" -lt 96 ] && cols=96
    [ "$rows" -lt 24 ] && rows=24
    lw=$(( cols * 46 / 100 ))
    [ "$lw" -lt 44 ] && lw=44
    [ "$lw" -gt 62 ] && lw=62
    rw=$(( cols - lw - 4 ))
    [ "$rw" -lt 36 ] && rw=36
    box_h=$(( rows - 6 ))
    [ "$box_h" -lt 16 ] && box_h=16
    r_inner=$(( rw - 2 ))

    local step_title l_box_title r_box_title intro_line status_line key_line
    local -a opt_title=() opt_badge=() opt_info=()
    local common_info

    if [ "$UI_LANG" = "en" ]; then
      step_title="Step 4b - ClamAV & Telegram Alert "
      l_box_title="ClamAV Operating Mode & Alert"
      r_box_title="Info & RAM Recommendation"
      intro_line=" ${CLAM_RAM_TXT}. Suggestion: ${CLAM_REC}. Choose mode (1-3) & Telegram alert (4) with Space/Enter."
      status_line=" Select ClamAV mode (1=Real-time, 2=Cronjob, 3=None) and toggle (4) Telegram notification with [Space], confirm with [Enter]."
      key_line=" Up/Down: select | Space: choose/toggle | Enter: confirm | t: Telegram Bot | PgUp/Dn: Info | b/q: Back"

      common_info=$(printf 'RAM ANALYSIS & RECOMMENDATION:\n%s.\n\nRECOMMENDED MODE: %s\n%s\n\nThresholds (customizable via CLAMAV_LIVE_MIN_MB=%d / CLAMAV_CRON_MIN_MB=%d):\n- Real-time (live): >= %d MB free RAM\n- Scheduled/Cron (cron): >= %d MB free RAM\nYou can switch the operating mode and Telegram alerts at any time.' \
        "$CLAM_RAM_TXT" "$CLAM_REC" "$CLAM_REC_WHY" "$CLAMAV_LIVE_MIN_MB" "$CLAMAV_CRON_MIN_MB" "$CLAMAV_LIVE_MIN_MB" "$CLAMAV_CRON_MIN_MB")

      opt_title[1]="Real-time (clamd + On-Access)"
      opt_title[2]="Scheduled / Cronjob (daily 03:30)"
      opt_title[3]="No ClamAV (disable / rollback)"
      opt_title[4]="Telegram alert on ClamAV detection"

      opt_info[1]=$(printf 'MODE 1: REAL-TIME MONITORING (clamd + clamonacc On-Access)\n\nWHAT DOES THIS MODE DO?\nclamd runs continuously as a background daemon and monitors /var/www, /home, /opt, /srv in real time via clamonacc (--fdpass). Detections are logged immediately to /var/log/clamav/clamonacc.log (OnAccessPrevention=no, so web traffic is never blocked).\n\nRAM REQUIREMENT:\nRequires ~1.5 GB RAM permanently (briefly more during signature reloads).\n\n%s' "$common_info")
      opt_info[2]=$(printf 'MODE 2: SCHEDULED / CRONJOB SCAN (daily at 03:30, no daemon)\n\nWHAT DOES THIS MODE DO?\nSets up /usr/local/sbin/clamav-scan.sh via systemd timer (clamav-scan.timer) or /etc/cron.d/clamav-scan at 03:30 with low CPU/IO priority (Nice=19, Idle IO, MemoryMax=2500M). Scans /var/www, /home, /root, /opt, /srv, /tmp, /var/tmp, and Docker volumes.\n\nRAM REQUIREMENT:\nZero RAM usage during normal daytime operation! The ~1.5 GB signature memory is only used during the nightly scan.\n\n%s' "$common_info")
      opt_info[3]=$(printf 'MODE 3: NO CLAMAV (DISABLE / ROLLBACK)\n\nWHAT DOES THIS MODE DO?\nIf ClamAV is currently active (real-time or cronjob), it will be stopped and disabled on [Enter] in the main menu (packages remain installed). Recommended for servers with very low available RAM.\n\n%s' "$common_info")
      opt_info[4]=$(printf 'OPTION 4: TELEGRAM NOTIFICATION FOR CLAMAV DETECTIONS\n\nWHAT DOES THIS OPTION DO?\nDetermines whether malware/webshell detections by ClamAV are immediately sent via your Telegram Bot (/usr/local/sbin/it-reinbek-notify clamav):\n- In Real-time mode (live): Starts the systemd watcher it-reinbek-clamwatch.service on /var/log/clamav/clamonacc.log.\n- In Cronjob mode (cron): /usr/local/sbin/clamav-scan.sh sends a Telegram alert when exit code 1 (infected files found) occurs.\n\nPress [Space] on row 4 to toggle Telegram notifications for ClamAV on or off!' )
    else
      step_title="Schritt 4b - ClamAV & Telegram "
      l_box_title="ClamAV Betriebsart & Meldung"
      r_box_title="Info & RAM-Empfehlung"
      intro_line=" ${CLAM_RAM_TXT}. Vorschlag: ${CLAM_REC}. Betriebsart (1-3) & Telegram (4) waehlen."
      status_line=" Betriebsart (1=Echtzeit, 2=Cronjob, 3=Kein ClamAV) & Punkt 4 (Telegram-Meldung bei Fund) mit [Leertaste] waehlen, [Enter] uebernimmt."
      key_line=" Pfeile: Wahl | Leertaste: Umschalten | Enter: Uebernehmen | t: Telegram-Bot | Bild^/v: Info | b/q: Zurueck"

      common_info=$(printf 'RAM-ANALYSE & EMPFEHLUNG:\n%s.\n\nVORSCHLAG: %s\n%s\n\nSchwellenwerte (anpassbar per CLAMAV_LIVE_MIN_MB=%d / CLAMAV_CRON_MIN_MB=%d):\n- Echtzeit (live): ab %d MB frei\n- Zeitplan/Cronjob (cron): ab %d MB frei\nDie Empfehlung ist ein Vorschlag - Sie koennen die Betriebsart und die Telegram-Benachrichtigung jederzeit frei waehlen.' \
        "$CLAM_RAM_TXT" "$CLAM_REC" "$CLAM_REC_WHY" "$CLAMAV_LIVE_MIN_MB" "$CLAMAV_CRON_MIN_MB" "$CLAMAV_LIVE_MIN_MB" "$CLAMAV_CRON_MIN_MB")

      opt_title[1]="Echtzeit (clamd + On-Access)"
      opt_title[2]="Zeitplan / Cronjob (taegl. 03:30)"
      opt_title[3]="Kein ClamAV (Deaktivieren)"
      opt_title[4]="Telegram-Meldung bei ClamAV-Fund"

      opt_info[1]=$(printf 'MODUS 1: ECHTZEIT-UEBERWACHUNG (clamd + clamonacc On-Access)\n\nWAS MACHT DIESE BETRIEBSART?\nclamd laeuft dauerhaft als Dienst und ueberwacht /var/www, /home, /opt, /srv in Echtzeit per clamonacc (--fdpass). Neue Webshells oder Backdoors werden sofort beim Anlegen erkannt und in /var/log/clamav/clamonacc.log gemeldet (OnAccessPrevention=no, blockiert den Webbetrieb nicht).\n\nSPEICHERBEDARF (RAM):\nBenoetigt dauerhaft ca. 1,5 GB RAM (beim Signatur-Reload kurzzeitig mehr).\n\n%s' "$common_info")
      opt_info[2]=$(printf 'MODUS 2: ZEITPLAN / CRONJOB (taeglicher Scan um 03:30, ohne Daemon)\n\nWAS MACHT DIESE BETRIEBSART?\nRichtet /usr/local/sbin/clamav-scan.sh per systemd-Timer (clamav-scan.timer) bzw. /etc/cron.d/clamav-scan um 03:30 Uhr mit niedriger Prioritaet (Nice=19, Idle-IO, MemoryMax=2500M) ein. Prueft /var/www, /home, /root, /opt, /srv, /tmp, /var/tmp sowie Docker-Volumes (ohne DB-Volumes).\n\nSPEICHERBEDARF (RAM):\nTagsueber 0 MB Dauer-RAM! Die ca. 1,5 GB RAM werden nur nachts waehrend des Scans belegt.\n\n%s' "$common_info")
      opt_info[3]=$(printf 'MODUS 3: KEIN CLAMAV (DEAKTIVIEREN / RUECKBAU)\n\nWAS MACHT DIESE BETRIEBSART?\nIst ClamAV bereits eingerichtet (Echtzeit oder Cronjob), werden Dienste und Timer beim Anwenden im Hauptmenue gestoppt und deaktiviert (Pakete bleiben installiert). Sinnvoll bei sehr wenig freiem Arbeitsspeicher.\n\n%s' "$common_info")
      opt_info[4]=$(printf 'OPTION 4: TELEGRAM-BENACHRICHTIGUNG BEI CLAMAV-FUND\n\nWAS MACHT DIESE OPTION?\nLegt fest, ob Viren- und Webshell-Funde von ClamAV sofort ueber den zentralen Telegram-Bot (/usr/local/sbin/it-reinbek-notify clamav) gemeldet werden:\n- Im Echtzeit-Modus (live): Ueberwacht /var/log/clamav/clamonacc.log per Dienst it-reinbek-clamwatch.service.\n- Im Cronjob-Modus (cron): /usr/local/sbin/clamav-scan.sh sendet bei Exit-Code 1 (Fund) sofort die Trefferliste per Telegram.\n\nMit [Leertaste] auf Zeile 4 schalten Sie die Telegram-Benachrichtigung fuer ClamAV ein oder aus! Falls noch kein Bot-Token hinterlegt ist, oeffnet sich automatisch der Telegram-Dialog.' )
    fi

    local b1="" b2="" b3="" b4=""
    if [ "$UI_LANG" = "en" ]; then
      [ "$CLAM_REC" = "live" ] && b1="recommended"
      [ "$CLAM_REC" = "cron" ] && b2="recommended"
      [ "$CLAM_REC" = "none" ] && b3="recommended"
      [ "$CLAM_MODE_CUR" = "live" ] && b1="active${b1:+, $b1}"
      [ "$CLAM_MODE_CUR" = "cron" ] && b2="active${b2:+, $b2}"
      [ "$CLAM_MODE_CUR" = "none" ] && b3="inactive${b3:+, $b3}"
      [ "$want_tg" -eq 1 ] && b4="YES (active)" || b4="NO (off)"
    else
      [ "$CLAM_REC" = "live" ] && b1="empfohlen"
      [ "$CLAM_REC" = "cron" ] && b2="empfohlen"
      [ "$CLAM_REC" = "none" ] && b3="empfohlen"
      [ "$CLAM_MODE_CUR" = "live" ] && b1="aktiv${b1:+, $b1}"
      [ "$CLAM_MODE_CUR" = "cron" ] && b2="aktiv${b2:+, $b2}"
      [ "$CLAM_MODE_CUR" = "none" ] && b3="inaktiv${b3:+, $b3}"
      [ "$want_tg" -eq 1 ] && b4="JA (aktiv)" || b4="NEIN (aus)"
    fi
    opt_badge[1]="${b1:+[$b1]}"
    opt_badge[2]="${b2:+[$b2]}"
    opt_badge[3]="${b3:+[$b3]}"
    opt_badge[4]="[$b4]"

    local -a rlines=()
    local rline wline
    while IFS= read -r rline; do
      if [ -z "$rline" ]; then
        rlines+=("")
      else
        while IFS= read -r wline; do
          rlines+=("$wline")
        done < <(printf '%s\n' "$rline" | fold -s -w "$r_inner")
      fi
    done <<< "${opt_info[$sel]}"

    local r_total="${#rlines[@]}"
    local rmax=$(( r_total - box_h ))
    [ "$rmax" -lt 0 ] && rmax=0
    [ "$iscroll" -gt "$rmax" ] && iscroll="$rmax"
    [ "$iscroll" -lt 0 ] && iscroll=0
    local r_more_up=0 r_more_dn=0
    [ "$iscroll" -gt 0 ] && r_more_up=1
    [ $(( iscroll + box_h )) -lt "$r_total" ] && r_more_dn=1

    local rup_s="" rdn_s=""
    if [ "$r_more_up" -eq 1 ]; then rup_s=$( [ "$UI_LANG" = "en" ] && echo " ^more " || echo " ^mehr " ); fi
    if [ "$r_more_dn" -eq 1 ]; then rdn_s=$( [ "$UI_LANG" = "en" ] && echo " PgDn v more " || echo " Bild v mehr " ); fi

    local l_fill_top=$(( lw - ${#l_box_title} - 4 ))
    [ "$l_fill_top" -lt 1 ] && l_fill_top=1
    local r_fill_top=$(( rw - ${#r_box_title} - ${#rup_s} - 4 ))
    [ "$r_fill_top" -lt 1 ] && r_fill_top=1

    printf '\e[H\e[2J'
    tui_topbar "$cols" " IT-Reinbek PHP2Shell-Auditor v${VERSION}" "$step_title"
    printf '%s\n' "${intro_line:0:$cols}"
    printf '%s+-- %s%s%s %s++-- %s%s%s %s%s%s%s+%s\n' \
      "$C" "$C$B" "$l_box_title" "$N$C" "$(printf '%*s' "$l_fill_top" '' | tr ' ' '-')" \
      "$C$B" "$r_box_title" "$N$C" "$(printf '%*s' "$r_fill_top" '' | tr ' ' '-')" "$Y" "$rup_s" "$C" "$N"

    local row idx mark item_color badge title max_tlen lstr raw_len pad_len lpad rstr r_pad rfmt
    for (( row=0; row<box_h; row++ )); do
      idx=$(( row + 1 ))
      rstr="${rlines[$(( iscroll + row ))]:-}"
      if [ "$idx" -le 4 ]; then
        item_color=""
        mark=" "
        if [ "$idx" -le 3 ]; then
          if [ "$idx" -eq "$chosen" ]; then
            if { [ "$idx" -eq 1 ] && [ "$CLAM_MODE_CUR" = "live" ]; } || { [ "$idx" -eq 2 ] && [ "$CLAM_MODE_CUR" = "cron" ]; }; then
              mark="x"; item_color="$G"
            elif [ "$idx" -eq 3 ] && [ "$CLAM_MODE_CUR" != "none" ]; then
              mark="-"; item_color="${R}${B}"
            else
              mark="+"; item_color="${Y}${B}"
            fi
          fi
        else
          if [ "$want_tg" -eq 1 ]; then
            if [ "$TG_CUR" -eq 1 ] && [ "$(tg_conf_get TG_CLAMAV)" = "1" ]; then
              mark="x"; item_color="$G"
            else
              mark="+"; item_color="${Y}${B}"
            fi
          else
            if [ "$TG_CUR" -eq 1 ] && [ "$(tg_conf_get TG_CLAMAV)" = "1" ]; then
              mark="-"; item_color="${R}${B}"
            else
              mark=" "; item_color=""
            fi
          fi
        fi
        badge="${opt_badge[$idx]}"
        title="${opt_title[$idx]}"
        max_tlen=$(( lw - 12 - ${#badge} ))
        [ "$max_tlen" -lt 10 ] && max_tlen=10
        title="${title:0:$max_tlen}"
        if [ "$idx" -eq "$sel" ]; then
          lstr=" > [$mark] $idx) $title"
        else
          lstr="   [$mark] $idx) $title"
        fi
        raw_len=$(( ${#lstr} + ${#badge} + 1 ))
        pad_len=$(( lw - raw_len ))
        [ "$pad_len" -lt 1 ] && pad_len=1
        lstr="${lstr}$(printf '%*s' "$pad_len" '')${badge} "
        if [ "$idx" -eq "$sel" ]; then
          if [ -n "$item_color" ]; then
            lpad=$'\e[7m'"${item_color}${B}${lstr}"$'\e[0m'
          else
            lpad=$'\e[7m'"${B}${lstr}"$'\e[0m'
          fi
        elif [ -n "$item_color" ]; then
          lpad="${item_color}${lstr}${N}"
        else
          lpad="${lstr}"
        fi
      else
        lpad=$(printf '%*s' "$lw" '')
      fi

      rstr="${rstr:0:$r_inner}"
      r_pad=$(( r_inner - ${#rstr} ))
      [ "$r_pad" -lt 0 ] && r_pad=0
      case "$rstr" in
        MODUS*|MODE\ *|OPTION\ *)
          rfmt=" ${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        WAS\ MACHT*|SPEICHERBEDARF*|RAM-ANALYSE*|WHAT\ DOES*|RAM\ REQUIREMENT*|RAM\ ANALYSIS*)
          rfmt=" ${B}${C}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        VORSCHLAG:*|RECOMMENDED\ MODE:*)
          rfmt=" ${G}${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        *)
          rfmt=" ${rstr}$(printf '%*s' "$r_pad" '') " ;;
      esac
      printf '%s|%s%s%s||%s%s%s|%s\n' "$C" "$N" "$lpad" "$C" "$N" "$rfmt" "$C" "$N"
    done

    local r_fill_bot=$(( rw - ${#rdn_s} ))
    [ "$r_fill_bot" -lt 1 ] && r_fill_bot=1
    printf '%s+%s++%s%s%s%s+%s\n' \
      "$C" "$(printf '%*s' "$lw" '' | tr ' ' '-')" \
      "$(printf '%*s' "$r_fill_bot" '' | tr ' ' '-')" "$Y" "$rdn_s" "$C" "$N"
    printf '%s%s%s\n' "$C" "${status_line:0:$cols}" "$N"
    printf '%s%s%s' "$B" "${key_line:0:$cols}" "$N"

    IFS= tty_read -rsn1 key || return 0
    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) sel=$(( sel > 1 ? sel - 1 : 4 )); [ "$sel" -le 3 ] && chosen="$sel"; iscroll=0 ;;
          B) sel=$(( sel < 4 ? sel + 1 : 1 )); [ "$sel" -le 3 ] && chosen="$sel"; iscroll=0 ;;
          5) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll > 5 ? iscroll - 5 : 0 )) ;;
          6) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll + 5 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) sel=$(( sel > 1 ? sel - 1 : 4 )); [ "$sel" -le 3 ] && chosen="$sel"; iscroll=0 ;;
      j|J) sel=$(( sel < 4 ? sel + 1 : 1 )); [ "$sel" -le 3 ] && chosen="$sel"; iscroll=0 ;;
      1|2|3) sel="$key"; chosen="$key"; iscroll=0 ;;
      4) sel=4; want_tg=$(( 1 - want_tg )); iscroll=0 ;;
      " ")
        if [ "$sel" -eq 4 ]; then
          want_tg=$(( 1 - want_tg ))
        else
          chosen="$sel"
        fi
        ;;
      t|T)
        tui_telegram_screen "sub"
        ;;
      l|L)
        if [ "$UI_LANG" = "de" ]; then UI_LANG="en"; else UI_LANG="de"; fi
        ;;
      b|B|q|Q)
        load_menu_texts
        return 0
        ;;
      "")
        [ "$sel" -le 3 ] && chosen="$sel"
        CLAM_TG_WANT="$want_tg"
        TG_CLAM="$want_tg"
        case "$chosen" in
          1)
            CLAM_MODE_WANT="live"
            M_SEL[17]=1
            if [ "$CLAM_MODE_CUR" != "live" ]; then M_ACTIVE[17]=0; fi
            ;;
          2)
            CLAM_MODE_WANT="cron"
            M_SEL[17]=1
            if [ "$CLAM_MODE_CUR" != "cron" ]; then M_ACTIVE[17]=0; fi
            ;;
          3)
            CLAM_MODE_WANT="none"
            M_SEL[17]=0
            ;;
        esac
        if [ "$chosen" != "3" ] && [ "$want_tg" -eq 1 ] && ! tg_is_configured && [ -z "$TG_TOKEN_IN" ]; then
          TG_ON=1
          M_SEL[18]=1
          tui_telegram_screen "sub"
        fi
        load_menu_texts
        return 0
        ;;
    esac
  done
}

tui_auditd_screen() {
  tg_init
  local aud_cur=0 watch_cur=0 sel=1 chosen=1 iscroll=0 key k2 k3
  [ -f "$AUDIT_RULE" ] && aud_cur=1
  systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null && watch_cur=1

  if [ "${AUDIT_TG_WANT:-}" = "1" ]; then
    sel=1
  elif [ "${AUDIT_TG_WANT:-}" = "0" ]; then
    sel=2
  elif [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 1 ]; then
    sel=1
  elif [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 0 ]; then
    if [ "${TG_AUDIT:-1}" -eq 1 ] && { [ "$TG_ON" -eq 1 ] || [ "$TG_CUR" -eq 1 ]; }; then sel=1; else sel=2; fi
  else
    sel=1
  fi
  chosen="$sel"

  while true; do
    aud_cur=0; watch_cur=0
    [ -f "$AUDIT_RULE" ] && aud_cur=1
    systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null && watch_cur=1

    local cols rows lw rw box_h r_inner
    cols=$(tput cols 2>/dev/null || echo 118)
    rows=$(tput lines 2>/dev/null || echo 34)
    [ "$cols" -lt 96 ] && cols=96
    [ "$rows" -lt 24 ] && rows=24
    lw=$(( cols * 46 / 100 ))
    [ "$lw" -lt 44 ] && lw=44
    [ "$lw" -gt 62 ] && lw=62
    rw=$(( cols - lw - 4 ))
    [ "$rw" -lt 36 ] && rw=36
    box_h=$(( rows - 6 ))
    [ "$box_h" -lt 16 ] && box_h=16
    r_inner=$(( rw - 2 ))

    local step_title l_box_title r_box_title intro_line status_line key_line
    local -a opt_title=() opt_badge=() opt_info=()

    if [ "$UI_LANG" = "en" ]; then
      step_title="Step 4a - auditd & Telegram Notification "
      l_box_title="auditd & Notification Mode"
      r_box_title="Info & Security Notes"
      intro_line=" Choose whether auditd (php2shell_exec) should send Telegram alerts (even if auditd is already enabled)."
      status_line=" Select mode (1=auditd + Telegram alert, 2=auditd local log only, 3=Disable/Rollback auditd) and press [Enter]."
      key_line=" Up/Down: select | Space/Enter: confirm | t: Configure Telegram Bot | l: DE/EN | b/q: Back"

      opt_title[1]="auditd + Telegram alert (recommended)"
      opt_title[2]="auditd local only (/var/log/audit)"
      opt_title[3]="Disable auditd rule (rollback)"

      opt_info[1]=$'OPTION 1: AUDITD + TELEGRAM NOTIFICATION (it-reinbek-auditwatch)\n\nWHAT DOES THIS OPTION DO?\n1. Ensures /etc/audit/rules.d/99-php2shell.rules is active (logs all execve 64/32-bit process executions by www-data/apache/nginx under key php2shell_exec).\n2. Installs and starts the systemd service it-reinbek-auditwatch.service, which watches /var/log/audit/audit.log in real time and sends immediate Telegram alerts via /usr/local/sbin/it-reinbek-notify auditd whenever a web worker spawns a shell or binary.\n\nIf Telegram credentials are not yet configured, selecting this option automatically opens the Telegram Bot setup screen.'
      opt_info[2]=$'OPTION 2: AUDITD LOCAL LOGGING ONLY (NO TELEGRAM)\n\nWHAT DOES THIS OPTION DO?\nKeeps or enables /etc/audit/rules.d/99-php2shell.rules for local forensic logging in /var/log/audit/audit.log (inspect with: ausearch -k php2shell_exec), but disables/stops the Telegram watcher (it-reinbek-auditwatch.service).'
      opt_info[3]=$'OPTION 3: DISABLE AUDITD RULE (ROLLBACK)\n\nWHAT DOES THIS OPTION DO?\nMarks #13 for rollback [-]: Stops it-reinbek-auditwatch.service, removes /etc/audit/rules.d/99-php2shell.rules, and unloads the php2shell_exec kernel rule on [Enter] in the main menu.'
    else
      step_title="Schritt 4a - auditd & Telegram-Meldung "
      l_box_title="auditd & Benachrichtigung"
      r_box_title="Info & Funktionsweise"
      intro_line=" Waehlen Sie, ob bei auditd (php2shell_exec) eine Telegram-Benachrichtigung gewuenscht ist (auch bei bereits aktivem auditd)."
      status_line=" Option waehlen (1=auditd + Telegram-Meldung, 2=auditd nur lokal ohne Telegram, 3=auditd deaktivieren) & [Enter] druecken."
      key_line=" Pfeile: Wahl | Leertaste/Enter: Uebernehmen | t: Telegram-Bot konfigurieren | l: DE/EN | b/q: Zurueck"

      opt_title[1]="auditd + Telegram-Meldung (empf.)"
      opt_title[2]="auditd nur lokal (ohne Telegram)"
      opt_title[3]="auditd deaktivieren (Rueckbau)"

      opt_info[1]=$'OPTION 1: AUDITD + TELEGRAM-BENACHRICHTIGUNG (it-reinbek-auditwatch)\n\nWAS MACHT DIESE OPTION?\n1. Stellt sicher, dass die Kernel-Regel /etc/audit/rules.d/99-php2shell.rules aktiv ist (protokolliert alle Programm-/Shell-Starts execve 64/32-Bit durch Webserver-Benutzer unter dem Schluessel php2shell_exec).\n2. Richtet den Hintergrunddienst it-reinbek-auditwatch.service ein, der /var/log/audit/audit.log in Echtzeit ueberwacht und verdächtige Prozessstarts sofort ueber /usr/local/sbin/it-reinbek-notify auditd an Ihren Telegram-Bot meldet.\n\nAuch wenn auditd bereits vorher eingerichtet war, koennen Sie die Telegram-Meldung hier jederzeit nachtraeglich zu- oder abschalten! Falls noch kein Bot-Token hinterlegt ist, oeffnet sich automatisch der Telegram-Dialog.'
      opt_info[2]=$'OPTION 2: AUDITD NUR LOKAL PROTOKOLLIEREN (OHNE TELEGRAM)\n\nWAS MACHT DIESE OPTION?\nAktiviert bzw. behaelt /etc/audit/rules.d/99-php2shell.rules fuer die lokale Auswertung in /var/log/audit/audit.log (Abfrage mit: ausearch -k php2shell_exec), schaltet aber den Telegram-Watcher (it-reinbek-auditwatch.service) ab.'
      opt_info[3]=$'OPTION 3: AUDITD-UEBERWACHUNG DEAKTIVIEREN (RUECKBAU)\n\nWAS MACHT DIESE OPTION?\nMarkiert Massnahme #13 zur Rueckabwicklung [-]: Stoppt it-reinbek-auditwatch.service, loescht /etc/audit/rules.d/99-php2shell.rules und entlaedt die Regel im Kernel beim Ausfuehren im Hauptmenue.'
    fi

    if [ "$UI_LANG" = "en" ]; then
      if [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 1 ]; then opt_badge[1]="[active]"; else opt_badge[1]="[recommended]"; fi
      if [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 0 ]; then opt_badge[2]="[active]"; else opt_badge[2]="[local]"; fi
      if [ "$aud_cur" -eq 0 ]; then opt_badge[3]="[inactive]"; else opt_badge[3]="[rollback]"; fi
    else
      if [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 1 ]; then opt_badge[1]="[aktiv]"; else opt_badge[1]="[empfohlen]"; fi
      if [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 0 ]; then opt_badge[2]="[aktiv]"; else opt_badge[2]="[nur lokal]"; fi
      if [ "$aud_cur" -eq 0 ]; then opt_badge[3]="[inaktiv]"; else opt_badge[3]="[rueckbau]"; fi
    fi

    local -a rlines=()
    local rline wline
    while IFS= read -r rline; do
      if [ -z "$rline" ]; then
        rlines+=("")
      else
        while IFS= read -r wline; do
          rlines+=("$wline")
        done < <(printf '%s\n' "$rline" | fold -s -w "$r_inner")
      fi
    done <<< "${opt_info[$sel]}"

    local r_total="${#rlines[@]}"
    local rmax=$(( r_total - box_h ))
    [ "$rmax" -lt 0 ] && rmax=0
    [ "$iscroll" -gt "$rmax" ] && iscroll="$rmax"
    [ "$iscroll" -lt 0 ] && iscroll=0
    local r_more_up=0 r_more_dn=0
    [ "$iscroll" -gt 0 ] && r_more_up=1
    [ $(( iscroll + box_h )) -lt "$r_total" ] && r_more_dn=1

    local rup_s="" rdn_s=""
    if [ "$r_more_up" -eq 1 ]; then rup_s=$( [ "$UI_LANG" = "en" ] && echo " ^more " || echo " ^mehr " ); fi
    if [ "$r_more_dn" -eq 1 ]; then rdn_s=$( [ "$UI_LANG" = "en" ] && echo " PgDn v more " || echo " Bild v mehr " ); fi

    local l_fill_top=$(( lw - ${#l_box_title} - 4 ))
    [ "$l_fill_top" -lt 1 ] && l_fill_top=1
    local r_fill_top=$(( rw - ${#r_box_title} - ${#rup_s} - 4 ))
    [ "$r_fill_top" -lt 1 ] && r_fill_top=1

    printf '\e[H\e[2J'
    tui_topbar "$cols" " IT-Reinbek PHP2Shell-Auditor v${VERSION}" "$step_title"
    printf '%s\n' "${intro_line:0:$cols}"
    printf '%s+-- %s%s%s %s++-- %s%s%s %s%s%s%s+%s\n' \
      "$C" "$C$B" "$l_box_title" "$N$C" "$(printf '%*s' "$l_fill_top" '' | tr ' ' '-')" \
      "$C$B" "$r_box_title" "$N$C" "$(printf '%*s' "$r_fill_top" '' | tr ' ' '-')" "$Y" "$rup_s" "$C" "$N"

    local row idx mark item_color badge title max_tlen lstr raw_len pad_len lpad rstr r_pad rfmt
    for (( row=0; row<box_h; row++ )); do
      idx=$(( row + 1 ))
      rstr="${rlines[$(( iscroll + row ))]:-}"
      if [ "$idx" -le 3 ]; then
        item_color=""
        mark=" "
        if [ "$idx" -eq "$chosen" ]; then
          if { [ "$idx" -eq 1 ] && [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 1 ]; } || { [ "$idx" -eq 2 ] && [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 0 ]; }; then
            mark="x"; item_color="$G"
          elif [ "$idx" -eq 3 ] && [ "$aud_cur" -eq 1 ]; then
            mark="-"; item_color="${R}${B}"
          else
            mark="+"; item_color="${Y}${B}"
          fi
        fi
        badge="${opt_badge[$idx]}"
        title="${opt_title[$idx]}"
        max_tlen=$(( lw - 12 - ${#badge} ))
        [ "$max_tlen" -lt 10 ] && max_tlen=10
        title="${title:0:$max_tlen}"
        if [ "$idx" -eq "$sel" ]; then
          lstr=" > [$mark] $idx) $title"
        else
          lstr="   [$mark] $idx) $title"
        fi
        raw_len=$(( ${#lstr} + ${#badge} + 1 ))
        pad_len=$(( lw - raw_len ))
        [ "$pad_len" -lt 1 ] && pad_len=1
        lstr="${lstr}$(printf '%*s' "$pad_len" '')${badge} "
        if [ "$idx" -eq "$sel" ]; then
          if [ -n "$item_color" ]; then
            lpad=$'\e[7m'"${item_color}${B}${lstr}"$'\e[0m'
          else
            lpad=$'\e[7m'"${B}${lstr}"$'\e[0m'
          fi
        elif [ -n "$item_color" ]; then
          lpad="${item_color}${lstr}${N}"
        else
          lpad="${lstr}"
        fi
      else
        lpad=$(printf '%*s' "$lw" '')
      fi

      rstr="${rstr:0:$r_inner}"
      r_pad=$(( r_inner - ${#rstr} ))
      [ "$r_pad" -lt 0 ] && r_pad=0
      case "$rstr" in
        OPTION\ *)
          rfmt=" ${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        WAS\ MACHT*|WHAT\ DOES*)
          rfmt=" ${B}${C}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        *)
          rfmt=" ${rstr}$(printf '%*s' "$r_pad" '') " ;;
      esac
      printf '%s|%s%s%s||%s%s%s|%s\n' "$C" "$N" "$lpad" "$C" "$N" "$rfmt" "$C" "$N"
    done

    local r_fill_bot=$(( rw - ${#rdn_s} ))
    [ "$r_fill_bot" -lt 1 ] && r_fill_bot=1
    printf '%s+%s++%s%s%s%s+%s\n' \
      "$C" "$(printf '%*s' "$lw" '' | tr ' ' '-')" \
      "$(printf '%*s' "$r_fill_bot" '' | tr ' ' '-')" "$Y" "$rdn_s" "$C" "$N"
    printf '%s%s%s\n' "$C" "${status_line:0:$cols}" "$N"
    printf '%s%s%s' "$B" "${key_line:0:$cols}" "$N"

    IFS= tty_read -rsn1 key || return 0
    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) sel=$(( sel > 1 ? sel - 1 : 3 )); chosen="$sel"; iscroll=0 ;;
          B) sel=$(( sel < 3 ? sel + 1 : 1 )); chosen="$sel"; iscroll=0 ;;
          5) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll > 5 ? iscroll - 5 : 0 )) ;;
          6) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll + 5 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) sel=$(( sel > 1 ? sel - 1 : 3 )); chosen="$sel"; iscroll=0 ;;
      j|J) sel=$(( sel < 3 ? sel + 1 : 1 )); chosen="$sel"; iscroll=0 ;;
      1|2|3) sel="$key"; chosen="$key"; iscroll=0 ;;
      " ") chosen="$sel" ;;
      t|T)
        tui_telegram_screen "sub"
        ;;
      l|L)
        if [ "$UI_LANG" = "de" ]; then UI_LANG="en"; else UI_LANG="de"; fi
        ;;
      b|B|q|Q)
        load_menu_texts
        return 0
        ;;
      "")
        chosen="$sel"
        case "$chosen" in
          1)
            AUDIT_TG_WANT="1"
            TG_AUDIT=1
            M_SEL[13]=1
            # Falls auditd schon aktiv war, aber der Telegram-Watcher noch nicht läuft -> als [+] Änderung vormerken!
            if [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 0 ]; then
              M_ACTIVE[13]=0
            fi
            if ! tg_is_configured && [ -z "$TG_TOKEN_IN" ]; then
              TG_ON=1
              M_SEL[18]=1
              tui_telegram_screen "sub"
            fi
            ;;
          2)
            AUDIT_TG_WANT="0"
            TG_AUDIT=0
            M_SEL[13]=1
            # Falls auditd aktiv war und der Watcher lief, jetzt auf "nur lokal" umstellen -> als [+] Änderung vormerken
            if [ "$aud_cur" -eq 1 ] && [ "$watch_cur" -eq 1 ]; then
              M_ACTIVE[13]=0
            fi
            ;;
          3)
            AUDIT_TG_WANT="0"
            M_SEL[13]=0
            ;;
        esac
        load_menu_texts
        return 0
        ;;
    esac
  done
}

tui_telegram_screen() {
  local mode="${1:-wizard}"
  tg_init
  local sel=1 iscroll=0 key k2 k3 val="" status_msg=""

  while true; do
    local cols rows lw rw box_h r_inner
    cols=$(tput cols 2>/dev/null || echo 118)
    rows=$(tput lines 2>/dev/null || echo 34)
    [ "$cols" -lt 96 ] && cols=96
    [ "$rows" -lt 24 ] && rows=24
    lw=$(( cols * 48 / 100 ))
    [ "$lw" -lt 46 ] && lw=46
    [ "$lw" -gt 64 ] && lw=64
    rw=$(( cols - lw - 4 ))
    [ "$rw" -lt 36 ] && rw=36
    box_h=$(( rows - 6 ))
    [ "$box_h" -lt 16 ] && box_h=16
    r_inner=$(( rw - 2 ))

    local tok_disp="(nicht gesetzt)"
    if [ -n "$TG_TOKEN_IN" ]; then
      tok_disp="${TG_TOKEN_IN:0:9}... (Laenge ${#TG_TOKEN_IN})"
    fi
    local chat_disp="${TG_CHAT_IN:-(nicht gesetzt)}"
    local lbl_disp="${TG_LABEL_IN:-$(hostname -f 2>/dev/null || hostname)}"

    local step_title l_box_title r_box_title intro_line status_line key_line
    local -a opt_title=() opt_badge=() opt_info=()
    local sec_info

    if [ "$UI_LANG" = "en" ]; then
      step_title="Step 3/4 - Telegram Bot & Notifications "
      l_box_title="Telegram Bot & Components"
      r_box_title="Info & Security"
      intro_line=" Should security alerts be sent via Telegram Bot? Credentials are stored securely (0600 root:root) for all modules."
      if [ -n "$status_msg" ]; then
        status_line=" $status_msg"
      else
        status_line=" Space: toggle [x]/[ ] or edit field (2-4) | t: Test token/chat (read-only) | Enter: Save & Continue"
      fi
      key_line=" Up/Down: select | Space: Toggle/Edit | t: Test Bot/Chat | Enter: Continue | l: DE/EN | q: Back/Skip"

      sec_info=$(printf 'SECURE STORAGE & ARCHITECTURE:\n- Directory /etc/it-reinbek is locked to mode 0700 (root:root).\n- Config /etc/it-reinbek/telegram.conf is written atomically via mktemp with mode 0600 (root:root).\n- Dispatcher /usr/local/sbin/it-reinbek-notify (mode 0750 root:root) passes the Bot Token to curl via stdin (-K -), so the token never appears in process lists (ps / /proc/*/cmdline).\n- Rate-limiting (max 20 msgs / 5 min) protects against alert storms.\n- Shared 1:1 with the IT-Reinbek Linux Hardening script (fail2ban, rkhunter, ClamAV, auditd).')

      opt_title[1]="Enable Telegram Bot notifications"
      opt_title[2]="Bot Token: $tok_disp"
      opt_title[3]="Chat-ID:   $chat_disp"
      opt_title[4]="Server:    $lbl_disp"
      opt_title[5]="fail2ban:  Report IP bans (stored/active)"
      opt_title[6]="rkhunter:  Report rootkit warnings (stored)"
      opt_title[7]="ClamAV:    Report malware/webshell hits"
      opt_title[8]="auditd:    Report PHP shell/execve starts"
      opt_title[9]="Test Token & Chat-ID now (read-only)"

      opt_info[1]=$(printf '1) TELEGRAM BOT NOTIFICATIONS (MASTER SWITCH)\n\nQuestion before remediation:\nShould this server send security notifications via a Telegram Bot?\n\n- [x] / [+] Enabled: Collects Bot Token, Chat-ID, and Server Label and stores them securely for fail2ban, rkhunter, ClamAV, and auditd.\n- [ ] Disabled: No Telegram messages will be sent.\n\n%s' "$sec_info")
      opt_info[2]=$(printf '2) TELEGRAM BOT TOKEN (Press [Space] to enter/change)\n\nCurrent value: %s\n\nHow to create a bot:\n1. Open Telegram and message @BotFather -> /newbot\n2. Copy the HTTP API Token (format: 123456789:AAH...)\n3. Send at least one message (/start) to your new bot in Telegram!\n\n%s' "$tok_disp" "$sec_info")
      opt_info[3]=$(printf '3) TELEGRAM CHAT-ID (Press [Space] to enter/change)\n\nCurrent value: %s\n\nFormats:\n- Personal chat: positive number (e.g. 123456789, get via @userinfobot)\n- Group / Channel: negative number (e.g. -1001234567890)\n\n%s' "$chat_disp" "$sec_info")
      opt_info[4]=$(printf '4) SERVER LABEL (Press [Space] to enter/change)\n\nCurrent value: %s\n\nShown in the header of every Telegram message so you immediately recognize which host sent the alert.\n\n%s' "$lbl_disp" "$sec_info")
      opt_info[5]=$(printf '5) MODULE: FAIL2BAN (TG_FAIL2BAN)\n\nStores TG_FAIL2BAN=1 in /etc/it-reinbek/telegram.conf and (if fail2ban is installed) hooks /etc/fail2ban/action.d/it-reinbek-telegram.conf into jail.local so IP bans are reported immediately.\n\n%s' "$sec_info")
      opt_info[6]=$(printf '6) MODULE: RKHUNTER (TG_RKHUNTER)\n\nStores TG_RKHUNTER=1 in /etc/it-reinbek/telegram.conf and installs /etc/cron.daily/rkhunter-it-reinbek so daily Rootkit Hunter warnings are sent via Telegram.\n\n%s' "$sec_info")
      opt_info[7]=$(printf '7) MODULE: CLAMAV (TG_CLAMAV)\n\nReports malware & webshell findings from ClamAV (both in Real-time mode via it-reinbek-clamwatch.service and in daily Cron/Timer mode via clamav-scan.sh).\n\n%s' "$sec_info")
      opt_info[8]=$(printf '8) MODULE: AUDITD (TG_AUDITD - php2shell_exec)\n\nReports suspicious program/shell executions by webserver users (www-data, apache, nginx) in real time via it-reinbek-auditwatch.service - works even if auditd was already configured previously!\n\n%s' "$sec_info")
      opt_info[9]=$(printf '9) READ-ONLY API TEST (getMe & getChat)\n\nPress [Space] or [t] to verify your Bot Token and Chat-ID against api.telegram.org without modifying the system yet.\n\n%s' "$sec_info")
    else
      step_title="Schritt 3/4 - Telegram-Bot & Bausteine "
      l_box_title="Telegram-Bot & Bausteine"
      r_box_title="Info & Sicherheit"
      intro_line=" Sollen Infos via Telegram-Bot gesendet werden? Zugangsdaten werden fuer alle Bausteine sicher abgelegt (0600 root:root)."
      if [ -n "$status_msg" ]; then
        status_line=" $status_msg"
      else
        status_line=" Leertaste: [x]/[ ] umschalten od. Feld (2-4) eingeben | t: Token/Chat pruefen | Enter: Uebernehmen & Weiter"
      fi
      key_line=" Pfeile: Wahl | Leertaste: Umschalten/Eingabe | t: Bot-Test | Enter: Weiter (Menue) | l: DE/EN | q: Zurueck"

      sec_info=$(printf 'SICHERE ABLAGE GEGEN UNERLAUBTEN ZUGRIFF:\n- Ordner /etc/it-reinbek wird mit 0700 (root:root) angelegt.\n- Konfig /etc/it-reinbek/telegram.conf wird atomar per mktemp mit 0600 (root:root) geschrieben.\n- Dispatcher /usr/local/sbin/it-reinbek-notify (0750 root:root) uebergibt das Bot-Token per Stdin (curl -K -), sodass es niemals in der Prozessliste (ps / /proc/*/cmdline) sichtbar ist.\n- Rate-Limit (max. 20 Nachr./5 Min.) schuetzt vor Nachrichtenflut.\n- Kompatibel & vorgehalten fuer das IT-Reinbek Linux-Haertungsskript (fail2ban, rkhunter, ClamAV, auditd).')

      opt_title[1]="Telegram-Benachrichtigungen nutzen"
      opt_title[2]="Bot-Token: $tok_disp"
      opt_title[3]="Chat-ID:   $chat_disp"
      opt_title[4]="Server:    $lbl_disp"
      opt_title[5]="fail2ban:  IP-Sperren melden (vorhalten)"
      opt_title[6]="rkhunter:  Warnungen melden (vorhalten)"
      opt_title[7]="ClamAV:    Viren-/Webshell-Funde melden"
      opt_title[8]="auditd:    Shell-/Prozessstarts melden"
      opt_title[9]="Verbindung testen (getMe / getChat)"

      opt_info[1]=$(printf '1) TELEGRAM-BOT BENACHRICHTIGUNGEN (HAUPTSCHALTER)\n\nVorab-Abfrage:\nSollen Sicherheits-Informationen via Telegram-Bot gesendet werden?\n\n- [x] / [+] Aktiviert: Fragt Bot-Token, Chat-ID und Server-Label ab und legt diese gegen unerlaubten Zugriff geschuetzt fuer fail2ban, rkhunter, ClamAV und auditd ab.\n- [ ] Deaktiviert: Es werden keine Nachrichten per Telegram versendet.\n\n%s' "$sec_info")
      opt_info[2]=$(printf '2) TELEGRAM BOT-TOKEN (Mit [Leertaste] eingeben/aendern)\n\nAktuell: %s\n\nSo erstellen Sie den Bot:\n1. In Telegram @BotFather oeffnen -> /newbot senden\n2. Den HTTP-API-Token kopieren (Format: 123456789:AAH...)\n3. Dem neuen Bot in Telegram einmal /start schreiben!\n(Eingabe erfolgt verdeckt ohne Echo auf dem Bildschirm)\n\n%s' "$tok_disp" "$sec_info")
      opt_info[3]=$(printf '3) TELEGRAM CHAT-ID (Mit [Leertaste] eingeben/aendern)\n\nAktuell: %s\n\nFormate:\n- Einzelchat: positive Zahl (z. B. 123456789, abrufbar ueber @userinfobot)\n- Gruppe / Kanal: negative Zahl (z. B. -1001234567890)\n\n%s' "$chat_disp" "$sec_info")
      opt_info[4]=$(printf '4) SERVER-NAME / LABEL (Mit [Leertaste] eingeben/aendern)\n\nAktuell: %s\n\nSteht in der Kopfzeile jeder Telegram-Nachricht, damit Sie sofort sehen, welcher Server meldet.\n\n%s' "$lbl_disp" "$sec_info")
      opt_info[5]=$(printf '5) BAUSTEIN: FAIL2BAN (TG_FAIL2BAN)\n\nHaelt die Einstellung TG_FAIL2BAN in /etc/it-reinbek/telegram.conf vor und bindet (falls fail2ban installiert ist) sofort /etc/fail2ban/action.d/it-reinbek-telegram.conf ein, damit IP-Sperren gemeldet werden.\n\n%s' "$sec_info")
      opt_info[6]=$(printf '6) BAUSTEIN: RKHUNTER (TG_RKHUNTER)\n\nHaelt die Einstellung TG_RKHUNTER in /etc/it-reinbek/telegram.conf vor und richtet den täglichen Wrapper /etc/cron.daily/rkhunter-it-reinbek ein, der bei Rootkit-Warnungen sofort per Telegram informiert.\n\n%s' "$sec_info")
      opt_info[7]=$(printf '7) BAUSTEIN: CLAMAV (TG_CLAMAV)\n\nMeldet Viren- und Webshell-Funde von ClamAV sofort per Telegram (sowohl im Echtzeit-Modus ueber it-reinbek-clamwatch.service als auch beim naechtlichen Cronjob-Scan ueber clamav-scan.sh).\n\n%s' "$sec_info")
      opt_info[8]=$(printf '8) BAUSTEIN: AUDITD (TG_AUDITD - php2shell_exec)\n\nMeldet verdächtige Programm-/Shell-Starts durch Webserver-User (www-data, apache, nginx) in Echtzeit ueber it-reinbek-auditwatch.service - auch dann, wenn auditd bereits vorher auf dem Server eingerichtet war!\n\n%s' "$sec_info")
      opt_info[9]=$(printf '9) VERBINDUNGSTEST (getMe & getChat - rein lesend)\n\nDruecken Sie [Leertaste] oder [t], um Bot-Token und Chat-ID sofort lesend gegen api.telegram.org zu pruefen.\n\n%s' "$sec_info")
    fi

    opt_badge[1]=$( [ "$TG_ON" -eq 1 ] && echo "[JA/ON]" || echo "[NEIN/OFF]" )
    opt_badge[2]="[Edit]"
    opt_badge[3]="[Edit]"
    opt_badge[4]="[Edit]"
    opt_badge[5]=$( [ "$TG_F2B" -eq 1 ] && echo "[JA]" || echo "[NEIN]" )
    opt_badge[6]=$( [ "$TG_RKH" -eq 1 ] && echo "[JA]" || echo "[NEIN]" )
    opt_badge[7]=$( [ "$TG_CLAM" -eq 1 ] && echo "[JA]" || echo "[NEIN]" )
    if [ -f "$AUDIT_RULE" ]; then
      opt_badge[8]=$( [ "$TG_AUDIT" -eq 1 ] && echo "[JA, auditd aktiv]" || echo "[NEIN, auditd aktiv]" )
    else
      opt_badge[8]=$( [ "$TG_AUDIT" -eq 1 ] && echo "[JA]" || echo "[NEIN]" )
    fi
    opt_badge[9]="[Test]"

    local -a rlines=()
    local rline wline
    while IFS= read -r rline; do
      if [ -z "$rline" ]; then
        rlines+=("")
      else
        while IFS= read -r wline; do
          rlines+=("$wline")
        done < <(printf '%s\n' "$rline" | fold -s -w "$r_inner")
      fi
    done <<< "${opt_info[$sel]}"

    local r_total="${#rlines[@]}"
    local rmax=$(( r_total - box_h ))
    [ "$rmax" -lt 0 ] && rmax=0
    [ "$iscroll" -gt "$rmax" ] && iscroll="$rmax"
    [ "$iscroll" -lt 0 ] && iscroll=0
    local r_more_up=0 r_more_dn=0
    [ "$iscroll" -gt 0 ] && r_more_up=1
    [ $(( iscroll + box_h )) -lt "$r_total" ] && r_more_dn=1

    local rup_s="" rdn_s=""
    if [ "$r_more_up" -eq 1 ]; then rup_s=$( [ "$UI_LANG" = "en" ] && echo " ^more " || echo " ^mehr " ); fi
    if [ "$r_more_dn" -eq 1 ]; then rdn_s=$( [ "$UI_LANG" = "en" ] && echo " PgDn v more " || echo " Bild v mehr " ); fi

    local l_fill_top=$(( lw - ${#l_box_title} - 4 ))
    [ "$l_fill_top" -lt 1 ] && l_fill_top=1
    local r_fill_top=$(( rw - ${#r_box_title} - ${#rup_s} - 4 ))
    [ "$r_fill_top" -lt 1 ] && r_fill_top=1

    printf '\e[H\e[2J'
    tui_topbar "$cols" " IT-Reinbek PHP2Shell-Auditor v${VERSION}" "$step_title"
    printf '%s\n' "${intro_line:0:$cols}"
    printf '%s+-- %s%s%s %s++-- %s%s%s %s%s%s%s+%s\n' \
      "$C" "$C$B" "$l_box_title" "$N$C" "$(printf '%*s' "$l_fill_top" '' | tr ' ' '-')" \
      "$C$B" "$r_box_title" "$N$C" "$(printf '%*s' "$r_fill_top" '' | tr ' ' '-')" "$Y" "$rup_s" "$C" "$N"

    local row idx mark item_color badge title max_tlen lstr raw_len pad_len lpad rstr r_pad rfmt
    for (( row=0; row<box_h; row++ )); do
      idx=$(( row + 1 ))
      rstr="${rlines[$(( iscroll + row ))]:-}"
      if [ "$idx" -le 9 ]; then
        item_color=""
        mark=" "
        case "$idx" in
          1)
            if [ "$TG_ON" -eq 1 ] && [ "$TG_CUR" -eq 1 ]; then mark="x"; item_color="$G"
            elif [ "$TG_ON" -eq 1 ] && [ "$TG_CUR" -eq 0 ]; then mark="+"; item_color="${Y}${B}"
            elif [ "$TG_ON" -eq 0 ] && [ "$TG_CUR" -eq 1 ]; then mark="-"; item_color="${R}${B}"
            else mark=" "; item_color=""
            fi
            ;;
          2)
            if [ -n "$TG_TOKEN_IN" ]; then mark="x"; item_color="$G"; else mark=" "; item_color="${Y}"; fi
            ;;
          3)
            if [ -n "$TG_CHAT_IN" ]; then mark="x"; item_color="$G"; else mark=" "; item_color="${Y}"; fi
            ;;
          4)
            if [ -n "$TG_LABEL_IN" ]; then mark="x"; item_color="$G"; else mark=" "; fi
            ;;
          5)
            if [ "$TG_F2B" -eq 1 ]; then mark="x"; item_color="$G"; else mark=" "; fi
            ;;
          6)
            if [ "$TG_RKH" -eq 1 ]; then mark="x"; item_color="$G"; else mark=" "; fi
            ;;
          7)
            if [ "$TG_CLAM" -eq 1 ]; then mark="x"; item_color="$G"; else mark=" "; fi
            ;;
          8)
            if [ "$TG_AUDIT" -eq 1 ]; then mark="x"; item_color="$G"; else mark=" "; fi
            ;;
          9)
            mark="t"; item_color="$C"
            ;;
        esac

        badge="${opt_badge[$idx]}"
        title="${opt_title[$idx]}"
        max_tlen=$(( lw - 12 - ${#badge} ))
        [ "$max_tlen" -lt 10 ] && max_tlen=10
        title="${title:0:$max_tlen}"
        if [ "$idx" -eq "$sel" ]; then
          lstr=" > [$mark] $idx) $title"
        else
          lstr="   [$mark] $idx) $title"
        fi
        raw_len=$(( ${#lstr} + ${#badge} + 1 ))
        pad_len=$(( lw - raw_len ))
        [ "$pad_len" -lt 1 ] && pad_len=1
        lstr="${lstr}$(printf '%*s' "$pad_len" '')${badge} "
        if [ "$idx" -eq "$sel" ]; then
          if [ -n "$item_color" ]; then
            lpad=$'\e[7m'"${item_color}${B}${lstr}"$'\e[0m'
          else
            lpad=$'\e[7m'"${B}${lstr}"$'\e[0m'
          fi
        elif [ -n "$item_color" ]; then
          lpad="${item_color}${lstr}${N}"
        else
          lpad="${lstr}"
        fi
      else
        lpad=$(printf '%*s' "$lw" '')
      fi

      rstr="${rstr:0:$r_inner}"
      r_pad=$(( r_inner - ${#rstr} ))
      [ "$r_pad" -lt 0 ] && r_pad=0
      case "$rstr" in
        [1-9]\)\ *)
          rfmt=" ${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        SICHERE\ ABLAGE*|SECURE\ STORAGE*|Vorab-Abfrage:*|Question\ before*)
          rfmt=" ${B}${C}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
        *)
          rfmt=" ${rstr}$(printf '%*s' "$r_pad" '') " ;;
      esac
      printf '%s|%s%s%s||%s%s%s|%s\n' "$C" "$N" "$lpad" "$C" "$N" "$rfmt" "$C" "$N"
    done

    local r_fill_bot=$(( rw - ${#rdn_s} ))
    [ "$r_fill_bot" -lt 1 ] && r_fill_bot=1
    printf '%s+%s++%s%s%s%s+%s\n' \
      "$C" "$(printf '%*s' "$lw" '' | tr ' ' '-')" \
      "$(printf '%*s' "$r_fill_bot" '' | tr ' ' '-')" "$Y" "$rdn_s" "$C" "$N"
    printf '%s%s%s\n' "$C" "${status_line:0:$cols}" "$N"
    printf '%s%s%s' "$B" "${key_line:0:$cols}" "$N"

    IFS= tty_read -rsn1 key || return 0
    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) sel=$(( sel > 1 ? sel - 1 : 9 )); iscroll=0 ;;
          B) sel=$(( sel < 9 ? sel + 1 : 1 )); iscroll=0 ;;
          5) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll > 5 ? iscroll - 5 : 0 )) ;;
          6) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll + 5 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) sel=$(( sel > 1 ? sel - 1 : 9 )); iscroll=0 ;;
      j|J) sel=$(( sel < 9 ? sel + 1 : 1 )); iscroll=0 ;;
      [1-9]) sel="$key"; iscroll=0 ;;
      l|L)
        if [ "$UI_LANG" = "de" ]; then UI_LANG="en"; else UI_LANG="de"; fi
        ;;
      t|T)
        if ! tg_valid_token "$TG_TOKEN_IN"; then
          status_msg="FEHLER: Bitte zuerst ein gueltiges Bot-Token (Punkt 2) eingeben!"
        else
          status_msg="Pruefe Bot-Token & Chat-ID lesend gegen api.telegram.org ..."
          if tg_check_token "$TG_TOKEN_IN"; then
            if tg_valid_chat "$TG_CHAT_IN"; then
              if tg_check_chat "$TG_TOKEN_IN" "$TG_CHAT_IN"; then
                status_msg="OK: Bot (@${TG_BOT_USER:-bot}) und Chat (${TG_CHAT_TITLE:-$TG_CHAT_IN}) erfolgreich verifiziert!"
              else
                status_msg="WARNUNG: Bot (@${TG_BOT_USER:-bot}) OK, aber Chat nicht erreichbar (${TG_LAST_ERR:-/start beim Bot gesendet?})."
              fi
            else
              status_msg="OK: Bot (@${TG_BOT_USER:-bot}) verifiziert! Bitte noch Chat-ID (Punkt 3) eintragen."
            fi
          else
            status_msg="FEHLER: Bot-Token ungueltig oder kein Internet (${TG_LAST_ERR:-Pruefung fehlgeschlagen})."
          fi
        fi
        ;;
      " ")
        case "$sel" in
          1)
            TG_ON=$(( 1 - TG_ON ))
            if [ "$TG_ON" -eq 1 ] && [ -z "$TG_TOKEN_IN" ]; then
              printf '\n%sBot-Token (Eingabe verdeckt, Enter bestaetigt):%s ' "$B$Y" "$N"
              tty_read -rs val || val=""
              echo ""
              if [ -n "$val" ]; then
                if tg_valid_token "$val"; then
                  TG_TOKEN_IN="$val"
                  status_msg="Bot-Token uebernommen."
                else
                  status_msg="Ungueltiges Token-Format (erwartet: 123456789:AAH...)."
                fi
              fi
              if [ -z "$TG_CHAT_IN" ]; then
                printf '%sTelegram Chat-ID (z. B. 123456789 oder -100...):%s ' "$B$Y" "$N"
                tty_read -r val || val=""
                if [ -n "$val" ] && tg_valid_chat "$val"; then
                  TG_CHAT_IN="$val"
                  status_msg="Bot-Token & Chat-ID uebernommen."
                fi
              fi
            fi
            ;;
          2)
            printf '\n%sBot-Token (Eingabe verdeckt, leer = unveraendert):%s ' "$B$Y" "$N"
            tty_read -rs val || val=""
            echo ""
            if [ -n "$val" ]; then
              if tg_valid_token "$val"; then
                TG_TOKEN_IN="$val"
                TG_ON=1
                status_msg="Bot-Token aktualisiert."
              else
                status_msg="Ungueltiges Token-Format (erwartet: 123456789:AAH...)."
              fi
            fi
            ;;
          3)
            printf '\n%sTelegram Chat-ID [%s]:%s ' "$B$Y" "${TG_CHAT_IN:-}" "$N"
            tty_read -r val || val=""
            if [ -n "$val" ]; then
              if tg_valid_chat "$val"; then
                TG_CHAT_IN="$val"
                TG_ON=1
                status_msg="Chat-ID aktualisiert: $val"
              else
                status_msg="Ungueltige Chat-ID (nur Ziffern, optional fuehrendes Minus)."
              fi
            fi
            ;;
          4)
            printf '\n%sServer-Name / Label [%s]:%s ' "$B$Y" "$lbl_disp" "$N"
            tty_read -r val || val=""
            if [ -n "$val" ]; then
              if tg_valid_label "$val"; then
                TG_LABEL_IN="$val"
                status_msg="Server-Label aktualisiert: $val"
              else
                status_msg="Ungueltiges Label (max. 64 Zeichen, keine Anfuehrungszeichen/Zeilenumbrueche)."
              fi
            fi
            ;;
          5) TG_F2B=$(( 1 - TG_F2B )) ;;
          6) TG_RKH=$(( 1 - TG_RKH )) ;;
          7) TG_CLAM=$(( 1 - TG_CLAM )); CLAM_TG_WANT="$TG_CLAM" ;;
          8) TG_AUDIT=$(( 1 - TG_AUDIT )); AUDIT_TG_WANT="$TG_AUDIT" ;;
          9)
            if tg_valid_token "$TG_TOKEN_IN" && tg_check_token "$TG_TOKEN_IN"; then
              if tg_valid_chat "$TG_CHAT_IN" && tg_check_chat "$TG_TOKEN_IN" "$TG_CHAT_IN"; then
                status_msg="OK: Bot (@${TG_BOT_USER:-bot}) & Chat (${TG_CHAT_TITLE:-$TG_CHAT_IN}) erreichbar!"
              else
                status_msg="Bot (@${TG_BOT_USER:-bot}) OK, Chat-Pruefung: ${TG_LAST_ERR:-Chat-ID pruefen}"
              fi
            else
              status_msg="FEHLER: ${TG_LAST_ERR:-Bitte gueltiges Bot-Token unter 2) eingeben}"
            fi
            ;;
        esac
        ;;
      b|B|q|Q)
        load_menu_texts
        return 0
        ;;
      "")
        if [ "$TG_ON" -eq 1 ]; then
          if ! tg_valid_token "$TG_TOKEN_IN" || ! tg_valid_chat "$TG_CHAT_IN"; then
            status_msg="Bitte erst Bot-Token (2) und Chat-ID (3) eingeben (oder Punkt 1 mit Leertaste abwaehlen)!"
            continue
          fi
          M_SEL[18]=1
          CLAM_TG_WANT="$TG_CLAM"
          AUDIT_TG_WANT="$TG_AUDIT"
          # Falls Telegram bereits aktiv war, aber Einstellungen geändert wurden -> als [+] zur Aktualisierung vormerken
          if [ "$TG_CUR" -eq 1 ]; then
            if [ "$TG_TOKEN_IN" != "$(tg_conf_get TG_TOKEN)" ] || \
               [ "$TG_CHAT_IN" != "$(tg_conf_get TG_CHAT_ID)" ] || \
               [ "$TG_LABEL_IN" != "$(tg_conf_get TG_LABEL)" ] || \
               [ "$TG_F2B" != "$(tg_conf_get TG_FAIL2BAN)" ] || \
               [ "$TG_RKH" != "$(tg_conf_get TG_RKHUNTER)" ] || \
               [ "$TG_CLAM" != "$(tg_conf_get TG_CLAMAV)" ] || \
               [ "$TG_AUDIT" != "$(tg_conf_get TG_AUDITD)" ]; then
              M_ACTIVE[18]=0
            fi
          fi
          # Falls auditd bereits auf dem Server aktiv ist und Telegram für auditd gewünscht ist -> direkt vormerken!
          if [ -f "$AUDIT_RULE" ]; then
            if [ "$TG_AUDIT" -eq 1 ] && ! systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null; then
              M_ACTIVE[13]=0
              M_SEL[13]=1
            elif [ "$TG_AUDIT" -eq 0 ] && systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null; then
              M_ACTIVE[13]=0
              M_SEL[13]=1
            fi
          fi
        else
          M_SEL[18]=0
        fi
        load_menu_texts
        return 0
        ;;
    esac
  done
}

tui_befund_screen() {
  local scroll=0 key k2 k3
  local host_str os_str vuln
  host_str=$(hostname 2>/dev/null || echo "server")
  os_str="${OS_PRETTY:-Linux}"
  vuln=$(( ${#NEED_UPDATE[@]} + ${#DK_VULN[@]} ))

  while true; do
    clam_recommend
    clam_mode_detect
    tg_init
    local cols rows box_h text_w
    cols=$(tput cols 2>/dev/null || echo 118)
    rows=$(tput lines 2>/dev/null || echo 34)
    [ "$cols" -lt 88 ] && cols=88
    [ "$rows" -lt 22 ] && rows=22
    box_h=$(( rows - 5 ))
    text_w=$(( cols - 6 ))

    local step_title box_title status_line key_line rec_line
    local s_php s_dk s_stale s_att s_comp s_mit s_sess s_aud s_clam s_tg
    if [ "$UI_LANG" = "en" ]; then
      step_title="Step 2/4 - System Audit & Findings "
      box_title="Info"
      status_line=" Read-only system audit completed. Review findings below and press [Enter] for Step 3/4 (Telegram Bot & Menu)."
      key_line=" Up/Down/PgDn: scroll | Enter: Continue (Telegram & Menu) | t: Telegram | l: DE/EN | p/r: Print | q: Quit"

      if [ "$COMP" -gt 0 ]; then
        rec_line="${R}${B}SUSPECTED COMPROMISE!${N} Recommended: [1] Preserve evidence -> Disconnect -> [3/4/6] Patch -> [10] Restart -> [12] Quarantine -> [11] Sessions -> [15] Rotate secrets."
      elif [ "$vuln" -gt 0 ]; then
        rec_line="${Y}${B}PHP IS VULNERABLE (No compromise detected).${N} BSI: Patch immediately ([3]/[4]+[5]/[6]) or apply ALL BSI workarounds ([7]+[8]+[9]) -> [10] Restart -> [11] Sessions."
      elif [ "$ATT" -gt 0 ]; then
        rec_line="${Y}${B}PHP patched, but attack/segfault indicators found.${N} Recommended: [1] Evidence, [13] auditd monitoring, [15] Rotate secrets."
      elif [ "$STALE" -gt 0 ]; then
        rec_line="${Y}${B}Patched on disk, but services still run old PHP in RAM.${N} Recommended: [10] Restart PHP-FPM / web services."
      else
        rec_line="${G}${B}No immediate action required.${N} Optional: [13] auditd monitoring, [17] ClamAV protection, [18] Telegram alerts, [15] Print audit report."
      fi

      if [ "${#NEED_UPDATE[@]}" -gt 0 ]; then s_php="${R}${B}VULNERABLE (${#NEED_UPDATE[@]} package/binary target(s))${N}"; else s_php="${G}${B}PATCHED / OK${N}"; fi
      if [ "${#DK_VULN[@]}" -gt 0 ]; then s_dk="${R}${B}VULNERABLE (${#DK_VULN[@]} container(s))${N}"; else s_dk="${G}${B}OK / None vulnerable${N}"; fi
      if [ "$STALE" -gt 0 ]; then s_stale="${Y}${B}RESTART REQUIRED ($STALE process(es))${N}"; else s_stale="${G}${B}Up to date in RAM${N}"; fi
      if [ "$ATT" -gt 0 ]; then s_att="${Y}${B}$ATT indicator(s) found${N}"; else s_att="${G}${B}None (0)${N}"; fi
      if [ "$COMP" -gt 0 ]; then s_comp="${R}${B}$COMP CRITICAL indicator(s)!${N}"; else s_comp="${G}${B}None (0)${N}"; fi
      if [ "$CLAM_MODE_CUR" = "live" ]; then
        s_clam="${G}${B}[x] Active (Real-time clamd+On-Access)${N} | RAM suggestion: ${CLAM_REC} (~${CLAM_EFF_MB} MB free)"
      elif [ "$CLAM_MODE_CUR" = "cron" ]; then
        s_clam="${G}${B}[x] Active (Daily Cron/Timer 03:30)${N} | RAM suggestion: ${CLAM_REC} (~${CLAM_EFF_MB} MB free)"
      else
        s_clam="[ ] Inactive | RAM suggestion: ${Y}${B}${CLAM_REC}${N} (~${CLAM_EFF_MB} MB free)"
      fi
      if [ "$TG_CUR" -eq 1 ]; then
        s_tg="${G}${B}[x] Configured (${TG_CONF}, 0600)${N} | Modules: $(tg_cat_text "$TG_F2B" "$TG_RKH" "$TG_CLAM" "$TG_AUDIT")"
      else
        s_tg="[ ] Not configured yet (will be asked in Step 3/4)"
      fi
    else
      step_title="Schritt 2/4 - Systempruefung & Befund "
      box_title="Info"
      status_line=" Lesende Systempruefung abgeschlossen. Befund pruefen und mit [Enter] weiter zu Schritt 3/4 (Telegram-Bot & Menue)."
      key_line=" Pfeile/Bild: scrollen | Enter: Weiter (Telegram & Menue) | t: Telegram | l: DE/EN | p/r: Drucken | q: Abbruch"

      if [ "$COMP" -gt 0 ]; then
        rec_line="${R}${B}VERDACHT AUF BEFALL!${N} Empfehlung: [1] Beweise sichern -> Vom Netz trennen -> [3/4/6] Update -> [10] Dienste neu starten -> [12] Quarantaene -> [11] Sessions -> [15] Secrets rotieren."
      elif [ "$vuln" -gt 0 ]; then
        rec_line="${Y}${B}PHP ist verwundbar, kein Befall erkannt.${N} BSI-Empfehlung: Sofort Update ([3]/[4]+[5]/[6]) oder ALLE BSI-Workarounds ([7]+[8]+[9]) -> [10] Dienste neu starten -> [11] Sessions."
      elif [ "$ATT" -gt 0 ]; then
        rec_line="${Y}${B}PHP gepatcht, aber Hinweise auf Angriffsversuche/Segfaults.${N} Empfohlen: [1] Beweise sichern, [13] auditd-Ueberwachung, [15] Secrets rotieren."
      elif [ "$STALE" -gt 0 ]; then
        rec_line="${Y}${B}Gepatcht, aber Dienste laufen noch mit altem Code im RAM.${N} Empfohlen: [10] Dienste neu starten."
      else
        rec_line="${G}${B}Kein unmittelbarer Handlungsbedarf erkannt.${N} Optional: [13] auditd-Ueberwachung, [17] ClamAV-Schutz, [18] Telegram-Bot, [15] Revisionsbericht drucken."
      fi

      if [ "${#NEED_UPDATE[@]}" -gt 0 ]; then s_php="${R}${B}VERWUNDBAR (${#NEED_UPDATE[@]} Ziel(e))${N}"; else s_php="${G}${B}GEPATCHT / OK${N}"; fi
      if [ "${#DK_VULN[@]}" -gt 0 ]; then s_dk="${R}${B}VERWUNDBAR (${#DK_VULN[@]} Container)${N}"; else s_dk="${G}${B}OK / Keine verwundbaren Container${N}"; fi
      if [ "$STALE" -gt 0 ]; then s_stale="${Y}${B}NEUSTART NOETIG ($STALE Prozess(e))${N}"; else s_stale="${G}${B}Aktuell im RAM${N}"; fi
      if [ "$ATT" -gt 0 ]; then s_att="${Y}${B}$ATT Hinweis(e) gefunden${N}"; else s_att="${G}${B}Keine (0)${N}"; fi
      if [ "$COMP" -gt 0 ]; then s_comp="${R}${B}$COMP KRITISCHE Treffer!${N}"; else s_comp="${G}${B}Keine (0)${N}"; fi
      if [ "$CLAM_MODE_CUR" = "live" ]; then
        s_clam="${G}${B}[x] Aktiv (Echtzeit clamd+On-Access)${N} | RAM-Vorschlag: ${CLAM_REC} (~${CLAM_EFF_MB} MB frei)"
      elif [ "$CLAM_MODE_CUR" = "cron" ]; then
        s_clam="${G}${B}[x] Aktiv (Zeitplan/Cronjob 03:30)${N} | RAM-Vorschlag: ${CLAM_REC} (~${CLAM_EFF_MB} MB frei)"
      else
        s_clam="[ ] Inaktiv | RAM-Vorschlag: ${Y}${B}${CLAM_REC}${N} (~${CLAM_EFF_MB} MB frei)"
      fi
      if [ "$TG_CUR" -eq 1 ]; then
        s_tg="${G}${B}[x] Eingerichtet (${TG_CONF}, 0600)${N} | Bausteine: $(tg_cat_text "$TG_F2B" "$TG_RKH" "$TG_CLAM" "$TG_AUDIT")"
      else
        s_tg="[ ] Noch nicht eingerichtet (wird im naechsten Schritt 3/4 abgefragt)"
      fi
    fi

    if [ "${M_ACTIVE[7]:-0}" -eq 1 ]; then s_mit="${G}${B}[x] $( [ "$UI_LANG" = "en" ] && echo "Active" || echo "Aktiv" )${N}"; else s_mit="[ ] $( [ "$UI_LANG" = "en" ] && echo "Inactive" || echo "Inaktiv" )"; fi
    if [ "${M_ACTIVE[8]:-0}" -eq 1 ]; then s_sess="${G}${B}[x] $( [ "$UI_LANG" = "en" ] && echo "Active" || echo "Aktiv" )${N}"; else s_sess="[ ] $( [ "$UI_LANG" = "en" ] && echo "Inactive" || echo "Inaktiv" )"; fi
    if [ "${M_ACTIVE[13]:-0}" -eq 1 ]; then
      if systemctl is-active --quiet it-reinbek-auditwatch.service 2>/dev/null; then
        s_aud="${G}${B}[x] $( [ "$UI_LANG" = "en" ] && echo "Active (+ Telegram)" || echo "Aktiv (+ Telegram)" )${N}"
      else
        s_aud="${G}${B}[x] $( [ "$UI_LANG" = "en" ] && echo "Active (local only)" || echo "Aktiv (nur lokal)" )${N}"
      fi
    else
      s_aud="[ ] $( [ "$UI_LANG" = "en" ] && echo "Inactive" || echo "Inaktiv" )"
    fi

    local -a blines=()
    blines+=("")
    blines+=("  ${B}Server:${N} ${host_str}   ${B}System:${N} ${os_str}   ${B}CRIT:${N} ${R}${B}${CRIT}${N}   ${B}WARN:${N} ${Y}${B}${WARN}${N}   ${B}COMP:${N} ${R}${B}${COMP}${N}   ${B}ATT:${N} ${Y}${B}${ATT}${N}")
    blines+=("")
    if [ "$UI_LANG" = "en" ]; then
      blines+=("  This tool audits the server for ${B}CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)${N} per BSI advisory.")
      blines+=("  No changes have been made yet. You decide in the next steps which actions to apply or roll back.")
    else
      blines+=("  Dieses Werkzeug prueft den Server auf ${B}CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)${N} gemaess BSI-Warnung.")
      blines+=("  Es wurde noch nichts veraendert. Sie entscheiden in den naechsten Schritten selbst, was umgesetzt wird.")
    fi
    blines+=("")

    local rline wline
    while IFS= read -r wline; do
      blines+=("  $wline")
    done < <(printf '%s\n' "$rec_line" | fold -s -w "$((text_w - 2))")

    blines+=("")
    if [ "$UI_LANG" = "en" ]; then
      blines+=("  ${C}${B}CURRENT SYSTEM FINDINGS OVERVIEW:${N}")
      blines+=("    Host PHP Packages/Binaries : $s_php")
      blines+=("    Docker / OCI Containers    : $s_dk")
      blines+=("    Running Services (RAM)     : $s_stale")
      blines+=("    Attack / Crash Indicators  : $s_att")
      blines+=("    Compromise / Webshells     : $s_comp")
      blines+=("    BSI Workarounds (#7/#8)    : INI Drop-in: $s_mit | Session Storage: $s_sess | Auditd (#13): $s_aud")
      blines+=("    ClamAV Protection (#17)    : $s_clam")
      blines+=("    Telegram Bot Alerts (#18)  : $s_tg")
      blines+=("")
      blines+=("  ${C}${B}DETAILED SCAN LOG (scroll with Up/Down/PgDn):${N}")
      blines+=("  $(printf '%*s' "$((text_w - 4))" '' | tr ' ' '-')")
    else
      blines+=("  ${C}${B}AKTUELLER BEFUND (ZUSAMMENFASSUNG):${N}")
      blines+=("    Host-PHP-Pakete/Binaries   : $s_php")
      blines+=("    Docker / OCI Container     : $s_dk")
      blines+=("    Laufende Dienste (RAM)     : $s_stale")
      blines+=("    Angriffs-/Segfault-Spuren  : $s_att")
      blines+=("    Kompromittierung/Webshells : $s_comp")
      blines+=("    BSI-Workarounds (#7/#8)    : INI-Drop-in: $s_mit | Session-Schutz: $s_sess | Auditd (#13): $s_aud")
      blines+=("    ClamAV Malwareschutz (#17) : $s_clam")
      blines+=("    Telegram-Bot Meldung (#18) : $s_tg")
      blines+=("")
      blines+=("  ${C}${B}DETAILLIERTER SCAN-BERICHT (mit Pfeiltasten / Bild-ab scrollen):${N}")
      blines+=("  $(printf '%*s' "$((text_w - 4))" '' | tr ' ' '-')")
    fi

    if [ -n "${SCAN_CAPTURED:-}" ] && [ -s "$SCAN_CAPTURED" ]; then
      while IFS= read -r rline; do
        rline=$(printf '%s' "$rline" | tr '\t' ' ')
        local plain_r
        plain_r=$(printf '%s' "$rline" | sed $'s/\e\\[[0-9;]*[a-zA-Z]//g')
        if [ "${#plain_r}" -gt "$((text_w - 2))" ]; then
          while IFS= read -r wline; do
            blines+=("  $wline")
          done < <(printf '%s\n' "$plain_r" | fold -s -w "$((text_w - 2))")
        else
          blines+=("  $rline")
        fi
      done < "$SCAN_CAPTURED"
    fi

    local total="${#blines[@]}"
    local max_scroll=$(( total - box_h ))
    [ "$max_scroll" -lt 0 ] && max_scroll=0
    [ "$scroll" -gt "$max_scroll" ] && scroll="$max_scroll"
    [ "$scroll" -lt 0 ] && scroll=0

    local more_up=0 more_dn=0
    [ "$scroll" -gt 0 ] && more_up=1
    [ $(( scroll + box_h )) -lt "$total" ] && more_dn=1

    printf '\e[H\e[2J'
    tui_topbar "$cols" " IT-Reinbek PHP2Shell-Auditor v${VERSION}" "$step_title"
    tui_single_box_top "$cols" "$box_title" "$more_up"

    local idx line plain plen pad
    for (( idx=0; idx<box_h; idx++ )); do
      line="${blines[$(( scroll + idx ))]:-}"
      plain=$(printf '%s' "$line" | sed $'s/\e\\[[0-9;]*[a-zA-Z]//g')
      plen="${#plain}"
      pad=$(( cols - 4 - plen ))
      [ "$pad" -lt 0 ] && pad=0
      printf '%s|%s %s%*s %s|%s\n' "$C" "$N" "$line" "$pad" "" "$C" "$N"
    done

    tui_single_box_bot "$cols" "$more_dn"
    printf '%s%s%s\n' "$C" "${status_line:0:$cols}" "$N"
    printf '%s%s%s' "$B" "${key_line:0:$cols}" "$N"

    IFS= tty_read -rsn1 key || return 1
    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) scroll=$(( scroll - 1 )) ;;
          B) scroll=$(( scroll + 1 )) ;;
          5) IFS= tty_read -rsn1 -t 0.02 _ || true; scroll=$(( scroll - box_h / 2 )) ;;
          6) IFS= tty_read -rsn1 -t 0.02 _ || true; scroll=$(( scroll + box_h / 2 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) scroll=$(( scroll - 1 )) ;;
      j|J) scroll=$(( scroll + 1 )) ;;
      " ") scroll=$(( scroll + box_h / 2 )) ;;
      t|T)
        tui_telegram_screen "sub"
        ;;
      l|L)
        if [ "$UI_LANG" = "de" ]; then UI_LANG="en"; else UI_LANG="de"; fi
        load_menu_texts 2>/dev/null || true
        ;;
      p|P)
        clear
        act_rotate
        printf '\n%s[Enter] ...%s' "$B" "$N"
        tty_read -r _ || true
        ;;
      r|R)
        clear
        act_print_full_report
        printf '\n%s[Enter] ...%s' "$B" "$N"
        tty_read -r _ || true
        ;;
      ""|m|M)
        return 0
        ;;
      q|Q)
        clear
        return 1
        ;;
    esac
  done
}

tui_render() {
  local cur="$1" iscroll="${2:-0}"
  local cols rows lw rw box_h i mark state_txt badge num title lpad rline wline
  cols=$(tput cols 2>/dev/null || echo 118)
  rows=$(tput lines 2>/dev/null || echo 34)
  [ "$cols" -lt 96 ] && cols=96
  [ "$rows" -lt 24 ] && rows=24

  lw=$(( cols * 46 / 100 ))
  [ "$lw" -lt 44 ] && lw=44
  [ "$lw" -gt 62 ] && lw=62
  rw=$(( cols - lw - 4 ))
  [ "$rw" -lt 36 ] && rw=36
  box_h=$(( rows - 6 ))
  [ "$box_h" -lt 16 ] && box_h=16

  local r_inner=$(( rw - 2 ))

  if [ "$UI_LANG" = "en" ]; then
    if [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_SEL[$cur]}" -eq 1 ]; then
      state_txt="ACTIVE / CONFIGURED [x] (Press Space to mark for ROLLBACK [-] or adjust sub-options)"
    elif [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_SEL[$cur]}" -eq 0 ]; then
      state_txt="MARKED FOR ROLLBACK [-] (will be reverted on [Enter]!)"
    elif [ "${M_ACTIVE[$cur]}" -eq 0 ] && [ "${M_SEL[$cur]}" -eq 1 ]; then
      state_txt="MARKED FOR ACTIVATION [+] (will be applied on [Enter]!)"
    else
      state_txt="NOT CONFIGURED [ ] (Press Space to mark for activation [+])"
    fi
  else
    if [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_SEL[$cur]}" -eq 1 ]; then
      state_txt="AKTIV / KONFIGURIERT [x] (Leertaste markiert zur RUECKABWICKLUNG [-] bzw. oeffnet Optionen)"
    elif [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_SEL[$cur]}" -eq 0 ]; then
      state_txt="ZUR RUECKABWICKLUNG VORGEMERKT [-] (wird bei [Enter] rueckgaengig gemacht!)"
    elif [ "${M_ACTIVE[$cur]}" -eq 0 ] && [ "${M_SEL[$cur]}" -eq 1 ]; then
      state_txt="ZUR AKTIVIERUNG VORGEMERKT [+] (wird bei [Enter] ausgefuehrt/konfiguriert!)"
    else
      state_txt="NICHT KONFIGURIERT [ ] (Anwaehlen mit Leertaste markiert zur Aktivierung [+])"
    fi
  fi

  local -a rlines=()
  local raw_right
  if [ "$UI_LANG" = "en" ]; then
    raw_right=$(
      printf 'ACTION #%d: %s\n\n' "$cur" "${M_TITLE[$cur]}"
      printf 'CURRENT SYSTEM & SELECTION STATUS:\n%s\n\n' "$state_txt"
      printf 'IMPACT LEVEL / RISK:\n%s\n\n' "${M_RISK[$cur]}"
      printf 'WHAT DOES THIS STEP DO?\n%s\n\n' "${M_WHAT[$cur]}"
      printf 'CONSEQUENCES & NOTES (BSI):\n%s\n\n' "${M_IMPACT[$cur]}"
      printf 'ROLLBACK (WHEN UNCHECKING THE BOX):\n%s\n' "${M_UNDO[$cur]}"
    )
  else
    raw_right=$(
      printf 'MAßNAHME #%d: %s\n\n' "$cur" "${M_TITLE[$cur]}"
      printf 'AKTUELLER SYSTEM- & AUSWAHLSTATUS:\n%s\n\n' "$state_txt"
      printf 'EINGRIFFSTIEFE / RISIKO:\n%s\n\n' "${M_RISK[$cur]}"
      printf 'WAS MACHT DIESER SCHRITT?\n%s\n\n' "${M_WHAT[$cur]}"
      printf 'FOLGEN & HINWEISE (BSI):\n%s\n\n' "${M_IMPACT[$cur]}"
      printf 'RÜCKABWICKLUNG (BEI ABWÄHLEN DER CHECKBOX):\n%s\n' "${M_UNDO[$cur]}"
    )
  fi
  while IFS= read -r rline; do
    if [ -z "$rline" ]; then
      rlines+=("")
    else
      while IFS= read -r wline; do
        rlines+=("$wline")
      done < <(printf '%s\n' "$rline" | fold -s -w "$r_inner")
    fi
  done <<< "$raw_right"

  local -a llines=()
  local last_cat="" cur_row_idx=0
  for i in {1..18}; do
    if [ "${M_CAT[$i]}" != "$last_cat" ]; then
      last_cat="${M_CAT[$i]}"
      llines+=("CAT|$last_cat")
    fi
    [ "$i" -eq "$cur" ] && cur_row_idx="${#llines[@]}"
    llines+=("ITEM|$i")
  done

  local l_total="${#llines[@]}"
  local lscroll=0
  if [ "$l_total" -gt "$box_h" ]; then
    lscroll=$(( cur_row_idx - box_h / 2 ))
    local lmax=$(( l_total - box_h ))
    [ "$lscroll" -gt "$lmax" ] && lscroll="$lmax"
    [ "$lscroll" -lt 0 ] && lscroll=0
  fi
  local l_more_up=0 l_more_dn=0
  [ "$lscroll" -gt 0 ] && l_more_up=1
  [ $(( lscroll + box_h )) -lt "$l_total" ] && l_more_dn=1

  local r_total="${#rlines[@]}"
  local rmax=$(( r_total - box_h ))
  [ "$rmax" -lt 0 ] && rmax=0
  [ "$iscroll" -gt "$rmax" ] && iscroll="$rmax"
  [ "$iscroll" -lt 0 ] && iscroll=0
  local r_more_up=0 r_more_dn=0
  [ "$iscroll" -gt 0 ] && r_more_up=1
  [ $(( iscroll + box_h )) -lt "$r_total" ] && r_more_dn=1

  local count_new=0 count_undo=0 count_act=0
  for i in {1..18}; do
    [ "${M_ACTIVE[$i]}" -eq 1 ] && count_act=$(( count_act + 1 ))
    if [ "${M_ACTIVE[$i]}" -eq 0 ] && [ "${M_SEL[$i]}" -eq 1 ]; then count_new=$(( count_new + 1 )); fi
    if [ "${M_ACTIVE[$i]}" -eq 1 ] && [ "${M_SEL[$i]}" -eq 0 ]; then count_undo=$(( count_undo + 1 )); fi
  done

  local step_title l_box_title r_box_title status_line key_line
  if [ "$UI_LANG" = "en" ]; then
    step_title="Step 4/4 - Remediation (CRIT:${CRIT} WARN:${WARN} COMP:${COMP}) "
    l_box_title="Selection (1-18)"
    r_box_title="Info"
    status_line=" Active [x]: ${count_act} | Marked for activation [+]: ${count_new} | Marked for rollback [-]: ${count_undo} | Enter applies changes."
    key_line=" Arrows: select | Space: [x]/[+]/[-] | t: Telegram | c: ClamAV | Enter: Apply | b: Findings | l: DE/EN | q: Quit"
  else
    step_title="Schritt 4/4 - Massnahmen (CRIT:${CRIT} WARN:${WARN} COMP:${COMP}) "
    l_box_title="Auswahl (1-18)"
    r_box_title="Info"
    status_line=" Aktiv [x]: ${count_act} | Zur Aktivierung [+]: ${count_new} | Zur Rueckabwicklung [-]: ${count_undo} | Enter fuehrt Aenderungen aus."
    key_line=" Pfeile: Wahl | Leertaste: [x]/[+]/[-] | t: Telegram | c: ClamAV | Enter: Weiter | b: Befund | l: DE/EN | q: Ende"
  fi

  printf '\e[H\e[2J'
  tui_topbar "$cols" " IT-Reinbek PHP2Shell-Auditor v${VERSION}" "$step_title"

  if [ "$UI_LANG" = "en" ]; then
    printf ' Select actions with Space. Legend: %s[x] Active%s | %s[+] Activate (new)%s | %s[-] Rollback%s | [ ] Inactive\n' \
      "$G$B" "$N" "$Y$B" "$N" "$R$B" "$N"
  else
    printf ' Waehlen Sie die gewuenschten Massnahmen. Legende: %s[x] Aktiv%s | %s[+] Neu aktivieren%s | %s[-] Rueckabwickeln%s | [ ] Inaktiv\n' \
      "$G$B" "$N" "$Y$B" "$N" "$R$B" "$N"
  fi

  local lup_s="" rup_s="" ldn_s="" rdn_s=""
  if [ "$l_more_up" -eq 1 ]; then lup_s=$( [ "$UI_LANG" = "en" ] && echo " ^more " || echo " ^mehr " ); fi
  if [ "$r_more_up" -eq 1 ]; then rup_s=$( [ "$UI_LANG" = "en" ] && echo " ^more " || echo " ^mehr " ); fi
  if [ "$l_more_dn" -eq 1 ]; then ldn_s=$( [ "$UI_LANG" = "en" ] && echo " v more " || echo " v mehr " ); fi
  if [ "$r_more_dn" -eq 1 ]; then rdn_s=$( [ "$UI_LANG" = "en" ] && echo " PgDn v more " || echo " Bild v mehr " ); fi

  local l_fill_top=$(( lw - ${#l_box_title} - ${#lup_s} - 4 ))
  [ "$l_fill_top" -lt 1 ] && l_fill_top=1
  local r_fill_top=$(( rw - ${#r_box_title} - ${#rup_s} - 4 ))
  [ "$r_fill_top" -lt 1 ] && r_fill_top=1

  printf '%s+-- %s%s%s %s%s%s%s++-- %s%s%s %s%s%s%s+%s\n' \
    "$C" "$C$B" "$l_box_title" "$N$C" "$(printf '%*s' "$l_fill_top" '' | tr ' ' '-')" "$Y" "$lup_s" "$C" \
    "$C$B" "$r_box_title" "$N$C" "$(printf '%*s' "$r_fill_top" '' | tr ' ' '-')" "$Y" "$rup_s" "$C" "$N"

  local row lentry ltype lid lstr rstr rfmt raw_len pad_len item_color r_plain r_pad max_tlen
  for (( row=0; row<box_h; row++ )); do
    lentry="${llines[$(( lscroll + row ))]:-}"
    rstr="${rlines[$(( iscroll + row ))]:-}"

    if [ -z "$lentry" ]; then
      lpad=$(printf '%*s' "$lw" '')
    else
      ltype="${lentry%%|*}"
      lid="${lentry#*|}"
      if [ "$ltype" = "CAT" ]; then
        lstr=" -- $lid --"
        lstr="${lstr:0:$lw}"
        raw_len="${#lstr}"
        pad_len=$(( lw - raw_len ))
        [ "$pad_len" -lt 0 ] && pad_len=0
        lpad="${C}${B}${lstr}${N}$(printf '%*s' "$pad_len" '')"
      else
        item_color=""
        if [ "${M_ACTIVE[$lid]}" -eq 1 ] && [ "${M_SEL[$lid]}" -eq 1 ]; then
          mark="x"; item_color="$G"
          badge=$( [ "$UI_LANG" = "en" ] && echo "[active]" || echo "[aktiv]" )
        elif [ "${M_ACTIVE[$lid]}" -eq 1 ] && [ "${M_SEL[$lid]}" -eq 0 ]; then
          mark="-"; item_color="${R}${B}"
          badge=$( [ "$UI_LANG" = "en" ] && echo "[- rollback]" || echo "[- rueckbau]" )
        elif [ "${M_ACTIVE[$lid]}" -eq 0 ] && [ "${M_SEL[$lid]}" -eq 1 ]; then
          mark="+"; item_color="${Y}${B}"
          badge=$( [ "$UI_LANG" = "en" ] && echo "[+ new]" || echo "[+ neu]" )
        else
          mark=" "; item_color=""
          badge=$( [ "$UI_LANG" = "en" ] && echo "[inactive]" || echo "[inaktiv]" )
        fi

        printf -v num "%2d" "$lid"
        title="${M_TITLE[$lid]}"
        max_tlen=$(( lw - 13 - ${#badge} ))
        [ "$max_tlen" -lt 10 ] && max_tlen=10
        title="${title:0:$max_tlen}"

        if [ "$lid" -eq "$cur" ]; then
          lstr=" > [$mark] $num) $title"
        else
          lstr="   [$mark] $num) $title"
        fi
        raw_len=$(( ${#lstr} + ${#badge} + 1 ))
        pad_len=$(( lw - raw_len ))
        [ "$pad_len" -lt 1 ] && pad_len=1
        lstr="${lstr}$(printf '%*s' "$pad_len" '')${badge} "

        if [ "$lid" -eq "$cur" ]; then
          if [ -n "$item_color" ]; then
            lpad=$'\e[7m'"${item_color}${B}${lstr}"$'\e[0m'
          else
            lpad=$'\e[7m'"${B}${lstr}"$'\e[0m'
          fi
        elif [ -n "$item_color" ]; then
          lpad="${item_color}${lstr}${N}"
        else
          lpad="${lstr}"
        fi
      fi
    fi

    rstr="${rstr:0:$r_inner}"
    r_plain="$rstr"
    r_pad=$(( r_inner - ${#r_plain} ))
    [ "$r_pad" -lt 0 ] && r_pad=0

    case "$rstr" in
      MAßNAHME*|ACTION\ \#*)
        rfmt=" ${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
      AKTUELLER\ SYSTEM*|EINGRIFFSTIEFE*|WAS\ MACHT*|FOLGEN*|RÜCKABWICKLUNG*|CURRENT\ SYSTEM*|IMPACT\ LEVEL*|WHAT\ DOES*|CONSEQUENCES*|ROLLBACK\ *)
        rfmt=" ${B}${C}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
      *ZUR\ RUECKABWICKLUNG*|*ZUR\ RÜCKABWICKLUNG*|*HOCH*|*WARNUNG*|*MARKED\ FOR\ ROLLBACK*|*HIGH*)
        rfmt=" ${R}${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
      *ZUR\ AKTIVIERUNG*|*MARKED\ FOR\ ACTIVATION*)
        rfmt=" ${Y}${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
      *AKTIV\ /\ KONFIGURIERT*|*KEINE\ ÄNDERUNG*|*ACTIVE\ /\ CONFIGURED*|*NO\ CHANGE*)
        rfmt=" ${G}${B}${rstr}${N}$(printf '%*s' "$r_pad" '') " ;;
      *)
        rfmt=" ${rstr}$(printf '%*s' "$r_pad" '') " ;;
    esac

    printf '%s|%s%s%s||%s%s%s|%s\n' "$C" "$N" "$lpad" "$C" "$N" "$rfmt" "$C" "$N"
  done

  local l_fill_bot=$(( lw - ${#ldn_s} ))
  [ "$l_fill_bot" -lt 1 ] && l_fill_bot=1
  local r_fill_bot=$(( rw - ${#rdn_s} ))
  [ "$r_fill_bot" -lt 1 ] && r_fill_bot=1

  printf '%s+%s%s%s%s++%s%s%s%s+%s\n' \
    "$C" "$(printf '%*s' "$l_fill_bot" '' | tr ' ' '-')" "$Y" "$ldn_s" "$C" \
    "$(printf '%*s' "$r_fill_bot" '' | tr ' ' '-')" "$Y" "$rdn_s" "$C" "$N"

  printf '%s%s%s\n' "$C" "${status_line:0:$cols}" "$N"
  printf '%s%s%s' "$B" "${key_line:0:$cols}" "$N"
}

interactive_menu() {
  [ "$NO_MENU" -eq 0 ] || return 0
  # Stellt die originalen Terminal-Deskriptoren (FD 3/4) vor der Prüfung wieder her (beendet die tee-Pipe sauber)
  exec 1>&3 2>&4
  sleep 0.1

  if [ "$HAS_TTY" -ne 1 ]; then info "Kein interaktives Terminal - TUI-Menü übersprungen."; return 0; fi
  if [ "$(id -u)" -ne 0 ]; then
    recommend
    warn "Maßnahmen benötigen root (bitte mit sudo starten) - TUI-Menü übersprungen."
    return 0
  fi

  ensure_state_dir
  init_menu_data

  # Schritt 2/4: Befund-Screen im Box-TUI anzeigen (Abbrechen mit q beendet sauber)
  if ! tui_befund_screen; then
    return 0
  fi

  # Schritt 3/4: Vorab-Abfrage Telegram-Bot & Baustein-Benachrichtigungen (fail2ban, rkhunter, ClamAV, auditd)
  tui_telegram_screen "wizard"

  local cur=1 iscroll=0 key k2 k3 num_buf="" i has_changes
  while true; do
    tui_render "$cur" "$iscroll"
    IFS= tty_read -rsn1 key || break

    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) cur=$(( cur > 1 ? cur - 1 : 18 )); iscroll=0 ;;
          B) cur=$(( cur < 18 ? cur + 1 : 1 )); iscroll=0 ;;
          5) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll > 5 ? iscroll - 5 : 0 )) ;;
          6) IFS= tty_read -rsn1 -t 0.02 _ || true; iscroll=$(( iscroll + 5 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) cur=$(( cur > 1 ? cur - 1 : 18 )); iscroll=0 ;;
      j|J) cur=$(( cur < 18 ? cur + 1 : 1 )); iscroll=0 ;;
      c|C)
        cur=17
        iscroll=0
        tui_clamav_screen
        ;;
      t|T)
        cur=18
        iscroll=0
        tui_telegram_screen "sub"
        ;;
      b|B)
        if ! tui_befund_screen; then
          clear
          break
        fi
        ;;
      l|L)
        if [ "$UI_LANG" = "de" ]; then UI_LANG="en"; else UI_LANG="de"; fi
        load_menu_texts
        ;;
      " ")
        if [ "$cur" -eq 13 ]; then
          tui_auditd_screen
        elif [ "$cur" -eq 17 ]; then
          tui_clamav_screen
        elif [ "$cur" -eq 18 ]; then
          tui_telegram_screen "sub"
        elif [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_REVERSIBLE[$cur]}" -eq 0 ]; then
          M_ACTIVE[$cur]=0; M_SEL[$cur]=1
        else
          M_SEL[$cur]=$(( 1 - M_SEL[$cur] ))
        fi
        ;;
      s|S)
        sync_selection_with_active
        ;;
      p|P)
        clear
        act_rotate
        sync_selection_with_active
        printf '\n%s[Enter] drücken, um zur TUI zurückzukehren ...%s' "$B" "$N"
        tty_read -r _ || true
        ;;
      r|R)
        clear
        act_print_full_report
        sync_selection_with_active
        printf '\n%s[Enter] drücken, um zur TUI zurückzukehren ...%s' "$B" "$N"
        tty_read -r _ || true
        ;;
      q|Q)
        clear
        break
        ;;
      [0-9])
        printf '\nNummer (1-18), Enter bestätigt: %s' "$key"
        tty_read -r -t 2 num_buf || num_buf=""
        num_buf="${key}${num_buf}"
        if [[ "$num_buf" =~ ^[0-9]+$ ]] && [ "$num_buf" -ge 1 ] && [ "$num_buf" -le 18 ]; then
          cur="$num_buf"
          iscroll=0
          if [ "$cur" -eq 13 ]; then
            tui_auditd_screen
          elif [ "$cur" -eq 17 ]; then
            tui_clamav_screen
          elif [ "$cur" -eq 18 ]; then
            tui_telegram_screen "sub"
          else
            M_SEL[$cur]=$(( 1 - M_SEL[$cur] ))
          fi
        fi
        ;;
      ""|x|X)
        clear
        has_changes=0
        for i in {1..18}; do
          if [ "${M_SEL[$i]}" -ne "${M_ACTIVE[$i]}" ]; then has_changes=1; fi
        done

        if [ "$has_changes" -eq 0 ]; then
          if [ "$cur" -eq 13 ]; then
            tui_auditd_screen
            continue
          elif [ "$cur" -eq 17 ]; then
            tui_clamav_screen
            continue
          elif [ "$cur" -eq 18 ]; then
            tui_telegram_screen "sub"
            continue
          elif [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_REVERSIBLE[$cur]}" -eq 1 ]; then
            hdr "Maßnahme #$cur (${M_TITLE[$cur]}) ist bereits AKTIV [x]"
            if confirm "Möchtest du diese Maßnahme RÜCKABWICKELN (j) oder erneut ausführen (n)?"; then
              revert_action_by_id "$cur"
            else
              apply_action_by_id "$cur"
            fi
          else
            hdr "Führe Maßnahme #$cur aus: ${M_TITLE[$cur]}"
            apply_action_by_id "$cur"
          fi
        else
          hdr "Wende alle geänderten Checkboxen ([+] Aktivierung / [-] Rückabwicklung) an"
          # Falls Telegram (#18) neu aktiviert/aktualisiert wird, zuerst ausführen, damit /usr/local/sbin/it-reinbek-notify bereitsteht
          if [ "${M_ACTIVE[18]}" -eq 0 ] && [ "${M_SEL[18]}" -eq 1 ]; then
            printf '\n%s>>> [+] AKTIVIERE Maßnahme #18: %s <<<%s\n' "$B$Y" "${M_TITLE[18]}" "$N"
            apply_action_by_id 18
            M_ACTIVE[18]=1
          fi
          for i in {1..18}; do
            if [ "${M_ACTIVE[$i]}" -eq 0 ] && [ "${M_SEL[$i]}" -eq 1 ]; then
              printf '\n%s>>> [+] AKTIVIERE Maßnahme #%d: %s <<<%s\n' "$B$Y" "$i" "${M_TITLE[$i]}" "$N"
              apply_action_by_id "$i"
            elif [ "${M_ACTIVE[$i]}" -eq 1 ] && [ "${M_SEL[$i]}" -eq 0 ]; then
              printf '\n%s>>> [-] RÜCKABWICKLUNG Maßnahme #%d: %s <<<%s\n' "$B$R" "$i" "${M_TITLE[$i]}" "$N"
              revert_action_by_id "$i"
            fi
          done
        fi

        sync_selection_with_active
        printf '\n%sVorgang abgeschlossen. Aktueller Systemstatus wurde neu eingelesen. [Enter] für TUI ...%s ' "$B$G" "$N"
        tty_read -r _ || break
        ;;
    esac
  done

  [ -n "$BACKUP_DIR" ] && info "Config-Backup: $BACKUP_DIR (Anleitung: RESTORE.txt)"
  [ -n "$QUAR_DIR" ] && info "Quarantäne: $QUAR_DIR"
  [ -f "$LOGFILE" ] && info "Aktionsprotokoll: $LOGFILE"
}

recommend() {
  hdr "Empfehlung je nach Befund (gemäß BSI Version 1.1 & PHP-Notfall-Advisory)"
  local vuln=$(( ${#NEED_UPDATE[@]} + ${#DK_VULN[@]} ))
  if [ "$COMP" -gt 0 ]; then
    printf '%sVERDACHT AUF BEFALL.%s Empfohlene Reihenfolge: [1] Beweise sichern -> System vom Internet trennen (BSI) -> [3/4/6] Update -> [10] Dienste neu starten -> [12] Dateien in Quarantäne -> [11] Sessions leeren -> [15] Secrets rotieren & Bericht drucken.\n' "$R" "$N"
    printf 'Wichtig: Nicht zuerst patchen/neustarten, das vernichtet Spuren im Arbeitsspeicher.\n'
  elif [ "$vuln" -gt 0 ]; then
    printf '%sPHP ist verwundbar, kein Befall erkannt.%s BSI-Empfehlung: Unverzüglich Notfall-Update einspielen ([3] Update / [4]+[5] Branch-Upgrade / [6] Docker) oder vorübergehend vom Internet trennen. Falls beides sofort nicht möglich ist: ALLE BSI-Workarounds ([7] + [8] + [9]) anwenden -> [10] Dienste neu starten -> [11] Sessions -> [16] Verifikation.\n' "$Y" "$N"
  elif [ "$ATT" -gt 0 ]; then
    printf '%sPHP gepatcht, aber Hinweise auf Angriffsversuche/Segfaults.%s Empfohlen: [1] Beweise sichern, [13] auditd-Überwachung, [15] Secrets prüfen/rotieren & Bericht drucken (wegen PHPSESSID-Memory-Leak!).\n' "$Y" "$N"
  elif [ "$STALE" -gt 0 ]; then
    printf '%sGepatcht, aber Dienste laufen noch mit altem Code im Speicher.%s Empfohlen: [10] Dienste neu starten.\n' "$Y" "$N"
  else
    printf '%sKein unmittelbarer Handlungsbedarf erkannt.%s Optional: [13] dauerhafte Überwachung per auditd, [15] Revisionsbericht drucken.\n' "$G" "$N"
  fi
}

# --------------------------------------------------------------------- main

show_legal_disclaimer
ensure_state_dir

if [ -n "$REPORT" ]; then
  exec > >(tee "$REPORT" "$SCAN_CAPTURED") 2>&1
elif [ "$(id -u)" -eq 0 ]; then
  rm -f "$SCAN_CAPTURED" 2>/dev/null || true
  exec > >(tee "$SCAN_CAPTURED") 2>&1
fi

printf '%sPHP2Shell-Check v%s%s  (CVE-2026-109618 / CVE-2026-109619 | BSI BITS-H 2026-297981-1132 v1.1)  Host: %s  Zeit: %s\n' \
  "$B" "$VERSION" "$N" "$(hostname)" "$(date '+%F %T %Z')"
[ "$(id -u)" -eq 0 ] || warn "Nicht als root gestartet - Prüfungen sind eingeschränkt (Logs, Crontabs, /proc), Maßnahmen sind deaktiviert."

check_versions
suggest_install
check_runtime

if [ "$DO_SCAN" -eq 1 ]; then
  detect_webroots
  if [ "${#WEBROOTS[@]}" -eq 0 ]; then
    warn "Keine Webroots gefunden - mit --webroot DIR angeben. Dateiscan übersprungen."
  else
    scan_files
  fi
  scan_php_internals
  scan_persistence
  scan_logs
  scan_docker
fi

hdr "Zusammenfassung"
printf 'CRIT: %d   WARN: %d   (Kompromittierungs-Verdacht: %d, Angriffsversuche in Logs: %d)\n' "$CRIT" "$WARN" "$COMP" "$ATT"

cat <<'EOF'

Hinweis (BSI v1.1 & Security-Research):
Erfolgreiche PHP2Shell-Exploits führen nicht zwingend zu einem Worker-Crash oder Log-Eintrag.
Zudem kann CVE-2026-109618 Arbeitsspeicher über PHPSESSID-Cookies auslesen, ohne Dateien abzulegen.
"Nichts gefunden" ist daher KEIN Beweis für Unversehrtheit.
EOF

interactive_menu

if [ "$CRIT" -gt 0 ]; then exit 2; elif [ "$WARN" -gt 0 ]; then exit 1; else exit 0; fi
