#!/usr/bin/env bash
#
# php2shell-check.sh  (v12 - Stateful TUI, Reversible Config & Emergency-Patch Edition)
# Prüft PHP auf CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) & CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) ("PHP2Shell"),
# berücksichtigt den BSI-IT-Sicherheitshinweis BITS-H Nr. 2026-297981-1132 (Version 1.1 vom 21.10.2026),
# die Notfall-Updates (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 + EOL-Backports für 7.4 / 8.0 / 8.1)
# sowie tagesaktuelle Analysen/IOCs (Armis, Abstract Security, Datadog, Sansec, Corelight, IT-Administrator).
#
# Neu in v12:
# - Robuster Terminal-/FD-Mechanismus (exec 3>&1 4>&2): Öffnet die Split-Screen-TUI zuverlässig
#   auch nach der Hintergrund-Aufzeichnung (tee) unter sudo, SSH und Tabby.
# - Erweiterte Erkennung der Notfall-Backports für PHP 7.4, 8.0 und 8.1 (Changelog + Build-Datum >= 21.10.2026).
# - Vorgeschalteter rechtlicher Haftungsausschluss (Disclaimer zur Nutzung in Eigenverantwortung).
# - Zustandsbasierte Split-Screen-TUI (Links Checkboxen 1-16 ohne Zähllücken, rechts Live-Erklärung):
#     * [x] (Grün)  = Maßnahme/Konfiguration ist bereits auf dem System AKTIV / angewendet
#     * [ ] (Weiß)  = Maßnahme/Konfiguration ist NICHT aktiv
#     * [+] (Gelb)  = Neu ausgewählt -> wird beim Ausführen [Enter] AKTIVIERT / installiert
#     * [-] (Rot)   = War aktiv [x] und wurde abgewählt -> wird beim Ausführen [Enter] RÜCKABGEWICKELT!
# - Druckfunktion für Checkliste [p] SOWIE kompletten Revisions-Bericht (Scan-Report + Checkliste) [r].
#
# Aufruf (als root):
#   sudo ./php2shell-check.sh [--since YYYY-MM-DD] [--webroot DIR]...
#                             [--report DATEI] [--versions-only] [--no-menu] [--accept-disclaimer]
#
# Exit-Codes: 0 = sauber, 1 = Warnungen, 2 = verwundbar/Verdachtsfälle
#
set -uo pipefail

SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SINCE="2026-10-17"
REPORT=""
DO_SCAN=1
NO_MENU=0
ACCEPT_DISCLAIMER=0

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
  cat <<'EOF'
Verwendung: php2shell-check.sh [Optionen]
  --since YYYY-MM-DD     Zeitpunkt, ab dem Änderungen verdächtig sind (Standard: 2026-10-17)
  --webroot DIR          Webroot explizit angeben (mehrfach möglich; sonst Autodetect)
  --report DATEI         Ausgabe zusätzlich in Datei schreiben (ohne Farben)
  --versions-only        Nur Versionsprüfung, kein Kompromittierungs-Scan
  --no-menu              Kein interaktives Maßnahmenmenü (z. B. für Cron/CI)
  --accept-disclaimer    Haftungsausschluss vorab akzeptieren (für automatisierte Läufe)
  -h, --help             Diese Hilfe
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --since)             SINCE="${2:-}"; shift 2 ;;
    --webroot)           WEBROOTS+=("${2:-}"); shift 2 ;;
    --report)            REPORT="${2:-}"; shift 2 ;;
    --versions-only)     DO_SCAN=0; shift ;;
    --no-menu)           NO_MENU=1; shift ;;
    --accept-disclaimer) ACCEPT_DISCLAIMER=1; shift ;;
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

show_legal_disclaimer() {
  [ "$ACCEPT_DISCLAIMER" -eq 1 ] && return 0
  [ "$NO_MENU" -eq 1 ] && return 0
  [ "$HAS_TTY" -eq 1 ] || return 0

  clear
  cat <<EOF
${B}${R}================================================================================
       WICHTIGER RECHTLICHER HINWEIS & HAFTUNGSAUSSCHLUSS (DISCLAIMER)
================================================================================${N}

Dieses Skript (${B}php2shell-check.sh v12${N}) dient der Sicherheitsanalyse sowie der
unterstützten Eindämmung und Behebung der Schwachstellen ${B}CVE-2026-109618${N} und
${B}CVE-2026-109619 ("PHP2Shell")${N}.

${B}1. Bereitstellung ohne Gewähr ("AS IS") & Eigenverantwortung${N}
Die Bereitstellung und Nutzung dieses Skripts erfolgt unentgeltlich und auf
alleinige Gefahr sowie in voller Eigenverantwortung des Anwenders/Betreibers.
Es wird keinerlei Gewährleistung für Richtigkeit, Vollständigkeit, Aktualität,
Fehlerfreiheit oder die Eignung für einen bestimmten Zweck übernommen.

${B}2. Keine Garantie auf Erkennung oder vollständigen Schutz${N}
Ein Scan ohne Treffer ("0 CRIT / 0 WARN") ist KEIN Beweis dafür, dass das
System nicht kompromittiert wurde. Ebenso ersetzen temporäre Workarounds laut
BSI (BITS-H Nr. 2026-297981-1132) keinen Patch.

${B}3. Systemeingriffe, Rückabwicklung & Betriebsrisiken${N}
Der initiale Scan arbeitet rein lesend. Wenn Sie im anschließenden TUI-Menü
jedoch aktiv Maßnahmen aktivieren oder deaktivieren (z. B. Paket-Updates,
PHP-Branch-Wechsel, Docker-Compose-Stopp/Recreate, Konfigurationsänderungen,
Quarantäne oder deren Rückabwicklung), greift das Skript tief in das laufende
System ein. Trotz integrierter Backups und Rollback-Mechanismen kann es zu
Dienstunterbrechungen, Inkompatibilitäten oder Datenverlust kommen.

${B}4. Haftungsbeschränkung (gemäß deutschem Recht, §§ 521, 599, 276 BGB)${N}
Jegliche Haftung der Autoren, Bereitsteller oder Mitwirkenden für direkte oder
indirekte Schäden, Folgeschäden, Datenverlust, Systemausfälle oder entgangenen
Gewinn ist ausgeschlossen, soweit diese nicht auf Vorsatz oder grober
Fahrlässigkeit beruhen oder eine zwingende gesetzliche Haftung wegen der
Verletzung des Lebens, des Körpers oder der Gesundheit besteht.

${B}5. Autorisierung${N}
Sie bestätigen, dass Sie berechtigt sind, dieses System zu prüfen und ggf.
administrativ zu verändern, und dass aktuelle externe Backups vorliegen.
${R}================================================================================${N}
EOF
  local ans
  printf '\nBitte tippen Sie exakt %sICH AKZEPTIERE%s (oder %sJA%s), um den Haftungsausschluss\nanzuerkennen und das Skript in Eigenverantwortung zu starten (alles andere bricht ab):\n> ' "$B$G" "$N" "$B$G" "$N"
  tty_read -r ans || exit 1
  case "$ans" in
    "ICH AKZEPTIERE"|"ich akzeptiere"|"JA"|"ja")
      alog "Haftungsausschluss vom Benutzer ($(id -un)) akzeptiert."
      printf '%sHaftungsausschluss akzeptiert. Starte Systemprüfung ...%s\n\n' "$G" "$N"
      ;;
    *)
      printf '\n%sHaftungsausschluss nicht akzeptiert. Skript wird ohne Änderungen beendet.%s\n' "$Y" "$N"
      exit 1
      ;;
  esac
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
    up=$("$php" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
    ml=$("$php" -r 'echo ini_get("memory_limit");' 2>/dev/null)
    pms=$("$php" -r 'echo ini_get("post_max_size");' 2>/dev/null)
    umf=$("$php" -r 'echo ini_get("upload_max_filesize");' 2>/dev/null)
    feb=$("$php" -r 'echo ini_get("fatal_error_backtraces");' 2>/dev/null)
    expose=$("$php" -r 'echo ini_get("expose_php");' 2>/dev/null)
    info "CLI-Konfig: upload_progress=${up:-0}, memory_limit=${ml:-?}, post_max_size=${pms:-?}, upload_max_filesize=${umf:-?}, fatal_error_backtraces=${feb:-n/a}, expose_php=${expose:-0} (FPM/Apache können abweichen!)"
    if [ "${expose:-0}" = "1" ]; then
      warn "expose_php=1 aktiv: Server verrät seine PHP-Version im HTTP-Header 'X-Powered-By' an Angreifer/Scanner (Corelight-Hinweis)."
    fi
  fi

  local b start_warn
  for b in $(find_php_binaries); do
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
     - expose_php = 0                       (verhindert Versions-Leak über X-Powered-By Header)" \
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

# --- Maßnahme 13: auditd-Überwachung & Rückabwicklung ---

act_auditd() {
  if ! command -v auditctl >/dev/null 2>&1; then
    warn "auditd ist nicht installiert (Debian/Ubuntu: apt install auditd). Danach erneut wählen."; return 0
  fi
  local u uid users=()
  mapfile -t users < <(web_users)
  [ "${#users[@]}" -gt 0 ] || { warn "Keine Webserver-User gefunden."; return 0; }
  explain "Überwachung: Prozessstarts durch Webserver-User mit auditd protokollieren" "niedrig-mittel" \
    "Legt $AUDIT_RULE an (execve b64 & b32 durch: ${users[*]}) und lädt die Regeln" \
    "Erkennt Shell-Starts durch PHP - das wichtigste verhaltensbasierte Signal. Rein beobachtend, blockiert nichts." \
    "Checkbox [13] in der TUI wieder abwählen (löscht $AUDIT_RULE und lädt Regeln neu)"
  confirm "Audit-Regel anlegen?" || return 0
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
}

undo_auditd() {
  [ -f "$AUDIT_RULE" ] || { info "Keine Audit-Regel ($AUDIT_RULE) vorhanden."; return 0; }
  explain "Rückabwicklung #13: auditd-Überwachungsregel ($AUDIT_RULE) entfernen" "niedrig" \
    "Löscht $AUDIT_RULE und lädt die Audit-Regeln neu (augenrules --load / auditctl -D -k php2shell_exec)" \
    "Prozessstarts durch Webserver-User werden nicht mehr gesondert unter 'php2shell_exec' protokolliert." \
    "Checkbox [13] wieder aktivieren"
  confirm "Audit-Regel ($AUDIT_RULE) jetzt entfernen?" || return 0
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
  for f in ${files[@]+"${files[@]}"}; do rm -f -- "$f" && info "entfernt: $f"; done
  for pf in ${pools[@]+"${pools[@]}"}; do sed -i "/^; $MARK_MEM\$/,+1d" "$pf" && info "bereinigt: $pf"; done
  auditctl -D -k php2shell_exec >/dev/null 2>&1 || true
  command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1
  alog "Alle temporären Workarounds zurückgenommen"
  if confirm "PHP-/Webserver-Dienste jetzt direkt neu starten (Maßnahme 10)?"; then act_restart; fi
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
  for i in {1..16}; do M_ACTIVE[$i]=0; done

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
}

sync_selection_with_active() {
  local i
  detect_live_states
  for i in {1..16}; do
    M_SEL[$i]="${M_ACTIVE[$i]}"
  done
}

init_menu_data() {
  local i
  for i in {1..16}; do M_REVERSIBLE[$i]=1; done
  M_REVERSIBLE[10]=0
  M_REVERSIBLE[14]=0
  M_REVERSIBLE[16]=0

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

  M_CAT[13]="IV. Bereinigung & Druck"; M_TITLE[13]="auditd-Überwachung aktivieren"
  M_RISK[13]="NIEDRIG (rein protokollierend, blockiert nichts)"
  M_WHAT[13]="Richtet eine auditd-Regel (/etc/audit/rules.d/99-php2shell.rules) ein, die alle Programm-/Shell-Starts (execve 64-Bit & 32-Bit) durch Webserver-Benutzer (www-data, apache, nginx) mit dem Schlüssel 'php2shell_exec' protokolliert."
  M_IMPACT[13]="Erzeugt Audit-Log-Einträge bei Prozessstarts durch PHP (Auswertung mit: ausearch -k php2shell_exec)."
  M_UNDO[13]="Haken [x] -> [ ] abwählen und [Enter] drücken: Löscht /etc/audit/rules.d/99-php2shell.rules und entlädt die Regel im Kernel."

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
  esac
}

tui_render() {
  local cur="$1" cols lw rw=46 i mark state_txt num title lpad rline wline
  cols=$(tput cols 2>/dev/null || echo 118)
  [ "$cols" -lt 96 ] && cols=96
  lw=50
  rw=$(( cols - lw - 5 ))
  [ "$rw" -lt 40 ] && rw=40

  if [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_SEL[$cur]}" -eq 1 ]; then
    state_txt="AKTIV / KONFIGURIERT [x] (Abwählen mit Leertaste markiert zur RÜCKABWICKLUNG [-])"
  elif [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_SEL[$cur]}" -eq 0 ]; then
    state_txt="ZUR RÜCKABWICKLUNG VORGEMERKT [-] (wird bei [Enter] rückgängig gemacht!)"
  elif [ "${M_ACTIVE[$cur]}" -eq 0 ] && [ "${M_SEL[$cur]}" -eq 1 ]; then
    state_txt="ZUR AKTIVIERUNG VORGEMERKT [+] (wird bei [Enter] ausgeführt/konfiguriert!)"
  else
    state_txt="NICHT KONFIGURIERT [ ] (Anwählen mit Leertaste markiert zur Aktivierung [+])"
  fi

  local -a rlines=()
  local raw_right
  raw_right=$(
    printf 'MAßNAHME #%d: %s\n\n' "$cur" "${M_TITLE[$cur]}"
    printf 'AKTUELLER SYSTEM- & AUSWAHLSTATUS:\n%s\n\n' "$state_txt"
    printf 'EINGRIFFSTIEFE / RISIKO:\n%s\n\n' "${M_RISK[$cur]}"
    printf 'WAS MACHT DIESER SCHRITT?\n%s\n\n' "${M_WHAT[$cur]}"
    printf 'FOLGEN & HINWEISE (BSI):\n%s\n\n' "${M_IMPACT[$cur]}"
    printf 'RÜCKABWICKLUNG (BEI ABWÄHLEN DER CHECKBOX):\n%s\n' "${M_UNDO[$cur]}"
  )
  while IFS= read -r rline; do
    if [ -z "$rline" ]; then
      rlines+=("")
    else
      while IFS= read -r wline; do
        rlines+=("$wline")
      done < <(printf '%s\n' "$rline" | fold -s -w "$rw")
    fi
  done <<< "$raw_right"

  local -a llines=()
  local last_cat=""
  for i in {1..16}; do
    if [ "${M_CAT[$i]}" != "$last_cat" ]; then
      last_cat="${M_CAT[$i]}"
      llines+=("CAT|$last_cat")
    fi
    llines+=("ITEM|$i")
  done

  printf '\e[H\e[2J'
  printf '%sPHP2Shell-Check v12 TUI%s (BSI v1.1) | Befund: %sCRIT:%d%s %sWARN:%d%s %sCOMP:%d%s | Legende: %s[x]=Aktiv%s %s[+]=Neu%s %s[-]=Rückabwickeln%s\n' \
    "$B" "$N" "$R" "$CRIT" "$N" "$Y" "$WARN" "$N" "$R" "$COMP" "$N" "$G" "$N" "$Y" "$N" "$R" "$N"
  printf '%s\n' "$(printf '%*s' "$cols" '' | tr ' ' '=')"
  printf '%s%-*s%s | %s%s%s\n' "$B" "$lw" " STATUS & MAßNAHMEN (1-16 ohne Lücken)" "$N" "$B" "ERKLÄRUNG, STATUS & RÜCKABWICKLUNG" "$N"
  printf '%s+%s\n' "$(printf '%*s' "$lw" '' | tr ' ' '-')" "$(printf '%*s' "$((rw+2))" '' | tr ' ' '-')"

  local max_rows="${#llines[@]}"
  [ "${#rlines[@]}" -gt "$max_rows" ] && max_rows="${#rlines[@]}"

  local row lentry ltype lid lstr rstr rfmt raw_len pad_len item_color
  for (( row=0; row<max_rows; row++ )); do
    lentry="${llines[$row]:-}"
    rstr="${rlines[$row]:-}"

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
        lpad="${C}${B}${lstr}${N}$(printf '%*s' "$pad_len" '')"
      else
        item_color=""
        if [ "${M_ACTIVE[$lid]}" -eq 1 ] && [ "${M_SEL[$lid]}" -eq 1 ]; then
          mark="x"; item_color="$G"
        elif [ "${M_ACTIVE[$lid]}" -eq 1 ] && [ "${M_SEL[$lid]}" -eq 0 ]; then
          mark="-"; item_color="${R}${B}"
        elif [ "${M_ACTIVE[$lid]}" -eq 0 ] && [ "${M_SEL[$lid]}" -eq 1 ]; then
          mark="+"; item_color="${Y}${B}"
        else
          mark=" "; item_color=""
        fi

        printf -v num "%2d" "$lid"
        title="${M_TITLE[$lid]}"
        if [ "$lid" -eq "$cur" ]; then
          lstr=" > [$mark] $num) $title"
        else
          lstr="   [$mark] $num) $title"
        fi
        lstr="${lstr:0:$lw}"
        raw_len="${#lstr}"
        pad_len=$(( lw - raw_len ))
        if [ "$lid" -eq "$cur" ]; then
          lpad=$'\e[7m'"${B}${lstr}"$(printf '%*s' "$pad_len" '')$'\e[0m'
        elif [ -n "$item_color" ]; then
          lpad="${item_color}${lstr}${N}$(printf '%*s' "$pad_len" '')"
        else
          lpad="${lstr}$(printf '%*s' "$pad_len" '')"
        fi
      fi
    fi

    case "$rstr" in
      MAßNAHME*|AKTUELLER\ SYSTEM*|EINGRIFFSTIEFE*|WAS\ MACHT*|FOLGEN*|RÜCKABWICKLUNG*)
        rfmt="${B}${C}${rstr}${N}" ;;
      *ZUR\ RÜCKABWICKLUNG*|*HOCH*|*WARNUNG*)
        rfmt="${R}${B}${rstr}${N}" ;;
      *ZUR\ AKTIVIERUNG*)
        rfmt="${Y}${B}${rstr}${N}" ;;
      *AKTIV\ /\ KONFIGURIERT*|*KEINE\ ÄNDERUNG*)
        rfmt="${G}${B}${rstr}${N}" ;;
      *)
        rfmt="$rstr" ;;
    esac

    printf '%s | %s\n' "$lpad" "$rfmt"
  done

  printf '%s+%s\n' "$(printf '%*s' "$lw" '' | tr ' ' '-')" "$(printf '%*s' "$((rw+2))" '' | tr ' ' '-')"
  printf '%sSteuerung:%s [Pfeil Hoch/Runter] od. [j/k] = Navigieren | [Leertaste] = Checkbox umschalten (Aktivieren [+] / Rückabwickeln [-])\n' "$B" "$N"
  printf '           [Enter] od. [x] = Änderungen anwenden | [p] = Checkliste drucken | [r] = Scan-Report + Checkliste drucken | [q] = Ende\n'
}

interactive_menu() {
  [ "$NO_MENU" -eq 0 ] || return 0
  # Stellt die originalen Terminal-Deskriptoren (FD 3/4) vor der Prüfung wieder her (beendet die tee-Pipe sauber)
  exec 1>&3 2>&4
  sleep 0.1

  if [ "$HAS_TTY" -ne 1 ]; then info "Kein interaktives Terminal - TUI-Menü übersprungen."; return 0; fi
  if [ "$(id -u)" -ne 0 ]; then warn "Maßnahmen benötigen root (bitte mit sudo starten) - TUI-Menü übersprungen."; return 0; fi

  ensure_state_dir
  recommend
  printf '\n%sDrücke [Enter], um das zustandsbasierte Split-Screen-TUI-Menü zu öffnen (oder q zum Beenden) ...%s ' "$B" "$N"
  local start_ans
  tty_read -r start_ans || return 0
  case "$start_ans" in q|Q|0) return 0 ;; esac

  init_menu_data

  local cur=1 key k2 k3 num_buf="" i has_changes
  while true; do
    tui_render "$cur"
    IFS= tty_read -rsn1 key || break

    if [[ "$key" == $'\e' ]]; then
      IFS= tty_read -rsn1 -t 0.05 k2 || k2=""
      if [[ "$k2" == "[" ]]; then
        IFS= tty_read -rsn1 -t 0.05 k3 || k3=""
        case "$k3" in
          A) cur=$(( cur > 1 ? cur - 1 : 16 )) ;;
          B) cur=$(( cur < 16 ? cur + 1 : 1 )) ;;
        esac
      fi
      continue
    fi

    case "$key" in
      k|K) cur=$(( cur > 1 ? cur - 1 : 16 )) ;;
      j|J) cur=$(( cur < 16 ? cur + 1 : 1 )) ;;
      " ")
        if [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_REVERSIBLE[$cur]}" -eq 0 ]; then
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
        printf 'Nummer (1-16), Enter bestätigt: %s' "$key"
        tty_read -r -t 2 num_buf || num_buf=""
        num_buf="${key}${num_buf}"
        if [[ "$num_buf" =~ ^[0-9]+$ ]] && [ "$num_buf" -ge 1 ] && [ "$num_buf" -le 16 ]; then
          cur="$num_buf"
          M_SEL[$cur]=$(( 1 - M_SEL[$cur] ))
        fi
        ;;
      ""|x|X)
        clear
        has_changes=0
        for i in {1..16}; do
          if [ "${M_SEL[$i]}" -ne "${M_ACTIVE[$i]}" ]; then has_changes=1; fi
        done

        if [ "$has_changes" -eq 0 ]; then
          if [ "${M_ACTIVE[$cur]}" -eq 1 ] && [ "${M_REVERSIBLE[$cur]}" -eq 1 ]; then
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
          for i in {1..16}; do
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

printf '%sPHP2Shell-Check v12%s  (CVE-2026-109618 / CVE-2026-109619 | BSI BITS-H 2026-297981-1132 v1.1)  Host: %s  Zeit: %s\n' \
  "$B" "$N" "$(hostname)" "$(date '+%F %T %Z')"
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
