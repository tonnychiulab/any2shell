#!/usr/bin/env bash
# ==============================================================================
# HTTP2Shell / Node2Shell / Python2Shell / Broccoli2Shell (CVE-2026-111497)
# Non-Destructive Exposure & Vulnerability Audit Script
#
# Reference:
#   https://strobes.co/blog/http2shell-brotli-rce-cve-2026-111497/
#   Upstream Fix: google/brotli commit 0ed4268 (GHSA-9v8h-qqgm-4m35)
#
# Features:
#   1. Pre-flight Environment Check: Verifies both core POSIX/Linux utilities
#      (even standard built-ins/distro defaults) and target stack tools before
#      formally executing the vulnerability checks.
#   2. Strictly Non-Destructive (Read-Only): Zero network exploit probes, zero
#      package modifications, zero container creations, and zero disk writes
#      until the user explicitly confirms saving the report.
#   3. Comprehensive Coverage per Strobes Advisory:
#      - Node.js runtime & bundled process.versions.brotli check
#      - Express 5 / body-parser 2.x & direct zlib Brotli decode path scan
#      - Bun runtime version check
#      - Python Brotli / brotlicffi package, transitive dependency (pipdeptree),
#        HTTP client (urllib3, requests, aiohttp, httpx, scrapy), & lockfile scan
#      - System libbrotli packages (dpkg / rpm / apk) & curl libbrotli linkage
#      - Running processes with libbrotlidec mapped in memory (/proc/*/maps)
#      - Local Docker container/image non-destructive inspection (optional)
#   4. Interactive Confirmation Before Saving Report: Holds the full audit
#      report in memory, previews it to the terminal, and asks the user for
#      confirmation before writing any file to disk.
# ==============================================================================

set -u
set -o pipefail

# ------------------------------------------------------------------------------
# Global Configuration & State
# ------------------------------------------------------------------------------
SCRIPT_VERSION="1.0.0"
CVE_ID="CVE-2026-111497"
ADVISORY_URL="https://strobes.co/blog/http2shell-brotli-rce-cve-2026-111497/"
SCAN_DIR="${1:-$(pwd)}"
DEFAULT_REPORT_FILE="http2shell_cve_2026_111497_report_$(date +%Y%m%d_%H%M%S 2>/dev/null || echo 'audit').txt"

# Counters for summary
COUNT_VULNERABLE=0
COUNT_WARNING=0
COUNT_SAFE=0
COUNT_INFO=0

# In-memory report buffer (no temporary files written to disk)
REPORT_BUFFER=""

# Associative array for command availability
declare -A CMD_AVAILABLE

# ------------------------------------------------------------------------------
# Terminal Color Helpers (degrades gracefully if not a TTY)
# ------------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_RED='\033[31m'
    C_GREEN='\033[32m'
    C_YELLOW='\033[33m'
    C_BLUE='\033[34m'
    C_CYAN='\033[36m'
else
    C_RESET=''
    C_BOLD=''
    C_RED=''
    C_GREEN=''
    C_YELLOW=''
    C_BLUE=''
    C_CYAN=''
fi

# ------------------------------------------------------------------------------
# Logging & In-Memory Report Accumulation Functions
# ------------------------------------------------------------------------------
append_report() {
    local line="$1"
    REPORT_BUFFER+="${line}"$'\n'
}

log_both() {
    local term_msg="$1"
    local plain_msg="$2"
    printf "%b\n" "$term_msg"
    append_report "$plain_msg"
}

log_section() {
    local title="$1"
    local divider="=============================================================================="
    printf "\n%b%s%b\n%b[%s]%b\n%b%s%b\n" \
        "$C_BLUE" "$divider" "$C_RESET" \
        "$C_BOLD$C_CYAN" "$title" "$C_RESET" \
        "$C_BLUE" "$divider" "$C_RESET"
    append_report ""
    append_report "$divider"
    append_report "[$title]"
    append_report "$divider"
}

log_finding() {
    local level="$1"   # VULNERABLE | WARNING | SAFE | INFO | SKIP
    local component="$2"
    local detail="$3"

    case "$level" in
        VULNERABLE)
            COUNT_VULNERABLE=$((COUNT_VULNERABLE + 1))
            log_both "  ${C_RED}${C_BOLD}[VULNERABLE]${C_RESET} ${C_BOLD}${component}${C_RESET}: ${detail}" \
                     "  [VULNERABLE] ${component}: ${detail}"
            ;;
        WARNING)
            COUNT_WARNING=$((COUNT_WARNING + 1))
            log_both "  ${C_YELLOW}${C_BOLD}[WARNING]${C_RESET}    ${C_BOLD}${component}${C_RESET}: ${detail}" \
                     "  [WARNING]    ${component}: ${detail}"
            ;;
        SAFE)
            COUNT_SAFE=$((COUNT_SAFE + 1))
            log_both "  ${C_GREEN}${C_BOLD}[SAFE]${C_RESET}       ${C_BOLD}${component}${C_RESET}: ${detail}" \
                     "  [SAFE]       ${component}: ${detail}"
            ;;
        SKIP)
            log_both "  ${C_CYAN}[SKIPPED]${C_RESET}    ${component}: ${detail}" \
                     "  [SKIPPED]    ${component}: ${detail}"
            ;;
        *)
            COUNT_INFO=$((COUNT_INFO + 1))
            log_both "  ${C_BLUE}[INFO]${C_RESET}       ${component}: ${detail}" \
                     "  [INFO]       ${component}: ${detail}"
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Semantic Version Comparison Helper (Pure Bash + Required Pre-checked Tools)
# Returns:
#   0 if ver1 == ver2
#   1 if ver1 >  ver2
#   2 if ver1 <  ver2
# ------------------------------------------------------------------------------
version_compare() {
    local v1="${1#v}"
    local v2="${2#v}"

    # Strip build/pre-release suffixes (e.g., -alpine, +build, -rc1)
    v1="${v1%%[-+]*}"
    v2="${v2%%[-+]*}"

    if [ "$v1" = "$v2" ]; then
        return 0
    fi

    local IFS=.
    # shellcheck disable=SC2206
    local i ver1=($v1) ver2=($v2)

    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done

    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z "${ver2[i]:-}" ]]; then
            ver2[i]=0
        fi
        # Ensure numeric comparison (strip non-digits if any)
        local n1="${ver1[i]//[^0-9]/}"
        local n2="${ver2[i]//[^0-9]/}"
        n1="${n1:-0}"
        n2="${n2:-0}"
        if ((10#$n1 > 10#$n2)); then
            return 1
        fi
        if ((10#$n1 < 10#$n2)); then
            return 2
        fi
    done
    return 0
}

# Check if version is in vulnerable Brotli range [1.0.3, 1.2.0] except patched 1.0.10 and 1.1.1
# Returns 0 if VULNERABLE, 1 if SAFE
is_brotli_c_version_vulnerable() {
    local ver="$1"
    # Fixed versions: 1.0.10, 1.1.1, >= 1.2.1, or < 1.0.3
    if [ "$ver" = "1.0.10" ] || [ "$ver" = "1.1.1" ]; then
        return 1
    fi

    version_compare "$ver" "1.0.3"
    local cmp_low=$?
    if [ "$cmp_low" -eq 2 ]; then
        # Below 1.0.3 -> Not affected by CVE-2026-111497
        return 1
    fi

    version_compare "$ver" "1.2.0"
    local cmp_high=$?
    if [ "$cmp_high" -eq 0 ] || [ "$cmp_high" -eq 2 ]; then
        # Between 1.0.3 and 1.2.0 (and not 1.0.10 / 1.1.1) -> Vulnerable
        return 0
    fi

    return 1
}

# ------------------------------------------------------------------------------
# Phase 0: Pre-Flight Environment & Command Verification
# Checks BOTH standard Linux base commands AND optional runtime/package tools
# before allowing the script to formally execute.
# ------------------------------------------------------------------------------
preflight_check_environment() {
    log_section "0. PRE-FLIGHT ENVIRONMENT & COMMAND VERIFICATION (環境與指令預檢)"

    # 1. Verify Bash runtime version (requires Bash >= 4.0 for associative arrays)
    if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
        printf "%b[FATAL]%b Bash 4.0 or newer is required to run this script.\n" "$C_RED" "$C_RESET" >&2
        exit 1
    fi
    log_finding "INFO" "Bash Shell" "Detected GNU Bash ${BASH_VERSION}"

    # 2. Mandatory core Linux/POSIX commands (even standard distro defaults must be checked)
    local required_core_cmds=(
        "grep"
        "awk"
        "sed"
        "find"
        "sort"
        "head"
        "tr"
        "cut"
        "wc"
        "date"
        "uname"
        "id"
        "cat"
        "ps"
        "dirname"
        "basename"
        "chmod"
    )

    local missing_core=()
    for cmd in "${required_core_cmds[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            CMD_AVAILABLE["$cmd"]=1
            local cmd_path
            cmd_path="$(command -v "$cmd" 2>/dev/null)"
            log_finding "INFO" "Core Command [$cmd]" "Available (${cmd_path})"
        else
            CMD_AVAILABLE["$cmd"]=0
            missing_core+=("$cmd")
            log_finding "VULNERABLE" "Core Command [$cmd]" "MISSING (Required for script execution)"
        fi
    done

    # 3. Optional / Target-Specific inspection commands
    local optional_inspect_cmds=(
        "node"
        "npm"
        "bun"
        "python3"
        "python"
        "pip3"
        "pip"
        "pipdeptree"
        "dpkg"
        "rpm"
        "apk"
        "curl"
        "ldd"
        "docker"
        "sudo"
        "readlink"
    )

    for cmd in "${optional_inspect_cmds[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            CMD_AVAILABLE["$cmd"]=1
            local cmd_path
            cmd_path="$(command -v "$cmd" 2>/dev/null)"
            log_finding "INFO" "Audit Tool [$cmd]" "Available (${cmd_path})"
        else
            CMD_AVAILABLE["$cmd"]=0
            log_finding "SKIP" "Audit Tool [$cmd]" "Not installed (related checks will be skipped safely)"
        fi
    done

    # 4. Evaluate whether the environment can formally execute the script
    if [ "${#missing_core[@]}" -gt 0 ]; then
        printf "\n%b%b[PRE-FLIGHT FAILED]%b Missing essential Linux base commands: %s\n" \
            "$C_RED" "$C_BOLD" "$C_RESET" "${missing_core[*]}" >&2
        printf "This environment cannot formally execute the audit script. Aborting without changes.\n" >&2
        exit 1
    fi

    # Check target scan directory readability
    if [ ! -d "$SCAN_DIR" ] || [ ! -r "$SCAN_DIR" ]; then
        printf "\n%b%b[PRE-FLIGHT FAILED]%b Target scan directory '%s' does not exist or is not readable.\n" \
            "$C_RED" "$C_BOLD" "$C_RESET" "$SCAN_DIR" >&2
        exit 1
    fi

    # Record host metadata now that uname/date/id are verified
    local host_info user_info scan_time
    host_info="$(uname -srmo 2>/dev/null || uname -a 2>/dev/null || echo 'Unknown')"
    user_info="$(id -un 2>/dev/null || echo 'unknown') (UID: $(id -u 2>/dev/null || echo '?'))"
    scan_time="$(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date)"

    log_finding "INFO" "Environment Pre-Flight Status" "PASSED - All ${#required_core_cmds[@]} mandatory base utilities verified."
    log_finding "INFO" "System Architecture" "${host_info}"
    log_finding "INFO" "Execution User" "${user_info} (Read-only non-destructive mode)"
    log_finding "INFO" "Scan Timestamp" "${scan_time}"
    log_finding "INFO" "Target Workspace Directory" "${SCAN_DIR}"
}

# ------------------------------------------------------------------------------
# Phase 1: Node.js & Bun Runtime Checks
# Reference:
#   - Node.js 26.x: vulnerable < 26.12.1 (Fixed in 26.12.1)
#   - Node.js 24.x (LTS): vulnerable < 24.22.1 (Fixed in 24.22.1)
#   - Node.js 22.x (LTS): vulnerable < 22.23.4 (Fixed in 22.23.4)
#   - Node.js 25.x, 23.x, 20.x and older: EOL, all versions affected (no fix)
#   - Bundled Brotli: process.versions.brotli vulnerable if 1.0.3 .. 1.2.0
#   - Bun: vulnerable <= 1.4.3 (Fixed in 1.4.4)
# ------------------------------------------------------------------------------
check_nodejs_and_bun() {
    log_section "1. NODE.JS & BUN RUNTIME AUDIT (Node.js 與 Bun 執行環境檢查)"

    # --- 1A. Node.js Runtime & Bundled Brotli ---
    if [ "${CMD_AVAILABLE[node]:-0}" -eq 1 ]; then
        local node_ver_raw node_ver major_ver
        node_ver_raw="$(node --version 2>/dev/null || true)"
        node_ver="${node_ver_raw#v}"
        major_ver="${node_ver%%.*}"

        if [ -n "$node_ver" ]; then
            case "$major_ver" in
                26)
                    version_compare "$node_ver" "26.12.1"
                    if [ $? -eq 2 ]; then
                        log_finding "VULNERABLE" "Node.js Runtime (${node_ver_raw})" \
                            "Node.js 26.x below 26.12.1 is vulnerable to CVE-2026-111497. Upgrade to >= 26.12.1."
                    else
                        log_finding "SAFE" "Node.js Runtime (${node_ver_raw})" \
                            "Patched Node.js 26.x release (>= 26.12.1)."
                    fi
                    ;;
                24)
                    version_compare "$node_ver" "24.22.1"
                    if [ $? -eq 2 ]; then
                        log_finding "VULNERABLE" "Node.js Runtime (${node_ver_raw})" \
                            "Node.js 24.x below 24.22.1 is vulnerable to CVE-2026-111497. Upgrade to >= 24.22.1."
                    else
                        log_finding "SAFE" "Node.js Runtime (${node_ver_raw})" \
                            "Patched Node.js 24.x LTS release (>= 24.22.1)."
                    fi
                    ;;
                22)
                    version_compare "$node_ver" "22.23.4"
                    if [ $? -eq 2 ]; then
                        log_finding "VULNERABLE" "Node.js Runtime (${node_ver_raw})" \
                            "Node.js 22.x below 22.23.4 is vulnerable to CVE-2026-111497. Upgrade to >= 22.23.4."
                    else
                        log_finding "SAFE" "Node.js Runtime (${node_ver_raw})" \
                            "Patched Node.js 22.x LTS release (>= 22.23.4)."
                    fi
                    ;;
                25|23|21|20|19|18|16|14|12)
                    log_finding "VULNERABLE" "Node.js Runtime (${node_ver_raw})" \
                        "End-of-Life (EOL) Node.js line (${major_ver}.x) receives NO fix for CVE-2026-111497. Migrate to 22.23.4+, 24.22.1+, or 26.12.1+."
                    ;;
                *)
                    log_finding "INFO" "Node.js Runtime (${node_ver_raw})" \
                        "Unrecognized major line (${major_ver}.x); verify bundled Brotli version below."
                    ;;
            esac

            # Check bundled Brotli version via node -p "process.versions.brotli"
            local node_brotli_ver
            node_brotli_ver="$(node -p "process.versions.brotli" 2>/dev/null || true)"
            if [ -n "$node_brotli_ver" ] && [ "$node_brotli_ver" != "undefined" ]; then
                if is_brotli_c_version_vulnerable "$node_brotli_ver"; then
                    log_finding "VULNERABLE" "Node.js Bundled Brotli (${node_brotli_ver})" \
                        "process.versions.brotli is ${node_brotli_ver} (affected range: 1.0.3 through 1.2.0)."
                else
                    log_finding "SAFE" "Node.js Bundled Brotli (${node_brotli_ver})" \
                        "process.versions.brotli is ${node_brotli_ver} (outside vulnerable range or patched)."
                fi
            fi
        fi
    else
        log_finding "SKIP" "Node.js Runtime" "node binary not found in PATH."
    fi

    # --- 1B. Bun Runtime ---
    if [ "${CMD_AVAILABLE[bun]:-0}" -eq 1 ]; then
        local bun_ver_raw bun_ver
        bun_ver_raw="$(bun --version 2>/dev/null || true)"
        bun_ver="${bun_ver_raw#v}"
        if [ -n "$bun_ver" ]; then
            version_compare "$bun_ver" "1.4.4"
            if [ $? -eq 2 ]; then
                log_finding "VULNERABLE" "Bun Runtime (${bun_ver_raw})" \
                    "Bun <= 1.4.3 is vulnerable to HTTP2Shell (CVE-2026-111497). Upgrade to Bun >= 1.4.4."
            else
                log_finding "SAFE" "Bun Runtime (${bun_ver_raw})" \
                    "Bun ${bun_ver_raw} is patched (>= 1.4.4)."
            fi
        fi
    else
        log_finding "SKIP" "Bun Runtime" "bun binary not found in PATH."
    fi

    # --- 1C. Node.js Project Dependencies & Code Paths (Express 5 / body-parser 2.x / zlib) ---
    if [ -f "${SCAN_DIR}/package.json" ]; then
        log_finding "INFO" "Node.js Project Detected" "Found ${SCAN_DIR}/package.json"
        if [ "${CMD_AVAILABLE[npm]:-0}" -eq 1 ]; then
            local npm_ls_out
            npm_ls_out="$(cd "$SCAN_DIR" && npm ls express body-parser --depth=2 2>/dev/null || true)"
            if [ -n "$npm_ls_out" ]; then
                if printf "%s" "$npm_ls_out" | grep -Eq "express@5\.(0|1|2|3)\.|body-parser@2\.(0|1|2|3)\."; then
                    log_finding "WARNING" "Express 5 / body-parser 2.x Exposure" \
                        "Detected Express 5.0-5.3 or body-parser 2.0-2.3 (inflates Content-Encoding: br by default)."
                else
                    log_finding "INFO" "npm ls express body-parser" \
                        "No Express 5.0-5.3 or body-parser 2.0-2.3 detected in top-level tree."
                fi
            fi
        fi
    fi

    # Non-destructive source code pattern check in SCAN_DIR (bounded depth to stay fast & safe)
    local js_matches
    js_matches="$(find "$SCAN_DIR" -maxdepth 4 \
        -type d \( -name node_modules -o -name .git -o -name .venv -o -name venv -o -name dist -o -name build \) -prune \
        -o -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
        -exec grep -HnE "express\.json|bodyParser|createBrotliDecompress|brotliDecompress|fetch\(" {} + 2>/dev/null | head -n 15 || true)"

    if [ -n "$js_matches" ]; then
        local match_count
        match_count="$(printf "%s\n" "$js_matches" | wc -l | tr -d ' ')"
        log_finding "WARNING" "Node.js Code Path Scan (${SCAN_DIR})" \
            "Found ${match_count}+ lines referencing express.json/bodyParser/brotliDecompress/fetch() (verify runtime patch level)."
    else
        log_finding "INFO" "Node.js Code Path Scan (${SCAN_DIR})" \
            "No direct express.json, bodyParser, or brotliDecompress calls found in project source files (depth <= 4)."
    fi
}

# ------------------------------------------------------------------------------
# Phase 2: Python Packages, Transitive Dependencies & Lockfiles
# Reference:
#   - PyPI Brotli: vulnerable <= 1.2.0 (Fixed in 1.2.1)
#   - PyPI brotlicffi: vulnerable <= 1.2.0.x (Fixed in 1.2.1.0)
#   - Auto-decoding HTTP clients when Brotli is installed:
#     urllib3, requests, aiohttp, httpx, scrapy
# ------------------------------------------------------------------------------
check_python_environment() {
    log_section "2. PYTHON PACKAGES & LOCKFILE AUDIT (Python 套件與相依鎖定檔檢查)"

    local pip_cmd=""
    if [ "${CMD_AVAILABLE[pip3]:-0}" -eq 1 ]; then
        pip_cmd="pip3"
    elif [ "${CMD_AVAILABLE[pip]:-0}" -eq 1 ]; then
        pip_cmd="pip"
    fi

    if [ -n "$pip_cmd" ]; then
        # Check Brotli PyPI package
        local brotli_info brotli_ver
        brotli_info="$("$pip_cmd" show Brotli 2>/dev/null || true)"
        if [ -n "$brotli_info" ]; then
            brotli_ver="$(printf "%s\n" "$brotli_info" | awk -F': ' '/^Version:/ {print $2}' | tr -d '[:space:]')"
            if [ -n "$brotli_ver" ]; then
                version_compare "$brotli_ver" "1.2.1"
                if [ $? -eq 2 ]; then
                    log_finding "VULNERABLE" "PyPI Package [Brotli]" \
                        "Installed version ${brotli_ver} is <= 1.2.0 (vulnerable to CVE-2026-111497). Upgrade to Brotli >= 1.2.1."
                else
                    log_finding "SAFE" "PyPI Package [Brotli]" \
                        "Installed version ${brotli_ver} is patched (>= 1.2.1)."
                fi
            fi
        else
            log_finding "SAFE" "PyPI Package [Brotli]" "Not installed in current ${pip_cmd} environment."
        fi

        # Check brotlicffi PyPI package
        local brotlicffi_info brotlicffi_ver
        brotlicffi_info="$("$pip_cmd" show brotlicffi 2>/dev/null || true)"
        if [ -n "$brotlicffi_info" ]; then
            brotlicffi_ver="$(printf "%s\n" "$brotlicffi_info" | awk -F': ' '/^Version:/ {print $2}' | tr -d '[:space:]')"
            if [ -n "$brotlicffi_ver" ]; then
                version_compare "$brotlicffi_ver" "1.2.1.0"
                if [ $? -eq 2 ]; then
                    log_finding "VULNERABLE" "PyPI Package [brotlicffi]" \
                        "Installed version ${brotlicffi_ver} is < 1.2.1.0 (vulnerable to CVE-2026-111497). Upgrade to >= 1.2.1.0."
                else
                    log_finding "SAFE" "PyPI Package [brotlicffi]" \
                        "Installed version ${brotlicffi_ver} is patched (>= 1.2.1.0)."
                fi
            fi
        else
            log_finding "SAFE" "PyPI Package [brotlicffi]" "Not installed in current ${pip_cmd} environment."
        fi

        # Check HTTP clients that auto-decode Content-Encoding: br when Brotli/brotlicffi is present
        local http_clients=("urllib3" "requests" "aiohttp" "httpx" "scrapy")
        local installed_clients=()
        for pkg in "${http_clients[@]}"; do
            local pkg_ver
            pkg_ver="$("$pip_cmd" show "$pkg" 2>/dev/null | awk -F': ' '/^Version:/ {print $2}' | tr -d '[:space:]' || true)"
            if [ -n "$pkg_ver" ]; then
                installed_clients+=("${pkg} (${pkg_ver})")
            fi
        done

        if [ "${#installed_clients[@]}" -gt 0 ]; then
            if [ -n "${brotli_info}" ] || [ -n "${brotlicffi_info}" ]; then
                log_finding "WARNING" "Python HTTP Auto-Decoding Exposure" \
                    "Detected HTTP clients [${installed_clients[*]}] alongside Brotli/brotlicffi (outbound responses auto-decode br)."
            else
                log_finding "INFO" "Python HTTP Clients" \
                    "Detected [${installed_clients[*]}], but neither Brotli nor brotlicffi is installed in this environment."
            fi
        fi
    else
        log_finding "SKIP" "Python pip Audit" "Neither pip3 nor pip found in PATH."
    fi

    # Optional transitive dependency tree via pipdeptree
    if [ "${CMD_AVAILABLE[pipdeptree]:-0}" -eq 1 ]; then
        local tree_out
        tree_out="$(pipdeptree -r -p Brotli 2>/dev/null || true)"
        if [ -n "$tree_out" ]; then
            log_finding "INFO" "pipdeptree Transitive Dependents (Brotli)" \
                "$(printf "%s" "$tree_out" | tr '\n' ' ' | cut -c1-120)..."
        fi
    fi

    # Lockfile scan in SCAN_DIR (poetry.lock, uv.lock, requirements*.txt, Pipfile.lock)
    local lockfiles
    lockfiles="$(find "$SCAN_DIR" -maxdepth 4 \
        -type d \( -name node_modules -o -name .git -o -name .venv -o -name venv \) -prune \
        -o -type f \( -name "poetry.lock" -o -name "uv.lock" -o -name "requirements*.txt" -o -name "Pipfile.lock" \) \
        -print 2>/dev/null || true)"

    if [ -n "$lockfiles" ]; then
        while IFS= read -r lf; do
            [ -z "$lf" ] && continue
            local br_hits
            br_hits="$(grep -inE "brotli|brotlicffi" "$lf" 2>/dev/null | head -n 5 || true)"
            if [ -n "$br_hits" ]; then
                log_finding "WARNING" "Python Lockfile Reference (${lf})" \
                    "Contains Brotli/brotlicffi constraint: $(printf "%s" "$br_hits" | tr '\n' '; ')"
            else
                log_finding "SAFE" "Python Lockfile (${lf})" "No Brotli/brotlicffi references found."
            fi
        done <<< "$lockfiles"
    else
        log_finding "INFO" "Python Lockfiles (${SCAN_DIR})" \
            "No poetry.lock, uv.lock, requirements*.txt, or Pipfile.lock found (depth <= 4)."
    fi
}

# ------------------------------------------------------------------------------
# Phase 3: System Libraries, Package Managers & Running Processes (/proc/*/maps)
# Reference:
#   - dpkg -l | grep -i brotli (Debian/Ubuntu)
#   - rpm -qa | grep -i brotli (RHEL/Fedora)
#   - apk info -v | grep -i brotli (Alpine)
#   - curl --version (libcurl automatic br decoding when linked to libbrotli)
#   - grep -l brotlidec /proc/*/maps 2>/dev/null (Running processes with decoder)
# ------------------------------------------------------------------------------
check_system_libraries_and_processes() {
    log_section "3. SYSTEM LIBRARIES & RUNNING PROCESSES (系統函式庫與執行中程序檢查)"

    # --- 3A. Debian / Ubuntu (dpkg) ---
    if [ "${CMD_AVAILABLE[dpkg]:-0}" -eq 1 ]; then
        local dpkg_out
        dpkg_out="$(dpkg -l 2>/dev/null | grep -i brotli || true)"
        if [ -n "$dpkg_out" ]; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                local pkg_name pkg_ver base_ver
                pkg_name="$(printf "%s" "$line" | awk '{print $2}')"
                pkg_ver="$(printf "%s" "$line" | awk '{print $3}')"
                # Extract upstream X.Y.Z from Debian version string (e.g., 1.0.9-2build6 -> 1.0.9)
                base_ver="$(printf "%s" "$pkg_ver" | sed -E 's/^[0-9]+://; s/-.*$//')"
                if is_brotli_c_version_vulnerable "$base_ver"; then
                    log_finding "WARNING" "Debian/Ubuntu Package [${pkg_name}]" \
                        "Installed version ${pkg_ver} (upstream base ${base_ver} in 1.0.3..1.2.0). Verify distro security backport status."
                else
                    log_finding "SAFE" "Debian/Ubuntu Package [${pkg_name}]" \
                        "Installed version ${pkg_ver} (upstream base ${base_ver})."
                fi
            done <<< "$dpkg_out"
        else
            log_finding "INFO" "Debian/Ubuntu (dpkg)" "No brotli packages found via dpkg -l."
        fi
    fi

    # --- 3B. RHEL / CentOS / Fedora (rpm) ---
    if [ "${CMD_AVAILABLE[rpm]:-0}" -eq 1 ]; then
        local rpm_out
        rpm_out="$(rpm -qa 2>/dev/null | grep -i brotli || true)"
        if [ -n "$rpm_out" ]; then
            while IFS= read -r pkg; do
                [ -z "$pkg" ] && continue
                log_finding "WARNING" "RPM Package [${pkg}]" \
                    "Verify against distro errata for CVE-2026-111497 (upstream 1.0.3..1.2.0 affected)."
            done <<< "$rpm_out"
        else
            log_finding "INFO" "RHEL/Fedora (rpm)" "No brotli packages found via rpm -qa."
        fi
    fi

    # --- 3C. Alpine Linux (apk) ---
    if [ "${CMD_AVAILABLE[apk]:-0}" -eq 1 ]; then
        local apk_out
        apk_out="$(apk info -v 2>/dev/null | grep -i brotli || true)"
        if [ -n "$apk_out" ]; then
            while IFS= read -r pkg; do
                [ -z "$pkg" ] && continue
                log_finding "WARNING" "Alpine Package [${pkg}]" \
                    "Verify against Alpine security tracker for CVE-2026-111497."
            done <<< "$apk_out"
        else
            log_finding "INFO" "Alpine (apk)" "No brotli packages found via apk info -v."
        fi
    fi

    # --- 3D. curl / libcurl Brotli Linkage Check ---
    if [ "${CMD_AVAILABLE[curl]:-0}" -eq 1 ]; then
        local curl_ver_out
        curl_ver_out="$(curl --version 2>/dev/null || true)"
        if printf "%s" "$curl_ver_out" | grep -qi "brotli"; then
            local curl_line1
            curl_line1="$(printf "%s\n" "$curl_ver_out" | head -n 1)"
            log_finding "WARNING" "curl / libcurl Brotli Support" \
                "${curl_line1} links libbrotli (using 'curl --compressed' or CURLOPT_ACCEPT_ENCODING on untrusted URLs invokes libbrotlidec)."
        else
            log_finding "SAFE" "curl / libcurl" "curl does not report built-in brotli decoding support."
        fi
    fi

    # --- 3E. Running Processes with libbrotlidec Loaded in Memory ---
    if [ -d /proc ]; then
        local proc_maps
        proc_maps="$(grep -l "brotlidec" /proc/[0-9]*/maps 2>/dev/null || true)"
        if [ -n "$proc_maps" ]; then
            local pid_list=()
            while IFS= read -r map_path; do
                [ -z "$map_path" ] && continue
                local pid proc_comm
                pid="$(printf "%s" "$map_path" | cut -d'/' -f3)"
                proc_comm="$(cat "/proc/${pid}/comm" 2>/dev/null || echo 'unknown')"
                pid_list+=("PID ${pid} (${proc_comm})")
            done <<< "$proc_maps"
            log_finding "WARNING" "Running Processes with libbrotlidec Mapped" \
                "Found ${#pid_list[@]} readable process(es) with libbrotlidec in memory: ${pid_list[*]}. Note: Processes must be restarted after patching!"
        else
            log_finding "INFO" "Running Processes (/proc/*/maps)" \
                "No readable process memory maps currently list libbrotlidec (note: inspecting other users' processes requires root/sudo)."
        fi
    fi
}

# ------------------------------------------------------------------------------
# Phase 4: Non-Destructive Local Docker Inventory (Optional)
# Note: Strictly avoids 'docker run' (which could create/pull containers).
# Only inspects running containers if docker daemon is accessible.
# ------------------------------------------------------------------------------
check_docker_environment() {
    log_section "4. NON-DESTRUCTIVE CONTAINER INVENTORY (Docker 容器唯讀盤點)"

    if [ "${CMD_AVAILABLE[docker]:-0}" -eq 1 ]; then
        local running_containers
        running_containers="$(docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null || true)"
        if [ -n "$running_containers" ]; then
            local c_count
            c_count="$(printf "%s\n" "$running_containers" | wc -l | tr -d ' ')"
            log_finding "INFO" "Running Docker Containers (${c_count})" \
                "Detected running containers: $(printf "%s" "$running_containers" | tr '\n' '; '). Inspect bundled Node/Python inside images if internet-facing."
        else
            log_finding "INFO" "Docker Daemon" \
                "No running containers returned (or current user lacks permission to query Docker socket)."
        fi
    else
        log_finding "SKIP" "Docker Check" "docker CLI not installed."
    fi
}

# ------------------------------------------------------------------------------
# Phase 5: Summary & Remediation Guidance
# ------------------------------------------------------------------------------
generate_summary_and_remediation() {
    log_section "5. AUDIT SUMMARY & REMEDIATION GUIDANCE (檢查總結與修補建議)"

    log_both "  Total Vulnerable Findings : ${C_RED}${C_BOLD}${COUNT_VULNERABLE}${C_RESET}" \
             "  Total Vulnerable Findings : ${COUNT_VULNERABLE}"
    log_both "  Total Warning / Exposure  : ${C_YELLOW}${C_BOLD}${COUNT_WARNING}${C_RESET}" \
             "  Total Warning / Exposure  : ${COUNT_WARNING}"
    log_both "  Total Safe / Patched      : ${C_GREEN}${C_BOLD}${COUNT_SAFE}${C_RESET}" \
             "  Total Safe / Patched      : ${COUNT_SAFE}"
    log_both "  Total Informational       : ${C_BLUE}${COUNT_INFO}${C_RESET}" \
             "  Total Informational       : ${COUNT_INFO}"

    local guidance="
  Recommended Remediation Steps (per Strobes CVE-2026-111497 Advisory):
  1. Upgrade Runtimes & Libraries:
     - Google Brotli (libbrotlidec) : Upgrade to 1.0.10, 1.1.1, or >= 1.2.1
     - Node.js                      : Upgrade to >= 22.23.4 (22.x), >= 24.22.1 (24.x), or >= 26.12.1 (26.x)
     - Node.js EOL (<=20, 23, 25)   : Migrate to a supported LTS line (22, 24, or 26)
     - Bun                          : Upgrade to >= 1.4.4
     - Python PyPI Packages         : Upgrade Brotli >= 1.2.1 and brotlicffi >= 1.2.1.0
  2. Temporary Mitigations (if immediate patching is not possible):
     - Inbound HTTP  : Reject 'Content-Encoding: br' at reverse proxy/WAF or set express.json({ inflate: false })
     - Outbound HTTP : In Python, uninstall optional 'Brotli' / 'brotlicffi' packages so urllib3/requests/aiohttp/httpx
                       fall back to gzip/deflate (stripping Accept-Encoding header alone is NOT sufficient)
  3. Post-Patch Actions:
     - Restart all running processes that had libbrotlidec loaded in memory
     - Update lockfiles (poetry.lock, uv.lock, requirements.txt, package-lock.json) and rebuild container images"

    log_both "$guidance" "$guidance"
}

# ------------------------------------------------------------------------------
# Phase 6: Interactive User Confirmation Before Saving Report to Disk
# Ensures zero files are written unless explicitly approved by the user.
# ------------------------------------------------------------------------------
prompt_and_save_report() {
    printf "\n%b==============================================================================%b\n" "$C_CYAN" "$C_RESET"
    printf "%b[REPORT CONFIRMATION / 紀錄報告存檔確認]%b\n" "$C_BOLD$C_YELLOW" "$C_RESET"
    printf "All checks have completed in read-only mode. No files have been written to disk.\n"
    printf "Default report path: %b%s%b\n" "$C_BOLD" "$DEFAULT_REPORT_FILE" "$C_RESET"
    printf "%b==============================================================================%b\n" "$C_CYAN" "$C_RESET"

    # Check if stdin is interactive
    if [ ! -t 0 ]; then
        printf "%b[NOTICE]%b Non-interactive stdin detected. Skipping file creation to strictly honor confirmation policy.\n" \
            "$C_YELLOW" "$C_RESET"
        return 0
    fi

    local confirm_answer=""
    read -r -p "Do you want to save this audit report to disk? 是否要將檢查紀錄報告存檔？ [y/N]: " confirm_answer

    case "$confirm_answer" in
        [yY]|[yY][eE][sS])
            local custom_path=""
            read -r -p "Enter output file path (press Enter for default: ${DEFAULT_REPORT_FILE}): " custom_path
            local final_path="${custom_path:-$DEFAULT_REPORT_FILE}"

            local target_dir
            target_dir="$(dirname "$final_path" 2>/dev/null || echo '.')"
            if [ ! -d "$target_dir" ] || [ ! -w "$target_dir" ]; then
                printf "%b[ERROR]%b Directory '%s' does not exist or is not writable. Report was NOT saved.\n" \
                    "$C_RED" "$C_RESET" "$target_dir" >&2
                return 1
            fi

            if [ -e "$final_path" ]; then
                local overwrite_ans=""
                read -r -p "File '${final_path}' already exists. Overwrite? 檔案已存在，是否覆寫？ [y/N]: " overwrite_ans
                case "$overwrite_ans" in
                    [yY]|[yY][eE][sS]) ;;
                    *)
                        printf "%b[CANCELLED]%b Report was not saved.\n" "$C_YELLOW" "$C_RESET"
                        return 0
                        ;;
                esac
            fi

            printf "%s\n" "$REPORT_BUFFER" > "$final_path"
            chmod 0600 "$final_path" 2>/dev/null || true
            printf "%b[SUCCESS]%b Audit report saved to: %b%s%b\n" \
                "$C_GREEN" "$C_RESET" "$C_BOLD" "$final_path" "$C_RESET"
            ;;
        *)
            printf "%b[SKIPPED]%b User declined saving the report. Zero files were written to disk.\n" \
                "$C_YELLOW" "$C_RESET"
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Main Execution Entrypoint
# ------------------------------------------------------------------------------
main() {
    append_report "=============================================================================="
    append_report "HTTP2Shell / Node2Shell / Python2Shell (CVE-2026-111497) Security Audit Report"
    append_report "Reference : ${ADVISORY_URL}"
    append_report "Script Ver: ${SCRIPT_VERSION} (Strictly Non-Destructive / Read-Only)"
    append_report "=============================================================================="

    # Step 0: Pre-flight check of all core & optional commands
    preflight_check_environment

    # Ask user if they want to proceed after seeing pre-flight environment readiness (when interactive)
    if [ -t 0 ]; then
        printf "\n"
        local proceed_ans=""
        read -r -p "Pre-flight environment check passed. Proceed with formal non-destructive scan? 環境預檢通過，是否開始執行非破壞性檢測？ [Y/n]: " proceed_ans
        case "$proceed_ans" in
            [nN]|[nN][oO])
                printf "%b[ABORTED]%b Scan cancelled by user after pre-flight check. No files written.\n" "$C_YELLOW" "$C_RESET"
                exit 0
                ;;
            *) ;;
        esac
    fi

    # Steps 1-5: Non-destructive vulnerability & exposure checks
    check_nodejs_and_bun
    check_python_environment
    check_system_libraries_and_processes
    check_docker_environment
    generate_summary_and_remediation

    # Step 6: Prompt user before saving report to disk
    prompt_and_save_report
}

main "$@"