#!/usr/bin/env bash
#
# netscan.sh
#
# A network reconnaissance and vulnerability-analysis tool that generates
# a text report for a given target host.
#
# CURRENT STATUS (final milestone):
#   Runs a single enhanced nmap scan (-sV --script vuln) and shares the
#   raw output across every report section - no redundant scans. Analysis
#   combines three independent strategies:
#     Strategy A: nmap's own NSE "vuln" script findings (State: VULNERABLE)
#     Strategy B: local version-range checks against known CVEs, using
#                 real version comparison rather than substring matching
#     Strategy C: live lookups against the NIST NVD REST API for the
#                 product/version pairs nmap identified
#   Recommendations are generated dynamically from whatever Strategy A/B/C
#   actually found for this scan - they are not canned/placeholder text.
#
# Usage: ./netscan.sh <target>
#   <target>   IP address or hostname to scan (must be authorized)
#
# Example:
#   ./netscan.sh scanme.nmap.org
#   ./netscan.sh 127.0.0.1
#
# Requirements: nmap, curl, jq
#   Debian/Ubuntu: sudo apt update && sudo apt install nmap jq
#   Fedora/CentOS: sudo dnf install nmap jq
#   Windows (Git Bash): winget install jqlang.jq ; install nmap from nmap.org

set -uo pipefail

NVD_RESULTS_LIMIT=3
NVD_MAX_QUERIES=2   # Responsible API use: cap live NVD lookups per run.

# ----------------------------------------------------------------------------
# validate_args
#   Confirms exactly one, non-empty target argument was supplied.
# ----------------------------------------------------------------------------
validate_args() {
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 <target>" >&2
        echo "  <target>   IP address or hostname to scan" >&2
        exit 1
    fi

    if [[ -z "$1" ]]; then
        echo "Error: target cannot be empty." >&2
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# check_requirements
#   Confirms nmap, curl, and jq are all installed before doing anything
#   else. Exits with a clear message and install hints if any are missing,
#   rather than letting the scan run and silently produce a broken report.
# ----------------------------------------------------------------------------
check_requirements() {
    local missing=()
    for tool in nmap curl jq; do
        command -v "$tool" &> /dev/null || missing+=("$tool")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: missing required tool(s): ${missing[*]}" >&2
        echo "  Debian/Ubuntu: sudo apt update && sudo apt install ${missing[*]}" >&2
        echo "  Fedora/CentOS: sudo dnf install ${missing[*]}" >&2
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# version_lt A B
#   Returns success (0) if version string A is strictly less than version
#   string B, using `sort -V` (natural/version sort) rather than plain
#   string comparison. This correctly handles suffixes like "p1" in
#   OpenSSH versions and "rc3"/"b"/"c" in ProFTPD versions, which is what
#   lets us do real range checks (e.g. "is this before 1.3.3c?") instead
#   of the substring matching that caused false positives previously.
# ----------------------------------------------------------------------------
version_lt() {
    [[ "$1" == "$2" ]] && return 1
    local lowest
    lowest=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
    [[ "$lowest" == "$1" ]]
}

# ----------------------------------------------------------------------------
# extract_product_version <version_info_string>
#   Given the trailing "product + version" text from an nmap -sV line
#   (e.g. "Apache httpd 2.4.49" or "OpenSSH 7.6p1 Ubuntu 4ubuntu0.7"),
#   prints "product|version" on stdout. Product names can be multiple
#   words, so this finds the first token that starts with a digit and
#   treats everything before it as the product name.
# ----------------------------------------------------------------------------
extract_product_version() {
    local version_info="$1"
    echo "$version_info" | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9]/) {
                    prod = ""
                    for (j = 1; j < i; j++) {
                        prod = (j == 1) ? $j : prod " " $j
                    }
                    print prod "|" $i
                    exit
                }
            }
        }'
}

# ----------------------------------------------------------------------------
# write_header
#   Writes the report title and scan metadata (target + timestamp).
# ----------------------------------------------------------------------------
write_header() {
    local target="$1"
    local report_file="$2"

    {
        echo "============================================================"
        echo " Network Scan Report"
        echo "============================================================"
        echo "Target:      $target"
        echo "Scan Date:   $(date)"
        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# perform_scan
#   Runs the single, enhanced nmap scan used by the rest of the script.
#   -sV enables service/version detection and --script vuln runs nmap's
#   "vuln" NSE script category so we get both port/service info and
#   vulnerability findings from one scan. Prints raw nmap output to
#   stdout and returns nmap's own exit status to the caller (it does NOT
#   swallow the exit code the way a bare command substitution would).
# ----------------------------------------------------------------------------
perform_scan() {
    local target="$1"
    nmap -sV --script vuln "$target"
    return $?
}

# ----------------------------------------------------------------------------
# write_ports_section
#   Filters the captured scan results down to actual nmap port-table rows
#   and appends the section to the report file. The filter is anchored to
#   nmap's own "<port>/<proto> <state> ..." format so it can't match
#   unrelated lines that merely contain the word "open" - e.g. the
#   "cpe:/a:openbsd:openssh" service-info line, or NSE prose like
#   "...opening connections to the target web server..." from the
#   Slowloris script description, both of which the old `grep "open"`
#   filter incorrectly pulled into this section.
# ----------------------------------------------------------------------------
write_ports_section() {
    local scan_results="$1"
    local report_file="$2"

    {
        echo "--- Open Ports and Detected Services ---"
        local port_lines
        port_lines=$(echo "$scan_results" | grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open[[:space:]]")
        if [[ -n "$port_lines" ]]; then
            echo "$port_lines"
        else
            echo "No open ports detected."
        fi
        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# write_vulnerabilities_section
#   Builds the "Potential Vulnerabilities Identified" section using three
#   independent strategies against the already-captured scan results, and
#   records what each one finds into the FINDINGS array so
#   write_recommendations_section can react to real results instead of
#   printing static text.
#
#     Strategy A: nmap's own NSE "vuln" script findings. Anchored to the
#                 literal "State: VULNERABLE" marker the vulns.lua NSE
#                 library uses, with an explicit NOT-VULNERABLE exclusion
#                 as a second safety net, and a few lines of context on
#                 each side (4 before, 7 after) so the script name,
#                 title, and description are visible - not just the bare
#                 State line - without spilling into unrelated content.
#
#     Strategy B: local version-range checks against a short list of
#                 known-bad services, using version_lt() for a real
#                 version comparison instead of substring matching (which
#                 previously caused e.g. "ProFTPD 1.3.3d" - a version
#                 released AFTER the CVE-2010-4221 fix - to be incorrectly
#                 flagged just because it contained "ProFTPD 1.3.3").
#
#     Strategy C: live NVD REST API lookups (curl + jq) for the
#                 product/version pairs nmap identified, capped to
#                 NVD_MAX_QUERIES per run per NVD's rate-limit guidance.
# ----------------------------------------------------------------------------
FINDINGS=()   # populated by strategies A/B/C; consumed by recommendations

write_vulnerabilities_section() {
    local scan_results="$1"
    local report_file="$2"

    {
        echo "--- Potential Vulnerabilities Identified ---"

        # --- Strategy A: NSE Script Findings -------------------------------
        echo ""
        echo "[Strategy A: NSE Script Findings]"
        local nse_hits
        nse_hits=$(echo "$scan_results" | grep -B 4 -A 7 "State: VULNERABLE" | grep -v "NOT VULNERABLE")
        if [[ -n "$nse_hits" ]]; then
            echo "$nse_hits"
            FINDINGS+=("nse")
        else
            echo "No high-confidence 'VULNERABLE' findings reported by NSE scripts."
        fi

        # --- Strategy B: Known Vulnerable Version Checks --------------------
        echo ""
        echo "[Strategy B: Known Vulnerable Version Checks]"
        local version_hits=""
        local port_lines
        port_lines=$(echo "$scan_results" | grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open[[:space:]]")

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+open[[:space:]]+([^[:space:]]+)[[:space:]]+(.*)$ ]]; then
                local svc="${BASH_REMATCH[3]}"
                local version_info="${BASH_REMATCH[4]}"

                case "$version_info" in
                    *"vsftpd 2.3.4"*)
                        version_hits+="[!!] vsftpd 2.3.4 is running, which contains a known critical backdoor (installed via a compromised source tarball in 2011).\n"
                        FINDINGS+=("vsftpd_backdoor")
                        ;;
                    *"Apache httpd 2.4.49"*)
                        version_hits+="[!!] Apache httpd 2.4.49 is running, which is vulnerable to path traversal / RCE (CVE-2021-41773).\n"
                        FINDINGS+=("apache_path_traversal")
                        ;;
                esac

                if [[ "$svc" == "ssh" ]]; then
                    local parsed product version
                    parsed=$(extract_product_version "$version_info")
                    IFS='|' read -r product version <<< "$parsed"
                    if [[ "$product" == "OpenSSH" && -n "$version" ]]; then
                        if version_lt "$version" "4.4"; then
                            version_hits+="[!!] OpenSSH $version is running. Versions before 4.4 are affected by CVE-2006-5051, a signal-handler race condition allowing remote DoS and, if GSSAPI authentication is enabled, possible arbitrary code execution.\n"
                            FINDINGS+=("openssh_old")
                        fi
                        if version_lt "$version" "5.2"; then
                            version_hits+="[!!] OpenSSH $version is running. Versions before 5.2 are affected by CVE-2008-5161, which can allow a man-in-the-middle attacker to recover a small amount of plaintext from CBC-mode ciphertext.\n"
                            FINDINGS+=("openssh_old")
                        fi
                    fi
                fi

                if [[ "$svc" == "ftp" ]]; then
                    local parsed product version
                    parsed=$(extract_product_version "$version_info")
                    IFS='|' read -r product version <<< "$parsed"
                    if [[ "$product" == "ProFTPD" && -n "$version" ]] && version_lt "$version" "1.3.3c"; then
                        version_hits+="[!!] ProFTPD $version is running. Versions 1.3.2rc3 through 1.3.3b (i.e. before 1.3.3c) are affected by CVE-2010-4221, a stack-based buffer overflow in pr_netio_telnet_gets() allowing remote code execution via crafted TELNET IAC sequences. (This is a distinct RCE bug, not the unrelated 2011 ProFTPD backdoor incident.)\n"
                        FINDINGS+=("proftpd_overflow")
                    fi
                fi
            fi
        done <<< "$port_lines"

        if [[ -n "$version_hits" ]]; then
            echo -e "$version_hits"
        else
            echo "No known-vulnerable service versions matched from the local check list."
        fi

        # --- Strategy C: Live NVD Lookups -----------------------------------
        echo ""
        echo "[Strategy C: NVD API Lookups]"
        local queried=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$queried" -ge "$NVD_MAX_QUERIES" ]] && break
            if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+open[[:space:]]+([^[:space:]]+)[[:space:]]+(.*)$ ]]; then
                local svc="${BASH_REMATCH[3]}"
                local version_info="${BASH_REMATCH[4]}"
                case "$svc" in
                    ssh|http|https|ftp|smtp|mysql|ms-sql-s|rdp|telnet)
                        local parsed product version
                        parsed=$(extract_product_version "$version_info")
                        IFS='|' read -r product version <<< "$parsed"
                        if [[ -n "$product" && -n "$version" ]]; then
                            query_nvd "$product" "$version"
                            queried=$((queried + 1))
                            FINDINGS+=("nvd_queried")
                        fi
                        ;;
                esac
            fi
        done <<< "$port_lines"
        if [[ "$queried" -eq 0 ]]; then
            echo "No eligible services found for NVD lookup."
        fi

        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# query_nvd "product_name" "product_version"
#   Queries the NVD REST API for CVEs matching a product/version keyword
#   search and prints a formatted block (caller redirects to the report).
#   NOTE: NVD's keywordSearch does substring text matching, not exact
#   version matching - e.g. searching "2.4.6" can also surface CVEs for
#   "2.4.66" or "2.4.67". Treat these results as a starting point for
#   further investigation, not a definitive per-version CVE list.
# ----------------------------------------------------------------------------
query_nvd() {
    local product="$1"
    local version="$2"

    echo
    echo "Querying NVD for vulnerabilities in: $product $version..."

    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${NVD_RESULTS_LIMIT}"

    local vulnerabilities_json
    vulnerabilities_json=$(curl -s --max-time 15 "$nvd_api_url")
    local curl_status=$?

    if [[ $curl_status -ne 0 || -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD (curl exit code: $curl_status)."
        echo "  [!] The API might be down, unreachable, or you may be rate-limited."
        return
    fi

    if ! echo "$vulnerabilities_json" | jq -e . > /dev/null 2>&1; then
        echo "  [!] Error: NVD response was not valid JSON. Skipping."
        return
    fi

    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null 2>&1; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi

    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null 2>&1; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi

    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'

    sleep 6   # Be a good API citizen - avoid hammering the endpoint.
}

# ----------------------------------------------------------------------------
# write_recommendations_section
#   Builds mitigation recommendations from the FINDINGS array populated by
#   write_vulnerabilities_section, so this section reflects what was
#   actually found on THIS scan rather than printing static/canned text
#   regardless of results.
# ----------------------------------------------------------------------------
write_recommendations_section() {
    local report_file="$1"

    {
        echo "--- Recommendations ---"

        if [[ " ${FINDINGS[*]} " == *" vsftpd_backdoor "* ]]; then
            echo "* Replace vsftpd 2.3.4 immediately - this build contains a known backdoor and should be treated as fully compromised. Reinstall from an official, patched vsftpd release."
        fi
        if [[ " ${FINDINGS[*]} " == *" apache_path_traversal "* ]]; then
            echo "* Upgrade Apache HTTP Server past 2.4.51 to remediate CVE-2021-41773/CVE-2021-42013 (path traversal / RCE). If upgrading isn't immediately possible, ensure 'Require all denied' is set for cgi-bin and disable mod_cgi if unused."
        fi
        if [[ " ${FINDINGS[*]} " == *" openssh_old "* ]]; then
            echo "* Upgrade OpenSSH to the latest stable release. If GSSAPI authentication is enabled, disable it unless required (CVE-2006-5051). Disable CBC-mode ciphers in sshd_config in favor of CTR/GCM modes (CVE-2008-5161)."
        fi
        if [[ " ${FINDINGS[*]} " == *" proftpd_overflow "* ]]; then
            echo "* Upgrade ProFTPD to 1.3.3c or later to remediate CVE-2010-4221 (stack buffer overflow via TELNET IAC sequences). This is unrelated to the separate 2011 ProFTPD backdoor incident - confirm which issue applies to your build before communicating risk to stakeholders."
        fi
        if [[ " ${FINDINGS[*]} " == *" nse "* ]]; then
            echo "* Review each NSE 'State: VULNERABLE' finding above individually, cross-reference the listed CVE ID(s), and apply the vendor's patch or documented workaround for that specific service."
        fi
        if [[ " ${FINDINGS[*]} " == *" nvd_queried "* ]]; then
            echo "* Review the NVD API results above. Because NVD keywordSearch does substring matching, verify each returned CVE's affected-version range actually includes the installed version before prioritizing remediation."
        fi
        if [[ ${#FINDINGS[@]} -eq 0 ]]; then
            echo "No vulnerabilities were identified by any of the three analysis strategies in this scan."
            echo "General hardening still applies: keep all services patched, disable anything not in active use, and restrict access to management ports (SSH, RDP, database ports) via firewall rules or a VPN."
        fi

        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# main
#   Entry point. Validates input and tool availability, runs one enhanced
#   nmap scan, verifies the scan actually succeeded before writing
#   anything, then builds the report section by section from the shared
#   scan results.
# ----------------------------------------------------------------------------
main() {
    validate_args "$@"
    check_requirements

    local target="$1"
    local report_file="netscan_report_$(date +%Y%m%d_%H%M%S).txt"

    echo "Scanning $target (this can take a while with --script vuln)..."
    local scan_results
    scan_results=$(perform_scan "$target")
    local scan_exit=$?

    if [[ $scan_exit -ne 0 ]]; then
        echo "Error: nmap scan failed (exit code $scan_exit). No report was generated." >&2
        exit 1
    fi
    if [[ -z "$scan_results" ]]; then
        echo "Error: nmap returned no output. No report was generated." >&2
        exit 1
    fi

    : > "$report_file"

    write_header "$target" "$report_file"
    write_ports_section "$scan_results" "$report_file"
    write_vulnerabilities_section "$scan_results" "$report_file"
    write_recommendations_section "$report_file"

    echo "Scan complete. Report saved to: $report_file"
}

main "$@"
