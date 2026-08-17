#!/bin/bash
#
# netscan.sh
#
# A simple network reconnaissance tool that generates a text report
# for a given target host.
#
# Milestone 5: The scanner now does real vulnerability analysis instead
# of just reporting open ports. perform_scan() runs a single enhanced
# nmap scan (-sV --script vuln) so the target only gets hit once, and
# the raw results are shared by both write_ports_section() and the new
# write_vulnerabilities_section(). Vulnerability analysis uses two
# strategies: (A) grepping the NSE output for its own "VULNERABLE"
# findings, and (B) a manual case-statement check against a short list
# of known-bad service/version strings. The recommendations section is
# still a placeholder for a future milestone.
#
# Usage: ./netscan.sh <target>
#   <target>   IP address or hostname to scan (must be authorized)
#
# Example:
#   ./netscan.sh scanme.nmap.org
#   ./netscan.sh 127.0.0.1

# ----------------------------------------------------------------------------
# validate_args
#   Confirms exactly one, non-empty target argument was supplied.
#   Exits with a usage message otherwise.
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
#   whole "vuln" NSE script category against the target so we get both
#   port/service info and vulnerability findings out of one scan.
#   Echoes the raw scan output so the caller can capture it, e.g.:
#       SCAN_RESULTS=$(perform_scan "$target")
# ----------------------------------------------------------------------------
perform_scan() {
    local target="$1"

    nmap -sV --script vuln "$target"
}

# ----------------------------------------------------------------------------
# write_ports_section
#   Filters the already-captured scan results down to the lines that
#   show open ports and appends the section to the report file.
# ----------------------------------------------------------------------------
write_ports_section() {
    local scan_results="$1"
    local report_file="$2"

    {
        echo "--- Open Ports and Detected Services ---"
        echo "$scan_results" | grep "open"
        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# write_vulnerabilities_section
#   Builds the "Potential Vulnerabilities Identified" section using two
#   strategies against the already-captured scan results:
#
#     Strategy A: grep for the high-confidence "VULNERABLE" findings
#                 that nmap's own vuln NSE scripts report directly.
#
#     Strategy B: a manual case-statement check that walks the scan
#                 results line by line and flags a short list of
#                 known-insecure service/version strings, for issues
#                 the NSE scripts don't call out explicitly.
# ----------------------------------------------------------------------------
write_vulnerabilities_section() {
    local scan_results="$1"
    local report_file="$2"

    {
        echo "--- Potential Vulnerabilities Identified ---"

        echo ""
        echo "[Strategy A: NSE Script Findings]"
        local nse_hits
        nse_hits=$(echo "$scan_results" | grep "VULNERABLE")
        if [[ -n "$nse_hits" ]]; then
            echo "$nse_hits"
        else
            echo "No high-confidence 'VULNERABLE' findings reported by NSE scripts."
        fi

        echo ""
        echo "[Strategy B: Known Vulnerable Version Checks]"
        local version_hits
        version_hits=$(echo "$scan_results" | while read -r line; do
            case "$line" in
                *"vsftpd 2.3.4"*)
                    echo "[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 is running, which contains a known critical backdoor."
                    ;;
                *"Apache httpd 2.4.49"*)
                    echo "[!!] VULNERABILITY DETECTED: Apache 2.4.49 is running, which is vulnerable to path traversal (CVE-2021-41773)."
                    ;;
                *"OpenSSH 4."*|*"OpenSSH 5.1"*|*"OpenSSH 5.2"*|*"OpenSSH 5.3"*)
                    echo "[!!] VULNERABILITY DETECTED: Outdated OpenSSH version is running, which is affected by several known CVEs from that release series."
                    ;;
                *"ProFTPD 1.3.3"*)
                    echo "[!!] VULNERABILITY DETECTED: ProFTPD 1.3.3 is running, which contains a known backdoor (CVE-2010-4221)."
                    ;;
            esac
        done)
        if [[ -n "$version_hits" ]]; then
            echo "$version_hits"
        else
            echo "No known-vulnerable service versions matched from the local check list."
        fi

        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# write_recommendations_section
#   PLACEHOLDER for this milestone. Recommendations derived from the
#   vulnerability analysis will be added in a later milestone.
# ----------------------------------------------------------------------------
write_recommendations_section() {
    local report_file="$1"

    {
        echo "--- Recommendations ---"
        echo "[Placeholder] Recommendations have not been implemented yet."
        echo "[Placeholder] This section will be completed in a future milestone."
        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# main
#   Entry point. Validates input, runs one enhanced nmap scan, creates a
#   fresh report file, then calls each write_* function in turn to build
#   the report section by section from the shared scan results.
# ----------------------------------------------------------------------------
main() {
    validate_args "$@"

    local target="$1"
    local report_file="netscan_report_$(date +%Y%m%d_%H%M%S).txt"

    echo "Scanning $target (this can take a while with --script vuln)..."
    local scan_results
    scan_results=$(perform_scan "$target")

    # Start with a clean, empty report file
    : > "$report_file"

    write_header "$target" "$report_file"
    write_ports_section "$scan_results" "$report_file"
    write_vulnerabilities_section "$scan_results" "$report_file"
    write_recommendations_section "$report_file"

    echo "Scan complete. Report saved to: $report_file"
}

main "$@"
