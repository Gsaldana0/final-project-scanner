#!/bin/bash
#
# netscan.sh
#
# A simple network reconnaissance tool that generates a text report
# for a given target host.
#
# Milestone 3: The "Open Ports and Detected Services" section is no
# longer placeholder text. write_ports_section() now runs a live
# `nmap -sV` scan against the target, pipes the output through
# `grep "open"` to filter down to just the open-port lines, and
# writes the result straight into the report. The vulnerabilities
# and recommendations sections are left as placeholders on purpose --
# those get wired up in a future milestone.
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
# write_ports_section
#   Runs a live nmap scan (-sV for service/version detection) against
#   the target, filters the output down to the lines that show open
#   ports, and appends the section to the report file.
# ----------------------------------------------------------------------------
write_ports_section() {
    local target="$1"
    local report_file="$2"

    {
        echo "--- Open Ports and Detected Services ---"
        nmap -sV "$target" | grep "open"
        echo ""
    } >> "$report_file"
}

# ----------------------------------------------------------------------------
# write_vulnerabilities_section
#   PLACEHOLDER for this milestone. Vulnerability analysis based on
#   the detected service versions will be added in a later milestone.
# ----------------------------------------------------------------------------
write_vulnerabilities_section() {
    local report_file="$1"

    {
        echo "--- Potential Vulnerabilities Identified ---"
        echo "[Placeholder] Vulnerability analysis has not been implemented yet."
        echo "[Placeholder] This section will be completed in a future milestone."
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
#   Entry point. Validates input, creates a fresh report file, then
#   calls each write_* function in turn to build the report section
#   by section.
# ----------------------------------------------------------------------------
main() {
    validate_args "$@"

    local target="$1"
    local report_file="netscan_report_$(date +%Y%m%d_%H%M%S).txt"

    # Start with a clean, empty report file
    : > "$report_file"

    write_header "$target" "$report_file"
    write_ports_section "$target" "$report_file"
    write_vulnerabilities_section "$report_file"
    write_recommendations_section "$report_file"

    echo "Scan complete. Report saved to: $report_file"
}

main "$@"
