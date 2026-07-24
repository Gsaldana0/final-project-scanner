# Final-project-scanner

## Overview
This project is a Bash-based network vuulnerability scanner that uses nmap to scan a target host or network range for open ports and running services, then generates a clear, timestamped text report summarizing the findings. The goal is to provide a lightweight, command-line tool for quickly accessing the exposed attack surface of a device or network on **networks you own or have explicit written or documented verbal permission to test**.

## Purpose / Learning
This project was built for a bash scripting course focused on network and device security, shell scripting fundamentals, and best programming practices (argument handling, error checking, modular functions, and clean output formatting).

## Features
* Scansa single host, hostname, or CIDR range using nmap
* Performs service/version detection (-sV) and default safe NSE scripts (-sC)
* Parses results to list ope ports and services
* Flags a few common high-risk open ports (FTP, telnet, RDP, SMB) with basic notes
* Saves both a raw nmap output file and formatted, readable report
*Timestamps every report so scan history is preserved

## Requirements
* Linux/Unix envoronment with Bash
* nmap installed
  * ### Bash
  * _sudo apt install nmap_


## Usage
* ### bash
* _./scanner.sh <target> [output_directory]

## Arguments
* _target_--IP address, hostname, or CIDR range to scan (required)
* _output_directory_--where to save reports (optional, defaults to _./reports_)

## Examples:
### bash
_./scanner.sh 192.168.1.1_

_./scanner.sh 192.168.1.0/24 ./reports_

Reports are saved as __scan_report_<timstamp>.txt__ in the output directory, along with the raw nmap output for reference.

## Current Status
Initial setup and basic port/service scanning functionality implemented along with automated report generation and simple risk flagging for common high-risk ports.

## Future Goals
* Expand vulnerability identification (e.g. integrate NSE vulnerability scripts or CVE lookups)
* Add HTML/PDF report export
* Add configurable scan profiles (quick scan vs. full scan)
* Add logging and scheduling support for recurring scans

## Legal / Ethical Notice
Only scan systems and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal and/or violate terms of service of your network provider.
