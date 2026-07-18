# FLOCK_CVE_SCANNER

**Scan and exploit with permission**

## Overview

FLOCK_CVE_SCANNER is a comprehensive security testing tool for identifying and validating CVE-2025 vulnerabilities. It features multi-threaded scanning, Shodan integration, and optional exploitation capabilities for authorized security assessments.

## Features

* CVE-2025-59403: Unauthenticated admin API / ADB RCE (CVSS 9.8)
* CVE-2025-59407: Hardcoded keystore crypto key (Critical)
* CVE-2025-47818: Hardcoded fallback hotspot credentials
* CVE-2025-47823: Hardcoded system password on ALPR firmware <=2.2
* Shodan integration with built-in queries
* Multi-threaded scanning
* Optional exploitation mode (disabled by default)
* JSON output for results
* Interactive and command-line modes

## Installation

```bash
git clone https://github.com/ekomsSavior/FLOCK_CVE_SCANNER.git
cd FLOCK_CVE_SCANNER
pip install requests shodan ipaddress
```

## Usage

### Basic Scanning (Safe Mode)

```bash
python3 scanner.py
```

This runs in SCAN ONLY mode by default. It will identify vulnerable systems without executing any exploits.

### Enabling Exploitation

```bash
python3 scanner.py --exploit
```

The exploitation flag must be explicitly set. This is a safety measure to prevent accidental exploitation.

### Command Line Options

```bash
python3 scanner.py -t 192.168.1.100           # Scan a single target
python3 scanner.py -t 192.168.1.100 --exploit # Scan and exploit a single target
python3 scanner.py -f targets.txt             # Scan from a file
python3 scanner.py -f targets.txt --exploit   # Scan and exploit from a file
python3 scanner.py -o results.json            # Save results to JSON
python3 scanner.py -v --exploit               # Verbose output with exploitation
python3 scanner.py -T 20 --timeout 10         # Increase threads and timeout
```

### Interactive Mode

1. Run `python3 scanner.py`
2. Select an input method:
   * Single IP
   * IP Range (CIDR)
   * From File
   * Shodan Query (requires API key)
   * Random Scan
3. Enter targets or API keys when prompted
4. Review results and choose to continue or exit

### Shodan Integration

When prompted for a Shodan API key, enter your key. The scanner uses built-in queries specific to CVE-2025 vulnerabilities. The key is not stored or logged.

## Safety Features

* **Exploitation disabled by default**: The tool starts in SCAN ONLY mode
* **User confirmation required**: --exploit flag must be explicitly set
* **Non-destructive scanning**: Default payloads only check for vulnerabilities
* **Rate limiting**: Configurable threads to avoid overwhelming targets

## Output

Results are displayed in real-time with color-coded output:
* Red: Critical vulnerabilities and successful exploits
* Yellow: Medium severity findings
* Green: Successful connections or findings

When exploitation is enabled, successful exploits will show:
* Command output
* Extracted credentials or keys
* Confirmation of access

## Legal Notice

**This tool is for authorized security testing only.** Use only on systems you own or have explicit written permission to test. Unauthorized scanning or exploitation may violate laws and regulations. The authors assume no liability for misuse.

## Known Limitations

* Shodan API requires an account and key
* Free Shodan tier has rate limits
* Some targets may require HTTPS
* ADB exploitation requires port 5555 to be open
