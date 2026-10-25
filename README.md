# Web Security Scanner

## Project Topic
Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws.

## Overview
Web Security Scanner is a Python-based tool that checks HTTP security headers and looks for possible CORS origin reflection. Results require manual verification before identifying a vulnerability.

## Features
- Checks for CORS origin reflection.
- Checks for common HTTP security headers.
- Displays HTTP response status.
- Reports present and missing security headers.
- Reads target URLs from a text file.

## Requirements
- Python 3
- requests library

## Installation
Install the required dependency:

python3 -m pip install requests
## Usage
Create a text file containing one authorized target URL per line.

Run the scanner:

    python3 web_security_scanner.py -l test_targets.txt -c https://example.com
Note: https://example.com is a placeholder Origin for basic testing. Use a controlled Origin and verify CORS behaviour manually before reporting a finding.
Optional arguments:

- `-t`: Number of threads
- `--timeout`: Request timeout in seconds
- `-o`: Output file for flagged CORS results

## Important Notes
- Test only websites you own or have explicit permission to assess.
- CORS reflection does not automatically confirm a vulnerability.
- Missing security headers must be evaluated in context.
- Use a valid, authorized CORS test origin for meaningful CORS assessment.
- `https://example.com` is a placeholder Origin; use a controlled Origin and manually verify CORS behaviour before reporting a finding.
- The current output file option saves flagged CORS results; it does not save the complete security-header report.

## Project Status
Educational project. Testing and validation are ongoing.
