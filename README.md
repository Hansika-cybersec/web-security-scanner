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

## Installation
Install the required dependencies:

```bash
python -m pip install -r requirements.txt
```
## Usage

Create a text file containing one authorized target URL per line.

Check the available command-line arguments:

```bash
python web_security_scanner.py -h
```

The scanner requires the following arguments:
- `-l` or `--list`: Path to the target-list file.
- `-c` or `--collab`: Origin value used for CORS testing.

Optional arguments:
- `-t` or `--threads`: Number of concurrent threads.
- `--timeout`: Request timeout in seconds.
- `-o` or `--output`: File for flagged CORS results.

To perform a scan, provide a target-list file and a valid, controlled Origin appropriate for CORS testing. Use only authorized targets.

## Important Notes
- Test only websites you own or have explicit permission to assess.
- CORS reflection does not automatically confirm a vulnerability.
- Missing security headers must be evaluated in context.
- Use a valid, authorized CORS test origin for meaningful CORS assessment.
- The current output file option saves flagged CORS results; it does not save the complete security-header report.

## Project Status
Educational project. Testing and validation are ongoing.
