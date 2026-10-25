#!/usr/bin/env python3
"""
Simple CORS misconfiguration scanner.

Sends each target a request with a custom Origin header (your collaborator
domain) and flags it for MANUAL VERIFICATION if that origin is reflected
in the Access-Control-Allow-Origin response header.

Only scan domains you own or are authorized to test (e.g. in-scope bug bounty).

Usage:
    python3 cors_scanner.py -l domains.txt -c yourid.oastify.com
    python3 cors_scanner.py -l domains.txt -c yourid.oastify.com -t 20 -o results.txt
"""
def show_banner():
    print(r"""
  ____ ___  ____  ____
 / ___/ _ \|  _ \|  _ \
| |   | | | | |_) | |_) |
| |__| |_| |  _ <|  __/
 \____\___/|_| \_\_|

  WEB SECURITY SCANNER
  Version 1.0
""")
import argparse
import concurrent.futures
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def normalize(domain):
    domain = domain.strip()
    if not domain or domain.startswith("#"):
        return None
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    return domain.rstrip("/")


def check(url, origin, timeout):
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (CORS-Scanner)",
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout,
                         verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return {"url": url, "error": str(e.__class__.__name__)}

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    return {
        "url": url,
        "status": r.status_code,
        "acao": acao,
        "acac": acac,
        "reflected": acao == origin,
    }

def check_security_headers(url, timeout):
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
    ]

    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Web-Security-Scanner"},
        )
    except requests.RequestException as e:
        return {"url": url, "error": type(e).__name__}

    present = [
        header for header in security_headers
        if header in response.headers
    ]
    missing = [
        header for header in security_headers
        if header not in response.headers
    ]

    return {
        "url": url,
        "status": response.status_code,
        "present_headers": present,
        "missing_headers": missing,
    }
def main():
    show_banner()
    p = argparse.ArgumentParser(description="Web security scanner for HTTP headers and CORS checks")
    p.add_argument("-l", "--list", required=True, help="File with one domain per line")
    p.add_argument("-c", "--collab", required=True,
                   help="Collaborator domain to use as Origin (e.g. abc.oastify.com)")
    p.add_argument("-t", "--threads", type=int, default=10, help="Threads (default 10)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    p.add_argument("-o", "--output", help="Save flagged results to this file")
    args = p.parse_args()

    collab = args.collab.strip()
    origin = collab if collab.startswith(("http://", "https://")) else "https://" + collab

    try:
        with open(args.list) as f:
            targets = [u for u in (normalize(line) for line in f) if u]
    except FileNotFoundError:
        sys.exit(f"File not found: {args.list}")

    print(f"[*] Scanning {len(targets)} targets with Origin: {origin}\n")
    flagged = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(check, u, origin, args.timeout) for u in targets]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            url = res["url"]

            if "error" in res:
                print(f"[-] {url} -> error ({res['error']})")
                continue

            if res["reflected"]:
                if res["acac"]:
                    tag = f"{RED}[!!] REFLECTED + CREDENTIALS{RESET}"
                else:
                    tag = f"{YELLOW}[!] REFLECTED{RESET}"
                print(f"{tag} {url} (status {res['status']}) -> VERIFY MANUALLY")
                flagged.append(res)
            else:
                acao = res["acao"] or "none"
                print(f"{GREEN}[ok]{RESET} {url} (ACAO: {acao})")
    print("\n[*] Checking security headers...")
    for target in targets:
        result = check_security_headers(target, args.timeout)

        if "error" in result:
            print(f"[-] {target} -> header check error ({result['error']})")
            continue

        print(f"\n[Headers] {target} (status {result['status']})")
        print(f"  Present: {', '.join(result['present_headers']) or 'none'}")
        print(f"  Missing: {', '.join(result['missing_headers']) or 'none'}")
    print(f"\n[*] Done. {len(flagged)} target(s) need manual verification.")

    if args.output and flagged:
        with open(args.output, "w") as f:
            for r in flagged:
                f.write(f"{r['url']} | ACAO: {r['acao']} | "
                        f"Credentials: {r['acac']} | Status: {r['status']}\n")
        print(f"[*] Saved to {args.output}")


if __name__ == "__main__":
    main()
