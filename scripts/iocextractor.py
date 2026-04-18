# Script Name: IOC Extractor
# Purpose: The purpose of this script is to reliably locate IP addresses, email addresses, and potentially malicious file hashes within an input file.

import re
import argparse
import requests 

USER_API_KEY = "Insert user API key here"

def findIPS(text):
    pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    return set(re.findall(pattern, text))

def findEmails(text):
    pattern = r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    return set(re.findall(pattern, text))

def findHashes(text):
    pattern = r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b"
    return set(re.findall(pattern, text))

def checkVirusTotal(ioc, ioc_type):
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "email":
        domain = ioc.split('@')[1]
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": USER_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        print(f"  {ioc} — {malicious}/{total} vendors flagged as malicious")
    elif response.status_code == 404:
        print(f"  {ioc} — Not found in VirusTotal")
    else:
        print(f"  {ioc} — API error {response.status_code}")
  
def main():
    parser = argparse.ArgumentParser(description="Extract IOCs (IPs, emails, & hashes) from a file.")
    parser.add_argument("input_file", help="Name of input text file to search")
    parser.add_argument("--ips",    action="store_true", help="Extract IP addresses")
    parser.add_argument("--emails", action="store_true", help="Extract email addresses")
    parser.add_argument("--hashes", action="store_true", help="Extract file hashes")
    args = parser.parse_args()
    extract_all = not (args.ips or args.emails or args.hashes)
    try:
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.input_file}")
        return
    if args.ips or extract_all:
        ips = findIPS(text)
        print(f"\n[IP Addresses] ({len(ips)} found)")
        for ip in sorted(ips):
            print(f"  {ip}")
            checkVirusTotal(ip, "ip")

    if args.emails or extract_all:
        emails = findEmails(text)
        print(f"\n[Email Addresses] ({len(emails)} found)")
        for email in sorted(emails):
            print(f"  {email}")
            checkVirusTotal(email, "email")

    if args.hashes or extract_all:
        hashes = findHashes(text)
        print(f"\n[Hashes] ({len(hashes)} found)")
        for h in sorted(hashes):
            print(f"  {h}")
            checkVirusTotal(h, "hash")

if __name__ == "__main__":
    main()
