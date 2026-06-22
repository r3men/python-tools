# Script Name: IP Enricher
# Purpose: The purpose of this script is to cross-check given IP addresses against multiple different malware analysis websites such as VirusTotal and AbuseIPDB to identify malicious addresses.

import argparse
import requests
import json
import time
import ipaddress
import contextlib

ABUSEIPDB_API_KEY = "Insert API key here"
VIRUSTOTAL_API_KEY = "Insert API key here"

def isValidIP(s): # Function to check if an IP address found is valid.
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def readFile(input_file):
    valid_ips = []
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                if isValidIP(line):
                    valid_ips.append(line) # Add valid IPs to a list
                else:
                    print(f"[WARN] Skipping invalid IP: {line}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return valid_ips

def queryAbuseIPDB(ip):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        response.raise_for_status()
        data = response.json()["data"]
        return { # Return a dictionary containing information found on that IP
            "abuseScore": data["abuseConfidenceScore"],
            "country":    data["countryCode"],
            "isp":        data["isp"],
            "reports":    data["totalReports"],
            "lastSeen":   data["lastReportedAt"]
        }
    except Exception as e:
        print(f"[ERROR] AbuseIPDB query failed for {ip}: {e}")
        return None
    
def queryVirusTotal(ip):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]
        return {
            "malicious":  data["last_analysis_stats"]["malicious"],
            "suspicious": data["last_analysis_stats"]["suspicious"],
            "harmless":   data["last_analysis_stats"]["harmless"],
            "country":    data.get("country", "N/A"), # Fallback to N/A in case IP is not associated with a specific country
            "asOwner":    data.get("as_owner", "N/A")
        }
    except Exception as e:
        print(f"[ERROR] VirusTotal query failed for {ip}: {e}")
        return None
    
def enrichIP(ip, use_abuse=True, use_vt=True):
    results = {}
    if use_abuse:
        results["abuse"] = queryAbuseIPDB(ip)
        time.sleep(1)
    if use_vt:
        results["virustotal"] = queryVirusTotal(ip)
        time.sleep(15) # Respect API limits
    return results

def printResults(ip, results, fmt="table", emit=print): # default format is a table
    abuse = results.get("abuse")
    vt = results.get("virustotal")
    if fmt == "table":
        emit(f"\n{'='*50}")
        emit(f"  IP: {ip}")
        emit(f"{'='*50}")
        if abuse:
            emit(f"\n  [AbuseIPDB]")
            emit(f"    Abuse Score : {abuse['abuseScore']}/100")
            emit(f"    Country     : {abuse['country']}")
            emit(f"    ISP         : {abuse['isp']}")
            emit(f"    Reports     : {abuse['reports']}")
            emit(f"    Last Seen   : {abuse['lastSeen']}")
        else:
            emit(f"\n  [AbuseIPDB] No data returned.")
        if vt:
            emit(f"\n  [VirusTotal]")
            emit(f"    Malicious   : {vt['malicious']}")
            emit(f"    Suspicious  : {vt['suspicious']}")
            emit(f"    Harmless    : {vt['harmless']}")
            emit(f"    Country     : {vt['country']}")
            emit(f"    AS Owner    : {vt['asOwner']}")
        else:
            emit(f"\n  [VirusTotal] No data returned.")
        emit(f"\n{'='*50}\n")
    elif fmt == "json":
        output = {"ip": ip, "abuse": abuse, "virustotal": vt}
        emit(json.dumps(output, indent=4))
    elif fmt == "csv":
        emit(f"{ip},"
             f"{abuse['abuseScore'] if abuse else 'N/A'},"
             f"{abuse['country'] if abuse else 'N/A'},"
             f"{abuse['isp'] if abuse else 'N/A'},"
             f"{vt['malicious'] if vt else 'N/A'},"
             f"{vt['suspicious'] if vt else 'N/A'}")
    else:
        emit(f"[ERROR] Unknown format: {fmt}")

def main():
    parser = argparse.ArgumentParser(description="Analyze given IPs across multiple malware analysis sources such as VirusTotal and AbuseIPDB.")
    parser.add_argument("input_file", help="Name of input text file to search")
    parser.add_argument("--abuseipdb", action="store_true", help="Check IP against AbuseIPDB records")
    parser.add_argument("--virustotal", action="store_true", help="Check IP against VirusTotal records")
    parser.add_argument("--output", "-o", help="Write results to a file")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format (table, json, csv)")
    parser.add_argument("--threshold", type=int, default=0, help="Only show IPs with abuse score above this value")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show decode errors and warnings")
    args = parser.parse_args()
    query_all = not (args.abuseipdb or args.virustotal)
    ips = readFile(args.input_file)
    if not ips:
        print("[ERROR] No valid IPs found in file.")
        return

    out_ctx = open(args.output, "w", encoding="utf-8") if args.output else contextlib.nullcontext()

    with out_ctx as out_file:
        def emit(s=""):
            print(s) # Print to console & output file
            if args.output:
                out_file.write(s + "\n")
        if args.format == "csv":
            emit("ip,abuseScore,country,isp,malicious,suspicious")
        for ip in ips:
            results = enrichIP(ip, args.abuseipdb or query_all, args.virustotal or query_all)
            abuse = results.get("abuse")
            if abuse and abuse["abuseScore"] < args.threshold:
                if args.verbose:
                    print(f"[SKIP] {ip} scored {abuse['abuseScore']}, below threshold of {args.threshold}")
                continue
            printResults(ip, results, args.format, emit)
    if args.output:
        print(f"\n[INFO] Results written to {args.output}")

if __name__ == "__main__":
    main()