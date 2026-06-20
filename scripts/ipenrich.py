import argparse
import requests
import json
import time
import ipaddress

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
    
def enrichIP(ip):
    results = {}
    results["abuse"] = queryAbuseIPDB(ip)
    time.sleep(15) # Respect API rate limits
    results["virustotal"] = queryVirusTotal(ip)
    return results

def printResults(ip, results, format="table"): # Default format is to be printed as a table
    abuse = results.get("abuse")
    vt = results.get("virustotal") 
    if format == "table":
        print(f"\n{'='*50}")
        print(f"  IP: {ip}")
        print(f"{'='*50}")
        if abuse:
            print(f"\n  [AbuseIPDB]")
            print(f"    Abuse Score : {abuse['abuseScore']}/100")
            print(f"    Country     : {abuse['country']}")
            print(f"    ISP         : {abuse['isp']}")
            print(f"    Reports     : {abuse['reports']}")
            print(f"    Last Seen   : {abuse['lastSeen']}")
        else:
            print(f"\n  [AbuseIPDB] No data returned.")
        if vt:
            print(f"\n  [VirusTotal]")
            print(f"    Malicious   : {vt['malicious']}")
            print(f"    Suspicious  : {vt['suspicious']}")
            print(f"    Harmless    : {vt['harmless']}")
            print(f"    Country     : {vt['country']}")
            print(f"    AS Owner    : {vt['asOwner']}")
        else:
            print(f"\n  [VirusTotal] No data returned.")
        print(f"\n{'='*50}\n")
    elif format == "json":
        output = {"ip": ip, "abuse": abuse, "virustotal": vt}
        print(json.dumps(output, indent=4))
    elif format == "csv":
        print(f"{ip},"
              f"{abuse['abuseScore'] if abuse else 'N/A'},"
              f"{abuse['country'] if abuse else 'N/A'},"
              f"{abuse['isp'] if abuse else 'N/A'},"
              f"{vt['malicious'] if vt else 'N/A'},"
              f"{vt['suspicious'] if vt else 'N/A'}")
    else:
        print(f"[ERROR] Unknown format: {format}")