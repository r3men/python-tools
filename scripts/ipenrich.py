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