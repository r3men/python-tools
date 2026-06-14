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
    