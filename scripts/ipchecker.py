# Script Name: IP Checker
# Purpose: The purpose of this script is to utilize a VirusTotal API key to directly automate the checking of suspected IP addresses, rather than having to manually check each one.

import requests
import argparse

USER_API_KEY = "Replace with actual user key here"
parser = argparse.ArgumentParser()

parser.add_argument("input_file", help="File with IP addresses to check")

def checkIP(ip_address):
   url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}" 
   headers = {
      "accept": "application/json",
      "x-apikey": USER_API_KEY
   }
   response = requests.get(url, headers=headers)
   if response.status_code == 200:
      try:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats["malicious"]
        harmless_count = stats["harmless"]
        suspicious_count = stats["suspicious"]
        undetected_count = stats["undetected"]
        results = [malicious_count, harmless_count, suspicious_count, undetected_count]
        return results
      except (KeyError, ValueError) as e:
        print(f"Error parsing response: {e}")
        return None
   else:
      print("Error while retrieving VirusTotal data.")
      return None

def main():
   args = parser.parse_args()
   try:
      with open(args.input_file, "r") as f:
           ip_list = [line.strip() for line in f.readlines() if line.strip()]
   except FileNotFoundError:
      print(f"File not found: {args.input_file}")
      return
   for ip in ip_list:
      result = checkIP(ip)
      if result is not None:
         print(f"IP Address: {ip} | Malicious: {result[0]} | Harmless: {result[1]} | Suspicious: {result[2]} | Undetected: {result[3]}")

if __name__ == "__main__":
    main()
  
    
  
   
