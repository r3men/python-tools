# Script Name: IP Checker
# Purpose: The purpose of this script is to utilize a VirusTotal API key to directly automate the checking of suspected IP addresses, rather than having to manually check each one.

import requests

USER_API_KEY = "Replace with actual user key here"

def checkIP(ip_address):
   url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}" # Constructs the API endpoint using the provided IP address
   headers = {
      "accept": "application/json",
      "x-apikey": USER_API_KEY
   }
  
  response = response.get(url, headers=headers)
    
  
   
