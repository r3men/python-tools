# Script Name: IOC Extractor
# Purpose: The purpose of this script is to reliably locate IP addresses, email addresses, and potentially malicious file hashes within an input file.

import re
import argparse

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
  
def main():
  parser = argparse.ArgumentParser(description="Extract IOCs (IPs, emails, & hashes) from a file.")
  parser.add_argument("input_file", help="Name of input text file to search")
  parser.add_argument("--ips",    action="store_true", help="Extract IP addresses")
  parser.add_argument("--emails", action="store_true", help="Extract email addresses")
  parser.add_argument("--hashes", action="store_true", help="Extract file hashes")
  args = parser.parse_args()

  extract_all = not (args.ips or args.emails or args.hashes)

if "__name__" == "__main__":
  main()
