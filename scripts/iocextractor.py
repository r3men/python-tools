# Script Name: IOC Extractor
# Purpose: The purpose of this script is to reliably locate IP addresses, email addresses, and potentially malicious file hashes within an input file.

import re
import argparse

def findIPS(text):
  pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
  ip_addresses = set(re.findall(pattern, text))
  return ip_addresses
  
def findEmails(text):
  emails = []
  return emails
  
def findHashes():
  hashes = [text]
  return hashes

def main():


if "__name__" == "__main__":
  main()
