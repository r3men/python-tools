# python-tools
A repository dedicated to a multitude of scripts designed for improved quality-of-life for cybersecurity enthusiasts or professionals. The repository will be continuously updated as I add more and more scripts.

## iocextractor.py
A script that takes in a user's chosen input file and provides the user with options to extract indicators of compromise (hashes, IP addresses, and email addresses) using regex patterns.
### Usage
python3 iocextractor.py --ips --emails --hashes input.txt | All arguments are optional besides the input file. By default, the script will extract all three.

## decode.py
A script that detects and decodes encoded strings (Base64, URL, Hex, and ROT13) from an input file, handling false positive filtering to ensure clean, readable output.
### Usage
python3 decode.py input.txt | All arguments are optional besides the input file. By default, the script will attempt all four encoding types. Use --base64, --hex, --url, or --rot13 to target a specific format. Use -o output.txt to save results to a file, and --verbose to show decode warnings and errors.

## ipenrich.py
A script that cross-checks IP addresses against multiple threat intelligence sources (AbuseIPDB and VirusTotal) to identify and enrich potentially malicious addresses with reputation data.
### Usage
python3 ipenrich.py ips.txt | All arguments are optional besides the input file. By default, the script will query both AbuseIPDB and VirusTotal. Use --abuseipdb or --virustotal to target a specific source. Use --threshold to filter out IPs below a certain abuse score, --format to output as table, json, or csv, and -o output.txt to save results to a file.
