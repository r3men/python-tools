# python-tools
A repository dedicated to a multitude of scripts designed for improved quality-of-life for cybersecurity enthusiasts or professionals. The repository will be continuously updated as I add more and more scripts.

## iocextractor.py
A script that takes in a user's chosen input file and provides the user with options to extract indicators of compromise (hashes, IP addresses, and email addresses) using regex patterns.
### Usage
python3 iocextractor.py --ips --emails --hashes input.txt | All arguments are optional besides the input file. By default, the script will extract all three.
