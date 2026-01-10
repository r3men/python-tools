# python-tools
A Python Security Tool Collection

Here, you will find a collection of python automation scripts designed to complete common security tasks. Each tool has its own unique focus.

**🔧 IP Log Analyzer (log_analyzer.py)**

A command‑line tool for analyzing log files, extracting IPv4 addresses, detecting suspicious events, and exporting results in TXT, JSON, or CSV formats. Supports both interactive mode and argparse automation.
Features:
- Extracts IPv4 addresses from any log file
- Counts occurrences and sorts by frequency
- Detects suspicious events (failed, error, unauthorized, denied)
- Classifies IPs as Private or Public
- Supports TXT, JSON, CSV export
- Fully automated via argparse
- Graceful error handling
