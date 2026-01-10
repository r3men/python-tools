# python-tools
A Python Security Tool Collection

Here, you will find a collection of python automation scripts designed to complete common security tasks. Each tool has its own unique focus.

## 🔧 IP Log Analyzer (log_analyzer.py)

A command‑line tool for analyzing log files, extracting IPv4 addresses, detecting suspicious events, and exporting results in TXT, JSON, or CSV formats. Supports both interactive mode and argparse automation.
Features:
- Extracts IPv4 addresses from any log file
- Counts occurrences and sorts by frequency
- Detects suspicious events (failed, error, unauthorized, denied)
- Classifies IPs as Private or Public
- Supports TXT, JSON, CSV export
- Fully automated via argparse
- Graceful error handling

## 🔐 SIEM Log Parser (siem_engine.py)
A modular Python tool for analyzing authentication logs and detecting suspicious login behavior. Designed for SOC analysts and cybersecurity enthusiasts, this engine supports both interactive mode and argparse automation. It identifies brute force attacks, password spraying, root login attempts, and multi-stage attack chains using time-window and correlation logic.
Features:
- Parses standard auth.log format and extracts timestamps, IPs, and usernames
- Detects brute force, slow brute force, and high-velocity login attempts
- Identifies password spraying based on unique username patterns
- Flags root login attempts and fail→success compromise chains
- Implements advanced correlation rules for multi-stage attacks
- Supports interactive mode and argparse automation
- Outputs clean summary to terminal or saves to TXT file
- Graceful error handling for file paths and input threshold
