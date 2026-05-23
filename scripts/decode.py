# Script Name: Decoder
# Purpose: Scans a text file and decodes any detected Base64, Hex, URL-encoded, or ROT13 strings.

import re
import base64
import urllib.parse
import codecs
import argparse
import contextlib

COMMON_WORDS = {'the', 'and', 'for', 'are', 'you', 'this', 'with', 'from', 'that', 'have'}

def isBase64(s):
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    if len(s) % 4 != 0 or len(s) < 8:
        return False
    return bool(re.match(pattern, s))

def isHex(s):
    cleaned = s.replace(' ', '').replace('\\x', '').replace('0x', '')
    return len(cleaned) % 2 == 0 and len(cleaned) >= 6 and bool(re.match(r'^[a-fA-F0-9]+$', cleaned))

def isURL(s):
    return '%' in s and bool(re.search(r'%[0-9A-Fa-f]{2}', s))

def isROT13(s):
    decoded = codecs.decode(s, 'rot_13')
    if decoded == s:
        return False
    original_hits = len(set(s.lower().split()) & COMMON_WORDS)
    decoded_hits = len(set(decoded.lower().split()) & COMMON_WORDS)
    return decoded_hits > original_hits

def decodeBase64(s):
    result = base64.b64decode(s).decode('utf-8', errors='replace')
    if '\ufffd' in result:
        raise ValueError("Decoded output contains invalid UTF-8 bytes")
    printable = sum(c.isprintable() for c in result)
    if printable / len(result) < 0.8:
        raise ValueError("Decoded output is not printable")
    return result

def decodeHex(s):
    cleaned = s.replace(' ', '').replace('\\x', '').replace('0x', '')
    result = bytes.fromhex(cleaned).decode('utf-8', errors='replace')
    if '\ufffd' in result:
        raise ValueError("Decoded hex output contains invalid UTF-8 bytes")
    printable = sum(c.isprintable() for c in result)
    if not result or printable / len(result) < 0.8:
        raise ValueError("Decoded hex output is not printable")
    return result

def decodeURL(s):
    return urllib.parse.unquote(s)

def decodeROT13(s):
    return codecs.decode(s, 'rot_13')

def main():
    parser = argparse.ArgumentParser(description="Decode suspicious strings from a file.")
    parser.add_argument("input_file", help="Name of input text file to search")
    parser.add_argument("--base64", action="store_true", help="Decode Base64")
    parser.add_argument("--hex", action="store_true", help="Decode Hex")
    parser.add_argument("--url", action="store_true", help="Decode URL")
    parser.add_argument("--rot13", action="store_true", help="Decode ROT13")
    parser.add_argument("--all", action="store_true", help="Decode all supported formats")
    parser.add_argument("--output", "-o", help="Write results to a file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show decode errors and warnings")
    args = parser.parse_args()
    extract_all = args.all or not (args.base64 or args.hex or args.url or args.rot13)

    try:
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.input_file}")
        return

    out_ctx = open(args.output, "w", encoding="utf-8") if args.output else contextlib.nullcontext()

    with out_ctx as out_file:
        def emit(s=""):
            print(s)
            if args.output:
                out_file.write(s + "\n")

        if args.base64 or extract_all:
            emit("\n[Base64]")
            for line in text.splitlines():
                stripped = line.strip()
                if isBase64(stripped):
                    try:
                        decoded = decodeBase64(stripped)
                        emit(f"{stripped} → {decoded}")
                    except Exception as e:
                        if args.verbose:
                            print(f"  [WARN] Base64 decode failed for '{stripped}': {e}")

        if args.hex or extract_all:
            emit("\n[Hex]")
            for line in text.splitlines():
                stripped = line.strip()
                if isHex(stripped):
                    try:
                        decoded = decodeHex(stripped)
                        emit(f"{stripped} → {decoded}")
                    except Exception as e:
                        if args.verbose:
                            print(f"  [WARN] Hex decode failed for '{stripped}': {e}")

        if args.url or extract_all:
            emit("\n[URL]")
            for line in text.splitlines():
                stripped = line.strip()
                if isURL(stripped):
                    try:
                        decoded = decodeURL(stripped)
                        emit(f"{stripped} → {decoded}")
                    except Exception as e:
                        if args.verbose:
                            print(f"  [WARN] URL decode failed for '{stripped}': {e}")

        if args.rot13 or extract_all:
            emit("\n[ROT13]")
            for line in text.splitlines():
                stripped = line.strip()
                if isROT13(stripped):
                    try:
                        decoded = decodeROT13(stripped)
                        emit(f"{stripped} → {decoded}")
                    except Exception as e:
                        if args.verbose:
                            print(f"  [WARN] ROT13 decode failed for '{stripped}': {e}")

    if args.output:
        print(f"\n[INFO] Results written to {args.output}")

if __name__ == "__main__":
    main()
