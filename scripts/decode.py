# Script Name: Decoder
# Purpose: Detect and decode encoded blobs (Base64, URL, Hex, ROT13) from an input file, handling multiple layers of encoding.

import re
import base64
import urllib.parse
import codecs
import argparse


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
    readable = sum(c.isalpha() for c in decoded)
    return readable > len(s) * 0.6
