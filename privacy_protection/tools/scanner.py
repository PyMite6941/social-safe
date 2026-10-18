#!/usr/bin/env python3
"""
Simple PII scanner using regex patterns.
Usage: python3 scanner.py <file_or_directory>
"""
import json
import re
import sys
from pathlib import Path

PATTERNS_FILE = Path(__file__).parent / "patterns" / "pii.json"

def load_patterns():
    with open(PATTERNS_FILE) as f:
        return json.load(f)

def scan_text(text, patterns):
    findings = {}
    for name, regex in patterns.items():
        matches = re.findall(regex, text)
        if matches:
            # deduplicate
            findings[name] = list(set(matches))
    return findings

def scan_file(path):
    try:
        content = path.read_text(errors='ignore')
    except Exception as e:
        return {"error": str(e)}
    return scan_text(content, load_patterns())

def main():
    if len(sys.argv) < 2:
        print("Usage: scanner.py <file_or_directory>")
        sys.exit(1)
    target = Path(sys.argv[1])
    if target.is_file():
        result = scan_file(target)
        print(json.dumps(result, indent=2))
    elif target.is_dir():
        for file in target.rglob("*"):
            if file.is_file():
                res = scan_file(file)
                # only show if something found
                if any(res.values()) and not res.get("error"):
                    print(f"=== {file} ===")
                    print(json.dumps(res, indent=2))
    else:
        print("Path not found")
        sys.exit(1)

if __name__ == "__main__":
    main()
