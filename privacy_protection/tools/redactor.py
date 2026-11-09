#!/usr/bin/env python3
"""
Redact PII from text using patterns.
Replace matches with [REDACTED_<TYPE>].
"""
import json
import re
import sys
from pathlib import Path

PATTERNS_FILE = Path(__file__).parent / "patterns" / "pii.json"

def load_patterns():
    with open(PATTERNS_FILE) as f:
        return json.load(f)

def redact_text(text, patterns):
    # We need to replace each match with a tag.
    # Build a regex that matches any of the patterns, using named groups.
    # For simplicity, iterate over patterns and replace sequentially.
    # Note: overlapping matches may be an issue; we accept that.
    redacted = text
    for name, regex in patterns.items():
        # Use a function to replace each match with a tag
        def repl(m):
            return f"[REDACTED_{name.upper()}]"
        redacted = re.sub(regex, repl, redacted)
    return redacted

def main():
    if len(sys.argv) < 3:
        print("Usage: redactor.py <input_file> <output_file>")
        sys.exit(1)
    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    if not in_path.is_file():
        print("Input file not found")
        sys.exit(1)
    patterns = load_patterns()
    content = in_path.read_text(errors='ignore')
    redacted = redact_text(content, patterns)
    out_path.write_text(redacted)
    print(f"Redacted {in_path} -> {out_path}")

if __name__ == "__main__":
    main()
