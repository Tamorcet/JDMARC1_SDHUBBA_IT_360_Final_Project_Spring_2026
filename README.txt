# Malware Detector with AI Recommendations

## Overview

This program monitors live network traffic and checks packet payloads against a list of known malicious SHA-256 hashes.

When a match is found, the program prints:

- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Match type
- SHA-256 hash
- Timestamp
- AI-generated remediation recommendations

The AI recommendations can use OpenAI if an API key is configured. If OpenAI fails, the program uses local fallback recommendations.

---

## Files

```text
main.py
monitor.py
hash_db.py
ai_recommendations.py
config.py
malicious_hashes.txt
requirements.txt
README.md