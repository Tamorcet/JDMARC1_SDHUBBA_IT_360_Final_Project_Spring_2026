# config.py
# Stores settings for the malware detector.

# Network interface to monitor.
# Use None to let Scapy choose automatically.
# For localhost testing, use "lo".
# For real network traffic, use your network interface, such as "ens33", "eth0", or "enp0s3".
INTERFACE = "lo"

# Packet filter.
# This limits capture to TCP and UDP traffic.
BPF_FILTER = "tcp or udp"

# File containing known malicious SHA-256 hashes.
HASH_DB_PATH = "malicious_hashes.txt"

# OpenAI model used for AI recommendations.
OPENAI_MODEL = "gpt-5.2"

# If True, the program tries OpenAI first.
# If OpenAI fails, it uses the local fallback recommendation system.
USE_OPENAI = True
