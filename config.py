# Set to None to let Scapy choose the default interface.
# You can also set this to something like "eth0" after checking with: ip a
INTERFACE = None

# Berkeley Packet Filter expression.
# Examples: "tcp", "udp", "tcp or udp", "port 80"
BPF_FILTER = "tcp or udp"

# Path to your malicious SHA-256 hash list file.
HASH_DB_PATH = "malicious_hashes.txt"

# AI settings.
# Set USE_OPENAI_AI = True only after installing openai and setting OPENAI_API_KEY.
USE_OPENAI_AI = False
OPENAI_MODEL = "gpt-5.5"
