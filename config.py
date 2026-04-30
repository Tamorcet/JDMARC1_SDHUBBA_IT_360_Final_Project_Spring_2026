# Set to None to let Scapy choose the default interface.
INTERFACE = None

# Berkeley Packet Filter expression.
# Examples:
# "tcp"
# "udp"
# "tcp or udp"
# "port 80"
BPF_FILTER = "tcp or udp"

# Path to your mixed hash list file.
HASH_DB_PATH = "malicious_hashes.txt"
