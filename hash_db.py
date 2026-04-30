def load_hash_database(path: str) -> set[str]:
    """
    Load only SHA-256 hashes (64 hex characters) from a text file.
    Invalid, short, or other hash types are ignored.
    """
    hashes: set[str] = set()
    total_entries = 0

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            total_entries += 1
            value = line.strip().lower()

            if not value or value.startswith("#"):
                continue

            if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
                hashes.add(value)

    print(f"[+] Filtered {len(hashes)} SHA-256 hashes from {total_entries} lines.")
    return hashes
