# hash_db.py
# Loads malicious hashes from a text file.

def load_hashes(path: str) -> set[str]:
    """
    Reads malicious hashes from a file.

    Each hash should be on its own line.
    Blank lines are ignored.
    Hashes are converted to lowercase so matching is consistent.
    """

    hashes = set()

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            cleaned = line.strip().lower()

            # Ignore empty lines.
            if not cleaned:
                continue

            hashes.add(cleaned)

    return hashes
