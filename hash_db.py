def load_hashes(path: str) -> set[str]:
    """
    Loads malicious hashes from a text file.
    Each valid SHA-256 hash should be 64 hexadecimal characters.
    Blank lines and comment lines are ignored.
    """
    hashes: set[str] = set()

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            value = line.strip().lower()

            if not value or value.startswith("#"):
                continue

            # Keep only likely SHA-256 hashes.
            if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
                hashes.add(value)

    return hashes
