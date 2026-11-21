"""Strict formatted-name splitting shared by inventory and declared-product checks."""


def cpe_parts(value):
    parts = []
    current = ""
    escaped = False
    for char in value:
        if escaped:
            current += "\\" + char
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append(current)
            current = ""
        else:
            current += char
    if escaped:
        raise ValueError("Incomplete CPE escape")
    parts.append(current)
    if (
        len(parts) != 13
        or parts[:2] != ["cpe", "2.3"]
        or parts[2] not in ("a", "o", "h")
        or any(not p or any(ord(c) < 32 for c in p) for p in parts)
    ):
        raise ValueError("Use a complete CPE 2.3 formatted name")
    return parts
