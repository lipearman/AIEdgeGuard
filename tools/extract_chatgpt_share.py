"""Extract conversation text from a downloaded ChatGPT share page HTML.

Usage: python extract_chatgpt_share.py <page.html> <out.txt>
"""
import json
import re
import sys

MARKER = "streamController.enqueue("


def parse_js_strings(data: str) -> list[str]:
    chunks = []
    pos = 0
    while True:
        i = data.find(MARKER, pos)
        if i < 0:
            break
        i += len(MARKER)
        if i >= len(data) or data[i] != '"':
            pos = i
            continue
        j = i + 1
        buf = []
        pairs = {'n': '\n', 't': '\t', 'r': '\r', '"': '"',
                 '\\': '\\', '/': '/', 'b': '\b', 'f': '\f'}
        while j < len(data):
            ch = data[j]
            if ch == '\\':
                nxt = data[j + 1]
                if nxt == 'u':
                    buf.append(chr(int(data[j + 2:j + 6], 16)))
                    j += 6
                    continue
                buf.append(pairs.get(nxt, nxt))
                j += 2
                continue
            if ch == '"':
                break
            buf.append(ch)
            j += 1
        chunks.append(''.join(buf))
        pos = j
    return chunks


def decode_turbo_stream(serialized: str):
    """Decode react-router turbo-stream wire format.

    Structure: {"_<key>": <ref>, ...} arrays where keys/values prefixed with
    '_' are numeric indices into a flat `promises`-like array. We rebuild the
    value array and resolve references.
    """
    # The payload is a JSON array of encoded parts: '[' ... ']'
    try:
        parts = json.loads(serialized)
    except json.JSONDecodeError:
        return None

    # Flatten: each element is itself an encoded array [type, value...].
    # Collect all entries in order; entries starting with '_' are refs.
    entries = []

    def walk(node):
        if isinstance(node, list):
            entries.append(node)
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for k, v in node.items():
                entries.append([k, v])
                walk(v)

    walk(parts)
    return parts


def try_simple_extract(joined: str) -> list[str]:
    """Fallback: pull readable message strings heuristically."""
    # Message contents in ChatGPT shares appear as JSON-escaped strings.
    # Look for the pattern  "parts":["  ...  "]  inside the stream text.
    texts = re.findall(r'"parts":\["(.*?)"\]', joined)
    out = []
    for t in texts:
        try:
            out.append(json.loads('"' + t + '"'))
        except json.JSONDecodeError:
            out.append(t)
    return out


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, encoding='utf-8', errors='replace').read()
    chunks = parse_js_strings(data)
    joined = ''.join(chunks)
    open(dst + '.raw.txt', 'w', encoding='utf-8').write(joined)
    print(f"chunks={len(chunks)} chars={len(joined)}")

    msgs = try_simple_extract(joined)
    print(f"heuristic messages found: {len(msgs)}")
    with open(dst, 'w', encoding='utf-8') as f:
        for i, m in enumerate(msgs):
            f.write(f"\n\n===== MESSAGE {i} =====\n")
            f.write(m)
    if not msgs:
        # dump first 3000 chars for inspection
        with open(dst + '.head.txt', 'w', encoding='utf-8') as f:
            f.write(joined[:3000])
        print("No heuristic match; raw + head files written.")


if __name__ == '__main__':
    main()
