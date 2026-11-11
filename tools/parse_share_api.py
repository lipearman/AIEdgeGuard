"""Parse ChatGPT share API JSON into readable conversation text.

Usage: python parse_share_api.py <share_api.json> <out.md>
"""
import json
import sys


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = json.load(open(src, encoding='utf-8'))
    conv = data.get('linear_conversation')
    title = data.get('title', '')

    if isinstance(conv, list):
        nodes = conv
    elif isinstance(conv, dict):
        # Build ordered message list by walking from current_node
        mapping = conv.get('mapping', {})
        nodes = []
        node_id = conv.get('current_node')
        while node_id:
            node = mapping.get(node_id)
            if not node:
                break
            nodes.append(node)
            node_id = node.get('parent')
        nodes.reverse()
    else:
        nodes = []

    messages = []
    for node in nodes:
        msg = node.get('message') if isinstance(node, dict) else None
        if not msg:
            continue
        role = msg.get('author', {}).get('role', '')
        if role not in ('user', 'assistant'):
            continue
        parts = msg.get('content', {}).get('parts', [])
        texts = []
        for p in parts:
            if isinstance(p, str) and p.strip():
                texts.append(p)
            elif isinstance(p, dict):
                t = p.get('text') or json.dumps(p, ensure_ascii=False)[:500]
                if t:
                    texts.append(t)
        body = '\n\n'.join(texts).strip()
        if not body:
            continue
        # Skip noise (system-like empty content)
        messages.append((role, body))

    sys.stderr.write(f"messages: {len(messages)}\n")
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(f"# {title}\n\n")
        for i, (role, body) in enumerate(messages):
            f.write(f"\n\n---\n\n## [{i}] {role.upper()}\n\n")
            f.write(body)
    sys.stderr.write(f"written: {dst}\n")


if __name__ == '__main__':
    main()
