"""Convert absolute links to relative in ai-call-center static files.

Enables publishing the app under a path prefix (/AICallCenter) via the funnel
— relative links resolve under the prefix at every page depth. Backups are
written as <file>.bak-aicall before editing. Idempotent.
"""
import shutil

S = r"C:\Users\Admin\ai-call-center\services\gateway\app\static"


def patch(fname: str, pairs: list[tuple[str, str]]) -> int:
    path = S + "\\" + fname
    shutil.copyfile(path, path + ".bak-aicall")
    c = open(path, encoding="utf-8").read()
    n = 0
    for old, new in pairs:
        if old in c:
            c = c.replace(old, new)
            n += 1
    open(path, "w", encoding="utf-8", newline="").write(c)
    return n


def main() -> None:
    print("[1]", patch("outbound.js", [
        ("fetch('/api/outbound'+path", "fetch('api/outbound'+path"),
    ]))
    print("[2]", patch("callback.html", [
        ("fetch('/api/leads'", "fetch('api/leads'"),
    ]))
    print("[3]", patch("index.html", [
        ('href="/" class="active"', 'href="./" class="active"'),
        ('href="/outbound.html"', 'href="outbound.html"'),
        ('href="/form"', 'href="form"'),
        ('fetch("/health")', 'fetch("health")'),
    ]))
    print("[4]", patch("outbound.html", [
        ('href="/" class="brand"', 'href="./" class="brand"'),
        ('<a href="/">ประวัติการโทร</a>', '<a href="./">ประวัติการโทร</a>'),
        ('href="/outbound.html"', 'href="outbound.html"'),
    ]))


if __name__ == "__main__":
    main()
