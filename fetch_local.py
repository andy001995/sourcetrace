import os, sys, httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
entry, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)

def save_flat(url, base):
    try:
        r = httpx.get(url, timeout=15, follow_redirects=True, headers=UA)
        if r.status_code != 200:
            print("SKIP", r.status_code, url); return None
        name = os.path.basename(urlparse(url).path) or "index.html"
        path = os.path.join(base, name)
        with open(path, "wb") as f:
            f.write(r.content)
        print("OK", len(r.content), name)
        return name
    except Exception as e:
        print("ERR", url, e); return None

r = httpx.get(entry, timeout=15, follow_redirects=True, headers=UA)
soup = BeautifulSoup(r.text, "html.parser")

assets = []
for tag, attr in [("script","src"), ("link","href")]:
    for el in soup.find_all(tag):
        v = el.get(attr)
        if not v: continue
        if tag=="link" and "stylesheet" not in (el.get("rel") or []): continue
        assets.append(urljoin(entry, v))
assets = list(dict.fromkeys(assets))

names = {}
for a in assets:
    n = save_flat(a, outdir)
    if n: names[a] = n

# 重写 HTML：把绝对 URL 换成相对文件名
html = r.text
for a, n in names.items():
    html = html.replace(a, n)

with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as f:
    f.write(html)

print("DONE ->", outdir)
