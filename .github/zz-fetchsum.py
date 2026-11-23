# Option B prototype: fetch every module named in a repo's go.sum files from
# proxy.golang.org into a GOPROXY file layout, checking each against go.sum.
import sys, os, hashlib, base64, zipfile, io, json, time, urllib.request, concurrent.futures as cf
repo, out = sys.argv[1], sys.argv[2]
PROXY = "https://proxy.golang.org"
def esc(p): return "".join("!" + c.lower() if c.isupper() else c for c in p)
def h1(files):  # files: list of (name, bytes)
    s = "".join("%s  %s\n" % (hashlib.sha256(b).hexdigest(), n) for n, b in sorted(files))
    return "h1:" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
want = {}
for root, dirs, fs in os.walk(repo):
    dirs[:] = [d for d in dirs if d not in (".git", "vendor")]
    if "go.sum" in fs:
        for line in open(os.path.join(root, "go.sum")):
            p = line.split()
            if len(p) == 3: want[(p[0], p[1])] = p[2]
def get(url):
    with urllib.request.urlopen(url, timeout=120) as r: return r.read()
res = {"entries": len(want), "ok": 0, "bad": [], "failed": [], "bytes": 0}
def one(k):
    mod, ver = k; h = want[k]
    if ver.endswith("/go.mod"):
        v = ver[:-7]; b = get(f"{PROXY}/{esc(mod)}/@v/{esc(v)}.mod"); got = h1([("go.mod", b)]); ext = ".mod"
    else:
        v = ver; b = get(f"{PROXY}/{esc(mod)}/@v/{esc(v)}.zip")
        z = zipfile.ZipFile(io.BytesIO(b)); got = h1([(n, z.read(n)) for n in z.namelist()]); ext = ".zip"
    if got != h: return ("bad", k, 0)
    d = os.path.join(out, esc(mod), "@v"); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, esc(v) + ext), "wb").write(b)
    if not os.path.exists(os.path.join(d, esc(v) + ".info")):
        open(os.path.join(d, esc(v) + ".info"), "wb").write(get(f"{PROXY}/{esc(mod)}/@v/{esc(v)}.info"))
    return ("ok", k, len(b))
t = time.monotonic()
with cf.ThreadPoolExecutor(8) as ex:
    futs = {ex.submit(one, k): k for k in want}
    for f in cf.as_completed(futs):
        try:
            s, k, n = f.result()
            if s == "ok": res["ok"] += 1; res["bytes"] += n
            else: res["bad"].append(" ".join(k))
        except Exception as e: res["failed"].append(" ".join(futs[f]) + ": " + str(e)[:80])
res["seconds"] = round(time.monotonic() - t, 1)
print(json.dumps(res))
