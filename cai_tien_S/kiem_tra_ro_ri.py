# -*- coding: utf-8 -*-
"""
kiem_tra_ro_ri.py - Kiem tra S2 (+ san pham) co nho thong tin tuong lai khong

VAN DE
  S2 lay nha cung cap tu CPE trong cau hinh NVD hien tai. NVD gan CPE khi phan tich lo hong,
  thuong sau ngay cong bo (nam 2024-2025 NVD tre phan tich), va co the uu tien phan tich lo hong
  da vao KEV. Neu lo hong bi khai thac de co CPE hon, S2 duoc loi tu thong tin chua co tai ngay D.

HAI PHEP KIEM TRA
  K1. Ty le co CPE trong nhom bi khai thac so voi nhom khong bi khai thac.
  K2. Chay lai S2 voi nha cung cap lay tu sourceIdentifier: dia chi cua don vi cong bo (CNA),
      co ngay tu luc cong bo nen khong ro ri. Lich su KEV cung dem theo sourceIdentifier.

Chay sau cai_tien_S.py (dung lai du lieu da tai).
"""
import os, sys, json, gzip
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "cai_tien_S.py"), encoding="utf-8").read()
src = src.split("# ============================================================== 3.")[0]
sys.argv = [sys.argv[0]]
exec(compile(src, "cai_tien_S", "exec"))
lines.clear()
full = open(os.path.join(HERE, "cai_tien_S.py"), encoding="utf-8").read()
exec(compile("def exp_hits" + full.split("def exp_hits")[1].split("\n# ====")[0], "exp_hits", "exec"))

# ---------------------------------------------------------------- sourceIdentifier tu tep NVD da tai
cache = os.path.join(DATA, "nvd_cna.csv.gz")
if os.path.exists(cache):
    cna = pd.read_csv(cache)
else:
    rows = []
    for y in NVD_YEARS:
        js = json.loads(gzip.decompress(open(os.path.join(DATA, f"nvdcve-2.0-{y}.json.gz"), "rb").read()))
        rows += [(it["cve"]["id"].upper(), (it["cve"].get("sourceIdentifier") or "").lower())
                 for it in js.get("vulnerabilities", [])]
        del js
    cna = pd.DataFrame(rows, columns=["id", "cna"]); cna.to_csv(cache, index=False)
cmap = dict(zip(cna["id"], cna["cna"].fillna("")))
d["cna"] = d["id"].map(cmap).fillna("")

log("=" * 78); log("K1. TY LE CO CPE: NHOM BI KHAI THAC SO VOI NHOM KHONG BI KHAI THAC"); log("=" * 78)
for y in YEARS:
    s = d[d["year"] == y]
    log(f"  {y}: bi khai thac {100*s.loc[s['y']==1,'co_cpe'].mean():5.1f}% co CPE   "
        f"khong bi khai thac {100*s.loc[s['y']==0,'co_cpe'].mean():5.1f}%")

# ---------------------------------------------------------------- lich su KEV theo CNA
kev["cna"] = kev["cve"].map(cmap).fillna("")
by_cna = {}
for c, ad in zip(kev["cna"], kev["added"]):
    if c: by_cna.setdefault(c, []).append(ad.value)
by_cna = {c: np.sort(np.array(a)) for c, a in by_cna.items()}
d["nkev_cna"] = [int(np.searchsorted(by_cna[c], D.value, side="right")) if c in by_cna else 0
                 for c, D in zip(d["cna"], d["D"])]
d["bac_cna"] = 0
for i, (lo, hi) in enumerate(BUCKETS): d.loc[(d["nkev_cna"] >= lo) & (d["nkev_cna"] <= hi), "bac_cna"] = i

def learn(col, ty):
    tr = d[d["D"] + pd.Timedelta(days=FOLLOW) < pd.Timestamp(f"{ty}-01-01")]
    g = tr.groupby(col)["y"].agg(["sum", "count"])
    return {b: float(g.loc[b, "sum"] / g.loc[b, "count"]) if b in g.index else 0.0 for b in range(len(BUCKETS))}, g

log("\n" + "=" * 78); log("K2. S2 VOI NHA CUNG CAP LAY TU CNA (khong ro ri)"); log("=" * 78)
PR = {}
for ty in TEST:
    PR[ty] = {"cpe": learn("bac", ty)[0], "cna": learn("bac_cna", ty)[0]}
    p, g = learn("bac_cna", ty)
    log(f"  Kiem thu {ty}: " + ", ".join(f"bac {b}: {int(g.loc[b,'sum']) if b in g.index else 0}/"
                                      f"{int(g.loc[b,'count']) if b in g.index else 0}" for b in range(len(BUCKETS))))

def sc(s, ty, kind):
    c, e = s["cvss"].values, s["epss"].values
    if kind == "S0": return c * e ** ALPHA
    col, key = ("bac", "cpe") if kind == "S2 (CPE)" else ("bac_cna", "cna")
    f = np.array([PR[ty][key][b] for b in s[col].values])
    return c * np.maximum(e, f) ** ALPHA

KINDS = ["S0", "S2 (CPE)", "S2 (CNA)"]
VOL = [(f"Va {int(f*100)}%", f) for f in FRACS] + [("Va bang CSA", None)]
tot = {}; Pn = 0
for yy in TEST:
    s = d[d["year"] == yy]; t = s["y"].values; Pn += int(t.sum()); W = int((s["cvss"] >= CSA_T).sum())
    for k in KINDS:
        for vl, f in VOL:
            tot[(k, vl)] = tot.get((k, vl), 0) + exp_hits(sc(s, yy, k), t, W if f is None else f * len(s))
log(f"\n  Gop 2024 va 2025, {Pn} lo hong bi khai thac")
log(f"  {'Cach xep':<12}" + "".join(f"{vl:>14}" for vl, _ in VOL))
for k in KINDS:
    log(f"  {k:<12}" + "".join(f"{tot[(k, vl)]:>8.1f} ({100*tot[(k, vl)]/Pn:>3.0f}%)" for vl, _ in VOL))

rng = np.random.default_rng(SEED)
log("\n  S2 (CNA) so voi S0, khoang tin cay 95% bootstrap:")
data = {yy: (d[d["year"] == yy]) for yy in TEST}
pre = {yy: (sc(s, yy, "S0"), sc(s, yy, "S2 (CNA)"), s["y"].values, s["cvss"].values) for yy, s in data.items()}
for vl, f in VOL:
    obs = sum(exp_hits(b2, t, int((c >= CSA_T).sum()) if f is None else f * len(t)) -
              exp_hits(b0, t, int((c >= CSA_T).sum()) if f is None else f * len(t)) for b0, b2, t, c in pre.values())
    bs = []
    for _ in range(NBOOT):
        tt = 0.0
        for b0, b2, t, c in pre.values():
            i = rng.integers(0, len(t), len(t)); K = int((c[i] >= CSA_T).sum()) if f is None else f * len(t)
            tt += exp_hits(b2[i], t[i], K) - exp_hits(b0[i], t[i], K)
        bs.append(tt)
    lo, hi = np.percentile(bs, [2.5, 97.5])
    log(f"    {vl:<14}{obs:+6.1f} ca  [{lo:+6.1f}, {hi:+6.1f}]  {'CO Y NGHIA' if lo > 0 else 'chua ro'}")

top = (d[d["year"].isin(TEST)].groupby("cna")["y"].agg(["sum", "count"]).sort_values("sum", ascending=False).head(8))
log("\n  CNA co nhieu lo hong bi khai thac nhat trong 2024-2025:")
for c, r in top.iterrows(): log(f"    {c or '(trong)':<40}{int(r['sum']):>4} / {int(r['count']):,}")

open(os.path.join(OUT, "kiem_tra_ro_ri.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
