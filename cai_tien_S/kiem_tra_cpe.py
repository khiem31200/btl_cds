# -*- coding: utf-8 -*-
"""kiem_tra_cpe.py - So S0 va S2 (CPE) chi tren lo hong da co CPE, de bo loi the do thieu CPE.
Chay sau cai_tien_S.py."""
import os, sys
import numpy as np, pandas as pd
HERE = os.path.dirname(os.path.abspath(__file__))
full = open(os.path.join(HERE, "cai_tien_S.py"), encoding="utf-8").read()
sys.argv = [sys.argv[0]]
exec(compile(full.split("# ============================================================== 3.")[0], "a", "exec"))
exec(compile("def exp_hits" + full.split("def exp_hits")[1].split("\n# ====")[0], "b", "exec"))
exec(compile("def priors" + full.split("def priors")[1].split("\nlog(")[0], "c", "exec"))
lines.clear()
rng = np.random.default_rng(SEED)
log("S0 so voi S2 (CPE), CHI TREN LO HONG DA CO CPE (p_ncc hoc lai tren tap co CPE)")
d = d[d["co_cpe"] == 1].copy()
pre = {}
for yy in TEST:
    tr, _, p_ncc = priors(yy)
    s = d[d["year"] == yy]; c, e, t = s["cvss"].values, s["epss"].values, s["y"].values
    f = np.array([p_ncc[b] for b in s["bac"].values])
    pre[yy] = (c * e ** ALPHA, c * np.maximum(e, f) ** ALPHA, t, c)
    log(f"  {yy}: {len(s):,} lo hong co CPE, {int(t.sum())} bi khai thac")
for vl, fr in [(f"Va {int(x*100)}%", x) for x in FRACS] + [("Va bang CSA", None)]:
    K = lambda t, c: int((c >= CSA_T).sum()) if fr is None else fr * len(t)
    a = sum(exp_hits(b0, t, K(t, c)) for b0, b2, t, c in pre.values())
    b = sum(exp_hits(b2, t, K(t, c)) for b0, b2, t, c in pre.values())
    bs = []
    for _ in range(NBOOT):
        tt = 0.0
        for b0, b2, t, c in pre.values():
            i = rng.integers(0, len(t), len(t)); tt += exp_hits(b2[i], t[i], K(t[i], c[i])) - exp_hits(b0[i], t[i], K(t[i], c[i]))
        bs.append(tt)
    lo, hi = np.percentile(bs, [2.5, 97.5])
    log(f"  {vl:<12} S0 {a:6.1f}   S2 {b:6.1f}   chenh {b-a:+5.1f} [{lo:+5.1f}, {hi:+5.1f}]  {'CO Y NGHIA' if lo > 0 else 'chua ro'}")
open(os.path.join(OUT, "kiem_tra_cpe.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
