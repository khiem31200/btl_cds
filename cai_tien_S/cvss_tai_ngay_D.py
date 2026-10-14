# -*- coding: utf-8 -*-
"""
cvss_tai_ngay_D.py - Dung diem CVSS co san tai ngay quyet dinh thay vi diem NVD cham sau

VAN DE
  Script cua nhom (src/05_kiem_chung.py) lay CVSS theo thu tu: diem NVD (Primary), neu khong co
  thi diem Secondary, va bo lo hong khong co diem. Nhung:
    - diem NVD thuong duoc cham SAU ngay cong bo (NVD tre phan tich tu 2024);
    - diem Secondary gom ca diem cua CNA (co ngay khi cong bo) va diem cua CISA-ADP
      (CISA bo sung sau, chuong trinh Vulnrichment);
    - bo lo hong khong co diem lam tap phan tich nghieng: nam 2025, 100% lo hong KEV co diem,
      nhom con lai chi 94,2%.

BON CACH CHON DIEM (cung tap, cung nhan, cung EPSS)
  V0  Nhu nhom: NVD > Secondary bat ky; bo lo hong khong co diem.            (doi chieu)
  V1  Uu tien nguon som: CNA > CISA-ADP > NVD; bo lo hong khong co diem.      (cung tap V0)
  V2  Chi CNA, giu ca lo hong khong co diem CNA (gan CVSS = trung vi diem CNA
      cua du lieu huan luyen). Tap rong hon: them lo hong chi co diem NVD/ADP hoac khong co diem.
  V3  Nhu V2 nhung lo hong khong co diem CNA bi bo (tap hep hon).

Danh gia: CVSS, S0 = CVSS x EPSS^0.3, va quy tac CSA (CVSS tu 8,0), thiet ke dot thang nhu
cai_tien_S.py. Chay sau cai_tien_S.py.
"""
import os, sys, json, gzip
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
full = open(os.path.join(HERE, "cai_tien_S.py"), encoding="utf-8").read()
sys.argv = [sys.argv[0]]
exec(compile(full.split("# ============================================================== 2.")[0], "a", "exec"))
exec(compile("def exp_hits" + full.split("def exp_hits")[1].split("\n# ====")[0], "b", "exec"))
lines.clear()
ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"     # CISA-ADP

# ---------------------------------------------------------------- tach diem CVSS theo nguon
cache = os.path.join(DATA, "nvd_cvss_nguon.csv.gz")
if os.path.exists(cache):
    cv = pd.read_csv(cache)
else:
    rows = []
    for y in NVD_YEARS:          # lo hong ma nam cu van co the cong bo trong 2023-2025
        js = json.loads(gzip.decompress(open(os.path.join(DATA, f"nvdcve-2.0-{y}.json.gz"), "rb").read()))
        for it in js["vulnerabilities"]:
            c = it["cve"]; si = c.get("sourceIdentifier"); met = c.get("metrics", {})
            v3 = (met.get("cvssMetricV31") or []) or (met.get("cvssMetricV30") or [])
            r = dict(id=c["id"].upper(), published=c.get("published", "")[:10], status=c.get("vulnStatus"),
                     nvd=None, cna=None, adp=None, khac=None)
            for m in v3:
                s = m["cvssData"]["baseScore"]
                if m.get("type") == "Primary": r["nvd"] = r["nvd"] or s
                elif m.get("source") == si: r["cna"] = r["cna"] or s
                elif m.get("source") == ADP: r["adp"] = r["adp"] or s
                else: r["khac"] = r["khac"] or s
            rows.append(r)
        del js
    cv = pd.DataFrame(rows); cv.to_csv(cache, index=False)
cv = cv[cv["status"] != "Rejected"].copy()
cv["published"] = pd.to_datetime(cv["published"]); cv["year"] = cv["published"].dt.year
cv = cv[cv["year"].isin(YEARS)].copy()
cv["kev_date"] = cv["id"].map(kd)
sec = cv["cna"].fillna(cv["adp"]).fillna(cv["khac"])
cv["V0"] = cv["nvd"].fillna(sec)
cv["V1"] = cv["cna"].fillna(cv["adp"]).fillna(cv["khac"]).fillna(cv["nvd"])

log("=" * 78); log("NGUON DIEM CVSS 3.x, LO HONG CONG BO 2023-2025"); log("=" * 78)
cv["kev"] = cv["kev_date"].notna()
for y in YEARS:
    for g, lab in [(True, "KEV"), (False, "khong KEV")]:
        s = cv[(cv["year"] == y) & (cv["kev"] == g)]
        log(f"  {y} {lab:<10}{len(s):>7,}  co CNA {100*s['cna'].notna().mean():5.1f}%  "
            f"co ADP {100*s['adp'].notna().mean():5.1f}%  co NVD {100*s['nvd'].notna().mean():5.1f}%  "
            f"khong diem nao {100*s['V0'].isna().mean():5.1f}%")
b = cv.dropna(subset=["nvd", "cna"])
log(f"\n  Lo hong co ca diem NVD va CNA: {len(b):,}; khac nhau {100*(b['nvd']!=b['cna']).mean():.1f}%, "
    f"NVD cao hon {100*(b['nvd']>b['cna']).mean():.1f}%, thap hon {100*(b['nvd']<b['cna']).mean():.1f}%")
bk = b[b["kev"]]
log(f"  Rieng lo hong KEV: {len(bk)}; khac nhau {100*(bk['nvd']!=bk['cna']).mean():.1f}%, "
    f"NVD cao hon {100*(bk['nvd']>bk['cna']).mean():.1f}%, thap hon {100*(bk['nvd']<bk['cna']).mean():.1f}%")
log(f"  Vuot nguong 8,0 theo NVD nhung khong theo CNA: {int(((b['nvd']>=8)&(b['cna']<8)).sum()):,}; "
    f"nguoc lai: {int(((b['nvd']<8)&(b['cna']>=8)).sum()):,}")

# ---------------------------------------------------------------- dung dot thang cho moi cach
parts = []
for y in YEARS:
    for m in range(1, 13):
        D = month_end(y, m); Dt = pd.Timestamp(D); emap = load_epss(D)
        c = cv[(cv["year"] == y) & (cv["published"].dt.month == m)].copy()
        c["D"] = Dt; c["epss"] = c["id"].map(emap).fillna(0.0)
        c["loai"] = c["kev_date"].notna() & (c["kev_date"] <= Dt)
        c["y"] = (c["kev_date"].notna() & (c["kev_date"] > Dt) &
                  (c["kev_date"] <= Dt + pd.Timedelta(days=FOLLOW))).astype(int)
        parts.append(c[~c["loai"]])
d = pd.concat(parts, ignore_index=True)

def tap(v, yy):
    s = d[d["year"] == yy].copy()
    if v in ("V0", "V1"):
        s = s.dropna(subset=["V0"]); s["cvss"] = s[v]
    elif v == "V3":
        s = s.dropna(subset=["cna"]); s["cvss"] = s["cna"]
    else:
        tr = d[d["D"] + pd.Timedelta(days=FOLLOW) < pd.Timestamp(f"{yy}-01-01")]
        s["cvss"] = s["cna"].fillna(float(tr["cna"].median()))
    return s

TEN = {"V0": "V0 nhu nhom (NVD truoc)", "V1": "V1 nguon som truoc", "V2": "V2 chi CNA, giu het",
       "V3": "V3 chi CNA, bo thieu"}
VOL = [(f"Va {int(f*100)}%", f) for f in FRACS] + [("Va bang CSA", None)]
log("\n" + "=" * 78); log("KET QUA GOP 2024 VA 2025 (so lo hong bi khai thac bat duoc / tong)"); log("=" * 78)
R = {}
for v in TEN:
    tot = {}; P = N = Wt = Kt = 0
    for yy in TEST:
        s = tap(v, yy); c, e, t = s["cvss"].values, s["epss"].values, s["y"].values
        P += int(t.sum()); N += len(s); W = int((c >= CSA_T).sum()); Wt += W; Kt += int(t[c >= CSA_T].sum())
        for name, sc in [("CVSS", c), ("S0", c * e ** ALPHA), ("EPSS", e)]:
            for vl, f in VOL:
                tot[(name, vl)] = tot.get((name, vl), 0) + exp_hits(sc, t, W if f is None else f * len(s))
    R[v] = (tot, P, N, Wt, Kt)
    log(f"\n{TEN[v]}: {N:,} lo hong, {P} bi khai thac")
    log(f"  Quy tac CSA: phai va {Wt:,} ({100*Wt/N:.1f}%), bat {Kt}/{P} ({100*Kt/P:.1f}%), "
        f"bo sot {100*(P-Kt)/P:.1f}%, hieu suat gap {(Kt/P)/(Wt/N):.2f} lan ngau nhien")
    log(f"  {'Cach xep':<8}" + "".join(f"{vl:>16}" for vl, _ in VOL))
    for name in ["CVSS", "S0", "EPSS"]:
        log(f"  {name:<8}" + "".join(f"{tot[(name, vl)]:>9.1f} ({100*tot[(name, vl)]/P:>3.0f}%)" for vl, _ in VOL))

log("\n" + "=" * 78); log("S0 HON CVSS (so ca) THEO TUNG CACH CHON DIEM, khoang tin cay 95% bootstrap"); log("=" * 78)
rng = np.random.default_rng(SEED)
for v in TEN:
    pre = []
    for yy in TEST:
        s = tap(v, yy); c, e, t = s["cvss"].values, s["epss"].values, s["y"].values; pre.append((c, e, t))
    for vl, f in [("Va 5%", 0.05), ("Va bang CSA", None)]:
        Kf = lambda c, n: int((c >= CSA_T).sum()) if f is None else f * n
        obs = sum(exp_hits(c * e ** ALPHA, t, Kf(c, len(t))) - exp_hits(c, t, Kf(c, len(t))) for c, e, t in pre)
        bs = []
        for _ in range(NBOOT):
            x = 0.0
            for c, e, t in pre:
                i = rng.integers(0, len(t), len(t)); cc, ee, tt = c[i], e[i], t[i]
                x += exp_hits(cc * ee ** ALPHA, tt, Kf(cc, len(tt))) - exp_hits(cc, tt, Kf(cc, len(tt)))
            bs.append(x)
        lo, hi = np.percentile(bs, [2.5, 97.5])
        log(f"  {TEN[v]:<26}{vl:<14}{obs:+6.1f} ca  [{lo:+6.1f}, {hi:+6.1f}]  {'CO Y NGHIA' if lo > 0 else 'chua ro'}")

open(os.path.join(OUT, "cvss_tai_ngay_D.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
