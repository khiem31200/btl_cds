# -*- coding: utf-8 -*-
"""
msrc_kiem_chung.py - Dung co "Exploited" cua Microsoft (MSRC) lam nguon canh bao som hon CISA KEV

NGUON
  API CVRF cong khai cua MSRC: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mmm>
  Moi lo hong co muc "Exploit Status" (Threats, Type 1), vi du
  "Publicly Disclosed:No;Exploited:Yes;...", va lich su sua doi (RevisionHistory) co ngay.

NGAY MICROSOFT BAO DA BI KHAI THAC (hai cach, de khong nhin truoc tuong lai)
  lac quan : ngay sua doi som nhat co nhac toi "exploit" (vi du "Updated the Exploited flag"),
             neu khong co thi lay ngay cong bo dau tien (co da bat ngay tu luc cong bo).
  than trong: ngay sua doi MUON NHAT cua lo hong. Co chac chan da bat tai ngay nay.

HAI PHEP DO
  M1. Do tre: Microsoft bao truoc CISA KEV bao nhieu ngay, voi lo hong Microsoft co trong ca hai.
  M2. Cong thuc: KEV* = 1 neu CISA KEV HOAC Microsoft da bao bi khai thac truoc hoac dung ngay D.
      Tap phan tich, nhan va thiet ke giu nguyen nhu cai_tien_S.py (loai lo hong da vao CISA KEV
      truoc ngay D, nhan la vao CISA KEV trong 180 ngay sau D), nen chi khac o diem:
        S0     = CVSS x EPSS^0.3
        S_MSRC = CVSS x [KEV* + (1 - KEV*) x EPSS^0.3]
  Nhan van la CISA KEV de nguon tin hieu va nguon nhan tach biet.

Chay sau cai_tien_S.py.
"""
import os, sys, json, time, re, urllib.request
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
full = open(os.path.join(HERE, "cai_tien_S.py"), encoding="utf-8").read()
sys.argv = [sys.argv[0]]
exec(compile(full.split("# ============================================================== 3.")[0], "a", "exec"))
exec(compile("def exp_hits" + full.split("def exp_hits")[1].split("\n# ====")[0], "b", "exec"))
lines.clear()

MSRC = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{a}"
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
mdir = os.path.join(DATA, "msrc"); os.makedirs(mdir, exist_ok=True)

def fetch(alias):
    p = os.path.join(mdir, f"{alias}.json")
    if not os.path.exists(p):
        for a in range(4):
            try:
                req = urllib.request.Request(MSRC.format(a=alias), headers={"User-Agent": UA, "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=300) as r: open(p, "wb").write(r.read())
                print(f"  tai MSRC {alias}", flush=True); break
            except Exception as e:
                print(f"  loi {type(e).__name__} {alias}, thu lai", flush=True); time.sleep(5 * (a + 1))
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None

# ---------------------------------------------------------------- doc co Exploited cua MSRC
flags = {}
for y in range(2022, 2027):
    for m in range(1, 13):
        if (y, m) > (2026, 10): break
        doc = fetch(f"{y}-{MON[m-1]}")
        if not doc: continue
        for v in doc.get("Vulnerability", []):
            cve = (v.get("CVE") or "").upper()
            st = [t["Description"]["Value"] for t in v.get("Threats", []) if t.get("Type") == 1]
            if not any("Exploited:Yes" in s for s in st): continue
            rev = [(pd.Timestamp(r["Date"][:10]), r.get("Description", {}).get("Value", ""))
                   for r in v.get("RevisionHistory", []) if r.get("Date")]
            if not rev: continue
            rev.sort()
            ment = [dt for dt, tx in rev if re.search(r"exploit", tx, re.I)]
            opt, cons = (min(ment) if ment else rev[0][0]), rev[-1][0]
            o = flags.get(cve)
            flags[cve] = (min(opt, o[0]) if o else opt, min(cons, o[1]) if o else cons)
fl = pd.DataFrame([(c, a, b) for c, (a, b) in flags.items()], columns=["cve", "opt", "cons"])
log("=" * 78); log("CO EXPLOITED CUA MICROSOFT (tai lieu CVRF 01/2022 den 10/2026)"); log("=" * 78)
log(f"  {len(fl):,} lo hong duoc Microsoft danh dau Exploited:Yes")

# ---------------------------------------------------------------- M1: do tre so voi CISA KEV
log("\n" + "=" * 78); log("M1. MICROSOFT BAO TRUOC CISA KEV BAO NHIEU NGAY"); log("=" * 78)
fl["kev"] = fl["cve"].map(kd)
both = fl[fl["kev"].notna()].copy()
log(f"  Co ca hai nguon: {len(both)}   Chi Microsoft (khong co trong CISA KEV): {int(fl['kev'].isna().sum())}")
ms_kev = kev[kev["vendorProject"].str.lower() == "microsoft"]
ms_kev_recent = ms_kev[ms_kev["added"] >= "2022-06-01"]
log(f"  Muc KEV cua Microsoft them tu 06/2022: {len(ms_kev_recent)}, trong do co co MSRC: "
    f"{int(ms_kev_recent['cve'].isin(fl['cve']).sum())}")
for k in ["opt", "cons"]:
    lead = (both["kev"] - both[k]).dt.days
    log(f"\n  Cach tinh ngay {'lac quan' if k == 'opt' else 'than trong'}: so ngay CISA KEV - ngay Microsoft bao")
    log(f"    trung vi {lead.median():+.0f} ngay; Microsoft bao truoc (>0): {int((lead>0).sum())}, "
        f"cung ngay: {int((lead==0).sum())}, bao sau (<0): {int((lead<0).sum())}")
    for lo, hi, lab in [(1, 1, "1 ngay"), (2, 7, "2-7 ngay"), (8, 30, "8-30 ngay"), (31, 10**5, "tren 30 ngay")]:
        log(f"    truoc {lab:<13}: {int(((lead>=lo)&(lead<=hi)).sum())}")
both_recent = both[both["opt"] >= "2023-01-01"]
lead_r = (both_recent["kev"] - both_recent["opt"]).dt.days
log(f"\n  Rieng co bat tu 2023 (lac quan): {len(both_recent)} lo hong, trung vi {lead_r.median():+.0f} ngay, "
    f"cung ngay {int((lead_r==0).sum())}, truoc {int((lead_r>0).sum())}, sau {int((lead_r<0).sum())}")

# ---------------------------------------------------------------- M2: dua vao cong thuc
log("\n" + "=" * 78); log("M2. KEV* = CISA KEV HOAC MICROSOFT, TREN TAP LO HONG MOI CONG BO (2024-2025)"); log("=" * 78)
fo, fc = dict(zip(fl["cve"], fl["opt"])), dict(zip(fl["cve"], fl["cons"]))
d["ms_opt"] = [int(c in fo and fo[c] <= D) for c, D in zip(d["id"], d["D"])]
d["ms_cons"] = [int(c in fc and fc[c] <= D) for c, D in zip(d["id"], d["D"])]
t = d[d["year"].isin(TEST)]
for k, lab in [("ms_opt", "lac quan"), ("ms_cons", "than trong")]:
    s = t[t[k] == 1]
    log(f"  Microsoft da bao truoc ngay D ({lab}): {len(s)} lo hong, {int(s['y'].sum())} vao CISA KEV trong 180 ngay sau")
log(f"  Tong so lo hong bi khai thac (nhan): {int(t['y'].sum())}")

def sc(s, kind):
    c, e = s["cvss"].values, s["epss"].values
    if kind == "S0": return c * e ** ALPHA
    f = s["ms_opt" if kind == "S_MSRC lac quan" else "ms_cons"].values
    return c * np.where(f == 1, 1.0, e ** ALPHA)

KINDS = ["S0", "S_MSRC lac quan", "S_MSRC than trong"]
VOL = [(f"Va {int(x*100)}%", x) for x in FRACS] + [("Va bang CSA", None)]
K = lambda n, c, f: int((c >= CSA_T).sum()) if f is None else f * n
tot, Pn = {}, 0
for yy in TEST:
    s = d[d["year"] == yy]; tt = s["y"].values; Pn += int(tt.sum()); c = s["cvss"].values
    for kd_ in KINDS:
        for vl, f in VOL: tot[(kd_, vl)] = tot.get((kd_, vl), 0) + exp_hits(sc(s, kd_), tt, K(len(s), c, f))
log(f"\n  Gop 2024 va 2025, {Pn} lo hong bi khai thac")
log(f"  {'Cach xep':<20}" + "".join(f"{vl:>14}" for vl, _ in VOL))
for kd_ in KINDS:
    log(f"  {kd_:<20}" + "".join(f"{tot[(kd_, vl)]:>8.1f} ({100*tot[(kd_, vl)]/Pn:>3.0f}%)" for vl, _ in VOL))

rng = np.random.default_rng(SEED)
pre = {yy: d[d["year"] == yy] for yy in TEST}
pre = {yy: (sc(s, "S0"), sc(s, "S_MSRC than trong"), s["y"].values, s["cvss"].values) for yy, s in pre.items()}
log("\n  S_MSRC than trong so voi S0, khoang tin cay 95% bootstrap:")
for vl, f in VOL:
    obs = sum(exp_hits(b1, tt, K(len(tt), c, f)) - exp_hits(b0, tt, K(len(tt), c, f)) for b0, b1, tt, c in pre.values())
    bs = []
    for _ in range(NBOOT):
        x = 0.0
        for b0, b1, tt, c in pre.values():
            i = rng.integers(0, len(tt), len(tt)); x += exp_hits(b1[i], tt[i], K(len(tt), c[i], f)) - exp_hits(b0[i], tt[i], K(len(tt), c[i], f))
        bs.append(x)
    lo, hi = np.percentile(bs, [2.5, 97.5])
    log(f"    {vl:<14}{obs:+6.1f} ca  [{lo:+6.1f}, {hi:+6.1f}]  {'CO Y NGHIA' if lo > 0 else 'chua ro'}")

# ---------------------------------------------------------------- M3: so ngay duoc canh bao som hon
log("\n" + "=" * 78); log("M3. QUY TAC 'BI KHAI THAC THI VA KHAN CAP': KICH HOAT SOM HON BAO NHIEU NGAY"); log("=" * 78)
ms23 = kev[(kev["vendorProject"].str.lower() == "microsoft") & (kev["added"] >= "2023-01-01")].copy()
ms23["ms"] = ms23["cve"].map(fc)
gain = (ms23["added"] - ms23["ms"]).dt.days.clip(lower=0).fillna(0)
log(f"  Muc KEV cua Microsoft them tu 01/2023: {len(ms23)} (dung ngay than trong)")
log(f"  Kich hoat som hon nho Microsoft: {int((gain>0).sum())} lo hong ({100*(gain>0).mean():.1f}%), "
    f"tong {int(gain.sum())} ngay, trung vi trong nhom duoc loi {gain[gain>0].median():.0f} ngay")
log(f"  Phan chiem trong toan bo KEV them tu 01/2023: {int((gain>0).sum())} / {int((kev['added']>='2023-01-01').sum())}")
only = fl[fl["kev"].isna() & (fl["opt"] >= "2023-01-01")]
log(f"  Microsoft bao bi khai thac tu 2023 nhung CISA chua them: {len(only)} "
    f"(vi du {', '.join(only['cve'].head(5))})")

open(os.path.join(OUT, "msrc_kiem_chung.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
