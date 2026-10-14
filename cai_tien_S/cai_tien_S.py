# -*- coding: utf-8 -*-
"""
cai_tien_S.py - Kiem chung hai cai tien cho cong thuc S voi lo hong moi cong bo

    S0 (goc)        = CVSS x EPSS^0.3
    S1 (+ PoC)      = CVSS x max(EPSS, p_poc  neu da co PoC truoc ngay D)^0.3
    S2 (+ san pham) = CVSS x max(EPSS, p_ncc(so lan nha cung cap da vao KEV truoc ngay D))^0.3
    S3 (ca hai)     = CVSS x max(EPSS, p_poc, p_ncc)^0.3
    (bo he so x10 va AC vi khong doi thu tu; KEV = 0 voi moi lo hong trong tap phan tich)

THIET KE (giong Thu_Kha_Thi/src/05_kiem_chung.py de so sanh duoc)
  - Lo hong cong bo nam 2023, 2024, 2025, co CVSS 3.x. Moi thang cong bo la mot dot,
    ngay quyet dinh D = cuoi thang, EPSS lay dung ngay D (khong co diem thi coi bang 0).
  - Loai lo hong da vao KEV truoc hoac dung ngay D. Nhan y = vao KEV trong 180 ngay sau D.
  - Vi D la cuoi thang cong bo, moi lo hong deu moi cong bo toi da 31 ngay:
    day dung la nhom ma cong thuc goc khong canh bao truoc duoc.
  - Danh muc KEV cat ve 08/10/2026 nhu cac notebook cua nhom.

CHONG RO RI DU LIEU TUONG LAI
  - PoC chi tinh neu Exploit-DB cong bo truoc hoac dung ngay D.
  - So lan nha cung cap da vao KEV chi dem cac muc KEV co ngay them truoc hoac dung ngay D.
  - p_poc va p_ncc hoc tren cac dot huan luyen co cua so nhan da KET THUC truoc ngay 01/01
    cua nam kiem thu (D + 180 ngay < 01/01). Kiem thu 2024 hoc tren dot 01-06/2023,
    kiem thu 2025 hoc tren dot 01/2023 den 06/2024.

Chay:  python3 cai_tien_S.py         (lan dau tai khoang 300 MB NVD va 37 tep EPSS)
Can:   nvd.nist.gov, epss.empiricalsecurity.com, raw.githubusercontent.com, gitlab.com
"""
import os, io, re, sys, json, gzip, time, urllib.request
from datetime import date, timedelta
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data"); OUT = os.path.join(HERE, "ket_qua")
os.makedirs(DATA, exist_ok=True); os.makedirs(OUT, exist_ok=True)
UA = "Nhom14-AcademicResearch/1.0 (course project; metadata only)"
NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz"
EPSS_DAY = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

YEARS, TEST, FOLLOW = [2023, 2024, 2025], [2024, 2025], 180
NVD_YEARS = range(2002, 2026)          # can ca lo hong cu de biet nha cung cap cua moi muc KEV
KEV_CUT = pd.Timestamp("2026-10-08")
ALPHA, CSA_T = 0.3, 8.0
FRACS = [0.01, 0.05, 0.10, 0.25]
BUCKETS = [(0, 0), (1, 4), (5, 19), (20, 99), (100, 10**9)]
SEED, NBOOT = 42, 1000
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

def get(url, path, retries=4):
    if os.path.exists(path) and os.path.getsize(path) > 0: return
    for a in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=300) as r: data = r.read()
            open(path, "wb").write(data); print(f"  tai {os.path.basename(path)}", flush=True); return
        except Exception as e:
            print(f"  loi {type(e).__name__} {url}, thu lai {a + 1}", flush=True); time.sleep(4 * (a + 1))
    raise RuntimeError("khong tai duoc " + url)

def month_end(y, m):
    return date(y + (m == 12), m % 12 + 1, 1) - timedelta(days=1)

# ============================================================== 1. thu thap va doc du lieu
def vendors_of(cve):
    out = set()
    def walk(nodes):
        for n in nodes or []:
            for m in n.get("cpeMatch", []) or []:
                if m.get("vulnerable"):
                    p = m.get("criteria", "").split(":")
                    if len(p) > 4: out.add(p[3].lower())
            walk(n.get("nodes"))
    for cfg in cve.get("configurations", []) or []:
        walk(cfg.get("nodes"))
    return sorted(out)

def pick(lst, kind):
    for m in lst or []:
        if m.get("type") == kind: return m["cvssData"]["baseScore"]
    return None

def load_nvd():
    cache = os.path.join(DATA, "nvd_gon.csv.gz")
    if os.path.exists(cache):
        return pd.read_csv(cache, keep_default_na=False, na_values=[""])
    rows = []
    for y in NVD_YEARS:
        p = os.path.join(DATA, f"nvdcve-2.0-{y}.json.gz"); get(NVD_FEED.format(y=y), p)
        js = json.loads(gzip.decompress(open(p, "rb").read()))
        for it in js.get("vulnerabilities", []):
            c = it["cve"]; met = c.get("metrics", {})
            v3 = (met.get("cvssMetricV31") or []) or (met.get("cvssMetricV30") or [])
            rows.append(dict(id=c["id"].upper(), published=(c.get("published") or "")[:10],
                             status=c.get("vulnStatus"), cvss3_nvd=pick(v3, "Primary"),
                             cvss3_cna=pick(v3, "Secondary"), vendors=";".join(vendors_of(c))))
        del js; print(f"  doc NVD {y}: tong {len(rows):,}", flush=True)
    df = pd.DataFrame(rows); df.to_csv(cache, index=False); return df

_ec = {}
def load_epss(D):
    for b in range(5):
        dd = D - timedelta(days=b); p = os.path.join(DATA, f"epss_{dd.isoformat()}.csv.gz")
        if not os.path.exists(p):
            try: get(EPSS_DAY.format(d=dd.isoformat()), p, retries=2)
            except RuntimeError: continue
        if p not in _ec:
            raw = gzip.decompress(open(p, "rb").read()).decode()
            e = pd.read_csv(io.StringIO(raw), comment="#")
            _ec[p] = dict(zip(e["cve"].str.upper(), e["epss"].astype(float)))
        return _ec[p]
    raise FileNotFoundError(f"thieu EPSS ngay {D}")

log("=" * 78); log("THU THAP DU LIEU"); log("=" * 78)
get(KEV_URL, os.path.join(DATA, "kev.json")); get(EDB_URL, os.path.join(DATA, "files_exploits.csv"))
nvd_all = load_nvd()
nvd_all["vendors"] = nvd_all["vendors"].fillna("")
vend = dict(zip(nvd_all["id"], nvd_all["vendors"]))

kj = json.load(open(os.path.join(DATA, "kev.json")))
kev = pd.DataFrame(kj["vulnerabilities"])
kev["cve"] = kev["cveID"].str.upper(); kev["added"] = pd.to_datetime(kev["dateAdded"])
kev = kev[kev["added"] <= KEV_CUT].copy()
# nha cung cap cua moi muc KEV: lay theo CPE cua NVD de khop voi lo hong moi; khong co CPE thi dung ten CISA
kev["vlist"] = [vend.get(c) or re.sub(r"[^a-z0-9]+", "_", v.lower()).strip("_")
                for c, v in zip(kev["cve"], kev["vendorProject"])]
kd = dict(zip(kev["cve"], kev["added"]))
log(f"KEV phien ban {kj['catalogVersion']}, cat ve {KEV_CUT.date()}: {len(kev):,} muc")

edb = pd.read_csv(os.path.join(DATA, "files_exploits.csv"), usecols=["codes", "date_published"])
edb = edb.dropna(subset=["codes"]); edb["date_published"] = pd.to_datetime(edb["date_published"], errors="coerce")
poc_first = {}
for codes, dp in zip(edb["codes"], edb["date_published"]):
    if pd.isna(dp): continue
    for cv in re.findall(r"CVE-\d{4}-\d{4,}", codes.upper()):
        if cv not in poc_first or dp < poc_first[cv]: poc_first[cv] = dp
log(f"Exploit-DB: {len(edb):,} ma khai thac co ma tham chieu, {len(poc_first):,} CVE co PoC")

# lich su KEV theo nha cung cap: danh sach ngay them (da sap xep) de dem nhanh tai ngay D
kev_by_vendor = {}
for vl, ad in zip(kev["vlist"], kev["added"]):
    for v in filter(None, vl.split(";")): kev_by_vendor.setdefault(v, []).append(ad.value)
kev_by_vendor = {v: np.sort(np.array(a)) for v, a in kev_by_vendor.items()}
def vendor_count(vl, Dt):
    best = 0
    for v in filter(None, vl.split(";")):
        a = kev_by_vendor.get(v)
        if a is not None: best = max(best, int(np.searchsorted(a, Dt.value, side="right")))
    return best

# ============================================================== 2. dung cac dot theo thang
nvd = nvd_all[nvd_all["status"] != "Rejected"].copy()
nvd["published"] = pd.to_datetime(nvd["published"]); nvd["year"] = nvd["published"].dt.year
nvd = nvd[nvd["year"].isin(YEARS)]
nvd["cvss"] = pd.to_numeric(nvd["cvss3_nvd"]).fillna(pd.to_numeric(nvd["cvss3_cna"]))
nvd = nvd.dropna(subset=["cvss"]).copy()
nvd["kev_date"] = nvd["id"].map(kd)

parts = []
for y in YEARS:
    for m in range(1, 13):
        D = month_end(y, m); Dt = pd.Timestamp(D); emap = load_epss(D)
        c = nvd[(nvd["year"] == y) & (nvd["published"].dt.month == m)].copy()
        c["D"] = Dt
        c["epss"] = c["id"].map(emap).fillna(0.0)
        c["loai"] = c["kev_date"].notna() & (c["kev_date"] <= Dt)
        c["y"] = (c["kev_date"].notna() & (c["kev_date"] > Dt) &
                  (c["kev_date"] <= Dt + pd.Timedelta(days=FOLLOW))).astype(int)
        pf = c["id"].map(poc_first)
        c["poc"] = (pf.notna() & (pf <= Dt)).astype(int)
        c["nkev"] = [vendor_count(vl, Dt) for vl in c["vendors"]]
        c["co_cpe"] = (c["vendors"] != "").astype(int)
        parts.append(c[~c["loai"]])
d = pd.concat(parts, ignore_index=True)
d["bac"] = 0
for i, (lo, hi) in enumerate(BUCKETS): d.loc[(d["nkev"] >= lo) & (d["nkev"] <= hi), "bac"] = i

log("\n" + "=" * 78); log("DU LIEU PHAN TICH (moi lo hong moi cong bo toi da 31 ngay tai ngay D)"); log("=" * 78)
log(f"{'Nam':<6}{'Lo hong':>10}{'Bi khai thac':>14}{'Co PoC tai D':>14}{'Co CPE':>10}{'NCC tung vao KEV':>18}")
for y in YEARS:
    s = d[d["year"] == y]
    log(f"{y:<6}{len(s):>10,}{int(s['y'].sum()):>14}{int(s['poc'].sum()):>14,}"
        f"{100*s['co_cpe'].mean():>9.1f}%{100*(s['nkev']>0).mean():>17.1f}%")

# ============================================================== 3. hoc p_poc va p_ncc (walk-forward)
def priors(ty):
    tr = d[d["D"] + pd.Timedelta(days=FOLLOW) < pd.Timestamp(date(ty, 1, 1))]
    p_poc = float(tr.loc[tr["poc"] == 1, "y"].mean()) if (tr["poc"] == 1).any() else 0.0
    p_b = tr.groupby("bac")["y"].agg(["sum", "count"])
    p_ncc = {b: float(p_b.loc[b, "sum"] / p_b.loc[b, "count"]) if b in p_b.index else 0.0
             for b in range(len(BUCKETS))}
    return tr, p_poc, p_ncc

log("\n" + "=" * 78); log("THAM SO HOC TREN DU LIEU CU"); log("=" * 78)
P = {}
for ty in TEST:
    tr, p_poc, p_ncc = priors(ty); P[ty] = (p_poc, p_ncc)
    log(f"Kiem thu {ty}: hoc tren {tr['D'].min().date()} den {tr['D'].max().date()} "
        f"({len(tr):,} lo hong, {int(tr['y'].sum())} bi khai thac)")
    log(f"  p_poc = {p_poc:.4f}  (co PoC: {int((tr['poc']==1).sum()):,} lo hong, "
        f"{int(tr.loc[tr['poc']==1,'y'].sum())} bi khai thac)")
    for b, (lo, hi) in enumerate(BUCKETS):
        n = int((tr["bac"] == b).sum()); k = int(tr.loc[tr["bac"] == b, "y"].sum())
        lab = f"{lo}" if lo == hi else (f"{lo}+" if hi > 10**8 else f"{lo}-{hi}")
        log(f"  p_ncc[nha cung cap da co {lab:>6} muc KEV] = {p_ncc[b]:.5f}  ({k}/{n:,})")

def scores(s, ty):
    p_poc, p_ncc = P[ty]
    c, e = s["cvss"].values, s["epss"].values
    fp = np.where(s["poc"].values == 1, p_poc, 0.0)
    fn = np.array([p_ncc[b] for b in s["bac"].values])
    return {"CVSS": c, "EPSS": e,
            "S0 goc": c * e ** ALPHA,
            "S1 + PoC": c * np.maximum(e, fp) ** ALPHA,
            "S2 + san pham": c * np.maximum(e, fn) ** ALPHA,
            "S3 + PoC + san pham": c * np.maximum.reduce([e, fp, fn]) ** ALPHA}

def exp_hits(sc, y, K):
    K = int(K)
    if K <= 0: return 0.0
    if K >= len(sc): return float(y.sum())
    t = np.partition(sc, len(sc) - K)[len(sc) - K]
    above, at = sc > t, sc == t
    return float(y[above].sum() + (K - above.sum()) * y[at].sum() / at.sum())

# ============================================================== 4. ket qua tren nam kiem thu
log("\n" + "=" * 78); log("KET QUA: SO LO HONG BI KHAI THAC BAT DUOC KHI VA CUNG SO LUONG"); log("=" * 78)
VOLS = [(f"Va {int(f*100)}%", f) for f in FRACS] + [("Va bang quy tac CSA", None)]
res = {}
for ty in TEST + ["Gop"]:
    yrs = TEST if ty == "Gop" else [ty]
    tot = {}; Pn = 0
    for yy in yrs:
        s = d[d["year"] == yy]; t = s["y"].values; Pn += int(t.sum()); M = scores(s, yy)
        W = int((s["cvss"].values >= CSA_T).sum())
        for name, sc in M.items():
            for vl, f in VOLS:
                K = W if f is None else f * len(s)
                tot[(name, vl)] = tot.get((name, vl), 0.0) + exp_hits(sc, t, K)
    res[ty] = (tot, Pn)
    log(f"\n{('Gop 2024 va 2025' if ty == 'Gop' else 'Nam ' + str(ty))}: {Pn} lo hong bi khai thac")
    log(f"  {'Cach xep':<22}" + "".join(f"{vl:>21}" for vl, _ in VOLS))
    for name in scores(d[d["year"] == TEST[0]], TEST[0]).keys():
        log(f"  {name:<22}" + "".join(f"{tot[(name, vl)]:>12.1f} ({100*tot[(name, vl)]/Pn:>4.1f}%)" for vl, _ in VOLS))

# ============================================================== 5. khoang tin cay bootstrap
log("\n" + "=" * 78); log("CHENH LECH SO VOI S0, GOP 2024 VA 2025, KHOANG TIN CAY 95% BOOTSTRAP"); log("=" * 78)
rng = np.random.default_rng(SEED)
data = {}
for yy in TEST:
    s = d[d["year"] == yy]; data[yy] = (scores(s, yy), s["y"].values, s["cvss"].values)
CI = {}
for name in ["S1 + PoC", "S2 + san pham", "S3 + PoC + san pham"]:
    for vl, f in VOLS:
        obs = 0.0; bs = np.zeros(NBOOT)
        for yy, (M, t, c) in data.items():
            K = int((c >= CSA_T).sum()) if f is None else f * len(t)
            obs += exp_hits(M[name], t, K) - exp_hits(M["S0 goc"], t, K)
        for b in range(NBOOT):
            tot = 0.0
            for yy, (M, t, c) in data.items():
                i = rng.integers(0, len(t), len(t)); tt = t[i]
                K = int((c[i] >= CSA_T).sum()) if f is None else f * len(t)
                tot += exp_hits(M[name][i], tt, K) - exp_hits(M["S0 goc"][i], tt, K)
            bs[b] = tot
        lo, hi = np.percentile(bs, [2.5, 97.5]); CI[(name, vl)] = (obs, lo, hi)
        log(f"  {name:<22}{vl:<22}{obs:+7.1f} ca   [{lo:+6.1f}, {hi:+6.1f}]   "
            f"{'CO Y NGHIA' if lo > 0 else ('KEM HON CO Y NGHIA' if hi < 0 else 'chua ro')}")

# ============================================================== 6. ai duoc bat them
log("\n" + "=" * 78); log("NHOM LO HONG BI KHAI THAC: TIN HIEU CO SAN TAI NGAY D"); log("=" * 78)
t = d[d["year"].isin(TEST)]; pos = t[t["y"] == 1]
log(f"  {len(pos)} lo hong bi khai thac trong 2024-2025 (sau ngay D)")
log(f"  co PoC truoc ngay D        : {int(pos['poc'].sum())} ({100*pos['poc'].mean():.1f}%)   "
    f"ca tap: {100*t['poc'].mean():.2f}%")
log(f"  NCC da tung vao KEV        : {int((pos['nkev']>0).sum())} ({100*(pos['nkev']>0).mean():.1f}%)   "
    f"ca tap: {100*(t['nkev']>0).mean():.1f}%")
log(f"  NCC co tu 20 muc KEV       : {int((pos['nkev']>=20).sum())} ({100*(pos['nkev']>=20).mean():.1f}%)   "
    f"ca tap: {100*(t['nkev']>=20).mean():.1f}%")
log(f"  trung vi EPSS tai D        : {pos['epss'].median():.4f}   ca tap: {t['epss'].median():.4f}")

json.dump({"ket_qua": {str(k): {f"{a}|{b}": v for (a, b), v in tot.items()} | {"P": Pn}
                       for k, (tot, Pn) in res.items()},
           "ci": {f"{a}|{b}": list(v) for (a, b), v in CI.items()},
           "tham_so": {str(k): {"p_poc": v[0], "p_ncc": v[1]} for k, v in P.items()}},
          open(os.path.join(OUT, "ket_qua.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(os.path.join(OUT, "ket_qua.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
log("\nDa luu ket_qua/ket_qua.txt va ket_qua/ket_qua.json")
