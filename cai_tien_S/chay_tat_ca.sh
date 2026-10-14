#!/usr/bin/env bash
# Chay toan bo kiem chung theo thu tu. Lan dau tai khoang 600 MB (NVD, EPSS, MSRC) vao data/.
# Yeu cau: python3, pandas, numpy; truy cap nvd.nist.gov, epss.empiricalsecurity.com,
#          raw.githubusercontent.com, gitlab.com, api.msrc.microsoft.com
set -e
cd "$(dirname "$0")"
python3 cai_tien_S.py       | tee chay.log
python3 kiem_tra_ro_ri.py
python3 kiem_tra_cpe.py
python3 msrc_kiem_chung.py
python3 cvss_tai_ngay_D.py  | tee chay_cvss.log
echo "XONG. Ket qua trong ket_qua/"
