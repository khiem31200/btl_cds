---
name: kiem-chung-cong-thuc-s
description: Chạy lại và diễn giải bộ kiểm chứng công thức ưu tiên vá S (CVSS, EPSS, KEV) của Nhóm 14, gồm các cải tiến đã thử (PoC, lịch sử nhà cung cấp, cờ MSRC) và so sánh cách chọn điểm CVSS. Dùng khi người dùng muốn chạy lại kiểm chứng, tái lập số liệu, thử một biến thể công thức mới hoặc hỏi ý nghĩa kết quả trong thư mục cai_tien_S/.
---

# Kiểm chứng công thức S

Bộ script trong `cai_tien_S/` kiểm chứng công thức ưu tiên vá của repo nhóm
`vuongtranminh/Cybersecurity-Policy-and-Governance` (bản tại commit f375088):

```
S = AC × CVSS × [KEV + (1 − KEV) × EPSS^0,3] × 10
```

Thiết kế giống `Thu_Kha_Thi/src/05_kiem_chung.py` của nhóm: mỗi tháng công bố là một đợt, ngày quyết định D là cuối tháng, EPSS lấy đúng ngày D, loại lỗ hổng đã vào CISA KEV trước D, nhãn là vào CISA KEV trong 180 ngày sau D, kiểm thử năm 2024 và 2025. Mọi lỗ hổng trong tập mới công bố tối đa 31 ngày.

## Chạy

1. Kiểm tra môi trường: `python3 -c "import pandas, numpy"`. Thiếu thì `pip install pandas numpy`.
2. Kiểm tra mạng, mỗi lệnh phải trả về 200 hoặc 206:
   ```bash
   for u in https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz \
            https://epss.empiricalsecurity.com/epss_scores-2024-01-31.csv.gz \
            https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json \
            https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
            https://api.msrc.microsoft.com/cvrf/v3.0/updates; do
     curl -sS -o /dev/null -w "%{http_code} $u\n" -r 0-100 --max-time 30 "$u"; done
   ```
   Nếu một host bị chặn, dừng lại và báo người dùng tên host. Không thay bằng số liệu giả.
3. Chạy toàn bộ (lần đầu tải khoảng 600 MB vào `cai_tien_S/data/`, mất 15 đến 30 phút; các lần sau dùng bộ nhớ đệm):
   ```bash
   bash cai_tien_S/chay_tat_ca.sh
   ```
   Chạy nền và theo dõi log, vì lâu. Có thể chạy riêng từng script; `cai_tien_S.py` phải chạy trước vì các script khác dùng lại dữ liệu nó tải.

| Script | Câu hỏi | Tệp kết quả |
|---|---|---|
| `cai_tien_S.py` | Thêm PoC (Exploit-DB) và lịch sử nhà cung cấp (CPE) vào S có bắt thêm lỗ hổng mới bị khai thác không | `ket_qua/ket_qua.txt`, `.json` |
| `kiem_tra_ro_ri.py` | CPE có rò rỉ không; chạy lại với nhà cung cấp lấy từ CNA | `ket_qua/kiem_tra_ro_ri.txt` |
| `kiem_tra_cpe.py` | So S0 và S2 chỉ trên lỗ hổng đã có CPE | `ket_qua/kiem_tra_cpe.txt` |
| `msrc_kiem_chung.py` | Cờ "Exploited" của Microsoft báo trước CISA KEV bao lâu, đưa vào nhánh KEV có lợi không | `ket_qua/msrc_kiem_chung.txt` |
| `cvss_tai_ngay_D.py` | Dùng điểm CVSS có sẵn tại ngày D (CNA) thay điểm NVD chấm sau thì kết luận đổi ra sao | `ket_qua/cvss_tai_ngay_D.txt` |

## Kiểm tra tái lập (bắt buộc trước khi diễn giải)

Dòng S0, CVSS, EPSS gộp 2024 và 2025 phải khớp bảng A1 của nhóm (116 lỗ hổng bị khai thác, 84.821 lỗ hổng):

| Cách xếp | Vá 1% | Vá 5% | Vá 10% | Vá 25% | Vá bằng CSA |
|---|---|---|---|---|---|
| CVSS | 7,4 | 21,8 | 39,7 | 66,1 | 66,0 |
| EPSS | 21,0 | 35,6 | 47,0 | 56,7 | 56,8 |
| S0 | 20,0 | 40,0 | 48,7 | 72,0 | 72,0 |

Lệch nhỏ có thể do NVD hoặc KEV đã thay đổi sau ngày 14/10/2026. Lệch lớn (khác số lỗ hổng, khác số ca) nghĩa là dữ liệu tải thiếu hoặc thiết kế bị sửa: tìm nguyên nhân trước khi báo kết quả. Lỗi đã từng gặp: chỉ đọc tệp NVD theo năm của mã CVE sẽ bỏ sót lỗ hổng mã năm cũ nhưng công bố trong 2023–2025 (tổng ra 80.781 thay vì 84.821).

## Kết quả lần chạy 14/10/2026 (để so sánh)

- **PoC:** không đổi gì. Tại ngày D chỉ 3 / 116 lỗ hổng bị khai thác đã có PoC trên Exploit-DB.
- **Lịch sử nhà cung cấp theo CPE:** +15,5 ca ở khối lượng CSA, nhưng phần lớn là rò rỉ: 100% lỗ hổng bị khai thác có CPE, nhóm còn lại 66–81% (CPE do NVD gán sau). Bản không rò rỉ dùng CNA: +1,4 đến +5,0 ca, không có ý nghĩa thống kê.
- **Cờ MSRC:** 85 / 108 lần Microsoft báo cùng ngày với CISA; vào công thức chỉ +1 đến +2 ca, chưa có ý nghĩa.
- **Điểm CVSS tại ngày D:** S hơn CVSS khi vá 5% là +18,2 ca theo cách của nhóm (NVD trước), +12,4 khi ưu tiên nguồn sớm, chỉ +5,3 (chưa có ý nghĩa) khi chỉ dùng điểm CNA. Quy tắc CSA tính bằng điểm CNA chỉ chọn 11,7% lỗ hổng và bỏ sót 57,8% lỗ hổng bị khai thác (so với 25,1% và 43,1% theo điểm NVD).

## Nguyên tắc khi sửa hoặc thêm biến thể

- Mọi tín hiệu phải có tại hoặc trước ngày D. Tham số học được chỉ học trên các đợt có cửa sổ nhãn kết thúc trước 01/01 của năm kiểm thử.
- Không dùng CPE hay điểm NVD làm tín hiệu tại ngày D mà không kiểm tra rò rỉ theo kiểu `kiem_tra_ro_ri.py`: so tỷ lệ có dữ liệu giữa nhóm bị khai thác và nhóm còn lại.
- Giữ nhãn là CISA KEV, tách khỏi nguồn tín hiệu.
- So sánh ở cùng khối lượng vá; báo khoảng tin cậy bootstrap, không chỉ số điểm.
- Kết quả âm cũng phải báo trung thực.
