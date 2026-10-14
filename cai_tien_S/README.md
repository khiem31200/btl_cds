# Kiểm chứng hai cải tiến cho công thức S với lỗ hổng mới công bố

Thiết kế giống `Thu_Kha_Thi/src/05_kiem_chung.py` của repo nhóm (bản tại commit f375088): mỗi tháng công bố là một đợt, ngày quyết định D là cuối tháng, EPSS lấy đúng ngày D, nhãn là vào KEV trong 180 ngày sau D, kiểm thử 2024 và 2025. Mọi lỗ hổng trong tập đều mới công bố tối đa 31 ngày.

| Tệp | Nội dung |
|---|---|
| `cai_tien_S.py` | Tải dữ liệu, so S0 (gốc), S1 (+PoC), S2 (+lịch sử nhà cung cấp theo CPE), S3 (cả hai) |
| `kiem_tra_ro_ri.py` | Kiểm tra rò rỉ của CPE; chạy lại S2 với nhà cung cấp lấy từ CNA (`sourceIdentifier`) |
| `kiem_tra_cpe.py` | So S0 và S2 chỉ trên lỗ hổng đã có CPE |
| `msrc_kiem_chung.py` | Dùng cờ "Exploited" của Microsoft (API CVRF của MSRC) làm nguồn cảnh báo sớm hơn CISA KEV |
| `ket_qua/` | Kết quả chạy |

Chạy: `python3 cai_tien_S.py`, sau đó `python3 kiem_tra_ro_ri.py` và `python3 kiem_tra_cpe.py`, `python3 msrc_kiem_chung.py`. Cần truy cập `nvd.nist.gov`, `epss.empiricalsecurity.com`, `raw.githubusercontent.com`, `gitlab.com`, `api.msrc.microsoft.com`.

Kiểm tra đối chiếu: S0, CVSS và EPSS ra đúng số trong bảng A1 của nhóm (gộp 2024 và 2025, 116 ca: S0 bắt 20 / 40 / 48,7 / 72 / 72 ca khi vá 1% / 5% / 10% / 25% / bằng khối lượng CSA).
