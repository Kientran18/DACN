# Tìm hiểu AI cho bảo mật thiết bị đầu cuối (EDR) và lựa chọn của DACN

> Báo cáo tìm hiểu (Giai đoạn 1), cập nhật 2026-11-25. Các phần mô tả DACN chỉ nói về những gì **đã có trong code**; mọi số liệu ML của DACN hiện **chưa có**, vì chưa có dữ liệu có nhãn. Thiết kế chi tiết nằm ở [ML_SIGNALS.md](../../implementation/ML_SIGNALS.md) và [RISK_SCORING.md](../../implementation/RISK_SCORING.md).

## 1. AI dùng ở đâu trong một EDR

| Bài toán | Đầu vào | Đầu ra | Ví dụ trong ngành / nghiên cứu |
|---|---|---|---|
| Phân loại tệp tĩnh (malware classification) | Byte hoặc đặc trưng PE (header, import, section, chuỗi, entropy) | Xác suất độc hại | EMBER (Anderson & Roth, 2018), EMBER2024; MalConv (Raff và cs., 2018) |
| Phát hiện bất thường hành vi (anomaly detection) | Chuỗi sự kiện tiến trình, file, registry, mạng | Điểm bất thường so với baseline | Forrest và cs. (1996) với chuỗi system call; Isolation Forest (Liu và cs., 2008); mô hình trên provenance graph (UNICORN, Han và cs., 2020) |
| UEBA (User & Entity Behavior Analytics) | Hành vi theo thực thể (người dùng, máy, tiến trình) qua thời gian | Độ lệch so với baseline của chính thực thể hoặc nhóm tương đồng | Tính năng UEBA trong các SIEM thương mại |
| Tổng hợp rủi ro (risk scoring / risk-based alerting) | Nhiều tín hiệu yếu từ rule, IOC, ML | Điểm rủi ro theo thực thể trong cửa sổ thời gian | Risk-Based Alerting của Splunk ES; trường `risk_score` (0–100) của rule Elastic Security |
| Hỗ trợ điều tra | Alert, process tree, timeline | Gom nhóm alert, gợi ý ưu tiên | Tương quan theo provenance (HOLMES, Milajerdi và cs., 2019) |

## 2. Mô hình tĩnh và mô hình hành vi

| Tiêu chí | Tĩnh (static, trên tệp) | Hành vi (behavioral, trên telemetry) |
|---|---|---|
| Thời điểm | Trước hoặc ngay khi tệp chạy | Trong và sau khi chạy |
| Dữ liệu huấn luyện | Bộ dữ liệu công khai lớn có nhãn (EMBER2024) | Phải lấy trên chính môi trường; nhãn hiếm, thường không có |
| Điểm mạnh | Nhanh, không cần tệp chạy; có nền đánh giá chung | Bắt được kỹ thuật không cần tệp mới (LOLBin, PowerShell, lạm dụng công cụ hợp lệ) |
| Điểm yếu | Bị qua mặt bằng packing hay obfuscation; không thấy fileless; số đo trên bộ dữ liệu khác không chuyển sang môi trường thật | Nhiễu cao (cái gì mới cũng "bất thường"); baseline trôi theo thời gian; có thể bị đầu độc baseline |
| Khả năng giải thích | Thấp với GBDT nhiều đặc trưng (2568 chiều) | Cao nếu dùng thống kê hoặc độ hiếm; thấp nếu dùng deep learning |
| Ánh xạ MITRE ATT&CK | Gián tiếp (giai đoạn Execution) | Trực tiếp hơn, ví dụ quan hệ cha–con bất thường thường liên quan T1059 (Command and Scripting Interpreter), cổng lạ liên quan T1571 (Non-Standard Port). Đây là liên hệ để định hướng, **không phải khả năng phát hiện đã kiểm chứng** |

Hai cách tiếp cận bổ trợ nhau. Vì vậy DACN dùng cả hai làm **tín hiệu phụ**, gộp với rule qua điểm rủi ro, thay vì để chúng tự ra quyết định.

## 3. Các họ kỹ thuật phát hiện bất thường

| Họ | Ví dụ | Ưu | Nhược với DACN |
|---|---|---|---|
| Thống kê, tần suất, độ hiếm | Stack counting, "lần đầu thấy", độ hiếm cặp cha–con | Đơn giản, giải thích theo từng giá trị, ít dữ liệu, không thêm phụ thuộc | Chỉ thấy độ hiếm của từng giá trị, không thấy tổ hợp phức tạp |
| Dựa trên cây cách ly | Isolation Forest, Random Cut Forest | Không cần nhãn, nhanh, hợp đặc trưng số | Cần vector số; giải thích kém hơn; với dữ liệu ít thì điểm không ổn định |
| Dựa trên khoảng cách hoặc mật độ | LOF, k-NN, One-Class SVM | Bắt được bất thường cục bộ | Nhạy với cách chuẩn hóa đặc trưng; chi phí tăng theo dữ liệu |
| Học sâu | Autoencoder, LSTM trên chuỗi sự kiện, GNN trên provenance graph | Mô hình hóa được chuỗi và đồ thị | Cần nhiều dữ liệu và tài nguyên (VM 2 GB); khó giải thích; khó kiểm thử trong 12 tuần |

## 4. Những cạm bẫy phải tránh

- **Base-rate fallacy** (Axelsson, 2000). Sự kiện độc hại cực hiếm, nên FPR nhỏ vẫn sinh nhiều cảnh báo giả mỗi ngày. Phải báo cáo số cảnh báo trên ngày hoặc trên máy, không chỉ báo AUC hay accuracy.
- **"Thế giới đóng"** (Sommer & Paxson, 2010). Phát hiện bất thường hợp với việc tìm cái *mới*, không đồng nghĩa với việc tìm cái *độc hại*. Cần ngữ cảnh và giải thích để người phân tích đánh giá.
- **Sai lầm thực nghiệm** (Arp và cs., 2022, "Dos and Don'ts of Machine Learning in Computer Security"): rò rỉ dữ liệu khi chia train/test sai thời gian, nhãn sai, bộ dữ liệu không đại diện, so sánh với baseline yếu. DACN tách cửa sổ train và score theo thời gian (`trained_until`).
- **Concept drift.** Phần mềm cập nhật làm baseline cũ đi. Mô hình phát hiện malware cũng suy giảm theo thời gian (Jordaney và cs., 2017, Transcend).
- **Tấn công vào chính mô hình.** Kẻ tấn công có thể đầu độc baseline nếu máy đã bị xâm nhập trong cửa sổ train, hoặc tạo mẫu né mô hình tĩnh. Vì vậy điểm ML không được kích hoạt hành động tự động.
- **Quyền riêng tư.** Baseline dẫn xuất từ đường dẫn, tên người dùng và command line. DACN chỉ lưu sha256 của giá trị và không commit baseline.

## 5. Lựa chọn của DACN và lý do

| Lựa chọn | Lý do | Trạng thái |
|---|---|---|
| **Rule-first.** Rule, correlation và IOC là nguồn alert chính | Giải thích được, gắn MITRE có căn cứ, kiểm thử được bằng fixture | Đã có (rule `synthetic_only`) |
| **ML tĩnh EMBER2024** (Dot_Net, Win64) làm tín hiệu `ML_STATIC` | Có bộ dữ liệu công khai lớn có nhãn; LightGBM nhẹ; không cần dữ liệu riêng để train | Mô hình nháp; đã nối vào luồng (tắt mặc định); đường `thrember` thật chưa chạy |
| **Độ hiếm hành vi** (`ML_BEHAVIOR`) thay vì Isolation Forest hay học sâu | Giải thích theo từng đặc trưng kèm `source_event_ids`; ít dữ liệu; không thêm phụ thuộc; không pickle | Nháp, tắt mặc định; chưa có số đo |
| **Tổng hợp rủi ro** có trần cho ML | Đề cương yêu cầu tổng hợp nhiều cơ chế; mô hình tham chiếu là Risk-Based Alerting; trần ML (24/100) giữ ML ở vai trò hỗ trợ | Đã có; trọng số chưa hiệu chỉnh |
| **ML không tạo alert, không response** | Chưa có ngưỡng và số đo FPR trên VM; phản ứng phải có con người duyệt (NIST SP 800-61) | Bảo đảm bằng kiểm tra tĩnh trong test |

## 6. Kế hoạch đánh giá (chưa thực hiện, cần dữ liệu từ VM)

1. Thu baseline lành tính trên Windows 10 VM trong nhiều ngày sử dụng bình thường. Không tắt Defender, không dùng mã độc thật.
2. Train ML_BEHAVIOR trên N ngày đầu và chấm các ngày sau (chia theo thời gian).
3. Chạy kịch bản lab an toàn SC01–SC07 (có thể tham khảo các test của Atomic Red Team ở mức vô hại) **do người dùng tự chạy** trên VM. Ghi nhãn theo kịch bản.
4. Đo: số alert và tín hiệu ML mỗi ngày trên tải lành tính; thứ hạng của chủ thể thuộc kịch bản trong danh sách rủi ro (precision@k); độ trễ; CPU và RAM. **Không** dùng accuracy.
5. Hiệu chỉnh `config/risk-scoring.yaml` (tăng `version`), sau đó nhờ Cyber duyệt. Trước khi làm xong các bước này, mọi điểm vẫn là "heuristic chưa hiệu chỉnh".

## 7. Đối chiếu với Wazuh

Wazuh (mã nguồn mở) phát hiện chủ yếu bằng decoder và rule có mức 0–15, kèm rule tổng hợp theo tần suất và khung thời gian (`frequency`/`timeframe`). Cách này gần với rule và correlation của DACN. Wazuh indexer dựa trên OpenSearch, nơi có plugin Anomaly Detection; tích hợp loại này cần hạ tầng cụm, nằm ngoài phạm vi local-first của DACN. DACN học theo cách Wazuh coi mức của rule là thông tin chính, rồi bổ sung điểm rủi ro theo thực thể để gộp nhiều tín hiệu yếu.

## 8. Tài liệu tham khảo

- H. S. Anderson, P. Roth. *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models*. arXiv:1804.04637, 2018. Bộ dữ liệu EMBER2024 và thư viện `thrember` (FutureComputing4AI) — xem [ML_EMBER2024_MODELS.md](../../implementation/ML_EMBER2024_MODELS.md).
- E. Raff và cs. *Malware Detection by Eating a Whole EXE*. AAAI Workshops, 2018.
- S. Forrest, S. A. Hofmeyr, A. Somayaji, T. A. Longstaff. *A Sense of Self for Unix Processes*. IEEE S&P, 1996.
- F. T. Liu, K. M. Ting, Z.-H. Zhou. *Isolation Forest*. IEEE ICDM, 2008.
- V. Chandola, A. Banerjee, V. Kumar. *Anomaly Detection: A Survey*. ACM Computing Surveys, 2009.
- S. Axelsson. *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*. ACM TISSEC, 2000.
- R. Sommer, V. Paxson. *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection*. IEEE S&P, 2010.
- D. Arp và cs. *Dos and Don'ts of Machine Learning in Computer Security*. USENIX Security, 2022.
- R. Jordaney và cs. *Transcend: Detecting Concept Drift in Malware Classification Models*. USENIX Security, 2017.
- S. M. Milajerdi và cs. *HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows*. IEEE S&P, 2019.
- X. Han và cs. *UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats*. NDSS, 2020.
- MITRE ATT&CK (attack.mitre.org); NIST SP 800-61; Wazuh documentation (rules, levels); Atomic Red Team.
