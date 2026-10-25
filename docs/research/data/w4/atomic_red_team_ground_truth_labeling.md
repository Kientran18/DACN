# Nghiên Cứu: Phân Tích Metadata Kịch Bản Atomic Red Team & Thuật Toán Gắn Nhãn Ground-Truth Theo Phả Hệ Tiến Trình

**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer)  
**Thời điểm khảo sát:** Ngày 21/10/2026 (Tuần 4)  
**Phiên bản & Nguồn tài liệu chính thức:**  
* Red Canary Atomic Red Team Spec (`https://atomicredteam.io/`)  
* Invoke-AtomicRedTeam v2.2+ Wiki (`https://github.com/redcanaryco/invoke-atomicredteam/wiki`)  
* ATTIRE (ATT&CK Test Execution Log Schema v1.1)  
**Mục tiêu:** Đánh giá cấu trúc metadata kịch bản của Atomic Red Team và thiết kế cơ chế đối chiếu (correlation), tự động gắn nhãn (automated ground-truth labeling) cho dữ liệu Sysmon tại tầng Silver/Gold phục vụ kiểm thử Detection và huấn luyện AI.

---

## 1. Đặt Vấn Đề Kỹ Thuật & Phân Định Vai Trò Kiến Trúc

### 1.1. Phân định vai trò: Không xem Atomic Red Team là Production Collector
Trong hệ sinh thái công cụ được khảo sát ở Tuần 4, cần khẳng định rõ nguyên tắc kiến trúc:
* **Sysmon, osquery, Velociraptor, Wazuh** thuộc nhóm công cụ giám sát, thu thập hoặc phân tích sự kiện (Defensive Telemetry Collectors / Analyzers).
* **Atomic Red Team** thuộc nhóm công cụ **Mô phỏng đối kháng (Adversary Emulation Framework)**. Công cụ này **tuyệt đối không được triển khai làm nguồn thu thập dữ liệu (collector) trên máy trạm production**. Vai trò duy nhất của Atomic Red Team dưới góc nhìn Data Engineering là **kích hoạt các hành vi tấn công có kiểm soát trong môi trường Lab/PoC** và cung cấp **Siêu dữ liệu Nhãn gốc (Ground-Truth Metadata)** để đánh giá độ chính xác của hệ thống EDR.

### 1.2. Bài toán nhiễu khi gắn nhãn theo cửa sổ thời gian thuần túy (Naive Time-Window Labeling)
Khi thực thi một bài kiểm thử Atomic Red Team từ thời điểm $t_{\text{start}}$ đến $t_{\text{end}}$ trên máy trạm Windows, Sysmon sẽ thu thập hàng trăm sự kiện hệ thống. Nếu pipeline dữ liệu chỉ gán nhãn độc hại (`is_malicious = 1`) dựa trên điều kiện thời gian đơn thuần:

$$t_{\text{start}} \le t_{\text{event}} \le t_{\text{end}}$$

thì toàn bộ các hoạt động nền hợp lệ của hệ điều hành diễn ra cùng lúc (như `svchost.exe`, `SearchIndexer.exe`, trình duyệt Chrome cập nhật, hay tác vụ đọc log của chính Python Collector) đều bị **gán nhãn nhầm là tấn công (Label Contamination / False Positive Labels)**. Việc đưa dữ liệu nhiễu này vào huấn luyện mô hình AI ở tầng Gold sẽ làm suy giảm nghiêm trọng chất lượng phân lớp.

Do đó, bài toán đặt ra cho Data Engineering là: **Làm thế nào kết hợp metadata của Atomic Red Team với khóa phả hệ `process_guid` (`ADR 0002`) của Sysmon để chỉ gắn nhãn chính xác các sự kiện thực sự thuộc về chuỗi tấn công?**

---

## 2. Khảo Sát Mô Hình Metadata Của Atomic Red Team

Quá trình khảo sát tài liệu chính thức (`[NHẬN ĐỊNH TỪ TÀI LIỆU]`) kết hợp đối chiếu kịch bản PoC thực tế (`[ĐÃ THỬ NGHIỆM POC]`) cho thấy metadata của Atomic Red Team được chia thành 2 lớp bổ trợ lẫn nhau:

### 2.1. Lớp Metadata Kịch Bản Tĩnh (Static Scenario Definition – YAML)
Mỗi kỹ thuật MITRE ATT&CK trong kho lưu trữ Atomic Red Team được định nghĩa trong một tệp `Txxxx.yaml` (hoặc `Txxxx.xxx.yaml`). Các trường dữ liệu quan trọng đối với Data Pipeline bao gồm:

| Trường Metadata (YAML) | Kiểu Dữ Liệu | Ý Nghĩa Truy Vết & Gắn Nhãn Dữ Liệu |
| :--- | :--- | :--- |
| `attack_technique` | `STRING` | Mã kỹ thuật MITRE ATT&CK chuẩn (ví dụ: `T1059.001`, `T1547.001`, `T1055`). Dùng làm nhãn lớp mục tiêu (`mitre_technique_id`). |
| `display_name` | `STRING` | Tên chính thức của kỹ thuật tấn công theo MITRE. |
| `atomic_tests[].auto_generated_guid` | `UUID (STRING)` | **Khóa định danh bất biến toàn cục** của từng kịch bản con (Test Case). Giúp phân biệt các biến thể thực thi khác nhau trong cùng một kỹ thuật MITRE. |
| `atomic_tests[].name` | `STRING` | Tên mô tả cụ thể của bài kiểm thử (ví dụ: *Mimikatz PowerShell Execution*). |
| `atomic_tests[].supported_platforms` | `LIST[STRING]` | Hệ điều hành hỗ trợ (trong phạm vi đồ án chỉ lọc giá trị `windows`). |
| `atomic_tests[].input_arguments` | `MAP` | Danh sách tham số mặc định (đường dẫn tệp drop, khóa registry đích, IP/URL). Dùng để đối khớp với `file_path`, `target_object`, `dest_ip` trong bảng Silver. |
| `atomic_tests[].executor.name` | `STRING` | Trình thông dịch thực thi bài test (`powershell`, `command_prompt`, `manual`). Cho biết tiến trình gốc (`ParentImage` / `Image`) khởi phát chuỗi sự kiện. |
| `atomic_tests[].executor.command` | `STRING` | Mẫu câu lệnh tấn công. |
| `atomic_tests[].executor.cleanup_command` | `STRING` | Câu lệnh dọn dẹp dấu vết sau khi test xong (cần được loại trừ khỏi tập huấn luyện hành vi tấn công để tránh nhiễu). |

### 2.2. Lớp Metadata Nhật Ký Thực Thi Động (Dynamic Execution Log – JSONL / ATTIRE)
Khi kích hoạt kịch bản thông qua framework `Invoke-AtomicRedTeam` (PowerShell module), tham số `-ExecutionLogPath` kết hợp `Attire-ExecutionLogger` sẽ sinh ra bản ghi nhật ký cho **từng lần chạy thử nghiệm (Test Run)**:

```json
{
  "execution_id": "exec-20261021-001",
  "atomic_guid": "43f71ec6-1111-4444-8888-000000000001",
  "attack_technique": "T1059.001",
  "test_name": "PowerShell Drop-Execute-Connect PoC",
  "hostname": "DESKTOP-IDEMGQU",
  "username": "DESKTOP-IDEMGQU\\Trankien",
  "executor": "powershell",
  "runner_pid": 5120,
  "start_time_utc": "2026-10-18T09:11:54.0000000Z",
  "end_time_utc": "2026-10-18T09:12:02.0000000Z",
  "phase": "EXECUTION",
  "command_executed": "powershell.exe -ExecutionPolicy Bypass -File run_poc.ps1",
  "exit_code": 0
}
```

**Giá trị cốt lõi của Execution Log:** Cung cấp bộ ba khóa neo (Anchor Keys) gồm **`hostname`**, **`runner_pid`** (PID của tiến trình PowerShell/CMD thực thi bài test) và khoảng thời gian **`[start_time_utc, end_time_utc]`** chuẩn UTC.

---

## 3. Thuật Toán Đối Chiếu & Gắn Nhãn 2 Pha Qua Phả Hệ `ProcessGuid`

Để giải quyết triệt để bài toán nhiễu nền (Background Noise) và rủi ro tái sử dụng PID (PID Reuse – `ADR 0002`), nhóm Data thiết kế thuật toán đối chiếu 2 pha (Two-Stage Lineage Correlation) chạy trực tiếp trên DuckDB Silver Layer:

```text
+---------------------------------------------------------------------------------------------------+
|               THUẬT TOÁN ĐỐI CHIẾU & LAN TRUYỀN NHÃN GROUND-TRUTH (2-STAGE LINEAGE)               |
|                                                                                                   |
|  [PHA 1: XÁC ĐỊNH HẠT GIỐNG (ANCHOR DISCOVERY)]                                                   |
|   Atomic Execution Log: (hostname, runner_pid, start_time_utc, end_time_utc)                      |
|           |                                                                                       |
|           +---> Khớp với `silver_process_events` (ID 1) trong cửa sổ [start - 1s, end + 2s]       |
|           +---> Tìm được khóa bất biến: `seed_process_guid` (Ví dụ: 43f71ec6-8d5b-6ad4-2501-...)  |
|                                                                                                   |
|  [PHA 2: LAN TRUYỀN ĐỆ QUY TRÊN ĐỒ THỊ TIẾN TRÌNH (RECURSIVE DAG PROPAGATION)]                    |
|   Từ `seed_process_guid` ---> Truy vấn đệ quy `parent_guid = process_guid`                        |
|           |                                                                                       |
|           +---> Tập hợp toàn bộ cây con cháu: G_test = {guid_0, guid_1, guid_2, ...}              |
|           |                                                                                       |
|           +---> Gán nhãn (mitre_technique_id, atomic_guid) cho mọi bản ghi trong 4 bảng:          |
|                 * silver_process_events   (WHERE process_guid IN G_test)                          |
|                 * silver_file_events      (WHERE process_guid IN G_test)                          |
|                 * silver_registry_events  (WHERE process_guid IN G_test)                          |
|                 * silver_network_events   (WHERE process_guid IN G_test)                          |
+---------------------------------------------------------------------------------------------------+
```

### 3.1. Mô hình toán học của phép đối chiếu
Gọi $R$ là một lần chạy thử nghiệm Atomic Red Team với bộ thông số:

$$R = \langle h, p_{\text{runner}}, t_{\text{start}}, t_{\text{end}}, \tau_{\text{mitre}}, g_{\text{atomic}} \rangle$$

Trong đó $h$ là `hostname`, $p_{\text{runner}}$ là `runner_pid`, $\tau_{\text{mitre}}$ là mã kỹ thuật MITRE và $g_{\text{atomic}}$ là `atomic_guid`.

* **Pha 1 (Tìm tập tiến trình gốc $G_0$):** Với độ dung sai đồng hồ $\Delta t = 2\text{ s}$, tập hạt giống $G_0$ các mã định danh `process_guid` được xác định từ bảng `silver_process_events` ($E_{\text{proc}}$):

$$G_0(R) = \left\{ e.\text{process\_guid} \;\middle|\; e \in E_{\text{proc}} \land e.\text{hostname} = h \land (t_{\text{start}} - \Delta t \le e.\text{timestamp} \le t_{\text{end}} + \Delta t) \land (e.\text{pid} = p_{\text{runner}} \lor e.\text{ppid} = p_{\text{runner}}) \right\}$$

* **Pha 2 (Bao đóng bắc cầu trên cây phả hệ $G^*(R)$):** Tập toàn bộ các tiến trình thuộc chuỗi tấn công $G^*(R)$ là bao đóng đệ quy theo quan hệ cha–con (`parent_guid`):

$$G_{k}(R) = G_{k-1}(R) \cup \left\{ e.\text{process\_guid} \;\middle|\; e \in E_{\text{proc}} \land e.\text{parent\_guid} \in G_{k-1}(R) \land e.\text{timestamp} \ge t_{\text{start}} - \Delta t \right\}$$

$$G^*(R) = \bigcup_{k=0}^{D_{\max}} G_k(R) \quad (\text{với độ sâu tối đa } D_{\max} = 10)$$

Mọi sự kiện $x \in E_{\text{proc}} \cup E_{\text{file}} \cup E_{\text{reg}} \cup E_{\text{net}}$ có $x.\text{process\_guid} \in G^*(R)$ và nằm trong pha `EXECUTION` đều được gắn nhãn $\text{label}(x) = (\tau_{\text{mitre}}, g_{\text{atomic}})$.

### 3.2. Câu lệnh SQL Thực thi trên DuckDB Silver Layer
Nhờ khả năng hỗ trợ chuẩn SQL `WITH RECURSIVE` tốc độ cao của DuckDB, toàn bộ thuật toán 2 pha trên được biểu diễn gọn nhẹ như sau:

```sql
WITH RECURSIVE atomic_lineage AS (
    -- Pha 1: Tìm các tiến trình hạt giống (Seed Processes) khởi phát từ Runner PID của Atomic
    SELECT 
        p.process_guid,
        p.parent_guid,
        p.image_path,
        p.timestamp AS proc_start_time,
        r.test_run_id,
        r.atomic_guid,
        r.mitre_technique_id,
        r.start_time_utc,
        r.end_time_utc,
        1 AS tree_depth
    FROM silver_process_events p
    INNER JOIN silver_atomic_test_runs r
        ON p.hostname = r.hostname
        AND p.timestamp BETWEEN (r.start_time_utc - INTERVAL '1 second') 
                            AND (r.end_time_utc + INTERVAL '2 seconds')
        AND (p.pid = r.runner_pid OR p.ppid = r.runner_pid)
    WHERE p.event_type = 'PROCESS_START'

    UNION ALL

    -- Pha 2: Đệ quy tìm toàn bộ tiến trình con, cháu theo khóa chuẩn hóa `process_guid`
    SELECT 
        child.process_guid,
        child.parent_guid,
        child.image_path,
        child.timestamp AS proc_start_time,
        parent_tree.test_run_id,
        parent_tree.atomic_guid,
        parent_tree.mitre_technique_id,
        parent_tree.start_time_utc,
        parent_tree.end_time_utc,
        parent_tree.tree_depth + 1 AS tree_depth
    FROM silver_process_events child
    INNER JOIN atomic_lineage parent_tree
        ON child.parent_guid = parent_tree.process_guid
    WHERE child.event_type = 'PROCESS_START'
      AND child.timestamp >= parent_tree.proc_start_time
      AND parent_tree.tree_depth < 10
)
SELECT DISTINCT 
    process_guid, 
    test_run_id, 
    atomic_guid, 
    mitre_technique_id, 
     MAX(tree_depth) AS max_lineage_depth
FROM atomic_lineage
GROUP BY process_guid, test_run_id, atomic_guid, mitre_technique_id;
```

---

## 4. Kiểm Chứng Trên Dữ Liệu Thực Nghiệm Tuần 3 (`DESKTOP-IDEMGQU`)

Đối chiếu thuật toán trên với bộ mẫu thật đã thu thập ở Tuần 3 (`poc_run_20261018_021142.json` trên máy trạm `DESKTOP-IDEMGQU`), toàn bộ chuỗi hành vi đa bảng được tự động gom nhóm và gắn nhãn chính xác tuyệt đối:

| Thứ Tự | Bảng Sự Kiện Silver | `sysmon_event_id` | `process_guid` | Hành Vi Thực Tế Trong Mẫu PoC Tuần 3 | Kết Quả Đối Chiếu Nhãn |
| :---: | :--- | :---: | :--- | :--- | :--- |
| 1 | `silver_process_events` | `1` | `43f71ec6-8d5b-6ad4-2501-000000000400` | Tiến trình gốc `powershell.exe` (Runner PID `5120`) kích hoạt kịch bản thử nghiệm. | **Khớp Pha 1 (Anchor Seed)** $\rightarrow$ Gán nhãn gốc. |
| 2 | `silver_file_events` | `11` | `43f71ec6-8d5b-6ad4-2501-000000000400` | PowerShell tạo file nhị phân `C:\Users\Trankien\AppData\Local\Temp\edr_poc\..._drop.exe`. | **Khớp qua `process_guid`** của Seed $\rightarrow$ Gán nhãn File Drop. |
| 3 | `silver_process_events` | `1` | `43f71ec6-8d5b-6ad4-2601-000000000400` | PowerShell spawn tiến trình con `EDR_POC_..._drop.exe` và `conhost.exe` (`parent_guid = ...2501...`). | **Khớp Pha 2 (Depth = 2)** $\rightarrow$ Lan truyền nhãn sang con. |
| 4 | `silver_registry_events` | `13` | `43f71ec6-8d5b-6ad4-2601-000000000400` | Thao tác `SetValue` ghi giá trị `DWORD (0x00000001)` vào khóa `HKU\...\SOFTWARE\EDR_PoC\TestDword`. | **Khớp qua `process_guid` con** $\rightarrow$ Gán nhãn Registry Modification. |
| 5 | `silver_network_events` | `3` | `43f71ec6-8d5b-6ad4-2601-000000000400` | Mở kết nối outbound TCP cổng `443` tới địa chỉ IP `172.66.147.243`. | **Khớp qua `process_guid` con** $\rightarrow$ Gán nhãn C2 Network Connect. |

Trong khi đó, hơn 140 sự kiện hệ thống bình thường khác của Windows diễn ra trong cùng khoảng thời gian $09:11:50\text{ UTC} \rightarrow 09:12:05\text{ UTC}$ trên máy `DESKTOP-IDEMGQU` không có quan hệ phả hệ với `43f71ec6-8d5b-6ad4-2501-000000000400` nên được giữ nguyên nhãn `is_malicious = 0` (Benign).

---

## 5. Xử Lý Các Trường Hợp Biên (Edge Cases) & Đề Xuất Cho Pipeline Tuần 5

### 5.1. Ba trường hợp biên cần lưu ý khi gắn nhãn
1. **Kỹ thuật gián đoạn phả hệ trực tiếp (Broken Parent-Child Lineage – WMI / Scheduled Tasks / Services):**
   * *Hiện tượng:* Một số bài test Atomic (như `T1053.005` Scheduled Task hoặc `T1047` WMI) không gọi trực tiếp tiến trình con từ PowerShell mà gửi yêu cầu RPC sang tiến trình hệ thống (`svchost.exe` hoặc `WmiPrvSE.exe`) để sinh tiến trình độc hại. Khi đó `parent_guid` của tiến trình mới sẽ trỏ về `WmiPrvSE.exe` thay vì `runner_pid`.
   * *Giải pháp bổ sung:* Kết hợp thêm luật khớp phụ (Secondary Fallback Match) sử dụng trường `RuleName` của Sysmon hoặc khớp đường dẫn đối tượng đích (`input_arguments` trong YAML khớp với `command_line` / `file_path` trong cửa sổ thời gian $[t_{\text{start}}, t_{\text{end}}]$).
2. **Tách biệt Pha Thực Thi (`EXECUTION`) và Pha Dọn Dẹp (`CLEANUP`):**
   * *Hiện tượng:* Khi chạy `Invoke-AtomicTest -Cleanup`, công cụ sẽ xóa file và xóa khóa registry vừa tạo. Nếu gộp chung log của lệnh Cleanup vào nhãn tấn công, mô hình AI sẽ học nhầm hành vi quản trị dọn dẹp.
   * *Giải pháp:* Trong bảng `silver_atomic_test_runs`, bổ sung cột `execution_phase` (`'EXECUTION'` vs. `'CLEANUP'`). Chỉ những bản ghi thuộc pha `'EXECUTION'` mới được dùng để đánh giá độ nhạy phát hiện (Recall) và huấn luyện AI.
3. **Dự phòng khi không bật Execution Logger của PowerShell:**
   * Nếu Cyber/Software chạy nhanh câu lệnh Atomic mà quên xuất file log JSONL, họ có thể chèn một biến môi trường hoặc đối số đánh dấu (Marker Tag, ví dụ `--atomic-id=T1059.001`) vào câu lệnh khởi chạy; Sysmon Event ID 1 sẽ bắt trọn chuỗi này trong cột `command_line` để tự động nhận diện hạt giống `seed_process_guid`.

### 5.2. Kết luận & Đóng góp cho Thiết kế Pipeline Tuần 5
* **Không cài đặt Atomic Red Team vào nhánh collector vận hành thực tế.**
* **Bổ sung bảng `silver_atomic_test_runs` và View `v_labeled_silver_events`** vào thiết kế lưu trữ DuckDB của Tuần 5 để tự động hóa hoàn toàn quy trình chấm điểm Detection Rules (DET-001 $\rightarrow$ DET-010) và trích xuất bảng đặc trưng có nhãn tại tầng Gold.