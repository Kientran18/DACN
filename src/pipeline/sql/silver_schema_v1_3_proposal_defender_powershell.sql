-- =============================================================================
-- ĐỀ XUẤT DDL v1.3 (PROPOSAL) — Windows Defender + PowerShell Script Block (4104).
-- Thiết kế: docs/architecture/w8/telemetry-defender-powershell-proposal.md (D3, người dùng duyệt 2026-11-26 thay cho
-- Data/Cyber; chưa có review độc lập). Không sửa v1.1, không sửa v1.2; chỉ CREATE ... IF NOT EXISTS.
-- Áp sau v1.1 và v1.2 (SilverStore). Nạp lại được từ Bronze (replay).
--
-- Tên cột nguồn đã đối chiếu với mẫu XML THẬT đã khử định danh từ một Windows 10 VM (2026-11-28; Defender
-- 4.18.26100.4, Windows PowerShell 5.1): 1116/1117 (EICAR, Atomic A09), 5007, 4104 một phần và 19 phần.
-- 5001/5013 CHƯA có mẫu: chỉ lưu khung chung + raw_data.
-- Giá trị Defender giữ dạng CHUỖI GỐC (không ép kiểu): rule đọc theo tên, không cần số; tránh bịa khi ép kiểu lỗi.
-- =============================================================================

CREATE TABLE IF NOT EXISTS silver_defender_events (
    event_id VARCHAR(36) PRIMARY KEY,            -- UUIDv5 Computer|Channel|EventRecordID (ADR 0001)
    timestamp TIMESTAMPTZ NOT NULL,              -- System/TimeCreated@SystemTime
    ingest_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL,                 -- WINDOWS_DEFENDER
    event_type VARCHAR(48) NOT NULL,             -- DEFENDER_MALWARE_DETECTED | ..._ACTION | _RTP_DISABLED | _CONFIG_CHANGED | _TAMPER_BLOCKED
    windows_event_id INTEGER NOT NULL,           -- 1116 | 1117 | 5001 | 5007 | 5013
    channel VARCHAR(128) NOT NULL,
    record_id BIGINT NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    level INTEGER,                               -- System/Level (mẫu: 1116 = 3, 1117 = 4, 5007 = 4)
    detection_id VARCHAR(36),                    -- 'Detection ID' bỏ ngoặc {}; cùng giá trị ở 1116 và 1117 của một phát hiện (đã thấy trên mẫu)
    detection_time VARCHAR,                      -- 'Detection Time' (chuỗi gốc, ví dụ 2026-11-28T02:52:51.815Z)
    threat_id VARCHAR,                           -- 'Threat ID'
    threat_name VARCHAR,                         -- 'Threat Name'
    severity_id VARCHAR,                         -- 'Severity ID'
    severity_name VARCHAR,                       -- 'Severity Name' (severity của Defender, KHÔNG phải severity alert DACN)
    category_name VARCHAR,                       -- 'Category Name'
    source_name VARCHAR,                         -- 'Source Name' (ví dụ Real-Time Protection, System)
    process_name VARCHAR,                        -- 'Process Name' (đường dẫn đầy đủ hoặc 'Unknown'); không có PID
    detection_user VARCHAR,                      -- 'Detection User' (định danh: che khi báo cáo)
    path_raw VARCHAR,                            -- 'Path' nguyên văn (có thể bị Defender cắt ngắn)
    resource_type VARCHAR(32),                   -- tiền tố trước ':_' trong Path (mẫu: 'file', 'CmdLine'); NULL nếu không có tiền tố
    resource_value VARCHAR,                      -- phần sau ':_'; NULL nếu không có tiền tố
    origin_name VARCHAR,                         -- 'Origin Name'
    execution_name VARCHAR,                      -- 'Execution Name'
    type_name VARCHAR,                           -- 'Type Name'
    action_id VARCHAR,                           -- 'Action ID'
    action_name VARCHAR,                         -- 'Action Name' (1116: 'Not Applicable'; 1117: ví dụ Quarantine, Remove)
    error_code VARCHAR,                          -- 'Error Code'
    remediation_user VARCHAR,                    -- 'Remediation User'
    signature_version VARCHAR,                   -- 'Security intelligence Version'
    engine_version VARCHAR,                      -- 'Engine Version'
    old_value VARCHAR,                           -- 5007 'Old Value'
    new_value VARCHAR,                           -- 5007 'New Value'
    raw_data JSON NOT NULL                       -- event_data gốc đầy đủ
);

CREATE TABLE IF NOT EXISTS silver_powershell_scriptblock_events (
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    ingest_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL,                 -- POWERSHELL
    event_type VARCHAR(48) NOT NULL,             -- POWERSHELL_SCRIPT_BLOCK
    windows_event_id INTEGER NOT NULL,           -- 4104
    channel VARCHAR(128) NOT NULL,
    record_id BIGINT NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    level INTEGER,                               -- System/Level (mẫu: 5 = Verbose)
    writer_process_id INTEGER,                   -- System/Execution@ProcessID (tiến trình ghi sự kiện; giả định là powershell.exe, CHƯA đối chiếu với Sysmon E1)
    user_sid VARCHAR,                            -- System/Security@UserID
    script_block_id VARCHAR(36) NOT NULL,        -- 'ScriptBlockId'
    message_number INTEGER NOT NULL,             -- 'MessageNumber'
    message_total INTEGER NOT NULL,              -- 'MessageTotal'
    script_block_text VARCHAR NOT NULL,          -- 'ScriptBlockText' (có thể chứa bí mật: API che mặc định, D8)
    script_text_sha256 VARCHAR(64) NOT NULL,     -- sha256(UTF-8) của phần này, tính từ script_block_text
    script_path VARCHAR,                         -- 'Path' (rỗng khi chạy tương tác)
    raw_data JSON NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_ps_sbid ON silver_powershell_scriptblock_events(hostname, script_block_id);
CREATE INDEX IF NOT EXISTS ix_def_detid ON silver_defender_events(detection_id);

-- Script block đã đủ mọi phần (1..message_total). Block thiếu phần KHÔNG xuất hiện ở đây (không bịa phần thiếu).
-- Gom theo (hostname, script_block_id, message_total): cùng ScriptBlockId có thể lặp lại khi chạy lại cùng script (chưa xác minh).
CREATE OR REPLACE VIEW v_powershell_scriptblocks_complete AS
SELECT hostname, script_block_id, message_total,
       min(timestamp) AS first_ts, max(timestamp) AS last_ts,
       count(DISTINCT message_number) AS parts_seen,
       string_agg(script_block_text, '' ORDER BY message_number) AS script_text,
       list(event_id ORDER BY message_number) AS event_ids,
       min(writer_process_id) AS writer_process_id,
       count(DISTINCT writer_process_id) AS writer_pid_count
FROM silver_powershell_scriptblock_events
GROUP BY hostname, script_block_id, message_total
HAVING count(DISTINCT message_number) = message_total AND count(*) = message_total;
