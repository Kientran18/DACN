-- =============================================================================
-- ĐỀ XUẤT DDL v1.2 (PROPOSAL) — CHƯA ĐƯỢC Data/Cyber/Software PHÊ DUYỆT.
-- Không sửa v1.1. Chỉ THÊM bảng mới (không ALTER bảng v1.1) để tương thích ngược.
-- Lý do tách khỏi gold_security_alerts v1.1:
--   * process_guid NOT NULL không dùng được cho alert không gắn process (health/registry);
--   * mitre_technique_id đơn trị, trong khi DET-010 gắn hai technique;
--   * v1.1 thiếu rule_version, coverage_status, missing_fields, trạng thái, dedup;
--   * confidence_score NOT NULL buộc phải bịa số; ở đây KHÔNG có cột confidence số.
-- Ghi chú migration: bảng mới, nạp lại được từ _detection_results/Silver; gold_security_alerts v1.1 giữ nguyên, không dùng.
-- =============================================================================

-- Lineage Silver -> Bronze (PH3-T04), bảng phụ thay vì thêm cột vào 4 bảng Silver
CREATE TABLE IF NOT EXISTS silver_event_lineage (
    event_id VARCHAR(36) PRIMARY KEY,
    bronze_segment VARCHAR NOT NULL,
    bronze_line_no INTEGER NOT NULL,
    bronze_content_hash VARCHAR(64) NOT NULL,    -- sha256(raw_xml UTF-8)
    mapper_version VARCHAR NOT NULL,
    ingest_run_id VARCHAR
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id VARCHAR(36) PRIMARY KEY,
    detection_dedup_key VARCHAR NOT NULL UNIQUE,   -- từ DetectionResult.dedup_key
    group_key VARCHAR NOT NULL,                    -- rule_id|host|process_guid|bucket thời gian
    created_at_utc TIMESTAMPTZ NOT NULL,
    first_seen_utc TIMESTAMPTZ NOT NULL,
    last_seen_utc TIMESTAMPTZ NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    detection_source VARCHAR(32) NOT NULL,         -- RULE | IOC | ML (ML không tự tạo alert response)
    rule_id VARCHAR(32) NOT NULL,
    rule_version INTEGER NOT NULL,
    rule_name VARCHAR NOT NULL,
    severity VARCHAR(16) NOT NULL,
    severity_reason VARCHAR NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'NEW',
    mitre_technique_ids JSON,                      -- mảng; chỉ khi rule có mitre_basis
    hostname VARCHAR(64) NOT NULL,
    process_guid VARCHAR(36),                      -- NULLABLE có chủ ý
    image_path VARCHAR,
    command_line VARCHAR,
    user_name VARCHAR,
    contributing_event_ids VARCHAR[] NOT NULL,
    matched_fields JSON NOT NULL,
    missing_fields JSON NOT NULL,
    coverage_status VARCHAR(32) NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_status_history (
    history_id VARCHAR(36) PRIMARY KEY,
    alert_id VARCHAR(36) NOT NULL,
    from_status VARCHAR(24),
    to_status VARCHAR(24) NOT NULL,
    actor VARCHAR NOT NULL,
    note VARCHAR NOT NULL,
    at_utc TIMESTAMPTZ NOT NULL
);

-- Khoảng hở telemetry (INSUFFICIENT_TELEMETRY): KHÔNG phải cảnh báo đe dọa
CREATE TABLE IF NOT EXISTS coverage_gaps (
    gap_id VARCHAR(36) PRIMARY KEY,
    detection_dedup_key VARCHAR NOT NULL UNIQUE,
    rule_id VARCHAR(32) NOT NULL,
    rule_version INTEGER NOT NULL,
    hostname VARCHAR(64),
    contributing_event_ids VARCHAR[] NOT NULL,
    missing_fields JSON NOT NULL,
    coverage_status VARCHAR(32) NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(36) PRIMARY KEY,
    title VARCHAR NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'OPEN',
    created_at_utc TIMESTAMPTZ NOT NULL,
    created_by VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id VARCHAR(36) NOT NULL,
    alert_id VARCHAR(36) NOT NULL,
    linked_at_utc TIMESTAMPTZ NOT NULL,
    linked_by VARCHAR NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);
CREATE TABLE IF NOT EXISTS incident_notes (
    note_id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL,
    actor VARCHAR NOT NULL,
    note VARCHAR NOT NULL,
    at_utc TIMESTAMPTZ NOT NULL
);

-- Audit append-only: chỉ INSERT; chuỗi băm (prev_hash -> row_hash) để phát hiện sửa/xóa
CREATE TABLE IF NOT EXISTS audit_log (
    seq BIGINT PRIMARY KEY,
    at_utc TIMESTAMPTZ NOT NULL,
    actor VARCHAR NOT NULL,
    action VARCHAR NOT NULL,
    target_type VARCHAR NOT NULL,
    target_id VARCHAR NOT NULL,
    reason VARCHAR NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    row_hash VARCHAR(64) NOT NULL
);

-- Response (PH7): hàng đợi hành động có phê duyệt. Kết quả/rollback là JSON.
CREATE TABLE IF NOT EXISTS response_actions (
    action_id VARCHAR(36) PRIMARY KEY,
    alert_id VARCHAR(36),
    action_type VARCHAR(32) NOT NULL,              -- TERMINATE_PROCESS | QUARANTINE_FILE | RESTORE_FILE
    target JSON NOT NULL,
    requested_mode VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'REQUESTED',
    requested_by VARCHAR NOT NULL,
    requested_at_utc TIMESTAMPTZ NOT NULL,
    approved_by VARCHAR,
    approved_at_utc TIMESTAMPTZ,
    decision_reason VARCHAR,
    result JSON,
    rollback JSON,
    updated_at_utc TIMESTAMPTZ NOT NULL
);
