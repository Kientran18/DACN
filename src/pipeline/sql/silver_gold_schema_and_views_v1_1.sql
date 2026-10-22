-- =============================================================================
-- LOCAL EDR DATA PIPELINE - DUCKDB SCHEMA & ENRICHED VIEWS SPECIFICATION v1.1
-- Issue: [W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage #27
-- Phụ trách: Huỳnh Hữu Nhật (Data Engineer Lead)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. TẦNG SILVER: 4 BẢNG SỰ KIỆN CHUẨN HÓA (SCHEMA v1.1)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS silver_process_events (
    -- Common Silver Envelope v1.1 (13 Columns)
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_utc_time TIMESTAMPTZ,
    ingest_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL DEFAULT 'SYSMON',
    event_type VARCHAR(32) NOT NULL,
    sysmon_event_id INTEGER NOT NULL,
    channel VARCHAR(64) NOT NULL,
    record_id BIGINT NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    process_guid VARCHAR(36) NOT NULL,
    rule_name VARCHAR,
    raw_data JSON NOT NULL,
    -- Process Specific Columns (Sysmon Event ID 1 & 5)
    pid INTEGER NOT NULL,
    ppid INTEGER,
    parent_guid VARCHAR(36),
    image_path VARCHAR NOT NULL,
    command_line VARCHAR,
    current_working_directory VARCHAR,
    user_name VARCHAR,
    integrity_level VARCHAR(16),
    session_id INTEGER,
    parent_image VARCHAR,
    parent_command_line VARCHAR,
    file_sha256 VARCHAR(64),
    imphash VARCHAR(32),
    hashes JSON
);

CREATE TABLE IF NOT EXISTS silver_file_events (
    -- Common Silver Envelope v1.1
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_utc_time TIMESTAMPTZ,
    ingest_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL DEFAULT 'SYSMON',
    event_type VARCHAR(32) NOT NULL,
    sysmon_event_id INTEGER NOT NULL,
    channel VARCHAR(64) NOT NULL,
    record_id BIGINT NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    process_guid VARCHAR(36) NOT NULL,
    rule_name VARCHAR,
    raw_data JSON NOT NULL,
    -- File Specific Columns (Sysmon Event ID 11, 15, 23, 26, 29)
    operation VARCHAR(32) NOT NULL,
    pid INTEGER,
    file_path VARCHAR NOT NULL,
    file_extension VARCHAR(32),
    image_path VARCHAR NOT NULL,
    creation_utc_time TIMESTAMPTZ,
    user_name VARCHAR,
    file_sha256 VARCHAR(64),
    hashes JSON
);

CREATE TABLE IF NOT EXISTS silver_registry_events (
    -- Common Silver Envelope v1.1
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_utc_time TIMESTAMPTZ,
    ingest_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL DEFAULT 'SYSMON',
    event_type VARCHAR(32) NOT NULL,
    sysmon_event_id INTEGER NOT NULL,
    channel VARCHAR(64) NOT NULL,
    record_id BIGINT NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    process_guid VARCHAR(36) NOT NULL,
    rule_name VARCHAR,
    raw_data JSON NOT NULL,
    -- Registry Specific Columns (Sysmon Event ID 12, 13, 14)
    operation VARCHAR(32) NOT NULL,
    pid INTEGER,
    target_object VARCHAR NOT NULL,
    hive VARCHAR(16) NOT NULL,
    key_path VARCHAR NOT NULL,
    value_name VARCHAR,
    value_type_inferred VARCHAR(32),
    details VARCHAR,
    new_name VARCHAR,
    image_path VARCHAR NOT NULL,
    user_name VARCHAR
);

CREATE TABLE IF NOT EXISTS silver_network_events (
    -- Common Silver Envelope v1.1
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_utc_time TIMESTAMPTZ,
    ingest_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(32) NOT NULL DEFAULT 'SYSMON',
    event_type VARCHAR(32) NOT NULL,
    sysmon_event_id INTEGER NOT NULL,
    channel VARCHAR(64) NOT NULL,
    record_id BIGINT NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    process_guid VARCHAR(36) NOT NULL,
    rule_name VARCHAR,
    raw_data JSON NOT NULL,
    -- Network & DNS Specific Columns (Sysmon Event ID 3 & Event ID 22)
    pid INTEGER,
    image_path VARCHAR NOT NULL,
    user_name VARCHAR,
    protocol VARCHAR(16),
    direction VARCHAR(16),
    ip_version VARCHAR(8),
    src_ip VARCHAR(45),
    src_port INTEGER,
    dest_ip VARCHAR(45),
    dest_port INTEGER,
    dest_hostname VARCHAR,
    dns_query_name VARCHAR,
    dns_query_status INTEGER,
    dns_query_results VARCHAR
);

-- -----------------------------------------------------------------------------
-- 2. BẢNG QUẢN TRỊ PIPELINE: QUARANTINE DLQ, WATERMARKS & LAB GROUND-TRUTH
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS silver_quarantine_dlq (
    quarantine_id VARCHAR(36) PRIMARY KEY,
    quarantined_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    error_code VARCHAR(64) NOT NULL,
    error_stage VARCHAR(32) NOT NULL,
    error_reason VARCHAR NOT NULL,
    source_reference VARCHAR NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    reprocess_status VARCHAR(32) NOT NULL DEFAULT 'PENDING_TRIAGE',
    raw_payload JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS silver_ingestion_watermarks (
    hostname VARCHAR(64) NOT NULL,
    channel VARCHAR(64) NOT NULL,
    last_record_id BIGINT NOT NULL,
    last_event_timestamp TIMESTAMPTZ NOT NULL,
    channel_epoch_tag VARCHAR(64) NOT NULL DEFAULT 'DEFAULT',
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (hostname, channel)
);

CREATE TABLE IF NOT EXISTS silver_atomic_test_runs (
    test_run_id VARCHAR(36) PRIMARY KEY,
    marker VARCHAR(64),
    atomic_guid VARCHAR(36),
    mitre_technique_id VARCHAR(32) NOT NULL,
    test_name VARCHAR NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    runner_pid INTEGER,
    start_time_utc TIMESTAMPTZ NOT NULL,
    end_time_utc TIMESTAMPTZ NOT NULL,
    execution_phase VARCHAR(16) NOT NULL DEFAULT 'EXECUTION',
    command_executed VARCHAR,
    raw_run_metadata JSON
);

-- -----------------------------------------------------------------------------
-- 3. CÁC SQL VIEWS LÀM GIÀU NGỮ CẢNH (ENRICHED VIEWS CHO CYBER DETECTION)
-- Học từ cơ chế ProcessTracker của Velociraptor & SQL Views của osquery (W04)
-- -----------------------------------------------------------------------------

-- 3.1. Làm giàu sự kiện File với ngữ cảnh của Process khởi tạo (CommandLine, ParentImage, IntegrityLevel)
CREATE OR REPLACE VIEW v_silver_file_enriched AS
SELECT 
    f.*,
    p.command_line AS process_command_line,
    p.parent_guid AS parent_process_guid,
    p.parent_image AS parent_image_path,
    p.parent_command_line,
    p.integrity_level,
    p.file_sha256 AS process_image_sha256
FROM silver_file_events f
LEFT JOIN silver_process_events p
    ON f.process_guid = p.process_guid
   AND p.event_type = 'PROCESS_START';

-- 3.2. Làm giàu sự kiện Registry với ngữ cảnh của Process khởi tạo
CREATE OR REPLACE VIEW v_silver_registry_enriched AS
SELECT 
    r.*,
    p.command_line AS process_command_line,
    p.parent_guid AS parent_process_guid,
    p.parent_image AS parent_image_path,
    p.integrity_level
FROM silver_registry_events r
LEFT JOIN silver_process_events p
    ON r.process_guid = p.process_guid
   AND p.event_type = 'PROCESS_START';

-- 3.3. Làm giàu sự kiện Network/DNS với ngữ cảnh của Process khởi tạo
CREATE OR REPLACE VIEW v_silver_network_enriched AS
SELECT 
    n.*,
    p.command_line AS process_command_line,
    p.parent_guid AS parent_process_guid,
    p.parent_image AS parent_image_path,
    p.integrity_level
FROM silver_network_events n
LEFT JOIN silver_process_events p
    ON n.process_guid = p.process_guid
   AND p.event_type = 'PROCESS_START';

-- 3.4. View đệ quy dựng toàn bộ cây phả hệ tiến trình (Process Lineage DAG)
CREATE OR REPLACE VIEW v_process_tree_lineage AS
WITH RECURSIVE process_dag AS (
    -- Nút gốc (các tiến trình mà cha của nó chưa từng xuất hiện trong bảng PROCESS_START)
    SELECT 
        p.event_id,
        p.hostname,
        p.timestamp,
        p.process_guid,
        p.parent_guid,
        p.pid,
        p.ppid,
        p.image_path,
        p.command_line,
        p.integrity_level,
        1 AS tree_depth,
        p.process_guid AS root_process_guid,
        p.image_path AS lineage_path
    FROM silver_process_events p
    WHERE p.event_type = 'PROCESS_START'
      AND NOT EXISTS (
          SELECT 1 FROM silver_process_events parent_chk
          WHERE parent_chk.process_guid = p.parent_guid
            AND parent_chk.event_type = 'PROCESS_START'
      )

    UNION ALL

    -- Đệ quy nối các tiến trình con, cháu qua khóa chuẩn hóa process_guid
    SELECT 
        c.event_id,
        c.hostname,
        c.timestamp,
        c.process_guid,
        c.parent_guid,
        c.pid,
        c.ppid,
        c.image_path,
        c.command_line,
        c.integrity_level,
        dag.tree_depth + 1 AS tree_depth,
        dag.root_process_guid,
        dag.lineage_path || ' -> ' || c.image_path AS lineage_path
    FROM silver_process_events c
    INNER JOIN process_dag dag
        ON c.parent_guid = dag.process_guid
    WHERE c.event_type = 'PROCESS_START'
      AND dag.tree_depth < 12
)
SELECT * FROM process_dag;

-- -----------------------------------------------------------------------------
-- 4. TẦNG GOLD: BẢNG FEATURE STORE & BẢNG CẢNH BÁO AN NINH (CONTRACTS v1.1)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS gold_process_features (
    feature_record_id VARCHAR(36) PRIMARY KEY,
    process_guid VARCHAR(36) NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    window_start_utc TIMESTAMPTZ NOT NULL,
    window_end_utc TIMESTAMPTZ NOT NULL,
    tree_depth INTEGER NOT NULL DEFAULT 1,
    child_process_count_10s INTEGER NOT NULL DEFAULT 0,
    cmd_length INTEGER NOT NULL DEFAULT 0,
    cmd_shannon_entropy DOUBLE NOT NULL DEFAULT 0.0,
    is_temp_execution BOOLEAN NOT NULL DEFAULT FALSE,
    file_create_count_5s INTEGER NOT NULL DEFAULT 0,
    file_delete_count_5s INTEGER NOT NULL DEFAULT 0,
    reg_set_value_count_10s INTEGER NOT NULL DEFAULT 0,
    net_outbound_count_30s INTEGER NOT NULL DEFAULT 0,
    unique_dest_ip_count_60s INTEGER NOT NULL DEFAULT 0,
    dns_query_count_60s INTEGER NOT NULL DEFAULT 0,
    source_event_ids VARCHAR[] NOT NULL,
    ground_truth_label VARCHAR(32) DEFAULT 'UNKNOWN'
);

CREATE TABLE IF NOT EXISTS gold_security_alerts (
    alert_id VARCHAR(36) PRIMARY KEY,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    first_seen_utc TIMESTAMPTZ NOT NULL,
    last_seen_utc TIMESTAMPTZ NOT NULL,
    detection_source VARCHAR(32) NOT NULL,
    rule_id VARCHAR(32) NOT NULL,
    rule_name VARCHAR NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence_score DOUBLE NOT NULL,
    mitre_tactic VARCHAR(64),
    mitre_technique_id VARCHAR(32),
    hostname VARCHAR(64) NOT NULL,
    process_guid VARCHAR(36) NOT NULL,
    parent_guid VARCHAR(36),
    image_path VARCHAR NOT NULL,
    command_line VARCHAR,
    user_name VARCHAR,
    feature_record_ids VARCHAR[],
    contributing_event_ids VARCHAR[] NOT NULL,
    bronze_raw_references JSON NOT NULL,
    investigation_summary JSON
);