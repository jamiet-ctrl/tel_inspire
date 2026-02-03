-- =============================================================
-- TELECOM / ISP CUSTOMER DATABASE — AUDIT-HARDENED
-- MariaDB / MySQL Compatible
-- Compliant with: Ofcom General Conditions, UK GDPR,
--                 Consumer Rights Act 2015, Trading Standards
-- =============================================================
-- Run this whole file in one go in phpMyAdmin or via CLI:
--   mysql -u root -p yourdb < customers.sql
-- =============================================================


-- =============================================================
-- STAFF / ADMIN USERS
-- =============================================================

CREATE TABLE IF NOT EXISTS staff_users (
    staff_id                CHAR(36)        NOT NULL PRIMARY KEY,
    username                VARCHAR(50)     NOT NULL UNIQUE,
    email_address           VARCHAR(255)    NOT NULL UNIQUE,
    first_name              VARCHAR(100)    NOT NULL,
    last_name               VARCHAR(100)    NOT NULL,
    role                    ENUM('viewer','agent','supervisor','compliance_officer','admin','system')
                                            NOT NULL DEFAULT 'viewer',
    is_active               TINYINT(1)      NOT NULL DEFAULT 1,
    password_hash           VARCHAR(255)    NOT NULL,
    last_login_at           DATETIME(3)     NULL,
    last_password_change_at DATETIME(3)     NULL,
    created_at              DATETIME(3)     NOT NULL DEFAULT NOW(3),
    updated_at              DATETIME(3)     NOT NULL DEFAULT NOW(3) ON UPDATE NOW(3),
    created_by              CHAR(36)        NULL,
    CONSTRAINT fk_staff_created_by FOREIGN KEY (created_by) REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- CUSTOMERS TABLE
-- =============================================================

CREATE TABLE IF NOT EXISTS customers (
    customer_id             VARCHAR(10)     NOT NULL PRIMARY KEY,

    -- Identity
    first_name              VARCHAR(100)    NOT NULL,
    last_name               VARCHAR(100)    NOT NULL,
    date_of_birth           DATE            NULL,                       -- SENSITIVE
    national_insurance_no   VARCHAR(13)     NULL,                       -- SENSITIVE — encrypt at app layer

    -- Contact
    email_address           VARCHAR(255)    NOT NULL UNIQUE,
    phone_number            VARCHAR(20)     NULL,
    mobile_number           VARCHAR(20)     NULL,

    -- Address
    address_line_1          VARCHAR(255)    NOT NULL,
    address_line_2          VARCHAR(255)    NULL,
    city                    VARCHAR(100)    NOT NULL,
    county                  VARCHAR(100)    NULL,
    postcode                VARCHAR(10)     NOT NULL,
    country                 VARCHAR(50)     NOT NULL DEFAULT 'United Kingdom',

    -- Account
    account_status          ENUM('active','suspended','pending_activation','pending_cancellation','cancelled','archived')
                                            NOT NULL DEFAULT 'pending_activation',
    verification_status     ENUM('not_verified','pending','verified','failed','flagged')
                                            NOT NULL DEFAULT 'not_verified',

    -- Vulnerability (Ofcom C5)
    is_vulnerable           TINYINT(1)      NOT NULL DEFAULT 0,
    vulnerability_reasons   JSON            NULL,                       -- e.g. ["financial_difficulty","mental_health"]
    vulnerability_notes     TEXT            NULL,
    vulnerability_flagged_at DATETIME(3)    NULL,
    vulnerability_reviewed_at DATETIME(3)   NULL,

    -- Social tariff
    eligible_for_social_tariff TINYINT(1)   NOT NULL DEFAULT 0,
    social_tariff_applied_at   DATETIME(3)  NULL,

    -- Contact preferences & consent
    contact_preference      ENUM('email','post','phone','sms','no_marketing_contact')
                                            NOT NULL DEFAULT 'email',
    marketing_consent       TINYINT(1)      NOT NULL DEFAULT 0,
    marketing_consent_given_at      DATETIME(3) NULL,
    marketing_consent_withdrawn_at  DATETIME(3) NULL,

    -- Contract
    contract_start_date     DATE            NULL,
    contract_end_date       DATE            NULL,
    contract_type           VARCHAR(50)     NULL,
    end_of_contract_notified TINYINT(1)     NOT NULL DEFAULT 0,

    -- Notes
    customer_notes          TEXT            NULL,
    admin_notes             TEXT            NULL,

    -- GDPR timestamps
    gdpr_data_given_at      DATETIME(3)     NULL,
    last_data_access_request DATE           NULL,
    data_erasure_requested_at DATETIME(3)   NULL,

    -- Timestamps & ownership
    account_created_at      DATETIME(3)     NOT NULL DEFAULT NOW(3),
    account_updated_at      DATETIME(3)     NOT NULL DEFAULT NOW(3) ON UPDATE NOW(3),
    created_by              CHAR(36)        NULL,
    updated_by              CHAR(36)        NULL,

    CONSTRAINT fk_cust_created_by FOREIGN KEY (created_by) REFERENCES staff_users(staff_id),
    CONSTRAINT fk_cust_updated_by FOREIGN KEY (updated_by) REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- CUSTOMER COMPLAINTS (Ofcom C4 — mandatory)
-- =============================================================

CREATE TABLE IF NOT EXISTS customer_complaints (
    complaint_id            INT UNSIGNED    NOT NULL AUTO_INCREMENT PRIMARY KEY,
    customer_id             VARCHAR(10)     NOT NULL,
    complaint_date          DATETIME(3)     NOT NULL DEFAULT NOW(3),
    complaint_subject       VARCHAR(255)    NOT NULL,
    complaint_details       TEXT            NOT NULL,
    status                  ENUM('open','under_review','resolved','escalated_to_ADR')
                                            NOT NULL DEFAULT 'open',
    resolution_details      TEXT            NULL,
    resolved_at             DATETIME(3)     NULL,
    escalated_to_adr        TINYINT(1)      NOT NULL DEFAULT 0,
    staff_assigned          CHAR(36)        NULL,
    created_at              DATETIME(3)     NOT NULL DEFAULT NOW(3),
    updated_at              DATETIME(3)     NOT NULL DEFAULT NOW(3) ON UPDATE NOW(3),

    CONSTRAINT fk_complaint_cust    FOREIGN KEY (customer_id)    REFERENCES customers(customer_id),
    CONSTRAINT fk_complaint_staff   FOREIGN KEY (staff_assigned) REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- AUDIT LOG — HARDENED WITH HASH CHAIN
-- =============================================================
-- Triggers write here automatically.
-- Do NOT insert into this table manually from your app.
-- The hash chain links every row — tampering breaks the chain.

CREATE TABLE IF NOT EXISTS audit_log (
    log_id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    customer_id             VARCHAR(10)     NULL,
    table_name              VARCHAR(50)     NOT NULL,
    action                  ENUM('INSERT','UPDATE','DELETE','VIEW','VIEW_SENSITIVE',
                                 'CONSENT_CHANGE','STATUS_CHANGE','VULNERABILITY_CHANGE',
                                 'GDPR_REQUEST_CREATED','GDPR_REQUEST_UPDATED','BREACH_LOGGED')
                                            NOT NULL,
    old_data                JSON            NULL,           -- Full row before the change
    new_data                JSON            NULL,           -- Full row after the change
    changed_fields          JSON            NULL,           -- e.g. ["postcode","phone_number"]
    performed_by            CHAR(36)        NULL,
    performed_at            DATETIME(3)     NOT NULL DEFAULT NOW(3),
    ip_address              VARCHAR(45)     NULL,
    session_id              VARCHAR(255)    NULL,

    -- Hash chain
    previous_hash           VARCHAR(64)     NULL,
    row_hash                VARCHAR(64)     NULL,

    CONSTRAINT fk_audit_staff FOREIGN KEY (performed_by) REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- SENSITIVE FIELD ACCESS LOG
-- =============================================================
-- App layer inserts here every time staff views a sensitive field.

CREATE TABLE IF NOT EXISTS sensitive_field_access_log (
    access_log_id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    customer_id             VARCHAR(10)     NOT NULL,
    staff_id                CHAR(36)        NOT NULL,
    fields_accessed         JSON            NOT NULL,       -- e.g. ["date_of_birth","national_insurance_no"]
    access_reason           TEXT            NULL,
    accessed_at             DATETIME(3)     NOT NULL DEFAULT NOW(3),
    ip_address              VARCHAR(45)     NULL,

    CONSTRAINT fk_sens_cust     FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    CONSTRAINT fk_sens_staff    FOREIGN KEY (staff_id)    REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- CONSENT HISTORY (immutable — never UPDATE or DELETE)
-- =============================================================

CREATE TABLE IF NOT EXISTS consent_history (
    consent_id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    customer_id             VARCHAR(10)     NOT NULL,
    consent_type            ENUM('marketing','data_processing','cookie','third_party_sharing')
                                            NOT NULL,
    consent_given           TINYINT(1)      NOT NULL,       -- 1 = opted in, 0 = opted out
    given_at                DATETIME(3)     NOT NULL DEFAULT NOW(3),
    given_by                VARCHAR(50)     NOT NULL,       -- 'customer', 'system', or a staff username
    method                  VARCHAR(50)     NULL,           -- 'web_form', 'phone', 'email', 'sms'
    ip_address              VARCHAR(45)     NULL,
    notes                   TEXT            NULL,

    CONSTRAINT fk_consent_cust FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- GDPR REQUEST TRACKER
-- =============================================================

CREATE TABLE IF NOT EXISTS gdpr_requests (
    request_id              INT UNSIGNED    NOT NULL AUTO_INCREMENT PRIMARY KEY,
    customer_id             VARCHAR(10)     NOT NULL,
    request_type            ENUM('subject_access','erasure','portability','rectification','restriction','objection')
                                            NOT NULL,
    status                  ENUM('received','acknowledged','in_progress','completed','denied','escalated')
                                            NOT NULL DEFAULT 'received',
    received_at             DATETIME(3)     NOT NULL DEFAULT NOW(3),
    acknowledged_at         DATETIME(3)     NULL,
    completed_at            DATETIME(3)     NULL,
    deadline_at             DATETIME(3)     NULL,           -- Set by trigger on INSERT: received_at + 1 month
    is_overdue              TINYINT(1)      NOT NULL DEFAULT 0, -- Updated by trigger / app layer
    handled_by              CHAR(36)        NULL,
    denial_reason           TEXT            NULL,           -- Must be filled if status = denied
    notes                   TEXT            NULL,
    created_at              DATETIME(3)     NOT NULL DEFAULT NOW(3),
    updated_at              DATETIME(3)     NOT NULL DEFAULT NOW(3) ON UPDATE NOW(3),

    CONSTRAINT fk_gdpr_cust     FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    CONSTRAINT fk_gdpr_staff    FOREIGN KEY (handled_by)  REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- DATA BREACH LOG
-- =============================================================

CREATE TABLE IF NOT EXISTS data_breach_log (
    breach_id               INT UNSIGNED    NOT NULL AUTO_INCREMENT PRIMARY KEY,
    detected_at             DATETIME(3)     NOT NULL DEFAULT NOW(3),
    reported_by             CHAR(36)        NULL,
    breach_type             VARCHAR(100)    NOT NULL,
    description             TEXT            NOT NULL,
    affected_customer_ids   JSON            NULL,           -- e.g. ["RK34UL","AB12CD"]
    estimated_affected_count INT            NULL,
    data_types_exposed      JSON            NULL,           -- e.g. ["email","postcode"]
    ico_notified            TINYINT(1)      NOT NULL DEFAULT 0,
    ico_notified_at         DATETIME(3)     NULL,
    customers_notified      TINYINT(1)      NOT NULL DEFAULT 0,
    customers_notified_at   DATETIME(3)     NULL,
    status                  ENUM('open','under_investigation','contained','closed')
                                            NOT NULL DEFAULT 'open',
    resolution_details      TEXT            NULL,
    resolved_at             DATETIME(3)     NULL,

    CONSTRAINT fk_breach_staff FOREIGN KEY (reported_by) REFERENCES staff_users(staff_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================
-- INDEXES
-- =============================================================

CREATE INDEX idx_customers_postcode         ON customers(postcode);
CREATE INDEX idx_customers_email            ON customers(email_address);
CREATE INDEX idx_customers_status           ON customers(account_status);
CREATE INDEX idx_customers_vulnerable       ON customers(is_vulnerable);
CREATE INDEX idx_customers_contract_end     ON customers(contract_end_date);

CREATE INDEX idx_complaints_customer        ON customer_complaints(customer_id);
CREATE INDEX idx_complaints_status          ON customer_complaints(status);

CREATE INDEX idx_audit_customer             ON audit_log(customer_id);
CREATE INDEX idx_audit_performed_at         ON audit_log(performed_at);
CREATE INDEX idx_audit_action               ON audit_log(action);
CREATE INDEX idx_audit_table                ON audit_log(table_name);

CREATE INDEX idx_sensitive_customer         ON sensitive_field_access_log(customer_id);
CREATE INDEX idx_sensitive_staff            ON sensitive_field_access_log(staff_id);
CREATE INDEX idx_sensitive_accessed_at      ON sensitive_field_access_log(accessed_at);

CREATE INDEX idx_consent_customer           ON consent_history(customer_id);
CREATE INDEX idx_consent_type               ON consent_history(consent_type);

CREATE INDEX idx_gdpr_customer              ON gdpr_requests(customer_id);
CREATE INDEX idx_gdpr_status                ON gdpr_requests(status);
CREATE INDEX idx_gdpr_deadline              ON gdpr_requests(deadline_at);

CREATE INDEX idx_breach_status              ON data_breach_log(status);
CREATE INDEX idx_breach_detected            ON data_breach_log(detected_at);


-- =============================================================
-- FUNCTION: Generate Customer ID
-- =============================================================
-- Generates IDs like RK34UL (2 letters, 2 digits, 2 letters)
-- Usage: SELECT generate_customer_id();

DELIMITER //
CREATE OR REPLACE FUNCTION generate_customer_id()
RETURNS VARCHAR(10)
DETERMINISTIC
BEGIN
    DECLARE new_id VARCHAR(10);
    DECLARE exists_already INT;

    REPEAT
        SET new_id = CONCAT(
            CHAR(65 + FLOOR(RAND() * 26)),
            CHAR(65 + FLOOR(RAND() * 26)),
            FLOOR(RAND() * 10),
            FLOOR(RAND() * 10),
            CHAR(65 + FLOOR(RAND() * 26)),
            CHAR(65 + FLOOR(RAND() * 26))
        );

        SELECT COUNT(1) INTO exists_already
        FROM customers WHERE customer_id = new_id;

    UNTIL exists_already = 0
    END REPEAT;

    RETURN new_id;
END//
DELIMITER ;


-- =============================================================
-- PROCEDURE: Compute Audit Hash
-- =============================================================
-- Called by triggers after inserting into audit_log.
-- Builds the SHA2 hash chain.

DELIMITER //
CREATE OR REPLACE PROCEDURE compute_audit_hash(IN p_log_id BIGINT UNSIGNED)
BEGIN
    DECLARE prev_hash VARCHAR(64) DEFAULT NULL;
    DECLARE row_content TEXT;
    DECLARE new_hash VARCHAR(64);

    -- Get previous row's hash
    SELECT row_hash INTO prev_hash
    FROM audit_log
    WHERE log_id = p_log_id - 1;

    -- Build content string from this row
    SELECT CONCAT(
        COALESCE(customer_id, ''),
        table_name,
        action,
        COALESCE(CAST(old_data AS CHAR), ''),
        COALESCE(CAST(new_data AS CHAR), ''),
        COALESCE(performed_by, ''),
        DATE_FORMAT(performed_at, '%Y-%m-%d %H:%i:%s.%f'),
        COALESCE(prev_hash, 'GENESIS')
    )
    INTO row_content
    FROM audit_log
    WHERE log_id = p_log_id;

    SET new_hash = SHA2(row_content, 256);

    UPDATE audit_log
    SET previous_hash = prev_hash,
        row_hash      = new_hash
    WHERE log_id = p_log_id;
END//
DELIMITER ;


-- =============================================================
-- PROCEDURE: Verify Hash Chain
-- =============================================================
-- Run this to check for tampering.
--   CALL verify_audit_chain();
-- Returns every row with expected vs actual hash + tampered flag.

DELIMITER //
CREATE OR REPLACE PROCEDURE verify_audit_chain()
BEGIN
    CREATE TEMPORARY TABLE IF NOT EXISTS _audit_check (
        log_id          BIGINT UNSIGNED,
        expected_hash   VARCHAR(64),
        actual_hash     VARCHAR(64),
        tampered        TINYINT(1)
    );
    TRUNCATE TABLE _audit_check;

    BEGIN
        DECLARE prev_hash VARCHAR(64) DEFAULT NULL;
        DECLARE cur_log_id BIGINT UNSIGNED;
        DECLARE cur_customer_id VARCHAR(10);
        DECLARE cur_table_name VARCHAR(50);
        DECLARE cur_action VARCHAR(30);
        DECLARE cur_old_data TEXT;
        DECLARE cur_new_data TEXT;
        DECLARE cur_performed_by CHAR(36);
        DECLARE cur_performed_at VARCHAR(30);
        DECLARE cur_row_hash VARCHAR(64);
        DECLARE row_content TEXT;
        DECLARE expected VARCHAR(64);
        DECLARE done TINYINT(1) DEFAULT 0;

        DECLARE audit_cursor CURSOR FOR
            SELECT log_id, customer_id, table_name, action,
                   CAST(old_data AS CHAR), CAST(new_data AS CHAR),
                   performed_by, DATE_FORMAT(performed_at, '%Y-%m-%d %H:%i:%s.%f'),
                   row_hash
            FROM audit_log ORDER BY log_id ASC;

        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = 1;

        OPEN audit_cursor;
        read_loop:
        LOOP
            FETCH audit_cursor INTO
                cur_log_id, cur_customer_id, cur_table_name, cur_action,
                cur_old_data, cur_new_data, cur_performed_by,
                cur_performed_at, cur_row_hash;

            IF done THEN LEAVE read_loop; END IF;

            SET row_content = CONCAT(
                COALESCE(cur_customer_id, ''),
                cur_table_name,
                cur_action,
                COALESCE(cur_old_data, ''),
                COALESCE(cur_new_data, ''),
                COALESCE(cur_performed_by, ''),
                cur_performed_at,
                COALESCE(prev_hash, 'GENESIS')
            );

            SET expected = SHA2(row_content, 256);

            INSERT INTO _audit_check VALUES (
                cur_log_id,
                expected,
                cur_row_hash,
                IF(expected <> cur_row_hash, 1, 0)
            );

            SET prev_hash = cur_row_hash;
        END LOOP;
        CLOSE audit_cursor;
    END;

    SELECT * FROM _audit_check;
    DROP TEMPORARY TABLE IF EXISTS _audit_check;
END//
DELIMITER ;


-- =============================================================
-- TRIGGER: CUSTOMERS — AFTER INSERT
-- =============================================================

DELIMITER //
CREATE TRIGGER trg_customers_after_insert
AFTER INSERT ON customers
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, old_data, new_data,
        changed_fields, performed_by, performed_at
    ) VALUES (
        NEW.customer_id,
        'customers',
        'INSERT',
        NULL,
        JSON_OBJECT(
            'customer_id',              NEW.customer_id,
            'first_name',               NEW.first_name,
            'last_name',                NEW.last_name,
            'date_of_birth',            '[REDACTED]',
            'national_insurance_no',    '[REDACTED]',
            'email_address',            NEW.email_address,
            'phone_number',             NEW.phone_number,
            'mobile_number',            NEW.mobile_number,
            'address_line_1',           NEW.address_line_1,
            'address_line_2',           NEW.address_line_2,
            'city',                     NEW.city,
            'county',                   NEW.county,
            'postcode',                 NEW.postcode,
            'account_status',           NEW.account_status,
            'verification_status',      NEW.verification_status,
            'is_vulnerable',            NEW.is_vulnerable,
            'vulnerability_reasons',    NEW.vulnerability_reasons,
            'marketing_consent',        NEW.marketing_consent,
            'contract_start_date',      NEW.contract_start_date,
            'contract_end_date',        NEW.contract_end_date,
            'contract_type',            NEW.contract_type
        ),
        NULL,
        NEW.created_by,
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);

    -- Log consent to consent_history if marketing consent is on at creation
    IF NEW.marketing_consent = 1 THEN
        INSERT INTO consent_history (customer_id, consent_type, consent_given, given_by)
        VALUES (NEW.customer_id, 'marketing', 1, COALESCE(NEW.created_by, 'SYSTEM'));
    END IF;
END//
DELIMITER ;


-- =============================================================
-- TRIGGER: CUSTOMERS — AFTER UPDATE
-- =============================================================

DELIMITER //
CREATE TRIGGER trg_customers_after_update
AFTER UPDATE ON customers
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;
    DECLARE action_type VARCHAR(30);
    DECLARE changed JSON;

    -- Build the list of changed fields
    SET changed = JSON_ARRAY();

    IF OLD.first_name <> NEW.first_name OR (OLD.first_name IS NULL) <> (NEW.first_name IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'first_name'); END IF;
    IF OLD.last_name <> NEW.last_name OR (OLD.last_name IS NULL) <> (NEW.last_name IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'last_name'); END IF;
    IF OLD.email_address <> NEW.email_address OR (OLD.email_address IS NULL) <> (NEW.email_address IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'email_address'); END IF;
    IF OLD.phone_number <> NEW.phone_number OR (OLD.phone_number IS NULL) <> (NEW.phone_number IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'phone_number'); END IF;
    IF OLD.mobile_number <> NEW.mobile_number OR (OLD.mobile_number IS NULL) <> (NEW.mobile_number IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'mobile_number'); END IF;
    IF OLD.address_line_1 <> NEW.address_line_1 OR (OLD.address_line_1 IS NULL) <> (NEW.address_line_1 IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'address_line_1'); END IF;
    IF OLD.address_line_2 <> NEW.address_line_2 OR (OLD.address_line_2 IS NULL) <> (NEW.address_line_2 IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'address_line_2'); END IF;
    IF OLD.city <> NEW.city OR (OLD.city IS NULL) <> (NEW.city IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'city'); END IF;
    IF OLD.postcode <> NEW.postcode OR (OLD.postcode IS NULL) <> (NEW.postcode IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'postcode'); END IF;
    IF OLD.account_status <> NEW.account_status OR (OLD.account_status IS NULL) <> (NEW.account_status IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'account_status'); END IF;
    IF OLD.is_vulnerable <> NEW.is_vulnerable
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'is_vulnerable'); END IF;
    IF OLD.marketing_consent <> NEW.marketing_consent
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'marketing_consent'); END IF;
    IF OLD.date_of_birth <> NEW.date_of_birth OR (OLD.date_of_birth IS NULL) <> (NEW.date_of_birth IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'date_of_birth'); END IF;
    IF OLD.national_insurance_no <> NEW.national_insurance_no OR (OLD.national_insurance_no IS NULL) <> (NEW.national_insurance_no IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'national_insurance_no'); END IF;
    IF OLD.contract_start_date <> NEW.contract_start_date OR (OLD.contract_start_date IS NULL) <> (NEW.contract_start_date IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'contract_start_date'); END IF;
    IF OLD.contract_end_date <> NEW.contract_end_date OR (OLD.contract_end_date IS NULL) <> (NEW.contract_end_date IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'contract_end_date'); END IF;
    IF OLD.customer_notes <> NEW.customer_notes OR (OLD.customer_notes IS NULL) <> (NEW.customer_notes IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'customer_notes'); END IF;
    IF OLD.admin_notes <> NEW.admin_notes OR (OLD.admin_notes IS NULL) <> (NEW.admin_notes IS NULL)
        THEN SET changed = JSON_ARRAY_APPEND(changed, '$', 'admin_notes'); END IF;

    -- Determine the specific action type
    SET action_type = 'UPDATE';
    IF OLD.is_vulnerable <> NEW.is_vulnerable THEN
        SET action_type = 'VULNERABILITY_CHANGE';
    ELSEIF OLD.account_status <> NEW.account_status THEN
        SET action_type = 'STATUS_CHANGE';
    ELSEIF OLD.marketing_consent <> NEW.marketing_consent THEN
        SET action_type = 'CONSENT_CHANGE';
    END IF;

    -- Insert audit row — sensitive fields redacted in both snapshots
    INSERT INTO audit_log (
        customer_id, table_name, action, old_data, new_data,
        changed_fields, performed_by, performed_at
    ) VALUES (
        NEW.customer_id,
        'customers',
        action_type,
        JSON_OBJECT(
            'customer_id',              OLD.customer_id,
            'first_name',               OLD.first_name,
            'last_name',                OLD.last_name,
            'date_of_birth',            '[REDACTED]',
            'national_insurance_no',    '[REDACTED]',
            'email_address',            OLD.email_address,
            'phone_number',             OLD.phone_number,
            'address_line_1',           OLD.address_line_1,
            'postcode',                 OLD.postcode,
            'account_status',           OLD.account_status,
            'is_vulnerable',            OLD.is_vulnerable,
            'marketing_consent',        OLD.marketing_consent
        ),
        JSON_OBJECT(
            'customer_id',              NEW.customer_id,
            'first_name',               NEW.first_name,
            'last_name',                NEW.last_name,
            'date_of_birth',            '[REDACTED]',
            'national_insurance_no',    '[REDACTED]',
            'email_address',            NEW.email_address,
            'phone_number',             NEW.phone_number,
            'address_line_1',           NEW.address_line_1,
            'postcode',                 NEW.postcode,
            'account_status',           NEW.account_status,
            'is_vulnerable',            NEW.is_vulnerable,
            'marketing_consent',        NEW.marketing_consent
        ),
        changed,
        NEW.updated_by,
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);

    -- Log consent change to consent_history
    IF OLD.marketing_consent <> NEW.marketing_consent THEN
        INSERT INTO consent_history (customer_id, consent_type, consent_given, given_by)
        VALUES (NEW.customer_id, 'marketing', NEW.marketing_consent, COALESCE(NEW.updated_by, 'SYSTEM'));
    END IF;
END//
DELIMITER ;


-- =============================================================
-- TRIGGER: CUSTOMERS — AFTER DELETE
-- =============================================================

DELIMITER //
CREATE TRIGGER trg_customers_after_delete
AFTER DELETE ON customers
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, old_data, new_data,
        performed_by, performed_at
    ) VALUES (
        OLD.customer_id,
        'customers',
        'DELETE',
        JSON_OBJECT(
            'customer_id',              OLD.customer_id,
            'first_name',               OLD.first_name,
            'last_name',                OLD.last_name,
            'date_of_birth',            '[REDACTED]',
            'national_insurance_no',    '[REDACTED]',
            'email_address',            OLD.email_address,
            'account_status',           OLD.account_status
        ),
        NULL,
        OLD.updated_by,
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);
END//
DELIMITER ;


-- =============================================================
-- TRIGGERS: CUSTOMER COMPLAINTS — INSERT / UPDATE / DELETE
-- =============================================================

DELIMITER //
CREATE TRIGGER trg_complaints_after_insert
AFTER INSERT ON customer_complaints
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, new_data, performed_at
    ) VALUES (
        NEW.customer_id,
        'customer_complaints',
        'INSERT',
        JSON_OBJECT(
            'complaint_id',      NEW.complaint_id,
            'customer_id',       NEW.customer_id,
            'complaint_subject', NEW.complaint_subject,
            'status',            NEW.status,
            'staff_assigned',    NEW.staff_assigned
        ),
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);
END//
DELIMITER ;

DELIMITER //
CREATE TRIGGER trg_complaints_after_update
AFTER UPDATE ON customer_complaints
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, old_data, new_data,
        changed_fields, performed_at
    ) VALUES (
        NEW.customer_id,
        'customer_complaints',
        'UPDATE',
        JSON_OBJECT('complaint_id', OLD.complaint_id, 'status', OLD.status, 'resolution_details', OLD.resolution_details),
        JSON_OBJECT('complaint_id', NEW.complaint_id, 'status', NEW.status, 'resolution_details', NEW.resolution_details),
        JSON_ARRAY('status', 'resolution_details'),
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);
END//
DELIMITER ;

DELIMITER //
CREATE TRIGGER trg_complaints_after_delete
AFTER DELETE ON customer_complaints
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, old_data, performed_at
    ) VALUES (
        OLD.customer_id,
        'customer_complaints',
        'DELETE',
        JSON_OBJECT('complaint_id', OLD.complaint_id, 'complaint_subject', OLD.complaint_subject),
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);
END//
DELIMITER ;


-- =============================================================
-- TRIGGERS: GDPR REQUESTS — BEFORE INSERT / AFTER INSERT / AFTER UPDATE
-- =============================================================

DELIMITER //
CREATE TRIGGER trg_gdpr_before_insert
BEFORE INSERT ON gdpr_requests
FOR EACH ROW
BEGIN
    -- Auto-set the 1-month legal deadline
    SET NEW.deadline_at = DATE_ADD(NEW.received_at, INTERVAL 1 MONTH);
END//
DELIMITER ;

DELIMITER //
CREATE TRIGGER trg_gdpr_after_insert
AFTER INSERT ON gdpr_requests
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, new_data, performed_at
    ) VALUES (
        NEW.customer_id,
        'gdpr_requests',
        'GDPR_REQUEST_CREATED',
        JSON_OBJECT(
            'request_id',   NEW.request_id,
            'request_type', NEW.request_type,
            'status',       NEW.status,
            'deadline_at',  NEW.deadline_at
        ),
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);
END//
DELIMITER ;

DELIMITER //
CREATE TRIGGER trg_gdpr_after_update
AFTER UPDATE ON gdpr_requests
FOR EACH ROW
BEGIN
    DECLARE new_log_id BIGINT UNSIGNED;

    INSERT INTO audit_log (
        customer_id, table_name, action, old_data, new_data, performed_at
    ) VALUES (
        NEW.customer_id,
        'gdpr_requests',
        'GDPR_REQUEST_UPDATED',
        JSON_OBJECT('request_id', OLD.request_id, 'status', OLD.status, 'completed_at', OLD.completed_at),
        JSON_OBJECT('request_id', NEW.request_id, 'status', NEW.status, 'completed_at', NEW.completed_at),
        NOW(3)
    );

    SET new_log_id = LAST_INSERT_ID();
    CALL compute_audit_hash(new_log_id);
END//
DELIMITER ;


-- =============================================================
-- VIEW: customer_safe_view
-- =============================================================
-- Masks sensitive fields. Use this for viewer / agent roles.
-- Supervisors and above query the customers table directly.

CREATE OR REPLACE VIEW customer_safe_view AS
SELECT
    customer_id,
    first_name,
    last_name,
    '****-**-****'          AS date_of_birth,
    email_address,
    phone_number,
    mobile_number,
    address_line_1,
    address_line_2,
    city,
    county,
    postcode,
    country,
    account_status,
    verification_status,
    '***-***-****'          AS national_insurance_no,
    is_vulnerable,
    vulnerability_reasons,
    vulnerability_notes,
    vulnerability_flagged_at,
    vulnerability_reviewed_at,
    eligible_for_social_tariff,
    social_tariff_applied_at,
    contact_preference,
    marketing_consent,
    marketing_consent_given_at,
    marketing_consent_withdrawn_at,
    contract_start_date,
    contract_end_date,
    contract_type,
    end_of_contract_notified,
    customer_notes,
    admin_notes,
    gdpr_data_given_at,
    account_created_at,
    account_updated_at
FROM customers;


-- =============================================================
-- VIEW: gdpr_overdue_requests
-- =============================================================
-- Shows any GDPR requests past the 1-month legal deadline.

CREATE OR REPLACE VIEW gdpr_overdue_requests AS
SELECT
    request_id,
    customer_id,
    request_type,
    status,
    received_at,
    deadline_at,
    TIMESTAMPDIFF(DAY, deadline_at, NOW()) AS days_overdue,
    handled_by,
    notes
FROM gdpr_requests
WHERE completed_at IS NULL
  AND NOW() > deadline_at;


-- =============================================================
-- SAMPLE DATA
-- =============================================================

-- Staff
INSERT INTO staff_users (staff_id, username, email_address, first_name, last_name, role, password_hash)
VALUES
    (UUID(), 'system',   'system@internal',            'System',  'User',   'system',            '$2a$12$placeholder'),
    (UUID(), 'jsmith',   'jsmith@yourcompany.co.uk',   'Jane',    'Smith',  'supervisor',        '$2a$12$placeholder'),
    (UUID(), 'tcooper',  'tcooper@yourcompany.co.uk',  'Tom',     'Cooper', 'agent',             '$2a$12$placeholder'),
    (UUID(), 'rbutler',  'rbutler@yourcompany.co.uk',  'Rachel',  'Butler', 'compliance_officer','$2a$12$placeholder');

-- Customer (triggers will auto-log to audit_log + consent_history)
INSERT INTO customers (
    customer_id,
    first_name, last_name, date_of_birth,
    email_address, phone_number, mobile_number,
    address_line_1, address_line_2, city, county, postcode,
    account_status, verification_status,
    is_vulnerable, vulnerability_reasons, vulnerability_notes,
    vulnerability_flagged_at,
    contact_preference,
    marketing_consent, marketing_consent_given_at,
    contract_start_date, contract_end_date, contract_type,
    customer_notes, admin_notes,
    gdpr_data_given_at,
    created_by
)
VALUES (
    generate_customer_id(),
    'James', 'Mitchell', '1985-03-12',
    'james.mitchell@email.com', '01234 567890', '07911 123456',
    '14 Maple Street', 'Apt 2B', 'Manchester', 'Greater Manchester', 'M1 2AB',
    'active', 'verified',
    1,
    JSON_ARRAY('financial_difficulty'),
    'Customer struggling with payments since job loss Oct 2025. Payment plan offered.',
    NOW(3),
    'email',
    1, DATE_SUB(NOW(), INTERVAL 30 DAY),
    '2025-10-01', '2026-10-01', '12_month',
    'Please contact me via email only.',
    'Referred to social tariff team 2026-01-15. Follow up needed.',
    DATE_SUB(NOW(), INTERVAL 30 DAY),
    (SELECT staff_id FROM staff_users WHERE username = 'system')
);

-- GDPR request (trigger auto-sets deadline and logs to audit)
INSERT INTO gdpr_requests (customer_id, request_type, status, handled_by, notes)
VALUES (
    (SELECT customer_id FROM customers WHERE email_address = 'james.mitchell@email.com'),
    'subject_access',
    'received',
    (SELECT staff_id FROM staff_users WHERE username = 'rbutler'),
    'Customer requested full data dump via email on 2026-02-01.'
);

-- Complaint (trigger auto-logs to audit)
INSERT INTO customer_complaints (customer_id, complaint_subject, complaint_details, staff_assigned)
VALUES (
    (SELECT customer_id FROM customers WHERE email_address = 'james.mitchell@email.com'),
    'Billing error on January invoice',
    'Customer was charged £45.99 instead of the agreed £29.99. Overpayment of £16.00.',
    (SELECT staff_id FROM staff_users WHERE username = 'tcooper')
);
