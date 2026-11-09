CREATE TABLE vendors (
    id SERIAL PRIMARY KEY,
    vendor_name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    grade TEXT DEFAULT 'N/A',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned TIMESTAMP,
    overall_score_current INTEGER,
    overall_score_1month INTEGER,
    overall_score_3months INTEGER,
    overall_score_12months INTEGER,
    subdomain_count INTEGER DEFAULT 0,
    trend INTEGER,
    low_score_alert_sent_at TIMESTAMP -- When low score alert was last sent
);

ALTER TABLE vendors
ADD COLUMN certifications TEXT DEFAULT 'None';

ALTER TABLE vendors
    ADD COLUMN portfolio TEXT,
    ADD COLUMN tier TEXT,
    ADD COLUMN industry TEXT;
    ADD COLUMN additional_domains JSONB DEFAULT '[]';
-- Import vendors data from cleaned CSV (no header, just data)
-- Format: vendor_name,domain,overall_score_current,grade
-- Optional bulk import (vendor_name,domain,overall_score_current,grade; no header row):
-- \copy vendors(vendor_name, domain, overall_score_current, grade) FROM '/path/to/vendors.csv' WITH (FORMAT csv, DELIMITER ',');


CREATE TABLE subdomains (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL REFERENCES vendors(domain) ON DELETE CASCADE,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('Active', 'Inactive')),
    subdomain TEXT,
    UNIQUE (vendor_id, subdomain)
);

-- Add column to track manually added subdomains
-- This column will help preserve manual additions during forced rediscovery

ALTER TABLE subdomains 
ADD COLUMN manually_added BOOLEAN DEFAULT FALSE;

-- Add timestamp for when the subdomain was manually added
ALTER TABLE subdomains 
ADD COLUMN manually_added_at TIMESTAMP DEFAULT NULL;

-- Add index for performance on manual subdomain queries
CREATE INDEX idx_subdomains_manually_added ON subdomains(manually_added) WHERE manually_added = TRUE;

-- Update existing subdomains to set manually_added = FALSE (they are discovered)
UPDATE subdomains SET manually_added = FALSE WHERE manually_added IS NULL;

-- Add comment to the table
COMMENT ON COLUMN subdomains.manually_added IS 'Indicates if this subdomain was manually added by a user (TRUE) or discovered automatically (FALSE)';
COMMENT ON COLUMN subdomains.manually_added_at IS 'Timestamp when the subdomain was manually added';


CREATE TABLE scores (
    id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    domain TEXT NOT NULL REFERENCES vendors(domain) ON DELETE CASCADE,
    score_category TEXT NOT NULL CHECK (score_category IN ('Website', 'Domain Reputation', 'Encryption', 'DNS','Network','Email','Overall')),
    time_period TEXT NOT NULL CHECK (time_period IN ('current', '1month', '3months', '12months')),
    score INTEGER,
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (vendor_id, domain, score_category,updated_at)
);

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    domain TEXT NOT NULL REFERENCES vendors(domain) ON DELETE CASCADE,
    subdomain TEXT,
    score_category TEXT NOT NULL CHECK (score_category IN ('Website', 'Domain Reputation', 'Encryption', 'DNS','Network','Email')),
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('Info','Low', 'Medium', 'High', 'Critical')),
    detected_at TIMESTAMP DEFAULT NOW(),
    slack_alert_sent_at TIMESTAMP -- When this vulnerability was sent to Slack
);

CREATE TABLE news (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL REFERENCES vendors(domain) ON DELETE CASCADE,
    event_date DATE NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical','Info')),
    source_url TEXT NOT NULL,
    event_type VARCHAR(20) NOT NULL CHECK (event_type IN ('Incident', 'News')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    slack_alert_sent_at TIMESTAMP, -- When this news item was sent to Slack
    UNIQUE(domain, title)
);

-- Table for tracking excluded subdomains (permanently blocked from discovery and scoring)
CREATE TABLE excluded_subdomains (
    id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    domain TEXT NOT NULL REFERENCES vendors(domain) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    excluded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vendor_id, subdomain)
);


-- Vendiant API Layer Database Schema
-- Simplified schema with group information merged into api_credentials

-- API Credentials table with integrated group information
CREATE TABLE IF NOT EXISTS api_credentials (
    id SERIAL PRIMARY KEY,
    credential_hash VARCHAR(255) NOT NULL UNIQUE,
    credential_prefix VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    request_limit INTEGER DEFAULT 5000,
    is_enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP WITHOUT TIME ZONE,
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    created_by VARCHAR(255),
    config JSONB DEFAULT '{}'::jsonb,
    -- Merged group information
    group_name VARCHAR(120) NOT NULL DEFAULT 'read_only',
    assigned_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by VARCHAR(255)
);

-- Access Groups table (for reference and validation)
CREATE TABLE IF NOT EXISTS access_groups (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(120) NOT NULL UNIQUE,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Request Audit Log table
CREATE TABLE IF NOT EXISTS request_audit_log (
    id SERIAL PRIMARY KEY,
    credential_id INTEGER REFERENCES api_credentials(id),
    key_name VARCHAR(255),
    action VARCHAR(60),
    client_ip INET,
    user_agent TEXT,
    request_data JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    response_code INTEGER,
    success BOOLEAN,
    endpoint_path TEXT,
    http_method TEXT,
    request_hash TEXT,
    request_summary TEXT,
    slack_alert_sent_at TIMESTAMP -- When this API request was sent to Slack
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_api_credentials_hash ON api_credentials(credential_hash);
CREATE INDEX IF NOT EXISTS idx_api_credentials_prefix ON api_credentials(credential_prefix);
CREATE INDEX IF NOT EXISTS idx_api_credentials_enabled ON api_credentials(is_enabled);
CREATE INDEX IF NOT EXISTS idx_api_credentials_group_name ON api_credentials(group_name);
CREATE INDEX IF NOT EXISTS idx_request_audit_log_credential_id ON request_audit_log(credential_id);
CREATE INDEX IF NOT EXISTS idx_request_audit_log_timestamp ON request_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_audit_log_key_name ON request_audit_log(key_name);
CREATE INDEX IF NOT EXISTS idx_request_audit_log_endpoint ON request_audit_log(endpoint_path);

-- Insert default access groups
INSERT INTO access_groups (group_name, description, permissions) VALUES
('read_only', 'Read-only access to domain reports and risk scores', '{"vendors": ["read"], "reports": ["read"]}'),
('admin', 'Full access to all resources including API key management', '{"vendors": ["read"], "reports": ["read"], "auth": ["read", "create", "delete"], "audit": ["read"]}')
ON CONFLICT (group_name) DO NOTHING;

-- Add slack alert tracking columns
ALTER TABLE breach_records ADD COLUMN IF NOT EXISTS slack_alert_sent_at TIMESTAMP;

-- Add comments for documentation
COMMENT ON COLUMN api_credentials.group_name IS 'Permission group (read_only, admin)';
COMMENT ON COLUMN api_credentials.assigned_at IS 'When the group was assigned to this credential';
COMMENT ON COLUMN api_credentials.assigned_by IS 'Who assigned the group to this credential';
COMMENT ON COLUMN request_audit_log.key_name IS 'Name of the API key used for the request (for easier identification)'; 