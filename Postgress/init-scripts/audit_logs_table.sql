-- Create audit_logs table for tracking user actions
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_name TEXT,
    user_email TEXT NOT NULL,
    user_role TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    slack_alert_sent_at TIMESTAMP -- When this audit log was sent to Slack
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);

-- Add comments for documentation
COMMENT ON TABLE audit_logs IS 'Stores audit trail of user actions performed in the dashboard';
COMMENT ON COLUMN audit_logs.user_id IS 'User ID from authentication system';
COMMENT ON COLUMN audit_logs.user_name IS 'Display name of the user';
COMMENT ON COLUMN audit_logs.user_email IS 'Email address of the user';
COMMENT ON COLUMN audit_logs.user_role IS 'Role of the user (admin/user)';
COMMENT ON COLUMN audit_logs.action IS 'Action performed (e.g., CREATE, UPDATE, DELETE, VIEW, SCAN)';
COMMENT ON COLUMN audit_logs.resource_type IS 'Type of resource affected (e.g., vendor, scan, subdomain)';
COMMENT ON COLUMN audit_logs.resource_id IS 'ID or identifier of the affected resource';
COMMENT ON COLUMN audit_logs.details IS 'Additional details about the action in JSON format';
COMMENT ON COLUMN audit_logs.ip_address IS 'IP address of the user when action was performed';
COMMENT ON COLUMN audit_logs.user_agent IS 'User agent string from the browser';
