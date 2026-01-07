-- Scheduled scans table for recurring scan automation
CREATE TABLE scheduled_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    cron_expr VARCHAR(100) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    target_asset_ids UUID[],
    credential_ids UUID[],
    next_run_at BIGINT,
    last_run_at BIGINT,
    last_scan_id UUID REFERENCES scans(id),
    config JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for efficient querying
CREATE INDEX idx_scheduled_scans_org_id ON scheduled_scans(organization_id);
CREATE INDEX idx_scheduled_scans_enabled ON scheduled_scans(is_enabled) WHERE deleted_at IS NULL;
CREATE INDEX idx_scheduled_scans_next_run ON scheduled_scans(next_run_at) WHERE is_enabled = true AND deleted_at IS NULL;
CREATE INDEX idx_scheduled_scans_deleted_at ON scheduled_scans(deleted_at);
