-- Add composite indexes for common query patterns

-- Findings by asset and status (used in asset detail views)
CREATE INDEX IF NOT EXISTS idx_findings_asset_id_status ON findings(asset_id, status);

-- Scans by organization and status (used in scan listing/filtering)
CREATE INDEX IF NOT EXISTS idx_scans_organization_id_status ON scans(organization_id, status);

-- Assets by organization, type, and active status (used in asset listing/filtering)
CREATE INDEX IF NOT EXISTS idx_assets_org_type_active ON assets(organization_id, type, is_active);

-- Findings by scan (used when viewing scan results)
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id) WHERE scan_id IS NOT NULL;

-- Cloud credentials by organization (used in credential listing)
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_org_id ON cloud_credentials(organization_id);
