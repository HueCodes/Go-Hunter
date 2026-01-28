-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    plan VARCHAR(50) DEFAULT 'free',
    max_users INTEGER DEFAULT 5,
    max_assets INTEGER DEFAULT 100,
    max_scans_day INTEGER DEFAULT 10,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_deleted_at ON organizations(deleted_at);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    organization_id UUID REFERENCES organizations(id),
    role VARCHAR(50) DEFAULT 'member',
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    magic_link_token VARCHAR(255),
    magic_link_expires BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_organization_id ON users(organization_id);
CREATE INDEX idx_users_magic_link_token ON users(magic_link_token);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- Cloud credentials table
CREATE TABLE cloud_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    encrypted_data BYTEA NOT NULL,
    region VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    last_used BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_cloud_credentials_organization_id ON cloud_credentials(organization_id);
CREATE INDEX idx_cloud_credentials_provider ON cloud_credentials(provider);
CREATE INDEX idx_cloud_credentials_deleted_at ON cloud_credentials(deleted_at);

-- Assets table
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    credential_id UUID REFERENCES cloud_credentials(id),
    type VARCHAR(50) NOT NULL,
    value VARCHAR(1024) NOT NULL,
    source VARCHAR(100),
    discovered_at BIGINT,
    last_seen_at BIGINT,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    parent_id UUID REFERENCES assets(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_assets_organization_id ON assets(organization_id);
CREATE INDEX idx_assets_credential_id ON assets(credential_id);
CREATE INDEX idx_assets_type ON assets(type);
CREATE INDEX idx_assets_is_active ON assets(is_active);
CREATE INDEX idx_assets_parent_id ON assets(parent_id);
CREATE INDEX idx_assets_deleted_at ON assets(deleted_at);
CREATE UNIQUE INDEX idx_assets_org_type_value ON assets(organization_id, type, value) WHERE deleted_at IS NULL;

-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    target_asset_ids UUID[],
    credential_ids UUID[],
    started_at BIGINT,
    completed_at BIGINT,
    error TEXT,
    assets_scanned INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    ports_open INTEGER DEFAULT 0,
    services_found INTEGER DEFAULT 0,
    config JSONB DEFAULT '{}',
    task_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_scans_organization_id ON scans(organization_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_task_id ON scans(task_id);
CREATE INDEX idx_scans_deleted_at ON scans(deleted_at);

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    scan_id UUID REFERENCES scans(id),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    type VARCHAR(100),
    category VARCHAR(100),
    evidence TEXT,
    raw_data JSONB DEFAULT '{}',
    port INTEGER,
    protocol VARCHAR(10),
    service VARCHAR(100),
    banner TEXT,
    remediation TEXT,
    "references" JSONB DEFAULT '[]',
    first_seen_at BIGINT,
    last_seen_at BIGINT,
    resolved_at BIGINT,
    resolved_by UUID REFERENCES users(id),
    hash VARCHAR(64) UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_findings_organization_id ON findings(organization_id);
CREATE INDEX idx_findings_asset_id ON findings(asset_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_type ON findings(type);
CREATE INDEX idx_findings_deleted_at ON findings(deleted_at);
