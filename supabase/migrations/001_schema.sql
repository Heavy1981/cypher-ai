-- ============================================================
-- CYPHER AI — Supabase Schema
-- Execute no SQL Editor do Supabase
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Organizations (tenants) ──────────────────────────────────
CREATE TABLE organizations (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name        TEXT NOT NULL,
  slug        TEXT UNIQUE NOT NULL,
  plan        TEXT DEFAULT 'starter',
  is_active   BOOLEAN DEFAULT true,
  settings    JSONB DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Users ────────────────────────────────────────────────────
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  email           TEXT UNIQUE NOT NULL,
  full_name       TEXT NOT NULL,
  hashed_password TEXT NOT NULL,
  role            TEXT DEFAULT 'analyst',
  is_active       BOOLEAN DEFAULT true,
  mfa_enabled     BOOLEAN DEFAULT false,
  mfa_secret      TEXT,
  last_login      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_users_org ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);

-- ── Clients ──────────────────────────────────────────────────
CREATE TABLE clients (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  industry        TEXT,
  contact_email   TEXT,
  risk_profile    TEXT DEFAULT 'medium',
  is_active       BOOLEAN DEFAULT true,
  metadata        JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_clients_org ON clients(organization_id);

-- ── Integrations ─────────────────────────────────────────────
CREATE TABLE integrations (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id        UUID REFERENCES clients(id) ON DELETE CASCADE,
  type             TEXT NOT NULL,
  name             TEXT NOT NULL,
  credentials      JSONB DEFAULT '{}',
  config           JSONB DEFAULT '{}',
  is_active        BOOLEAN DEFAULT true,
  last_sync        TIMESTAMPTZ,
  last_health_check TIMESTAMPTZ,
  health_status    TEXT DEFAULT 'unknown',
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_integrations_client ON integrations(client_id);

-- ── Playbooks ─────────────────────────────────────────────────
CREATE TABLE playbooks (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
  name                TEXT NOT NULL,
  description         TEXT,
  trigger_conditions  JSONB DEFAULT '{}',
  steps               JSONB DEFAULT '[]',
  is_active           BOOLEAN DEFAULT true,
  is_automated        BOOLEAN DEFAULT false,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ── Incidents ─────────────────────────────────────────────────
CREATE TABLE incidents (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
  client_id           UUID REFERENCES clients(id),
  assignee_id         UUID REFERENCES users(id),
  playbook_id         UUID REFERENCES playbooks(id),
  ref                 TEXT UNIQUE NOT NULL,
  title               TEXT NOT NULL,
  description         TEXT,
  severity            TEXT DEFAULT 'medium',
  status              TEXT DEFAULT 'open',
  category            TEXT,
  mitre_tactics       JSONB DEFAULT '[]',
  mitre_techniques    JSONB DEFAULT '[]',
  risk_score          FLOAT,
  cvss_score          FLOAT,
  affected_hosts      JSONB DEFAULT '[]',
  affected_users      JSONB DEFAULT '[]',
  affected_ips        JSONB DEFAULT '[]',
  jira_ticket_id      TEXT,
  servicenow_ticket_id TEXT,
  pagerduty_incident_id TEXT,
  ai_summary          TEXT,
  ai_recommendations  JSONB DEFAULT '[]',
  detected_at         TIMESTAMPTZ,
  contained_at        TIMESTAMPTZ,
  resolved_at         TIMESTAMPTZ,
  created_at          TIMESTAMPTZ DEFAULT NOW(),
  updated_at          TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_incidents_org      ON incidents(organization_id);
CREATE INDEX idx_incidents_client   ON incidents(client_id);
CREATE INDEX idx_incidents_status   ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);

-- ── Alerts ───────────────────────────────────────────────────
CREATE TABLE alerts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id     UUID REFERENCES incidents(id),
  client_id       UUID REFERENCES clients(id) ON DELETE CASCADE,
  integration_id  UUID REFERENCES integrations(id),
  external_id     TEXT,
  source          TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        TEXT NOT NULL,
  raw_data        JSONB DEFAULT '{}',
  enrichment      JSONB DEFAULT '{}',
  status          TEXT DEFAULT 'new',
  occurred_at     TIMESTAMPTZ,
  ingested_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_alerts_client ON alerts(client_id);
CREATE INDEX idx_alerts_status ON alerts(status);

-- ── Messages (AI chat) ────────────────────────────────────────
CREATE TABLE messages (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
  role        TEXT NOT NULL,
  content     TEXT NOT NULL,
  author_id   UUID REFERENCES users(id),
  metadata    JSONB DEFAULT '{}',
  tokens_used INTEGER,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_messages_incident ON messages(incident_id);

-- ── Actions ──────────────────────────────────────────────────
CREATE TABLE actions (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id      UUID REFERENCES incidents(id) ON DELETE CASCADE,
  integration_id   UUID REFERENCES integrations(id),
  triggered_by_id  UUID REFERENCES users(id),
  type             TEXT NOT NULL,
  target           TEXT NOT NULL,
  parameters       JSONB DEFAULT '{}',
  status           TEXT DEFAULT 'pending',
  result           JSONB DEFAULT '{}',
  error_message    TEXT,
  is_automated     BOOLEAN DEFAULT false,
  can_rollback     BOOLEAN DEFAULT false,
  rolled_back_at   TIMESTAMPTZ,
  executed_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_actions_incident ON actions(incident_id);

-- ── IOCs ─────────────────────────────────────────────────────
CREATE TABLE iocs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id     UUID REFERENCES incidents(id) ON DELETE CASCADE,
  organization_id UUID REFERENCES organizations(id),
  type            TEXT NOT NULL,
  value           TEXT NOT NULL,
  confidence      FLOAT DEFAULT 0.5,
  tags            JSONB DEFAULT '[]',
  context         JSONB DEFAULT '{}',
  vt_result       JSONB,
  shodan_result   JSONB,
  abuse_score     INTEGER,
  first_seen      TIMESTAMPTZ DEFAULT NOW(),
  last_seen       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_iocs_incident  ON iocs(incident_id);
CREATE INDEX idx_iocs_type_val  ON iocs(type, value);

-- ── Timeline Events ───────────────────────────────────────────
CREATE TABLE timeline_events (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
  actor_id    UUID REFERENCES users(id),
  event_type  TEXT NOT NULL,
  description TEXT NOT NULL,
  metadata    JSONB DEFAULT '{}',
  occurred_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_timeline_incident ON timeline_events(incident_id);

-- ── Artifacts ─────────────────────────────────────────────────
CREATE TABLE artifacts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  incident_id     UUID REFERENCES incidents(id) ON DELETE CASCADE,
  uploaded_by_id  UUID REFERENCES users(id),
  filename        TEXT NOT NULL,
  file_type       TEXT NOT NULL,
  file_size       INTEGER NOT NULL,
  storage_path    TEXT NOT NULL,
  sha256          TEXT,
  description     TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── Correlation Rules ─────────────────────────────────────────
CREATE TABLE correlation_rules (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  logic           JSONB DEFAULT '{}',
  severity_override TEXT,
  is_active       BOOLEAN DEFAULT true,
  hit_count       INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── Row Level Security ────────────────────────────────────────
ALTER TABLE organizations      ENABLE ROW LEVEL SECURITY;
ALTER TABLE users              ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients            ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents          ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts             ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages           ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions            ENABLE ROW LEVEL SECURITY;
ALTER TABLE iocs               ENABLE ROW LEVEL SECURITY;
ALTER TABLE timeline_events    ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations       ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks          ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (used by backend)
-- Anon key has no access (all via backend API)

-- ── Seed: Demo Organization ───────────────────────────────────
INSERT INTO organizations (id, name, slug, plan) VALUES
  ('00000000-0000-0000-0000-000000000001', 'CYPHER AI Demo', 'cypher-demo', 'enterprise');

INSERT INTO clients (id, organization_id, name, industry, risk_profile) VALUES
  ('00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'TechCorp SA',   'Tecnologia', 'high'),
  ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001', 'FinBank Ltda',  'Financeiro', 'critical'),
  ('00000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-000000000001', 'RetailGroup',   'Varejo',     'medium'),
  ('00000000-0000-0000-0000-000000000013', '00000000-0000-0000-0000-000000000001', 'Prefeitura SP', 'Governo',    'high');

-- Admin user (senha: CypherAdmin123!)
-- hashed_password gerado com bcrypt
INSERT INTO users (id, organization_id, email, full_name, hashed_password, role) VALUES
  ('00000000-0000-0000-0000-000000000020',
   '00000000-0000-0000-0000-000000000001',
   'admin@cypher.ai',
   'Admin CYPHER AI',
   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQyCgbFHEHzaH3JTnGH4pPZAS',
   'org_admin');

-- Sample playbooks
INSERT INTO playbooks (organization_id, name, description, trigger_conditions, steps, is_automated) VALUES
(
  '00000000-0000-0000-0000-000000000001',
  'Resposta a Ransomware',
  'Playbook completo para incidentes de ransomware',
  '{"category": ["ransomware"], "severity": ["critical"]}',
  '[
    {"order":1,"phase":"containment","title":"Isolar host afetado","description":"Desconectar da rede via EDR"},
    {"order":2,"phase":"containment","title":"Bloquear C2 no firewall","description":"Identificar e bloquear IPs de C2"},
    {"order":3,"phase":"identification","title":"Coletar evidências forenses","description":"Capturar imagem de memória e logs"},
    {"order":4,"phase":"eradication","title":"Remover payload","description":"Limpar persistência maliciosa"},
    {"order":5,"phase":"recovery","title":"Restaurar de backup","description":"Verificar integridade e restaurar"},
    {"order":6,"phase":"lessons_learned","title":"Relatório pós-incidente","description":"Documentar e atualizar defesas"}
  ]',
  false
),
(
  '00000000-0000-0000-0000-000000000001',
  'Resposta a Phishing',
  'Tratamento de campanhas de phishing',
  '{"category": ["phishing"], "severity": ["high","critical"]}',
  '[
    {"order":1,"phase":"containment","title":"Bloquear domínio malicioso","description":"Bloquear no firewall/proxy"},
    {"order":2,"phase":"containment","title":"Resetar senha do usuário","description":"Forçar reset imediato"},
    {"order":3,"phase":"identification","title":"Verificar outros usuários","description":"Buscar no SIEM por cliques"},
    {"order":4,"phase":"eradication","title":"Remover e-mails maliciosos","description":"Purge via Microsoft 365/Google"}
  ]',
  true
);

-- ── Updated_at trigger ────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER incidents_updated_at
  BEFORE UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
