"""
SQLAlchemy ORM Models — CYPHER AI Platform
Multi-tenant: Organization → Clients → Incidents → Alerts → Actions
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    String, Text, Boolean, DateTime, ForeignKey,
    Enum, JSON, Integer, Float, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def new_uuid():
    return str(uuid.uuid4())


# ── Organization (Tenant) ─────────────────────────────────────
class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(50), default="starter")  # starter | pro | enterprise
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    users: Mapped[List["User"]] = relationship("User", back_populates="organization")
    clients: Mapped[List["Client"]] = relationship("Client", back_populates="organization")
    playbooks: Mapped[List["Playbook"]] = relationship("Playbook", back_populates="organization")
    rules: Mapped[List["CorrelationRule"]] = relationship("CorrelationRule", back_populates="organization")


# ── User ──────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50), default="analyst"
    )  # super_admin | org_admin | analyst | viewer | client_user
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")
    assigned_incidents: Mapped[List["Incident"]] = relationship("Incident", back_populates="assignee")

    __table_args__ = (Index("ix_users_email", "email"), Index("ix_users_org", "organization_id"))


# ── Client (empresa gerenciada) ───────────────────────────────
class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    industry: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    risk_profile: Mapped[str] = mapped_column(String(50), default="medium")  # low | medium | high | critical
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    extra_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="clients")
    integrations: Mapped[List["Integration"]] = relationship("Integration", back_populates="client")
    incidents: Mapped[List["Incident"]] = relationship("Incident", back_populates="client")

    __table_args__ = (Index("ix_clients_org", "organization_id"),)


# ── Integration (SIEM/EDR/FW credentials per client) ─────────
class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    # splunk | elastic | ms_sentinel | qradar |
    # crowdstrike | sentinelone | defender | carbon_black |
    # fortinet | palo_alto | pfsense | cisco_firepower |
    # aws_guardduty | azure_defender | gcp_scc |
    # jira | servicenow | pagerduty | slack | teams
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    credentials: Mapped[dict] = mapped_column(JSONB, default=dict)  # encrypted at app level
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    health_status: Mapped[str] = mapped_column(String(50), default="unknown")  # healthy | degraded | offline | unknown
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped["Client"] = relationship("Client", back_populates="integrations")

    __table_args__ = (Index("ix_integrations_client", "client_id"), Index("ix_integrations_type", "type"))


# ── Incident ──────────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    assignee_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)

    # Identification
    ref: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)  # INC-2024-001
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Classification
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # critical | high | medium | low | info
    status: Mapped[str] = mapped_column(String(30), default="open")
    # open | investigating | contained | eradicated | recovered | closed | false_positive
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # ransomware | phishing | data_breach | ddos | insider | apt | malware | ...

    # MITRE ATT&CK
    mitre_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # Scoring
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Affected assets
    affected_hosts: Mapped[list] = mapped_column(JSONB, default=list)
    affected_users: Mapped[list] = mapped_column(JSONB, default=list)
    affected_ips: Mapped[list] = mapped_column(JSONB, default=list)

    # External references
    jira_ticket_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    servicenow_ticket_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    pagerduty_incident_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # AI analysis
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_recommendations: Mapped[list] = mapped_column(JSONB, default=list)
    playbook_id: Mapped[Optional[str]] = mapped_column(ForeignKey("playbooks.id"), nullable=True)

    # Timestamps
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relations
    client: Mapped["Client"] = relationship("Client", back_populates="incidents")
    assignee: Mapped[Optional["User"]] = relationship("User", back_populates="assigned_incidents")
    playbook: Mapped[Optional["Playbook"]] = relationship("Playbook")
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="incident")
    messages: Mapped[List["Message"]] = relationship("Message", back_populates="incident")
    actions: Mapped[List["Action"]] = relationship("Action", back_populates="incident")
    iocs: Mapped[List["IOC"]] = relationship("IOC", back_populates="incident")
    timeline: Mapped[List["TimelineEvent"]] = relationship("TimelineEvent", back_populates="incident")
    artifacts: Mapped[List["Artifact"]] = relationship("Artifact", back_populates="incident")

    __table_args__ = (
        Index("ix_incidents_org", "organization_id"),
        Index("ix_incidents_client", "client_id"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
    )


# ── Alert (from SIEM/EDR) ─────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[Optional[str]] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    integration_id: Mapped[Optional[str]] = mapped_column(ForeignKey("integrations.id"), nullable=True)

    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # splunk | crowdstrike | etc
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    enrichment: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="new")  # new | triaged | correlated | closed
    occurred_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_client", "client_id"),
        Index("ix_alerts_status", "status"),
    )


# ── Message (AI chat) ─────────────────────────────────────────
class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # user | assistant | system
    content: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    extra_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="messages")

    __table_args__ = (Index("ix_messages_incident", "incident_id"),)


# ── Action (containment / response) ──────────────────────────
class Action(Base):
    __tablename__ = "actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    integration_id: Mapped[Optional[str]] = mapped_column(ForeignKey("integrations.id"), nullable=True)
    triggered_by_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)

    type: Mapped[str] = mapped_column(String(100), nullable=False)
    # isolate_host | block_ip | block_hash | quarantine_file | kill_process |
    # reset_password | disable_user | block_url | create_ticket | send_notification
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="pending")  # pending | running | success | failed | rolled_back
    result: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False)
    can_rollback: Mapped[bool] = mapped_column(Boolean, default=False)
    rolled_back_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="actions")

    __table_args__ = (Index("ix_actions_incident", "incident_id"),)


# ── IOC (Indicators of Compromise) ───────────────────────────
class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)

    type: Mapped[str] = mapped_column(String(50), nullable=False)
    # ip | domain | url | file_hash | email | user_agent | registry_key | mutex
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    context: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Enrichment data
    vt_result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    shodan_result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    abuse_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="iocs")

    __table_args__ = (
        Index("ix_iocs_incident", "incident_id"),
        Index("ix_iocs_type_value", "type", "value"),
    )


# ── Timeline Event ────────────────────────────────────────────
class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # incident_created | alert_correlated | status_change | action_executed |
    # ai_analysis | ioc_added | artifact_uploaded | note_added | escalated
    description: Mapped[str] = mapped_column(Text, nullable=False)
    extra_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline")

    __table_args__ = (Index("ix_timeline_incident", "incident_id"),)


# ── Artifact ──────────────────────────────────────────────────
class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    uploaded_by_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)

    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="artifacts")


# ── Playbook ──────────────────────────────────────────────────
class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_conditions: Mapped[dict] = mapped_column(JSONB, default=dict)
    # { "severity": ["critical"], "category": ["ransomware"], "keywords": ["encrypt"] }
    steps: Mapped[list] = mapped_column(JSONB, default=list)
    # [ { "order": 1, "type": "notify", "config": {...} }, ... ]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="playbooks")


# ── Correlation Rule ──────────────────────────────────────────
class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    logic: Mapped[dict] = mapped_column(JSONB, default=dict)
    # DSL: { "conditions": [...], "threshold": 5, "window_minutes": 10, "action": "create_incident" }
    severity_override: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="rules")
