"""
CYPHER AI Playbook Engine
Executa playbooks de resposta com suporte a ITSM (Jira/ServiceNow/PagerDuty)
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional
import httpx
import structlog

log = structlog.get_logger()

# ─────────────────────────────────────────────────────────────
# ITSM CONNECTORS
# ─────────────────────────────────────────────────────────────

class ServiceNowConnector:
    """ServiceNow Table API integration."""

    def __init__(self, url: str, user: str, password: str):
        self.base = url.rstrip("/")
        self.auth = (user, password)

    async def create_incident(self, incident: dict) -> dict:
        priority_map = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
        payload = {
            "short_description": f"[CYPHER AI] [{incident.get('ref')}] {incident.get('title')}",
            "description": incident.get("description", "Ver CYPHER AI para detalhes completos."),
            "urgency": priority_map.get(incident.get("severity", "medium"), "3"),
            "impact": priority_map.get(incident.get("severity", "medium"), "3"),
            "category": "Security",
            "subcategory": incident.get("category", "Incident"),
            "caller_id": "cypher_api",
            "u_cypher_id": incident.get("id"),
            "u_cypher_ref": incident.get("ref"),
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base}/api/now/table/incident",
                auth=self.auth,
                json=payload,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return {
                "ticket_id": result.get("number"),
                "sys_id": result.get("sys_id"),
                "url": f"{self.base}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}",
            }

    async def update_incident(self, sys_id: str, fields: dict) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.patch(
                f"{self.base}/api/now/table/incident/{sys_id}",
                auth=self.auth,
                json=fields,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            return resp.json().get("result", {})

    async def add_work_note(self, sys_id: str, note: str) -> dict:
        return await self.update_incident(sys_id, {"work_notes": note})

    async def close_incident(self, sys_id: str, resolution: str) -> dict:
        return await self.update_incident(sys_id, {
            "state": "6",  # Resolved
            "close_code": "Solved (Permanently)",
            "close_notes": resolution,
        })


class PagerDutyConnector:
    """PagerDuty Events API v2."""

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, integration_key: str, api_key: str = ""):
        self.integration_key = integration_key
        self.api_key = api_key

    async def trigger_incident(self, incident: dict) -> dict:
        sev_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
        payload = {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "dedup_key": incident.get("ref"),
            "payload": {
                "summary": f"[{incident.get('ref')}] {incident.get('title')}",
                "severity": sev_map.get(incident.get("severity", "medium"), "warning"),
                "source": "CYPHER AI",
                "component": incident.get("client_name", "Unknown"),
                "group": incident.get("category", "security"),
                "class": "security_incident",
                "custom_details": {
                    "cypher_id": incident.get("id"),
                    "affected_hosts": incident.get("affected_hosts", []),
                    "mitre_tactics": incident.get("mitre_tactics", []),
                },
            },
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(self.EVENTS_URL, json=payload)
            resp.raise_for_status()
            return resp.json()

    async def resolve_incident(self, dedup_key: str) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(self.EVENTS_URL, json={
                "routing_key": self.integration_key,
                "event_action": "resolve",
                "dedup_key": dedup_key,
            })
            return resp.json()


# ─────────────────────────────────────────────────────────────
# PLAYBOOK ENGINE
# ─────────────────────────────────────────────────────────────

class PlaybookEngine:
    """
    Executa playbooks passo a passo com suporte a:
    - Ações automáticas (contenção, bloqueio)
    - Criação de tickets ITSM
    - Notificações (Slack, Email, PagerDuty, Teams)
    - Condicionais baseadas em severidade/categoria
    - Rollback de ações
    """

    def __init__(self, db_session, incident_id: str, triggered_by_id: Optional[str] = None):
        self.db = db_session
        self.incident_id = incident_id
        self.triggered_by_id = triggered_by_id
        self._execution_log = []

    async def run(self, playbook: dict) -> dict:
        """Executa um playbook completo."""
        steps = playbook.get("steps", [])
        results = {"playbook": playbook.get("name"), "steps_executed": 0, "steps_failed": 0, "log": []}

        log.info("playbook_started", playbook=playbook.get("name"), incident=self.incident_id)

        for step in sorted(steps, key=lambda s: s.get("order", 0)):
            # Check conditions
            if not await self._check_conditions(step.get("conditions", {})):
                results["log"].append({"step": step.get("title"), "status": "skipped", "reason": "conditions_not_met"})
                continue

            step_result = await self._execute_step(step)
            results["log"].append(step_result)

            if step_result["status"] == "success":
                results["steps_executed"] += 1
            else:
                results["steps_failed"] += 1
                if step.get("on_failure") == "abort":
                    results["aborted"] = True
                    break

        # Record in timeline
        from app.models import TimelineEvent
        self.db.add(TimelineEvent(
            incident_id=self.incident_id,
            actor_id=self.triggered_by_id,
            event_type="playbook_executed",
            description=f"Playbook '{playbook.get('name')}' executado: {results['steps_executed']} passos concluídos",
            metadata=results,
        ))
        await self.db.commit()
        return results

    async def _check_conditions(self, conditions: dict) -> bool:
        if not conditions:
            return True
        from app.models import Incident
        from sqlalchemy import select
        result = await self.db.execute(select(Incident).where(Incident.id == self.incident_id))
        incident = result.scalar_one_or_none()
        if not incident:
            return False

        if "severity" in conditions:
            if incident.severity not in conditions["severity"]:
                return False
        if "category" in conditions:
            if incident.category not in conditions["category"]:
                return False
        if "status" in conditions:
            if incident.status not in conditions["status"]:
                return False
        return True

    async def _execute_step(self, step: dict) -> dict:
        title = step.get("title", "Unnamed step")
        step_type = step.get("type", "manual")
        log.info("playbook_step", step=title, type=step_type)

        try:
            if step_type == "manual":
                # Just logs — analyst does it manually
                return {"step": title, "status": "pending_manual", "note": step.get("description")}

            elif step_type == "action":
                return await self._run_action_step(step)

            elif step_type == "notify":
                return await self._run_notify_step(step)

            elif step_type == "ticket":
                return await self._run_ticket_step(step)

            elif step_type == "wait":
                seconds = step.get("wait_seconds", 60)
                await asyncio.sleep(min(seconds, 300))  # max 5 min
                return {"step": title, "status": "success", "waited_seconds": seconds}

            elif step_type == "condition_check":
                met = await self._check_conditions(step.get("check", {}))
                return {"step": title, "status": "success", "condition_met": met}

            else:
                return {"step": title, "status": "skipped", "reason": f"unknown_type: {step_type}"}

        except Exception as e:
            log.error("playbook_step_failed", step=title, error=str(e))
            return {"step": title, "status": "failed", "error": str(e)}

    async def _run_action_step(self, step: dict) -> dict:
        from app.models import Action
        from app.workers.action_tasks import execute_action

        config = step.get("action_config", {})
        action = Action(
            incident_id=self.incident_id,
            integration_id=config.get("integration_id"),
            triggered_by_id=self.triggered_by_id,
            type=config.get("type", "send_notification"),
            target=config.get("target", ""),
            parameters=config.get("parameters", {}),
            is_automated=True,
        )
        self.db.add(action)
        await self.db.flush()
        execute_action.apply_async(args=[action.id], queue="actions")
        return {"step": step.get("title"), "status": "success", "action_id": action.id, "dispatched": True}

    async def _run_notify_step(self, step: dict) -> dict:
        config = step.get("notify_config", {})
        channels = config.get("channels", [])
        results = {}

        from app.models import Incident, Client
        from sqlalchemy import select
        result = await self.db.execute(
            select(Incident, Client.name.label("cn"))
            .join(Client, Incident.client_id == Client.id)
            .where(Incident.id == self.incident_id)
        )
        row = result.first()
        incident_data = {}
        if row:
            inc, cn = row
            incident_data = {
                "ref": inc.ref, "title": inc.title, "severity": inc.severity,
                "status": inc.status, "client_name": cn,
            }

        for channel in channels:
            if channel == "slack":
                from app.core.config import settings
                from app.integrations.connectors import SlackConnector
                if settings.SLACK_BOT_TOKEN:
                    slack = SlackConnector(settings.SLACK_BOT_TOKEN, config.get("slack_channel", settings.SLACK_DEFAULT_CHANNEL))
                    r = await slack.send_incident_alert(incident_data)
                    results["slack"] = r.get("ok", False)

            elif channel == "pagerduty":
                from app.core.config import settings
                if settings.PAGERDUTY_API_KEY:
                    pd = PagerDutyConnector(settings.PAGERDUTY_API_KEY)
                    r = await pd.trigger_incident(incident_data)
                    results["pagerduty"] = r.get("status") == "success"

            elif channel == "teams":
                from app.core.config import settings
                if settings.TEAMS_WEBHOOK_URL:
                    async with httpx.AsyncClient(timeout=15) as client:
                        r = await client.post(settings.TEAMS_WEBHOOK_URL, json={
                            "@type": "MessageCard",
                            "themeColor": "FF0000" if incident_data.get("severity") == "critical" else "FFA500",
                            "title": f"🚨 CYPHER AI — {incident_data.get('ref')}",
                            "text": f"**{incident_data.get('title')}**\nSeveridade: {incident_data.get('severity', '').upper()}\nCliente: {incident_data.get('client_name')}",
                        })
                        results["teams"] = r.status_code == 200

        return {"step": step.get("title"), "status": "success", "notifications": results}

    async def _run_ticket_step(self, step: dict) -> dict:
        config = step.get("ticket_config", {})
        system = config.get("system", "jira")

        from app.models import Incident, Client
        from sqlalchemy import select
        result = await self.db.execute(
            select(Incident, Client.name.label("cn"))
            .join(Client, Incident.client_id == Client.id)
            .where(Incident.id == self.incident_id)
        )
        row = result.first()
        if not row:
            return {"step": step.get("title"), "status": "failed", "error": "Incident not found"}

        inc, cn = row
        incident_data = {
            "id": inc.id, "ref": inc.ref, "title": inc.title,
            "severity": inc.severity, "category": inc.category,
            "description": inc.description, "client_name": cn,
            "affected_hosts": inc.affected_hosts,
        }

        from app.core.config import settings

        if system == "jira" and settings.JIRA_URL:
            from app.integrations.connectors import JiraConnector
            jira = JiraConnector(settings.JIRA_URL, settings.JIRA_USER, settings.JIRA_API_TOKEN)
            result_data = await jira.create_ticket(incident_data)
            inc.jira_ticket_id = result_data.get("ticket_id")
            await self.db.commit()
            return {"step": step.get("title"), "status": "success", "ticket": result_data}

        elif system == "servicenow" and settings.SERVICENOW_URL:
            snow = ServiceNowConnector(settings.SERVICENOW_URL, settings.SERVICENOW_USER, settings.SERVICENOW_PASSWORD)
            result_data = await snow.create_incident(incident_data)
            return {"step": step.get("title"), "status": "success", "ticket": result_data}

        elif system == "pagerduty" and settings.PAGERDUTY_API_KEY:
            pd = PagerDutyConnector(settings.PAGERDUTY_API_KEY)
            r = await pd.trigger_incident(incident_data)
            inc.pagerduty_incident_id = r.get("dedup_key")
            await self.db.commit()
            return {"step": step.get("title"), "status": "success", "pagerduty": r}

        return {"step": step.get("title"), "status": "skipped", "reason": f"{system} not configured"}


# ─────────────────────────────────────────────────────────────
# BUILT-IN PLAYBOOK TEMPLATES
# ─────────────────────────────────────────────────────────────

BUILTIN_PLAYBOOKS = {
    "ransomware_response": {
        "name": "Ransomware Response Playbook",
        "description": "Resposta padrão NIST 800-61 para incidentes de ransomware",
        "trigger_conditions": {"category": ["ransomware"], "severity": ["critical", "high"]},
        "steps": [
            {
                "order": 1, "type": "notify", "phase": "identification",
                "title": "Notificar equipe de segurança",
                "notify_config": {"channels": ["slack", "pagerduty", "teams"]},
            },
            {
                "order": 2, "type": "ticket", "phase": "identification",
                "title": "Criar ticket ITSM",
                "ticket_config": {"system": "jira"},
            },
            {
                "order": 3, "type": "action", "phase": "containment",
                "title": "Isolar host comprometido (requer EDR)",
                "action_config": {"type": "isolate_host", "target": "{{affected_host_0}}"},
                "on_failure": "continue",
            },
            {
                "order": 4, "type": "action", "phase": "containment",
                "title": "Bloquear C2 IPs no firewall",
                "action_config": {"type": "block_ip", "target": "{{c2_ip}}"},
                "on_failure": "continue",
            },
            {
                "order": 5, "type": "manual", "phase": "eradication",
                "title": "Análise forense — snapshot da memória",
                "description": "Execute: volatility3 -f memory.dump windows.pslist",
                "estimated_minutes": 60,
            },
            {
                "order": 6, "type": "manual", "phase": "eradication",
                "title": "Identificar e remover persistência",
                "description": "Verificar: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, Scheduled Tasks, Services",
            },
            {
                "order": 7, "type": "manual", "phase": "recovery",
                "title": "Restaurar de backup limpo",
                "description": "Verificar integridade do backup antes de restaurar. Data do backup: anterior ao primeiro IOC.",
            },
            {
                "order": 8, "type": "notify", "phase": "lessons_learned",
                "title": "Notificar encerramento",
                "notify_config": {"channels": ["slack"]},
            },
        ],
    },

    "phishing_response": {
        "name": "Phishing Response Playbook",
        "description": "Resposta a campanha de phishing com potencial comprometimento de credenciais",
        "trigger_conditions": {"category": ["phishing"]},
        "steps": [
            {"order": 1, "type": "notify", "phase": "identification",
             "title": "Alertar equipe", "notify_config": {"channels": ["slack"]}},
            {"order": 2, "type": "ticket", "phase": "identification",
             "title": "Abrir ticket", "ticket_config": {"system": "jira"}},
            {"order": 3, "type": "action", "phase": "containment",
             "title": "Bloquear domínio de phishing no firewall",
             "action_config": {"type": "block_ip", "target": "{{phishing_domain}}"}, "on_failure": "continue"},
            {"order": 4, "type": "manual", "phase": "containment",
             "title": "Reset de credenciais dos usuários afetados",
             "description": "Forçar reset de senha + revogar tokens MFA para todos os usuários que clicaram no link."},
            {"order": 5, "type": "manual", "phase": "eradication",
             "title": "Verificar inbox rules maliciosas",
             "description": "Exchange/O365: Get-InboxRule -Mailbox <user> | Where-Object {$_.ForwardTo -ne $null}"},
            {"order": 6, "type": "manual", "phase": "recovery",
             "title": "Habilitar MFA para contas afetadas",
             "description": "Obrigatório após reset. Use Conditional Access no Azure AD."},
        ],
    },

    "data_breach_response": {
        "name": "Data Breach Response Playbook",
        "description": "Resposta a vazamento de dados — inclui notificações legais (LGPD/GDPR)",
        "trigger_conditions": {"category": ["data_breach"]},
        "steps": [
            {"order": 1, "type": "notify", "phase": "identification",
             "title": "URGENTE: Notificar CISO e Jurídico", "notify_config": {"channels": ["pagerduty", "teams"]}},
            {"order": 2, "type": "ticket", "phase": "identification",
             "title": "Criar ticket P1", "ticket_config": {"system": "servicenow"}},
            {"order": 3, "type": "action", "phase": "containment",
             "title": "Bloquear IP de exfiltração",
             "action_config": {"type": "block_ip", "target": "{{exfil_ip}}"}, "on_failure": "continue"},
            {"order": 4, "type": "manual", "phase": "containment",
             "title": "Revogar acessos de API keys expostas",
             "description": "Identificar e revogar todas as API keys, tokens OAuth e secrets que possam ter sido expostos."},
            {"order": 5, "type": "manual", "phase": "eradication",
             "title": "Mapear escopo do vazamento",
             "description": "Quantos registros, quais dados (PII, financeiro, saúde), qual período, quais sistemas."},
            {"order": 6, "type": "manual", "phase": "lessons_learned",
             "title": "Notificação ANPD (72h - LGPD Art. 48)",
             "description": "LGPD exige notificação à ANPD em até 72h após ciência do incidente quando houver risco aos titulares."},
        ],
    },
}
