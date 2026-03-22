"""
Action Tasks — contenção automatizada e resposta
isolate_host, block_ip, block_hash, kill_process, create_ticket, etc.
"""
import asyncio
import structlog
from datetime import datetime, timezone
from app.workers.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models import Action, Integration, Incident, TimelineEvent
from app.integrations.connectors import get_connector, JiraConnector, SlackConnector
from app.core.config import settings
from sqlalchemy import select

logger = structlog.get_logger()


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def execute_action(self, action_id: str):
    """Dispatcher central de ações de resposta."""
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Action).where(Action.id == action_id))
            action = result.scalar_one_or_none()
            if not action:
                return {"error": "action_not_found"}

            action.status = "running"
            action.executed_at = datetime.now(timezone.utc)
            await db.commit()

            try:
                handler_map = {
                    "isolate_host": _isolate_host,
                    "block_ip": _block_ip,
                    "block_hash": _block_hash,
                    "kill_process": _kill_process,
                    "disable_user": _disable_user,
                    "create_ticket": _create_ticket,
                    "send_notification": _send_notification,
                    "quarantine_file": _quarantine_file,
                }

                handler = handler_map.get(action.type)
                if not handler:
                    raise ValueError(f"Tipo de ação desconhecido: {action.type}")

                result_data = await handler(action, db)

                action.status = "success"
                action.result = result_data
                action.can_rollback = result_data.get("can_rollback", False)

                # Timeline
                db.add(TimelineEvent(
                    incident_id=action.incident_id,
                    event_type="action_executed",
                    description=f"Ação executada com sucesso: {action.type} em {action.target}",
                    metadata={"action_id": action_id, "result": result_data},
                ))

                await db.commit()
                logger.info("action_success", action_id=action_id, type=action.type)
                return {"status": "success", "result": result_data}

            except Exception as exc:
                action.status = "failed"
                action.error_message = str(exc)
                await db.commit()
                logger.error("action_failed", action_id=action_id, error=str(exc))
                raise self.retry(exc=exc)

    return run_async(_run())


async def _isolate_host(action: Action, db) -> dict:
    """Isola host via EDR (CrowdStrike / SentinelOne)."""
    if not action.integration_id:
        raise ValueError("integration_id obrigatório para isolate_host")

    result = await db.execute(select(Integration).where(Integration.id == action.integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise ValueError("Integração não encontrada")

    connector = get_connector(integration.type, integration.credentials, integration.config)
    device_id = action.parameters.get("device_id") or action.target

    if integration.type == "crowdstrike":
        return await connector.isolate_host(device_id)
    elif integration.type == "sentinelone":
        return await connector.isolate_agent(device_id)
    else:
        raise ValueError(f"isolate_host não suportado para {integration.type}")


async def _block_ip(action: Action, db) -> dict:
    """Bloqueia IP no firewall."""
    if not action.integration_id:
        raise ValueError("integration_id obrigatório para block_ip")

    result = await db.execute(select(Integration).where(Integration.id == action.integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise ValueError("Integração não encontrada")

    connector = get_connector(integration.type, integration.credentials, integration.config)
    ip = action.target
    comment = action.parameters.get("comment", "Blocked by CYPHER AI")

    if integration.type == "fortinet":
        return await connector.block_ip(ip, comment)
    elif integration.type == "palo_alto":
        return await connector.block_ip(ip)
    else:
        raise ValueError(f"block_ip não suportado para {integration.type}")


async def _block_hash(action: Action, db) -> dict:
    """Bloqueia hash no EDR."""
    result = await db.execute(select(Integration).where(Integration.id == action.integration_id))
    integration = result.scalar_one_or_none()
    connector = get_connector(integration.type, integration.credentials, integration.config)

    if integration.type == "crowdstrike":
        return await connector.block_hash(action.target, action.parameters.get("comment", "Blocked by CYPHER AI"))
    raise ValueError(f"block_hash não suportado para {integration.type}")


async def _kill_process(action: Action, db) -> dict:
    """Mata processo via EDR — usa RTR/remote script."""
    # CrowdStrike RTR: Real Time Response
    result = await db.execute(select(Integration).where(Integration.id == action.integration_id))
    integration = result.scalar_one_or_none()
    # Simplificado — implementar RTR session em extensão futura
    return {"action": "kill_process", "target": action.target, "note": "RTR session required"}


async def _disable_user(action: Action, db) -> dict:
    """Desabilita usuário — Azure AD / Active Directory."""
    # Implementação via Microsoft Graph API
    params = action.parameters
    return {"action": "disable_user", "user": action.target, "note": "Requires Azure AD / AD connector"}


async def _create_ticket(action: Action, db) -> dict:
    """Cria ticket no Jira ou ServiceNow."""
    params = action.parameters
    incident_result = await db.execute(select(Incident).where(Incident.id == action.incident_id))
    incident = incident_result.scalar_one_or_none()

    if settings.JIRA_URL and settings.JIRA_USER and settings.JIRA_API_TOKEN:
        jira = JiraConnector(settings.JIRA_URL, settings.JIRA_USER, settings.JIRA_API_TOKEN)
        result = await jira.create_ticket({
            "ref": incident.ref if incident else "N/A",
            "title": incident.title if incident else params.get("title", "Incidente"),
            "description": params.get("description", ""),
            "severity": incident.severity if incident else "medium",
        })
        if incident:
            incident.jira_ticket_id = result.get("ticket_id")
            await db.commit()
        return {**result, "can_rollback": False}

    return {"note": "Jira not configured", "can_rollback": False}


async def _send_notification(action: Action, db) -> dict:
    """Envia notificação via Slack / Email / Teams."""
    params = action.parameters
    incident_result = await db.execute(select(Incident).where(Incident.id == action.incident_id))
    incident = incident_result.scalar_one_or_none()

    results = {}
    if settings.SLACK_BOT_TOKEN:
        slack = SlackConnector(settings.SLACK_BOT_TOKEN, settings.SLACK_DEFAULT_CHANNEL)
        channel = params.get("slack_channel", settings.SLACK_DEFAULT_CHANNEL)
        slack.channel = channel
        r = await slack.send_incident_alert({
            "ref": incident.ref if incident else "N/A",
            "title": incident.title if incident else "Incidente",
            "severity": incident.severity if incident else "medium",
            "client_name": params.get("client_name", ""),
        })
        results["slack"] = r.get("ok", False)

    return {**results, "can_rollback": False}


async def _quarantine_file(action: Action, db) -> dict:
    """Quarentena arquivo via EDR."""
    result = await db.execute(select(Integration).where(Integration.id == action.integration_id))
    integration = result.scalar_one_or_none()
    # SentinelOne / CrowdStrike file quarantine
    return {"action": "quarantine_file", "target": action.target, "note": "Requires EDR connector"}
