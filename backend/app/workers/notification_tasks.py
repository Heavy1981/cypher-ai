"""Notification Tasks"""
import asyncio
import structlog
from app.workers.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models import Incident, Client
from app.integrations.connectors import SlackConnector
from app.core.config import settings
from sqlalchemy import select

logger = structlog.get_logger()


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task
def notify_new_incident(incident_id: str):
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Incident, Client)
                .join(Client, Incident.client_id == Client.id)
                .where(Incident.id == incident_id)
            )
            row = result.first()
            if not row:
                return
            incident, client = row

            if settings.SLACK_BOT_TOKEN:
                slack = SlackConnector(settings.SLACK_BOT_TOKEN)
                await slack.send_incident_alert({
                    "ref": incident.ref,
                    "title": incident.title,
                    "severity": incident.severity,
                    "client_name": client.name,
                })

    return run_async(_run())


@celery_app.task
def send_daily_report():
    async def _run():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import func
            from app.models import Organization
            orgs_result = await db.execute(select(Organization).where(Organization.is_active == True))
            organizations = orgs_result.scalars().all()

            for org in organizations:
                result = await db.execute(
                    select(
                        func.count(Incident.id).label("total"),
                        func.count(Incident.id).filter(Incident.severity == "critical").label("critical"),
                        func.count(Incident.id).filter(Incident.status == "open").label("open"),
                    ).where(
                        Incident.organization_id == org.id,
                        Incident.status != "closed",
                    )
                )
                stats = result.first()
                logger.info("daily_report", org_id=org.id, org_name=org.name,
                            total=stats.total, critical=stats.critical, open=stats.open)

    return run_async(_run())
