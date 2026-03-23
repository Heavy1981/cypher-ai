"""
Alert Tasks — ingestão, correlação e triagem automática
"""
import asyncio
import structlog
from app.workers.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models import Integration, Alert, Incident, Client, Organization
from app.integrations.connectors import get_connector
from app.services.ai_service import analyze_alert_batch
from sqlalchemy import select, and_

logger = structlog.get_logger()


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def poll_integration(self, integration_id: str):
    """Puxa alertas de uma integração específica."""
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Integration).where(
                    Integration.id == integration_id,
                    Integration.is_active == True
                )
            )
            integration = result.scalar_one_or_none()
            if not integration:
                return {"status": "skipped", "reason": "integration_not_found"}

            try:
                connector = get_connector(integration.type, integration.credentials, integration.config)
                raw_alerts = await connector.fetch_alerts(since_minutes=6)  # slight overlap

                new_count = 0
                for raw in raw_alerts:
                    # Verifica duplicata
                    existing = await db.execute(
                        select(Alert).where(
                            Alert.external_id == raw.get("external_id"),
                            Alert.integration_id == integration_id
                        )
                    )
                    if existing.scalar_one_or_none():
                        continue

                    alert = Alert(
                        client_id=integration.client_id,
                        integration_id=integration_id,
                        external_id=raw.get("external_id"),
                        source=raw.get("source", integration.type),
                        title=raw.get("title", "Unknown Alert"),
                        description=raw.get("description", ""),
                        severity=raw.get("severity", "medium"),
                        raw_data=raw.get("raw_data", {}),
                        occurred_at=raw.get("occurred_at"),
                    )
                    db.add(alert)
                    new_count += 1

                # Atualiza last_sync
                from datetime import datetime, timezone
                integration.last_sync = datetime.now(timezone.utc)
                integration.health_status = "healthy"

                await db.commit()
                logger.info("alerts_ingested", integration_id=integration_id, count=new_count)

                # Dispara correlação se houver novos alertas
                if new_count > 0:
                    correlate_unassigned_alerts.delay()

                return {"status": "ok", "new_alerts": new_count}

            except Exception as exc:
                integration.health_status = "degraded"
                await db.commit()
                logger.error("integration_poll_failed", integration_id=integration_id, error=str(exc))
                raise self.retry(exc=exc)

    return run_async(_run())


@celery_app.task
def poll_all_integrations():
    """Dispara poll para todas as integrações ativas."""
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Integration).where(Integration.is_active == True)
            )
            integrations = result.scalars().all()
            for integration in integrations:
                poll_integration.apply_async(
                    args=[integration.id],
                    queue="alerts",
                )
            return {"dispatched": len(integrations)}

    return run_async(_run())


@celery_app.task
def health_check_all_integrations():
    """Health check de todas as integrações."""
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Integration).where(Integration.is_active == True)
            )
            integrations = result.scalars().all()

            for integration in integrations:
                try:
                    connector = get_connector(integration.type, integration.credentials, integration.config)
                    health = await connector.health_check()
                    from datetime import datetime, timezone
                    integration.health_status = health.get("status", "unknown")
                    integration.last_health_check = datetime.now(timezone.utc)
                except Exception as e:
                    integration.health_status = "offline"
                    logger.warning("health_check_failed", integration_id=integration.id, error=str(e))

            await db.commit()
            return {"checked": len(integrations)}

    return run_async(_run())


@celery_app.task
def correlate_unassigned_alerts():
    """
    Correlaciona alertas sem incidente usando IA.
    Agrupa por client_id, janela de 30 minutos, e chama AI para decisão.
    Usa distributed lock via Redis para evitar race condition entre workers.
    """
    async def _run():
        import redis.asyncio as aioredis
        from app.core.config import settings
        redis_client = aioredis.from_url(settings.REDIS_URL)
        lock_key = "lock:correlate_unassigned_alerts"
        lock_ttl = 120  # segundos

        acquired = await redis_client.set(lock_key, "1", nx=True, ex=lock_ttl)
        if not acquired:
            logger.info("correlation_skipped", reason="lock_held_by_another_worker")
            await redis_client.aclose()
            return {"correlated": 0, "skipped": True}

        try:
            return await _do_correlate()
        finally:
            await redis_client.delete(lock_key)
            await redis_client.aclose()

    async def _do_correlate():
        from datetime import datetime, timedelta, timezone
        window_start = datetime.now(timezone.utc) - timedelta(minutes=30)

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Alert).where(
                    and_(
                        Alert.incident_id == None,
                        Alert.status == "new",
                        Alert.ingested_at >= window_start,
                    )
                ).order_by(Alert.client_id, Alert.ingested_at)
            )
            alerts = result.scalars().all()
            if not alerts:
                return {"correlated": 0}

            # Agrupa por client
            from itertools import groupby
            from operator import attrgetter
            alerts_sorted = sorted(alerts, key=attrgetter("client_id"))

            created_incidents = 0
            for client_id, group in groupby(alerts_sorted, key=attrgetter("client_id")):
                client_alerts = list(group)
                alerts_data = [
                    {
                        "title": a.title,
                        "description": a.description,
                        "severity": a.severity,
                        "source": a.source,
                    }
                    for a in client_alerts
                ]

                # AI decide se deve criar incidente
                analysis = await analyze_alert_batch(alerts_data)
                if not analysis.get("should_create_incident", False):
                    # Marca como triados
                    for a in client_alerts:
                        a.status = "triaged"
                    continue

                # Busca info do cliente
                client_result = await db.execute(select(Client).where(Client.id == client_id))
                client = client_result.scalar_one_or_none()
                if not client:
                    continue

                # Cria incidente
                import uuid
                from app.models import TimelineEvent
                from app.models import CorrelationRule  # noqa

                # Gera ref único usando uuid para evitar race condition
                from datetime import datetime
                ref = f"INC-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"

                incident = Incident(
                    organization_id=client.organization_id,
                    client_id=client_id,
                    ref=ref,
                    title=analysis.get("suggested_title", f"Incidente correlacionado — {len(client_alerts)} alertas"),
                    severity=analysis.get("priority", "medium"),
                    category=analysis.get("suggested_category"),
                    status="open",
                    mitre_tactics=analysis.get("mitre_tactics", []),
                    mitre_techniques=analysis.get("mitre_techniques", []),
                    risk_score=analysis.get("risk_score"),
                    ai_summary=analysis.get("summary"),
                    ai_recommendations=analysis.get("immediate_actions", []),
                )
                db.add(incident)
                await db.flush()  # get incident.id

                # Associa alertas ao incidente
                for alert in client_alerts:
                    alert.incident_id = incident.id
                    alert.status = "correlated"

                # Timeline
                db.add(TimelineEvent(
                    incident_id=incident.id,
                    event_type="incident_created",
                    description=f"Incidente criado automaticamente pela correlação de {len(client_alerts)} alertas",
                    extra_data={"alert_count": len(client_alerts), "ai_analysis": analysis},
                ))

                await db.commit()
                created_incidents += 1

                # Notifica
                notify_new_incident.delay(incident.id)

                logger.info("incident_auto_created", incident_id=incident.id, ref=ref, alerts=len(client_alerts))

            return {"correlated": created_incidents}

    return run_async(_run())


@celery_app.task
def ingest_webhook_alert(payload: dict, integration_id: str):
    """Processa alerta recebido via webhook em tempo real."""
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Integration).where(Integration.id == integration_id))
            integration = result.scalar_one_or_none()
            if not integration:
                return

            alert = Alert(
                client_id=integration.client_id,
                integration_id=integration_id,
                external_id=payload.get("id") or payload.get("alertId"),
                source=integration.type,
                title=payload.get("title") or payload.get("name", "Webhook Alert"),
                description=payload.get("description", ""),
                severity=payload.get("severity", "medium").lower(),
                raw_data=payload,
            )
            db.add(alert)
            await db.commit()

            # Correlação imediata para alta severidade
            if alert.severity in ("critical", "high"):
                correlate_unassigned_alerts.apply_async(countdown=10)

    return run_async(_run())


# Import circular fix
from app.workers.notification_tasks import notify_new_incident  # noqa
