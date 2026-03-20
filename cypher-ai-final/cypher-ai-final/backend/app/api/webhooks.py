"""
Webhook endpoints — recebe alertas em tempo real de SIEMs e EDRs
"""
from fastapi import APIRouter, Request, HTTPException, Header
from typing import Optional
import hmac, hashlib
from app.core.database import AsyncSessionLocal
from app.models import Integration
from sqlalchemy import select
from app.workers.alert_tasks import ingest_webhook_alert

router = APIRouter()

@router.post("/ingest/{integration_id}")
async def ingest_webhook(
    integration_id: str,
    request: Request,
    x_cypher_secret: Optional[str] = Header(None),
):
    """
    Endpoint universal de webhook para receber alertas.
    Configure a URL nos SIEMs/EDRs como:
    POST https://cypher.yourdomain.com/api/v1/webhooks/ingest/{integration_id}
    Header: X-Cypher-Secret: <seu_secret>
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Integration).where(Integration.id == integration_id, Integration.is_active == True)
        )
        integration = result.scalar_one_or_none()
        if not integration:
            raise HTTPException(404, "Integration not found")

        # Validate secret if configured
        webhook_secret = integration.config.get("webhook_secret")
        if webhook_secret and x_cypher_secret != webhook_secret:
            raise HTTPException(401, "Invalid webhook secret")

    payload = await request.json()
    ingest_webhook_alert.apply_async(args=[payload, integration_id], queue="alerts")
    return {"status": "accepted", "message": "Alert queued for processing"}


@router.post("/crowdstrike/{integration_id}")
async def crowdstrike_webhook(integration_id: str, request: Request):
    """CrowdStrike SIEM Connector webhook."""
    body = await request.json()
    events = body if isinstance(body, list) else [body]
    for event in events:
        ingest_webhook_alert.apply_async(args=[event, integration_id], queue="alerts")
    return {"status": "ok"}


@router.post("/sentinelone/{integration_id}")
async def sentinelone_webhook(integration_id: str, request: Request):
    """SentinelOne webhook callback."""
    payload = await request.json()
    ingest_webhook_alert.apply_async(args=[payload, integration_id], queue="alerts")
    return {"status": "ok"}


@router.post("/elastic/{integration_id}")
async def elastic_webhook(integration_id: str, request: Request):
    """Kibana/Elastic alerting webhook."""
    payload = await request.json()
    ingest_webhook_alert.apply_async(args=[payload, integration_id], queue="alerts")
    return {"status": "ok"}
