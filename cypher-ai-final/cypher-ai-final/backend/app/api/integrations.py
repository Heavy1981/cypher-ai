from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models import User, Integration, Client
from app.integrations.connectors import get_connector

router = APIRouter()

class IntegrationCreate(BaseModel):
    client_id: str
    type: str
    name: str
    credentials: dict
    config: dict = {}

@router.get("")
async def list_integrations(
    client_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(Integration, Client.name.label("client_name")).join(Client, Integration.client_id == Client.id).where(
        Client.organization_id == current_user.organization_id, Integration.is_active == True
    )
    if client_id:
        query = query.where(Integration.client_id == client_id)
    result = await db.execute(query.order_by(Integration.type))
    rows = result.all()
    return [{
        "id": i.id, "type": i.type, "name": i.name,
        "client_id": i.client_id, "client_name": cn,
        "health_status": i.health_status,
        "last_sync": i.last_sync.isoformat() if i.last_sync else None,
        "last_health_check": i.last_health_check.isoformat() if i.last_health_check else None,
    } for i, cn in rows]

@router.post("", status_code=201)
async def create_integration(
    body: IntegrationCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    # Validate client
    client_result = await db.execute(
        select(Client).where(Client.id == body.client_id, Client.organization_id == current_user.organization_id)
    )
    if not client_result.scalar_one_or_none():
        raise HTTPException(404, "Cliente não encontrado")

    # Test connection before saving
    try:
        connector = get_connector(body.type, body.credentials, body.config)
        health = await connector.health_check()
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(422, f"Falha ao conectar: {str(e)}")

    integration = Integration(
        client_id=body.client_id,
        type=body.type,
        name=body.name,
        credentials=body.credentials,
        config=body.config,
        health_status=health.get("status", "unknown"),
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)
    return {"id": integration.id, "name": integration.name, "health": health}

@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(404)

    try:
        connector = get_connector(integration.type, integration.credentials, integration.config)
        health = await connector.health_check()
        integration.health_status = health.get("status", "unknown")
        from datetime import datetime, timezone
        integration.last_health_check = datetime.now(timezone.utc)
        await db.commit()
        return health
    except Exception as e:
        return {"status": "offline", "error": str(e)}

@router.post("/{integration_id}/poll")
async def trigger_poll(
    integration_id: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    from app.workers.alert_tasks import poll_integration
    poll_integration.apply_async(args=[integration_id], queue="alerts")
    return {"message": "Coleta iniciada em background"}

@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(404)
    integration.is_active = False
    await db.commit()
    return {"message": "Integração removida"}
