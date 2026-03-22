from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models import User, Alert, Incident, Client

router = APIRouter()

@router.get("")
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    client_id: Optional[str] = None,
    unassigned: bool = False,
    page: int = 1,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [Client.organization_id == current_user.organization_id]
    if status:
        filters.append(Alert.status == status)
    if severity:
        filters.append(Alert.severity == severity)
    if source:
        filters.append(Alert.source == source)
    if client_id:
        filters.append(Alert.client_id == client_id)
    if unassigned:
        filters.append(Alert.incident_id == None)

    total = await db.execute(
        select(func.count()).select_from(Alert).join(Client, Alert.client_id == Client.id).where(and_(*filters))
    )
    result = await db.execute(
        select(Alert, Client.name.label("client_name"))
        .join(Client, Alert.client_id == Client.id)
        .where(and_(*filters))
        .order_by(Alert.ingested_at.desc())
        .offset((page - 1) * limit).limit(limit)
    )
    rows = result.all()
    return {
        "items": [{
            "id": a.id, "source": a.source, "title": a.title,
            "severity": a.severity, "status": a.status,
            "client_name": cn, "incident_id": a.incident_id,
            "external_id": a.external_id,
            "occurred_at": a.occurred_at.isoformat() if a.occurred_at else None,
            "ingested_at": a.ingested_at.isoformat(),
        } for a, cn in rows],
        "total": total.scalar(), "page": page, "limit": limit,
    }

@router.post("/{alert_id}/correlate")
async def correlate_to_incident(
    alert_id: str,
    body: dict,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alerta não encontrado")

    incident_id = body.get("incident_id")
    inc_result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
    )
    if not inc_result.scalar_one_or_none():
        raise HTTPException(404, "Incidente não encontrado")

    alert.incident_id = incident_id
    alert.status = "correlated"
    await db.commit()
    return {"message": "Alerta correlacionado ao incidente"}

@router.get("/{alert_id}/raw")
async def get_alert_raw(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404)
    return {"raw_data": alert.raw_data, "enrichment": alert.enrichment}
