from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from app.core.database import get_db
from app.core.security import require_analyst, get_current_user
from app.models import User, IOC, Incident
from app.workers.enrichment_tasks import enrich_ioc_now

router = APIRouter()

class IOCCreate(BaseModel):
    incident_id: str
    type: str  # ip | domain | url | file_hash | email
    value: str
    confidence: float = 0.8
    tags: list = []
    context: dict = {}

@router.get("")
async def list_iocs(
    incident_id: Optional[str] = None,
    ioc_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import and_
    filters = [IOC.organization_id == current_user.organization_id]
    if incident_id:
        filters.append(IOC.incident_id == incident_id)
    if ioc_type:
        filters.append(IOC.type == ioc_type)

    result = await db.execute(
        select(IOC).where(and_(*filters)).order_by(IOC.first_seen.desc()).limit(500)
    )
    iocs = result.scalars().all()
    return [{
        "id": i.id, "type": i.type, "value": i.value,
        "confidence": i.confidence, "tags": i.tags,
        "vt_result": i.vt_result, "abuse_score": i.abuse_score,
        "first_seen": i.first_seen.isoformat(),
    } for i in iocs]

@router.post("", status_code=201)
async def create_ioc(
    body: IOCCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    inc_result = await db.execute(
        select(Incident).where(Incident.id == body.incident_id, Incident.organization_id == current_user.organization_id)
    )
    if not inc_result.scalar_one_or_none():
        raise HTTPException(404, "Incidente não encontrado")

    ioc = IOC(
        incident_id=body.incident_id,
        organization_id=current_user.organization_id,
        type=body.type,
        value=body.value,
        confidence=body.confidence,
        tags=body.tags,
        context=body.context,
    )
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)

    # Enrich immediately
    enrich_ioc_now.delay(ioc.id)
    return {"id": ioc.id, "type": ioc.type, "value": ioc.value, "message": "IOC criado e enriquecimento iniciado"}

@router.post("/{ioc_id}/enrich")
async def force_enrich(
    ioc_id: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    enrich_ioc_now.delay(ioc_id)
    return {"message": "Enriquecimento iniciado"}
