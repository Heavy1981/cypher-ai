from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models import User, Client

router = APIRouter()

class ClientCreate(BaseModel):
    name: str
    industry: Optional[str] = None
    contact_email: Optional[str] = None
    risk_profile: str = "medium"

@router.get("")
async def list_clients(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    filters = [Client.organization_id == current_user.organization_id, Client.is_active == True]
    total = (await db.execute(select(func.count()).select_from(Client).where(*filters))).scalar()
    result = await db.execute(
        select(Client).where(*filters).order_by(Client.name)
        .offset((page - 1) * limit).limit(limit)
    )
    clients = result.scalars().all()
    return {
        "items": [{"id": c.id, "name": c.name, "industry": c.industry,
                   "risk_profile": c.risk_profile, "contact_email": c.contact_email} for c in clients],
        "total": total, "page": page, "limit": limit,
    }

@router.post("", status_code=201)
async def create_client(
    body: ClientCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    client = Client(
        organization_id=current_user.organization_id,
        name=body.name,
        industry=body.industry,
        contact_email=body.contact_email,
        risk_profile=body.risk_profile,
    )
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return {"id": client.id, "name": client.name}

@router.delete("/{client_id}")
async def delete_client(
    client_id: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Client).where(Client.id == client_id, Client.organization_id == current_user.organization_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Cliente não encontrado")
    client.is_active = False
    await db.commit()
    return {"message": "Cliente desativado"}
