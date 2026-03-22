from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user, require_admin
from app.models import User, Organization

router = APIRouter()

@router.get("")
async def list_organizations(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Organization).where(Organization.is_active == True))
    orgs = result.scalars().all()
    return [{"id": o.id, "name": o.name, "slug": o.slug, "plan": o.plan} for o in orgs]

@router.get("/me")
async def my_organization(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Organization).where(Organization.id == current_user.organization_id))
    org = result.scalar_one_or_none()
    if not org:
        from fastapi import HTTPException
        raise HTTPException(404, "Organização não encontrada")
    return {"id": org.id, "name": org.name, "slug": org.slug, "plan": org.plan, "settings": org.settings}
