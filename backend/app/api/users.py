"""Users API"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from app.core.database import get_db
from app.core.security import require_admin, get_current_user, hash_password
from app.models import User, Organization

router = APIRouter(prefix="/users")


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: str = "analyst"


@router.get("")
async def list_users(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.organization_id == current_user.organization_id)
    )
    users = result.scalars().all()
    return [{"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role,
              "is_active": u.is_active, "last_login": u.last_login} for u in users]


@router.post("", status_code=201)
async def create_user(
    body: UserCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(User).where(User.email == body.email.lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Email já cadastrado")

    user = User(
        organization_id=current_user.organization_id,
        email=body.email.lower(),
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"id": user.id, "email": user.email, "role": user.role}
