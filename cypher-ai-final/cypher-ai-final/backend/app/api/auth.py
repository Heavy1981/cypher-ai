from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from app.core.database import get_db
from app.core.security import (
    verify_password, hash_password, create_access_token,
    create_refresh_token, decode_token, get_current_user,
)
from app.models import User

router = APIRouter()

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    access_token = create_access_token({"sub": user.id, "org": user.organization_id, "role": user.role})
    return TokenResponse(
        access_token=access_token,
        refresh_token=create_refresh_token(user.id),
        user={"id": user.id, "email": user.email, "full_name": user.full_name,
              "role": user.role, "organization_id": user.organization_id},
    )

@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email,
            "full_name": current_user.full_name, "role": current_user.role,
            "organization_id": current_user.organization_id}
