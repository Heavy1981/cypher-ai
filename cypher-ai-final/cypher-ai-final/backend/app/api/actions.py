from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_db
from app.core.security import require_analyst, get_current_user
from app.models import User, Action, Incident
from app.workers.action_tasks import execute_action

router = APIRouter()

class ActionCreate(BaseModel):
    incident_id: str
    type: str
    target: str
    integration_id: Optional[str] = None
    parameters: dict = {}

ACTION_TYPES = [
    "isolate_host", "block_ip", "block_hash", "kill_process",
    "disable_user", "quarantine_file", "create_ticket",
    "send_notification", "reset_password",
]

@router.get("/types")
async def get_action_types():
    return {"types": ACTION_TYPES}

@router.get("")
async def list_actions(
    incident_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import and_
    filters = []
    if incident_id:
        filters.append(Action.incident_id == incident_id)
    result = await db.execute(
        select(Action).where(and_(*filters) if filters else True).order_by(Action.created_at.desc())
    )
    actions = result.scalars().all()
    return [{
        "id": a.id, "type": a.type, "target": a.target,
        "status": a.status, "is_automated": a.is_automated,
        "can_rollback": a.can_rollback,
        "result": a.result, "error_message": a.error_message,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
        "created_at": a.created_at.isoformat(),
    } for a in actions]

@router.post("", status_code=201)
async def create_action(
    body: ActionCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    if body.type not in ACTION_TYPES:
        raise HTTPException(400, f"Tipo inválido. Válidos: {ACTION_TYPES}")

    # Verify incident access
    inc_result = await db.execute(
        select(Incident).where(Incident.id == body.incident_id, Incident.organization_id == current_user.organization_id)
    )
    if not inc_result.scalar_one_or_none():
        raise HTTPException(404, "Incidente não encontrado")

    action = Action(
        incident_id=body.incident_id,
        integration_id=body.integration_id,
        triggered_by_id=current_user.id,
        type=body.type,
        target=body.target,
        parameters=body.parameters,
        is_automated=False,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)

    # Dispatch to Celery
    execute_action.apply_async(args=[action.id], queue="actions")

    return {"id": action.id, "status": "pending", "message": "Ação enfileirada para execução"}
