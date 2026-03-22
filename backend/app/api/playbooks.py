from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_db
from app.core.security import require_analyst, get_current_user
from app.models import User, Playbook, Incident
from app.services.ai_service import suggest_playbook

router = APIRouter()

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_conditions: dict = {}
    steps: list = []
    is_automated: bool = False

@router.get("")
async def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Playbook).where(
            Playbook.organization_id == current_user.organization_id,
            Playbook.is_active == True
        ).order_by(Playbook.name)
    )
    playbooks = result.scalars().all()
    return [{
        "id": p.id, "name": p.name, "description": p.description,
        "is_automated": p.is_automated,
        "trigger_conditions": p.trigger_conditions,
        "steps_count": len(p.steps),
    } for p in playbooks]

@router.post("", status_code=201)
async def create_playbook(
    body: PlaybookCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    playbook = Playbook(
        organization_id=current_user.organization_id,
        name=body.name,
        description=body.description,
        trigger_conditions=body.trigger_conditions,
        steps=body.steps,
        is_automated=body.is_automated,
    )
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)
    return {"id": playbook.id, "name": playbook.name}

@router.post("/generate")
async def generate_playbook_from_incident(
    body: dict,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Usa AI para gerar um playbook baseado no tipo de incidente."""
    incident_id = body.get("incident_id")
    if incident_id:
        result = await db.execute(
            select(Incident).where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        )
        incident = result.scalar_one_or_none()
        if not incident:
            raise HTTPException(404)
        data = {"title": incident.title, "category": incident.category, "severity": incident.severity}
    else:
        data = body

    playbook = await suggest_playbook(data)
    return {"playbook": playbook}

@router.post("/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    body: dict,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Executa um playbook em um incidente."""
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id, Playbook.organization_id == current_user.organization_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(404)

    incident_id = body.get("incident_id")
    executed_steps = []

    for step in playbook.steps:
        for action_def in step.get("actions", []):
            if action_def.get("type") == "automated":
                from app.models import Action
                from app.workers.action_tasks import execute_action
                action = Action(
                    incident_id=incident_id,
                    type=action_def.get("tool", "send_notification"),
                    target=action_def.get("target", ""),
                    parameters=action_def,
                    is_automated=True,
                    triggered_by_id=current_user.id,
                )
                db.add(action)
                await db.flush()
                execute_action.apply_async(args=[action.id], queue="actions")
                executed_steps.append(step.get("title"))

    await db.commit()
    return {"message": f"Playbook executado. {len(executed_steps)} passos automatizados.", "steps": executed_steps}
