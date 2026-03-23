from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from pydantic import BaseModel
from app.core.database import get_db
from app.core.security import get_current_user, require_analyst
from app.models import User, Incident, Client, Message, TimelineEvent
from app.services.ai_service import analyze_incident_stream, generate_executive_report

router = APIRouter()

class IncidentCreate(BaseModel):
    client_id: str
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    category: Optional[str] = None
    affected_hosts: List[str] = []
    affected_ips: List[str] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    assignee_id: Optional[str] = None

class MessageCreate(BaseModel):
    content: str

@router.get("")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    client_id: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [Incident.organization_id == current_user.organization_id]
    if status:
        filters.append(Incident.status == status)
    if severity:
        filters.append(Incident.severity == severity)
    if client_id:
        filters.append(Incident.client_id == client_id)

    total_result = await db.execute(select(func.count()).select_from(Incident).where(and_(*filters)))
    total = total_result.scalar()

    result = await db.execute(
        select(Incident, Client.name.label("client_name"))
        .join(Client, Incident.client_id == Client.id)
        .where(and_(*filters))
        .order_by(Incident.created_at.desc())
        .offset((page - 1) * limit).limit(limit)
    )
    rows = result.all()

    incidents = []
    for inc, client_name in rows:
        incidents.append({
            "id": inc.id, "ref": inc.ref, "title": inc.title,
            "severity": inc.severity, "status": inc.status,
            "category": inc.category, "client_name": client_name,
            "risk_score": inc.risk_score,
            "mitre_tactics": inc.mitre_tactics,
            "created_at": inc.created_at.isoformat(),
            "updated_at": inc.updated_at.isoformat(),
        })

    return {"items": incidents, "total": total, "page": page, "limit": limit}

@router.post("", status_code=201)
async def create_incident(
    body: IncidentCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    # Validate client belongs to org
    client_result = await db.execute(
        select(Client).where(Client.id == body.client_id, Client.organization_id == current_user.organization_id)
    )
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Cliente não encontrado")

    # Generate ref
    count_result = await db.execute(select(func.count()).select_from(Incident))
    count = count_result.scalar() or 0
    ref = f"INC-{datetime.now().year}-{str(count + 1).zfill(4)}"

    incident = Incident(
        organization_id=current_user.organization_id,
        client_id=body.client_id,
        assignee_id=current_user.id,
        ref=ref,
        title=body.title,
        description=body.description,
        severity=body.severity,
        category=body.category,
        affected_hosts=body.affected_hosts,
        affected_ips=body.affected_ips,
        detected_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    await db.flush()

    db.add(TimelineEvent(
        incident_id=incident.id,
        actor_id=current_user.id,
        event_type="incident_created",
        description=f"Incidente criado manualmente por {current_user.full_name}",
    ))
    await db.commit()

    # Trigger notifications async
    from app.workers.notification_tasks import notify_new_incident
    notify_new_incident.delay(incident.id)

    return {"id": incident.id, "ref": incident.ref, "title": incident.title}

@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Incident, Client.name.label("client_name"))
        .join(Client, Incident.client_id == Client.id)
        .where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(404, "Incidente não encontrado")
    inc, client_name = row

    # Load related counts
    from app.models import Alert, Action, IOC, Message as Msg
    alerts_count = await db.execute(select(func.count()).select_from(Alert).where(Alert.incident_id == incident_id))
    actions_count = await db.execute(select(func.count()).select_from(Action).where(Action.incident_id == incident_id))
    iocs_count = await db.execute(select(func.count()).select_from(IOC).where(IOC.incident_id == incident_id))
    msgs_count = await db.execute(select(func.count()).select_from(Msg).where(Msg.incident_id == incident_id))

    return {
        "id": inc.id, "ref": inc.ref, "title": inc.title,
        "description": inc.description, "severity": inc.severity,
        "status": inc.status, "category": inc.category,
        "client_id": inc.client_id, "client_name": client_name,
        "assignee_id": inc.assignee_id,
        "mitre_tactics": inc.mitre_tactics,
        "mitre_techniques": inc.mitre_techniques,
        "risk_score": inc.risk_score, "cvss_score": inc.cvss_score,
        "affected_hosts": inc.affected_hosts,
        "affected_users": inc.affected_users,
        "affected_ips": inc.affected_ips,
        "ai_summary": inc.ai_summary,
        "ai_recommendations": inc.ai_recommendations,
        "jira_ticket_id": inc.jira_ticket_id,
        "pagerduty_incident_id": inc.pagerduty_incident_id,
        "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
        "contained_at": inc.contained_at.isoformat() if inc.contained_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat(),
        "_counts": {
            "alerts": alerts_count.scalar(),
            "actions": actions_count.scalar(),
            "iocs": iocs_count.scalar(),
            "messages": msgs_count.scalar(),
        }
    }

@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incidente não encontrado")

    old_status = incident.status
    changes = []

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(incident, field, value)
        changes.append(f"{field}: {value}")

    # Status timestamps
    if body.status == "contained" and not incident.contained_at:
        incident.contained_at = datetime.now(timezone.utc)
    if body.status in ("closed", "resolved") and not incident.resolved_at:
        incident.resolved_at = datetime.now(timezone.utc)

    db.add(TimelineEvent(
        incident_id=incident_id,
        actor_id=current_user.id,
        event_type="status_change" if body.status else "incident_updated",
        description=f"Atualizado: {', '.join(changes)}",
    ))
    await db.commit()
    return {"message": "Incidente atualizado"}

@router.get("/{incident_id}/messages")
async def get_messages(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Validate access
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Incidente não encontrado")

    msgs_result = await db.execute(
        select(Message).where(Message.incident_id == incident_id).order_by(Message.created_at)
    )
    messages = msgs_result.scalars().all()
    return [{"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at.isoformat()} for m in messages]

@router.post("/{incident_id}/messages/stream")
async def send_message_stream(
    incident_id: str,
    body: MessageCreate,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Stream de resposta AI para chat do incidente."""
    result = await db.execute(
        select(Incident, Client.name.label("client_name"))
        .join(Client, Incident.client_id == Client.id)
        .where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(404, "Incidente não encontrado")
    incident, client_name = row

    # Save user message
    user_msg = Message(
        incident_id=incident_id,
        role="user",
        content=body.content,
        author_id=current_user.id,
    )
    db.add(user_msg)
    await db.commit()

    # Load recent messages for context
    msgs_result = await db.execute(
        select(Message).where(Message.incident_id == incident_id)
        .order_by(Message.created_at.desc()).limit(30)
    )
    messages = list(reversed(msgs_result.scalars().all()))
    api_messages = [{"role": m.role if m.role != "assistant" else "assistant", "content": m.content} for m in messages]

    incident_context = {
        "ref": incident.ref, "title": incident.title,
        "severity": incident.severity, "status": incident.status,
        "category": incident.category, "client_name": client_name,
        "affected_hosts": incident.affected_hosts,
        "affected_ips": incident.affected_ips,
        "mitre_tactics": incident.mitre_tactics,
    }

    full_response = []

    async def stream_and_save():
        async for chunk in analyze_incident_stream(api_messages, incident_context):
            full_response.append(chunk)
            yield chunk

        # Save AI response after streaming
        ai_content = "".join(full_response)
        async with db.begin():
            ai_msg = Message(
                incident_id=incident_id,
                role="assistant",
                content=ai_content,
            )
            db.add(ai_msg)

    return StreamingResponse(stream_and_save(), media_type="text/plain")

@router.get("/{incident_id}/timeline")
async def get_timeline(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.occurred_at)
    )
    events = result.scalars().all()
    return [{"id": e.id, "event_type": e.event_type, "description": e.description,
             "metadata": e.extra_data, "occurred_at": e.occurred_at.isoformat()} for e in events]

@router.post("/{incident_id}/report")
async def generate_report(
    incident_id: str,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Incident, Client.name.label("client_name"))
        .join(Client, Incident.client_id == Client.id)
        .where(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(404)
    incident, client_name = row

    msgs_result = await db.execute(
        select(Message).where(Message.incident_id == incident_id).order_by(Message.created_at).limit(50)
    )
    messages = [{"role": m.role, "content": m.content} for m in msgs_result.scalars().all()]

    incident_data = {
        "ref": incident.ref, "title": incident.title, "severity": incident.severity,
        "status": incident.status, "category": incident.category, "client": client_name,
        "affected_hosts": incident.affected_hosts, "affected_ips": incident.affected_ips,
        "mitre_tactics": incident.mitre_tactics, "mitre_techniques": incident.mitre_techniques,
        "detected_at": str(incident.detected_at), "resolved_at": str(incident.resolved_at),
    }

    report = await generate_executive_report(incident_data, messages)
    return {"report": report, "incident_ref": incident.ref}
