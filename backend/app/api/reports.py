from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.core.database import get_db
from app.core.security import get_current_user
from app.models import User, Incident, Alert, Action

router = APIRouter()

@router.get("/dashboard")
async def get_dashboard(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id

    # Incidents by severity
    sev_result = await db.execute(
        select(Incident.severity, func.count(Incident.id).label("count"))
        .where(Incident.organization_id == org_id, Incident.status != "closed")
        .group_by(Incident.severity)
    )
    by_severity = {row.severity: row.count for row in sev_result.all()}

    # Incidents by status
    status_result = await db.execute(
        select(Incident.status, func.count(Incident.id).label("count"))
        .where(Incident.organization_id == org_id)
        .group_by(Incident.status)
    )
    by_status = {row.status: row.count for row in status_result.all()}

    # Recent incidents
    recent_result = await db.execute(
        select(Incident).where(Incident.organization_id == org_id)
        .order_by(Incident.created_at.desc()).limit(5)
    )
    recent = recent_result.scalars().all()

    # MTTD and MTTR
    from datetime import datetime, timezone, timedelta
    last_30d = datetime.now(timezone.utc) - timedelta(days=30)
    resolved = await db.execute(
        select(Incident).where(
            Incident.organization_id == org_id,
            Incident.resolved_at != None,
            Incident.created_at >= last_30d,
        )
    )
    resolved_list = resolved.scalars().all()
    mttr_hours = 0
    if resolved_list:
        total_seconds = sum(
            (i.resolved_at - i.created_at).total_seconds()
            for i in resolved_list if i.resolved_at and i.created_at
        )
        mttr_hours = round(total_seconds / 3600 / len(resolved_list), 1)

    return {
        "incidents_by_severity": by_severity,
        "incidents_by_status": by_status,
        "total_open": sum(v for k, v in by_status.items() if k not in ("closed", "false_positive")),
        "total_critical": by_severity.get("critical", 0),
        "mttr_hours_30d": mttr_hours,
        "resolved_last_30d": len(resolved_list),
        "recent_incidents": [{
            "id": i.id, "ref": i.ref, "title": i.title,
            "severity": i.severity, "status": i.status,
            "created_at": i.created_at.isoformat(),
        } for i in recent],
    }
