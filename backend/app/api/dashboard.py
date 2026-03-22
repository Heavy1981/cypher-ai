"""Dashboard API — metrics, KPIs, trend data"""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.core.database import get_db
from app.core.security import get_current_user
from app.models import Incident, Alert, Action, IOC, Integration, Client, User

router = APIRouter(prefix="/dashboard")


@router.get("/metrics")
async def get_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    since_7d = now - timedelta(days=7)
    since_30d = now - timedelta(days=30)

    # Active incidents
    open_incidents = (await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.organization_id == org_id,
            Incident.status.in_(["open", "investigating"])
        )
    )).scalar()

    # Critical incidents
    critical = (await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.organization_id == org_id,
            Incident.severity == "critical",
            Incident.status != "closed"
        )
    )).scalar()

    # New incidents last 24h
    new_24h = (await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.organization_id == org_id,
            Incident.created_at >= since_24h
        )
    )).scalar()

    # New alerts last 24h (via client join)
    new_alerts_24h = (await db.execute(
        select(func.count()).select_from(Alert).join(Client, Alert.client_id == Client.id).where(
            Client.organization_id == org_id,
            Alert.ingested_at >= since_24h
        )
    )).scalar()

    # Actions executed (last 7d)
    actions_7d = (await db.execute(
        select(func.count()).select_from(Action).join(
            Incident, Action.incident_id == Incident.id
        ).where(
            Incident.organization_id == org_id,
            Action.status == "success",
            Action.executed_at >= since_7d
        )
    )).scalar()

    # MTTD — Mean Time to Detect (detected_at - created_at avg, last 30d)
    # MTTR — Mean Time to Resolve (resolved_at - created_at avg, last 30d)
    resolved_q = await db.execute(
        select(Incident.created_at, Incident.resolved_at).where(
            Incident.organization_id == org_id,
            Incident.resolved_at != None,
            Incident.created_at >= since_30d
        )
    )
    resolved_incidents = resolved_q.all()
    mttr_hours = None
    if resolved_incidents:
        total_hours = sum(
            (r.resolved_at - r.created_at).total_seconds() / 3600
            for r in resolved_incidents
        )
        mttr_hours = round(total_hours / len(resolved_incidents), 1)

    # Integration health
    integrations_result = await db.execute(
        select(Integration.health_status, func.count().label("count"))
        .join(Client, Integration.client_id == Client.id)
        .where(Client.organization_id == org_id, Integration.is_active == True)
        .group_by(Integration.health_status)
    )
    integration_health = {row.health_status: row.count for row in integrations_result}

    # By severity (open)
    by_severity = {}
    for sev in ["critical", "high", "medium", "low"]:
        c = (await db.execute(
            select(func.count()).select_from(Incident).where(
                Incident.organization_id == org_id,
                Incident.severity == sev,
                Incident.status.in_(["open", "investigating"])
            )
        )).scalar()
        by_severity[sev] = c

    # IOC count
    ioc_count = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.organization_id == org_id)
    )).scalar()

    # Active clients
    client_count = (await db.execute(
        select(func.count()).select_from(Client).where(
            Client.organization_id == org_id, Client.is_active == True
        )
    )).scalar()

    # Trend: incidents per day last 7 days
    trend = []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_count = (await db.execute(
            select(func.count()).select_from(Incident).where(
                Incident.organization_id == org_id,
                Incident.created_at >= day_start,
                Incident.created_at < day_end
            )
        )).scalar()
        trend.append({"date": day_start.strftime("%Y-%m-%d"), "count": day_count})

    return {
        "open_incidents": open_incidents,
        "critical_incidents": critical,
        "new_incidents_24h": new_24h,
        "new_alerts_24h": new_alerts_24h,
        "actions_executed_7d": actions_7d,
        "mttr_hours": mttr_hours,
        "by_severity": by_severity,
        "ioc_count": ioc_count,
        "client_count": client_count,
        "integration_health": integration_health,
        "incidents_trend_7d": trend,
    }
