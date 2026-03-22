"""
CYPHER AI — Celery Workers
Tasks assíncronas: ingestão de alertas, enriquecimento, automações, notificações
"""
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

# ── Celery app ────────────────────────────────────────────────
celery_app = Celery(
    "cypher",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.workers.alert_tasks",
        "app.workers.action_tasks",
        "app.workers.ai_tasks",
        "app.workers.notification_tasks",
        "app.workers.enrichment_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.alert_tasks.*": {"queue": "alerts"},
        "app.workers.action_tasks.*": {"queue": "actions"},
        "app.workers.ai_tasks.*": {"queue": "ai"},
        "app.workers.notification_tasks.*": {"queue": "default"},
        "app.workers.enrichment_tasks.*": {"queue": "default"},
    },
    # Scheduled tasks (Beat)
    beat_schedule={
        # Puxa alertas de todas as integrações ativas a cada 5 minutos
        "poll-all-integrations": {
            "task": "app.workers.alert_tasks.poll_all_integrations",
            "schedule": crontab(minute="*/5"),
        },
        # Health check das integrações a cada 15 minutos
        "health-check-integrations": {
            "task": "app.workers.alert_tasks.health_check_all_integrations",
            "schedule": crontab(minute="*/15"),
        },
        # Correlação de alertas não atribuídos a cada 2 minutos
        "correlate-unassigned-alerts": {
            "task": "app.workers.alert_tasks.correlate_unassigned_alerts",
            "schedule": crontab(minute="*/2"),
        },
        # Enriquecimento de IOCs pendentes a cada 10 minutos
        "enrich-pending-iocs": {
            "task": "app.workers.enrichment_tasks.enrich_pending_iocs",
            "schedule": crontab(minute="*/10"),
        },
        # Relatório diário de incidentes abertos (8h UTC)
        "daily-open-incidents-report": {
            "task": "app.workers.notification_tasks.send_daily_report",
            "schedule": crontab(hour=8, minute=0),
        },
    },
)
