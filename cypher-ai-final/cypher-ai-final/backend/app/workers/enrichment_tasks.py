"""Enrichment Tasks — IOC enrichment via VirusTotal, Shodan, AbuseIPDB"""
import asyncio
import structlog
from app.workers.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models import IOC
from app.integrations.connectors import VirusTotalEnricher
from app.core.config import settings
from sqlalchemy import select, and_

logger = structlog.get_logger()


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task
def enrich_pending_iocs():
    async def _run():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(IOC).where(
                    and_(IOC.vt_result == None, IOC.type.in_(["ip", "domain", "file_hash"]))
                ).limit(50)
            )
            iocs = result.scalars().all()
            if not iocs or not settings.VIRUSTOTAL_API_KEY:
                return {"enriched": 0}

            vt = VirusTotalEnricher(settings.VIRUSTOTAL_API_KEY)
            enriched = 0
            for ioc in iocs:
                try:
                    if ioc.type == "ip":
                        ioc.vt_result = await vt.check_ip(ioc.value)
                    elif ioc.type == "domain":
                        ioc.vt_result = await vt.check_domain(ioc.value)
                    elif ioc.type == "file_hash":
                        ioc.vt_result = await vt.check_hash(ioc.value)
                    enriched += 1
                except Exception as e:
                    logger.warning("ioc_enrich_failed", ioc_id=ioc.id, error=str(e))

            await db.commit()
            return {"enriched": enriched}

    return run_async(_run())


@celery_app.task
def enrich_ioc_now(ioc_id: str):
    """Enriquecimento imediato de IOC individual."""
    async def _run():
        if not settings.VIRUSTOTAL_API_KEY:
            return {"error": "VT not configured"}
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(IOC).where(IOC.id == ioc_id))
            ioc = result.scalar_one_or_none()
            if not ioc:
                return
            vt = VirusTotalEnricher(settings.VIRUSTOTAL_API_KEY)
            if ioc.type == "ip":
                ioc.vt_result = await vt.check_ip(ioc.value)
            elif ioc.type == "domain":
                ioc.vt_result = await vt.check_domain(ioc.value)
            elif ioc.type == "file_hash":
                ioc.vt_result = await vt.check_hash(ioc.value)
            await db.commit()

    return run_async(_run())
