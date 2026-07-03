"""
Argus OSINT — Data Retention

Background function that deletes investigations (and their evidence)
older than N days, based on config.data_retention_days.
"""
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, delete

logger = logging.getLogger("argus.retention")


async def cleanup_old_data(settings):
    """
    Delete investigations and associated evidence older than settings.data_retention_days.
    Called periodically from the main scheduler loop.
    """
    from database import AsyncSessionLocal
    from models import Investigation, Evidence

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=settings.data_retention_days)

    async with AsyncSessionLocal() as db:
        # Find old investigation IDs
        result = await db.execute(
            select(Investigation.id).where(Investigation.created_at < cutoff)
        )
        old_ids = [row[0] for row in result.all()]

        if not old_ids:
            return

        # Delete associated evidence first
        await db.execute(
            delete(Evidence).where(Evidence.investigation_id.in_(old_ids))
        )
        # Delete old investigations
        await db.execute(
            delete(Investigation).where(Investigation.id.in_(old_ids))
        )
        await db.commit()
        logger.info(f"Data retention: deleted {len(old_ids)} investigation(s) older than {settings.data_retention_days} days")