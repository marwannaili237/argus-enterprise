"""
Argus OSINT Platform — Entry Point
Runs FastAPI, Telegram bot, and monitor scheduler concurrently.
"""
import asyncio
import signal
import sys
import os
import logging
import time

sys.path.insert(0, os.path.dirname(__file__))

from logging_config import setup_logging
setup_logging()
logger = logging.getLogger("argus")

from config import get_settings

settings = get_settings()

# Global shutdown flag
shutdown_requested = False


async def run_api():
    import uvicorn
    from api.app import create_app
    app = create_app()
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=settings.api_port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    await server.serve()


async def run_bot():
    if not settings.telegram_bot_token:
        logger.warning("TELEGRAM_BOT_TOKEN not set — bot will not start. Set it to enable the Telegram interface.")
        return

    await asyncio.sleep(2)
    from bot.main import start_bot
    try:
        await start_bot(settings.telegram_bot_token)
    except Exception as e:
        logger.error(f"Bot error: {e}")


async def run_scheduler():
    global shutdown_requested
    from monitor_scheduler import POLL_INTERVAL_SECONDS, _run_monitor
    from database import AsyncSessionLocal
    from models import Monitor
    from sqlalchemy import select
    from retention import cleanup_old_data

    logger.info("Monitor scheduler started")

    # Hourly retention cleanup tracker
    last_retention_cleanup = time.monotonic()

    while not shutdown_requested:
        try:
            from datetime import datetime, timezone
            _utcnow = lambda: datetime.now(timezone.utc).replace(tzinfo=None)

            async with AsyncSessionLocal() as db:
                due = await db.execute(
                    select(Monitor).where(
                        Monitor.active == True,
                        Monitor.next_check <= _utcnow(),
                    )
                )
                due_monitors = due.scalars().all()

            if due_monitors:
                logger.info(f"Running {len(due_monitors)} due monitor(s)")
                tasks = [_run_monitor(m, settings) for m in due_monitors]
                await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            logger.error(f"Scheduler error: {e}")

        # Hourly data retention cleanup
        now = time.monotonic()
        if now - last_retention_cleanup >= 3600:
            try:
                await cleanup_old_data(settings)
            except Exception as e:
                logger.error(f"Retention cleanup error: {e}")
            last_retention_cleanup = now

        # Sleep in short intervals to check shutdown flag
        for _ in range(POLL_INTERVAL_SECONDS):
            if shutdown_requested:
                break
            await asyncio.sleep(1)

    logger.info("Monitor scheduler stopped")


async def main():
    global shutdown_requested

    logger.info("Starting Argus OSINT Platform", extra={"port": settings.api_port})
    logger.info(f"API → http://0.0.0.0:{settings.api_port}")
    if settings.telegram_bot_token:
        logger.info("Telegram bot → enabled")
    else:
        logger.info("Telegram bot → disabled (set TELEGRAM_BOT_TOKEN to enable)")
    logger.info("Monitor scheduler → enabled")

    tasks = [asyncio.create_task(run_api()), asyncio.create_task(run_bot()), asyncio.create_task(run_scheduler())]

    def _handle_shutdown(sig):
        global shutdown_requested
        shutdown_requested = True
        logger.info(f"Received {sig.name}, initiating graceful shutdown...")
        # Wait for running tasks to finish (30s timeout)
        for t in tasks:
            if not t.done():
                t.cancel()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_shutdown, sig)

    # Run all tasks
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass

    logger.info("Argus OSINT Platform stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass