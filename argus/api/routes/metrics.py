from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from sqlalchemy import select, func
from database import get_db
from models import Investigation, Monitor, User
import asyncio

router = APIRouter()

# In-memory counters
_plugin_execution_counts: dict[str, int] = {}


def increment_plugin_exec(plugin_name: str):
    """Increment the execution counter for a plugin."""
    _plugin_execution_counts[plugin_name] = _plugin_execution_counts.get(plugin_name, 0) + 1


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """Prometheus-format metrics endpoint."""
    lines = []

    async def _query(db):
        total_inv = await db.execute(select(func.count(Investigation.id)))
        lines.append(f"# HELP argus_investigations_total Total number of investigations")
        lines.append(f"# TYPE argus_investigations_total counter")
        lines.append(f"argus_investigations_total {total_inv.scalar() or 0}")

        status_rows = (await db.execute(
            select(Investigation.status, func.count(Investigation.id))
            .group_by(Investigation.status)
        )).all()
        lines.append(f"# HELP argus_investigations_by_status Investigations grouped by status")
        lines.append(f"# TYPE argus_investigations_by_status gauge")
        for status, count in status_rows:
            label = status.replace("-", "_")
            lines.append(f"argus_investigations_by_status{{status=\"{label}\"}} {count}")

        active_mon = await db.execute(
            select(func.count(Monitor.id)).where(Monitor.active == True)
        )
        lines.append(f"# HELP argus_active_monitors Number of active monitors")
        lines.append(f"# TYPE argus_active_monitors gauge")
        lines.append(f"argus_active_monitors {active_mon.scalar() or 0}")

        total_users = await db.execute(select(func.count(User.id)))
        lines.append(f"# HELP argus_users_total Total number of users")
        lines.append(f"# TYPE argus_users_total gauge")
        lines.append(f"argus_users_total {total_users.scalar() or 0}")

    from database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await _query(db)

    # Plugin execution counts (in-memory)
    lines.append(f"# HELP argus_plugin_executions_total Plugin execution counts")
    lines.append(f"# TYPE argus_plugin_executions_total counter")
    for plugin_name, count in sorted(_plugin_execution_counts.items()):
        label = plugin_name.replace("-", "_")
        lines.append(f'argus_plugin_executions_total{{plugin="{label}"}} {count}')

    return "\n".join(lines) + "\n"