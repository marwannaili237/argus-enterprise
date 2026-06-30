"""
Tests for SQLAlchemy models and database initialization.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from sqlalchemy import select
from models import User, Investigation, Evidence, Monitor


@pytest.fixture
def db_session():
    """Create an in-memory SQLite session for testing."""
    import asyncio
    from database import engine, Base, AsyncSessionLocal

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with AsyncSessionLocal() as session:
            yield session
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    # Run the async fixture synchronously
    loop = asyncio.new_event_loop()
    gen = _setup()
    session = loop.run_until_complete(gen.__anext__())
    yield session
    try:
        loop.run_until_complete(gen.__anext__())
    except StopAsyncIteration:
        pass
    loop.close()


class TestModels:
    def test_user_creation(self, db_session):
        user = User(telegram_id=123456, username="testuser", full_name="Test User")
        db_session.add(user)
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(db_session.commit())
        loop.run_until_complete(db_session.refresh(user))
        assert user.id is not None
        assert user.telegram_id == 123456
        assert user.username == "testuser"
        assert user.is_active is True
        loop.close()

    def test_investigation_creation(self, db_session):
        user = User(telegram_id=999)
        db_session.add(user)
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(db_session.commit())
        loop.run_until_complete(db_session.refresh(user))

        inv = Investigation(
            user_id=user.id,
            target="example.com",
            target_type="domain",
            status="pending",
        )
        db_session.add(inv)
        loop.run_until_complete(db_session.commit())
        loop.run_until_complete(db_session.refresh(inv))
        assert inv.id is not None
        assert inv.target == "example.com"
        assert inv.status == "pending"
        loop.close()

    def test_monitor_creation(self, db_session):
        user = User(telegram_id=888)
        db_session.add(user)
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(db_session.commit())
        loop.run_until_complete(db_session.refresh(user))

        mon = Monitor(
            user_id=user.id,
            target="example.com",
            target_type="domain",
            telegram_chat_id=12345,
            schedule="daily",
            interval_hours=24,
            active=True,
        )
        db_session.add(mon)
        loop.run_until_complete(db_session.commit())
        loop.run_until_complete(db_session.refresh(mon))
        assert mon.id is not None
        assert mon.schedule == "daily"
        assert mon.active is True
        loop.close()
