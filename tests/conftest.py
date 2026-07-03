"""
Shared test fixtures for Argus OSINT tests.
"""
import asyncio
import pytest
import sys
import os

# Ensure argus package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ─── Canonical layer fixtures (from conftest_canonical.py) ────────────
# Import all canonical fixtures so they're available to any test file
# without needing to import them explicitly.
sys.path.insert(0, os.path.dirname(__file__))
from conftest_canonical import (  # noqa: E402,F401
    canonical_db,
    canonical_service,
    provenance_service,
    make_entity,
    make_identity,
    make_evidence,
    make_observation,
    make_relationship,
    make_plugin_result,
)
