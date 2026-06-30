"""
Argus OSINT — Simple SQLite-backed result cache.

Caches plugin results keyed by "plugin_name:target" with a TTL.
"""
import json
import time
import sqlite3
import logging
import threading

logger = logging.getLogger("argus.cache")

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Get or create a thread-local SQLite connection for the cache."""
    if not hasattr(_local, "cache_conn"):
        _local.cache_conn = sqlite3.connect(":memory:", check_same_thread=False)
        _local.cache_conn.execute(
            "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, expires_at REAL)"
        )
        _local.cache_conn.commit()
    return _local.cache_conn


def cache_get(key: str, ttl_seconds: int = 3600):
    """
    Retrieve a cached value by key. Returns None if expired or not found.
    """
    conn = _get_conn()
    now = time.time()
    row = conn.execute(
        "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        return None
    value, expires_at = row
    if now > expires_at:
        conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        conn.commit()
        return None
    return json.loads(value)


def cache_set(key: str, value, ttl_seconds: int = 3600):
    """
    Store a value in the cache with a TTL.
    """
    conn = _get_conn()
    expires_at = time.time() + ttl_seconds
    conn.execute(
        "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
        (key, json.dumps(value, default=str), expires_at),
    )
    conn.commit()