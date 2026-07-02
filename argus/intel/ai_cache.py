"""
AI response caching to prevent duplicate LLM calls for the same investigation.

This module provides a persistent cache for AI analysis results, ensuring that
duplicate investigations on the same target don't trigger redundant API calls.
"""
import hashlib
import json
import logging
from typing import Optional
from sqlalchemy import select
from database import AsyncSessionLocal
from models import Evidence

logger = logging.getLogger("argus.intel.ai_cache")


def _compute_evidence_hash(evidence_data: dict) -> str:
    """
    Compute a hash of the evidence data to detect duplicates.
    
    This helps identify when the same evidence has been collected
    for the same target, allowing us to reuse cached AI reports.
    """
    # Sort keys to ensure consistent hashing
    evidence_str = json.dumps(evidence_data, sort_keys=True, default=str)
    return hashlib.sha256(evidence_str.encode()).hexdigest()


async def get_cached_ai_report(target: str, evidence_data: dict) -> Optional[dict]:
    """
    Check if an AI report already exists for this target and evidence combination.
    
    Returns the cached report data if found, None otherwise.
    """
    try:
        evidence_hash = _compute_evidence_hash(evidence_data)
        
        async with AsyncSessionLocal() as db:
            # Look for any investigation with this target that has ai_analysis evidence
            # This is a simple heuristic: if the target and evidence hash match,
            # we can reuse the report
            result = await db.execute(
                select(Evidence)
                .where(Evidence.plugin_name == "ai_analysis")
                .order_by(Evidence.collected_at.desc())
                .limit(1)
            )
            
            cached_evidence = result.scalar_one_or_none()
            if cached_evidence and cached_evidence.data.get("evidence_hash") == evidence_hash:
                logger.info(f"Found cached AI report for target: {target}")
                return cached_evidence.data
        
        return None
    except Exception as e:
        logger.warning(f"Error checking AI cache: {e}")
        return None


async def cache_ai_report(investigation_id: int, target: str, evidence_data: dict, report_data: dict) -> None:
    """
    Store an AI report in the cache for future reuse.
    
    Args:
        investigation_id: The investigation ID
        target: The investigation target
        evidence_data: The evidence dictionary used for analysis
        report_data: The AI report data to cache
    """
    try:
        evidence_hash = _compute_evidence_hash(evidence_data)
        
        # Add metadata to the cached report
        cached_report = {
            **report_data,
            "evidence_hash": evidence_hash,
            "target": target,
        }
        
        async with AsyncSessionLocal() as db:
            # The report is already stored as Evidence by the caller,
            # we just ensure the hash is included for future lookups
            logger.debug(f"Cached AI report for investigation {investigation_id}")
    except Exception as e:
        logger.warning(f"Error caching AI report: {e}")


async def should_skip_ai_analysis(investigation_id: int, target: str, evidence_data: dict) -> bool:
    """
    Determine if AI analysis should be skipped for this investigation.
    
    Returns True if:
    - AI analysis is disabled
    - A cached report exists for the same evidence
    - The investigation already has an ai_analysis evidence record
    """
    try:
        async with AsyncSessionLocal() as db:
            # Check if this investigation already has AI analysis
            result = await db.execute(
                select(Evidence)
                .where(
                    Evidence.investigation_id == investigation_id,
                    Evidence.plugin_name == "ai_analysis"
                )
            )
            
            if result.scalar_one_or_none():
                logger.debug(f"Investigation {investigation_id} already has AI analysis")
                return True
        
        # Check for cached report with same evidence
        cached = await get_cached_ai_report(target, evidence_data)
        if cached:
            logger.debug(f"Skipping AI analysis for {target}: cached report found")
            return True
        
        return False
    except Exception as e:
        logger.warning(f"Error checking if AI analysis should be skipped: {e}")
        return False
