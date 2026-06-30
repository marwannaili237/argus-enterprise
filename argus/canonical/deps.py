"""
FastAPI dependency injection for canonical services.

Usage in a route:

    from canonical.deps import get_canonical_service, get_provenance_service

    @router.post("/entities")
    async def create_entity(
        req: CreateEntityRequest,
        svc: CanonicalEntityService = Depends(get_canonical_service),
    ):
        return await svc.upsert_entity(req.type, req.value)
"""
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from canonical.services.canonical_entity import CanonicalEntityService
from canonical.services.provenance import ProvenanceService


async def get_canonical_service(
    db: AsyncSession = Depends(get_db),
) -> CanonicalEntityService:
    """FastAPI dependency that provides a CanonicalEntityService."""
    return CanonicalEntityService(db)


async def get_provenance_service(
    db: AsyncSession = Depends(get_db),
) -> ProvenanceService:
    """FastAPI dependency that provides a ProvenanceService."""
    return ProvenanceService(db)


__all__ = ["get_canonical_service", "get_provenance_service"]
