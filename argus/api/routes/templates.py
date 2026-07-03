from fastapi import APIRouter
from plugins.templates import list_templates

router = APIRouter(prefix="/templates", tags=["templates"])


@router.get("")
async def get_templates():
    """List all investigation templates with their plugin sets."""
    return list_templates()