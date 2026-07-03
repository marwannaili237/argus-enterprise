from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BasePlugin(ABC):
    name: str = "base"
    description: str = ""
    supported_target_types: list[str] = []

    @abstractmethod
    async def run(self, target: str) -> PluginResult:
        pass

    def supports(self, target_type: str) -> bool:
        return target_type in self.supported_target_types
