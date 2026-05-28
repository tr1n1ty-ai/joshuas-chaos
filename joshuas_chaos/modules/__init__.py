"""Base class for all chaos engineering modules."""

from abc import ABC, abstractmethod

from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult


class ChaosModule(ABC):
    """Abstract base class for all chaos engineering modules.

    Subclasses must define the class-level attributes and implement
    check_prereqs and dry_run. execute and cleanup have default
    implementations that raise NotImplementedError.
    """

    name: str
    description: str
    category: str
    required_permissions: list[str]
    cloudtrail_events: list[str]
    mitre_attack: list[str]
    destructive: bool = False
    reversible: bool = True

    @abstractmethod
    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Check pre-requisites without making any changes.

        Returns a ModuleResult describing what was found.
        """

    @abstractmethod
    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Run in observation-only mode. No resource modifications allowed.

        Returns a ModuleResult describing what would happen.
        """

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Execute the lab scenario. Requires explicit safety flag acknowledgement.

        Only targets resources tagged AttackLab=true or named with AttackLab prefix.
        Raises NotImplementedError for modules that have no execute phase.
        """
        raise NotImplementedError(
            f"Module '{self.name}' has no execute phase. "
            "Only dry-run is supported."
        )

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        """Undo any changes made by execute. Must be idempotent.

        Raises NotImplementedError for modules that create no state.
        """
        raise NotImplementedError(
            f"Module '{self.name}' has no cleanup phase. "
            "No state was created by this module."
        )
