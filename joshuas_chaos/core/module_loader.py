"""Dynamic module discovery and loading."""

import importlib
import importlib.util
import logging
from pathlib import Path

logger = logging.getLogger("joshuas_chaos")


class ModuleLoadError(Exception):
    """Raised when a module cannot be discovered or loaded."""


def discover_modules(modules_dir: Path | None = None) -> dict:
    """Dynamically import all ChaosModule subclasses from modules_dir.

    Each subdirectory of modules_dir that contains a module.py file is
    treated as a chaos module. The module.py must define a class that
    subclasses ChaosModule and is accessible as the module's ``MODULE``
    attribute or as the first ChaosModule subclass found in the file.

    Returns a dict mapping module_name -> ChaosModule instance.
    """
    from joshuas_chaos.modules import ChaosModule  # local import to avoid circular

    if modules_dir is None:
        modules_dir = Path(__file__).parents[1] / "modules"

    discovered: dict[str, ChaosModule] = {}

    for subdir in sorted(modules_dir.iterdir()):
        if not subdir.is_dir():
            continue
        module_py = subdir / "module.py"
        if not module_py.exists():
            continue

        module_name = subdir.name
        dotted = f"joshuas_chaos.modules.{module_name}.module"

        try:
            mod = importlib.import_module(dotted)
        except Exception as exc:
            logger.error("Failed to import module '%s': %s", module_name, exc)
            continue

        # Look for a MODULE attribute first, then find ChaosModule subclass
        instance: ChaosModule | None = None
        if hasattr(mod, "MODULE") and isinstance(mod.MODULE, ChaosModule):
            instance = mod.MODULE
        else:
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                try:
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ChaosModule)
                        and attr is not ChaosModule
                    ):
                        instance = attr()
                        break
                except TypeError:
                    continue

        if instance is None:
            logger.warning(
                "No ChaosModule subclass found in '%s'", module_py
            )
            continue

        discovered[module_name] = instance
        logger.info("Discovered module: %s (%s)", module_name, instance.description)

    return discovered


def get_module(name: str, modules: dict) -> object:
    """Return the ChaosModule instance for the given name.

    Raises ModuleLoadError if the module is not found.
    """
    if name not in modules:
        available = sorted(modules.keys())
        raise ModuleLoadError(
            f"Module '{name}' not found. Available modules: {available}"
        )
    return modules[name]
