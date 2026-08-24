import importlib.util
import inspect
import os
from typing import Dict, Type
from core.module_base import ModuleBase


def load_all_modules(base_dir: str = "modules") -> Dict[str, Type[ModuleBase]]:
    """
    Recursively scans the modules directory and subpackages,
    dynamically loading all ModuleBase subclasses and creating friendly aliases.
    """
    discovered: Dict[str, Type[ModuleBase]] = {}
    if not os.path.isdir(base_dir):
        return discovered

    categories = ["capture", "detect", "audit", "generate", "response", "report", "system", "custom"]

    for category in categories:
        cat_dir = os.path.join(base_dir, category)
        if not os.path.isdir(cat_dir):
            continue

        for filename in sorted(os.listdir(cat_dir)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue

            filepath = os.path.join(cat_dir, filename)
            module_name = filename[:-3]
            spec = importlib.util.spec_from_file_location(f"modules.{category}.{module_name}", filepath)
            if not spec or not spec.loader:
                continue

            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
            except Exception:
                continue

            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, ModuleBase) and obj is not ModuleBase:
                    key = f"{category}/{module_name}"
                    discovered[key] = obj

                    # Register short aliases (e.g. detect/portscan -> detect/portscan_detect)
                    if module_name.endswith("_detect"):
                        short_key = f"{category}/{module_name[:-7]}"
                        discovered[short_key] = obj
                    elif module_name.endswith("_audit"):
                        short_key = f"{category}/{module_name[:-6]}"
                        discovered[short_key] = obj
                    elif module_name.endswith("_payload"):
                        short_key = f"{category}/{module_name[:-8]}"
                        discovered[short_key] = obj
                    elif module_name.endswith("_anomaly"):
                        short_key = f"{category}/{module_name[:-8]}"
                        discovered[short_key] = obj
                    elif module_name.startswith("traffic_"):
                        short_key = f"{category}/{module_name[8:]}"
                        discovered[short_key] = obj
                    elif module_name.startswith("generate_"):
                        short_key = f"{category}/{module_name[9:]}"
                        discovered[short_key] = obj

    return discovered


def load_custom_modules(directory: str = "modules/custom") -> Dict[str, Type[ModuleBase]]:
    """Compatibility alias for custom modules directory."""
    return load_all_modules()