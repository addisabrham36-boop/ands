import importlib.util
import inspect
import os
from core.module_base import ModuleBase


def load_custom_modules(directory="modules/custom"):
    discovered = {}
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
        return discovered

    for filename in os.listdir(directory):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        filepath = os.path.join(directory, filename)
        module_name = filename[:-3]

        spec = importlib.util.spec_from_file_location(module_name, filepath)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[-] Failed to load {filename}: {e}")
            continue

        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, ModuleBase) and obj is not ModuleBase:
                key = f"custom/{module_name}"
                discovered[key] = obj
                print(f"[+] Discovered custom module: {key}")

    return discovered