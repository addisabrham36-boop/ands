from abc import ABC, abstractmethod


class ModuleBase(ABC):
    """Base class for every ANDS module. Subclasses define self.options
    in __init__ and implement run()."""

    def __init__(self, session):
        self.session = session
        self.options = {}
        # {name: {"value": ..., "required": bool, "desc": str}}

    def set_option(self, key, value):
        key = key.upper()
        if key in self.options:
            self.options[key]["value"] = value
            print(f"[+] {key} => {value}")
        else:
            print(f"[-] Unknown option: {key}")

    def show_options(self):
        print(f"\nModule options ({self.__class__.__name__}):")
        print(f"{'Name':<15}{'Value':<25}{'Required':<10}Description")
        for name, opt in self.options.items():
            print(f"{name:<15}{str(opt['value']):<25}{str(opt['required']):<10}{opt['desc']}")
        print()

    def missing_required(self):
        """Returns a list of required options that are still unset."""
        missing = []
        for name, opt in self.options.items():
            if opt["required"] and not opt["value"]:
                missing.append(name)
        return missing

    @abstractmethod
    def run(self):
        """Every module must implement this."""
        raise NotImplementedError
