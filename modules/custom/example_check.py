from core.module_base import ModuleBase


class ExampleCheck(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "", "required": False, "desc": "Example target field"},
        }

    def run(self):
        print(f"[+] Custom module ran successfully. TARGET={self.options['TARGET']['value']}")