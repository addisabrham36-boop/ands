import json


class Session:
    """Holds global state shared across every module in a console session."""

    def __init__(self):
        self.globals = {
            "TARGET": "",
            "INTERFACE": "",
            "ALERT_OUT": "",
        }
        self.alert_history = []
        self.artifacts = {}

    def set_global(self, key, value):
        self.globals[key.upper()] = value

    def get_global(self, key, default=""):
        return self.globals.get(key.upper(), default)

    def add_alert(self, alert):
        self.alert_history.append(alert)
        alert_out = self.get_global("ALERT_OUT")
        if alert_out:
            with open(alert_out, "a") as f:
                f.write(json.dumps(alert) + "\n")

    def clear_alerts(self):
        self.alert_history = []