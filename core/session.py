class Session:
    """Holds global state shared across every module in a console session."""

    def __init__(self):
        self.globals = {
            "TARGET": "",
            "INTERFACE": "",
        }
        self.alert_history = []   # every alert raised this session, for `uniq`
        self.artifacts = {}       # {"pcap": path, "log": path, "report": path} from the last run

    def set_global(self, key, value):
        self.globals[key.upper()] = value

    def get_global(self, key, default=""):
        return self.globals.get(key.upper(), default)

    def add_alert(self, alert):
        """alert = dict like {'source': ip, 'type': ..., 'detail': ..., 'time': ...}"""
        self.alert_history.append(alert)

    def clear_alerts(self):
        self.alert_history = []
