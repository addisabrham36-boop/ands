import itertools
import threading
import time
import sys
from core import colors

DEFAULT_MESSAGES = [
    "Sniffing the wire...",
    "Counting packets...",
    "Watching for anomalies...",
    "Crunching numbers...",
]


class Spinner:
    def __init__(self, messages=None):
        self.messages = messages or DEFAULT_MESSAGES
        self._stop_event = threading.Event()
        self._thread = None

    def _spin(self):
        frames = itertools.cycle(["|", "/", "-", "\\"])
        msg_cycle = itertools.cycle(self.messages)
        current_msg = next(msg_cycle)
        last_switch = time.time()
        while not self._stop_event.is_set():
            if time.time() - last_switch > 2:
                current_msg = next(msg_cycle)
                last_switch = time.time()
            sys.stdout.write(f"\r{colors.C.CYAN}[{next(frames)}] {current_msg}{colors.C.RESET}   ")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()