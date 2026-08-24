import http.server
import socketserver
import socket
import json
import os
import sys
import time
import urllib.parse
import threading
import webbrowser
import warnings
from typing import Optional

# Suppress cryptography / scapy deprecation warnings
warnings.filterwarnings("ignore")

from core.session import Session
from core.engine import LiveEngine
from web.api import APIHandler


PROHIBITED_PORTS = {5000, 8000, 8080}


def find_available_port(host: str = "0.0.0.0", preferred_port: int = 8899) -> int:
    """
    Finds the first available TCP port, starting from preferred_port and
    strictly skipping prohibited ports (5000, 8000, 8080).
    """
    candidate_ports = [preferred_port]
    # Add sequential fallback ports
    for p in range(preferred_port, preferred_port + 100):
        if p not in candidate_ports and p not in PROHIBITED_PORTS:
            candidate_ports.append(p)
    # Additional high-port ranges if needed
    for p in range(9000, 9100):
        if p not in candidate_ports and p not in PROHIBITED_PORTS:
            candidate_ports.append(p)

    for port in candidate_ports:
        if port in PROHIBITED_PORTS:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                return port
        except OSError:
            continue

    return preferred_port


class DashboardHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Multi-threaded HTTP & SSE Server for the ANDS Cyber SOC Dashboard."""

    session: Optional[Session] = None
    engine: Optional[LiveEngine] = None
    api: Optional[APIHandler] = None
    static_dir: str = os.path.join(os.path.dirname(__file__), "static")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=self.static_dir, **kwargs)

    def log_message(self, format, *args):
        # Suppress routine GET logging to keep terminal clean
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle_sse_stream(self):
        """Streams live telemetry points and security alert events via Server-Sent Events (SSE)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        initial_data = json.dumps({"connected": True, "time": time.strftime("%H:%M:%S")})
        self.wfile.write(f"event: init\ndata: {initial_data}\n\n".encode("utf-8"))
        self.wfile.flush()

        event_queue = []
        queue_lock = threading.Lock()

        def on_session_event(event_type: str, data: dict):
            with queue_lock:
                event_queue.append((event_type, data))

        self.session.register_listener(on_session_event)

        try:
            while True:
                time.sleep(0.5)
                stats = self.api.get_stats()
                stats_msg = json.dumps(stats)
                self.wfile.write(f"event: telemetry\ndata: {stats_msg}\n\n".encode("utf-8"))
                self.wfile.flush()

                with queue_lock:
                    pending = list(event_queue)
                    event_queue.clear()

                for ev_type, ev_data in pending:
                    msg = json.dumps(ev_data)
                    self.wfile.write(f"event: {ev_type}\ndata: {msg}\n\n".encode("utf-8"))
                    self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.session.unregister_listener(on_session_event)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/stream":
            self._handle_sse_stream()
            return
        elif path == "/api/stats":
            self._send_json(self.api.get_stats())
            return
        elif path == "/api/alerts":
            query = urllib.parse.parse_qs(parsed.query)
            sev = query.get("severity", [""])[0]
            limit = int(query.get("limit", [100])[0])
            self._send_json(self.api.get_alerts(severity=sev, limit=limit))
            return
        elif path == "/api/inventory":
            self._send_json(self.api.get_inventory())
            return
        elif path == "/api/modules":
            self._send_json(self.api.get_modules())
            return
        elif path == "/api/report/download/html":
            html_path = "reports/report.html"
            if os.path.exists(html_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Disposition", "attachment; filename=ands_report.html")
                with open(html_path, "rb") as f:
                    content = f.read()
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self._send_json({"error": "Report not generated yet. Run report/generate first."}, status=404)
                return

        # Default static file serving
        if path == "/" or not os.path.exists(os.path.join(self.static_dir, path.lstrip("/"))):
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            data = {}

        if path == "/api/modules/run":
            mod_path = data.get("module", "")
            options = data.get("options", {})
            res = self.api.run_module(mod_path, options)
            self._send_json(res)
            return
        elif path == "/api/alerts/clear":
            self._send_json(self.api.clear_alerts())
            return
        elif path == "/api/live/toggle":
            action = data.get("action", "start")
            iface = data.get("interface", "")
            self._send_json(self.api.toggle_live(action, iface))
            return
        elif path == "/api/firewall/action":
            action = data.get("action", "")
            ip = data.get("ip", "")
            self._send_json(self.api.firewall_action(action, ip))
            return
        elif path == "/api/whitelist/action":
            action = data.get("action", "")
            ip = data.get("ip", "")
            self._send_json(self.api.update_whitelist(action, ip))
            return
        elif path == "/api/report/generate":
            fmt = data.get("format", "html")
            from modules.report.generate_report import ReportGenerator
            rep_mod = ReportGenerator(self.session)
            rep_mod.set_option("FORMAT", fmt)
            rep_mod.run()
            self._send_json({"success": True, "artifacts": self.session.artifacts})
            return

        self._send_json({"error": "Endpoint not found"}, status=404)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_dashboard_server(session: Session, engine: LiveEngine, host="0.0.0.0", port=8899, open_browser=True):
    DashboardHTTPHandler.session = session
    DashboardHTTPHandler.engine = engine
    DashboardHTTPHandler.api = APIHandler(session, engine)

    # Protect against prohibited ports (5000, 8000, 8080)
    if port in PROHIBITED_PORTS:
        port = 8899

    # Automatically resolve port conflicts
    actual_port = find_available_port(host, preferred_port=port)
    if actual_port != port:
        print(f"[*] Port {port} is occupied or reserved. Selected free port: {actual_port}")

    server = ThreadingHTTPServer((host, actual_port), DashboardHTTPHandler)
    url = f"http://localhost:{actual_port}"

    print(f"\n{'='*70}")
    print(f"🛡️  ANDS SOC Analyst & Auditor Web Dashboard is LIVE!")
    print(f"    URL:      {url}")
    print(f"    Host:     {host}:{actual_port}")
    print(f"    Engine:   {'RUNNING' if engine.is_running() else 'IDLE (toggle via UI)'}")
    print(f"{'='*70}\n")

    if open_browser:
        try:
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard server stopped.")
    finally:
        server.server_close()
