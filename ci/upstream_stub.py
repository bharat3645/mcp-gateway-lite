#!/usr/bin/env python3
"""Minimal JSON-RPC echo upstream used by the CI smoke test."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            req = {}
        resp = json.dumps({
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"ok": True, "echo_method": req.get("method")},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *args):  # keep CI logs quiet
        pass


if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    HTTPServer((host, port), Handler).serve_forever()
