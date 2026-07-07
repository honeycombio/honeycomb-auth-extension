#!/usr/bin/env python3
"""Minimal mock of Honeycomb's /1/auth for local verification.

goodkey -> 200 with ingest scope + team/environment; badkey -> 401; else -> 500.
"""
import http.server
import json

RESP = {
    "api_key_access": {"events": True},
    "environment": {"name": "prod", "slug": "prod"},
    "team": {"name": "acme", "slug": "acme"},
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        key = self.headers.get("x-honeycomb-team", "")
        if key == "goodkey":
            body = json.dumps(RESP).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif key == "badkey":
            self.send_response(401)
            self.end_headers()
        else:
            self.send_response(500)
            self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", 8088), Handler).serve_forever()
