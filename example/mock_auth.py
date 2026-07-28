#!/usr/bin/env python3
"""Minimal mock of Honeycomb's /1/auth for local verification and e2e tests.

Keys: goodkey -> 200 (team acme, env prod, ingest scope); otherteamkey -> 200
(team other-team); otherenvkey -> 200 (env staging); classickey -> 200 (Classic:
empty environment values); noscope -> 200 without ingest scope; badkey -> 401;
else -> 500.

POST /down makes every subsequent /1/auth call return 500 (simulates an auth
backend outage for the stale-serving e2e scenario); POST /up recovers.
"""
import http.server
import json


def auth_response(team_name, team_slug, events=True, env_name="prod", env_slug="prod"):
    return {
        "api_key_access": {"events": events},
        "environment": {"name": env_name, "slug": env_slug},
        "team": {"name": team_name, "slug": team_slug},
    }


RESPONSES = {
    "goodkey": auth_response("acme", "acme"),
    "otherteamkey": auth_response("Other Team", "other-team"),
    "otherenvkey": auth_response("acme", "acme", env_name="Staging", env_slug="staging"),
    # Classic keys return empty strings for both environment values.
    "classickey": auth_response("acme", "acme", env_name="", env_slug=""),
    "noscope": auth_response("acme", "acme", events=False),
}

down = False


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global down
        if self.path in ("/down", "/up"):
            down = self.path == "/down"
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if down:
            self.send_response(500)
            self.end_headers()
            return
        key = self.headers.get("x-honeycomb-team", "")
        if key in RESPONSES:
            body = json.dumps(RESPONSES[key]).encode()
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
