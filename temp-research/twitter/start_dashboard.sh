#!/bin/bash
cd "$(dirname "$0")"
kill $(lsof -ti:8000) 2>/dev/null
sleep 1
exec ./venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from api import index
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            html = index().body.decode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()

host = ('0.0.0.0', 8000)
print(f'Dashboard: http://localhost:8000/')
HTTPServer(host, Handler).serve_forever()
"
