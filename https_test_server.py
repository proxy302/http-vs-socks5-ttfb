#!/usr/bin/env python3
"""A small local HTTPS server to measure against (HTTP/1.1 keep-alive, tiny response).

Make a certificate first:
  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
    -subj "/CN=bench.test" -addext "subjectAltName=DNS:bench.test,IP:127.0.0.1"
Then: python3 https_test_server.py 26443
"""
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"hello over TLS\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("https://127.0.0.1:%d/ (certificate cert.pem)" % port, flush=True)
server.serve_forever()
