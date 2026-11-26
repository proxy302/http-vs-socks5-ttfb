#!/usr/bin/env python3
"""ttfb_compare.py: is SOCKS5 slower than an HTTP proxy? Time each step of a request through both.

For every proxy you give it, the script opens fresh connections and times each step:
local DNS, TCP to the proxy, the proxy handshake (HTTP CONNECT or SOCKS5 greeting,
login and connect, with the number of round trips), the TLS handshake with the site,
and the wait for the first byte. It then sends more requests on the same connection
to show what a kept-alive connection costs.

Python 3.8+, standard library only. Maintained by Proxy302 (https://proxy302.com). MIT licensed.
"""
import argparse
import base64
import ipaddress
import socket
import ssl
import statistics
import struct
import sys
import time
from urllib.parse import unquote, urlsplit

SOCKS_REPLY = {
    0x01: "general failure", 0x02: "not allowed by the proxy's rules", 0x03: "network unreachable",
    0x04: "host unreachable", 0x05: "connection refused by the site", 0x06: "timed out reaching the site",
    0x07: "command not supported", 0x08: "address type not supported",
}


class Failed(Exception):
    def __init__(self, step, message):
        super().__init__(message)
        self.step = step


class Proxy:
    def __init__(self, text):
        self.raw = text
        if text == "direct":
            self.scheme = "direct"
            self.label = "direct (no proxy)"
            return
        u = urlsplit(text)
        self.scheme = u.scheme.lower()
        if self.scheme not in ("http", "socks5", "socks5h"):
            raise SystemExit("unsupported proxy scheme %r: use http://, socks5:// or socks5h://" % u.scheme)
        if not u.hostname or not u.port:
            raise SystemExit("proxy needs a host and a port: %r" % text)
        self.host, self.port = u.hostname, u.port
        self.user = unquote(u.username) if u.username is not None else None
        self.password = unquote(u.password) if u.password is not None else ""
        shown = "%s:%d" % (("[%s]" % self.host) if ":" in self.host else self.host, self.port)
        self.label = "%s://%s%s" % (self.scheme, (self.user + ":****@") if self.user else "", shown)


def read_until(sock, marker, limit=65536):
    data = b""
    while marker not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
        if len(data) > limit:
            raise ConnectionError("header too long")
    return data


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def read_response(sock, first=b""):
    """Read one HTTP/1.1 response with Content-Length or chunked body. Returns (status, keep_alive)."""
    head = first + read_until_from(sock, first)
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise Failed("response", "not an HTTP response: %r" % lines[0][:60])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k:
            headers[k.strip().lower()] = v.strip()
    keep = headers.get("connection", "").lower() != "close" and lines[0].startswith("HTTP/1.1")
    if "content-length" in headers:
        recv_exact(sock, int(headers["content-length"]))
    elif "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size = int(read_until(sock, b"\r\n").split(b";")[0].strip(), 16)
            recv_exact(sock, size + 2)
            if size == 0:
                break
    else:
        keep = False
        while sock.recv(65536):
            pass
    return status, keep


def read_until_from(sock, already):
    data = already
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed before the response header ended")
        data += chunk
    return data[len(already):]


def socks5_handshake(sock, proxy, host, port, resolved_ip):
    """Returns the number of round trips used."""
    trips = 0
    methods = b"\x00\x02" if proxy.user is not None else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    reply = recv_exact(sock, 2)
    trips += 1
    if reply[0] != 5:
        raise Failed("proxy", "the port did not answer like a SOCKS5 proxy (is it an HTTP proxy?)")
    if reply[1] == 0xFF:
        raise Failed("proxy", "the proxy accepted none of the login methods offered")
    if reply[1] == 0x02:
        if proxy.user is None:
            raise Failed("proxy", "the proxy wants a username and password")
        u, p = proxy.user.encode(), proxy.password.encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        status = recv_exact(sock, 2)
        trips += 1
        if status[1] != 0:
            raise Failed("proxy", "the SOCKS5 login was rejected")
    if resolved_ip is not None:
        ip = ipaddress.ip_address(resolved_ip)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    else:
        name = host.encode("idna")
        addr = b"\x03" + bytes([len(name)]) + name
    sock.sendall(b"\x05\x01\x00" + addr + struct.pack("!H", port))
    head = recv_exact(sock, 4)
    trips += 1
    if head[1] != 0:
        raise Failed("proxy", "SOCKS5 reply 0x%02x: %s" % (head[1], SOCKS_REPLY.get(head[1], "unknown")))
    skip = {1: 4, 4: 16}.get(head[3])
    if skip is None:
        skip = recv_exact(sock, 1)[0]
    recv_exact(sock, skip + 2)
    return trips


def one_connection(proxy, url, timeout, tls_ctx, reuse):
    """Times one fresh connection and `reuse` follow-up requests on it. Returns a dict of milliseconds."""
    u = urlsplit(url)
    https = u.scheme == "https"
    host, port = u.hostname, u.port or (443 if https else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    host_header = host if u.port is None else "%s:%d" % (host, port)
    r = {"trips": 0}
    clock = time.perf_counter

    # 1. local DNS: the proxy's name, and for socks5:// (no h) the site's name too
    t = clock()
    connect_host, connect_port = (host, port) if proxy.scheme == "direct" else (proxy.host, proxy.port)
    try:
        info = socket.getaddrinfo(connect_host, connect_port, type=socket.SOCK_STREAM)[0]
        site_ip = None
        if proxy.scheme == "socks5":
            site_ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror as e:
        raise Failed("dns", "could not resolve a name locally: %s" % e)
    r["dns"] = (clock() - t) * 1000

    # 2. TCP connect
    t = clock()
    sock = socket.socket(info[0], info[1], info[2])
    sock.settimeout(timeout)
    try:
        sock.connect(info[4])
    except OSError as e:
        raise Failed("tcp", "could not connect to %s:%s: %s" % (connect_host, connect_port, e))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    r["tcp"] = (clock() - t) * 1000

    # 3. proxy handshake
    t = clock()
    auth = ""
    if proxy.scheme == "http" and proxy.user is not None:
        token = base64.b64encode(("%s:%s" % (proxy.user, proxy.password)).encode()).decode()
        auth = "Proxy-Authorization: Basic %s\r\n" % token
    absolute = False
    try:
        if proxy.scheme == "http" and https:
            sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n" % (host, port, host, port, auth)).encode())
            line = read_until(sock, b"\r\n\r\n").split(b"\r\n", 1)[0].decode("latin-1")
            r["trips"] = 1
            if " 200 " not in line + " ":
                raise Failed("proxy", "CONNECT answered %r" % line)
        elif proxy.scheme == "http":
            absolute = True  # plain http:// through an HTTP proxy: no handshake, the request goes in absolute form
        elif proxy.scheme in ("socks5", "socks5h"):
            r["trips"] = socks5_handshake(sock, proxy, host, port, site_ip)
    except (OSError, ConnectionError) as e:
        if isinstance(e, Failed):
            raise
        raise Failed("proxy", "proxy handshake failed: %s" % e)
    r["proxy"] = (clock() - t) * 1000

    # 4. TLS with the site, through the tunnel
    r["tls"] = 0.0
    if https:
        t = clock()
        try:
            sock = tls_ctx.wrap_socket(sock, server_hostname=host)
        except (ssl.SSLError, OSError) as e:
            raise Failed("tls", "TLS handshake with %s failed: %s" % (host, e))
        r["tls"] = (clock() - t) * 1000

    # 5. request -> first byte of the answer
    target = url if absolute else path
    request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ttfb-compare/1.0\r\nAccept: */*\r\n%s\r\n"
               % (target, host_header, auth if absolute else "")).encode()
    t = clock()
    try:
        sock.sendall(request)
        first = sock.recv(1)
        if not first:
            raise ConnectionError("closed without an answer")
        r["ttfb"] = (clock() - t) * 1000
        r["status"], keep = read_response(sock, first)
        again = []
        for _ in range(reuse if keep else 0):
            t = clock()
            sock.sendall(request)
            first = sock.recv(1)
            if not first:
                break
            again.append((clock() - t) * 1000)
            _, keep = read_response(sock, first)
            if not keep:
                break
        r["again"] = statistics.median(again) if again else None
    except (OSError, ConnectionError) as e:
        raise Failed("response", "no answer from the site: %s" % e)
    finally:
        sock.close()
    r["first"] = r["dns"] + r["tcp"] + r["proxy"] + r["tls"] + r["ttfb"]
    return r


def fmt(v, width=8):
    return ("%.1f" % v).rjust(width) if v is not None else "-".rjust(width)


def main(argv):
    ap = argparse.ArgumentParser(description="Time a new request through an HTTP proxy and a SOCKS5 proxy, step by step.")
    ap.add_argument("proxies", nargs="+", metavar="PROXY",
                    help="http://USER:PASS@HOST:PORT, socks5h://..., socks5://..., or the word direct")
    ap.add_argument("--url", default="https://www.example.com/", help="page to request (default https://www.example.com/)")
    ap.add_argument("--rounds", type=int, default=5, help="fresh connections per proxy (default 5)")
    ap.add_argument("--reuse", type=int, default=2, help="extra requests on each connection (default 2)")
    ap.add_argument("--timeout", type=float, default=15, help="seconds per step (default 15)")
    ap.add_argument("--cafile", help="extra CA certificate to trust (for a test site with its own certificate)")
    ap.add_argument("--insecure", action="store_true", help="do not verify the site's certificate")
    a = ap.parse_args(argv)

    proxies = [Proxy(p) for p in a.proxies]
    tls_ctx = ssl.create_default_context(cafile=a.cafile)
    if a.insecure:
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

    print("url     %s" % a.url)
    print("rounds  %d fresh connections per proxy, alternating, plus %d more requests on each\n" % (a.rounds, a.reuse))
    width = max(len(p.label) for p in proxies)
    head = "%-5s %-*s %8s %8s %12s %8s %8s %11s %8s  %s" % (
        "round", width, "via", "dns", "tcp", "proxy (rt)", "tls", "wait", "first byte", "again", "status")
    print(head)
    results = {p.label: [] for p in proxies}
    for n in range(1, a.rounds + 1):
        for p in proxies:
            try:
                r = one_connection(p, a.url, a.timeout, tls_ctx, a.reuse)
            except Failed as e:
                print("%-5d %-*s  failed at %s: %s" % (n, width, p.label, e.step, e))
                continue
            results[p.label].append(r)
            print("%-5d %-*s %s %s %s (%d) %s %s %s %s  %s" % (
                n, width, p.label, fmt(r["dns"]), fmt(r["tcp"]), fmt(r["proxy"], 8), r["trips"],
                fmt(r["tls"]), fmt(r["ttfb"]), fmt(r["first"], 11), fmt(r["again"]), r["status"]))

    print("\nmedians, milliseconds")
    print(head.replace("round", "     ", 1).rsplit("  status", 1)[0])
    med = {}
    for p in proxies:
        rs = results[p.label]
        if not rs:
            print("%-5s %-*s  no successful round" % ("", width, p.label))
            continue
        m = {k: statistics.median([r[k] for r in rs]) for k in ("dns", "tcp", "proxy", "tls", "ttfb", "first")}
        ag = [r["again"] for r in rs if r["again"] is not None]
        m["again"] = statistics.median(ag) if ag else None
        m["trips"] = rs[0]["trips"]
        med[p.label] = m
        print("%-5s %-*s %s %s %s (%d) %s %s %s %s" % (
            "", width, p.label, fmt(m["dns"]), fmt(m["tcp"]), fmt(m["proxy"], 8), m["trips"],
            fmt(m["tls"]), fmt(m["ttfb"]), fmt(m["first"], 11), fmt(m["again"])))

    labels = list(med)
    if len(labels) >= 2:
        base = labels[0]
        print()
        for other in labels[1:]:
            diff = med[other]["first"] - med[base]["first"]
            print("%s reached the first byte %.1f ms %s than %s (median of fresh connections)." % (
                other, abs(diff), "later" if diff >= 0 else "sooner", base))
            if med[other]["again"] is not None and med[base]["again"] is not None:
                print("  on a reused connection the gap is %.1f ms." % (med[other]["again"] - med[base]["again"]))
            print("  proxy handshake: %d round trip(s) vs %d." % (med[other]["trips"], med[base]["trips"]))
    print("\nrt = round trips between you and the proxy before the site can be reached.")
    print("wait = from sending the request to the first byte of the answer.")
    print("again = median wait for the extra requests on the same, already open connection.")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
