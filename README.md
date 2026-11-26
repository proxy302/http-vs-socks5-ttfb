# http-vs-socks5-ttfb: is SOCKS5 slower than an HTTP proxy?

Only on a new connection, and only by its handshake. Before your request can reach the site, an HTTP proxy needs one round trip between you and the proxy (`CONNECT`, then `200`). A SOCKS5 proxy with a username and password needs three (greeting, login, connect request), or two when it has no login. So on a fresh connection SOCKS5 reaches the first byte about two round trips to the proxy later. Once the tunnel is open, both just relay bytes, and further requests on the same kept-alive connection cost the same. `ttfb_compare.py` measures this step by step for your own proxies and your own site, using only the Python standard library. Proxy302 maintains this tool and sells proxies. Our static residential (ISP) IPs come as HTTP or SOCKS5, chosen when you buy, and cost $7.99 for 30 days or $0.50 for a one-day test ([prices](https://proxy302.com/pricing/)).

> Maintained by [Proxy302](https://proxy302.com). MIT licensed. Works with any provider's HTTP or SOCKS5 proxy.

## Usage

```bash
git clone https://github.com/proxy302/http-vs-socks5-ttfb
cd http-vs-socks5-ttfb
python3 ttfb_compare.py "http://USER:PASS@HOST:PORT" "socks5h://USER:PASS@HOST2:PORT2"
python3 ttfb_compare.py "http://USER:PASS@HOST:PORT" "socks5h://USER:PASS@HOST2:PORT2" --url https://YOUR-SITE/ --rounds 10
python3 ttfb_compare.py direct "http://USER:PASS@HOST:PORT"      # against no proxy at all
```

USER, PASS, HOST and PORT are placeholders; percent-encode `@ : / # %` in the password. Python 3.8 or later, nothing to install.

Options: `--url` (default `https://www.example.com/`), `--rounds N` fresh connections per proxy (default 5, run alternately so a slow minute does not favour one side), `--reuse N` extra requests on each connection (default 2), `--timeout S`, `--cafile PEM` to trust a test server's certificate, `--insecure`. The exit code is 1 if any proxy never succeeded.

A static IP has one protocol, so comparing your own HTTP and SOCKS5 means two IPs, ideally in the same place. Compare proxies that sit at a similar distance from you, or the difference you measure is geography, not protocol.

## Example output

Recorded on 26 November 2026 on a Mac. The proxies are [mock-proxy-server](https://github.com/proxy302/mock-proxy-server) started with `--latency 50`, which holds back everything the proxy sends by 50 ms, as if it were 50 ms away. The site is `https_test_server.py` from this repository, reached as `bench.test`, which the proxy resolves to 127.0.0.1:

```bash
python3 https_test_server.py 26443
python3 mock_proxy.py --http 26128 --socks 26180 --user alice --password s3cret --map bench.test=127.0.0.1 --latency 50 --quiet
```

```text
$ python3 ttfb_compare.py http://alice:s3cret@127.0.0.1:26128 socks5h://alice:s3cret@127.0.0.1:26180 --url https://bench.test:26443/ --cafile cert.pem
url     https://bench.test:26443/
rounds  5 fresh connections per proxy, alternating, plus 2 more requests on each

round via                                       dns      tcp   proxy (rt)      tls     wait  first byte    again  status
1     http://alice:****@127.0.0.1:26128         2.0      0.1     53.2 (1)    106.4     53.2       215.0     51.9  200
1     socks5h://alice:****@127.0.0.1:26180      0.0      0.1    158.3 (3)    112.8     51.2       322.5     52.7  200
2     http://alice:****@127.0.0.1:26128         0.0      0.2     53.7 (1)    114.5     52.8       221.3     52.3  200
2     socks5h://alice:****@127.0.0.1:26180      0.0      0.2    158.4 (3)    114.9     52.9       326.4     52.8  200
3     http://alice:****@127.0.0.1:26128         0.0      0.2     52.1 (1)    112.6     50.9       216.0     51.5  200
3     socks5h://alice:****@127.0.0.1:26180      0.0      0.2    156.8 (3)    113.3     52.5       322.8     52.4  200
4     http://alice:****@127.0.0.1:26128         0.1      0.2     53.2 (1)    113.2     52.8       219.5     51.8  200
4     socks5h://alice:****@127.0.0.1:26180      0.0      0.2    158.3 (3)    114.6     52.2       325.4     52.5  200
5     http://alice:****@127.0.0.1:26128         0.0      0.1     51.9 (1)    110.1     52.5       214.6     52.0  200
5     socks5h://alice:****@127.0.0.1:26180      0.0      0.1    157.0 (3)    106.8     52.5       316.4     50.8  200

medians, milliseconds
      via                                       dns      tcp   proxy (rt)      tls     wait  first byte    again
      http://alice:****@127.0.0.1:26128         0.0      0.2     53.2 (1)    112.6     52.8       216.0     51.9
      socks5h://alice:****@127.0.0.1:26180      0.0      0.2    158.3 (3)    113.3     52.5       322.8     52.5

socks5h://alice:****@127.0.0.1:26180 reached the first byte 106.9 ms later than http://alice:****@127.0.0.1:26128 (median of fresh connections).
  on a reused connection the gap is 0.7 ms.
  proxy handshake: 3 round trip(s) vs 1.

rt = round trips between you and the proxy before the site can be reached.
wait = from sending the request to the first byte of the answer.
again = median wait for the extra requests on the same, already open connection.
```

The numbers follow the round trips: about 50 ms for HTTP's one, about 150 ms for SOCKS5's three, and the same TLS, wait and "again" figures for both. The same test against a SOCKS5 proxy with no login gave 2 round trips and a gap of 55.4 ms. With a real remote proxy, the `tcp` column also costs one round trip (the simulated delay does not touch the TCP connect), the same for both protocols.

## Reading the columns

| Column | What it covers | Who pays it |
|---|---|---|
| dns | Looking up the proxy's name on your machine; with `socks5://` (no `h`) also the site's name | Both; `socks5://` a little more |
| tcp | Opening a TCP connection to the proxy | Both, once per connection |
| proxy (rt) | HTTP `CONNECT`, or SOCKS5 greeting, login and connect. Includes the proxy's own connection to the site | SOCKS5 pays one or two extra round trips |
| tls | TLS handshake with the site, through the tunnel | Both, the same |
| wait | Sending the request until the first byte comes back | Both, the same |
| first byte | Sum of the above: what a new connection costs | |
| again | The same request again on the open connection | Both, the same |

For a plain `http://` URL through an HTTP proxy there is no CONNECT at all: the request goes to the proxy in absolute form, so `proxy (rt)` shows 0.

## What to do with the result

- **Many short requests through SOCKS5?** Reuse connections. `requests.Session`, `httpx.Client` and aiohttp's `ClientSession` keep connections open, so only the first request pays the handshake. Creating a new client per request pays it every time.
- **A browser?** Use HTTP regardless of speed. Chrome and other Chromium browsers cannot log in to a SOCKS5 proxy with a username and password.
- **Large downloads?** The handshake is paid once per connection, so it barely shows next to the transfer itself. Measure transfer speed with a real file instead (see [proxy-speed-test](https://github.com/proxy302/proxy-speed-test)).
- **`socks5://` or `socks5h://`?** With `socks5h://` the proxy looks up the site's name, so the answer fits the proxy's location and your own DNS resolver never sees the name. Use `socks5h://` unless you have a reason not to.

## Related

- [SOCKS5 vs HTTP proxy: which should I use?](https://github.com/proxy302/proxy-guides/blob/main/socks5-vs-http-proxy/README.md)
- [mock-proxy-server](https://github.com/proxy302/mock-proxy-server): the local test proxy used above
- [proxy-speed-test](https://github.com/proxy302/proxy-speed-test): latency a proxy adds compared with no proxy

*Checked 26 November 2026.*
