# Run a WireGuard or AmneziaWG file

Open a terminal in the directory containing your single-peer configuration
file. These examples use `Office.conf`. You can also supply a quoted path.

## System VPN

Use an Administrator terminal on Windows or a root shell on Linux. Bimeron
needs elevated privileges to create the tunnel adapter and set up routing.

```sh
bimeron run "Office.conf"
```

Leave Bimeron running and open a service reachable only through the VPN.
The peer's `AllowedIPs` determines which destinations use the tunnel.
For a full-tunnel IPv4 profile, you can also run the following in a second
terminal and compare the result with the VPN's expected public IPv4 address.
Use `curl.exe` in Windows PowerShell.

```sh
curl -4 --noproxy "*" https://api.ipify.org
```

Press **Ctrl+C** in the Bimeron terminal and wait for it to exit. Bimeron
restores the network settings it changed.

## Local SOCKS5 proxy

Run the following as your regular user. The proxy accepts TCP connections
on `127.0.0.1:1080` and leaves system adapters, routes and DNS unchanged.

```sh
bimeron proxy "Office.conf"
```

To use a different port, stop the proxy with **Ctrl+C** and specify the
loopback address and port before the filename:

```sh
bimeron proxy -listen 127.0.0.1:1081 "Office.conf"
```

Set your application's SOCKS5 address and port to match. To verify the
connection from a second terminal, replace the example URL below with a
service reachable only through the peer's `AllowedIPs` and check for its
expected response. Use port 1080 if you started the proxy on its default
port. The `socks5h` scheme sends the hostname to Bimeron for resolution.

```sh
curl --proxy socks5h://127.0.0.1:1081 https://office.example.com/
```

Press **Ctrl+C** in the Bimeron terminal to stop the listener, then clear
the application's proxy setting.
