#!/usr/bin/env python3
import argparse, socket, concurrent.futures, ipaddress, datetime
from jinja2 import Template

REPORT_TMPL = Template("""<!doctype html><html><head>
<meta charset="utf-8"><title>Port Scan Report</title>
<style>body{font-family:Arial,Helvetica,sans-serif;margin:24px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px} th{background:#f4f4f4}
.bad{color:#b00020;font-weight:600}.ok{color:#0a7b15;font-weight:600}
.caption{margin:0 0 8px;color:#555}
</style></head><body>
<h2>Port Scan Report</h2>
<p class="caption">Target(s): {{ targets }} • Ports: {{ portrange }} • Run at: {{ ts }}</p>
<table>
<tr><th>Host</th><th>Port</th><th>Status</th><th>Service (best guess)</th></tr>
{% for row in rows -%}
<tr>
  <td>{{ row.host }}</td>
  <td>{{ row.port }}</td>
  <td class="{{ 'ok' if row.status=='open' else 'bad' }}">{{ row.status }}</td>
  <td>{{ row.service }}</td>
</tr>
{%- endfor %}
</table>
</body></html>""")

COMMON = {20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",
          67:"dhcp",68:"dhcp",80:"http",110:"pop3",123:"ntp",135:"msrpc",
          139:"netbios",143:"imap",161:"snmp",389:"ldap",443:"https",
          445:"smb",465:"smtps",587:"submission",993:"imaps",995:"pop3s"}

def parse_targets(s):
    out = []
    for token in s.split(","):
        token = token.strip()
        if not token: continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            out.extend([str(ip) for ip in net.hosts()] or [str(net.network_address)])
        except ValueError:
            out.append(token)  # hostname or single IP
    return sorted(set(out))

def parse_ports(s):
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def scan_port(host, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return (host, port, "open")
        except (socket.timeout, ConnectionRefusedError, OSError):
            return (host, port, "closed")

def main():
    ap = argparse.ArgumentParser(description="Basic TCP Port Scanner -> HTML report")
    ap.add_argument("targets", help="Target(s): hostname/IP, comma-separated, CIDR allowed (e.g. 192.168.1.10,scanme.nmap.org,192.168.1.0/30)")
    ap.add_argument("--ports", default="1-1024", help="Ports (e.g. 22,80,443 or 1-1024)")
    ap.add_argument("--concurrency", type=int, default=500, help="Number of concurrent sockets")
    ap.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout seconds")
    ap.add_argument("--out", default="scan_report.html", help="Output HTML file")
    args = ap.parse_args()

    hosts = parse_targets(args.targets)
    ports = parse_ports(args.ports)

    work = [(h,p) for h in hosts for p in ports]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(scan_port, h, p, args.timeout) for (h,p) in work]
        for fut in concurrent.futures.as_completed(futs):
            host, port, status = fut.result()
            results.append({
                "host": host,
                "port": port,
                "status": status,
                "service": COMMON.get(port, "")
            })

    # Only show opens + a few closed for context (optional: filter to open only)
    rows = [r for r in results if r["status"] == "open"]
    if not rows:  # keep at least something in report
        rows = sorted(results, key=lambda r:(r["host"], r["port"]))[:min(50, len(results))]

    html = REPORT_TMPL.render(
        targets=",".join(hosts),
        portrange=args.ports,
        ts=datetime.datetime.now().isoformat(timespec="seconds"),
        rows=sorted(rows, key=lambda r:(r["host"], r["port"]))
    )
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Wrote {args.out} with {len(rows)} rows")

if __name__ == "__main__":
    main()
