import sys
import requests
import time
import json
import argparse
import socket
from ipwhois import IPWhois
from socket import gethostbyaddr, herror
from fpdf import FPDF
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor

console = Console()

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None

def query_ip_api(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', ''),
                'region': data.get('regionName', ''),
                'city': data.get('city', ''),
                'lat': data.get('lat', ''),
                'lon': data.get('lon', ''),
                'asn': data.get('as', ''),
                'org': data.get('org', '')
            }
        else:
            return {}
    except Exception as e:
        console.print(f"[red][ip-api error] {ip}: {e}[/red]")
        return {}

def query_whois(ip):
    result = {'cidr': '', 'netname': ''}
    try:
        w = IPWhois(ip)
        info = w.lookup_rdap()
        net = info.get('network', {})
        result['cidr'] = net.get('cidr', '')
        result['netname'] = net.get('name', '')
    except Exception as e:
        console.print(f"[red][WHOIS error] {ip}: {e}[/red]")
    return result

def reverse_dns(ip):
    try:
        return gethostbyaddr(ip)[0]
    except herror:
        return ''

def scan_ip(ip, ports=None):
    result = {'ip': ip}
    result.update(query_ip_api(ip))
    result.update(query_whois(ip))
    result['reverse_dns'] = reverse_dns(ip)
    
    if ports:
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port, ip, port): port for port in ports}
            for future in futures:
                port = futures[future]
                if future.result() is not None:
                    open_ports.append(str(port))
        result['open_ports'] = ', '.join(open_ports) if open_ports else 'None'
    
    return result

def save_pdf(results, filename):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(200, 10, "IP Scan Report", ln=True, align='C')
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Owner: Arka Dey", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    for res in results:
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, f"IP: {res['ip']}", ln=True)
        pdf.set_font("Arial", size=12)
        for k, v in res.items():
            if k != 'ip':
                pdf.multi_cell(0, 8, f"{k.title()}: {v}")
        pdf.ln(5)

    pdf.output(filename)
    console.print(f"[green][+] PDF report saved to {filename}[/green]")

def save_json(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    console.print(f"[green][+] JSON report saved to {filename}[/green]")

def run_scans(ips, threads, ports=None):
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("[cyan]Scanning IPs...", total=len(ips))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_ip, ip, ports): ip for ip in ips}
            for future in futures:
                result = future.result()
                results.append(result)
                progress.advance(task)
                time.sleep(1.5)
    return results

def parse_ports(port_str):
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def parse_args():
    parser = argparse.ArgumentParser(description="IP Scanner by Arka Dey (WHOIS + GeoIP + Port Scan)")
    parser.add_argument("input", help="Input file containing IPs (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output filename (example: report.pdf or report.json)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default 4)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '80,443' or '20-25')")
    return parser.parse_args()

def main():
    args = parse_args()
    try:
        with open(args.input, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        sys.exit(1)

    ports = None
    if args.ports:
        try:
            ports = parse_ports(args.ports)
            console.print(f"[yellow]Port scan enabled for: {args.ports}[/yellow]")
        except ValueError as e:
            console.print(f"[red]Invalid port specification: {e}[/red]")
            sys.exit(1)

    console.print("[bold magenta]IP Scanner - Arka Dey[/bold magenta]")
    console.print(f"Loaded {len(ips)} IPs. Starting scan...\n")

    results = run_scans(ips, args.threads, ports)

    if args.output.endswith(".pdf"):
        save_pdf(results, args.output)
    elif args.output.endswith(".json"):
        save_json(results, args.output)
    else:
        console.print("[red]Unsupported output format. Please use .pdf or .json[/red]")

if __name__ == "__main__":
    main()