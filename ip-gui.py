import sys
import requests
import time
import json
import csv
import argparse
import socket
from ipwhois import IPWhois
from socket import gethostbyaddr, herror
from fpdf import FPDF
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading 
console = Console()

# Global variables for thread management
scan_thread = None
executor = None
should_cancel = False

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
    global should_cancel
    if should_cancel:
        return None
        
    result = {'ip': ip}
    result.update(query_ip_api(ip))
    result.update(query_whois(ip))
    result['reverse_dns'] = reverse_dns(ip)
    
    if ports and not should_cancel:
        open_ports = []
        with ThreadPoolExecutor(max_workers=20) as port_executor: 
            futures = {port_executor.submit(scan_port, ip, port): port for port in ports}
            for future in as_completed(futures):
                if should_cancel:
                    break
                port = futures[future]
                if future.result() is not None:
                    open_ports.append(str(port))
        result['open_ports'] = ', '.join(open_ports) if open_ports else 'None'
    else:
        result['open_ports'] = 'N/A'
    
    return None if should_cancel else result

def parse_ports(port_str):
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if not (0 <= start <= 65535 and 0 <= end <= 65535 and start <= end):
                    raise ValueError("Port numbers must be between 0 and 65535.")
                ports.extend(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range '{part}': {e}")
        else:
            try:
                port = int(part)
                if not (0 <= port <= 65535):
                    raise ValueError("Port number must be between 0 and 65535.")
                ports.append(port)
            except ValueError as e:
                raise ValueError(f"Invalid port number '{part}': {e}")
    return ports

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

def save_csv(results, filename):
    if not results:
        console.print("[yellow]No results to save to CSV.[/yellow]")
        return

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        all_keys = set()
        for res in results:
            all_keys.update(res.keys())
        fieldnames = sorted(list(all_keys))

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()  
        for res in results:
            writer.writerow(res) 

    console.print(f"[green][+] CSV report saved to {filename}[/green]")

ip_text = None
thread_entry = None
port_entry = None
tree = None
all_scan_results = []
scan_thread = None
executor = None
should_cancel = False

def on_cancel_scan():
    global should_cancel, executor
    should_cancel = True
    if executor:
        executor.shutdown(wait=False)
    cancel_button.config(state=tk.DISABLED)
    scan_button.config(state=tk.NORMAL)
    messagebox.showinfo("Scan Cancelled", "The scan has been cancelled.")

def run_scans_threaded(ips, threads, ports, callback):
    global all_scan_results, executor, should_cancel
    all_scan_results = [] 
    should_cancel = False

    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("[cyan]Scanning IPs...", total=len(ips))
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_ip, ip, ports): ip for ip in ips}
                for future in as_completed(futures):
                    if should_cancel:
                        break
                    result = future.result()
                    if result:
                        all_scan_results.append(result)
                        root.after(0, callback, result) 
                        progress.advance(task)
        
        if not should_cancel:
            messagebox.showinfo("Scan Complete", "IP scanning has finished.")
    except Exception as e:
        if not should_cancel:
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {e}")
    finally:
        if not should_cancel:
            scan_button.config(state=tk.NORMAL)
            cancel_button.config(state=tk.DISABLED)

def update_table(result):
    row_values = [
        result.get('ip', ''),
        result.get('country', ''),
        result.get('region', ''),
        result.get('city', ''),
        result.get('lat', ''),
        result.get('lon', ''),
        result.get('asn', ''),
        result.get('org', ''),
        result.get('reverse_dns', ''),
        result.get('open_ports', 'N/A')
    ]
    tree.insert("", "end", values=row_values)
    tree.yview_moveto(1) 

def on_import_button_click():
    file_path = filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Select IP list file (one IP per line)"
    )
    
    if not file_path:
        return
    
    try:
        with open(file_path, 'r') as f:
            ip_list = [line.strip() for line in f if line.strip()]
            ip_text.delete("1.0", tk.END)
            ip_text.insert("1.0", "\n".join(ip_list))
        messagebox.showinfo("Import Successful", f"Successfully imported {len(ip_list)} IP addresses.")
    except Exception as e:
        messagebox.showerror("Import Error", f"Failed to import IPs: {e}")

def on_scan_button_click():
    global scan_thread, should_cancel
    should_cancel = False

    ips_raw = ip_text.get("1.0", "end-1c").strip()
    if not ips_raw:
        messagebox.showwarning("Input Error", "Please enter IP addresses or import from a text file.")
        return

    ips = [line.strip() for line in ips_raw.splitlines() if line.strip()]

    if not ips:
        messagebox.showwarning("Input Error", "No valid IP addresses found in input.")
        return

    if len(ips) > 1000:
        messagebox.showerror("Input Error", "Please provide a maximum of 1000 IPs.")
        return

    try:
        threads = int(thread_entry.get())
        if not (1 <= threads <= 100):  
            messagebox.showwarning("Input Error", "Number of threads must be between 1 and 100.")
            return
    except ValueError:
        messagebox.showerror("Input Error", "Invalid number of threads. Please enter an integer.")
        return

    ports_str = port_entry.get().strip()
    ports = None
    if ports_str:
        try:
            ports = parse_ports(ports_str)
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid port specification: {e}")
            return
    
    for item in tree.get_children():
        tree.delete(item)
    
    scan_button.config(state=tk.DISABLED)
    cancel_button.config(state=tk.NORMAL)

    scan_thread = threading.Thread(target=run_scans_threaded, args=(ips, threads, ports, update_table))
    scan_thread.daemon = True
    scan_thread.start()

def on_save_button_click():
    if not all_scan_results:
        messagebox.showwarning("Save Error", "No scan results to save.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[
            ("CSV files", "*.csv"),
            ("JSON files", "*.json"),
            ("PDF files", "*.pdf"),
            ("All files", "*.*")
        ]
    )
    if not file_path:
        return

    if file_path.endswith(".csv"):
        save_csv(all_scan_results, file_path)
    elif file_path.endswith(".json"):
        save_json(all_scan_results, file_path)
    elif file_path.endswith(".pdf"):
        save_pdf(all_scan_results, file_path)
    else:
        messagebox.showwarning("Unsupported Format", "Please choose a supported file extension (.csv, .json, .pdf).")

def create_gui():
    global root, ip_text, thread_entry, port_entry, tree, scan_button, cancel_button

    root = tk.Tk()
    root.title("IP Scanner - Arka Dey")
    root.geometry("1000x700")

    style = ttk.Style()
    style.theme_use("clam")

    input_frame = ttk.LabelFrame(root, text="Scan Configuration")
    input_frame.pack(padx=10, pady=10, fill="x", expand=False)

    input_frame.columnconfigure(0, weight=1)
    input_frame.columnconfigure(1, weight=3)

    # IP Address section with import button
    ip_label_frame = ttk.Frame(input_frame)
    ip_label_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
    
    ttk.Label(ip_label_frame, text="IP Addresses (one per line):").pack(side="left", padx=10, pady=5)
    import_button = ttk.Button(ip_label_frame, text="Import from TXT", command=on_import_button_click)
    import_button.pack(side="right", padx=5, pady=5)

    ip_text = tk.Text(input_frame, height=8, width=40, wrap="word")
    ip_text.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

    # Add note about file format
    ttk.Label(input_frame, text="Note: Import from text file with one IP per line", font=('Arial', 8)).grid(row=2, column=0, columnspan=2, sticky="w", padx=10)

    ttk.Label(input_frame, text="Number of Threads (1-100):").grid(row=3, column=0, padx=10, pady=5, sticky="w")
    thread_entry = ttk.Entry(input_frame)
    thread_entry.insert(0, "10")
    thread_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

    ttk.Label(input_frame, text="Ports (e.g., '80,443' or '20-25'):").grid(row=4, column=0, padx=10, pady=5, sticky="w")
    port_entry = ttk.Entry(input_frame)
    port_entry.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

    button_frame = ttk.Frame(input_frame)
    button_frame.grid(row=5, column=0, columnspan=2, pady=10)
    
    scan_button = ttk.Button(button_frame, text="Start Scan", command=on_scan_button_click)
    scan_button.pack(side="left", padx=5)

    cancel_button = ttk.Button(button_frame, text="Cancel Scan", command=on_cancel_scan, state=tk.DISABLED)
    cancel_button.pack(side="left", padx=5)

    save_button = ttk.Button(button_frame, text="Save Results", command=on_save_button_click)
    save_button.pack(side="left", padx=5)

    results_frame = ttk.LabelFrame(root, text="Scan Results")
    results_frame.pack(padx=10, pady=10, fill="both", expand=True)

    columns = ("IP", "Country", "Region", "City", "Latitude", "Longitude", "ASN", "Organization", "Reverse DNS", "Open Ports")
    
    tree = ttk.Treeview(results_frame, columns=columns, show="headings")
    
    tree.heading("IP", text="IP")
    tree.column("IP", width=120, anchor="w")
    tree.heading("Country", text="Country")
    tree.column("Country", width=100, anchor="w")
    tree.heading("Region", text="Region")
    tree.column("Region", width=100, anchor="w")
    tree.heading("City", text="City")
    tree.column("City", width=100, anchor="w")
    tree.heading("Latitude", text="Lat")
    tree.column("Latitude", width=60, anchor="center")
    tree.heading("Longitude", text="Lon")
    tree.column("Longitude", width=60, anchor="center")
    tree.heading("ASN", text="ASN")
    tree.column("ASN", width=80, anchor="w")
    tree.heading("Organization", text="Organization")
    tree.column("Organization", width=150, anchor="w")
    tree.heading("Reverse DNS", text="Reverse DNS")
    tree.column("Reverse DNS", width=150, anchor="w")
    tree.heading("Open Ports", text="Open Ports")
    tree.column("Open Ports", width=100, anchor="w")

    tree.pack(padx=5, pady=5, fill="both", expand=True)

    vsb = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
    vsb.pack(side='right', fill='y')
    tree.configure(yscrollcommand=vsb.set)

    hsb = ttk.Scrollbar(tree, orient="horizontal", command=tree.xview)
    hsb.pack(side='bottom', fill='x')
    tree.configure(xscrollcommand=hsb.set)

    root.mainloop()

def main():
    create_gui()

if __name__ == "__main__":
    main()