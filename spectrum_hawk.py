#!/usr/bin/env python3

import subprocess
import time
import csv
import os
import re
import json
import sys
import urllib.request
import urllib.error
import venv
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from jinja2 import Template
import requests

# Constants
OUTPUT_DIR = "wifi_enum_output"
SCAN_TIME = 30
FOCUSED_SCAN_TIME = 10
VENV_NAME = "shawk-venv"
REQUIREMENTS_FILE = "requirements.txt"

# Global lookup configuration
mac_cache = {}
USE_ONLINE_LOOKUP = False
MACADDRESS_API_KEY = None
SCAN_MODE = "normal"  # quick, normal, intense

# OUI database configuration
OUI_DB_PATH = os.path.join(OUTPUT_DIR, "oui_database.json")
LOCAL_CACHE_PATH = os.path.join(OUTPUT_DIR, "mac_cache.json")

# Global objects (will be initialized after venv check)
console = None
mac_lookup = None

def setup_virtual_environment():
    """Setup virtual environment and install requirements if needed"""
    
    # Create requirements.txt if it doesn't exist
    if not os.path.exists(REQUIREMENTS_FILE):
        with open(REQUIREMENTS_FILE, 'w') as f:
            f.write("""rich>=13.0.0
requests>=2.31.0
jinja2>=3.1.0
mac-vendor-lookup>=0.1.11""")
        print(f"[+] Created {REQUIREMENTS_FILE}")
    
    # Check if virtual environment exists
    if not os.path.exists(VENV_NAME):
        print(f"[+] Creating virtual environment '{VENV_NAME}'...")
        try:
            # Create virtual environment
            builder = venv.EnvBuilder(with_pip=True)
            builder.create(VENV_NAME)
            print(f"[✓] Virtual environment created: {VENV_NAME}")
        except Exception as e:
            print(f"[-] Failed to create virtual environment: {e}")
            sys.exit(1)
    
    # Check if we're running from within the virtual environment
    venv_python = os.path.join(VENV_NAME, "bin", "python")
    
    if not sys.executable.startswith(os.path.abspath(VENV_NAME)):
        print(f"\n[!] WARNING: Not running from virtual environment")
        print(f"[*] To run with virtual environment, use:")
        print(f"    sudo {venv_python} {sys.argv[0]}")
        print(f"\n[*] Or run the setup script:")
        print(f"    chmod +x setup.sh && sudo ./setup.sh")
        
        # Check if requirements are installed in current environment
        try:
            import rich
            import jinja2
            from mac_vendor_lookup import MacLookup
            print(f"\n[✓] Requirements already installed in current environment")
            print(f"[*] You can continue, but using virtual environment is recommended")
            
            # Ask if user wants to continue
            choice = input("\nContinue without virtual environment? (y/N): ").strip().lower()
            if choice not in ['y', 'yes']:
                print("[*] Exiting. Please run with virtual environment as shown above.")
                sys.exit(1)
                
        except ImportError as e:
            print(f"\n[-] Missing required package: {e}")
            print(f"[*] Please install requirements or use virtual environment")
            
            # Try to install in virtual environment
            print(f"\n[*] Installing requirements in virtual environment...")
            try:
                pip_cmd = f"{venv_python} -m pip install -r {REQUIREMENTS_FILE}"
                subprocess.run(pip_cmd, shell=True, check=True)
                print(f"[✓] Requirements installed in virtual environment")
                print(f"\n[*] Now run: sudo {venv_python} {sys.argv[0]}")
            except Exception as e:
                print(f"[-] Failed to install requirements: {e}")
            
            sys.exit(1)
    
    # If we're in the virtual environment, ensure requirements are installed
    else:
        print(f"[✓] Running from virtual environment: {VENV_NAME}")
        
        # Check if requirements are installed
        try:
            import rich
            import jinja2
            from mac_vendor_lookup import MacLookup
            print(f"[✓] All requirements are installed")
        except ImportError as e:
            print(f"[-] Missing package in virtual environment: {e}")
            print(f"[*] Installing requirements...")
            try:
                pip_cmd = f"{sys.executable} -m pip install -r {REQUIREMENTS_FILE}"
                subprocess.run(pip_cmd, shell=True, check=True)
                print(f"[✓] Requirements installed successfully")
            except Exception as e:
                print(f"[-] Failed to install requirements: {e}")
                sys.exit(1)
    
    return venv_python

def initialize_globals():
    """Initialize global objects after venv is confirmed"""
    global console, mac_lookup
    
    # Now it's safe to import and initialize
    from rich.console import Console
    from mac_vendor_lookup import MacLookup
    
    console = Console()
    mac_lookup = MacLookup()
    
    console.print(f"\n[bold green]Spectrum Hawk 🦅[/bold green]")
    console.print(f"[dim]Advanced WiFi Network & Device Enumeration Tool[/dim]")

def check_root_privileges():
    """Check if running as root/sudo, if not ask user to run with sudo"""
    
    if os.geteuid() != 0:  # Not root
        console.print("\n[bold red]✗ Root privileges required![/bold red]")
        console.print("\n[yellow]This tool needs root access to:")
        console.print("• Enable monitor mode on wireless interface")
        console.print("• Run airodump-ng for network scanning")
        console.print("• Manage network interfaces[/yellow]")
        
        venv_python = os.path.join(VENV_NAME, "bin", "python")
        script_path = os.path.abspath(sys.argv[0])
        
        console.print(f"\n[cyan]Please run with sudo and virtual environment:[/cyan]")
        console.print(f"[bold]sudo {venv_python} {script_path}[/bold]")
        
        # Show setup script option
        if os.path.exists("setup.sh"):
            console.print(f"\n[cyan]Or run the setup script:[/cyan]")
            console.print(f"[bold]chmod +x setup.sh && sudo ./setup.sh[/bold]")
        
        # Option to restart with sudo
        restart = input("\nRestart with sudo now? (y/N): ").strip().lower()
        if restart in ['y', 'yes']:
            try:
                console.print("[green]Restarting with sudo and virtual environment...[/green]")
                os.execvp('sudo', ['sudo', venv_python, script_path])
            except Exception as e:
                console.print(f"[red]Failed to restart: {e}[/red]")
                console.print(f"[red]Please manually run: sudo {venv_python} {script_path}[/red]")
        else:
            console.print("[yellow]Exiting. Run with sudo when ready.[/yellow]")
        
        sys.exit(1)
    
    console.print("[green]✓ Running with root privileges[/green]")

def update_all_databases():
    """Update both online and local vendor databases every time"""
    
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    console.print("[cyan]Updating vendor databases...[/cyan]")
    
    # Update 1: Local OUI database (always update every time)
    update_local_oui_database()
    
    # Update 2: mac-vendor-lookup package database (always update every time)
    update_package_database()
    
    # Load existing MAC cache if available
    load_mac_cache()

def update_local_oui_database():
    """Update our local JSON OUI database from online sources"""
    
    console.print("[dim]Updating local OUI database...[/dim]")
    
    # Sources to try (in order of preference)
    oui_sources = [
        ("https://standards-oui.ieee.org/oui/oui.csv", "IEEE OUI"),
        ("https://macaddress.io/database-download/csv", "MAC Address.io"),
    ]
    
    oui_data = {}
    success = False
    source_used = "Unknown"
    
    for url, source_name in oui_sources:
        try:
            console.print(f"[dim]Downloading from {source_name}...[/dim]")
            
            # Download the CSV file
            response = urllib.request.urlopen(url, timeout=30)
            csv_content = response.read().decode('utf-8')
            
            # Parse CSV
            lines = csv_content.strip().split('\n')
            for i, line in enumerate(lines):
                if i == 0:  # Skip header
                    continue
                
                try:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        mac_prefix = parts[0].strip().replace('-', ':').upper()
                        vendor = parts[2].strip().strip('"')
                        
                        if mac_prefix and vendor and vendor != "Private":
                            oui_data[mac_prefix] = vendor
                except Exception:
                    continue
            
            source_used = source_name
            console.print(f"[green]✓ Downloaded {len(oui_data)} vendor entries from {source_name}[/green]")
            success = True
            break
            
        except urllib.error.URLError as e:
            console.print(f"[yellow]Failed to download from {source_name}: {e.reason}[/yellow]")
            continue
        except Exception as e:
            console.print(f"[yellow]Error with {source_name}: {e}[/yellow]")
            continue
    
    if success and oui_data:
        # Save the database
        try:
            with open(OUI_DB_PATH, 'w') as f:
                json.dump({
                    "updated": datetime.now().isoformat(),
                    "source": source_used,
                    "entries": oui_data
                }, f, indent=2)
            
            console.print(f"[green]✓ Local OUI database updated with {len(oui_data)} entries[/green]")
            return True
                
        except Exception as e:
            console.print(f"[red]Failed to save local OUI database: {e}[/red]")
            return False
    else:
        if os.path.exists(OUI_DB_PATH):
            console.print("[yellow]Using existing local OUI database (download failed)[/yellow]")
            return True
        else:
            console.print("[red]Could not create local OUI database[/red]")
            return False

def update_package_database():
    """Update the mac-vendor-lookup package's database"""
    
    console.print("[dim]Updating package vendor database...[/dim]")
    
    try:
        # Force update the package's database
        mac_lookup.update_vendors()
        console.print("[green]✓ Package vendor database updated[/green]")
        return True
    except Exception as e:
        console.print(f"[yellow]Package update failed (using cached): {e}[/yellow]")
        # Try alternative method
        try:
            # Some versions use different method names
            if hasattr(mac_lookup, 'update_vendors'):
                mac_lookup.update_vendors()
            elif hasattr(mac_lookup, 'load_vendors'):
                mac_lookup.load_vendors()
            console.print("[green]✓ Package vendor database updated (alternative method)[/green]")
            return True
        except Exception as e2:
            console.print(f"[yellow]Alternative update also failed: {e2}[/yellow]")
            return False

def load_mac_cache():
    """Load MAC cache from previous sessions"""
    global mac_cache
    
    if os.path.exists(LOCAL_CACHE_PATH):
        try:
            with open(LOCAL_CACHE_PATH, 'r') as f:
                mac_cache = json.load(f)
                console.print(f"[dim]Loaded {len(mac_cache)} cached MAC entries[/dim]")
        except Exception as e:
            console.print(f"[yellow]Could not load MAC cache: {e}[/yellow]")
            mac_cache = {}

def save_mac_cache():
    """Save MAC cache for future sessions"""
    try:
        with open(LOCAL_CACHE_PATH, 'w') as f:
            json.dump(mac_cache, f, indent=2)
    except Exception as e:
        console.print(f"[yellow]Could not save MAC cache: {e}[/yellow]")

def local_lookup_from_db(mac):
    """Lookup MAC vendor from our local OUI database (fastest)"""
    
    # Normalize MAC address
    mac_clean = mac.upper().replace('-', ':')
    
    if not os.path.exists(OUI_DB_PATH):
        return None
    
    try:
        with open(OUI_DB_PATH, 'r') as f:
            data = json.load(f)
            oui_data = data.get("entries", {})
        
        # Try different prefix lengths (OUI can be 3, 4, or 5 bytes)
        prefixes_to_try = [
            mac_clean[:8],  # First 3 bytes (most common)
            mac_clean[:11], # First 4 bytes
            mac_clean[:14], # First 5 bytes
        ]
        
        for prefix in prefixes_to_try:
            if prefix in oui_data:
                return oui_data[prefix]
                
    except Exception as e:
        console.print(f"[dim]Local DB lookup error: {e}[/dim]")
    
    return None

def configure_lookup():
    """Ask user for lookup preferences"""
    global USE_ONLINE_LOOKUP, MACADDRESS_API_KEY
    
    console.print("\n[bold cyan]MAC Address Lookup Configuration[/bold cyan]")
    console.print("Choose how you want to perform MAC address vendor lookups:")
    console.print("\n[green]1. Offline Only[/green] - Fast, uses local database (recommended)")
    console.print("[yellow]2. Offline + Online[/yellow] - Most accurate, uses APIs")
    
    while True:
        choice = input("\nSelect option (1 or 2): ").strip()
        
        if choice == "1":
            console.print("[green]Using offline lookup only[/green]")
            USE_ONLINE_LOOKUP = False
            return
        
        elif choice == "2":
            USE_ONLINE_LOOKUP = True
            console.print("\n[yellow]Online Lookup Services[/yellow]")
            console.print("Online lookups provide better accuracy but require API keys.")
            console.print("\nAvailable APIs:")
            console.print("• [cyan]macaddress.io[/cyan]: https://macaddress.io/api (Free tier: 1,000 requests/month)")
            console.print("• You can also use other services without API keys (rate-limited)")
            
            use_keys = input("\nDo you want to enter an API key for macaddress.io? (y/N): ").strip().lower()
            
            if use_keys in ['y', 'yes']:
                console.print("\n[dim]Get your free API key at: https://macaddress.io/api[/dim]")
                api_key = input("Enter your macaddress.io API key (or press Enter to skip): ").strip()
                
                if api_key:
                    MACADDRESS_API_KEY = api_key
                    console.print("[green]API key saved[/green]")
                else:
                    console.print("[yellow]No API key provided. Will use rate-limited lookups.[/yellow]")
            else:
                console.print("[yellow]Using online lookup without API key (rate-limited)[/yellow]")
            
            console.print("[green]Using offline + online lookup[/green]")
            return
        
        else:
            console.print("[red]Invalid choice. Please enter 1 or 2.[/red]")

def configure_scan_mode():
    """Ask user for scanning mode"""
    global SCAN_MODE
    
    console.print("\n[bold cyan]Network Scanning Mode[/bold cyan]")
    console.print("Choose how you want to scan networks:")
    console.print("\n[green]1. Quick Scan[/green] - Only scan highest signal networks (fastest)")
    console.print("[yellow]2. Normal Scan[/yellow] - Scan mid to highest signal networks (balanced)")
    console.print("[red]3. Intense Scan[/red] - Scan all networks (comprehensive, slowest)")
    
    while True:
        choice = input("\nSelect scan mode (1, 2, or 3): ").strip()
        
        if choice == "1":
            SCAN_MODE = "quick"
            console.print("[green]Quick Scan Mode: Only scanning highest signal networks[/green]")
            return
        elif choice == "2":
            SCAN_MODE = "normal"
            console.print("[yellow]Normal Scan Mode: Scanning mid to high signal networks[/yellow]")
            return
        elif choice == "3":
            SCAN_MODE = "intense"
            console.print("[red]Intense Scan Mode: Scanning ALL networks (this will take time)[/red]")
            return
        else:
            console.print("[red]Invalid choice. Please enter 1, 2, or 3.[/red]")

def filter_aps_by_signal(csv_file, aps_dict):
    """Filter access points based on scan mode and signal strength"""
    if SCAN_MODE == "intense":
        console.print(f"[cyan]Intense mode: Will scan all {len(aps_dict)} networks[/cyan]")
        return aps_dict
    
    # Parse signal strength from CSV
    ap_signals = {}
    reading_aps = False
    
    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if not row:
                    reading_aps = False
                    continue
                if row[0].strip().upper() == "BSSID":
                    reading_aps = True
                    continue
                if reading_aps and len(row) > 8:
                    bssid = row[0].strip()
                    signal_str = row[8].strip()  # PWR column in airodump-ng
                    if signal_str and signal_str.lstrip('-').isdigit():
                        ap_signals[bssid] = int(signal_str)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not parse signal strengths: {e}[/yellow]")
        console.print("[yellow]Will scan all networks instead[/yellow]")
        return aps_dict
    
    # Filter based on mode
    filtered_aps = {}
    
    for bssid, info in aps_dict.items():
        if bssid in ap_signals:
            signal = ap_signals[bssid]
            
            if SCAN_MODE == "quick":
                # Quick mode: Only very strong signals (better than -60 dBm)
                if signal > -60:
                    filtered_aps[bssid] = info
                    console.print(f"[green]✓ {info['essid']} ({signal}dBm) - Selected (Strong)[/green]")
                else:
                    console.print(f"[dim]✗ {info['essid']} ({signal}dBm) - Skipped (Weak for quick mode)[/dim]")
            
            elif SCAN_MODE == "normal":
                # Normal mode: Mid to high signals (better than -75 dBm)
                if signal > -75:
                    filtered_aps[bssid] = info
                    console.print(f"[yellow]✓ {info['essid']} ({signal}dBm) - Selected[/yellow]")
                else:
                    console.print(f"[dim]✗ {info['essid']} ({signal}dBm) - Skipped (Too weak)[/dim]")
        else:
            # If we can't get signal, include it anyway (safer)
            filtered_aps[bssid] = info
            console.print(f"[yellow]? {info['essid']} (Signal unknown) - Included for safety[/yellow]")
    
    console.print(f"\n[bold]{len(filtered_aps)} out of {len(aps_dict)} networks selected for scanning[/bold]")
    return filtered_aps

def run_cmd(cmd, capture_output=False):
    console.print(f"[blue]Executing:[/blue] {cmd}")
    return subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)

def get_wireless_interfaces():
    result = run_cmd("iw dev", capture_output=True)
    interfaces = re.findall(r"Interface\s+(\w+)", result.stdout)
    console.print(f"[green]Detected interfaces:[/green] {interfaces}")
    return interfaces

def choose_interface(interfaces):
    if len(interfaces) == 1:
        console.print(f"[green]Using interface:[/green] {interfaces[0]}")
        return interfaces[0]
    console.print("[bold yellow]Multiple wireless interfaces found:")
    for idx, iface in enumerate(interfaces):
        console.print(f"[{idx}] {iface}")
    choice = int(input("Choose interface: "))
    return interfaces[choice]

def start_monitor_mode(iface):
    run_cmd("airmon-ng check kill")
    if iface.endswith("mon"):
        console.print(f"[yellow]Using existing monitor mode interface: {iface}[/yellow]")
        return iface
    run_cmd(f"airmon-ng start {iface}")
    return f"{iface}mon"

def stop_monitor_mode(mon_iface):
    run_cmd(f"airmon-ng stop {mon_iface}")
    run_cmd("service NetworkManager start")

def run_airodump(mon_iface, output_prefix, duration, channel=None, bssid=None):
    console.print(f"[cyan]Running airodump-ng for {duration} seconds on {mon_iface}...[/cyan]")
    options = ""
    if channel:
        options += f"-c {channel} "
    if bssid:
        options += f"--bssid {bssid} "
    csv_cmd = f"sudo timeout {duration}s airodump-ng --write-interval 1 --output-format csv -w {output_prefix} {options}{mon_iface}"
    console.print(f"[magenta]CSV Capture:[/magenta] {csv_cmd}")

    subprocess.run(csv_cmd, shell=True)
    csv_file = f"{output_prefix}-01.csv"

    retries = 5
    while not os.path.exists(csv_file) and retries:
        console.print(f"[yellow]Waiting for CSV file to be written... ({retries})[/yellow]")
        time.sleep(1)
        retries -= 1

    if not os.path.exists(csv_file):
        console.print(f"[red]CSV output not found! Something went wrong.[/red]")
        return None

    return csv_file

def safe_lookup(mac):
    """Lookup MAC vendor with user's preferred method"""
    # Check cache first
    if mac in mac_cache:
        return mac_cache[mac]
    
    # 1. First try our local OUI database (fastest)
    vendor = local_lookup_from_db(mac)
    if vendor:
        mac_cache[mac] = vendor
        return vendor
    
    # 2. Try the package's database (updated)
    try:
        vendor = mac_lookup.lookup(mac)
        if vendor and vendor != "Unknown":
            mac_cache[mac] = vendor
            return vendor
    except Exception:
        pass
    
    # 3. Only try online if user selected it
    if USE_ONLINE_LOOKUP:
        console.print(f"[yellow]Trying online lookup for {mac}...[/yellow]")
        
        # Try macaddress.io with user's API key (or without if not provided)
        try:
            if MACADDRESS_API_KEY:
                url = f"https://api.macaddress.io/v1?apiKey={MACADDRESS_API_KEY}&output=json&search={mac}"
            else:
                # Rate-limited public endpoint (no key required)
                url = f"https://api.macaddress.io/v1?output=json&search={mac}"
            
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                vendor = data.get("vendorDetails", {}).get("companyName", "Unknown")
                if vendor != "Unknown":
                    mac_cache[mac] = vendor
                    return vendor
        except Exception as e:
            console.print(f"[red]Online lookup failed for {mac} → {e}[/red]")
    
    mac_cache[mac] = "Unknown"
    return "Unknown"

def parse_aps_clients(csv_file):
    aps = {}
    reading_aps = False
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row:
                reading_aps = False
                continue
            if row[0].strip().upper() == "BSSID":
                reading_aps = True
                continue
            if reading_aps and len(row) > 13:
                bssid = row[0].strip()
                if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                    continue
                channel = row[3].strip() or "1"
                essid = row[13].strip() if row[13].strip() else "Hidden"
                vendor = safe_lookup(bssid)
                aps[bssid] = {"essid": essid, "vendor": vendor, "channel": channel, "stations": []}
    console.print(f"[blue]Parsed {len(aps)} APs from CSV.[/blue]")
    return aps

def parse_clients_from_csv(csv_file, target_bssid):
    stations = []
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        section = 'aps'
        for row in reader:
            if not row:
                section = 'clients'
                continue
            if section == 'clients' and len(row) > 5:
                station_mac = row[0].strip()
                ap_mac = row[5].strip()
                if ap_mac.lower() == target_bssid.lower():
                    vendor = safe_lookup(station_mac)
                    stations.append({"mac": station_mac, "vendor": vendor})
    console.print(f"[purple]Found {len(stations)} station(s) for {target_bssid}[/purple]")
    return stations

def save_results(all_data, timestamp):
    json_path = os.path.join(OUTPUT_DIR, f"output_{timestamp}.json")
    txt_path = os.path.join(OUTPUT_DIR, f"output_{timestamp}.txt")
    html_path = os.path.join(OUTPUT_DIR, f"output_{timestamp}.html")

    with open(json_path, 'w') as f:
        json.dump(all_data, f, indent=4)
    console.print(f"[green]Saved JSON:[/green] {json_path}")

    with open(txt_path, 'w') as f:
        for bssid, info in all_data.items():
            f.write(f"ESSID: {info['essid']}\n")
            f.write(f"BSSID: {bssid} → {info['vendor']}\n")
            f.write("Connected Stations:\n")
            for s in info['stations']:
                f.write(f" - MAC: {s['mac']} → {s['vendor']}\n")
            f.write("-" * 40 + "\n")
    console.print(f"[green]Saved TXT:[/green] {txt_path}")

    html_template = Template("""
    <html><head><style>
    body { font-family: Arial; }
    h2 { color: #2E86C1; }
    .block { border: 1px solid #ccc; padding: 10px; margin: 10px; }
    </style></head><body>
    {% for bssid, info in data.items() %}
    <div class="block">
        <h2>ESSID: {{ info.essid }}</h2>
        <p><strong>BSSID:</strong> {{ bssid }} → {{ info.vendor }}</p>
        <p><strong>Connected Stations:</strong></p>
        <ul>
        {% if info.stations %}
            {% for s in info.stations %}
                <li>{{ s.mac }} → {{ s.vendor }}</li>
            {% endfor %}
        {% else %}
            <li>No connected stations found.</li>
        {% endif %}
        </ul>
    </div>
    {% endfor %}
    </body></html>
    """)
    html_content = html_template.render(data=all_data)
    with open(html_path, 'w') as f:
        f.write(html_content)
    console.print(f"[green]Saved HTML:[/green] {html_path}")
    try:
        console.print("[blue]Opening HTML report in browser...[/blue]")
        subprocess.run(["xdg-open", html_path])
    except Exception as e:
        console.print(f"[red]Could not open HTML file → {e}[/red]")

def cleanup_focus_files():
    for fname in os.listdir(OUTPUT_DIR):
        if fname.startswith("focus_"):
            try:
                os.remove(os.path.join(OUTPUT_DIR, fname))
            except Exception as e:
                console.print(f"[red]Failed to delete {fname} → {e}[/red]")

def display_terminal(all_data):
    for bssid, info in all_data.items():
        console.print(f"\n[bold]ESSID:[/bold] {info['essid']}")
        console.print(f"[bold]BSSID:[/bold] {bssid} → {info['vendor']}")
        if info['stations']:
            console.print("[bold]Connected Stations:[/bold]")
            for s in info['stations']:
                console.print(f" - MAC: {s['mac']} → {s['vendor']}")
        else:
            console.print("No connected stations detected.")
        console.print("[dim]-" * 40)

def main():
    # Setup virtual environment FIRST (before any imports)
    venv_python = setup_virtual_environment()
    
    # Now initialize global objects (safe to import)
    initialize_globals()
    
    # Check for root privileges
    check_root_privileges()
    
    # Update ALL databases every time the tool starts
    update_all_databases()
    
    # Ask user for lookup preferences
    configure_lookup()
    
    # Ask user for scanning mode
    configure_scan_mode()
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    interfaces = get_wireless_interfaces()
    iface = choose_interface(interfaces)
    mon_iface = start_monitor_mode(iface)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = os.path.join(OUTPUT_DIR, f"scan_{timestamp}")
    general_csv = run_airodump(mon_iface, output_prefix, SCAN_TIME)
    if not general_csv:
        stop_monitor_mode(mon_iface)
        return

    # Parse ALL access points from initial scan
    all_aps = parse_aps_clients(general_csv)
    
    # Filter APs based on selected scan mode
    if SCAN_MODE == "intense":
        # Intense mode: Scan everything
        filtered_aps = all_aps
    else:
        # Quick or Normal mode: Filter by signal strength
        filtered_aps = filter_aps_by_signal(general_csv, all_aps)
    
    # Only scan the filtered APs
    for bssid, info in filtered_aps.items():
        console.print(f"[cyan]Focused scan starting for ESSID '{info['essid']}' → {bssid}[/cyan]")
        focus_prefix = os.path.join(OUTPUT_DIR, f"focus_{bssid.replace(':','')}_{timestamp}")
        focus_csv = run_airodump(mon_iface, focus_prefix, FOCUSED_SCAN_TIME, channel=info['channel'], bssid=bssid)
        if focus_csv:
            stations = parse_clients_from_csv(focus_csv, bssid)
            filtered_aps[bssid]['stations'] = stations
        else:
            console.print(f"[yellow]No client capture file found for BSSID {bssid}[/yellow]")
    
    # Note: Update the original all_aps dict with results from filtered scans
    # so we have complete data for display
    for bssid in filtered_aps:
        if bssid in all_aps:
            all_aps[bssid]['stations'] = filtered_aps[bssid].get('stations', [])
    
    # Save MAC cache for future sessions
    save_mac_cache()

    display_terminal(filtered_aps)
    save_results(filtered_aps, timestamp)
    cleanup_focus_files()
    stop_monitor_mode(mon_iface)

if __name__ == "__main__":
    main()
