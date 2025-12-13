import socket
import time
import ipaddress
from threading import Thread
from colorama import Fore, Style, init

# Initialize Colorama for colored output
init(autoreset=True)

# Dictionary of well-known TCP and UDP ports
COMMON_PORTS_TCP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
    445: "SMB", 1723: "PPTP", 5900: "VNC", 8443: "HTTPS-ALT" 
}

COMMON_PORTS_UDP = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    161: "SNMP", 162: "SNMPTRAP", 500: "IKE (VPN)", 137: "NetBIOS-NS", 138: "NetBIOS-DG" 
}

# Global variables
open_tcp_ports = []
open_udp_ports = []
target_ip = ""
VERBOSITY = False 

def scan_tcp_port(port):
    """Attempts to connect to a specific TCP port and performs basic version detection."""
    try:
        # 1. TCP Port Scan
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5) 
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                service = COMMON_PORTS_TCP.get(port, "Unknown Service")
                service_info = ""
                
                # --- Service Version Detection/Banner Grabbing Logic ---
                try:
                    s.settimeout(1.0)
                    data = s.recv(1024)
                    
                    if not data:
                        web_ports = [80, 443, 8080, 8443]
                        
                        if port in web_ports:
                            s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                        elif port in [21, 25, 110, 143, 23]:
                            s.sendall(b'\n')
                        
                        data = s.recv(1024)

                    if data:
                        decoded_data = data.decode('utf-8', errors='ignore').strip()
                        first_line = next((line for line in decoded_data.split('\n') if line.strip()), "").strip()
                        
                        if first_line:
                            service_info = f" | Info: {first_line}"
                        elif len(decoded_data) > 5 and len(decoded_data) < 100:
                            service_info = f" | Info: {decoded_data[:100]}..."

                except socket.timeout:
                    pass
                except Exception:
                    pass
                
                open_tcp_ports.append(f"{Fore.GREEN}✅ TCP Port {port:<5} ({service:<10}) is OPEN{service_info}{Style.RESET_ALL}")
            
    except Exception:
        if VERBOSITY:
            print(f"{Fore.YELLOW}⚠️ TCP Port {port:<5} is FILTERED (Error occurred/Blocked){Style.RESET_ALL}")
        pass

def scan_udp_port(port):
    """Attempts to scan a specific UDP port (Unreliable via standard socket)"""
    service = COMMON_PORTS_UDP.get(port, "Unknown Service")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.sendto(b'ping', (target_ip, port)) 
            
            try:
                s.recvfrom(1024)
                open_udp_ports.append(f"{Fore.GREEN}✅ UDP Port {port:<5} ({service:<10}) is OPEN{Style.RESET_ALL}")
            except socket.timeout:
                open_udp_ports.append(f"{Fore.YELLOW}❓ UDP Port {port:<5} ({service:<10}) is OPEN|FILTERED{Style.RESET_ALL}")
            
    except Exception:
        pass

def run_scanner(ip_address, start_port, end_port, scan_type):
    """Starts the scanning process"""
    global target_ip, open_tcp_ports, open_udp_ports
    target_ip = ip_address
    open_tcp_ports = []
    open_udp_ports = []
    
    display_mode = "Only OPEN/OPEN|FILTERED ports will be shown."
    
    # --- Tool Header (Simplified) ---
    print(Fore.CYAN + f"\n--- MD.FARID RANA Tools ---" + Style.RESET_ALL)
    
    print(f"Target: {ip_address}")
    print(f"Scanning ports from {start_port} to {end_port}... ({display_mode})")
    
    start_time = time.time()
    
    threads = []
    scan_ports = range(start_port, end_port + 1)

    for port in scan_ports:
        if scan_type == 'TCP' or scan_type == 'BOTH':
            thread = Thread(target=scan_tcp_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        if (scan_type == 'UDP' or scan_type == 'BOTH') and port in COMMON_PORTS_UDP:
            thread = Thread(target=scan_udp_port, args=(port,))
            threads.append(thread)
            thread.start()
            
    for thread in threads:
        thread.join()

    end_time = time.time()
    
    print(Fore.MAGENTA + "\n--- Scan Results ---" + Style.RESET_ALL)
    
    found_results = False
    
    if open_tcp_ports:
        print(Fore.CYAN + "\n[TCP Results]" + Style.RESET_ALL)
        for result in sorted(open_tcp_ports, key=lambda x: int(x.split()[3])):
            print(result)
        found_results = True
        
    if open_udp_ports:
        print(Fore.CYAN + "\n[UDP Results]" + Style.RESET_ALL)
        for result in sorted(open_udp_ports, key=lambda x: int(x.split()[3])):
            print(result)
        found_results = True
        
    if not found_results:
        print(Fore.RED + "❌ No OPEN or OPEN|FILTERED ports found in the specified range." + Style.RESET_ALL)
        
    print(Fore.YELLOW + f"\nScan completed in {end_time - start_time:.2f} seconds." + Style.RESET_ALL)
    print(Fore.CYAN + "------------------------------------\n" + Style.RESET_ALL)

# --- User Input and Validation ---
if __name__ == "__main__":
    
    # --- Compact Header: Name, NMAP style tool name, Skull, Features ---
    # Top Border
    print(Fore.MAGENTA + "\n" + "="*50)
    
    # Name Centered
    print(Fore.WHITE + f"{'MD.FARID RANA':^50}" + Style.RESET_ALL)
    
    # Tool Description (NMAP style)
    print(Fore.CYAN + f"{'☠️ NMAP Style Port Scanner ☠️':^50}" + Style.RESET_ALL)

    # Features (in a more compact list)
    print(Fore.YELLOW + "\nKey Features:" + Style.RESET_ALL)
    print(Fore.GREEN + " * Multi-Threaded Scanning" + Fore.WHITE + " | " + Fore.GREEN + "Service Version Detection" + Style.RESET_ALL)
    print(Fore.GREEN + " * TCP/UDP/BOTH Modes" + Fore.WHITE + " | " + Fore.GREEN + "Custom Range & Quick Scan" + Style.RESET_ALL)

    # Bottom Border
    print(Fore.MAGENTA + "="*50 + Style.RESET_ALL)

    while True:
        target = input(Fore.WHITE + "Enter Target IP Address (e.g., 192.168.1.1): " + Style.RESET_ALL).strip()
        try:
            ipaddress.ip_address(target)
            break
        except ValueError:
            print(Fore.RED + "Invalid IP address format. Please try again." + Style.RESET_ALL)

    print(Fore.YELLOW + "\nSelect Scan Type:" + Style.RESET_ALL)
    scan_type = input("Enter 'TCP', 'UDP', or 'BOTH' (Suggestion: BOTH): ").upper().strip()
    if scan_type not in ['TCP', 'UDP', 'BOTH']:
        scan_type = 'TCP' 
        print(Fore.YELLOW + "Invalid input. Defaulting to TCP scan." + Style.RESET_ALL)


    mode = input("Use Quick Mode (Scan common ports 1-1024)? (y/n): ").lower()
    if mode == 'y':
        p_start, p_end = 1, 1024
    else:
        while True:
            try:
                p_start = int(input("Enter Start Port (e.g., 1): "))
                p_end = int(input("Enter End Port (e.g., 65535): "))
                if 1 <= p_start <= 65535 and 1 <= p_end <= 65535 and p_start <= p_end:
                    break
                else:
                    print(Fore.RED + "Invalid port range. Ports must be between 1 and 65535, and Start Port must be <= End Port." + Style.RESET_ALL)
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter a number for the port." + Style.RESET_ALL)

    verbose_input = input("Enable Verbose Output (Show FILTERED ports/Errors)? (y/n): ").lower()
    if verbose_input == 'y':
        VERBOSITY = True
        
    run_scanner(target, p_start, p_end, scan_type)