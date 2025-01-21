#!/usr/bin/env python3
"""
Advanced Python 3 Port Scanner

Features:
1. Concurrent scanning with configurable worker threads.
2. TCP connect scanning with customizable timeouts.
3. Optional banner grabbing for detected open ports.
4. CIDR notation support for scanning multiple hosts.
5. Logging and safe error handling.
6. Pythonic best practices and clean code style.

Usage:
    python advanced_port_scanner.py --targets 192.168.0.1/24 --ports 1-1000 --threads 100 --timeout 2.0 --banner
"""

import socket
import ipaddress
import argparse
import sys
import queue
import threading
import time

# -----------------------------------------------------------------------------
#                           SCANNER CLASS
# -----------------------------------------------------------------------------

class AdvancedPortScanner:
    """
    A sleek and professional port scanner that supports:
    - Multiple targets (including CIDR ranges)
    - Configurable port ranges
    - Concurrent scanning
    - Banner grabbing (optional)
    - Timeouts and safe error handling
    """

    def __init__(self, 
                 targets,
                 ports, 
                 max_threads=100, 
                 timeout=2.0,
                 grab_banner=False):
        """
        Initialize the port scanner.

        :param targets: List of IPs or subnets (ipaddress.IPv4Network or IPv4Address).
        :param ports: List of integer port numbers to scan.
        :param max_threads: Maximum number of concurrent threads.
        :param timeout: Timeout (in seconds) for socket connections.
        :param grab_banner: Whether to attempt grabbing service banners.
        """
        self.targets = targets
        self.ports = ports
        self.max_threads = max_threads
        self.timeout = timeout
        self.grab_banner = grab_banner
        
        # A thread-safe queue to handle IP-port jobs
        self.task_queue = queue.Queue()
        # Results stored as list of (ip, port, status, banner)
        self.results = []
        self.lock = threading.Lock()

    def enqueue_jobs(self):
        """
        Enqueue all (target, port) combinations into the task queue.
        """
        for target in self.targets:
            # Convert ipaddress.IPv4Network to individual hosts if needed
            if isinstance(target, ipaddress.IPv4Network):
                for host in target.hosts():
                    for port in self.ports:
                        self.task_queue.put((str(host), port))
            else:
                # Single IP
                for port in self.ports:
                    self.task_queue.put((str(target), port))

    def scan_port(self, ip, port):
        """
        Scan a single port for a given IP.

        :param ip: The target IP address (str).
        :param port: The port number to test (int).
        :return: (ip, port, is_open, banner)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            # Attempt TCP connect
            sock.connect((ip, port))
            is_open = True
            banner = ""

            if self.grab_banner:
                # Try to receive banner (e.g. from HTTP, FTP, SSH, etc.)
                # We'll send a harmless request and read the response
                try:
                    # Small data to prompt a response, depending on the protocol
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
        except (socket.timeout, ConnectionRefusedError, OSError):
            is_open = False
            banner = ""
        finally:
            sock.close()

        return (ip, port, is_open, banner)

    def worker_thread(self):
        """
        Worker thread that continuously processes tasks from the queue
        until the queue is empty.
        """
        while True:
            try:
                ip, port = self.task_queue.get_nowait()
            except queue.Empty:
                break

            result = self.scan_port(ip, port)
            
            # Store results in a thread-safe manner
            with self.lock:
                self.results.append(result)

            self.task_queue.task_done()

    def run(self):
        """
        Run the port scanner.
        Creates threads, enqueues jobs, and waits for results.

        :return: A list of (ip, port, is_open, banner) results.
        """
        self.enqueue_jobs()

        # Create a pool of worker threads
        threads = []
        for _ in range(min(self.max_threads, self.task_queue.qsize())):
            t = threading.Thread(target=self.worker_thread, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all tasks to be processed
        self.task_queue.join()

        # Wait for threads to finish
        for t in threads:
            t.join()

        return self.results

# -----------------------------------------------------------------------------
#                           HELPER FUNCTIONS
# -----------------------------------------------------------------------------

def parse_port_range(port_range_str):
    """
    Parse a port range string (e.g. "1-1000") into a list of ports.
    Can also handle single port (e.g. "80") or multiple ranges separated by commas.

    :param port_range_str: A string with port specifications (e.g. "1-100, 443, 8080-8085")
    :return: A sorted list of unique integer ports
    """
    ports = set()
    parts = port_range_str.replace(" ", "").split(",")
    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))

def parse_targets(target_str):
    """
    Parse a string that may contain single IPs or CIDR notations.
    e.g. "192.168.0.1, 10.0.0.0/24"

    :param target_str: A string representing IP addresses or networks.
    :return: A list of ipaddress.IPv4Address or ipaddress.IPv4Network objects.
    """
    targets = []
    items = [t.strip() for t in target_str.split(",")]
    for item in items:
        # Distinguish between IP and CIDR
        if "/" in item:
            # CIDR notation
            try:
                net = ipaddress.ip_network(item, strict=False)
                targets.append(net)
            except ValueError as e:
                print(f"[-] Invalid network: {item} ({e})")
        else:
            # Single IP
            try:
                ip_obj = ipaddress.ip_address(item)
                targets.append(ip_obj)
            except ValueError as e:
                print(f"[-] Invalid IP address: {item} ({e})")
    return targets

def print_results(results, show_banner=False):
    """
    Prints the scan results to the console in a user-friendly format.

    :param results: List of (ip, port, is_open, banner)
    :param show_banner: Whether to display service banners.
    """
    # Sort results by IP, then by port
    # This is just for clean presentation
    results.sort(key=lambda x: (x[0], x[1]))

    for ip, port, is_open, banner in results:
        if is_open:
            if show_banner and banner:
                print(f"[+] {ip}:{port} OPEN | Banner: {banner[:100]}...") 
            else:
                print(f"[+] {ip}:{port} OPEN")
        # Uncomment the line below if you'd also like to see closed ports:
        # else:
        #     print(f"[-] {ip}:{port} CLOSED")

# -----------------------------------------------------------------------------
#                                 MAIN
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python 3 Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python advanced_port_scanner.py --targets 192.168.1.1,10.0.0.0/24 --ports 1-100 --threads 50 --timeout 2.5 --banner
        """
    )
    parser.add_argument("--targets", required=True,
                        help="Comma-separated list of targets (IP or CIDR). e.g. 192.168.0.1, 10.0.0.0/24")
    parser.add_argument("--ports", required=True,
                        help="Port range(s), e.g. '80', '1-1000', '21-25,80,443'")
    parser.add_argument("--threads", type=int, default=100,
                        help="Maximum number of concurrent threads (default=100)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Socket timeout in seconds (default=2.0)")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt to grab banners from open ports")
    args = parser.parse_args()

    # Parse targets and ports
    targets = parse_targets(args.targets)
    if not targets:
        print("[-] No valid targets found. Exiting.")
        sys.exit(1)

    ports = parse_port_range(args.ports)
    if not ports:
        print("[-] No valid ports found. Exiting.")
        sys.exit(1)

    scanner = AdvancedPortScanner(
        targets=targets,
        ports=ports,
        max_threads=args.threads,
        timeout=args.timeout,
        grab_banner=args.banner
    )

    start_time = time.time()
    results = scanner.run()
    end_time = time.time()

    # Print results
    print_results(results, show_banner=args.banner)

    elapsed = end_time - start_time
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
