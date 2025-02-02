#!/usr/bin/env python3
"""
Advanced Python 3 Port Scanner

DISCLAIMER: This tool is intended for educational and authorized testing purposes only.
The author is not responsible for any misuse or illegal activities conducted using this software.
Use at your own risk.

Features:
1. Concurrent scanning with configurable worker threads.
2. TCP and UDP scanning with customizable timeouts.
3. Optional banner grabbing and service fingerprinting for detected open ports.
4. OS detection using ping-based TTL analysis.
5. Rate-limiting to control scanning speed.
6. Advanced logging (to console and/or file).
7. CIDR notation support for scanning multiple hosts.
8. CSV output for results.
9. Real-time progress display (optional).
10. Robust error handling and Pythonic best practices.

Usage:
    python advanced_port_scanner.py --targets 192.168.0.1/24 --ports 1-1000 --threads 100 --timeout 2.0 \
        --banner --protocol both --rate-limit 50 --os-detect --output results.csv --progress
"""

import socket
import ipaddress
import argparse
import sys
import queue
import threading
import time
import logging
import subprocess
import re
import csv

# -------------------------------------------------------------------------------
#                           RATE LIMITER CLASS
# -------------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rate):
        """
        Initialize rate limiter.
        
        :param rate: Number of operations per second.
        """
        self.rate = rate
        self.lock = threading.Lock()
        self.last = time.time()

    def wait(self):
        """
        Wait until the next operation is allowed.
        """
        with self.lock:
            now = time.time()
            interval = 1.0 / self.rate
            elapsed = now - self.last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self.last = time.time()

# -------------------------------------------------------------------------------
#                         SERVICE FINGERPRINTING
# -------------------------------------------------------------------------------

def fingerprint_service(banner):
    """
    Simple service fingerprinting based on banner content.
    
    :param banner: Service banner string.
    :return: A string representing the identified service.
    """
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "SSH"
    elif "http" in banner_lower:
        return "HTTP"
    elif "smtp" in banner_lower:
        return "SMTP"
    elif "ftp" in banner_lower:
        return "FTP"
    elif "pop3" in banner_lower:
        return "POP3"
    elif "imap" in banner_lower:
        return "IMAP"
    elif "rdp" in banner_lower:
        return "RDP"
    else:
        return "Unknown"

# -------------------------------------------------------------------------------
#                           OS DETECTION
# -------------------------------------------------------------------------------

def detect_os(ip):
    """
    Detect operating system of the target host based on ping TTL value.
    
    :param ip: Target IP address (str).
    :return: A string representing the guessed OS.
    """
    try:
        if sys.platform.startswith("win"):
            command = ["ping", "-n", "1", ip]
        else:
            command = ["ping", "-c", "1", ip]
        output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
        ttl_search = re.search(r"ttl[=\s]*(\d+)", output, re.IGNORECASE)
        if ttl_search:
            ttl = int(ttl_search.group(1))
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
        return "Unknown"
    except Exception as e:
        logging.error(f"OS detection failed for {ip}: {e}")
        return "Unknown"

# -------------------------------------------------------------------------------
#                     ADVANCED PORT SCANNER CLASS
# -------------------------------------------------------------------------------

class AdvancedPortScanner:
    """
    Advanced port scanner supporting:
    - Multiple targets (including CIDR ranges)
    - Configurable port ranges
    - Concurrent scanning with threading
    - Banner grabbing and service fingerprinting (optional)
    - TCP and UDP scanning
    - Rate limiting
    - Real-time progress display (optional)
    """

    def __init__(self, targets, ports, max_threads=100, timeout=2.0,
                 grab_banner=False, protocol="tcp", rate_limit=0, show_progress=False):
        """
        Initialize the port scanner.
        
        :param targets: List of IPs or subnets (ipaddress.IPv4Network or IPv4Address).
        :param ports: List of integer port numbers to scan.
        :param max_threads: Maximum number of concurrent threads.
        :param timeout: Socket timeout in seconds.
        :param grab_banner: Whether to attempt grabbing service banners.
        :param protocol: Scanning protocol ("tcp", "udp", or "both").
        :param rate_limit: Maximum number of scan operations per second (0 for unlimited).
        :param show_progress: Whether to display real-time progress.
        """
        self.targets = targets
        self.ports = ports
        self.max_threads = max_threads
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.protocol = protocol.lower()
        self.rate_limit = rate_limit
        self.show_progress = show_progress
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit > 0 else None

        # A thread-safe queue to handle IP-port-protocol jobs.
        self.task_queue = queue.Queue()
        # Results stored as list of tuples: (ip, port, protocol, status, banner, fingerprint)
        self.results = []
        self.lock = threading.Lock()

        self.total_tasks = 0
        self.completed_tasks = 0

    def enqueue_jobs(self):
        """
        Enqueue all (target, port, protocol) combinations into the task queue.
        """
        for target in self.targets:
            if isinstance(target, ipaddress.IPv4Network):
                for host in target.hosts():
                    for port in self.ports:
                        if self.protocol in ("tcp", "both"):
                            self.task_queue.put((str(host), port, "tcp"))
                        if self.protocol in ("udp", "both"):
                            self.task_queue.put((str(host), port, "udp"))
            else:
                for port in self.ports:
                    if self.protocol in ("tcp", "both"):
                        self.task_queue.put((str(target), port, "tcp"))
                    if self.protocol in ("udp", "both"):
                        self.task_queue.put((str(target), port, "udp"))
        self.total_tasks = self.task_queue.qsize()

    def scan_port(self, ip, port, protocol):
        """
        Scan a single port for a given IP using specified protocol.
        
        :param ip: The target IP address (str).
        :param port: The port number to test (int).
        :param protocol: "tcp" or "udp".
        :return: (ip, port, protocol, status, banner, fingerprint)
        """
        if self.rate_limiter:
            self.rate_limiter.wait()

        banner = ""
        fingerprint = "Unknown"
        status = "closed"

        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((ip, port))
                status = "open"
                if self.grab_banner:
                    try:
                        # Send a generic HTTP HEAD request; may work on many services.
                        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                    except Exception as e:
                        logging.debug(f"Banner grab failed on {ip}:{port} (TCP): {e}")
                        banner = ""
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                status = "closed"
                banner = ""
            finally:
                sock.close()

        elif protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(b"", (ip, port))
                data, addr = sock.recvfrom(1024)
                status = "open"
                banner = data.decode(errors="ignore").strip() if data else ""
            except socket.timeout:
                status = "open|filtered"
                banner = ""
            except Exception as e:
                status = "closed"
                banner = ""
            finally:
                sock.close()

        if banner:
            fingerprint = fingerprint_service(banner)
        logging.debug(f"Scanned {ip}:{port}/{protocol.upper()} - {status}")
        return (ip, port, protocol, status, banner, fingerprint)

    def worker_thread(self):
        """
        Worker thread that continuously processes tasks from the queue until empty.
        """
        while True:
            try:
                ip, port, protocol = self.task_queue.get_nowait()
            except queue.Empty:
                break

            result = self.scan_port(ip, port, protocol)
            with self.lock:
                self.results.append(result)
                self.completed_tasks += 1

            self.task_queue.task_done()

    def progress_printer(self):
        """
        Thread to display real-time progress.
        """
        while self.completed_tasks < self.total_tasks:
            with self.lock:
                progress = (self.completed_tasks / self.total_tasks) * 100 if self.total_tasks > 0 else 0
            logging.info(f"Progress: {self.completed_tasks}/{self.total_tasks} ({progress:.2f}%) completed")
            time.sleep(1)
        logging.info("Progress: 100% completed.")

    def run(self):
        """
        Enqueue tasks, spawn worker threads, (optionally) a progress thread, and run the scan.
        
        :return: A list of (ip, port, protocol, status, banner, fingerprint) results.
        """
        self.enqueue_jobs()

        threads = []
        num_threads = min(self.max_threads, self.task_queue.qsize())
        if self.show_progress:
            progress_thread = threading.Thread(target=self.progress_printer, daemon=True)
            progress_thread.start()

        for _ in range(num_threads):
            t = threading.Thread(target=self.worker_thread, daemon=True)
            t.start()
            threads.append(t)

        self.task_queue.join()

        for t in threads:
            t.join()

        return self.results

# -------------------------------------------------------------------------------
#                           HELPER FUNCTIONS
# -------------------------------------------------------------------------------

def parse_port_range(port_range_str):
    """
    Parse a port range string (e.g. "1-1000") into a list of ports.
    Handles single ports or multiple ranges separated by commas.
    
    :param port_range_str: e.g. "1-100,443,8080-8085"
    :return: Sorted list of unique integer ports.
    """
    ports = set()
    for part in port_range_str.replace(" ", "").split(","):
        if "-" in part:
            try:
                start, end = part.split("-")
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except Exception as e:
                logging.error(f"Error parsing port range '{part}': {e}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception as e:
                logging.error(f"Error parsing port '{part}': {e}")
    return sorted(list(ports))

def parse_targets(target_str):
    """
    Parse a string that may contain single IPs or CIDR notations.
    
    :param target_str: e.g. "192.168.0.1,10.0.0.0/24"
    :return: List of ipaddress.IPv4Address or IPv4Network objects.
    """
    targets = []
    for item in target_str.split(","):
        item = item.strip()
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                targets.append(net)
            except ValueError as e:
                logging.error(f"Invalid network: {item} ({e})")
        else:
            try:
                ip_obj = ipaddress.ip_address(item)
                targets.append(ip_obj)
            except ValueError as e:
                logging.error(f"Invalid IP address: {item} ({e})")
    return targets

def print_results(results, show_banner=False):
    """
    Print scan results to console in a user-friendly format.
    
    :param results: List of tuples (ip, port, protocol, status, banner, fingerprint).
    :param show_banner: Whether to display service banners.
    """
    results.sort(key=lambda x: (x[0], x[1], x[2]))
    for ip, port, protocol, status, banner, fingerprint in results:
        if status in ("open", "open|filtered"):
            output = f"[+] {ip}:{port}/{protocol.upper()} - {status.upper()}"
            if show_banner and banner:
                output += f" | Banner: {banner[:100]}..."
            if fingerprint != "Unknown":
                output += f" | Fingerprint: {fingerprint}"
            print(output)

def write_csv(results, filename):
    """
    Write scan results to a CSV file.
    
    :param results: List of tuples (ip, port, protocol, status, banner, fingerprint).
    :param filename: Output CSV filename.
    """
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Port', 'Protocol', 'Status', 'Banner', 'Fingerprint']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, port, protocol, status, banner, fingerprint in results:
            writer.writerow({
                'IP': ip,
                'Port': port,
                'Protocol': protocol.upper(),
                'Status': status,
                'Banner': banner,
                'Fingerprint': fingerprint
            })

# -------------------------------------------------------------------------------
#                                 MAIN
# -------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python 3 Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Example:
  python advanced_port_scanner.py --targets 192.168.1.1,10.0.0.0/24 --ports 1-100 --threads 50 --timeout 2.5 \
      --banner --protocol both --rate-limit 50 --os-detect --output results.csv --progress
        """
    )
    parser.add_argument("--targets", required=True,
                        help="Comma-separated list of targets (IP or CIDR). e.g. 192.168.0.1,10.0.0.0/24")
    parser.add_argument("--ports", required=True,
                        help="Port range(s), e.g. '80', '1-1000', '21-25,80,443'")
    parser.add_argument("--threads", type=int, default=100,
                        help="Maximum number of concurrent threads (default=100)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Socket timeout in seconds (default=2.0)")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt to grab banners from open ports")
    parser.add_argument("--protocol", choices=["tcp", "udp", "both"], default="tcp",
                        help="Scanning protocol: tcp, udp, or both (default=tcp)")
    parser.add_argument("--rate-limit", type=float, default=0,
                        help="Maximum number of scan operations per second (0 for unlimited)")
    parser.add_argument("--os-detect", action="store_true",
                        help="Perform OS detection on hosts with open ports")
    parser.add_argument("--output", help="CSV file to write results")
    parser.add_argument("--progress", action="store_true",
                        help="Display real-time progress of the scan")
    parser.add_argument("--log-file", default=None,
                        help="Path to log file (default: logs to console)")
    parser.add_argument("--log-level", default="INFO",
                        help="Logging level (DEBUG, INFO, WARNING, ERROR; default=INFO)")
    args = parser.parse_args()

    # Configure logging: if log_file is provided, log to file; otherwise, log to console.
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        print(f"Invalid log level: {args.log_level}")
        sys.exit(1)
    logging.basicConfig(level=numeric_level,
                        filename=args.log_file,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    logging.info("Starting Advanced Python Port Scanner")

    targets = parse_targets(args.targets)
    if not targets:
        logging.error("No valid targets found. Exiting.")
        sys.exit(1)

    ports = parse_port_range(args.ports)
    if not ports:
        logging.error("No valid ports found. Exiting.")
        sys.exit(1)

    scanner = AdvancedPortScanner(
        targets=targets,
        ports=ports,
        max_threads=args.threads,
        timeout=args.timeout,
        grab_banner=args.banner,
        protocol=args.protocol,
        rate_limit=args.rate_limit,
        show_progress=args.progress
    )

    start_time = time.time()
    results = scanner.run()
    end_time = time.time()

    print_results(results, show_banner=args.banner)

    if args.output:
        write_csv(results, args.output)
        print(f"Results written to {args.output}")

    elapsed = end_time - start_time
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds.")

    # OS detection for hosts with open ports
    if args.os_detect:
        unique_hosts = {result[0] for result in results if result[3] in ("open", "open|filtered")}
        if unique_hosts:
            print("\n[*] Performing OS Detection:")
            for ip in sorted(unique_hosts):
                os_info = detect_os(ip)
                print(f"[*] {ip} - {os_info}")
        else:
            print("[*] No open hosts found for OS detection.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"\n[!] An unexpected error occurred: {e}")

"""
----------------------------------------------------------
Elaborate Explanation:
----------------------------------------------------------
This advanced Python port scanner is designed as a comprehensive tool for network
reconnaissance and security auditing. Below are the key aspects and features of the tool:

1. **Concurrent Scanning:**
   - Utilizes Python threading and a thread-safe queue to scan multiple hosts and ports concurrently.
   - The number of concurrent threads is configurable via the --threads parameter.

2. **Protocol Support:**
   - Supports both TCP and UDP scanning. Users can choose to scan using only TCP, only UDP, or both.
   - For UDP scanning, the tool distinguishes between ports that are "open" (data is returned)
     and those that are "open|filtered" (no response is received).

3. **Banner Grabbing and Service Fingerprinting:**
   - Optionally grabs banners from open ports (e.g., using a generic HTTP HEAD request).
   - Applies simple string-based heuristics to identify services (e.g., SSH, HTTP, FTP).

4. **OS Detection:**
   - Uses a basic ping-based TTL analysis to provide a guess as to the operating system of the target.
   - This is performed after the scan for hosts that have open ports.

5. **Rate Limiting:**
   - A built-in rate limiter controls the number of scan operations per second, reducing the chance
     of overloading the target network and minimizing the risk of detection.

6. **Advanced Logging:**
   - Configurable logging supports both console and file output. Log levels (DEBUG, INFO, etc.) can be set.
   - Detailed logging helps with troubleshooting and provides insight into the scanning process.

7. **CSV Output:**
   - The tool can output the scan results to a CSV file for further analysis or reporting, making it easy
     to integrate with other tools or workflows.

8. **Real-Time Progress Display:**
   - An optional progress indicator shows the percentage of completed tasks in real time, giving immediate
     feedback during long scans.

9. **Robust Error Handling:**
   - Comprehensive exception handling throughout the code ensures that errors are logged and that the scanner
     exits gracefully if unexpected issues occur.

----------------------------------------------------------
Usage Disclaimer:
----------------------------------------------------------
This tool is intended for educational purposes and authorized network testing only.
Unauthorized scanning of networks is illegal and unethical. The author is not responsible for any
misuse or damage caused by this tool. Always obtain proper permission before scanning any network or host.
