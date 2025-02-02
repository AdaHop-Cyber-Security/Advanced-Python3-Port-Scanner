Below is an example of a GitHub README section that explains the usage, features, and provides several examples for running the Advanced Python 3 Port Scanner.

---

# Advanced Python 3 Port Scanner

**Disclaimer:**  
This tool is intended for educational and authorized testing purposes only. The author is not responsible for any misuse or illegal activities conducted using this software. Use at your own risk.

## Features

- **Concurrent Scanning:**  
  Scan multiple hosts and ports concurrently with configurable worker threads.

- **Protocol Support:**  
  Supports TCP and UDP scanning. You can choose to scan either protocol or both simultaneously.

- **Banner Grabbing & Service Fingerprinting:**  
  Optionally grab service banners and apply heuristics to identify common services (e.g., SSH, HTTP, FTP).

- **OS Detection:**  
  Performs basic OS detection using ping-based TTL analysis on hosts with open ports.

- **Rate Limiting:**  
  Control the scanning speed by limiting the number of scan operations per second.

- **CIDR Notation Support:**  
  Scan single IPs or whole subnets using CIDR notation.

- **CSV Output:**  
  Save the scan results to a CSV file for further analysis.

- **Real-Time Progress Display:**  
  Optionally show a live progress indicator during scanning.

- **Robust Error Handling & Advanced Logging:**  
  Provides detailed logging to the console or a file to assist with troubleshooting.

## Usage

You can run the port scanner using Python 3 from the command line. Below is the basic usage:

```bash
python advanced_port_scanner.py --targets <TARGETS> --ports <PORT_RANGE> [OPTIONS]
```

### Required Arguments

- `--targets`  
  Comma-separated list of target IP addresses or CIDR subnets.  
  **Example:** `192.168.0.1,10.0.0.0/24`

- `--ports`  
  Port range(s) to scan. Accepts single ports, ranges (e.g., `1-1000`), or a combination separated by commas.  
  **Example:** `80,443,1000-1010`

### Optional Arguments

- `--threads`  
  Maximum number of concurrent threads (default: 100).  
  **Example:** `--threads 50`

- `--timeout`  
  Socket timeout in seconds (default: 2.0).  
  **Example:** `--timeout 2.5`

- `--banner`  
  Enable banner grabbing on open ports.

- `--protocol`  
  Specify the scanning protocol: `tcp`, `udp`, or `both` (default: `tcp`).  
  **Example:** `--protocol both`

- `--rate-limit`  
  Maximum number of scan operations per second (0 for unlimited).  
  **Example:** `--rate-limit 50`

- `--os-detect`  
  Perform OS detection on hosts with open ports.

- `--output`  
  CSV file to write the scan results.  
  **Example:** `--output results.csv`

- `--progress`  
  Display a real-time progress indicator during the scan.

- `--log-file`  
  Path to a log file. If not provided, logs are output to the console.

- `--log-level`  
  Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`; default: `INFO`).

## Examples

### 1. Scan a Single Host on a Specific Port

Scan IP `192.168.1.1` on port `80` using TCP:
```bash
python advanced_port_scanner.py --targets 192.168.1.1 --ports 80
```

### 2. Scan a Range of Ports on a Single Host with Banner Grabbing

Scan IP `192.168.1.1` on ports `1-100` and grab banners from open ports:
```bash
python advanced_port_scanner.py --targets 192.168.1.1 --ports 1-100 --banner
```

### 3. Scan a Subnet Using Both TCP and UDP Protocols with OS Detection

Scan the subnet `10.0.0.0/24` on ports `21-25,80,443` using both protocols, with OS detection enabled:
```bash
python advanced_port_scanner.py --targets 10.0.0.0/24 --ports 21-25,80,443 --protocol both --os-detect
```

### 4. Scan with Custom Thread Count, Timeout, Rate-Limit, and CSV Output

Scan the subnet `192.168.0.1/24` on ports `1-1000` using 100 threads, a 2-second timeout, a rate limit of 50 operations per second, outputting results to `results.csv` with real-time progress:
```bash
python advanced_port_scanner.py --targets 192.168.0.1/24 --ports 1-1000 --threads 100 --timeout 2.0 \
    --banner --protocol both --rate-limit 50 --os-detect --output results.csv --progress
```

## Logging

By default, logging messages are printed to the console. To log to a file, use the `--log-file` parameter:
```bash
python advanced_port_scanner.py --targets 192.168.1.1 --ports 80 --log-file scanner.log --log-level DEBUG
```

---

**Note:**  
Always ensure you have proper authorization before scanning any network or host. Unauthorized scanning can be illegal and unethical.

Happy scanning!
