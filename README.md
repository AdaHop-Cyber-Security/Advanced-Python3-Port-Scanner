Key Features Explained

    Concurrent Scanning
        Uses threading to scan multiple IP/port combinations in parallel.
        You can limit or increase concurrency using --threads.

    Multiple Target Formats
        Accepts CIDR notation (e.g., 10.0.0.0/24) to scan entire subnets.
        Accepts single IP addresses (e.g., 192.168.0.10).
        Use --targets 192.168.0.1,10.0.0.0/24 to scan multiple targets.

    Range of Ports
        Accepts multiple ranges and individual ports (e.g., 1-100,443,8080-8085).
        Automatically validates port numbers.

    Socket Timeout & Error Handling
        Timeout is adjustable via --timeout.
        Safe error handling on connection failures, timeouts, or invalid data.

    Banner Grabbing (Optional)
        If --banner is set, the scanner tries to grab a basic banner from each open port.
        Useful for identifying the running service/version at that port.

    Clean & Pythonic Code
        Docstrings, type hints, modular structure.
        Built with argparse for a professional command-line interface.

    Sorting & Pretty Printing
        Sorting the results by IP and port for clarity.
        Optionally show banners up to 100 characters.

Example Usage

    Scan a Single IP

python advanced_port_scanner.py --targets 192.168.1.10 --ports 80,443 --threads 50 --timeout 2.0 --banner

Scan a Subnet

python advanced_port_scanner.py --targets 192.168.1.0/24 --ports 1-100 --threads 100 --timeout 2.5

Scan Multiple Subnets and Ranges

    python advanced_port_scanner.py --targets 192.168.1.0/24,10.0.0.1 --ports 1-100,443,8080-8081 --threads 200 --banner

Best Practices and Tips

    Use Proper Thread Counts: Setting too many threads can overwhelm your network or cause resource exhaustion.
    Respect Firewalls and Legality: Always ensure you have permission to scan a target. Unauthorized scanning is often illegal.
    Banner Grabbing: Not all services respond with a banner. Some might close the connection on unknown data.
    Use Secure Python Versions: Keep Python updated to avoid security vulnerabilities.
    Logging: For production use, consider adding structured logging (e.g., to JSON or a logging library).

This advanced port scanner should serve as a solid foundation. Feel free to expand on it by adding:

    UDP scanning
    OS detection
    Service fingerprinting
    Rate-limiting
    Advanced logging

