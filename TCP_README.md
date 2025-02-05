# TCP Port Scanner Script

## Overview
This Python script performs TCP port scanning on a target host using the Scapy library. It sends SYN packets to a specified port on the target host and logs the responses. This can help determine whether a port is open, closed, or filtered. It is useful for network diagnostics, penetration testing, and security assessments.

## Requirements
To run this script, install Python on your machine along with the Scapy library.

## Install Scapy
To install Scapy, use the following command:
```bash
pip install scapy
```

## Usage
This script can be run from the command line (CLI) and accepts the following parameters:
Command Syntax:
```bash
python <script_name> --port <port_number> --host <host_address> --output_dir <log_directory>
```

Arguments:
--port <port_number>: The port number you want to scan on the target host (e.g., 80, 443).
--host <host_address>: The IP address of the host you want to scan. Defaults to 127.0.0.1 if not specified.
--output_dir <log_directory>: The directory where log files will be saved. If not provided, logs will be saved to ~/tcp_scan_script.
Example Command:
```bash
python tcp_port_scanner.py --port 80 --host 192.168.1.1 --output_dir ~/Documents/tcp_logs
```

This command will:
Scan port 80 on the host 192.168.1.1.
Save the logs in ~/Documents/tcp_logs.
Log File:
The script generates a log file named tcp_port_scan.log in the specified --output_dir. The log includes details about the scan, such as port status and any errors or warnings encountered during execution.

## Features
Sends SYN packets to the target port to check if it’s open, closed, or filtered.
Logs the results, including timestamped entries for each scan.
Provides error handling for invalid IP addresses and ports, and handles timeouts and other network issues.
Displays the status of the target port: open, closed, filtered, or unresponsive.

## Troubleshooting
Ensure Scapy is installed using pip install scapy.
Make sure the target host is reachable and the specified port is open for scanning.
Check the logs if you encounter errors like timeouts or invalid input.

## License:
This project is licensed under the MIT License - see the LICENSE file for details.
