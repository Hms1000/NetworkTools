# DNS Query Script

## Overview
This is a  Python script performing DNS lookups using the Scapy library. It sends queries to DNS servers and logs the responses for analysis. The script is useful for network diagnostics, research, and troubleshooting DNS issues.

## Requirements
To use this script, ensure Python is installed on your system along with the Scapy library.

## Install Scapy
To install Scapy, run the following command in your terminal or command prompt:

```bash
pip install scapy
```

## Usage
This script is designed to be used via the command line interface (CLI). Below are the available command-line arguments and how to use them.
Command Syntax:
```bash
python <script_name> --domain <domain_name> --dns_server <dns_server_address> --output_dir <log_directory>
```

Arguments:
--domain <domain_name>: The domain name you wish to query (e.g., github.com).
--dns_server <dns_server_address>: The IP address of the DNS server you want to query (e.g., 8.8.8.8). Default is 8.8.8.8 if not specified.
--output_dir <log_directory>: The directory where log files will be saved. If not provided, the script saves logs to ~/Downloads/dns_query_script.
Example Command:

```bash
python dns_query_script.py --domain github.com --dns_server 8.8.8.8 --output_dir ~/Documents/dns_logs
```

This command will:
Query the DNS server at 8.8.8.8 for the domain github.com.
Save the log files to ~/Documents/dns_logs.
Log File:
The script creates a log file named dns_query.log in the specified --output_dir. This log contains information about the DNS query and any responses received, including errors and warnings.

## Features:
Performs DNS queries and displays the response.
Logs the DNS queries and responses in a log file for later review.
Provides basic error handling, such as checking for network issues or no response from the DNS server.
## Troubleshooting:
Ensure that Scapy is correctly installed with pip install scapy.
Make sure you are connected to the internet and that the DNS server is reachable.
If you encounter any errors, check the logs for detailed information.
## License:
This project is licensed under the MIT License - see the LICENSE file for details
