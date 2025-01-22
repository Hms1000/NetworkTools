'''This is a Python script using Scapy to perform TCP port scanning on a target host'''
import os
import logging
import argparse
import ipaddress
from scapy.all import sr1, IP, TCP

#configure logging and create a log directory if it does not exist
def configure_logging(output_dir):
    log_path = os.path.join(output_dir, 'tcp_port_scan.log')

    #ensure the directory exists
    os.makedirs(output_dir, exist_ok=True)

    #setting up logging to a file including timestamps
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info(f'Logged file created at: {log_path}')

#validating port to make sure its in valid range
def validate_ports(port):
    try:
        if not 1 <= port <= 65535:
            raise ValueError(f'Invalid port {port}. Port should be in the range 1 - 65535.')
        return port

    except ValueError as e:
        raise ValueError(f'Invalid port: {port}. Port should be in range 1 - 65535.') from e


#validating ip address using ipaddress module to make sure its the correct format
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError as e:
        raise ValueError(f'Invalid IP address: {ip}') from e


#constructing the IP and TCP packet
def construct_packet(host, port):
    try:
        ip_packet = IP(dst=host)
        tcp_packet = TCP(dport=port, flags='S')
        return ip_packet / tcp_packet
    except Exception as e:
        logging.error(f'Error constructing packet: {e}')
        raise

#sending the constructed packet and waiting for response
def send_packet(packet, host, port):
    try:
        #send the packet and capture response, timeout set to 3 seconds
        response = sr1(packet, timeout=3, verbose=False)
        logging.info(f'Sending {packet} and waiting for {response}')

        status = None

        #if the host is unresponsive
        if response is None:
            status = "unresponsive"

        #SYN-ACK flag response, meaning the port is open
        elif response.haslayer(TCP) and response[TCP].flags == 0X12:
            status = "open"

        #RST-ACK flag response, meaning the port is filtered
        elif response.haslayer(TCP) and response[TCP].flags == 0X14:
            status = "filtered"

        else:
            status = "closed"
            logging.warning(f'Port {port} returned an unexpected response.')

        #we log and print status for different responses
        if status == 'open':
            logging.info(f'Host {host} is open on port {port}')
            print(f'Host {host} is open on port {port}')

        elif status == 'unresponsive':
            logging.warning(f'Host {host} is unresponsive on port {port}')
            print(f'Host {host} is unresponsive on port {port}')

        elif status == 'filtered':
            logging.warning(f'Host {host} on port {port} is filtered')
            print(f'Host {host} on port {port} is filtered')

        elif status == 'closed':
            logging.error(f'Port {port} is closed on host {host}')
            print(f'Port {port} is closed on host {host}')

        else:
            logging.error(f'Unknown status for port {port} on host {host}')
            print(f'Unknown status for port {port} on host {host}')
        return status

    except TimeoutError as e:
        logging.error(f'Timeout error: {e}')
        print(f'Timeout error: {e}')

    except Exception as e:
        logging.error(f'Error sending packet: {e}')
        print(f'Error sending packet: {e}')
        raise

#main function to put everything together
def main():
    try:
        parser = argparse.ArgumentParser(description='TCP Port Scanner')
        parser.add_argument(
            '--port', type=int, required=True, help='Port to scan on target host'
        )
        parser.add_argument(
            '--host', type=str, default='127.0.0.1', help='Target host (default:127.0.0.1)'
        )
        parser.add_argument(
            '--output_dir', type=str, help='Directory to save logs', default=os.getenv('TCP_LOG_DIR',os.path.join(os.path.expanduser('~'), 'tcp_scan_script'))
        )

        args = parser.parse_args()

        #configure logging
        configure_logging(args.output_dir)

        #validate inputs
        host = validate_ip(args.host)
        port = validate_ports(args.port)

        #constructing the packet
        packet = construct_packet(host, port)

        #sending the packet
        response = send_packet(packet, host, port)


    except Exception as e:
        logging.error(f'Main function error: {e}')
        print(f'Main function error: {e}')
        raise

if __name__ == '__main__':
    main()



