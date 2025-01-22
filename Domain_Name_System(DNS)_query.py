'''This is a Python script to perform dns look ups using Scapy '''
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sr1
import argparse
import logging
import os

'''argparse is a python module to enable the user to interact through command line (CLI),
We are importing logging to track progress and assist with debugging 
the os module is used for system level interaction eg to create files'''

#configure logging
def configure_logging(output_dir):
    log_path = os.path.join(output_dir, 'dns_query.log')

    #ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s-%(levelname)s-%(message)s'
    )

''' Create the dns_packet. Packets must encapsulate layers correctly,
 Ether (layer 2), IP (layer 3), UDP (layer 4), DNS (layer 7)'''

def make_dns_packet(dns_server, domain):
    try:
        dns_packet = (
            Ether() /
            IP(dst=dns_server) /
            UDP(dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain))
        )

        dns_packet.show()
        logging.info(f'Successfully created DNS packet: {dns_packet}')

        return dns_packet

    except Exception as e:
        logging.error(f'Error creating DNS packet: {e}')
        raise Exception(f'Error creating DNS packet: {e}')

#Here we are sending the DNS packet and waiting for response
def sending_dns_packet(dns_packet, dns_server, domain):
    try:
        response = sr1(dns_packet, timeout=2, verbose=False)
        print(f'Sending DNS query to {dns_server} for {domain}...')

        if not response:
            logging.warning(f'No response. Check server(s) or Network Connection')
            print(f'No response. Check server(s) or Network Connection')
            return

        response.show()
        logging.info('DNS response received successfully')

        return response

    except Exception as e:
        logging.error(f'Error sending DNS packet: {e}')
        raise Exception(f'Error sending DNS packet: {e}')

#Process and display responses
def process_dns_response(response):
    try:
        if not response:
            print('\nNo response received from the DNS server.')
            logging.warning('No response. Check server(s) or Network Connection')
            return

        print('\nDNS response')
        response.show()
        logging.info('DNS response displayed successfully')

    except Exception as e:
        logging.error(f'Unexpected error: {e}')
        raise

#Main function to put  everything together
def main():
    try:
        parser = argparse.ArgumentParser(description='Domain Name System(DNS) query')
        parser.add_argument(
            '--dns_server', type=str, help='IP address of the DNS Server to query (default:8.8.8.8)', default='8.8.8.8', required=False
        )
        parser.add_argument(
            '--domain', type=str, help='Domain name to query (e.g. facebook.com)', required=True
        )
        parser.add_argument(
            '--output_dir', help='Output directory for logs', default=os.getenv('DNS_LOG_DIR', os.path.join(os.path.expanduser('~'), 'Downloads', 'dns_query_script'))
        )
        args = parser.parse_args()

        #configure logging
        configure_logging(args.output_dir)

        #make DNS packets
        dns_packet = make_dns_packet(args.dns_server, args.domain)

        #send response
        response = sending_dns_packet(dns_packet, args.dns_server, args.domain)

        #displaying response
        process_dns_response(response)

    except Exception as e:
        logging.error(f'Main function error: {e}')
        print(f'Main function error: {e}')
        raise

if __name__ == '__main__':
    main()

