from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from prometheus_client import start_http_server, Gauge, Summary

import click
import datetime
import logging
import socket
import ssl
import sys
import time

# Create a metric to track time spent and requests made.
REQUEST_TIME = Summary('ssl_certificate_processing_seconds',
                       'Time checking certificates on all provided networks')
g_days_valid = Gauge('ssl_certificate_days_valid',
                     'Number of days before the certificate expires',
                     ['commonName', 'ipAddress', 'hostname', 'issuer', 'serialNumber'])


@click.command()
@click.option('--nets', help='Comma-separated list of networks to scan.', required=True)
@click.option('--port', default=9515, help='Port to listen on for web interface and telemetry. (default "9515")')
@click.option('--ssl_port', default=443, help='Port to scan on remote hosts for SSL certificates. (default "443")')
@click.option('--sleep', default=43200, help='Time to wait between scans in seconds. (default "43200")')
@click.option('--timeout', default=.5, help='Timeout interval for SSL connections in seconds. (default ".5")')
@click.option('--no_dns', default=False, help='Do not perform rDNS lookups',
              is_flag=True)
@click.option('--debug', default='False', help='Debug level logging. (default "False")', is_flag=True)
def main(nets, port, ssl_port, sleep, timeout, no_dns, debug):

    # Setup logging
    log = logging.getLogger()
    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

    # Start the HTTP server
    start_http_server(port)
    logging.info('Listening on {0}'.format(port))

    # Read networks to scan and scan
    ips = []
    network_ips = []
    for network in nets.split(','):
        try:
            network_ips = IPNetwork(network.rstrip())
        except AddrFormatError as e:
            logging.info(e)
            exit(1)

        # Exclude the network and broadcast addresses
        for ip in network_ips[1:-1]:
            ips.append(str(ip))
    while True:
        logging.info('Starting scan of {0} IP addresses, port {1}'.format(len(ips), ssl_port))
        ssl_certificate_days_valid(ssl_port=ssl_port, ips=ips, timeout=timeout, no_dns=no_dns)
        logging.info('Finished scan')
        time.sleep(sleep)


@REQUEST_TIME.time()
def ssl_certificate_days_valid(ssl_port, ips, timeout, no_dns):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    for ip in ips:
        context = ssl.create_default_context()

        # Since we're checking expiry, don't worry about the hostname
        context.check_hostname = False
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=ip)
        conn.settimeout(timeout)

        try:
            conn.connect((ip, ssl_port))
            ssl_info = conn.getpeercert()
        except socket.timeout:
            continue
        except ConnectionRefusedError:
            continue
        except ssl.SSLError as e:
            logging.debug("Couldn't connect to {0} on port {1}, got error {2}".format(ip, ssl_port, e))
            continue
        finally:
            conn.close()

        if len(ssl_info) > 0:
            days_valid = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt) - datetime.datetime.utcnow()
            common_name = ssl_info['subject'][-1][0][1]
            serial_number = ssl_info['serialNumber']
            issuer = ssl_info['issuer'][1][0][1]

            if not no_dns:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = ""

                g_days_valid.labels(commonName=common_name,
                                    ipAddress=ip,
                                    hostname=hostname,
                                    issuer=issuer,
                                    serialNumber=serial_number).set(days_valid.days)
            else:
                g_days_valid.labels(commonName=common_name,
                                    ipAddress=ip,
                                    hostname="",
                                    issuer=issuer,
                                    serialNumber=serial_number).set(days_valid.days)
        else:
            logging.debug("No certificate information received for {0} on port {1}".format(ip, ssl_port))

if __name__ == '__main__':
    main()
