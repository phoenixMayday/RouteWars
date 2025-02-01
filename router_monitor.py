import os
os.sys.path.append('./env/lib/python3.11/site-packages/')

from scapy.all import *
from netfilterqueue import NetfilterQueue
import socket
import logging

# Set up logging
logging.basicConfig(filename='router.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# Dictionary to store device IPs and their accessed websites/IPs
device_access_log = {}

def packet_callback(packet):
    # Convert the packet to a Scapy packet
    scapy_packet = IP(packet.get_payload())

    # Extract source IP (device on wlan0)
    src_ip = scapy_packet.src
    dst_ip = scapy_packet.dst

    # Log the destination IP/website
    if src_ip in device_access_log:
        device_access_log[src_ip].append(dst_ip)
    else:
        device_access_log[src_ip] = [dst_ip]

    # Log the access to a file
    logging.info(f"Device {src_ip} accessed {dst_ip}")

    # Accept the packet (forward it)
    packet.accept()

def main():
    # Bind the NFQUEUE to the callback function
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, packet_callback)

    try:
        print("Starting packet interception...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping packet interception...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
