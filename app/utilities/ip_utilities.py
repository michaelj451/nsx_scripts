#!/usr/bin/env python3
# app/utilities/ip_utilities.py

from datetime import datetime, timezone
import logging
import random
import string
import socket
import struct
import ipaddress


def get_iso_zulu_time():
    return datetime.now(timezone.utc).isoformat()

def generate_random_string(stringLength=5):
            
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for i in range(stringLength))

def cidr_to_netmask(self, cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def convert_cidr_to_subnet_mask(cidr):
    # Create an IPv4 network object with a dummy IP and the given CIDR
    network = ipaddress.ip_network(f"0.0.0.0/{cidr}")
    # Return the subnet mask as a string
    return str(network.netmask)

def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count("1") for x in netmask.split(".")])

def ip_to_decimal(ip):
    return int(ipaddress.ip_address(ip))

def decimal_to_ip(ip):
    return str(ipaddress.ip_address(ip))

def subnet_to_ip_low_high(subnet):
    
    network = ipaddress.ip_network(subnet, strict=False)
    ip_low = int(network.network_address)
    ip_high = int(network.broadcast_address)
    if ip_low > 4294967296: ip_low = 5000000000
    if ip_high > 4294967296: ip_high = 5000000000
    
    return ip_low, ip_high
    
def range_to_decimal_low_high(ip_range_in):
    ip_range = ip_range_in.split('-')
    ip_low = int(ip_to_decimal(ip_range[0]))
    ip_high = int(ip_to_decimal(ip_range[1]))
    if ip_low > 4294967296: ip_low = 5000000000
    if ip_high > 4294967296: ip_high = 5000000000
    
    return ip_low, ip_high

class AddrObjLowHigh:
    
    def __init__(self, obj_value, obj_type):
        self.obj_value = obj_value
        self.obj_type = obj_type
        self.get_addr_obj_ip_low_high()

    def get_addr_obj_ip_low_high(self):
        
        if self.obj_type == 'ip-netmask':
            try:
                self.ip_low, self.ip_high = subnet_to_ip_low_high(self.obj_value)
            except Exception as e:
                logging.error(f'error converting subnet to ip_low, ip_high: {str(e)}')
        elif self.obj_type == 'ip-range':
            try:
                self.ip_low, self.ip_high = range_to_decimal_low_high(self.obj_value)
            except Exception as e:
                logging.error(f'error converting range to ip_low, ip_high: {str(e)}')
        else:
            try:
                self.ip_low = None
                self.ip_high = None
            except Exception as e:
                logging.error(f'error converting ip to ip_low, ip_high: {str(e)}')