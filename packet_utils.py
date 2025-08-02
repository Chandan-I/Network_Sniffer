import socket
import struct

def get_protocol_name(proto_num):
    protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocols.get(proto_num, f"Unknown({proto_num})")

def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

def parse_packet(packet):
    eth_length = 14
    if len(packet) < eth_length + 20:
        return None

    ip_header = packet[eth_length:20+eth_length]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    protocol_num = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    protocol = get_protocol_name(protocol_num)
    src_port = dest_port = '-'

    # TCP or UDP header parsing
    if protocol in ['TCP', 'UDP']:
        offset = eth_length + iph_length
        if len(packet) >= offset + 4:
            tcp_udp_header = packet[offset:offset+4]
            src_port, dest_port = struct.unpack('!HH', tcp_udp_header)

    domain = get_domain(dest_ip)
    return {
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        'src_port': src_port,
        'dest_port': dest_port,
        'domain': domain,
        'protocol': protocol
    }