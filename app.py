import socket
import struct
import textwrap

# Indentation tabs for pretty printing
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '


def main():
    # Create raw socket for IP packets
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    HOST = socket.gethostbyname(socket.gethostname())
    conn.bind((HOST, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # 8 indicates IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(TAB_2 + f'Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement,
                 flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(TAB_2 + 'Flags:')
                print(TAB_3 + f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, '
                              f'RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

            # Other protocols
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print(TAB_1 + 'Non-IPv4 Data:')
            print(format_multi_line(DATA_TAB_1, data))


# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Convert MAC address bytes to human-readable format
def get_mac_addr(bytes_addr):
    return ':'.join('{:02x}'.format(b) for b in bytes_addr).upper()


# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Convert IPv4 address bytes to human-readable format
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return (src_port, dest_port, sequence, acknowledgement,
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:])


# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Format binary data into multi-line hex
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
