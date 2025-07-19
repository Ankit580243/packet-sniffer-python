import socket
import struct
import textwrap

# Format MAC address
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Format IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest, src, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest), get_mac_addr(src), socket.htons(proto), data[14:]

# Unpack IPv4 Packet
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('!8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Unpack ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP Segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

# Unpack UDP Segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Format multiline output
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# MAIN FUNCTION
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("🟢 Enhanced Packet Sniffer Started. Press Ctrl+C to stop.\n")

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\nEthernet Frame:')
        print(f'   ➤ Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # Check for IPv4
        if eth_proto == 8:
            version, header_len, ttl, proto, src, target, data = ipv4_packet(data)
            print('IPv4 Packet:')
            print(f'   ➤ Version: {version}, Header Length: {header_len}, TTL: {ttl}')
            print(f'   ➤ Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('   ➤ ICMP Packet:')
                print(f'       Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(format_multi_line('       Data: ', data))

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, data = tcp_segment(data)
                print('   ➤ TCP Segment:')
                print(f'       Src Port: {src_port}, Dest Port: {dest_port}')
                print(f'       Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(format_multi_line('       Data: ', data))

            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('   ➤ UDP Segment:')
                print(f'       Src Port: {src_port}, Dest Port: {dest_port}, Length: {size}')
                print(format_multi_line('       Data: ', data))
            else:
                print('   ➤ Other Protocol:')
                print(format_multi_line('       Data: ', data))

if __name__ == "__main__":
    main()
