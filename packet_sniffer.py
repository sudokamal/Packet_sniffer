import socket
import struct
import textwrap
import argparse
import sys
import time
import os

TAB_1 = '   '
DATA_TAB_1 = '   '

# Colors
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"{BOLD}{CYAN}Network Packet Sniffer{RESET}")
    print(f"{BOLD}{RED}Developed by Kamal Dhakar , Rajnish Das , Natasha Nagouri   {RESET}\n")

def get_interfaces():
    return socket.if_nameindex()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

def get_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        "URG": (offset_reserved_flags & 32) >> 5,
        "ACK": (offset_reserved_flags & 16) >> 4,
        "PSH": (offset_reserved_flags & 8) >> 3,
        "RST": (offset_reserved_flags & 4) >> 2,
        "SYN": (offset_reserved_flags & 2) >> 1,
        "FIN": offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(f'{byte:02x}' for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface")
    parser.add_argument("-p", "--protocol")
    parser.add_argument("--port", type=int)
    parser.add_argument("-d", "--detail", action="store_true")
    parser.add_argument("-x", "--hexdump", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

    banner()

    try:
        if args.interface:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.bind((args.interface, 0))
        else:
            interfaces = get_interfaces()
            print("Available interfaces:")
            for i in interfaces:
                print(i[1])
            iface = input("Select interface: ")
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.bind((iface, 0))
    except PermissionError:
        print("Permission denied")
        sys.exit(1)
    except:
        print("Invalid interface")
        sys.exit(1)

    packet_count = 0
    start_time = time.time()
    last_time = start_time
    last_count = 0

    log_file = open("log.txt", "w")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            packet_count += 1

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            if eth_proto == 8:
                ttl, proto, src, target, data = ipv4_packet(data)

                protocol_name = ""
                info = ""

                if proto == 1:
                    protocol_name = "ICMP"
                    icmp_type, code, checksum, data = icmp_packet(data)
                    info = f"Type:{icmp_type} Code:{code}"

                elif proto == 6:
                    protocol_name = "TCP"
                    src_port, dest_port, seq, ack, flags, data = tcp_segment(data)
                    info = f"{src_port}->{dest_port} Flags:{flags}"

                    if args.port and args.port not in (src_port, dest_port):
                        continue

                elif proto == 17:
                    protocol_name = "UDP"
                    src_port, dest_port, size, data = udp_segment(data)
                    info = f"{src_port}->{dest_port}"

                    if args.port and args.port not in (src_port, dest_port):
                        continue

                if args.protocol and args.protocol.lower() != protocol_name.lower():
                    continue

                timestamp = time.strftime('%H:%M:%S', time.localtime())
                length = len(raw_data)

                output = f"{timestamp} | {src} -> {target} | {protocol_name} | Len:{length}"
                print(output)
                log_file.write(output + "\n")

                if args.detail:
                    print(TAB_1 + info)

                if args.hexdump:
                    print(format_multi_line(DATA_TAB_1, raw_data))

            current_time = time.time()
            if current_time - last_time >= 1:
                rate = packet_count - last_count
                print(f"Packets/sec: {rate}")
                last_time = current_time
                last_count = packet_count

    except KeyboardInterrupt:
        duration = time.time() - start_time
        print("\n\nCapture stopped")
        print(f"Total packets: {packet_count}")
        print(f"Duration: {round(duration,2)} sec")
        print(f"Average rate: {round(packet_count/duration,2)} pkt/sec")
        log_file.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
