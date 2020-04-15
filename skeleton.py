import socket
import binascii
import sys
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr : bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    addr = socket.inet_ntoa(raw_ip_addr)
    print(addr)
    return str(addr)


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    """src_port, dst_port, data_offset, payload"""
    unpacked = struct.unpack("!HHLLH",ip_packet_payload[:14])
    src_port = unpacked[0]
    dst_port = unpacked[1]
    data_offset = unpacked[4] >> 12 # Bitwise right shift 
    offset = data_offset* 4
    payload = ip_packet_payload[offset:]
    return TcpPacket(src_port, dst_port, data_offset, payload)


def disp_application_layer_packet(tcp_packet: TcpPacket):
    print("-TCP Header:")
    print("------------")
    print("\t-Source port :", tcp_packet.src_port," -Destination port :",tcp_packet.dst_port)
    print("\t-Data Offset:", tcp_packet.data_offset)
    try:
        print("\t-TCP Data:\n")
        print("\t\t",tcp_packet.payload.decode("UTF-8"))
    except:
        pass
    pass


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    """
    extract -> protocol, ihl, source_address, destination_address, payload 
    """
    unpacked = struct.unpack("!BBHHHBBH4s4s", ip_packet[0:20])
    protocol = unpacked[6] #protocol is always 6 -> TCP
    version = unpacked[0] # version -> indicates the format of the internet header
    print("Protocol version :", version >> 4) # Bitwise right shift 4 bit
    ihl = (version & 0xF) # mask 4 bit
    length = ihl * 4
    src_addr = parse_raw_ip_addr(unpacked[8])
    dest_adrr = parse_raw_ip_addr(unpacked[9])
    payload = ip_packet[length:] #data 
    return IpPacket(protocol, ihl, src_addr, dest_adrr, payload)


def disp_network_layer_packet(ip_packet: IpPacket):
    print("-IP Header:")
    print("-----------")
    if ip_packet.protocol == 6:
        type = "TCP"
        print("\t-Protocol :", type," -ihl :",ip_packet.ihl)
    print("\t-Source_address :", ip_packet.source_address,"-Destination_address :",ip_packet.destination_address)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    #set up socket in order to accept raw data
    #socket.IPPROTO_TCP -> TCP
    skt = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
     
    while True:
        packet, addr = skt.recvfrom(4096) #receive packet and address
        ip = parse_network_layer_packet(packet) 
        disp_network_layer_packet(ip)
        tcp = parse_application_layer_packet(ip.payload)
        disp_application_layer_packet(tcp)
	# Receive packets and do processing here
        #pass
    pass


if __name__ == "__main__":
    main()