import socket
import binascii
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
        #print(self.protocol, self.ihl, self.source_address, self.destination_address, self.payload)



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


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    address = str(raw_ip_addr[0])
    for i in range(1,4):
         address += "."+str(raw_ip_addr[i])
    return address


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    source_port = get_port(ip_packet_payload[0:2])
    destination_port = get_port(ip_packet_payload[2:4])
    offset = hex(ip_packet_payload[12])
    offset = int(offset[2],16)
    payload_start_index = int(offset) * 4;
    payload = ip_packet_payload[int(payload_start_index):]
    return TcpPacket(int(source_port), int(destination_port), int(offset), payload)

def get_port(arr):
    port = int(binascii.hexlify(arr[0:2]),16)
    return port

def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    protocol = hex(ip_packet[9])
    protocol = protocol[-1:]
    ihl = hex(ip_packet[0])
    ihl = ihl[-1]
    source_address = parse_raw_ip_addr(ip_packet[12:16])
    destination_address = parse_raw_ip_addr(ip_packet[16:20])
    payload_start_index = int(ihl) * 4;
    payload = ip_packet[int(payload_start_index):]
    return IpPacket(int(protocol), int(ihl), source_address, destination_address, payload)



def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    TCP = 0x0006
    stealer = socket.socket(socket.AF_INET,socket.SOCK_RAW, TCP)
    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET,
                        socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        packet , addr = stealer.recvfrom(1204) 
        parsed_network_layer = parse_network_layer_packet(packet)
        protocol = parsed_network_layer.protocol
        if int(protocol) == 6:
            parsed_application_layer = parse_application_layer_packet(parsed_network_layer.payload)
            try:
                data = parsed_application_layer.payload.decode('UTF-8')
                print(data)
            except:
                print("Can't be decoded")   

if __name__ == "__main__":
    main()