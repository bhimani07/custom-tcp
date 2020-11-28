import socket


class PacketType(enumerate):
    SYN = 0
    SYN_ACK = 1
    ACK = 2
    NAK = 3
    DATA = 4
    TERMINATE = 5


class Packet:

    def __init__(self, packet_type, seq_number, peer_address, peer_port, payload):
        self.networkBytes = bytearray()
        self.packet_type = int(packet_type)
        self.seq_number = int(seq_number)
        self.peer_address = peer_address
        self.peer_port = int(peer_port)
        self.payload = payload
        self.is_sent = False
        self.timedout = [0, False]

    def to_network_bytes(self):
        packet_network_bytes = bytearray()
        packet_network_bytes.extend(self.packet_type.to_bytes(1, byteorder="big"))
        packet_network_bytes.extend(self.seq_number.to_bytes(4, byteorder="big"))
        packet_network_bytes.extend(socket.inet_aton(self.peer_address))
        packet_network_bytes.extend(self.peer_port.to_bytes(2, byteorder="big"))

        packet_network_bytes.extend(self.payload)

        return packet_network_bytes
