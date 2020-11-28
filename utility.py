import ipaddress

from numpy import uint32

from packet import Packet, PacketType

single_packet_payload_size = 20


def increase_sequence_number(seq_number, increase_by=1):
    sequence = uint32(seq_number) + uint32(increase_by)
    if sequence < seq_number:
        sequence = sequence + uint32(1)
    return sequence


def decrease_sequence_number(seq_number, decrease_by=1):
    sequence = uint32(seq_number) - uint32(decrease_by)
    if sequence == 0:
        sequence = sequence - uint32(1)
    return sequence


def to_int32(val):
    val &= ((1 << 32) - 1)
    if val & (1 << 31): val -= (1 << 32)
    return val


def byte_to_string(byte_data):
    return byte_data.decode('utf-8')


def string_to_byte(string_data):
    return string_data.encode('utf-8')


def sync_packet(packet_type, seq_number, peer_address, peer_port):
    return Packet(packet_type, seq_number, peer_address, peer_port, "")


def data_packet(packet_type, seq_number, peer_address, peer_port, payload):
    return Packet(packet_type, seq_number, peer_address, peer_port, payload)


def create_data_packets_from_data(peer_address, peer_port, total_payload, sequence_number=0):
    packet_list = list()

    if isinstance(total_payload, str):
        try:
            total_payload = total_payload.encode('utf-8')
        except Exception:
            raise Exception

    if len(total_payload) > 0:
        list_payload = list()
        while len(total_payload) != 0:
            list_payload.append(total_payload[:single_packet_payload_size])
            total_payload = total_payload[single_packet_payload_size:]
        for payload in list_payload:
            packet_list.append(
                data_packet(PacketType.DATA, sequence_number, peer_address, peer_port, payload))
            sequence_number = increase_sequence_number(sequence_number)
        packet_list.append(data_packet(PacketType.DATA, sequence_number, peer_address, peer_port, string_to_byte("")))
        sequence_number = increase_sequence_number(sequence_number)
        return packet_list, sequence_number

    return None


def from_network_bytes(response_bytes):
    packet_type = int.from_bytes(response_bytes[0:1], byteorder="big")
    sequence_number = int.from_bytes(response_bytes[1:5], byteorder="big")
    peer_address = str(ipaddress.IPv4Address(bytes(response_bytes[5:9])))
    peer_port = int.from_bytes(response_bytes[9:11], byteorder="big")
    payload = response_bytes[11:]

    return Packet(packet_type, sequence_number, peer_address, peer_port, payload)


def get_max_32bit_integer():
    return 4294967295
