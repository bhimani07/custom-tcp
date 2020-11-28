from threading import Timer

from COMP6461_LA2.bgcolor import BgColor
from packet import *
from utility import *

PACKET_SIZE = 1024  # length in bytes
WINDOW_LENGTH = 20  # Length of Window
PACKET_TIME_OUT = 5  # Packet retransmission timeout in seconds
WINDOW_RECEIVE_TIMEOUT = 0.5  # sender ACK loop timeout
MAX_HANDSHAKE_RETRY_ATTEMPTS = 25  # 25 times
HANDSHAKE_RETRY_INTERVAL = 2  # 2 seconds


class logger(enumerate):
    DEBUG = "DEBUG"
    ERROR = "ERROR"
    INFO = "INFO"


class reliable_socket:

    def __init__(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.reliable_socket_timeout = None
        self.host_address = None
        self.host_port = None
        self.max_number_of_connections = None
        self.current_active_connections = 0
        self.current_seq_number = uint32(0)
        self.data = list()
        self.router = ('127.0.0.1', 3000)
        self.debugging = True
        self.signal_when_done = None

    def print_if_debugging_is_enabled(self, type, message):
        if self.debugging:
            if type is logger.DEBUG:
                print(BgColor.color_yellow_wrapper("DEBUG: " + message))
            elif type is logger.ERROR:
                print(BgColor.color_red_wrapper("ERROR: " + message))
            elif type is logger.INFO:
                print(BgColor.color_blue_wrapper("INFO: " + message))
            elif type is None:
                print(message)

    @staticmethod
    def set_window(window_size):
        WINDOW_LENGTH = window_size

    def set_sequence_number(self, sequence_number):
        self.current_seq_number = uint32(sequence_number)

    def enable_debugging(self, should_debug):
        self.debugging = should_debug

    def set_router(self, router):
        self.router = router

    def bind(self, address, port):
        self.udp_socket.bind((address, port))

    def listen(self, max_number_of_connections=10):
        self.max_number_of_connections = max_number_of_connections

    def accept(self):
        try:
            network_bytes, router = self.udp_socket.recvfrom(PACKET_SIZE)
            connection_packet = from_network_bytes(network_bytes)
            if self.current_active_connections < self.max_number_of_connections:
                if connection_packet.packet_type == PacketType.SYN:
                    return self.try_to_accept_connection(connection_packet)
                else:
                    return None, None
        except socket.timeout:
            return None, None

    def try_to_accept_connection(self, connection_packet):
        new_realiable_socket = reliable_socket()
        new_realiable_socket.udp_socket.sendto(
            sync_packet(PacketType.SYN_ACK, new_realiable_socket.current_seq_number, connection_packet.peer_address,
                        connection_packet.peer_port).to_network_bytes(), self.router)

        new_realiable_socket.current_seq_number = increase_sequence_number(connection_packet.seq_number)
        new_realiable_socket.udp_socket.connect(self.router)
        new_realiable_socket.host_address = connection_packet.peer_address
        new_realiable_socket.host_port = connection_packet.peer_port
        new_realiable_socket.set_router(self.router)
        new_realiable_socket.signal_when_done = self.signal_when_done_callback
        new_realiable_socket.debugging = self.debugging
        new_realiable_socket.print_if_debugging_is_enabled(logger.INFO,
                                                           "CONNECTION ESTABLISHED -> " + str(
                                                               connection_packet.peer_address) + ":" + str(
                                                               connection_packet.peer_port) + "\n")
        # TODO: Fix number of active connections for multi client support
        self.current_active_connections += 1
        self.print_if_debugging_is_enabled(logger.INFO, "Received new Connection..!!!")
        self.print_if_debugging_is_enabled(logger.INFO, "Number of Active connections -> " + str(
            self.current_active_connections) + "\n")
        return new_realiable_socket, (connection_packet.peer_address, connection_packet.peer_port)

    def handshaking(self, address_to_connect):
        # server_ip = socket.gethostbyname(socket.gethostname())
        server_ip = socket.gethostbyname(address_to_connect[0])
        self.udp_socket.connect(self.router)
        for i in range(0, MAX_HANDSHAKE_RETRY_ATTEMPTS):
            try:
                self.udp_socket.sendall(
                    sync_packet(PacketType.SYN, self.current_seq_number, server_ip,
                                address_to_connect[1]).to_network_bytes())
                self.udp_socket.settimeout(HANDSHAKE_RETRY_INTERVAL)
                packet_network_bytes, route = self.udp_socket.recvfrom(PACKET_SIZE)
                packet = from_network_bytes(packet_network_bytes)
                self.udp_socket.sendall(
                    sync_packet(PacketType.SYN_ACK, self.current_seq_number, packet.peer_address,
                                packet.peer_port).to_network_bytes())
                self.host_address = packet.peer_address
                self.host_port = packet.peer_port
                self.print_if_debugging_is_enabled(logger.DEBUG,
                                                   "HANDSHAKING SUCCESSFUL WITH -> " + str(packet.peer_address) + ":" +
                                                   str(packet.peer_port) + "\n")
                return True
            except Exception:
                pass

        raise Exception

    def connect(self, host_address):
        try:
            if self.handshaking(host_address):
                self.current_seq_number = increase_sequence_number(self.current_seq_number)
        except Exception:
            raise Exception("Unable to Establish Connection with Server")

    # similar to TCP sendall
    def sendall(self, data):
        if not self.host_address:
            self.print_if_debugging_is_enabled(logger.ERROR, "host address is missing")
            return
        if not self.host_port:
            self.print_if_debugging_is_enabled(logger.ERROR, "host port is missing")
            return

        self.print_if_debugging_is_enabled(logger.INFO, "SENDING DATA\n")

        packet_list, updated_seq_number = create_data_packets_from_data(self.host_address, self.host_port, data,
                                                                        self.current_seq_number)
        self.current_seq_number = updated_seq_number
        # self.print_if_debugging_is_enabled(logger.DEBUG, "Current Seq Number: " + str(self.current_seq_number))
        self.print_if_debugging_is_enabled(logger.DEBUG, "Total packets to send" + str(len(packet_list)))
        if len(packet_list) < WINDOW_LENGTH:
            window = [-1 for i in range(0, len(packet_list))]
        else:
            window = [-1 for i in range(0, WINDOW_LENGTH)]
        timer_list = list()

        while len(packet_list) != 0 or self.is_there_packet_in_window(window):

            # window[:] = [value for value in window if self.is_packet(value)]
            #
            #
            # if len(window) < WINDOW_LENGTH:
            #     for i in range(len(window) - 1, WINDOW_LENGTH):
            #         window.append(0)
            #
            # for i in range(0, len(window)):
            #     if not self.is_packet(window[i]):
            #         if len(packet_list) > 0:
            #             window[i] = packet_list.pop(0)

            while not isinstance(window[0], Packet):
                if len(packet_list) > 0:
                    window[0] = packet_list.pop(0)
                    window.append(window.pop(0))
                else:
                    break

            for i in range(0, len(window)):
                if self.is_packet(window[i]):
                    if not window[i].is_sent:
                        self.print_if_debugging_is_enabled(logger.DEBUG, "sending packet " + str(
                            window[i].seq_number) + " with payload length: " + str(len(window[i].payload)))
                        self.udp_socket.sendall(window[i].to_network_bytes())
                        window[i].is_sent = True
                        if len(timer_list) <= i:
                            # self.print_if_debugging_is_enabled(logger.DEBUG,
                            #                                    "setting timeout for " + str(window[i].seq_number))
                            timer_list.append(Timer(PACKET_TIME_OUT, self.packet_timedout, [window[i]]))
                            timer_list[i].start()
                        else:
                            # self.print_if_debugging_is_enabled(logger.DEBUG,
                            #                                    "setting timeout for " + str(window[i].seq_number))
                            timer_list[i] = Timer(PACKET_TIME_OUT, self.packet_timedout, [window[i]])
                            timer_list[i].start()

                    elif self.is_packet(window[i]) and window[i].timedout[1]:
                        self.print_if_debugging_is_enabled(logger.DEBUG, "resending packet " + str(
                            window[i].seq_number) + " because it timeout with payload length: " +
                                                           str(len(window[i].payload)))
                        self.udp_socket.sendall(window[i].to_network_bytes())

            while self.is_there_packet_in_window(window):
                self.udp_socket.settimeout(0.1)
                try:
                    response, address = self.udp_socket.recvfrom(PACKET_SIZE)
                    packet = from_network_bytes(response)
                    self.print_if_debugging_is_enabled(logger.DEBUG,
                                                       "Current Sequence Number: " + str(self.current_seq_number))
                    self.print_if_debugging_is_enabled(logger.DEBUG, "packet received seq_number: " + str(
                        packet.seq_number) + " type: " + str(packet.packet_type))
                    if PacketType.ACK == packet.packet_type:
                        acked_packet = self.find_packet_from_seq_number(window, packet.seq_number)
                        if acked_packet is not None:
                            index = window.index(acked_packet)
                            if index in range(0, len(window)):
                                window[index] = 0
                    if PacketType.NAK == packet.packet_type:
                        nacked_packet = self.find_packet_from_seq_number(window, packet.seq_number)
                        if nacked_packet is not None:
                            self.udp_socket.sendall(nacked_packet)
                    if PacketType.DATA == packet.packet_type:
                        self.data.append(byte_to_string(bytes(packet.payload)))
                    if PacketType.TERMINATE == packet.packet_type and packet.seq_number == decrease_sequence_number(
                            self.current_seq_number):
                        self.print_if_debugging_is_enabled(logger.INFO,
                                                           "Signal that all packets are received at Server")
                        self.print_if_debugging_is_enabled(logger.INFO,
                                                           "Additionally send Terminate Messages to Server and Exit")
                        for i in range(0, 10):
                            self.udp_socket.sendall(
                                sync_packet(PacketType.TERMINATE, packet.seq_number, packet.peer_address,
                                            packet.peer_port).to_network_bytes())
                        self.print_if_debugging_is_enabled(logger.INFO, "EXITING!!!!\n\n")
                        return
                except socket.timeout:
                    break

    # similar to TCP recv
    def recv(self):
        payload = bytearray()
        window = [int(increase_sequence_number(self.current_seq_number, i)) for i in range(0, WINDOW_LENGTH + 1)]
        self.udp_socket.settimeout(10 * 20)
        self.print_if_debugging_is_enabled(logger.INFO, "RECEIVING DATA\n")
        while True:
            if self.is_packet(window[0]) and len(window[0].payload) == 0 and window[0].packet_type == PacketType.DATA:
                self.print_if_debugging_is_enabled(logger.DEBUG,
                                                   "Received Last Packet at Server wih sequence number: " + str(
                                                       window[0].seq_number) + "\n\n")
                last_packet = window.pop(0)
                self.udp_socket.settimeout(2)
                for i in range(0, 5):
                    self.udp_socket.sendall(
                        sync_packet(PacketType.TERMINATE,
                                    self.current_seq_number, last_packet.peer_address,
                                    last_packet.peer_port).to_network_bytes())
                    try:
                        data = self.udp_socket.recv(PACKET_SIZE)
                    except Exception as e:
                        continue
                    recv_packet = from_network_bytes(data)
                    if recv_packet.packet_type == PacketType.TERMINATE:
                        break
                self.current_seq_number = increase_sequence_number(self.current_seq_number)
                return bytes(payload)

            network_data_bytes = self.udp_socket.recv(PACKET_SIZE)
            packet = from_network_bytes(network_data_bytes)
            self.print_if_debugging_is_enabled(logger.DEBUG,
                                               "received package sequence number: " + str(
                                                   packet.seq_number) + "  length of payload: " +
                                               str(len(packet.payload)) + " type: " + str(packet.packet_type))
            self.print_if_debugging_is_enabled(logger.DEBUG, "current sequence number: " + str(self.current_seq_number))

            if packet.packet_type == PacketType.SYN or packet.packet_type == PacketType.SYN_ACK:
                self.udp_socket.sendall(sync_packet(PacketType.SYN, packet.seq_number, packet.peer_address,
                                                    packet.peer_port).to_network_bytes())

            if packet.packet_type != PacketType.DATA:
                self.print_if_debugging_is_enabled(logger.DEBUG, "received some delayed sync packet, ignore it!!!!\n\n")
                continue

            index = self.window_index_of_sequence_number(window, packet.seq_number)

            if index is not None:
                window[index] = packet
                if self.debugging:
                    print("Window: ", *window, sep='\n')
                    print("\n")
                while self.is_packet(window[0]) and window[0].packet_type == PacketType.DATA:
                    if len(window[0].payload) == 0:
                        break
                    pkt = window.pop(0)
                    self.current_seq_number = increase_sequence_number(pkt.seq_number)
                    current_last_pkt = window[len(window) - 1]
                    if self.is_packet(current_last_pkt):
                        window.append(increase_sequence_number(current_last_pkt.seq_number, 1))
                    else:
                        window.append(increase_sequence_number(current_last_pkt, 1))
                    payload.extend(pkt.payload)
            else:
                self.print_if_debugging_is_enabled(logger.DEBUG, "Duplicate/Future packet: " + str(
                    packet.seq_number) + " because window doesn't have slot for it!!!\n\n")
            self.udp_socket.sendall(sync_packet(PacketType.ACK, packet.seq_number, packet.peer_address,
                                                packet.peer_port).to_network_bytes())

    def is_packet(self, obj):
        return isinstance(obj, Packet)

    def is_there_packet_in_window(self, window):
        for i in range(len(window)):
            if isinstance(window[i], Packet):
                return True
        return False

    def packet_timedout(self, packet):
        packet.timedout[0] = packet.timedout[0] + 1
        packet.timedout[1] = True

    def find_packet_from_seq_number(self, window, seq_number):
        return next((packet for packet in window if self.is_packet(packet) and packet.seq_number == seq_number), None)

    def window_index_of_sequence_number(self, window, seq_number):
        for i in range(0, len(window)):
            if window[i] == int(seq_number) or (self.is_packet(window[i]) and window[i].seq_number == seq_number):
                return i

        return None

    def close(self):
        if self.signal_when_done is not None:
            self.print_if_debugging_is_enabled(logger.INFO, "Closing socket by signaling parent thread..!!!")
            self.signal_when_done()

    def signal_when_done_callback(self):
        if self.current_active_connections > 0:
            self.current_active_connections -= 1
        self.print_if_debugging_is_enabled(logger.INFO, "Connection pool size updated..!!!")
        self.print_if_debugging_is_enabled(logger.INFO, "Current connection pool size: " + str(
            self.max_number_of_connections - self.current_active_connections) + "\n\n")
