import threading

from reliable_socket import reliable_socket
from utility import *


def start_single_threaded_server():
    r = reliable_socket()
    r.bind("127.0.0.1", 9002)
    data = r.recv()
    print(byte_to_string(bytes(data)))


def handle_single_connection(connection, client_address):
    data = connection.recv()
    print(byte_to_string(bytes(data)))


def start_multi_threaded_server():
    r = reliable_socket()
    r.bind("localhost", 9002)
    r.listen(10)
    while True:
        connection, client_address = r.accept()
        if connection is not None and client_address is not None:
            threading.Thread(target=handle_single_connection, args=(connection, client_address)).start()


start_multi_threaded_server()
