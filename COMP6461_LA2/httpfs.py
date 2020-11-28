import argparse
import json
import mimetypes
import os
import socket
import sys
import threading
import traceback
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler
from io import BytesIO

from lockfile import LockFile

from COMP6461_LA2.bgcolor import BgColor
from reliable_socket import reliable_socket


class response_code(enumerate):
    NOT_FOUND = 404
    OK = 200
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    INTERNAL_SERVER_ERROR = 500


class logger(enumerate):
    DEBUG = "DEBUG"
    ERROR = "ERROR"


class server:
    debugging = None
    port = None
    directory = None

    def __init__(self, debugging, port, directory):
        server.debugging = debugging
        server.port = port
        server.directory = os.path.abspath(directory)

    def configure_and_start_server(self):
        tcp_socket = reliable_socket()
        try:
            tcp_socket.bind('localhost', server.port)
            tcp_socket.enable_debugging(True)
            tcp_socket.listen(10)
            if server.debugging:
                print(BgColor.color_green_wrapper("\n Server started on DEBUG mode"))
            print(BgColor.color_green_wrapper("\n Server started at port: " + str(server.port)))
            print(BgColor.color_green_wrapper(" Server's working directory set to: " + server.directory + "\n"))
        except socket.error:
            print("Socket Error : ", traceback.format_exc())
        while True:
            try:
                connection, client_address = tcp_socket.accept()
                self.print_if_debugging_is_enabled(None, "\n")
                self.print_if_debugging_is_enabled(logger.DEBUG, "client connected from " + str(client_address))
                threading.Thread(target=httpfs().handle_client_request, args=(connection, client_address)).start()
            except (KeyboardInterrupt, Exception):
                server.print_if_debugging_is_enabled(logger.ERROR, traceback.format_exc())
                break

    @staticmethod
    def print_if_debugging_is_enabled(type, message):
        if args.debugging:
            if type is logger.DEBUG:
                print(BgColor.color_yellow_wrapper("DEBUG: " + message))
            elif type is logger.ERROR:
                print(BgColor.color_red_wrapper("ERROR: " + message))
            elif type is None:
                print(message)


class httpfs:

    def __init__(self):
        self._connection = None
        self._client_address = None

        self._request_type = None
        self._request_path = None
        self._request_headers = {}
        self._request_query_parameters = None
        self._request_body = None

        self._response_status = {}
        self._response_headers = {}
        self._response_body = None

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def set_connection(self, connection):
        self._connection = connection

    @property
    def client_address(self):
        return self._client_address

    @client_address.setter
    def set_client_address(self, client_address):
        self._client_address = client_address

    @property
    def request_type(self):
        return self._request_type

    @request_type.setter
    def set_request_type(self, request_type):
        self._request_type = request_type

    @property
    def request_path(self):
        return self._request_path

    @request_path.setter
    def set_request_path(self, request_path):
        self._request_path = request_path

    @property
    def request_headers(self):
        return self._request_headers

    @request_headers.setter
    def set_request_headers(self, request_headers):
        self._request_headers.update(request_headers)

    @property
    def get_request_header_as_string(self):
        header = ""
        for key, val in self.request_headers.items():
            header = header + (key + ": " + val + "\n")
        return header

    @property
    def request_query_parameters(self):
        return self._request_query_parameters

    @request_query_parameters.setter
    def set_request_query_parameters(self, request_query_parameters):
        self._request_query_parameters = request_query_parameters

    @property
    def request_body(self):
        return self._request_body

    @request_body.setter
    def set_request_body(self, request_body):
        self._request_body = request_body

    @property
    def response_status(self):
        return self._response_status

    @response_status.setter
    def set_response_status(self, response_status):
        self._response_status = response_status

    @property
    def response_headers(self):
        return self._response_headers

    @response_headers.setter
    def set_response_headers(self, response_headers):
        self._response_headers.update(response_headers)

    @property
    def get_response_header_as_string(self):
        header = ""
        for key, val in self.response_headers.items():
            header = header + (key + ": " + str(val) + "\r\n")
        return header

    @property
    def response_body(self):
        return self._response_body

    @response_body.setter
    def set_response_body(self, response_body):
        self._response_body = response_body

    def get_byte_length_of_object(self, object):
        return sys.getsizeof(object.encode("utf-8"))

    def handle_client_request(self, connection, client_address):
        try:
            self.set_connection = connection
            self.set_client_address = str(client_address)
            while True:
                request = connection.recv()
                if len(request) > 0:
                    self.parse_request(request)
                    self.generate_response()
                    self.send_response()
                break
        except Exception as e:
            if not self.response_status:
                self.set_response_status = {"Internal Server Error": response_code.INTERNAL_SERVER_ERROR}
                self.set_response_body = json.dumps({"Message: ": "Internal Server Error " + self.request_path})
                self.set_response_headers = {"Content-Type": "application/json"}
                self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
            self.send_response()
            server.print_if_debugging_is_enabled(logger.ERROR, traceback.format_exc())
        finally:
            connection.close()

    """
        For HTTP Request Parsing 
        see (https://stackoverflow.com/a/5955949/14375140)
    """

    def parse_request(self, request):
        request = HTTPRequest(request)
        server.print_if_debugging_is_enabled(logger.DEBUG, "Received Request from client: " + self.client_address)
        if not request.error_code:
            self.set_request_type = request.command
            self.set_request_headers = request.headers
            self.set_request_path = request.path
            content_length = self.request_headers.get('Content-Length')
            if content_length:
                self.set_request_body = request.rfile.read(int(content_length)).decode("utf-8")
            server.print_if_debugging_is_enabled(logger.DEBUG,
                                                 "Parsing " + self.request_type + " request from client: " + self.client_address)
        else:
            self.set_request_type = request.command
            self.set_response_status = {"Bad Request": response_code.BAD_REQUEST}
            self.set_response_body = json.dumps("Invalid Request Format")
            self.set_response_headers = {"Content-Type": "application/json"}
            self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
            server.print_if_debugging_is_enabled(logger.DEBUG, "Bad Request: Invalid Request Format"
                                                 + str(request.error_code) + "From" + self.client_address)
            raise SyntaxError("Invalid Request Format: " + str(request.error_code))

    def generate_response(self):
        if ".." in self.request_path:
            self.set_response_status = {"Unauthorized": response_code.UNAUTHORIZED}
            self.set_response_body = json.dumps("Access denied")
            self.set_response_headers = {"Content-Type": "application/json"}
            self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
            server.print_if_debugging_is_enabled(logger.DEBUG,
                                                 "Access denied at path: " + server.directory + self.request_path +
                                                 " for client: " + self.client_address)
        else:
            if self.request_type == "GET":
                if self.request_path == "/":
                    list_of_files = os.listdir(server.directory)
                    self.set_response_status = {"OK": response_code.OK}
                    self.set_response_body = json.dumps({"list": list_of_files})
                    self.set_response_headers = {"Content-Type": "application/json"}
                    self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
                elif os.path.exists(server.directory + self.request_path):
                    with open(server.directory + self.request_path) as f:
                        file_content = f.read()
                        mime_type = mimetypes.guess_type(self.request_path)
                        self.set_response_status = {"OK": response_code.OK}
                        self.set_response_body = file_content
                        self.set_response_headers = {"Content-Type": mime_type[0]}
                        self.set_response_headers = {
                            "Content-Length": self.get_byte_length_of_object(self.response_body)}
                        if mime_type[0] != "application/json":
                            self.set_response_headers = {
                                "Content-Disposition": "attachment; filename=" + os.path.basename(f.name)}
                        else:
                            self.set_response_headers = {"Content-Disposition": "inline"}
                else:
                    self.set_response_status = {"Not Found": response_code.NOT_FOUND}
                    self.set_response_body = json.dumps({"message: ": "requested file does not exist or invalid path"})
                    self.set_response_headers = {"Content-Type": "application/json"}
                    self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
                    server.print_if_debugging_is_enabled(logger.DEBUG,
                                                         "requested file does not exist or invalid path at " + self._request_path + " for client: " + self.client_address)

            elif self.request_type == "POST":
                """
                 Preprocessing: If path has /post attached to it first than remove it, if path does't start 
                 with '/' than append it as well.
                """
                self.set_request_path = self.request_path.replace("/post", "", 1)
                if not self.request_path.startswith("/"):
                    self.set_request_path = "/" + self.request_path

                os.makedirs(os.path.dirname(server.directory + self.request_path), exist_ok=True)

                if os.path.isdir(server.directory + self.request_path):
                    self.set_response_status = {"Bad Request": response_code.BAD_REQUEST}
                    self.set_response_body = json.dumps({"Message: ": "requested path is directory"})
                    self.set_response_headers = {"Content-Type": "application/json"}
                    self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
                    server.print_if_debugging_is_enabled(logger.DEBUG,
                                                         "requested path is Directory for client " + self.client_address)
                    raise IsADirectoryError(self)

                if self.request_body:
                    lock = LockFile(server.directory + self.request_path)
                    lock.acquire()
                    mode = "w"
                    if "Overwrite" in self.request_headers.keys() and self.request_headers["Overwrite"]:
                        if self.request_headers["Overwrite"].lower() == "false":
                            mode = "a"
                    file = open(server.directory + self.request_path, mode)
                    file.write(self.request_body)
                    file.close()
                    lock.release()
                    self.set_response_status = {"OK": response_code.OK}
                    self.set_response_body = json.dumps({"Success: ": "true"})
                    self.set_response_headers = {"Content-Type": "application/json"}
                    self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}
                else:
                    self.set_response_status = {"OK": response_code.OK}
                    self.set_response_body = json.dumps({"Message: ": "No Content to Write"})
                    self.set_response_headers = {"Content-Type": "application/json"}
                    self.set_response_headers = {"Content-Length": self.get_byte_length_of_object(self.response_body)}

    def send_response(self):
        response_status = list(self.response_status.keys())[0]
        response_code = str(self.response_status[response_status])
        date = str(formatdate(timeval=None, localtime=False, usegmt=True))

        server.print_if_debugging_is_enabled(logger.DEBUG,
                                             "sending response of " + self.request_type + " request with status " +
                                             response_code + " at time: "
                                             + date + " to client: " + self.client_address)

        response = "HTTP/1.0 " + response_code + " " + response_status + "\r\n" + \
                   "Date: " + date + "\r\n" + \
                   "Server: " + "COMP6461_LA1 (Unix)" + "\r\n" + \
                   self.get_response_header_as_string + "\r\n" + \
                   self.response_body

        self.connection.sendall(response.encode('utf-8'))


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


parser = argparse.ArgumentParser(description="http server")

parser.add_argument("-v", dest="debugging",
                    help="Prints debugging messages if enabled",
                    action="store_true")
parser.add_argument("-p",
                    dest="port",
                    default="8080",
                    type=int,
                    help="Specifies the port number that the server will listen and serve at \
                            Default is 8080.",
                    action="store")
parser.add_argument("-d",
                    dest="directory",
                    help="Specifies the directory that the server will use to read/write requested files. Default is "
                         "the current directory when launching the application.",
                    default="./")

args = parser.parse_args()
server_instance = server(args.debugging, args.port, args.directory)
server_instance.configure_and_start_server()
