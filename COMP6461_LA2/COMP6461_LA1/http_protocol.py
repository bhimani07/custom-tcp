import re
import socket
import sys
from http.client import HTTPResponse
from io import BytesIO
from urllib.parse import urlparse

from reliable_socket import reliable_socket

sys.path.append('..')
from COMP6461_LA2.bgcolor import BgColor


def createTCPSocket(timeout=None):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout:
        tcp_socket.settimeout(timeout)
        return tcp_socket
    return tcp_socket


class http:
    HTTP_PROTOCOL = "HTTP/1.0"
    MAXIMUM_REDIRECT_LIMIT = 10
    redirect_counter = 0
    _redirect_codes = {301, 302}

    def __init__(self, print_response_from_http_client):

        self._server = None
        self._path = None
        self._port = None

        self._verbosity = None

        self._request_type = None
        self._request = None
        self._request_headers = {}
        self._request_query_parameters = ""
        self._request_body = ""

        self._response = None
        self._response_headers = None
        self._response_data = None

        self.print_response_from_http_client = print_response_from_http_client

    @property
    def server(self):
        return self._server

    @server.setter
    def set_server(self, server):
        self._server = server

    @property
    def path(self):
        return self._path

    @path.setter
    def set_path(self, path):
        if path == "":
            self._path = "/"
        else:
            self._path = path

    @property
    def port(self):
        return self._port

    @port.setter
    def set_port(self, port):
        self._port = port

    @property
    def verbosity(self):
        return self._verbosity

    @verbosity.setter
    def set_verbosity(self, verbosity):
        self._verbosity = verbosity

    @property
    def request_type(self):
        return self._request_type

    @request_type.setter
    def set_request_type(self, request_type):
        self._request_type = request_type

    @property
    def request(self):
        return self._request

    @request.setter
    def set_request(self, request):
        self._request = request

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
    def response(self):
        return self._response

    @response.setter
    def set_response(self, response):
        self._response = response

    @property
    def response_headers(self):
        return self._response_headers

    @response_headers.setter
    def set_response_headers(self, response_headers):
        self._response_headers = response_headers

    @property
    def response_data(self):
        return self._response_data

    @response_data.setter
    def set_response_data(self, response_data):
        self._response_data = response_data

    @property
    def redirect_codes(self):
        return self._redirect_codes

    def send_http_request(self):
        self.generate_request()
        try:
            tcp_socket = reliable_socket()
            tcp_socket.enable_debugging(False)
            tcp_socket.connect((self.server, self.port))
            tcp_socket.sendall(self.request)
            server_response = tcp_socket.recv()
            self.parse_response_and_display_results(server_response.decode("utf-8"))
        except socket.timeout as timeoutError:
            print("Socket Timeout : ", timeoutError)
        except socket.error as error:
            print("Socket Error : ", error)

    def generate_request(self):
        if self.request_query_parameters:
            self.set_request_query_parameters = "?" + self.request_query_parameters
        else:
            self.set_request_query_parameters = ""

        self.set_request = self.request_type.upper() + " " + self.path + \
                           self.request_query_parameters + " " + self.HTTP_PROTOCOL + " \n" + \
                           self.get_request_header_as_string + "\n"
        if self.request_type == "post":
            if self.request_body:
                self.set_request = self.request + self.request_body

    def parse_response_and_display_results(self, response):
        (headers, json_response) = response.split("\r\n\r\n")
        self.set_response = response
        self.set_response_headers = headers
        self.set_response_data = json_response

        response_headers = self.parse_headers(headers)
        response_status_code = response_headers.status

        self.print_response_from_http_client(
            BgColor.color_cyan_wrapper("\n" + "Response Status Code => " + str(response_status_code)))

        # If response header suggests a redirect.
        if response_status_code in self.redirect_codes and self.redirect_counter < self.MAXIMUM_REDIRECT_LIMIT:
            try:
                url = response_headers.getheader("Location")
                self.redirect_counter = self.redirect_counter + 1

                self.print_response_from_http_client(
                    "Redirecting to Address ===> " + url + " Count: " + str(self.redirect_counter))

                url = urlparse(url)
                self.set_server = url.netloc
                self.set_path = url.path
                self.set_port = url.port

                self.send_http_request()
            except AttributeError as error:
                self.print_response_from_http_client(
                    BgColor.color_red_wrapper("\n" + "Error Parsing Redirection Header: " + str(error)))
        else:
            self.redirect_counter = 0
            '''
                If Server sends response in-form of attachment then parse it and download it as a file.
            '''
            if response_headers.getheader("Content-Disposition") and response_headers.getheader(
                    "Content-Disposition").startswith("attachment"):
                filename = re.findall("filename=(.+)", response_headers.getheader("Content-Disposition"))[0]
                if filename:
                    output_file_name = filename
                else:
                    output_file_name = "attachment"
                self.print_response_from_http_client(BgColor.color_yellow_wrapper(self.response_headers),
                                                     self.response_data,
                                                     output_file_name)
                return
            self.display_results()

    def parse_headers(self, headers):
        headers_bytes = headers.encode()
        socket_response = Socket(headers_bytes)
        parsed_headers = HTTPResponse(socket_response)
        parsed_headers.begin()
        return parsed_headers

    def display_results(self):
        if self.verbosity:
            self.print_response_from_http_client(BgColor.color_yellow_wrapper(self.response), self.response_data)
        else:
            self.print_response_from_http_client(BgColor.color_yellow_wrapper(self.response_data), self.response_data)


class Socket():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file
