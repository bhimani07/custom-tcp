from threading import Thread

from COMP6461_LA2.COMP6461_LA1.http_protocol import http


def create_fake_get_list_request():
    http_client = http(print_response_from_http_client)

    http_client.set_server = "localhost"
    http_client.set_path = "/"
    http_client.set_verbosity = True
    http_client.set_port = 8080
    http_client.set_request_headers = {"Host": http_client.server}
    http_client.set_request_headers = {"User-Agent": "Test"}
    http_client.set_request_type = "get"
    http_client.send_http_request()


def create_fake_get_file_content_request():
    http_client = http(print_response_from_http_client)

    http_client.set_server = "localhost"
    http_client.set_verbosity = True
    http_client.set_path = "/bgcolor.py"
    http_client.set_port = 8080
    http_client.set_request_headers = {"Host": http_client.server}
    http_client.set_request_headers = {"User-Agent": "Test"}
    http_client.set_request_type = "get"
    http_client.send_http_request()


def create_fake_post_file_request():
    http_client = http(print_response_from_http_client)

    http_client.set_server = "localhost"
    '''
     Here path is wrong as it should always start with '/' but included this test case to test server for unauthorize
     access and error handling testing
    '''
    http_client.set_path = "COMP6461_LA1/output.json"
    http_client.set_port = 8080
    http_client.set_verbosity = True
    http_client.set_request_headers = {"Host": http_client.server}
    http_client.set_request_headers = {"User-Agent": "Test"}
    http_client.set_request_headers = {"Overwrite": "False"}
    http_client.set_request_type = "post"

    file = open("/Users/kishanbhimani/PycharmProjects/COMP6461_LA2/COMP6461_LA1/input.json", mode='r')
    request_body = file.read()
    http_client.set_request_body = request_body
    if "Content-Type" not in http_client.request_headers.keys():
        http_client.set_request_headers = {"Content-Type": "application/json"}
    if "Content-Length" not in http_client.request_headers.keys():
        http_client.set_request_headers = {"Content-Length": str(len(http_client.request_body))}

    http_client.send_http_request()


def print_response_from_http_client(output_to_console, output_to_file=None, output_file_name=None):
    print(output_to_console)
    '''
       following code to support Content-Disposition header.
    '''
    if output_to_file:
        if output_file_name:
            file = open("COMP6461_LA1/" + output_file_name, "w")
            file.write(output_to_file)
            file.close()


for i in range(0, 5):
    Thread(target=create_fake_get_list_request(), args=()).start()
    Thread(target=create_fake_get_file_content_request(), args=()).start()
    Thread(target=create_fake_post_file_request(), args=()).start()
