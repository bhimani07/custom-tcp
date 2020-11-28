# python3 httpc.py post -v -d "data to be posted" -p 8080 "http://localhost/hello.txt"
# python3 httpc.py post -v -header Overwrite:false -d "data to be posted" -p 8080 "http://localhost/hello.txt"

# python3 httpc.py get -v -p 8080 "http://localhost/hello"  (no such file)
# python3 httpc.py get -v -p 8080 "http://localhost/../hello"  (Access Denied)
# python3 httpc.py get -v -p 8080 "http://localhost/hello.txt"  (Will return Content-Disposition: attachment; filename=hello.txt)
# python3 httpc.py get -v -p 8080 "http://localhost/bgcolor.py"  (Will return Content-Disposition: attachment; filename=bgcolor.py)

import argparse
import sys
from urllib.parse import urlparse

sys.path.append(sys.path[0] + '/../..')
from COMP6461_LA2.COMP6461_LA1.http_protocol import http

version = "1.0"
user_agent_name = "httpc"


class httpc:

    def __init__(self):
        self._user_agent = user_agent_name + "/" + version

    def configure_and_start_http_client(self):
        http_client = http(self.print_response_from_http_client)

        url = urlparse(args.URL)

        http_client.set_server = url.netloc
        http_client.set_path = url.path
        http_client.set_port = args.port
        http_client.set_request_headers = {"Host": http_client.server}
        http_client.set_request_headers = {"User-Agent": self.user_agent}
        http_client.set_request_type = args.request_type

        if url.query:
            http_client.set_request_query_parameters = url.query

        if args.verbose:
            http_client.set_verbosity = True

        if args.header:
            for header in args.header:
                list_of_string = header.split(":")
                http_client.set_request_headers = {list_of_string[0]: list_of_string[1]}

        if args.request_type == "post":
            if args.data:
                request_body = args.data
            if args.file:
                file = open(args.file, mode='r')
                request_body = file.read()
            if args.data or args.file:
                http_client.set_request_body = request_body
                if "Content-Type" not in http_client.request_headers.keys():
                    http_client.set_request_headers = {"Content-Type": "application/json"}
                if "Content-Length" not in http_client.request_headers.keys():
                    http_client.set_request_headers = {"Content-Length": str(len(http_client.request_body))}

        http_client.send_http_request()

    @property
    def user_agent(self):
        return self._user_agent

    def print_response_from_http_client(self, output_to_console, output_to_file=None, output_file_name=None):
        print(output_to_console)
        if output_to_file:
            if output_file_name:
                file = open(output_file_name, "w")
                file.write(output_to_file)
                file.close()
            elif args.output:
                file = open(args.output, "w")
                file.write(output_to_file)
                file.close()


parser = argparse.ArgumentParser(description="httpc is a curl-like application but supports HTTP protocol only.")
sub_parser = parser.add_subparsers(dest="The commands are:")

# GET parser
get_parser = sub_parser.add_parser("get", help="Get executes a HTTP GET request for a given URL.")
get_parser.add_argument("-v", "--verbose",
                        help="Prints the detail of the response such as protocol, status,and headers.",
                        action="store_true")
get_parser.add_argument("-header",
                        help="Associates headers to HTTP Request with the format 'key:value'.",
                        default=[], action="append")
get_parser.add_argument("-o",
                        dest="output",
                        action="store",
                        help="Output body HTTP GET request to file",
                        default="")

get_parser.add_argument("-p",
                        dest="port",
                        type=int,
                        help="Specify port number of server for connection.",
                        action="store",
                        default="8080")

get_parser.add_argument("URL", help="HTTP URL")
get_parser.set_defaults(request_type="get")

# POST parser
post_parser = sub_parser.add_parser("post", help="Post executes a HTTP POST request for a given URL \
                                                 with inline data or from file.")
post_parser.add_argument("-v", "--verbose",
                         help="Prints the detail of the response such as protocol, status,and headers.",
                         action="store_true")
post_parser.add_argument("-header",
                         help="Associates headers to HTTP Request with the format'key:value'.",
                         action="append",
                         default=[])
group = post_parser.add_mutually_exclusive_group()
group.add_argument("-d",
                   dest="data",
                   help="Associates an inline data to the body HTTP POST request.",
                   default="")
group.add_argument("-f",
                   dest="file",
                   help="Associates the content of a file to the body HTTP POST request.",
                   default="")
post_parser.add_argument("-o",
                         dest="output",
                         action="store",
                         help="Output body HTTP POST request to file",
                         default="")

post_parser.add_argument("-p",
                         dest="port",
                         type=int,
                         help="Specify port number of server for connection.",
                         action="store",
                         default="8080")

post_parser.add_argument("URL", help="HTTP URL")

post_parser.set_defaults(request_type="post")

args = parser.parse_args()

# Start httpc
hc = httpc()
hc.configure_and_start_http_client()
