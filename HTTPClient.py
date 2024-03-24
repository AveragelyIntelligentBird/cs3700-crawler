import socket
import ssl

HTTP_VER = '1.1'
MAX_PACKET_SIZE = 4096
ENCODING = 'ascii'

class HTTPClient:
    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.socket = self.__open_new_socket()

        self.cookies = {}  # Will contain sessionid and csrftoken cookies

    def post_login(self, login_url, cgi_post_data):
        encoded_cgi_post_data = cgi_post_data.encode(ENCODING)

        request = self.__construct_request_header('POST', login_url, len(encoded_cgi_post_data))
        request += encoded_cgi_post_data
        pass

    def get_url(self, url):
        request = self.__construct_request_header('GET', url)
        print(request)

        self.socket.send(request.encode(ENCODING))
        data = self.socket.recv(MAX_PACKET_SIZE)

        print("Response:\n%s" % data.decode(ENCODING))

        # Covert response into a wrapper class


        # Update cookies if set-cookies
        pass

    def __open_new_socket(self):
        context = ssl.create_default_context()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server, self.port))

        return context.wrap_socket(sock, server_hostname=self.server)

    def __construct_request_header(self, method, url, content_length=0):
        header = f'{method} {url} HTTP/{HTTP_VER}\r\n'\
                 f'Host : {self.server}:{self.port}\r\n'\
                 'Connection: keep-alive'

        if self.cookies:
            cookie_header_val = '; '.join(
                [f'{key}={val}' for key, val in self.cookies]
            )
            header += f'Cookie: {cookie_header_val}\r\n'

        if content_length:
            header += f'Content-Length: {content_length}\r\n'

        return header + '\r\n'


class HTTPUtils:
    def construct_cgi_post_content(username, password, csrfmiddlewaretoken):
        cgi_fields = {"username" : username,
                      "password" : password,
                      "csrfmiddlewaretoken" : csrfmiddlewaretoken,
                      "next" : "" }
        return '&'.join(
                [f'{key}={val}' for key, val in cgi_fields]
            )