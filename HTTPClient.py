import logging
import socket
import ssl

from HTTPResponse import HTTPResponse

HTTP_VER = '1.1'
MAX_PACKET_SIZE = 4096
ENCODING = 'ascii'

class HTTPClient:
    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.socket = self.__open_new_socket()

        self.cookies = {}  # Will contain sessionid and csrftoken cookies

    def send_request(self, method, url, body=None):
        if body:
            request = self.__construct_request_header(method, url, len(body))
            request += body
        else:
            request = self.__construct_request_header(method, url)

        # Send request
        logging.info(f"REQUEST:\n{request}")
        self.socket.send(request.encode(ENCODING))

        # Receive
        response = self.__receive_response()
        logging.info(f"RESPONSE:\n{response.get_header_str()}\n\n[BODY]")
        logging.debug(response.get_body())

        # Update cookies if set-cookies
        new_cookies = response.get_new_cookies()
        if new_cookies:
            self.cookies.update(new_cookies)

        return response

    def close_connection(self):
        self.socket.close()

    def __open_new_socket(self):
        context = ssl.create_default_context()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server, self.port))

        return context.wrap_socket(sock, server_hostname=self.server)

    def __construct_request_header(self, method, url, content_length=0):
        header = f'{method} {url} HTTP/{HTTP_VER}\r\n'\
                 f'Host: {self.server}:{self.port}\r\n'\
                 'Connection: keep-alive\r\n'

        if self.cookies:
            cookie_header_val = '; '.join(
                [f'{key}={val}' for key, val in self.cookies.items()]
            )
            header += f'Cookie: {cookie_header_val}\r\n'

        if content_length:
            header += f'Content-Length: {content_length}\r\n'

        return header + '\r\n'

    def __receive_response(self):
        # Receive until header is fully received
        buffer = b''
        while b'\r\n\r\n' not in buffer:
            data = self.socket.recv(MAX_PACKET_SIZE)
            if not data:  # Socket closed too soon
                return HTTPResponse("", 503, "Local - Socket closed before the end of packet, retry.")
            buffer += data

        # Process header to determine remaining length of content
        header_string, _, body_part = buffer.partition(b'\r\n\r\n')
        response = HTTPResponse(header_string.decode(ENCODING))

        # Get remaining response data by content length
        content_len = response.get_content_length()
        if content_len is not None:
            complete_body = self.__receive_body_by_content_len(body_part, content_len)
        elif response.is_transfer_encoding_chunked(): # Alternatively, consider chunked encoding
            complete_body = self.__receive_chunked_body(body_part)
        else:
            complete_body = ""

        # Socket closed too soon, report a 503 for the crawler to retry
        if complete_body is None:
            return HTTPResponse("", 503, "Local - Socket closed before the end of packet, retry.")

        response.set_body(complete_body.decode(ENCODING))

        # Account for whether the server closed connection with this packet
        # If so, simply reopen socket
        if response.is_connection_closed():
            self.close_connection()
            self.__open_new_socket()

        return response

    def __receive_body_by_content_len(self, init_body_part, content_len):
        rem_content_len = content_len - len(init_body_part)
        body_chunks = [init_body_part]

        # Receive data for the content body for as long as there is outstanding content length
        while rem_content_len > 0:
            body_chunk = self.socket.recv(MAX_PACKET_SIZE)
            if not body_chunk:  # Socket closed
                return None
            rem_content_len -= len(body_chunk)
            body_chunks.append(body_chunk)  # Appending to list instead of to string for speed

        return b''.join(body_chunks)

    def __receive_chunked_body(self, body_buf):
        # Receive the rest of the packet, expecting to have CRLFx2 in the end
        while b'\r\n\r\n' not in body_buf:
            data = self.socket.recv(MAX_PACKET_SIZE)
            if not data:  # Socket closed
                return None
            body_buf += data

        # Parse the chunks from the buffer until a chunk-size of 0 is encountered
        body_chunks = []
        expecting_chunk_len = True
        next_chunk_len = -1  # -1 for expecting to read chunk len on the next line
        while next_chunk_len:
            if b'\r\n' in body_buf:
                if expecting_chunk_len:
                    chunk_len_line, _, body_buf = body_buf.partition(b'\r\n')

                    next_chunk_len = int(chunk_len_line.split(b';')[0], 16)
                    expecting_chunk_len = False
                else:
                    chunk_line, _, body_buf = body_buf.partition(b'\r\n')
                    if len(chunk_line) == next_chunk_len:
                        body_chunks.append(chunk_line)
                        expecting_chunk_len = True
                        next_chunk_len = -1
                    else:
                        logging.error("Malformed chunk was received. Retrying the same transmission.")
                        return None

        return b''.join(body_chunks)


class HTTPUtils:
    def construct_cgi_post_content(username, password, csrfmiddlewaretoken):
        cgi_fields = {"username" : username,
                      "password" : password,
                      "csrfmiddlewaretoken" : csrfmiddlewaretoken,
                      "next" : "" }
        return '&'.join(
                [f'{key}={val}' for key, val in cgi_fields.items()]
            )