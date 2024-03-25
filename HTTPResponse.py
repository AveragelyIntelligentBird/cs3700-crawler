
class HTTPResponse:
    header_lines = {}
    body = ""

    def __init__(self, header_string, response_code=None, response_message=None):
        # If the message was constructed manually
        if response_code and response_message:
            self.response_code = response_code
            self.header_string = f"HTTP/1.1 {response_code} {response_message}\n\n"
        else:
            self.header_string = header_string
            self.response_code = self.__parse_header(header_string)

    def get_header_str(self):
        return self.header_string

    def set_body(self, body):
        self.body = body

    def get_body(self):
        return self.body

    def get_response_code(self):
        return self.response_code

    def is_connection_closed(self):
        return ('connection' in self.header_lines and self.header_lines['connection'][0].strip() == "close") \
            or ('Connection' in self.header_lines and self.header_lines['Connection'][0].strip() == "close")

    def get_new_cookies(self):
        if 'set-cookie' in self.header_lines:
            new_cookie_header_vals = self.header_lines['set-cookie']
        elif 'Set-Cookie' in self.header_lines:
            new_cookie_header_vals = self.header_lines['Set-Cookie']
        elif 'Set-cookie' in self.header_lines:
            new_cookie_header_vals = self.header_lines['Set-cookie']
        else:
            return None

        new_cookies = {}
        for new_cookie_header_val in new_cookie_header_vals:
            cookie_name, cookie_val = new_cookie_header_val.split(';', 1)[0].strip().split("=", 1)
            new_cookies[cookie_name] = cookie_val

        return new_cookies

    def get_content_length(self):
        if 'content-length' in self.header_lines:
            content_len_val = self.header_lines['content-length'][0]
        elif 'Content-Length' in self.header_lines:
            content_len_val = self.header_lines['Content-Length'][0]
        elif 'Content-length' in self.header_lines:
            content_len_val = self.header_lines['Content-length'][0]
        else:
            return None

        return int(content_len_val.strip())

    def is_transfer_encoding_chunked(self):
        return ('transfer-encoding' in self.header_lines
                and self.header_lines['Transfer-Encoding'][0].strip() == "chunked") \
            or ('Transfer-Encoding' in self.header_lines
                and self.header_lines['Transfer-Encoding'][0].strip() == "chunked") \
            or ('Transfer-encoding' in self.header_lines
                and self.header_lines['Transfer-encoding'][0].strip() == "chunked")

    def get_new_location(self):
        if 'location' in self.header_lines:
            location_val = self.header_lines['location'][0]
        elif 'Location' in self.header_lines:
            location_val = self.header_lines['Location'][0]
        else:
            return None

        return location_val.strip()

    def __parse_header(self, header_string):
        header_lines = header_string.split("\r\n")

        if header_lines:
            response_code = int(header_lines[0].split(" ")[1])
        else:
            raise RuntimeError("The received header string was empty.")

        if len(header_lines) > 1:
            header_lines = header_lines[1:]
            for line in header_lines:
                if not line:
                    continue

                key, value = line.split(':', 1)
                if key in self.header_lines:
                    self.header_lines[key].append(value)
                else:
                    self.header_lines[key] = [value]

        return response_code