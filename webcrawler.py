import argparse
import socket
import ssl
from urllib.parse import urlparse
from bs4 import BeautifulSoup as bs


class WebCrawler:
    username = ''
    password = ''
    verbose = False
    queue = []
    visited = {}
    start = '/accounts/login/'
    logout = '/accounts/logout/'
    host = 'fakebook.3700.network'
    port = 443
    useragent = 'Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0'
    csrftoken = ''
    sessionid = ''
    flags = []

    def __init__(self, username, password, verbose):
        self.username = username
        self.password = password
        self.verbose = verbose

    def create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        context = ssl.create_default_context()
        sscok = context.wrap_socket(sock, server_hostname=self.host)
        return sscok

    def create_get_request(self, path):
        request = 'GET %s HTTP/1.1\r\n' % path
        request += 'HOST: %s\r\n' % self.host
        request += 'User-Agent: %s\r\n' % self.useragent
        request += 'Accept: text/html\r\n'
        #request += 'Accept-Encoding: gzip\r\n'
        request += 'Accept-Language: en-US\r\n'
        request += 'Referer: https://fakebook.3700.network/\r\n'
        if self.csrftoken != '' and self.sessionid != '':
            request += 'Cookie: csrftoken=%s; sessionid=%s\r\n' % (
                self.csrftoken, self.sessionid)
        elif self.csrftoken != '' and self.sessionid == '':
            request += 'Cookie: csrftoken=%s\r\n' % self.csrftoken
        request += 'Connection: close\r\n\r\n'
        return request

    def create_post_request(self, middleware):
        request = 'POST %s HTTP/1.1\r\n' % self.start
        request += 'HOST: %s\r\n' % self.host
        request += 'User-Agent: %s\r\n' % self.useragent
        request += 'Accept: text/html\r\n'
        #request += 'Accept-Encoding: gzip\r\n'
        request += 'Accept-Language: en-US\r\n'
        request += 'Connection: close\r\n'
        request += 'Cookie: csrftoken=%s\r\n' % self.csrftoken
        payload = 'username=%s&password=%s&csrfmiddlewaretoken=%s&next=/fakebook/' % (
            self.username, self.password, middleware)
        content_length = len(payload.encode())
        request += 'Content-Type: application/x-www-form-urlencoded\r\n'
        request += 'Content-Length: %d\r\n\r\n' % content_length
        request += payload
        return request

    def send_request(self, socket, request):
        socket.send(request.encode())
        if self.verbose:
            print('Send Request:')
            print(request + '\n')

    def recv_response(self, socket):
        chunks = []
        complete = False
        response = ''
        while not complete:
            chunk = socket.recv(65535)
            if len(chunk) == 0:
                complete = True
            else:
                response += chunk.decode()
        pair = response.split('\r\n\r\n')
        header = pair[0]
        data = ''
        if len(pair) > 1:
            data = pair[1]
        if self.verbose:
            print('Receive Response:')
            print(header + '\r\n')
        return header, data

    def update_cookie(self, header):
        lines = header.split('\r\n')
        for line in lines:
            if 'Set-Cookie' in line:
                section = line.split(' ')[1]
                value = section.split('=')[1]
                value = value[0:-1]
                if 'csrf' in section:
                    self.csrftoken = value
                elif 'sessionid' in section:
                    self.sessionid = value

    def extract_middleware(self, data):
        soup = bs(data, 'html.parser')
        token = soup.find_all('input', type='hidden')[0]['value']
        if self.verbose:
            print('Extracted middlewaretoken: %s\n' % token)
        return token

    def login(self):
        socket = self.create_socket()
        request = self.create_get_request(self.start)
        self.send_request(socket, request)
        header, data = self.recv_response(socket)
        socket.close()
        self.update_cookie(header)

        socket = self.create_socket()
        middleware = self.extract_middleware(data)
        request = self.create_post_request(middleware)
        self.send_request(socket, request)
        header, data = self.recv_response(socket)
        socket.close()
        self.update_cookie(header)

        socket = self.create_socket()
        request = self.create_get_request('/fakebook/')
        self.send_request(socket, request)
        header, data = self.recv_response(socket)
        socket.close()
        self.update_cookie(header)

        self.queue.append('/fakebook/')
        self.handle_response('/fakebook/', header, data)

    def get_header_code(self, header):
        first_line = header.split('\r\n')[0]
        return int(first_line.split(' ')[1])

    def get_location(self, header):
        lines = header.split('\r\n')
        for line in lines:
            if 'Location' in line:
                return line.split(' ')[1]

    def search_paths(self, data):
        soup = bs(data, 'html.parser')
        for link in soup.find_all('a', href=True):
            url = urlparse(link['href'])
            host = url.hostname
            path = url.path
            host_valid = False
            if host == None or host == self.host:
                host_valid = True
            if path not in self.visited and host_valid:
                self.queue.append(path)

    def search_flags(self, path, data):
        soup = bs(data, 'html.parser')
        for tag in soup.find_all('h2', class_='secret_flag'):
            flag_string = tag.string
            flag = flag_string.split(' ')[1]
            if flag not in self.flags:
                self.flags.append(flag)
                print(flag)

    def handle_response(self, current_path, header, data):
        code = self.get_header_code(header)
        if code == 302:
            self.visited[current_path] = True
            location = self.get_location(header)
            next_path = urlparse(location).path
            self.queue.append(next_path)
            self.queue.pop(0)
        elif code == 403:
            self.visited[current_path] = True
            self.queue.pop(0)
        elif code == 500:
            return
        elif code == 200:
            self.visited[current_path] = True
            self.search_paths(data)
            self.queue.pop(0)
            self.search_flags(current_path, data)
        else:
            self.visited[current_path] = True
            self.queue.pop(0)

    def run(self):
        self.login()
        while len(self.flags) < 5 and len(self.queue) > 0:
            path = self.queue[0]
            if path == self.logout:
                self.visited[path] = True
                self.queue.pop(0)
                continue
            socket = self.create_socket()
            request = self.create_get_request(path)
            self.send_request(socket, request)
            header, data = self.recv_response(socket)
            socket.close()
            self.update_cookie(header)
            self.handle_response(path, header, data)


desc = 'Can Ivit\'s Webcrawler for Fakebook'
ap = argparse.ArgumentParser(
    description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument('username', help='Username for Fakebook')
ap.add_argument('password', help='Password for Fakebook')
ap.add_argument('-v', '--verbose', action='store_true', default=False,
                help='Prints all HTTP requests and reponses')
args = ap.parse_args()
crawler = WebCrawler(args.username, args.password, args.verbose)
crawler.run()
