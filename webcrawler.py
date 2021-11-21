import argparse
import gzip
from os import sysconf
import socket
import ssl
import sys
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
    socket = None
    time_out = 0.5

    def __init__(self, username, password, verbose):
        self.username = username
        self.password = password
        self.verbose = verbose
        self.socket = self.create_socket()

    def create_socket(self):
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.time_out)
                sock.connect((self.host, self.port))
                context = ssl.create_default_context()
                ssock = context.wrap_socket(sock, server_hostname=self.host)
                return ssock
            except socket.timeout:
                continue

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
        request += 'Connection: keep-alive\r\n\r\n'
        return request

    def create_post_request(self, middleware):
        request = 'POST %s HTTP/1.1\r\n' % self.start
        request += 'HOST: %s\r\n' % self.host
        request += 'User-Agent: %s\r\n' % self.useragent
        request += 'Accept: text/html\r\n'
        #request += 'Accept-Encoding: gzip\r\n'
        request += 'Accept-Language: en-US\r\n'
        request += 'Connection: keep-alive\r\n'
        request += 'Cookie: csrftoken=%s\r\n' % self.csrftoken
        payload = 'username=%s&password=%s&csrfmiddlewaretoken=%s&next=/fakebook/' % (
            self.username, self.password, middleware)
        content_length = len(payload.encode())
        request += 'Content-Type: application/x-www-form-urlencoded\r\n'
        request += 'Content-Length: %d\r\n\r\n' % content_length
        request += payload
        return request

    def send_request(self, request):
        self.socket.send(request.encode())
        if self.verbose:
            print('Send Request:')
            print(request + '\n')

    def recv_response(self, request):
        response = ''
        complete = False
        while not complete:
            response = ''
            chunk = None
            try:
                chunk = self.socket.recv(65535)
                response = chunk.decode()
                complete = True
            except socket.timeout:
                self.socket.close()
                self.socket = self.create_socket()
                complete = False
                self.send_request(request)
            if len(response) == 0:
                self.socket.close()
                self.socket = self.create_socket()
                complete = False
                self.send_request(request)
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
        request = self.create_get_request(self.start)
        self.send_request(request)
        header, data = self.recv_response(request)
        self.update_cookie(header)

        middleware = self.extract_middleware(data)
        request = self.create_post_request(middleware)
        self.send_request(request)
        header, data = self.recv_response(request)
        self.update_cookie(header)

        request = self.create_get_request('/fakebook/')
        self.send_request(request)
        header, data = self.recv_response(request)
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
            if '/fakebook/' in path and path not in self.visited:
                self.queue.append(path)

    def search_flags(self, data):
        soup = bs(data, 'html.parser')
        for tag in soup.find_all('h2', class_='secret_flag'):
            flag_string = tag.string
            flag = flag_string.split(' ')[1]
            if flag not in self.flags:
                self.flags.append(flag)
                print(flag)

    def check_connection(self, header):
        for line in header.split('\r\n'):
            if 'Connection: close' in line:
                self.socket.close()
                self.socket = self.create_socket()

    def handle_response(self, current_path, header, data):
        self.check_connection(header)
        code = self.get_header_code(header)
        if code == 302:
            self.visited[current_path] = True
            location = self.get_location(header)
            next_path = urlparse(location).path
            self.queue.append(next_path)
            self.queue.pop(0)
        elif code == 500:
            return
        elif code == 200:
            self.visited[current_path] = True
            self.search_flags(data)
            self.search_paths(data)
            self.queue.pop(0)
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
            request = self.create_get_request(path)
            self.send_request(request)
            header, data = self.recv_response(request)
            self.update_cookie(header)
            self.handle_response(path, header, data)
            if self.verbose:
                print('FLAGS: %d\n' % len(self.flags))


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
