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
    start = 'https://fakebook.3700.network/accounts/login/'
    host = urlparse(start).netloc
    port = 443
    useragent = 'Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0'
    csrftoken = ''
    sessionid = ''

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

    def create_get_request(self, url):
        request = 'GET %s HTTP/1.1\r\n' % urlparse(url).path
        request += 'HOST: %s\r\n' % self.host
        request += 'User-Agent: %s\r\n' % self.useragent
        request += 'Accept: text/html\r\n'
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
        request = 'POST %s HTTP/1.1\r\n' % urlparse(self.start).path
        request += 'HOST: %s\r\n' % self.host
        request += 'User-Agent: %s\r\n' % self.useragent
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
        response = ''
        complete = False
        while not complete:
            chunk = socket.recv(65535)
            if len(chunk) == 0:
                complete = True
            else:
                response += chunk.decode()
        pair = response.split('\r\n\r\n')
        header = pair[0]
        data = pair[1]
        if self.verbose:
            print('Receive Response:')
            print(response)
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
        return data

    def run(self):
        self.login()


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