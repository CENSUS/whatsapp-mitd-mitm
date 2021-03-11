#!/usr/bin/env python3

__author__ = 'Chariton Karamitas <huku@census-labs.com>'


import sys
import os
import hashlib
import http
import http.server
import socketserver
import tempfile

import logger


_ADDRESS = ''
_PORT = 8000


class _HTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def setup(self):
        super(_HTTPRequestHandler, self).setup()
        self._logger = logger.get_logger(self.__class__.__name__)


    def _handle_push(self):

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            content_length = 0

        data = bytes()
        while len(data) < content_length:
            data += self.rfile.read(content_length - len(data))

        if len(data) > 0:

            filename = '%s/%s.bin' % (tempfile.gettempdir(), hashlib.md5(data).hexdigest())
            with open(filename, 'wb') as fp:
                fp.write(data)

            self._logger.info('Received %d bytes, stored in %s' % (content_length, filename))



    def _handle_log(self):

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            content_length = 0

        data = bytes()
        while len(data) < content_length:
            data += self.rfile.read(content_length - len(data))

        if len(data) > 0:
            self._logger.info(data.decode('utf-8'))



    def do_POST(self, *args, **kwargs):

        if self.path == '/push':
            self._handle_push()
        elif self.path == '/log':
            self._handle_log()

        self.send_response(http.HTTPStatus.OK)


    def log_message(self, format, *args):
        pass



class _AddressReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def start(address, port):
    try:
        with _AddressReuseTCPServer((address, port), _HTTPRequestHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    return os.EX_OK


def main(argv):
    print('Starting server on %s:%d' % (_ADDRESS, _PORT))
    start(_ADDRESS, _PORT)
    return os.EX_OK


if __name__ == '__main__':
    sys.exit(main(sys.argv))

