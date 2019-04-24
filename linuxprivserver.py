#!/usr/bin/env python3
import argparse
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote_plus
from base64 import b64decode

quiet = False
outfile = None

__version__ = '3'


class RequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    """
    Based on the Gist https://gist.github.com/huyng/814831,
    by Nathan Hamiel (2010)
    """
    def do_POST(self):
        self._set_headers()
        length = self.headers.get('content-length')
        length = int(length) if length else 0

        try:
            data = self.rfile.read(length)[5:]
            content = b64decode(unquote_plus(data.decode()))
            if not quiet:
                sys.stdout.buffer.write(content)
                sys.stdout.buffer.flush()
            if outfile is not None:
                outfile.write(content)
                outfile.flush()
        except:
            print('\x1b[1;32mSomething went terribly wrong, cannot parse returned data.\x1b[0m')

    def log_message(self, format, *args):
        pass


def main(ip, port, filename=None, q=False):
    global quiet, outfile
    quiet = q
    if filename is not None:
        outfile = open(filename, 'wb')
    server = HTTPServer((args.ip, args.port), RequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip',
                        dest='ip',
                        required=False,
                        default='0.0.0.0',
                        help='If not provided, defaults to 0.0.0.0')
    parser.add_argument('--port',
                        dest='port',
                        required=False,
                        default=8080,
                        type=int,
                        help='If not provided, defaults to 8080')
    parser.add_argument('--quiet',
                        dest='quiet',
                        required=False,
                        default=False,
                        action='store_true',
                        help="Don't output results to the terminal")
    parser.add_argument('--outfile',
                        dest='filename',
                        required=False,
                        default=None,
                        help='Save the output to a file')
    args = parser.parse_args()
    main(args.ip, args.port, args.filename, args.quiet, args.ssl)
