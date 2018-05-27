import config
import colorama
import logging
import os
import socket
import select
import ssl
import sys

logger = logging.getLogger(__name__)
logging.basicConfig(filename='client.log', filemode='w', level=getattr(logging, config.LOG_LEVEL))


class Client(object):
    def __init__(self,
                 host=config.HOST,
                 port=config.HOST,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 certfile=config.CERTFILE):
        logger.debug(f'Initialising Client(host={host}, port={port}, timeout={timeout}, certfile={certfile})')
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.eof = False

        colorama.init()

        logger.debug('Checking SSL certificate exists...')
        if not os.path.isfile(certfile):
            logger.error(f'SSL certificate "{certfile}" not found')
            raise FileNotFoundError(f'SSL certificate "{certfile}" not found')
        logger.debug('SSL certificate found.')
        self.certfile = certfile

        self.open()

        while True:
            try:
                self.interact()
            except KeyboardInterrupt:
                print('*** Interrupted! ***')
            finally:
                self.close()

    def open(self):
        """
        Connect to a host.
        """
        logger.debug('Attempting to establish connection to remote host...')
        try:
            self.sock = ssl.wrap_socket(
                socket.create_connection((self.host, self.port), self.timeout),
                ca_certs=self.certfile,
                cert_reqs=ssl.CERT_REQUIRED,
                ssl_version=ssl.PROTOCOL_TLSv1
            )
            logger.info(f'Established connection to {self.host}:{self.port}')
            print('Connected to remote host')
        except Exception:
            logger.error(f'Failed to connect to {self.host}:{self.port}', exc_info=True)
            print('Unable to connect to remote host')
            sys.exit()

    def close(self):
        """
         Close the connection.
        """
        logger.debug('Attempting to close connection to remote host...')
        sock = self.sock
        self.sock = None
        if sock:
            logger.debug('Socket exists, closing...')
            sock.close()
        logger.debug('Connection closed.')

    def read(self):
        logger.debug('Attempting to read data from socket...')
        buf = self.sock.recv(4096)
        logger.debug(f'Data retrieved: {buf}')
        return buf

    def write(self, buf):
        logger.debug(f'Attempting to write {buf} to stdout...')
        sys.stdout.write(buf.decode('utf-8'))
        self.prompt()
        sys.stdout.flush()

    def prompt(self):
        sys.stdout.write('\n>>> ')

    def get(self):
        logger.debug(f'Attempting to get data from stdin...')
        buf = sys.stdin.readline()
        logger.debug(f'Data retrieved: {buf}')
        return buf

    def send(self, buf):
        logger.debug(f'Attempting to send {buf} to socket...')
        self.sock.sendall(buf.encode('utf-8'))

    def interact(self):
        """Interaction function"""
        if sys.platform == 'win32':
            logger.info('System identified as Windows, using threaded interactor...')
            self.mt_interact()
        else:
            logger.info('System identified as non-Windows, using select interactor...')
            logger.debug('Starting listening...')
            socket_list = [sys.stdin, self.sock]
            read_s, write_s, error_s = select.select(socket_list, [], [])
            for sock in read_s:
                if sock == self.sock:
                    try:
                        data = self.read()
                    except EOFError:
                        logger.error('EOF Error', exc_info=True)
                        print('*** Connection to remote host lost ***')
                        sys.exit()
                    if data:
                        self.write(data)
                    else:
                        line = self.get()
                        if line:
                            self.send(line)

    def mt_interact(self):
        """Multithreaded version of interact()"""
        logger.debug('Starting listening thread...')
        import _thread
        _thread.start_new_thread(self.listener, ())
        logger.debug('Starting writing loop...')
        while True:
            line = self.get()
            if not line:
                break
            self.send(line)

    def listener(self):
        """Helper for mt_interact() - executes in other thread"""
        logger.debug('Starting listening...')
        while True:
            try:
                data = self.read()
            except EOFError:
                logger.error('EOF Error', exc_info=True)
                print('*** Connection to remote host lost ***')
                self.close()
                sys.exit()
            if data:
                self.write(data)
            else:
                sys.stdout.flush()

    def __del__(self):
        self.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage : python {__file__} hostname port')
        sys.exit()

    host = sys.argv[1]
    port = int(sys.argv[2])

    client = Client(host, port)