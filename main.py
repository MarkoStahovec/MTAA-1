from sip import socketserver
from sip import UDPHandler
from sip import socket
from sip import logging

HOST, PORT = '', 5060


def handle():
    pass


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect to google's dns and extract self private IP, just for printing purposes

    HOST = s.getsockname()[0]
    print(f"Server Address: {s.getsockname()[0]}:{PORT}")
    s.shutdown(socket.SHUT_RDWR)  # terminate socket
    s.close()

    logging.info("Server: %s", HOST)

    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()
