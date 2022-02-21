import sip
import logging
import socket
import socketserver
import sys


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect to google's dns and extract self private IP, just for printing purposes

    HOST = s.getsockname()[0]
    print(f"Server Address: {s.getsockname()[0]}:{sip.PORT}\nServer is running...")
    s.close()

    logging.info("Server: %s", HOST)

    if HOST == "127.0.0.1":
        HOST = sys.argv[1]

    sip.recordroute = "Record-Route: <sip:%s:%d;lr>" % (HOST, sip.PORT)
    sip.topvia = "Via: SIP/2.0/UDP %s:%d" % (HOST, sip.PORT)
    server = socketserver.UDPServer((HOST, sip.PORT), sip.UDPHandler)
    server.serve_forever()

