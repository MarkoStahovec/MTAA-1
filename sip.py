#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socketserver
import re
import os
import socket
# import threading
import sys
import time
import logging

HOST, PORT = '192.168.0.183', 6000

rx_ringing = re.compile(b"180")
rx_trying = re.compile(b"100 Trying")
rx_ok = re.compile(b"200 OK|200 Ok")
rx_cbye = re.compile(b"BYE$")

rx_register = re.compile(b"^REGISTER")
rx_invite = re.compile(b"^INVITE")
rx_ack = re.compile(b"^ACK")
rx_prack = re.compile(b"^PRACK")
rx_cancel = re.compile(b"^CANCEL")
rx_bye = re.compile(b"^BYE")
rx_options = re.compile(b"^OPTIONS")
rx_subscribe = re.compile(b"^SUBSCRIBE")
rx_publish = re.compile(b"^PUBLISH")
rx_notify = re.compile(b"^NOTIFY")
rx_info = re.compile(b"^INFO")
rx_message = re.compile(b"^MESSAGE")
rx_refer = re.compile(b"^REFER")
rx_update = re.compile(b"^UPDATE")
rx_from = re.compile(b"^From:")
rx_cfrom = re.compile(b"^f:")
rx_to = re.compile(b"^To:")
rx_cto = re.compile(b"^t:")
rx_tag = re.compile(b";tag")
rx_contact = re.compile(b"^Contact:")
rx_ccontact = re.compile(b"^m:")
rx_uri = re.compile(b"sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile(b"sip:([^ ;>$]*)")
# rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile(b"^SIP/2.0 ([^ ]*)")
rx_invalid = re.compile(b"^191\.168")  # TODO THIS IS WAS: rx_invalid = re.compile(b"^192\.168")
rx_invalid2 = re.compile(b"^10\.")
# rx_cseq = re.compile("^CSeq:")
# rx_callid = re.compile("Call-ID: (.*)$")
# rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile(b"^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile(b"^Route:")
rx_contentlength = re.compile(b"^Content-Length:")
rx_ccontentlength = re.compile(b"^l:")
rx_via = re.compile(b"^Via:")
rx_cvia = re.compile(b"^v:")
rx_branch = re.compile(b";branch=([^;]*)")
rx_rport = re.compile(b";rport$|;rport;")
rx_contact_expires = re.compile(b"expires=([^;$]*)")
rx_expires = re.compile(b"^Expires: (.*)$")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}
history = "history.txt"
callers = []
calling = False


def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, b'\000')
        # logging.debug("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(socketserver.BaseRequestHandler):
    def debugRegister(self):
        logging.debug("*** REGISTER ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)
                # self.data[0] = self.data[0].encode()

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        branch = ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    via = via.encode()
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    line = line.decode()
                    via = line.replace("rport", text)
                    via = via.encode()
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia.encode()):
                    data.append(line)
            else:
                data.append(line)
        return data

    def checkValidity(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("Registracia pre %s vyprsala" % uri)
            return False

    def getSocketInfo(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return socket, client_addr

    def getDestination(self):
        destination = None
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = b"%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = None
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = b"%s@%s" % (md.group(1), md.group(2))
                break

        return origin

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri.encode()
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line.decode(), ";tag=123456")
                    data[index] = data[index].encode()
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    line = line.decode()
                    data[index] = line.replace("rport", text).encode()
                    line = line.encode()
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = b"%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = b"Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = b"l: 0"
            index += 1
            if line == "":
                break
        # data.append("")
        for line in data:
            if type(line) == str:
                line = line.encode()

        text = b"\r\n".join(data)
        self.socket.sendto(text, self.client_address)
        showtime()
        logging.info("<<< %s" % data[0])
        logging.debug("---\n<< server odoslal [%d]:\n%s\n---" % (len(text), text))

    def processRegister(self):
        fromm = None
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = b"%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if rx_invalid.search(contact) or rx_invalid2.search(contact):
            if fromm in registrar:
                del registrar[fromm]
            self.sendResponse("488 Neplatna IP adresa")
            return
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse("200 0K")
                return
        else:
            now = int(time.time())
            validity = now + expires

        logging.info("Od: %s - Pre: %s" % (fromm, contact))
        logging.debug("Z Adresy: %s:%s" % self.client_address)
        logging.debug("Vyprsi o %d sekund" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]

        with open(history, "a+") as file:
            file.write("\n----- REGISTER -----\nADRESA:" + contact.decode() + "\n\n")

        self.debugRegister()
        self.sendResponse("200 0K")

    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE ")
        logging.debug("-----------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse("400 Zla poziadavka")
            return
        destination = self.getDestination()
        if len(destination) > 0:

            if origin.decode() not in callers:
                callers.append(origin.decode())
            if destination.decode() not in callers:
                callers.append(destination.decode())

            logging.info("Pre adresu: %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute.encode())
                text = b"\r\n".join(data)
                # text = string.join(data, "\r\n")
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server odoslal [%d]:\n%s\n---" % (len(text), text))

            else:
                self.sendResponse("480 Docasne nedostupne")
        else:
            self.sendResponse("500 Chyba na strane servera")

    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK ")
        logging.debug("--------------")
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("Pre adresu: %s" % destination)
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute.encode())
                text = b"\r\n".join(data)

                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server odoslal [%d]:\n%s\n---" % (len(text), text))

    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite ")
        logging.debug("----------------------")
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Nespravna poziadavka")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("Pre adresu: %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute.encode())
                text = b"\r\n".join(data)

                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server odoslal [%d]:\n%s\n---" % (len(text), text))

            else:
                self.sendResponse("406 Nespravna adresa")
        else:
            self.sendResponse("500 Chyba na strane servera")

    def processCode(self):
        global calling
        origin = self.getOrigin()
        caller_list = ''
        if len(origin) > 0:
            logging.debug("Od: %s" % origin)
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = b"\r\n".join(data)
                # text = string.join(data, "\r\n")
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server odoslal [%d]:\n%s\n---" % (len(text), text))

                #if rx_ringing.search(data[0]) and origin.decode() not in callers:
                #    callers.append(origin.decode())

                """
                    for k, v in registrar.items():
                        if k.decode() not in callers:
                            callers.append(k.decode())
                """

                #destination = self.getDestination()
                #if rx_ringing.search(data[0]) and destination.decode() not in callers:
                #    callers.append(destination.decode())

                if rx_ok.search(data[0]) and len(callers) >= 2:
                    if not calling:
                        calling = True
                        with open(history, "a+") as file:
                            for i in range(1, len(callers)):
                                caller_list = caller_list + callers[i] + ", "

                            file.write(f"\n----- HOVOR -----\n"
                                       f"DATUM: " + time.strftime("%a, %d %b %Y", time.localtime()))

                            file.write("\nOD:  " + callers[0] + "\nPRE:  " + caller_list + "\n\n")

                            file.write("PRIJATY O:  " + time.strftime("%H:%M:%S ", time.localtime()) + "\n")

                if rx_cbye.search(data[5]) and len(callers) >= 2:
                    calling = False
                    callers.clear()
                    with open(history, "a+") as file:
                        file.write("ZRUSENY O:  " + time.strftime("%H:%M:%S ", time.localtime()) +
                                   ",  " + origin.decode() + "\n\n")

                if rx_cbye.search(data[5]) and callers:
                    callers.remove(origin.decode())

    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)
                # print "message %s unknown" % self.data

    def handle(self):
        # socket.setdefaulttimeout(120)
        data = self.request[0]
        self.data = data.split(b"\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info(">>> %s" % request_uri)
            logging.debug("---\n>> server prijal [%d]:\n%s\n---" % (len(data), data))
            logging.debug("Z adresy %s:%d" % self.client_address)
            self.processRequest()

        else:
            if len(data) > 4:
                showtime()
                logging.info("---\n>> server received [%d]:" % len(data))
                """
                hexdump(data, ' ', 16)
                logging.warning("---")
                """

"""
if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect to google's dns and extract self private IP, just for printing purposes

    HOST = s.getsockname()[0]
    print(f"Server Address: {s.getsockname()[0]}:{PORT}\nServer is running...")
    s.close()

    logging.info("Server: %s", HOST)

    if HOST == "127.0.0.1":
        HOST = sys.argv[1]

    recordroute = "Record-Route: <sip:%s:%d;lr>" % (HOST, PORT)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (HOST, PORT)
    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()
"""