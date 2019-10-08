import re
import ssl
import sys
import uuid
import socket
import logging
import hashlib
import secrets
import requests
import sslkeylog
from argparse import ArgumentParser

import rcs_client_constants as CONST

logging.basicConfig(stream=sys.stderr, level=CONST.LOG_LEVEL, format=CONST.LOG_FMT)
sslkeylog.set_keylog("sslkeylog-rcs-tls.txt")

class Utils():
    def __init__(self):
        pass

    @staticmethod
    def get_ip_address(ip = "8.8.8.8", port = 80):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip, port))
        return s.getsockname()[0]

    @staticmethod
    def get_ip_address_from_socket(sock):
        return sock.getsockname()[0]

    @staticmethod
    def find_1st_occurrence(re_pattern, text):
        textObj = re.search(re_pattern, text)
        if textObj:
            return textObj.group(1)
        else:
            return ""

    @staticmethod
    def find_all_occurrence(re_pattern, text):
        return re.findall(re_pattern, text)

    @staticmethod
    def calc_sip_digest_auth(username, realm, password, uri, nonce):
        str1 = hashlib.md5("{}:{}:{}".format(username, realm, password).encode('utf-8')).hexdigest()
        str2 = hashlib.md5("REGISTER:{}".format(uri).encode('utf-8')).hexdigest()
        return hashlib.md5("{}:{}:{}".format(str1,nonce,str2).encode('utf-8')).hexdigest()


class ArgumentsException(Exception):
    pass


class Arguments():
    def __init__(self):
        self.parser = ArgumentParser()
        self.add_arguments()
        self.parse_args()
        self.validate()

    def parse_args(self):
        # Parse the supplied arguments and map each one to an attribute on
        # the Argument object.
        for k, v in self.parser.parse_args().__dict__.items():
            setattr(self, k, v)

    def validate(self):
        if not self.sim_mode:

            if self.realm == CONST.SIM_RCS_REALM:
                logging.warning("No SIP realm provided, using default Fi RCS realm.")
                self.realm = CONST.FI_RCS_REALM

            try:
                assert re.match(CONST.REGEX_MSISDN, str(self.username)) is not None
            except AssertionError as ae:
                logging.warning("No username provided or illegal format in the username provided.")
                logging.warning("Using default username instead.")
                self.username = CONST.DEMO_USERNAME

            if not self.password:
                raise ArgumentsException("In non-sim mode, please specify the user's password with '-p'")
            else:
                try:
                    assert re.match(CONST.REGEX_SIP_PASSWORD, str(self.password)) is not None
                except AssertionError as ae:
                    raise ArgumentsException("Illegal character or wrong length in the password provided!")

            try:
                assert re.match(CONST.REGEX_MSISDN, str(self.receiver)) is not None
            except AssertionError as ae:
                logging.warning("No receiver provided or illegal format in the receiver provided.")
                logging.warning("Using default reciver's MSISDN instead.")
                self.receiver = CONST.DEMO_RECEIVER

        else:
            if not self.password:
                logging.warning("No password provided, using default demo password.")
                self.password = CONST.DEMO_SIP_PWD

    def add_arguments(self):
        self.parser.add_argument('-u',
                                 '--username',
                                 dest='username',
                                 default=CONST.DEMO_USERNAME,
                                 # action='store_true',
                                 help='Username (in MSISDN format) for SIP')

        self.parser.add_argument('-p',
                                 '--pwd',
                                 dest='password',
                                 default=None,
                                 # action='store_true',
                                 help='Auth Password for SIP')

        self.parser.add_argument('-P',
                                 '--port',
                                 dest='port',
                                 default=CONST.FI_RCS_PORT,
                                 help='TCP port to use on SIP connection')

        self.parser.add_argument('-r',
                                 '--receiver',
                                 dest='receiver',
                                 default=CONST.DEMO_RECEIVER,
                                 # action='store_true',
                                 help='Receiver number (in MSISDN format) for SIP conversation')

        self.parser.add_argument('-s',
                                 '--realm',
                                 dest='realm',
                                 default=CONST.SIM_RCS_REALM,
                                 # action='store_true',
                                 help='SIP realm to register on')

        self.parser.add_argument('-t',
                                 '--transport',
                                 dest='trans_proto',
                                 default="tls",
                                 # action='store_true',
                                 help='Transport protocol to use for SIP')

        self.parser.add_argument('--imei',
                                 dest='imei',
                                 default=CONST.DEMO_IMEI,
                                 # action='store_true',
                                 help='IMEI of the device')

        self.parser.add_argument('--sim',
                                 dest='sim_mode',
                                 action='store_true',
                                 default=False,
                                 help='Use simulation mode (use pre-recorded responses instead of communicating with real server)')


class SipHeaders():

    def __init__(self, ip, username, receiver, p_cscf_addr, imei, port=20000, sip_ver=2, transport="tls", max_forwards=70, supported="path,gruu", branch_prefix="z9hG4bK", user_agent=CONST.DEMO_RCS_UA):
        self._ip = ip
        self._port = port
        self._username = username
        self._receiver = receiver
        self._p_cscf_addr = p_cscf_addr
        self._imei = imei
        self._user_agent = user_agent
        self._max_forwards = max_forwards
        # [TODO] Zengwen: the tag and branch are actually somehow correlated
        # Needs further update
        # the RFC 3261 says: "The combination of the To tag, From tag, 
        # and Call-ID completely defines a peer-to-peer SIP relationship
        # between Alice and Bob and is referred to as a dialog.""
        self._branch_prefix = branch_prefix
        self._supported = supported
        self._authorization = "Digest"
        self._allow_methods = "INVITE, ACK, BYE, CANCEL, NOTIFY, OPTIONS, MESSAGE"
        self._p_access_network_info = "IEEE-802.11;i-wlan-node-id=000000000000"
        self._expires = 600000
        self._q = 0.5

        if transport.lower() == "tls" or transport.lower() == "tcp" or transport.lower() == "udp":
            self._transport = transport.upper()
        else:
            self._transport = "TCP"
        if sip_ver == 2:
            self._sip_ver = "2.0"
        else:
            self._sip_ver = "1.0"


    def _build_sip_flags(self, capability="simple-im|chat|geopush|fthttp|chatbot"):
        '''
        Refer to GSMA RCC.07 v10.0. pp.33 of 398.
        Should check pp.54 for more service tags
        '''
        self._rcs_iari_flag_prefix = "+g.3gpp.iari-ref"
        self._rcs_icsi_flag_prefix = "+g.3gpp.icsi-ref"
        self._rcs_callcomposer_flag = "+g.gsma.callcomposer"
        self._rcs_ipcall_flag = "+g.gsma.rcs.ipcall"
        self._rcs_chatbot_version_flag = "+g.gsma.rcs.botversion=\"#=0.92,#=1\""
        self._rcs_cpm_ext_support_flag = "+g.gsma.rcs.cpmext"
        self._rcs_chat_oma_simple_im_flag = "+g.oma.sip-im"
        # self._rcs_flag_weight_flag = "expires=600000;q=0.5"

        self._rcs_icsi_tag_standalone_messaging = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.deferred"
        self._rcs_icsi_tag_chat_oma_cpm = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"
        self._rcs_icsi_tag_callcomposer = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.callcomposer"
        self._rcs_icsi_tag_postcall = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.callunanswered"
        self._rcs_icsi_tag_sharedmap = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.sharedmap"
        self._rcs_icsi_tag_sharedsketch = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.sharedsketch"
        self._rcs_icsi_tag_ipcall = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

        self._rcs_iari_tag_chat_oma_simple_im = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im"
        self._rcs_iari_tag_ft = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.ft"
        self._rcs_iari_tag_joyn_intmsg = "urn%3Aurn-7%3A3gpp-application.ims.iari.joyn.intmsg"
        self._rcs_iari_tag_fthttp = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp"
        self._rcs_iari_tag_ftsms = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms"
        self._rcs_iari_tag_geopush = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush"
        self._rcs_iari_tag_geosms = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms"
        self._rcs_iari_tag_chatbot = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot"
        self._rcs_iari_tag_chatbot_standalone_msg = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa"
        self._rcs_iari_tag_plugin_support = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.plugin"

        if capability == "simple-im|chat|geopush|fthttp|chatbot":
            return "{};{}=\"{},{},{},{}\";{}".format(
                self._rcs_chat_oma_simple_im_flag,
                self._rcs_iari_flag_prefix,
                self._rcs_iari_tag_chat_oma_simple_im,
                self._rcs_iari_tag_geopush,
                self._rcs_iari_tag_fthttp,
                self._rcs_iari_tag_chatbot,
                self._rcs_chatbot_version_flag
                )
        else: # used in capability definition in OPTIONS header
            return "{};{}=\"{},{},{},{},{},{}\";{}".format(
                self._rcs_chat_oma_simple_im_flag,
                self._rcs_iari_flag_prefix,
                self._rcs_iari_tag_chat_oma_simple_im,
                self._rcs_iari_tag_ft,
                self._rcs_iari_tag_geopush,
                self._rcs_iari_tag_joyn_intmsg,
                self._rcs_iari_tag_fthttp,
                self._rcs_iari_tag_chatbot,
                self._rcs_chatbot_version_flag
                )

    def set_call_id(self, call_id):
        return "Call-Id: {id}\r\n".format(id = call_id)

    def set_c_seq(self, c_seq, method):
        return "CSeq: {c_seq} {method}\r\n".format(c_seq = c_seq, method = method)

    def set_from(self, tag = uuid.uuid4()):
        return "From: <tel:{username}>;tag={tag}\r\n".format(username = self._username, tag = tag)

    def set_to(self, receiver):
        return "To: <tel:{to}>\r\n".format(to = receiver)
    
    def set_via(self, branch = secrets.token_urlsafe(10), options=";keep;server-keep;rport"):
        return "Via: SIP/{sip_ver}/{transport} {ip}:{port};branch={branch_prefix}{branch}{options}\r\n".format(
            sip_ver = self._sip_ver,
            transport = self._transport,
            ip = self._ip,
            port = self._port,
            branch_prefix = self._branch_prefix,
            branch = branch,
            options = options
            )

    def set_max_forwards(self):
        return "Max-Forwards: {max_forwards}\r\n".format(max_forwards = self._max_forwards)

    def set_accept_contact(self, capability="customized"):
        return "Accept-Contact: *;{feature_tags};explicit\r\n".format(feature_tags = self._build_sip_flags(capability))

    def set_contact(self, capability="simple-im|chat|geopush|fthttp|chatbot"):
        self._sip_instance_tag = "+sip.instance=\"<urn:gsma:imei:{imei}>\"".format(imei = self._imei)
        return "Contact: <sip:{username}@{ip}:{port};transport={transport}>;{identity};{feature_tags};expires={expires};q={q}\r\n".format(
            username = self._username,
            ip = self._ip,
            port = self._port,
            transport = self._transport.lower(),
            identity = self._sip_instance_tag,
            feature_tags = self._build_sip_flags(capability),
            expires = self._expires,
            q = self._q
            )

    def set_options_contact(self, capability="customized"):
        self._sip_instance_tag = "+sip.instance=\"<urn:gsma:imei:{imei}>\"".format(imei = self._imei)
        return "Contact: <sip:{username}@{ip}:{port};transport={transport}>;{identity};{feature_tags}\r\n".format(
            username = self._username,
            ip = self._ip,
            port = self._port,
            transport = self._transport.lower(),
            identity = self._sip_instance_tag,
            feature_tags = self._build_sip_flags(capability)
            )

    def set_accept(self):
        return "Accept: application/sdp\r\n"

    def set_supported(self):
        return "Supported: {supported}\r\n".format(supported = self._supported)

    def set_route(self, route_lst):
        return "Route: <{route}>\r\n".format(route = ">,<".join(route_lst))

    def set_p_preferred_identity(self):
        return "P-Preferred-Identity: tel:{username}\r\n".format(username = self._username)

    def set_user_agent(self):
        return "User-Agent: {user_agent}\r\n".format(user_agent = self._user_agent)

    def set_allow(self):
        return "Allow: {allow_methods}\r\n".format(allow_methods = self._allow_methods)

    def set_authorization(self, nonce, response):
        return "Authorization: {authorization} username=\"{username}\",uri=\"sip:{p_cscf_addr}\",algorithm=MD5,realm=\"{p_cscf_addr}\",nonce=\"{nonce}\",response=\"{response}\"\r\n".format(
            authorization = self._authorization,
            username = self._username,
            p_cscf_addr = self._p_cscf_addr,
            nonce = nonce,
            response = response)

    def set_x_google_event_id(self):
        return "X-Google-Event-Id: {x_google_event_id}\r\n".format(x_google_event_id = uuid.uuid4())

    def set_p_access_network_info(self):
        return "P-Access-Network-Info: {p_access_network_info}\r\n".format(p_access_network_info = self._p_access_network_info)

    def set_content_length(self, len=0):
        return "Content-Length: {content_len}\r\n\r\n".format(content_len=len)

class SipMessages():
    def __init__(self, username, password, realm, ip, receiver, p_cscf_addr, imei):
        self.username = username
        self.password = password
        self.receiver = receiver
        self.realm = realm
        self.uri = "sip:{}".format(self.realm)
        self.ip = ip
        self.headers = SipHeaders(ip, username, receiver, p_cscf_addr, imei)
        self.status_code_hldr = {   '401' : self.status_hdlr_401,
                                    '200' : self.status_hdlr_200,
                                    '511' : self.status_hdlr_511,
                                    'default' : self.status_hdlr_default}
        self.nonce = ""
        self.response = ""
        self.received_ip = ""
        self.rport = -1
        self.server_nonce = False
        self.path = ""
        self.path_tag = ""
        self.p_associated_uri = ""
        self.route_lst = []

    def register(self, seq, call_id):
        reg_str = "REGISTER sip:{realm} SIP/2.0\r\n".format(realm = self.realm)
        reg_msg = reg_str   + self.headers.set_call_id(call_id) \
                            + self.headers.set_c_seq(seq, "REGISTER") \
                            + self.headers.set_from(secrets.token_urlsafe(10)) \
                            + self.headers.set_to(self.username) \
                            + self.headers.set_via() \
                            + self.headers.set_max_forwards() \
                            + self.headers.set_contact() \
                            + self.headers.set_supported() \
                            + self.headers.set_p_preferred_identity() \
                            + self.headers.set_user_agent() \
                            + self.headers.set_allow() \
                            + self.headers.set_authorization(self.nonce, self.response) \
                            + self.headers.set_x_google_event_id() \
                            + self.headers.set_p_access_network_info() \
                            + self.headers.set_content_length(0)
        return reg_msg

    def options(self, seq, call_id):
        options_str = "OPTIONS tel:{receiver} SIP/2.0\r\n".format(receiver = self.receiver)
        options_msg = options_str + self.headers.set_call_id(call_id) \
                            + self.headers.set_c_seq(seq, "OPTIONS") \
                            + self.headers.set_from(secrets.token_urlsafe(10)) \
                            + self.headers.set_to(self.receiver) \
                            + self.headers.set_via(secrets.token_urlsafe(10), "") \
                            + self.headers.set_max_forwards() \
                            + self.headers.set_accept_contact() \
                            + self.headers.set_options_contact() \
                            + self.headers.set_accept() \
                            + self.headers.set_route(self.route_lst) \
                            + self.headers.set_p_preferred_identity() \
                            + self.headers.set_user_agent() \
                            + self.headers.set_allow() \
                            + self.headers.set_x_google_event_id() \
                            + self.headers.set_p_access_network_info() \
                            + self.headers.set_content_length(0)
        return options_msg


    def calculate_response(self):
        self.response = Utils.calc_sip_digest_auth(self.username, self.realm, self.password, self.uri, self.nonce)

    # Some resource maybe worth looking at: https://github.com/racker/python-twisted-core/blob/master/twisted/protocols/sip.py
    def message_parser(self, message):
        msg_split = message.split("\r\n\r\n")
        msg_header = msg_split[0]
        if len(msg_split) > 1:
            msg_body = msg_split[1]

        logging.debug("Split message header:\n\n{}\n".format(msg_header))
        logging.debug("Split message body:\n\n{}\n".format(msg_body))

        msg_header_lst = msg_header.split("\r\n")
        logging.debug("Found {} lines in total in the message header received.".format(len(msg_header_lst)))
        logging.debug("First line in message header:\n{}".format(msg_header_lst[0]))

        if (msg_header_lst[0].startswith("SIP/")):
            try:
                # status_code = msg_header_lst[0].split(" ")[1]
                # print(msg_header_lst)
                # print("trying parser for {}".format(status_code))
                # print(self.status_code_hldr[str(status_code)])
                self.status_code_hldr[msg_header_lst[0].split(" ")[1]](msg_header_lst) # handle 200, 401, 511 SIP response
            except Exception as e:
                logging.error(e)
                self.status_code_hldr['default']() # handle other cases


    def status_hdlr_200(self, msg_header_lst):
        logging.debug("Entering status_hdlr_200()")
        for l in msg_header_lst:
            if l.startswith("Via"):
                self.header_parser_via(l)
            elif l.startswith("Path"):
                self.header_parser_path(l)
            elif l.startswith("Service-Route"):
                self.header_parser_service_route(l)
            elif l.startswith("Contact"):
                self.header_parser_contact(l)
            elif l.startswith("To"):
                self.header_parser_to(l)
            elif l.startswith("From"):
                self.header_parser_from(l)
            elif l.startswith("Call-ID"):
                self.header_parser_call_id(l)
            elif l.startswith("CSeq"):
                self.header_parser_c_seq(l)
            elif l.startswith("P-Associated-URI"):
                self.header_parser_p_associated_uri(l)
            elif l.startswith("X-Google-Event-Id"):
                self.header_parser_x_google_event_id(l)
            elif l.startswith("Content-Length"):
                self.header_parser_content_length(l)


    def status_hdlr_401(self, msg_header_lst):
        logging.debug("Entering status_hdlr_401()")
        for l in msg_header_lst:
            if l.startswith("Via"):
                self.header_parser_via(l)
            elif l.startswith("To"):
                self.header_parser_to(l)
            elif l.startswith("From"):
                self.header_parser_from(l)
            elif l.startswith("Call-ID"):
                self.header_parser_call_id(l)
            elif l.startswith("CSeq"):
                self.header_parser_c_seq(l)
            elif l.startswith("WWW-Authenticate"):
                self.header_parser_www_auth(l)
            elif l.startswith("X-Google-Event-Id"):
                self.header_parser_x_google_event_id(l)
            elif l.startswith("Content-Length"):
                self.header_parser_content_length(l)


    def status_hdlr_511(self, msg_header_lst):
        logging.debug("Entering status_hdlr_511()")
        pass

    def status_hdlr_default(self, msg_header_lst):
        logging.debug("Entering status_hdlr_default()")
        pass

    def header_parser_via(self, message):
        self.rport = Utils.find_1st_occurrence(r"rport=(\d+);", message)
        self.received_ip = Utils.find_1st_occurrence(r"received=(.*)$", message)
        logging.debug(self.rport)
        logging.debug(self.received_ip)

    def header_parser_path(self, message):
        self.path = Utils.find_1st_occurrence(r"^<(.*)>", message)
        self.path_tag = Utils.find_1st_occurrence(r"^;(.*)>", message)
        self.route_lst.append("{path};transport={transport}".format(path = self.path, transport = "tls"))
        logging.debug(self.path)
        logging.debug(self.path_tag)
        logging.debug(self.route_lst)

    def header_parser_service_route(self, message):
        self.route_lst.append(Utils.find_1st_occurrence(r"^<(.*)>", message))
        logging.debug(self.route_lst)

    def header_parser_contact(self, message):
        logging.debug("Accepted contact info at server:\n", message)

    def header_parser_to(self, message):
        pass

    def header_parser_from(self, message):
        pass

    def header_parser_call_id(self, message):
        pass

    def header_parser_c_seq(self, message):
        pass

    def header_parser_p_associated_uri(self, message):
        self.p_associated_uri = Utils.find_1st_occurrence(r"^<(.*)>", message)
        logging.debug(self.p_associated_uri)

    def header_parser_www_auth(self, message):
        self.nonce = Utils.find_1st_occurrence(r"nonce=\"(.*?)\",", message)
        logging.debug(self.nonce)
        self.server_nonce = True

    def header_parser_x_google_event_id(self, message):
        pass

    def header_parser_content_length(self, message):
        pass


def main(args):

    logging.info("========================================================================")
    logging.info("|                    Connecting to RCS ACS server ...                  |")
    logging.info("========================================================================\n")

    try:
        # CREATE SOCKET
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)

        # WRAP SOCKET
        wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS, ciphers="ALL") # ssl_version=ssl.PROTOCOL_TLSv1_2

        # CONNECT AND PRINT REPLY
        try:
            wrappedSocket.connect((args.realm, args.port))
            logging.info("========================================================================")
            logging.info("|       Connected to RCS ACS server at {}       |".format(args.realm))
            logging.info("========================================================================\n")
        except:
            logging.info("========================================================================")
            logging.info("|             Error: Cannot connect to given RCS ACS server!           |")
            logging.info("========================================================================\n")

            # Regardless of what happened, try to gracefully close down the socket.
            # CLOSE SOCKET CONNECTION
            wrappedSocket.close()
            exit(-1)

        logging.info("========================================================================")
        logging.info("|                        Preparing SIP Messages ...                    |")
        logging.info("========================================================================\n")
        my_ip = Utils.get_ip_address_from_socket(wrappedSocket)
        rcs_messages = SipMessages(args.username, args.password, args.realm, my_ip, args.receiver, args.realm, args.imei)

        # Step 1. Send a SIP REGISTER message and get 401 Unauthorized response
        logging.info("========================================================================")
        logging.info("|                  Sending a SIP REGISTER message and                  |")
        logging.info("|                 expecting a 401 Unauthorized response                |")
        logging.info("========================================================================\n")
        # google_fi_register_1_req  = rcs_messages.register(1, "23099613-21b1-4565-902f-0001f4b4b99d", "", "")
        reg_call_id = uuid.uuid4()
        google_fi_register_1_req = rcs_messages.register(1, reg_call_id)
        logging.info("Sending:\n\n{}\n".format(google_fi_register_1_req))

        if not args.sim_mode:
            # send message (encoded into bytes) through socket
            wrappedSocket.send(google_fi_register_1_req.encode())

            # receive server's response
            google_fi_register_1_resp = wrappedSocket.recv(65535)
            logging.info("Received:\n\n{}\n".format(google_fi_register_1_resp.decode()))
        else:
            google_fi_register_1_resp = CONST.GOOGLE_FI_REGISTER_1_RESP.encode()

        # parse received message
        rcs_messages.message_parser(google_fi_register_1_resp.decode())

        # check nonce received
        if rcs_messages.server_nonce is True:
            rcs_messages.calculate_response()

            # Step 2. Send authenticated register message
            logging.info("========================================================================")
            logging.info("|                Sending the 2nd SIP REGISTER message                  |")
            logging.info("|                 with response calculated from nonce                  |")
            logging.info("========================================================================\n")
            logging.info("Formating 2nd REGISTER with nonce and response")

            google_fi_register_2_req = rcs_messages.register(2, reg_call_id)
            logging.info("Sending:\n\n{}\n".format(google_fi_register_2_req))

            # send message (encoded into bytes) through socket
            # wrappedSocket.send(google_fi_register_2_req.encode())

            # # receive server's response
            # google_fi_register_2_resp = wrappedSocket.recv(65535)
            # print("Received:\n\n{}\n".format(google_fi_register_2_resp.decode()))

            # # parse received message
            # rcs_messages.message_parser(google_fi_register_2_resp.decode())


            # Step 3. send options
            logging.info("========================================================================")
            logging.info("|                  Sending a SIP OPTIONS message and                   |")
            logging.info("|                   expecting a SIP 200 OK response                    |")
            logging.info("========================================================================\n")

            # rcs_messages.message_parser(google_fi_register_2_resp.decode())
            conversation_call_id = uuid.uuid4()
            google_fi_options_1_req = rcs_messages.options(1, conversation_call_id)
            logging.info("Sending:\n\n{}\n".format(google_fi_options_1_req))

        else:
            logging.warning("========================================================================")
            logging.warning("|            Error: No valid nonce found in the response!              |")
            logging.warning("========================================================================\n")
            exit(-2)

    except UnboundLocalError:
        # Socket has not been assigned.
        pass


if __name__ == '__main__':
    try:
        args = Arguments()
        logging.debug(args.port)
        logging.debug(args.realm)
        logging.debug(args.username)
        logging.debug(args.password)
        logging.debug(args.receiver)
        logging.debug(args.imei)
        logging.debug(args.sim_mode)

    except ArgumentsException as e:
        sys.stderr.write("\nERROR: " + str(e) + ".  Use '-h' for info.\n")
        sys.exit(-1)

    main(args)
