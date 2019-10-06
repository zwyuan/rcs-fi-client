import re
import ssl
import uuid
import socket
import hashlib
import secrets
import requests
import sslkeylog
from argparse import ArgumentParser

sslkeylog.set_keylog("sslkeylog-rcs-tls.txt")

regex_msisdn = r"^\+(9[976]\d|8[987530]\d|6[987]\d|5[90]\d|42\d|3[875]\d|2[98654321]\d|9[8543210]|8[6421]|6[6543210]|5[87654321]|4[987654310]|3[9643210]|2[70]|7|1)\d{1,14}$"


uri = "sip:us.pfi.rcs.telephony.goog"
realm = "us.pfi.rcs.telephony.goog"

HOST = "us.pfi.rcs.telephony.goog"
PORT = 443

user_agent = "IM-client/OMA1.0 Google/Pixel_2-9 Google/c24v0v014-27.0"
rand_tag = secrets.token_urlsafe(10)
rand_branch = secrets.token_urlsafe(17)

host = "acs-hov.jibe.google.com"
accept_encoding = "gzip"
connection = "Keep-Alive"
req_url = "https://acs-hov.jibe.google.com/"

BLACKBIRD_FULLY_INTEGRATED_MESSAGING_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.joyn.intmsg"
CPM_MSG = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg"
CPM_SESSION = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"
JIBE_STICKERS_CAPABILITY = "+g.jibe.stickers"
MMTEL_VOICECALLING_CAPABILITY = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
RBM_BOT_VERSION_PAYMENTS_V1 = "#=1.1"
RBM_BOT_VERSION_RICH_CARD = "#=0.91"
RBM_BOT_VERSION_RICH_CARD_CAROUSELS = "#=0.92"
RBM_BOT_VERSION_UP2 = "#=1"
RCSE_CAPABILITY_PRESENCE_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp"
RCSE_FILETRANSFER_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.ft"
RCSE_IMAGE_SHARE_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-is"
RCSE_SOCIAL_PRESENCE_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.sp"
RCSE_VIDEO_SHARE_CAPABILITY = "+g.3gpp.cs-voice"
RCS_FILETRANSFER_THUMBNAIL_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftthumb"
RCS_FILE_TRANSFER_VIA_SMS_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms"
RCS_GROUP_CHAT_CAPABILITY = "isfocus"
RCS_IPCALLING_CAPABILITY = "+g.gsma.rcs.ipcall"
RCS_LOCATION_PULL_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopull"
RCS_LOCATION_PULL_FT_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopullft"
RCS_LOCATION_PUSH_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush"
RCS_LOCATION_VIA_SMS_CAPABILITY = "urn%3Aurn-7%3A3gppapplication.ims.iari.rcs.geosms"
RCS_MESSAGE_REVOKE_CAPABILITY = "+g.gsma.rcs.msgrevoke"
RCS_POST_CALL_CAPABILITY = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.callunanswered"
RCS_RBM_BOT_CAPABILITY = "+g.gsma.rcs.isbot"
RCS_RBM_CAPABILITY = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot"
RCS_SHARED_MAP_CAPABILITY = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.sharedmap"
RCS_SHARED_SKETCH_CAPABILITY = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.sharedsketch"
RCS_VIDEOCALLINGONLY_CAPABILITY = "+g.gsma.rcs.ipvideocallonly"
# RBM_BOT_THREE_VERSIONS_TAG_FORMAT = "+g.gsma.rcs.botversion=\"%s,%s,%s\""
# RBM_BOT_TWO_VERSIONS_TAG_FORMAT = "+g.gsma.rcs.botversion=\"%s,%s\""


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
        # self.validate()

    def parse_args(self):
        # Parse the supplied arguments and map each one to an attribute on
        # the Argument object.
        for k, v in self.parser.parse_args().__dict__.items():
            setattr(self, k, v)

    def validate(self):
        pass
    #     if self.tcp and self.udp:
    #         raise ArgumentsException("Please specify only one of TCP or UDP")

    #     if not self.input_file:
    #         raise ArgumentsException("Please specify an input file with '-f'")

    #     if not self.dest_addr:
    #         raise ArgumentsException("Please specify a destination with '-d'")

    def add_arguments(self):
        # self.parser.add_argument('-f',
        #                          '--input_file',
        #                          dest='input_file',
        #                          default=None,
        #                          help='*Required - Input file')
        # self.parser.add_argument('-r',
        #                          '--reg',
        #                          dest='register',
        #                          action='store_true',
        #                          default=False,
        #                          help='Register for OTP')

        self.parser.add_argument('-u',
                                 '--username',
                                 dest='username',
                                 default="+11234567890",
                                 # action='store_true',
                                 help='Username (in MSISDN format) for SIP')

        self.parser.add_argument('-p',
                                 '--pwd',
                                 dest='password',
                                 default=None,
                                 # action='store_true',
                                 help='Auth Password for SIP')

        self.parser.add_argument('-r',
                                 '--receiver',
                                 dest='receiver',
                                 default="+19876543210",
                                 # action='store_true',
                                 help='Receiver number (in MSISDN format) for SIP conversation')

        self.parser.add_argument('--imei',
                                 dest='imei',
                                 default="12345678-12345-0",
                                 # action='store_true',
                                 help='IMEI of the device')

        self.parser.add_argument('-t',
                                 '--transport',
                                 dest='trans_proto',
                                 default="tls",
                                 # action='store_true',
                                 help='Transport protocol to use for SIP')


class SipHeaders():

    def __init__(self, ip, username, receiver, p_cscf_addr, imei, port=20000, sip_ver=2, transport="tls", max_forwards=70, supported="path,gruu", branch_prefix="z9hG4bK", user_agent="IM-client/OMA1.0 Google/Pixel_2-9 Google/c24v0v014-27.0"):
        self._ip = ip
        self._port = port
        self._username = username
        self._receiver = receiver
        self._p_cscf_addr = p_cscf_addr
        self._imei = imei
        self._user_agent = user_agent
        self._max_forwards = max_forwards
        self._branch_prefix = branch_prefix
        self._supported = supported
        self._authorization = "Digest"
        self._allow_methods = "INVITE, ACK, BYE, CANCEL, NOTIFY, OPTIONS, MESSAGE"
        self._p_access_network_info = "IEEE-802.11;i-wlan-node-id=000000000000"

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
        self._rcs_flag_weight_flag = "expires=600000;q=0.5"

        self._rcs_icsi_tag_standalone_messaging = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.deferred"
        self._rcs_icsi_tag_chat_oma_cpm = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"
        self._rcs_icsi_tag_callcomposer = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.callcomposer"
        self._rcs_icsi_tag_postcall = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.callunanswered"
        self._rcs_icsi_tag_sharedmap = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.sharedmap"
        self._rcs_icsi_tag_sharedsketch = "urn%3Aurn-7%3A3gpp-service.ims.icsi.gsma.sharedsketch"
        self._rcs_icsi_tag_ipcall = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

        self._rcs_iari_tag_chat_oma_simple_im = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im"
        self._rcs_iari_tag_fthttp = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp"
        self._rcs_iari_tag_ftsms = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms"
        self._rcs_iari_tag_geopush = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush"
        self._rcs_iari_tag_geosms = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms"
        self._rcs_iari_tag_chatbot = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot"
        self._rcs_iari_tag_chatbot_standalone_msg = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa"
        self._rcs_iari_tag_plugin_support = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.plugin"

        if capability == "simple-im|chat|geopush|fthttp|chatbot":
            return "{};{}=\"{},{},{},{}\";{};{}".format(
                self._rcs_chat_oma_simple_im_flag,
                self._rcs_iari_flag_prefix,
                self._rcs_iari_tag_chat_oma_simple_im,
                self._rcs_iari_tag_geopush,
                self._rcs_iari_tag_fthttp,
                self._rcs_iari_tag_chatbot,
                self._rcs_chatbot_version_flag,
                self._rcs_flag_weight_flag
                )
        else: # [TODO] Zengwen: change to other real values
            return "{};{}=\"{},{},{},{}\";{};{}".format(
                self._rcs_chat_oma_simple_im_flag,
                self._rcs_iari_flag_prefix,
                self._rcs_iari_tag_chat_oma_simple_im,
                self._rcs_iari_tag_geopush,
                self._rcs_iari_tag_fthttp,
                self._rcs_iari_tag_chatbot,
                self._rcs_chatbot_version_flag,
                self._rcs_flag_weight_flag
                )

    def set_call_id(self, call_id):
        return "Call-Id: {id}\r\n".format(id = call_id)

    def set_c_seq(self, c_seq, method):
        return "CSeq: {c_seq} {method}\r\n".format(c_seq = c_seq, method = method)

    def set_from(self, tag = uuid.uuid4()):
        return "From: <tel:{username}>;tag={tag}\r\n".format(username = self._username, tag = tag)

    def set_to(self, receiver):
        return "To: <tel:{to}>\r\n".format(to = receiver)
    
    def set_via(self, branch = secrets.token_urlsafe(10), options="keep;server-keep;rport"):
        return "Via: SIP/{sip_ver}/{transport} {ip}:{port};branch={branch_prefix}{branch};{options}\r\n".format(
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

    def set_contact(self, capability="simple-im|chat|geopush|fthttp|chatbot"):
        self._sip_instance_tag = "+sip.instance=\"<urn:gsma:imei:{imei}>\"".format(imei = self._imei)
        return "Contact: <sip:{username}@{ip}:{port};transport={transport}>;{identity};{feature_tags}\r\n".format(
            username = self._username,
            ip = self._ip,
            port = self._port,
            transport = self._transport.lower(),
            identity = self._sip_instance_tag,
            feature_tags = self._build_sip_flags(capability)
            )

    def set_supported(self):
        return "Supported: {supported}\r\n".format(supported = self._supported)

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

    def calculate_response(self):
        self.response = Utils.calc_sip_digest_auth(self.username, self.realm, self.password, self.uri, self.nonce)

    # Some resource maybe worth looking at: https://github.com/racker/python-twisted-core/blob/master/twisted/protocols/sip.py
    def message_parser(self, message):
        msg_split = message.split("\r\n\r\n")
        msg_header = msg_split[0]
        if len(msg_split) > 1:
            msg_body = msg_split[1]

        print("[debug]", "Split message header:\n\n{}\n".format(msg_header))
        print("[debug]", "Split message body:\n\n{}\n".format(msg_body))

        msg_header_lst = msg_header.split("\r\n")
        print("[debug]", "Found {} lines in total in the message header received.".format(len(msg_header_lst)))
        print("[debug]", "First line in message header:\n{}".format(msg_header_lst[0]))

        if (msg_header_lst[0].startswith("SIP/")):
            try:
                # status_code = msg_header_lst[0].split(" ")[1]
                # print(msg_header_lst)
                # print("trying parser for {}".format(status_code))
                # print(self.status_code_hldr[str(status_code)])
                self.status_code_hldr[msg_header_lst[0].split(" ")[1]](msg_header_lst) # handle 200, 401, 511 SIP response
            except Exception as e:
                print(e)
                self.status_code_hldr['default']() # handle other cases


    def status_hdlr_200(self, msg_header_lst):
        print("[debug]", "Entering status_hdlr_200()")
        for l in msg_header_lst:
            # print("[header line]: {}".format(l))
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

    def status_hdlr_401(self, msg_header_lst):
        print("[debug]", "Entering status_hdlr_401()")
        for l in msg_header_lst:
            # print("[header line]: {}".format(l))
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


    def status_hdlr_511(self, msg_header_lst):
        print("[debug]", "Entering status_hdlr_511()")
        pass

    def status_hdlr_default(self, msg_header_lst):
        print("[debug]", "Entering status_hdlr_default()")
        pass

    def header_parser_via(self, message):
        self.rport = Utils.find_1st_occurrence(r"rport=(\d+);", message)
        self.received_ip = Utils.find_1st_occurrence(r"received=(.*)$", message)
        print("[debug]", self.rport)
        print("[debug]", self.received_ip)
        pass

    def header_parser_path(self, message):
        self.path = Utils.find_1st_occurrence(r"^<(.*)>", message)
        self.path_tag = Utils.find_1st_occurrence(r"^;(.*)>", message)
        self.route_lst.append("{path};transport={transport}".format(path = self.path, transport = "tls"))
        print("[debug]", self.path)
        print("[debug]", self.path_tag)
        print("[debug]", self.route_lst)

    def header_parser_service_route(self, message):
        self.route_lst.append(Utils.find_1st_occurrence(r"^<(.*)>", message))
        print("[debug]", self.route_lst)

    def header_parser_contact(self, message):
        print("[debug]", "Accepted contact info at server:\n", message)
        pass

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
        print(self.p_associated_uri)

    def header_parser_www_auth(self, message):
        self.nonce = Utils.find_1st_occurrence(r"nonce=\"(.*?)\",", message)
        print(self.nonce)
        self.server_nonce = True

    def header_parser_x_google_event_id(self, message):
        pass

    def header_parser_content_length(self, message):
        pass


def main(args):

    print("========================================================================")
    print("|                    Connecting to RCS ACS server ...                  |")
    print("========================================================================\n")

    try:
        # CREATE SOCKET
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)

        # WRAP SOCKET
        wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS, ciphers="ALL") # ssl_version=ssl.PROTOCOL_TLSv1_2

        # CONNECT AND PRINT REPLY
        try:
            wrappedSocket.connect((HOST, PORT))
            print("========================================================================")
            print("|       Connected to RCS ACS server at {}       |".format(HOST))
            print("========================================================================\n")
        except:
            print("========================================================================")
            print("|             Error: Cannot connect to given RCS ACS server!           |")
            print("========================================================================\n")

            # Regardless of what happened, try to gracefully close down the socket.
            # CLOSE SOCKET CONNECTION
            wrappedSocket.close()
            exit(-1)

        print("========================================================================")
        print("|                        Preparing SIP Messages ...                    |")
        print("========================================================================\n")
        my_ip = Utils.get_ip_address_from_socket(wrappedSocket)
        rcs_messages = SipMessages(args.username, args.password, realm, my_ip, args.receiver, realm, args.imei)

        # Step 1. Send a SIP REGISTER message and get 401 Unauthorized response
        print("========================================================================")
        print("|                  Sending a SIP REGISTER message and                  |")
        print("|                 expecting a 401 Unauthorized response                |")
        print("========================================================================\n")
        # google_fi_register_1_req  = rcs_messages.register(1, "23099613-21b1-4565-902f-0001f4b4b99d", "", "")
        reg_call_id = uuid.uuid4()
        google_fi_register_1_req = rcs_messages.register(1, reg_call_id)
        print("Sending:\n\n{}\n".format(google_fi_register_1_req))

        # send message (encoded into bytes) through socket
        wrappedSocket.send(google_fi_register_1_req.encode())

        # receive server's response
        google_fi_register_1_resp = wrappedSocket.recv(65535)
        print("Received:\n\n{}\n".format(google_fi_register_1_resp.decode()))

        # parse received message
        rcs_messages.message_parser(google_fi_register_1_resp.decode())

        # check nonce received
        if rcs_messages.server_nonce is True:
            rcs_messages.calculate_response()

            # Step 2. Send authenticated register message
            print("========================================================================")
            print("|                Sending the 2nd SIP REGISTER message                  |")
            print("|                 with response calculated from nonce                  |")
            print("========================================================================\n")
            print("Formating 2nd REGISTER with nonce and response")

            google_fi_register_2_req = rcs_messages.register(2, reg_call_id)
            print("Sending:\n\n{}\n".format(google_fi_register_2_req))

            # send message (encoded into bytes) through socket
            # wrappedSocket.send(google_fi_register_2_req.encode())

            # # receive server's response
            # google_fi_register_2_resp = wrappedSocket.recv(65535)
            # print("Received:\n\n{}\n".format(google_fi_register_2_resp.decode()))

            # # parse received message
            # rcs_messages.message_parser(google_fi_register_2_resp.decode())


            # Step 3. send options
            print("========================================================================")
            print("|                  Sending a SIP OPTIONS message and                   |")
            print("|                   expecting a SIP 200 OK response                    |")
            print("========================================================================\n")

            rcs_messages.message_parser(google_fi_register_2_resp.decode())

            regex_sip_route = r"Service-Route:\s+(.*)$"
            sip_route_ret = Utils.find_all_occurrence(regex_sip_route, google_fi_register_2_resp)
            route = ",".join(r for r in sip_route_ret)

        else:
            print("========================================================================")
            print("|            Error: No valid nonce found in the response!              |")
            print("========================================================================\n")
            exit(-2)

    except UnboundLocalError:
        # Socket has not been assigned.
        pass



def args_handler(args):
    try:
        assert re.match(r"^[a-zA-Z0-9_-]{32}$", str(args.password)) is not None
    except AssertionError as ae:
        print("Illegal character or wrong length in the password provided!")
        print("Using toy password instead.")
        args.password = "H6GdpXDZSC7pg7zOMBgspQjxyWmghI4k"

    try:
        assert re.match(regex_msisdn, str(args.username)) is not None
    except AssertionError as ae:
        print("No username provided or illegal format in the username provided.")
        print("Using toy username instead.")
        args.username = "+11234567890"

    try:
        assert re.match(regex_msisdn, str(args.receiver)) is not None
    except AssertionError as ae:
        print("No receiver provided or illegal format in the receiver provided.")
        print("Using toy username instead.")
        args.receiver = "+19876543210"

    try:
        # assert re.match(regex_imei, str(args.imei)) is not None
        assert str(args.imei) is not ""
    except AssertionError as ae:
        print("No username provided or illegal format in the username provided.")
        print("Using toy username instead.")
        args.imei = "12345678-12345-0"



if __name__ == '__main__':
    try:
        args = Arguments()
        args_handler(args)
        print(args.password)

    except ArgumentsException as e:
        sys.stderr.write("\nERROR: " + str(e) + ".  Use '-h' for info.\n")
        sys.exit(-1)

    main(args)
