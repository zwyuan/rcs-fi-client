import re
import ssl
import sys
import uuid
import time
import socket
import logging
import hashlib
import secrets
import datetime
import requests
import sslkeylog
from argparse import ArgumentParser
from colorlog import ColoredFormatter

import rcs_client_constants as CONST

sslkeylog.set_keylog("sslkeylog-rcs-tls.txt")

# log.basicConfig(stream=sys.stderr, level=CONST.LOG_LEVEL, format=CONST.LOG_FMT)

logging.root.setLevel(CONST.LOG_LEVEL)
formatter = ColoredFormatter(CONST.LOG_FMT)
stream = logging.StreamHandler()
stream.setLevel(CONST.LOG_LEVEL)
stream.setFormatter(formatter)
log = logging.getLogger('pythonConfig')
log.setLevel(CONST.LOG_LEVEL)
log.addHandler(stream)

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

    @staticmethod
    def get_utc_time(time_datetime):
        return time_datetime.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    @staticmethod
    def time_since_1900_sec():
        epoch_time_sec = 2208988800
        return int(time.time()) + epoch_time_sec


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
                log.warning("No SIP realm provided, using default Fi RCS realm.")
                self.realm = CONST.FI_RCS_REALM

            try:
                assert re.match(CONST.REGEX_MSISDN, str(self.username)) is not None
            except AssertionError as ae:
                log.warning("No username provided or illegal format in the username provided.")
                log.warning("Using default username instead.")
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
                log.warning("No receiver provided or illegal format in the receiver provided.")
                log.warning("Using default reciver's MSISDN instead.")
                self.receiver = CONST.DEMO_RECEIVER

        else:
            if not self.password:
                log.warning("No password provided, using default demo password.")
                self.password = CONST.DEMO_SIP_PWD
            else:
                try:
                    assert re.match(CONST.REGEX_SIP_PASSWORD, str(self.password)) is not None
                except AssertionError as ae:
                    log.warning("Illegal character or wrong format in the password provided!")
                    log.warning("Using default demo password: {pwd}".format(pwd = CONST.DEMO_SIP_PWD))
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

    def __init__(self, ip, username, receiver, p_cscf_addr, imei, port=20000, sip_ver=2, transport="tls", max_forwards=70, branch_prefix="z9hG4bK", user_agent=CONST.DEMO_RCS_UA):
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
        # self._supported = supported
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

    def set_to(self, receiver, tag = ""):
        return "To: <tel:{to}>{tag}\r\n".format(to = receiver, tag = tag)
    
    def set_via(self, branch = secrets.token_urlsafe(10)[:10], options=";keep;server-keep;rport"):
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

    def set_accept_contact_invite(self, accept_contact):
        return "Accept-Contact: *;{accept_contact}\r\n".format(accept_contact = accept_contact)

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

    def set_contact_options(self, capability="customized"):
        self._sip_instance_tag = "+sip.instance=\"<urn:gsma:imei:{imei}>\"".format(imei = self._imei)
        return "Contact: <sip:{username}@{ip}:{port};transport={transport}>;{identity};{feature_tags}\r\n".format(
            username = self._username,
            ip = self._ip,
            port = self._port,
            transport = self._transport.lower(),
            identity = self._sip_instance_tag,
            feature_tags = self._build_sip_flags(capability)
            )

    def set_contact_invite(self, feature_tags=";+g.oma.sip-im"):
        self._sip_instance_tag = "+sip.instance=\"<urn:gsma:imei:{imei}>\"".format(imei = self._imei)
        return "Contact: <sip:{username}@{ip}:{port};transport={transport}>;{identity}{feature_tags}\r\n".format(
            username = self._username,
            ip = self._ip,
            port = self._port,
            transport = self._transport.lower(),
            identity = self._sip_instance_tag,
            feature_tags = feature_tags
            )

    def set_accept(self):
        return "Accept: application/sdp\r\n"

    def set_supported(self, supported):
        return "Supported: {supported}\r\n".format(supported = supported)

    def set_session_expires(self, field):
        return "Session-Expires: {val}\r\n".format(val = field)

    def set_content_type(self, c_type):
        return "Content-Type: {val}\r\n".format(val = c_type)

    def set_contribution_id(self, contrib_id):
        return "Contribution-ID: {val}\r\n".format(val = contrib_id)

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
        return "Content-Length: {content_len}\r\n".format(content_len=len)

class SipMessages():
    def __init__(self, username, password, realm, ip, receiver, p_cscf_addr, imei):
        self.username = username
        self.password = password
        self.receiver = receiver
        self.realm = realm
        self.uri = "sip:{}".format(self.realm)
        self.ip = ip
        self.headers = SipHeaders(ip, username, receiver, p_cscf_addr, imei)
        self.status_code = 0
        self.status_code_hldr = {   '200' : self.status_hdlr_200,
                                    '401' : self.status_hdlr_401,
                                    '403' : self.status_hdlr_403,
                                    '480' : self.status_hdlr_480,
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
        self.call_id = ""
        self.contact_ack_route = ""
        self.record_route_lst = []
        self.to_tag = ""
        self.from_tag = ""
        self.delivered = False
        self.displayed = False
        self.needs_ok = False

    def register(self, seq, call_id):
        reg_str = "REGISTER sip:{realm} SIP/2.0\r\n".format(realm = self.realm)
        reg_msg = reg_str   + self.headers.set_call_id(call_id) \
                            + self.headers.set_c_seq(seq, "REGISTER") \
                            + self.headers.set_from("{tag}".format(tag = secrets.token_urlsafe(10)[:10] if seq == 1 else self.from_tag)) \
                            + self.headers.set_to(self.username) \
                            + self.headers.set_via(secrets.token_urlsafe(10)[:10]) \
                            + self.headers.set_max_forwards() \
                            + self.headers.set_contact() \
                            + self.headers.set_supported("path,gruu") \
                            + self.headers.set_p_preferred_identity() \
                            + self.headers.set_user_agent() \
                            + self.headers.set_allow() \
                            + self.headers.set_authorization(self.nonce, self.response) \
                            + self.headers.set_x_google_event_id() \
                            + self.headers.set_p_access_network_info() \
                            + self.headers.set_content_length(0) \
                            + "\r\n"
        return reg_msg

    def options(self, seq, call_id):
        options_str = "OPTIONS tel:{receiver} SIP/2.0\r\n".format(receiver = self.receiver)
        options_msg = options_str + self.headers.set_call_id(call_id) \
                            + self.headers.set_c_seq(seq, "OPTIONS") \
                            + self.headers.set_from(secrets.token_urlsafe(10)[:10]) \
                            + self.headers.set_to(self.receiver) \
                            + self.headers.set_via(secrets.token_urlsafe(10)[:10], "") \
                            + self.headers.set_max_forwards() \
                            + self.headers.set_accept_contact() \
                            + self.headers.set_contact_options() \
                            + self.headers.set_accept() \
                            + self.headers.set_route(self.route_lst) \
                            + self.headers.set_p_preferred_identity() \
                            + self.headers.set_user_agent() \
                            + self.headers.set_allow() \
                            + self.headers.set_x_google_event_id() \
                            + self.headers.set_p_access_network_info() \
                            + self.headers.set_content_length(0) \
                            + "\r\n"
        return options_msg

    def invite(self, seq, call_id, my_ip, msg = "Hello", content_type = "text"):
        boundary    = secrets.token_urlsafe(11)[:11]
        contrib_id  = secrets.token_hex(32)[:32]
        invite_body = self.compose_invite_body(my_ip, msg, boundary, content_type)
        invite_str  = "INVITE tel:{receiver} SIP/2.0\r\n".format(receiver = self.receiver)
        invite_msg  = invite_str + self.headers.set_call_id(call_id) \
                    + self.headers.set_c_seq(seq, "INVITE") \
                    + self.headers.set_from(secrets.token_urlsafe(10)[:10]) \
                    + self.headers.set_to(self.receiver) \
                    + self.headers.set_via(secrets.token_urlsafe(10)[:10], ";keep") \
                    + self.headers.set_max_forwards() \
                    + self.headers.set_contact_invite() \
                    + self.headers.set_route(self.route_lst) \
                    + self.headers.set_p_preferred_identity() \
                    + self.headers.set_user_agent() \
                    + self.headers.set_allow() \
                    + self.headers.set_supported("timer") \
                    + self.headers.set_session_expires("1800;refresher=uac") \
                    + self.headers.set_content_type("multipart/mixed;boundary={}".format(boundary)) \
                    + self.headers.set_contribution_id(contrib_id) \
                    + self.headers.set_accept_contact_invite("+g.oma.sip-im") \
                    + self.headers.set_x_google_event_id() \
                    + self.headers.set_p_access_network_info() \
                    + self.headers.set_content_length(len(invite_body)) \
                    + "\r\n" \
                    + "{invite_body}\r\n".format(invite_body = invite_body)
        # log.debug("Composed INVITE message is:\n\n{}\n".format(invite_msg))
        return invite_msg

    def ok(self, seq, method):
        ok_str  = "SIP/2.0 200 OK \r\n".format(receiver = self.receiver)
        ok_msg  = ok_str + self.headers.set_via(self.from_tag, ";rport={rport};received={recv_ip}".format(rport = self.rport, recv_ip = self.received_ip)) \
                    + self.headers.set_contact_invite() \
                    + self.headers.set_to(self.receiver, ";{}".format(secrets.token_urlsafe(16)[:16])) \
                    + self.headers.set_from(self.from_tag) \
                    + self.headers.set_call_id(self.call_id) \
                    + self.headers.set_c_seq(seq, method) \
                    + self.headers.set_p_asserted_identity("") \
                    + self.headers.set_x_google_event_id() \
                    + self.headers.set_content_length(0)
        # log.debug("Composed OK message is:\n\n{}\n".format(ok_msg))
        return ok_msg

    def ack(self, seq):
        ack_str  = "ACK {contact_ack_route} SIP/2.0\r\n".format(contact_ack_route = self.contact_ack_route)
        ack_msg  = ack_str + self.headers.set_call_id(self.call_id) \
                    + self.headers.set_c_seq(seq, "ACK") \
                    + self.headers.set_from(self.from_tag) \
                    + self.headers.set_to(self.receiver, ";tag={}".format(self.to_tag)) \
                    + self.headers.set_via(secrets.token_urlsafe(10)[:10], "") \
                    + self.headers.set_max_forwards() \
                    + self.headers.set_route(self.record_route_lst) \
                    + self.headers.set_contact_invite("") \
                    + self.headers.set_user_agent() \
                    + self.headers.set_allow() \
                    + self.headers.set_x_google_event_id() \
                    + self.headers.set_content_length(0)

        # log.debug("Composed ACK message is:\n\n{}\n".format(ack_msg))
        return ack_msg

    def compose_invite_body(self, my_ip, msg, boundary="bS5DQx0W7AA", content_type = "text"):
        return "--{boundary}\r\n".format(boundary = boundary) \
                    + "{sdp_msg}\r\n".format(sdp_msg = self.compose_sdp_msg(my_ip)) \
                    + "--{boundary}\r\n".format(boundary = boundary) \
                    + "{cpim_msg}\r\n".format(cpim_msg = self.compose_cpim_msg(msg, content_type)) \
                    + "--{boundary}--\r\n".format(boundary = boundary)

    def compose_rcs_body(self, rcs_type, content):
        if rcs_type == "text":
            return content
        else:
            return ""

    def compose_rcs_msg(self, content_type, content):
        rcs_body = self.compose_rcs_body(content_type, content)
        if content_type == "text":
            rcs_msg = "Content-Length: {length}\r\n".format(length = len(rcs_body)) \
                    + "Content-Type: text/plain; charset=utf-8\r\n" \
                    + "\r\n" \
                    + rcs_body
        elif content_type == "ft_http":
            rcs_msg = "Content-Length: {length}\r\n".format(length = len(content)) \
                    + "Content-Type: application/vnd.gsma.rcs-ft-http+xml; charset=utf-8\r\n" \
                    + "\r\n" \
                    + content
        else:
            rcs_msg = "Content-Length: {length}\r\n".format(length = 12) \
                    + "Content-Type: text/plain; charset=utf-8\r\n" \
                    + "\r\n" \
                    + "Hello World!"
        # log.debug("Composed RCS message is:\n\n{}\n".format(rcs_msg))
        return rcs_msg

    def compose_rcs_ft_body(self, data_url, filename, file_type, file_size, has_thumbnail = True, tb_url = "https://cdn4.iconfinder.com/data/icons/new-google-logo-2015/400/new-google-favicon-512.png", tb_file_type = "image/png", tb_file_size = 17908):
        rcs_ft_xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" \
                    + "<file xmlns=\"urn:gsma:params:xml:ns:rcs:rcs:fthttp\">" \
                    +   "<file-info type=\"thumbnail\">" \
                    +       "<file-size>{tb_file_size}</file-size>".format(tb_file_size = tb_file_size) \
                    +       "<content-type>{tb_file_type}</content-type>".format(tb_file_type = tb_file_type) \
                    +       "<data url=\"{tb_url}\" until=\"{tb_until}\"></data>".format(tb_url = tb_url, tb_until = Utils.get_utc_time(datetime.datetime.utcnow() + datetime.timedelta(days=180))) \
                    +   "</file-info>" \
                    +   "<file-info type=\"file\">" \
                    +       "<file-size>{file_size}</file-size>".format(file_size = file_size) \
                    +       "<file-name>{filename}</file-name>".format(filename = filename) \
                    +       "<content-type>image/jpeg</content-type>" \
                    +       "<data url=\"{data_url}\" branded-url=\"{data_url}\" until=\"{data_until}\"></data>".format(data_url = data_url, data_until = Utils.get_utc_time(datetime.datetime.utcnow() + datetime.timedelta(days=180))) \
                    +   "</file-info>" \
                    + "</file>"

        # log.debug("Composed RCS FT HTTP message is:\n\n{}\n".format(rcs_ft_xml))
        return rcs_ft_xml

    def compose_imdn_msg(self, content = "Ok", content_type = "text"):
        imdn_msg_id = secrets.token_urlsafe(24)[:24]
        rcs_msg     = self.compose_rcs_msg(content_type, content)
        imdn_msg    = "NS: imdn <urn:ietf:params:imdn>\r\n" \
                    + "imdn.Disposition-Notification: positive-delivery, display\r\n" \
                    + "imdn.Message-ID: {msg_id}\r\n".format(msg_id = imdn_msg_id) \
                    + "To: <sip:anonymous@anonymous.invalid>\r\n" \
                    + "From: <sip:anonymous@anonymous.invalid>\r\n" \
                    + "DateTime: {time}\r\n".format(time = Utils.get_utc_time(datetime.datetime.utcnow())) \
                    + "\r\n" \
                    + rcs_msg
        # log.debug("Composed IMDN message is:\n\n{}\n".format(imdn_msg))
        return imdn_msg

    def compose_cpim_msg(self, msg, content_type = "text"):
        imdn_msg = self.compose_imdn_msg(msg, content_type)
        cpim_msg = "Content-Type: message/cpim\r\n" \
                    + "Content-Length: {length}\r\n".format(length = len(imdn_msg)) \
                    + "\r\n" \
                    + imdn_msg
        # log.debug("Composed CPIM message is:\n\n{}\n".format(cpim_msg))
        return cpim_msg

    def compose_sdp_body(self, my_ip):
        sdp_body = "v=0\r\n" \
                + "o={username} {time} {time} IN IP4 {ip}\r\n".format(username = self.username, time = Utils.time_since_1900_sec(), ip = my_ip) \
                + "s=-\r\n" \
                + "c=IN IP4 {ip}\r\n".format(ip = my_ip) \
                + "t=0 0\r\n" \
                + "m=message 9 TCP/TLS/MSRP *\r\n" \
                + "a=path:msrps://{ip}:9/{token};tcp\r\n".format(ip = my_ip, token = secrets.token_hex(32)[:32]) \
                + "a=fingerprint:SHA-1 {fingerprint}\r\n".format(fingerprint = "76:7C:2B:DA:26:8F:CB:25:D6:98:C3:EE:09:66:88:84:C7:BB:82:38") \
                + "a=connection:new\r\n" \
                + "a=setup:active\r\n" \
                + "a=accept-types:{accept_types}\r\n".format(accept_types = "message/cpim application/im-iscomposing+xml") \
                + "a=accept-wrapped-types:{accept_wrapped_types}\r\n".format(accept_wrapped_types = "text/plain application/vnd.gsma.rcs-ft-http+xml message/imdn+xml application/vnd.gsma.rcspushlocation+xml") \
                + "a=sendrecv\r\n"
        return sdp_body

    def compose_sdp_msg(self, my_ip):
        sdp_body = self.compose_sdp_body(my_ip)
        sdp_msg  = self.headers.set_content_type("application/sdp") \
                 + self.headers.set_content_length(len(sdp_body)) \
                 + "\r\n" \
                 + sdp_body
        # log.debug("Composed SDP message is:\n\n{}\n".format(sdp_msg))
        return sdp_msg


    def calculate_response(self):
        self.response = Utils.calc_sip_digest_auth(self.username, self.realm, self.password, self.uri, self.nonce)

    # Some resource maybe worth looking at: https://github.com/racker/python-twisted-core/blob/master/twisted/protocols/sip.py
    def message_parser(self, message):
        msg_split = message.split("\r\n\r\n")
        msg_header = msg_split[0]
        if len(msg_split) > 1:
            msg_body = msg_split[1:]

        log.debug("Split message header:\n\n{}\n".format(msg_header))
        log.debug("Split message body:\n\n{}\n".format(msg_body))

        msg_header_lst = msg_header.split("\r\n")
        log.debug("Found {} lines in total in the message header received.".format(len(msg_header_lst)))
        log.debug("First line in message header:\n{}".format(msg_header_lst[0]))

        if (msg_header_lst[0].startswith("SIP/")):
            try:
                # status_code = msg_header_lst[0].split(" ")[1]
                # print(msg_header_lst)
                # print("trying parser for {}".format(status_code))
                # print(self.status_code_hldr[str(status_code)])
                self.status_code_hldr[msg_header_lst[0].split(" ")[1]](msg_header_lst) # handle 200, 401, 511 SIP response
            except Exception as e:
                log.error("Received a response not in defined handlers!")
                log.error(e)
                self.status_code_hldr['default'](msg_header_lst) # handle other cases
        elif (msg_header_lst[0].startswith("MESSAGE")):
            if "status><delivered" in message:
                self.delivered = True
                log.warning("Received message deliver notification")
            elif "status><displayed" in message:
                self.displayed = True
                log.warning("Received message display notification")
        elif (msg_header_lst[0].startswith("OPTIONS")):
            self.needs_ok = True
            log.warning("Received message display notification")


    def status_hdlr_200(self, msg_header_lst):
        log.debug("Entering status_hdlr_200()")
        self.status_code = 200
        for l in msg_header_lst:
            if l.startswith("Via"):
                self.header_parser_via(l)
            elif l.startswith("Path"):
                self.header_parser_path(l)
            elif l.startswith("Service-Route"):
                self.header_parser_service_route(l)
            elif l.startswith("Record-Route"):
                self.header_parser_record_route(l)
            elif l.startswith("Contact"):
                self.header_parser_contact(l)
            elif l.startswith("To"):
                self.header_parser_to(l)
            elif l.startswith("From"):
                self.header_parser_from(l)
            elif l.startswith("Call-ID"):
                self.header_parser_call_id(l)
            elif l.startswith("Contact"):
                self.header_parser_contact(l)
            elif l.startswith("CSeq"):
                self.header_parser_c_seq(l)
            elif l.startswith("P-Associated-URI"):
                self.header_parser_p_associated_uri(l)
            elif l.startswith("X-Google-Event-Id"):
                self.header_parser_x_google_event_id(l)
            elif l.startswith("Content-Length"):
                self.header_parser_content_length(l)


    def status_hdlr_401(self, msg_header_lst):
        log.debug("Entering status_hdlr_401()")
        self.status_code = 401
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


    def status_hdlr_403(self, msg_header_lst):
        log.debug("Entering status_hdlr_403()")
        self.status_code = 403
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
            elif l.startswith("P-Charging-Vector"):
                self.header_parser_p_charging_vector(l)
            elif l.startswith("X-Google-Event-Id"):
                self.header_parser_x_google_event_id(l)
            elif l.startswith("Content-Length"):
                self.header_parser_content_length(l)


    def status_hdlr_480(self, msg_header_lst):
        log.debug("Entering status_hdlr_480()")
        self.status_code = 480
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
            elif l.startswith("P-Asserted-Identity"):
                self.header_parser_p_associated_identity(l)
            elif l.startswith("X-Google-Event-Id"):
                self.header_parser_x_google_event_id(l)
            elif l.startswith("Content-Length"):
                self.header_parser_content_length(l)


    def status_hdlr_511(self, msg_header_lst):
        log.debug("Entering status_hdlr_511()")
        self.status_code = 511
        pass

    def status_hdlr_default(self, msg_header_lst):
        log.debug("Entering status_hdlr_default()")
        self.status_code = self.status_code = msg_header_lst[0].split(" ")[1]

    def header_parser_via(self, message):
        self.rport = Utils.find_1st_occurrence(r"rport=(\d+);", message)
        self.received_ip = Utils.find_1st_occurrence(r"received=(.*)$", message)
        log.debug(self.rport)
        log.debug(self.received_ip)

    def header_parser_path(self, message):
        self.path = Utils.find_1st_occurrence(r"<(.*)>", message)
        self.path_tag = Utils.find_1st_occurrence(r";(.*)>", message)
        self.route_lst.append("{path};transport={transport}".format(path = self.path, transport = "tls"))
        log.debug(self.path)
        log.debug(self.path_tag)
        log.debug(self.route_lst)

    def header_parser_record_route(self, message):
        # log.debug("Processing found record route:\n\n{}\n".format(message))
        self.record_route_lst.append(Utils.find_1st_occurrence(r"<(.*)>", message))
        log.debug(self.record_route_lst)

    def header_parser_service_route(self, message):
        # log.debug("Processing found service route:\n\n{}\n".format(message))
        self.route_lst.append(Utils.find_1st_occurrence(r"<(.*)>", message))
        log.debug(self.route_lst)

    def header_parser_contact(self, message):
        log.debug("Accepted contact info at server: {}\n".format(message))

    def header_parser_to(self, message):
        self.to_tag = Utils.find_1st_occurrence(r"tag=(.*)$", message)

    def header_parser_from(self, message):
        self.from_tag = Utils.find_1st_occurrence(r"tag=(.*)$", message)

    def header_parser_call_id(self, message):
        self.call_id = Utils.find_1st_occurrence(r"Call-ID:\s(.*?)$", message)
        log.debug(self.call_id)

    def header_parser_contact(self, message):
        self.contact_ack_route = Utils.find_1st_occurrence(r"<(.*?)>", message)
        log.debug(self.contact_ack_route)

    def header_parser_c_seq(self, message):
        pass

    def header_parser_p_associated_uri(self, message):
        self.p_associated_uri = Utils.find_1st_occurrence(r"^<(.*)>", message)
        log.debug(self.p_associated_uri)

    def header_parser_p_associated_identity(self, message):
        pass

    def header_parser_www_auth(self, message):
        self.nonce = Utils.find_1st_occurrence(r"nonce=\"(.*?)\",", message)
        log.debug(self.nonce)
        self.server_nonce = True

    def header_parser_p_charging_vector(self, message):
        self.info(Utils.find_1st_occurrence(r"P-Charging-Vector:\s(.*?)$", message))

    def header_parser_x_google_event_id(self, message):
        pass

    def header_parser_content_length(self, message):
        pass


def main(args):

    log.info("========================================================================")
    log.info("|                    Connecting to RCS ACS server ...                  |")
    log.info("========================================================================\n")

    try:
        # CREATE SOCKET
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)

        # WRAP SOCKET
        wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS, ciphers="ALL") # ssl_version=ssl.PROTOCOL_TLSv1_2

        # CONNECT AND PRINT REPLY
        try:
            wrappedSocket.connect((args.realm, args.port))
            log.info("========================================================================")
            log.info("|       Connected to RCS ACS server at {}       |".format(args.realm))
            log.info("========================================================================\n")
        except:
            log.info("========================================================================")
            log.info("|             Error: Cannot connect to given RCS ACS server!           |")
            log.info("========================================================================\n")

            # Regardless of what happened, try to gracefully close down the socket.
            # CLOSE SOCKET CONNECTION
            wrappedSocket.close()
            exit(-1)

        log.info("========================================================================")
        log.info("|                        Preparing SIP Messages ...                    |")
        log.info("========================================================================\n")
        my_ip = Utils.get_ip_address_from_socket(wrappedSocket)
        rcs_messages = SipMessages(args.username, args.password, args.realm, my_ip, args.receiver, args.realm, args.imei)

        # Step 1. Send a SIP REGISTER message and get 401 Unauthorized response
        log.info("========================================================================")
        log.info("|                  Sending a SIP REGISTER message and                  |")
        log.info("|                 expecting a 401 Unauthorized response                |")
        log.info("========================================================================\n")
        # google_fi_register_1_req  = rcs_messages.register(1, "23099613-21b1-4565-902f-0001f4b4b99d", "", "")
        reg_call_id = uuid.uuid4()
        google_fi_register_1_req = rcs_messages.register(1, reg_call_id)
        log.info("Sending:\n\n{}\n".format(google_fi_register_1_req))

        if not args.sim_mode:
            # send message (encoded into bytes) through socket
            wrappedSocket.send(google_fi_register_1_req.encode())
            rcs_messages.status_code = 0

            # receive server's response
            google_fi_register_1_resp = wrappedSocket.recv(65535)
            log.info("Received:\n\n{}\n".format(google_fi_register_1_resp.decode()))
        else:
            google_fi_register_1_resp = CONST.GOOGLE_FI_REGISTER_1_RESP.encode()

        # parse received message
        rcs_messages.message_parser(google_fi_register_1_resp.decode())

        # check nonce received
        if rcs_messages.server_nonce is True:
            rcs_messages.calculate_response()

            # Step 2. Send authenticated register message
            log.info("========================================================================")
            log.info("|                Sending the 2nd SIP REGISTER message                  |")
            log.info("|                 with response calculated from nonce                  |")
            log.info("========================================================================\n")
            log.info("Formating 2nd REGISTER with nonce and response")

            google_fi_register_2_req = rcs_messages.register(2, reg_call_id)
            log.info("Sending:\n\n{}\n".format(google_fi_register_2_req))

            if not args.sim_mode:
                # send message (encoded into bytes) through socket
                wrappedSocket.send(google_fi_register_2_req.encode())
                rcs_messages.status_code = 0

                # receive server's response
                google_fi_register_2_resp = wrappedSocket.recv(65535)
                log.info("Received:\n\n{}\n".format(google_fi_register_2_resp.decode()))

            else:
                google_fi_register_2_resp = CONST.GOOGLE_FI_REGISTER_2_RESP.encode()

            # parse received message
            rcs_messages.message_parser(google_fi_register_2_resp.decode())


            # Step 3. send options
            log.info("========================================================================")
            log.info("|                  Sending a SIP OPTIONS message and                   |")
            log.info("|                   expecting a SIP 200 OK response                    |")
            log.info("========================================================================\n")

            # rcs_messages.message_parser(google_fi_register_2_resp.decode())
            conversation_call_id = uuid.uuid4()
            google_fi_options_1_req = rcs_messages.options(1, conversation_call_id)
            log.info("Sending:\n\n{}\n".format(google_fi_options_1_req))

            if not args.sim_mode:
                # send message (encoded into bytes) through socket
                wrappedSocket.send(google_fi_options_1_req.encode())
                rcs_messages.status_code = 0
                rcs_messages.delivered = False
                rcs_messages.displayed = False

                # receive server's response
                google_fi_options_1_resp = wrappedSocket.recv(65535)
                log.info("Received:\n\n{}\n".format(google_fi_options_1_resp.decode()))

            else:
                google_fi_options_1_resp = CONST.GOOGLE_FI_OPTIONS_1_RESP.encode()

            # parse received message
            rcs_messages.message_parser(google_fi_options_1_resp.decode())

            while rcs_messages.status_code == 0:
                google_fi_options_1_resp = wrappedSocket.recv(65535)
                log.info("Received:\n\n{}\n".format(google_fi_options_1_resp.decode()))
                rcs_messages.message_parser(google_fi_options_1_resp.decode())

            # expecting a 200 OK message
            if rcs_messages.status_code == 200:
                log.info("========================================================================")
                log.info("|                     Received SIP 200 OK and sending                  |")
                log.info("|                           a SIP INVITE message                       |")
                log.info("========================================================================\n")

                # Step 4. send SIP INVITE
                log.info("========================================================================")
                log.info("|                       Sending a SIP INVITE message                   |")
                log.info("|                 piggybacking the first SIP text message              |")
                log.info("========================================================================\n")
                
                # google_fi_rcs_ft_http_msg = rcs_messages.compose_rcs_ft_body("https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png", "googlelogo_color_272x92dp.png", "image/png", 5969)
                google_fi_rcs_ft_http_msg = rcs_messages.compose_rcs_ft_body("https://i.pinimg.com/originals/5f/72/8d/5f728ddcadd9249142996433bbdebcab.jpg", "5f728ddcadd9249142996433bbdebcab.jpg", "image/jpeg", 194137)
                # google_fi_invite_1_req = rcs_messages.invite(1, conversation_call_id, Utils.get_ip_address_from_socket(wrappedSocket), "Greetings from your hacker!")
                google_fi_invite_1_req = rcs_messages.invite(1, conversation_call_id, Utils.get_ip_address_from_socket(wrappedSocket), google_fi_rcs_ft_http_msg, "ft_http")
                log.info("Sending:\n\n{}\n".format(google_fi_invite_1_req))

                if not args.sim_mode:
                    # send message (encoded into bytes) through socket
                    wrappedSocket.send(google_fi_invite_1_req.encode())
                    rcs_messages.status_code = 0
                    rcs_messages.delivered = False
                    rcs_messages.displayed = False

                    # receive server's response
                    google_fi_invite_1_resp = wrappedSocket.recv(65535)
                    log.info("Received:\n\n{}\n".format(google_fi_invite_1_resp.decode()))

                else:
                    google_fi_invite_1_resp = CONST.GOOGLE_FI_INVITE_1_RESP.encode()

                # parse received message
                rcs_messages.message_parser(google_fi_invite_1_resp.decode())

                while rcs_messages.status_code == 0:
                    if rcs_messages.needs_ok == True:
                        google_fi_ok_1_req = rcs_messages.ok(1, "OPTIONS")
                        log.info("Sending:\n\n{}\n".format(google_fi_ok_1_req))
                        rcs_messages.status_code = 0
                        rcs_messages.delivered = False
                        rcs_messages.displayed = False
                        rcs_messages.needs_ok = False
                        google_fi_ok_1_resp = wrappedSocket.recv(65535)
                        log.info("Received:\n\n{}\n".format(google_fi_ok_1_resp.decode()))
                    else:
                        google_fi_invite_1_resp = wrappedSocket.recv(65535)
                        log.info("Received:\n\n{}\n".format(google_fi_options_1_resp.decode()))
                        rcs_messages.message_parser(google_fi_invite_1_resp.decode())

                # expecting a 200 OK message
                if rcs_messages.status_code == 200:
                    # Step 5. send SIP ACK
                    log.info("========================================================================")
                    log.info("|                        Received SIP 200 OK and                       |")
                    log.info("|                       sending a SIP ACK message                      |")
                    log.info("========================================================================\n")

                    google_fi_ack_1_req = rcs_messages.ack(1)
                    log.info("Sending:\n\n{}\n".format(google_fi_ack_1_req))

                    if not args.sim_mode:
                        # send message (encoded into bytes) through socket
                        wrappedSocket.send(google_fi_ack_1_req.encode())
                        rcs_messages.status_code = 0
                        rcs_messages.delivered = False
                        rcs_messages.displayed = False

                        # do not expect further Ack on ack
                        try:
                            google_fi_ack_1_resp = wrappedSocket.recv(65535)
                            log.info("Received:\n\n{}\n".format(google_fi_ack_1_resp.decode()))
                            while rcs_messages.status_code == 0:
                                if rcs_messages.needs_ok == True:
                                    google_fi_ok_1_req = rcs_messages.ok(1, "OPTIONS")
                                    log.info("Sending:\n\n{}\n".format(google_fi_ok_1_req))
                                    rcs_messages.status_code = 0
                                    rcs_messages.delivered = False
                                    rcs_messages.displayed = False
                                    rcs_messages.needs_ok = False
                                    google_fi_ok_1_resp = wrappedSocket.recv(65535)
                                    log.info("Received:\n\n{}\n".format(google_fi_ok_1_resp.decode()))
                                else:
                                    google_fi_ack_1_resp = wrappedSocket.recv(65535)
                                    log.info("Received:\n\n{}\n".format(google_fi_ack_1_resp.decode()))
                                    rcs_messages.message_parser(google_fi_ack_1_resp.decode())
                        except:
                            pass

                    # Step 6. sending a 2nd SIP message
                    log.info("========================================================================")
                    log.info("|                   Sending a second SIP text message                  |")
                    log.info("========================================================================\n")
                    google_fi_imdn_2_text_req = rcs_messages.compose_imdn_msg("And this is my 2nd test message", "text")
                    log.info("Sending:\n\n{}\n".format(google_fi_imdn_2_text_req))

                    if not args.sim_mode:
                        # send message (encoded into bytes) through socket
                        wrappedSocket.send(google_fi_imdn_2_text_req.encode())
                        rcs_messages.status_code = 0
                        rcs_messages.delivered = False
                        rcs_messages.displayed = False

                        # do not expect further ack
                        try:
                            google_fi_imdn_2_text_resp = wrappedSocket.recv(65535)
                            log.info("Received:\n\n{}\n".format(google_fi_imdn_2_text_resp.decode()))
                            while rcs_messages.status_code == 0:
                                if rcs_messages.needs_ok == True:
                                    google_fi_ok_1_req = rcs_messages.ok(1, "OPTIONS")
                                    log.info("Sending:\n\n{}\n".format(google_fi_ok_1_req))
                                    rcs_messages.status_code = 0
                                    rcs_messages.delivered = False
                                    rcs_messages.displayed = False
                                    rcs_messages.needs_ok = False
                                    google_fi_ok_1_resp = wrappedSocket.recv(65535)
                                    log.info("Received:\n\n{}\n".format(google_fi_ok_1_resp.decode()))
                                else:
                                    google_fi_imdn_2_text_resp = wrappedSocket.recv(65535)
                                    log.info("Received:\n\n{}\n".format(google_fi_imdn_2_text_resp.decode()))
                                    rcs_messages.message_parser(google_fi_imdn_2_text_resp.decode())

                        except:
                            pass


                    # Step 7. sending a SIP FT HTTP message for file
                    log.info("========================================================================")
                    log.info("|                   Sending a FT HTTP message for file                 |")
                    log.info("========================================================================\n")
                    google_fi_rcs_ft_http_msg = rcs_messages.compose_rcs_ft_body("https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png", "googlelogo_color_272x92dp.png", "image/png", 5969)
                    google_fi_imdn_3_ft_req = rcs_messages.compose_imdn_msg(google_fi_rcs_ft_http_msg, "ft_http")
                    log.info("Sending:\n\n{}\n".format(google_fi_imdn_3_ft_req))

                    if not args.sim_mode:
                        # send message (encoded into bytes) through socket
                        wrappedSocket.send(google_fi_imdn_3_ft_req.encode())
                        rcs_messages.status_code = 0
                        rcs_messages.delivered = False
                        rcs_messages.displayed = False
                        # do not expect further ack
                        try:
                            google_fi_imdn_3_ft_resp = wrappedSocket.recv(65535)
                            log.info("Received:\n\n{}\n".format(google_fi_imdn_3_ft_resp.decode()))
                            while rcs_messages.status_code == 0:
                                google_fi_imdn_3_ft_resp = wrappedSocket.recv(65535)
                                log.info("Received:\n\n{}\n".format(google_fi_imdn_3_ft_resp.decode()))
                                rcs_messages.message_parser(google_fi_imdn_3_ft_resp.decode())
                        except:
                            pass

                else:
                    log.warning("========================================================================")
                    log.warning("|                     Error: SIP {} received!                    |".format(rcs_messages.status_code))
                    log.warning("========================================================================\n")

            else:
                log.warning("========================================================================")
                log.warning("|                     Error: SIP {} received!                    |".format(rcs_messages.status_code))
                log.warning("========================================================================\n")



        else:
            log.warning("========================================================================")
            log.warning("|            Error: No valid nonce found in the response!              |")
            log.warning("========================================================================\n")
            exit(-2)

    except UnboundLocalError:
        # Socket has not been assigned.
        pass


if __name__ == '__main__':
    try:
        args = Arguments()
        log.debug(args.port)
        log.debug(args.realm)
        log.debug(args.username)
        log.debug(args.password)
        log.debug(args.receiver)
        log.debug(args.imei)
        log.debug(args.sim_mode)

    except ArgumentsException as e:
        sys.stderr.write("\nERROR: " + str(e) + ".  Use '-h' for info.\n")
        sys.exit(-1)

    main(args)
