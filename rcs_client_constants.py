#!/usr/bin/env python3
# encoding: utf-8
"""
Constants.py
"""

# Use python logging library for better logging control
import logging
# LOG_FMT       = '[%(levelname)s] %(message)s'
LOG_FMT       = "%(log_color)s[%(levelname)s]%(reset)s | %(log_color)s%(message)s%(reset)s"
LOG_LEVEL     = logging.DEBUG

# Switch for using simulation mode or not
SIM_MODE      = False

# Simulation mode
DEMO_USERNAME = "+11234567890"
DEMO_RECEIVER = "+19876543210"
DEMO_IMEI     = "12345678-123456-0"
DEMO_SIP_PWD  = "H6GdpXDZSC7pg7zOMBgspQjxyWmghI4k"
DEMO_RCS_UA   = "IM-client/OMA1.0 Google/Pixel_2-9 Google/c24v0v014-27.0"

FI_RCS_REALM  = "us.pfi.rcs.telephony.goog"
SIM_RCS_REALM = "www.google.com"

FI_RCS_PORT   = 443

# Regex patterns
REGEX_SIP_PASSWORD = r"^[a-zA-Z0-9_-]{32}$"
REGEX_MSISDN = r"^\+(9[976]\d|8[987530]\d|6[987]\d|5[90]\d|42\d|3[875]\d|2[98654321]\d|9[8543210]|8[6421]|6[6543210]|5[87654321]|4[987654310]|3[9643210]|2[70]|7|1)\d{1,14}$"


# RCS feature tags and capability
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


# Pre-recorded responses

GOOGLE_FI_REGISTER_1_RESP = """SIP/2.0 401 Unauthorized
Via: SIP/2.0/TLS 1.2.3.4:20000;branch=z9hG4bKGGGGGHdyjGGGGG;keep;server-keep;rport=40216;received=11.22.33.44
To: <tel:+11234567890>;tag=1bggggg9
From: <tel:+11234567890>;tag=lNfGGGGGVGGGGG
Call-ID: 7ggggge3-8cd0-4c26-9757-28gggggd30e0
CSeq: 1 REGISTER
WWW-Authenticate: Digest nonce="vsyGGGGGcKZZsGGGGGPB+Q==",algorithm=MD5,realm="us.pfi.rcs.telephony.goog"
X-Google-Event-Id: LGGGGGIABWCDGGGGGBEGGGGGPA======
Content-Length: 0\n\n
""".replace("\n", "\r\n")


GOOGLE_FI_REGISTER_2_RESP = """SIP/2.0 200 OK
Via: SIP/2.0/TLS 1.2.3.4:20000;branch=z9hG4bGGGGGx0W1AA;rport=24041;server-keep=210;keep=240;received=11.22.33.44
Path: <sip:216.239.36.131:443;lr>
Service-Route: <sip:ABAIGGPMEW7FSMSU6VYUGGGGG4KOCNNS7EGSFL5GUGQ4GGGGGPUD6DGD3X2H7PU:5060;uri-econt=D6KGGGGG6WATERZLA7BE5LGGGGGEA;lr>
Service-Route: <sip:AAQFKG4GGGGO5VATHF4UGGCDGGGGGBL3HN3GGGGGYKFJTAQ7ACGGGGGHYBN2B3Q:5060;lr;transport=udp;uri-econt=HIWGGGGGIGBC2USGGGGGFWT3NMZ35STGVTGGGGG4OR5VERFHTI2ATGGGGGPOTXCQ>
Contact: <sip:+11234567890@1.2.3.4:20000;transport=tls>;q=0.5;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot";+g.gsma.rcs.botversion="#=0.92,#=1";expires=2997;+sip.instance="<urn:gsma:imei:12345678-123456-0>";+g.oma.sip-im
To: <tel:+11234567890>;tag=e2fagggggdggggbb
From: <tel:+11234567890>;tag=GGGGG0WzAA
Call-ID: 2ggggg13-21b1-4565-902f-000gggggb99d
CSeq: 2 REGISTER
P-Associated-URI: <tel:+11234567890>
X-Google-Event-Id: LVGGGGGAB45LCCSGGGGGSC2X2I======
Content-Length: 0\n\n
""".replace("\n", "\r\n")


GOOGLE_FI_OPTIONS_1_RESP = """SIP/2.0 200 OK
Via: SIP/2.0/TLS 1.2.3.4:20000;branch=z9hG4bgggggx0W3AA;rport=24041;received=11.22.33.44
Contact: <sip:AAGGGGGSDGGGGGNDPGGGGGDSGGGGGUHGGGGGUZHDIGGGGG2L4GGGGGVZJGGGGG5:5060;transport=udp;uri-econt=MQGGGGGL6VUGGGGGEWNXGGGGGM36GGGGGZS2GGGGGNGGGGGICKN4GGGGGASGGGGG>;+g.oma.sip-im;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.ft,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot";+g.gsma.rcs.botversion="#=0.92,#=1"
To: <tel:+19876543210>;tag=04gggggbaggggga5
From: <tel:+11234567890>;tag=QODQx0W2AA
Call-ID: 4ggggg43-e3eb-4111-b4a8-99gggggc11bf
CSeq: 1 OPTIONS
P-Asserted-Identity: <tel:+19876543210>
X-Google-Event-Id: 4ggggg42-2798-4f23-971a-1cgggggd5476
Content-Length: 0\n\n
""".replace("\n", "\r\n")


GOOGLE_FI_INVITE_1_RESP = """SIP/2.0 200 OK
Via: SIP/2.0/TLS 1.2.3.4:20000;branch=z9hG4bGGGGGx0W6AA;rport=24041;keep;received=11.22.33.44
Record-Route: <sip:216.239.36.131:443;lr;uri-msrp-addr=L2Jgggggby9iggggg2lvLggggg9ydGMtbggggg9wcmgggggzLmgggggvNA;transport=tls>
Contact: <sip:AAGGGGGSRGGGGGG7UTGGGGGS4GDGGGGGHTOCGGGGGIACZDQLYGGGGGMBF7GGGGG:5060;transport=udp;uri-econt=OAW7GGGGG5YGKCGGGGG4NDLOLGGGGGOJKBGGGGGOKNGGGGGJCRSGGGGGYNNGGGGG>;+g.gsma.rcs.msgrevoke;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp"
To: <tel:+19876543210>;tag=bbgggggfggggg287
From: <tel:+11234567890>;tag=GGGGG0W5AA
Call-ID: 0gggggf5-7a3b-48d8-9ab0-aagggggaebd8
CSeq: 1 INVITE
Content-Type: application/sdp
Server: IM-serv/OMA2.0
P-Asserted-Identity: <tel:+19876543210>
X-Google-Event-Id: 
Content-Length: 609

v=0
o=- 1568489358305 1568489358305 IN IP4 216.239.36.133
s=-
c=IN IP4 216.239.36.133
t=0 0
m=message 443 TCP/TLS/MSRP *
a=accept-types:message/cpim
a=accept-wrapped-types:text/plain message/cpim message/imdn+xml application/im-iscomposing+xml application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml
a=sendrecv
a=maxsize:10000
a=setup:passive
a=path:msrps://216.239.36.133:443/ADCgggggDBTgggggnshJgggggai8vgggggk4pgggggGIMZ1rggggg1LLIgggggb_Rhlgggggnghggggg73Bggggg078kkgggggOkMggggg4_NLbQ;tcp
a=fingerprint:SHA-1 AB:C9:GG:1D:GG:GG:GG:GG:0D:F8:GG:91:GG:GG:GG:GG:8D:GG:GG:F7\n\n
""".replace("\n", "\r\n")

