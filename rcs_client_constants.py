#!/usr/bin/env python3
# encoding: utf-8
"""
Constants.py
"""

# Use python logging library for better logging control
import logging
LOG_FMT       = '[%(levelname)s] %(message)s'
LOG_LEVEL     = logging.DEBUG

# Switch for using simulation mode or not
SIM_MODE      = False

# Simulation mode
DEMO_USERNAME = "+11234567890"
DEMO_RECEIVER = "+19876543210"
DEMO_IMEI     = "12345678-12345-0"
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
Via: SIP/2.0/TLS 172.31.81.209:20000;branch=z9hG4bKqIrNsHdyj3539w;keep;server-keep;rport=40216;received=131.179.60.171
To: <tel:+11234567890>;tag=1bfa7f79
From: <tel:+11234567890>;tag=lNfcEzbJVTW7Qw
Call-ID: 77e6d3e3-8cd0-4c26-9757-2884868d30e0
CSeq: 1 REGISTER
WWW-Authenticate: Digest nonce="vsyANogTcKZZsZm74VPB+Q==",algorithm=MD5,realm="us.pfi.rcs.telephony.goog"
X-Google-Event-Id: LWN52OIABWCDECWNKBEJICJCPA======
Content-Length: 0\n\n
""".replace("\n", "\r\n")


