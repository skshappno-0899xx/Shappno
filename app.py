import os
import sys
import json
import base64
import ssl
import gzip
import time
import http.client
import urllib3
import requests
from io import BytesIO
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, request, jsonify

# ── Same folder import (Vercel / local both work) ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import MajoRLoGinrEs_pb2

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CREDIT = {"dev": "SHAPPNO_CODEX", "tg": "@SHAPPNO_04XX"}

# ============================================================
# CONFIG
# ============================================================
MajorLoginHost  = "loginbp.ppmainecoonghj.com"
MajorLoginPath  = "/MajorLogin"
FreeFireVersion = "OB55"

GUEST_URL     = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
CLIENT_ID     = 100067
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

RESPONSE_HEADER_LEN = 64
DEFAULT_REGION      = "BD"
DEFAULT_LANG        = "bn"


# ============================================================
# PROTOBUF ENCODER
# ============================================================
def encode_varint(num: int) -> bytes:
    if num < 0:
        raise ValueError("Number must be non-negative")
    out = []
    while True:
        b = num & 0x7F
        num >>= 7
        if num:
            b |= 0x80
        out.append(b)
        if not num:
            break
    return bytes(out)


def create_field(num, val):
    if isinstance(val, bool):
        return encode_varint((num << 3) | 0) + encode_varint(int(val))
    if isinstance(val, int):
        return encode_varint((num << 3) | 0) + encode_varint(val)
    if isinstance(val, (str, bytes)):
        v = val.encode() if isinstance(val, str) else val
        return encode_varint((num << 3) | 2) + encode_varint(len(v)) + v
    if isinstance(val, dict):
        nested = create_packet(val)
        return encode_varint((num << 3) | 2) + encode_varint(len(nested)) + nested
    return b""


def create_packet(fields: dict) -> bytes:
    return b"".join(create_field(k, v) for k, v in fields.items())


# ============================================================
# AES-CBC
# ============================================================
def encrypt_api(plain_hex: str) -> str:
    plain  = bytes.fromhex(plain_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()


def _aes_decrypt(data: bytes) -> bytes:
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        dec = cipher.decrypt(data)
        padlen = dec[-1]
        if 1 <= padlen <= 16 and all(b == padlen for b in dec[-padlen:]):
            dec = dec[:-padlen]
        return dec
    except Exception:
        return b""


# ============================================================
# RESPONSE DECODER
# ============================================================
def decode_response(resp: bytes):
    def _try_parse(blob: bytes):
        if not blob:
            return None
        try:
            m = MajoRLoGinrEs_pb2.MajorLoginRes()
            m.ParseFromString(blob)
            if m.account_id > 0 and (m.lock_region or m.noti_region or m.token):
                return m
        except Exception:
            pass
        return None

    m = _try_parse(resp)
    if m:
        return m, "plaintext proto", resp

    if len(resp) > RESPONSE_HEADER_LEN:
        m = _try_parse(resp[RESPONSE_HEADER_LEN:])
        if m:
            return m, f"plaintext proto (skip {RESPONSE_HEADER_LEN}B sig)", resp[RESPONSE_HEADER_LEN:]

    if len(resp) >= 16 and len(resp) % 16 == 0:
        dec = _aes_decrypt(resp)
        if dec:
            m = _try_parse(dec)
            if m:
                return m, "AES-CBC", dec

            if len(dec) > RESPONSE_HEADER_LEN:
                m = _try_parse(dec[RESPONSE_HEADER_LEN:])
                if m:
                    return m, f"AES-CBC (skip {RESPONSE_HEADER_LEN}B sig)", dec[RESPONSE_HEADER_LEN:]

    return None, "unknown", resp


# ============================================================
# JWT DECODER
# ============================================================
def decode_jwt(token: str) -> dict:
    try:
        if not token or not isinstance(token, str):
            return {}
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(payload_b64)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


# ============================================================
# BUILD MajorLogin REQUEST BODY
# ============================================================
def build_major_login_body(access_token: str, open_id: str,
                           region: str = DEFAULT_REGION,
                           lang: str = DEFAULT_LANG) -> bytes:
    fields = {
        3:  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        4:  "free fire",
        5:  1,
        7:  "1.132.4",
        8:  "Android OS 15 / API-35 (AP3A.240617.008/T.R4T2.24e2a71-650ec)",
        9:  "Handheld",
        10: "airtel now cirkle",
        11: "WIFI",
        12: 1666,
        13: 750,
        14: "360",
        15: "ARM64 FP ASIMD AES | 2000 | 8",
        16: 7723,
        17: "Mali-G52 MC2",
        18: "OpenGL ES 3.2 v1.r49p1-03bet0.19498e0ae1d5dac223383c39a2e58f04",
        19: "Google|3744f365-78fe-424a-871e-f77a0a095356",
        20: "103.109.214.50",
        21: lang,
        22: open_id,
        23: "8",
        24: "Handheld",
        25: "realme RMX3710",
        26: region,
        29: access_token,
        30: 1,
        41: "airtel now cirkle",
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 225554,
        61: 155321,
        62: 733,
        64: 155845,
        65: 225554,
        66: 155845,
        67: 225554,
        73: 2,
        74: "/data/app/~~ln8dFa29BUuPBtG4A-WwXQ==/com.dts.freefireth-tXx7bnxvKbykwJzwnEHs2Q==/lib/arm64",
        76: 1,
        77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~ln8dFa29BUuPBtG4A-WwXQ==/com.dts.freefireth-tXx7bnxvKbykwJzwnEHs2Q==/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019121229",
        85: 3,
        86: "OpenGLES2",
        87: 8191,
        88: 8,
        92: 9754,
        93: "android",
        94: "KqsHT+PFj/2sTPjf+unI9C5rnnStUzOFVqOADw9TI8tgL2bTnmzrBM/dEzyqy4BtAVua+w9mgLRIMrjXa67/qXm0pz5uQWsxC6sd8Um7OmMNHRmy",
        95: 111207,
        96: '{"cur_rate":[60,45,90],"support_etc2":false}',
        97: 1,
        99: "4",
        100: "4",
        102: "4455414f055f5f0336",
        104: 52972,
        105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    return create_packet(fields)


# ============================================================
# GARENA GUEST TOKEN
# ============================================================
def get_access_token(uid, password):
    headers = {
        "User-Agent":   "GarenaMSDK/4.0.42(M2006C3LII ;Android 10;en;IN;app 1.126.2 2019120816;)",
        "Accept":       "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Connection":   "Keep-Alive",
    }
    payload = {
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_type":   2,
        "password":      password,
        "response_type": "token",
        "uid":           int(uid),
    }
    try:
        r = requests.post(GUEST_URL, headers=headers, json=payload,
                          verify=False, timeout=8)
        if r.status_code == 200:
            j = r.json()
            if j.get("code") == 0:
                d = j.get("data", {}) or {}
                return d.get("access_token"), d.get("open_id")
    except Exception:
        pass
    return None, None


# ============================================================
# MAJOR LOGIN REQUEST
# ============================================================
def major_login_request(access_token, open_id,
                        region=DEFAULT_REGION, lang=DEFAULT_LANG):
    try:
        ob        = FreeFireVersion
        plaintext = build_major_login_body(access_token, open_id, region, lang)
        body      = bytes.fromhex(encrypt_api(plaintext.hex()))

        ctx  = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(MajorLoginHost, context=ctx, timeout=8)
        conn.request("POST", MajorLoginPath, body=body, headers={
            'User-Agent':       'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept':           '*/*',
            'Accept-Encoding':  'deflate, gzip',
            'Authorization':    'Bearer',
            'X-Ga':             'v1 1',
            'X-Ga-Sv':          '1789556611',
            'Releaseversion':   ob,
            'Content-Type':     'application/x-www-form-urlencoded',
            'X-Unity-Version':  '2018.4.12f1',
        })

        resp = conn.getresponse()
        raw  = resp.read()
        if resp.getheader("Content-Encoding") == "gzip":
            with gzip.GzipFile(fileobj=BytesIO(raw)) as f:
                raw = f.read()
        conn.close()

        if resp.status in (200, 201):
            return raw, None
        return None, f"HTTP {resp.status}: {raw[:120].decode('utf-8', 'replace')}"
    except Exception as e:
        return None, str(e)


# ============================================================
# ROUTE — ONLY /token (lolo.py style response)
# ============================================================
@app.get("/token")
def api_token():
    start_time = time.time()

    uid      = request.args.get("uid", "").strip()
    password = request.args.get("password", "").strip()

    if not uid or not password:
        return jsonify({"status": "error", "message": "Missing uid or password"}), 400

    if not uid.isdigit() or len(uid) < 8:
        return jsonify({"status": "error", "message": "Invalid UID format"}), 400

    access_token, open_id = get_access_token(uid, password)
    if not access_token or not open_id:
        return jsonify({"status": "error", "message": "OAuth failed"}), 400

    raw, err = major_login_request(access_token, open_id)
    if not raw:
        return jsonify({
            "status": "error",
            "message": err or "JWT generation failed"
        }), 400

    res, mode, _ = decode_response(raw)
    if not res or not res.token:
        return jsonify({
            "status": "error",
            "message": "No JWT token received",
            "decode_mode": mode
        }), 400

    jwt_payload = decode_jwt(res.token)
    real_uid = str(jwt_payload.get("account_id", res.account_id or "N/A"))
    elapsed = time.time() - start_time

    return jsonify({
        "status":       "success",
        "real_uid":     real_uid,
        "access_token": access_token,
        "open_id":      open_id,
        "token":        res.token,
        "time":         f"{elapsed:.2f}s",
    }), 200


# ── Vercel / local ──
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8789))
    print(f"✅ SHAPPNO JWT API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)