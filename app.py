#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import threading
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import requests
import urllib3
from flask import Flask, request, jsonify, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import MajoRLoGinrEq_pb2
import MajorLoginRes_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==========================================
# Encryption Keys (Request Body)
# ==========================================
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

VERSION = "1.132.1"
OB_VERSION = "OB55"
OAUTH_URL = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# ==========================================
# Guest Accounts Pool (3 per region)
# ==========================================
GUEST_ACCOUNTS = {
    "BD": [
        {
            "uid": "8023505301",
            "password": "FB44444AAB86A0D8BC20C232067ED3251A8E8C1644D2CCD66163719657FBE5BE",
            "account_id": "18466832940",
            "name": "Crownx¹⁶⁸⁴⁸",
            "region": "BD",
        },
        {
            "uid": "8023505458",
            "password": "03C55C1BE1395891684A056F7BF90C059B5E8DD0714296561C5C612057591263",
            "account_id": "18466833272",
            "name": "Crownx⁹⁰³¹⁹",
            "region": "BD",
        },
        {
            "uid": "8023506372",
            "password": "EED238D962D3BCBC1077650CBC420EC202CF58088F212951A3A0AF2E54F6381A",
            "account_id": "18466835491",
            "name": "Crownx⁵⁷⁰⁷⁷",
            "region": "BD",
        },
    ],
    "IND": [
        {
            "uid": "7972054944",
            "password": "B98E359FBF83AC67D95D234DC3D6F5AAA06282944C3EE8A770AB14017F3F72D8",
            "account_id": "18381096274",
            "name": "Crownx⁷²⁰³⁹",
            "region": "IND",
        },
        {
            "uid": "7972054988",
            "password": "62F8A6EC66C0387108B32990B6A90D6A63E429205F7279C8B0DB9EF389D9FBA6",
            "account_id": "18381096442",
            "name": "Crownx⁹¹⁸⁷⁰",
            "region": "IND",
        },
        {
            "uid": "7972055472",
            "password": "9DB48AABB9BB67C1E6A3A3B26DC68E989F76FBE12AF770C1B5D346B6EF68AD24",
            "account_id": "18381097938",
            "name": "Crownx¹¹⁸⁵⁹",
            "region": "IND",
        },
    ],
    "SAC": [
        {
            "uid": "8251980252",
            "password": "7351C5D7EC943BA543EAEC5D0BB25FAC34646D014F429B370E521B00CFB9BAF9",
            "account_id": "18702057654",
            "name": "Crownx⁷⁵⁸⁹⁴",
            "region": "SAC",
        },
        {
            "uid": "8251979921",
            "password": "BE0CCE00D3CB38E6364FD1CFFB3E18AB4145ADC7DD69127DE8D924A75550B6FE",
            "account_id": "18702057436",
            "name": "Crownx⁶⁷⁹⁸⁴",
            "region": "SAC",
        },
        {
            "uid": "8251980738",
            "password": "BA832BACBBEBE006EE18076D2AA0F9C20DC33865B86721118FBADDAA203445B3",
            "account_id": "18702057907",
            "name": "Crownx⁰⁵⁸⁰⁵",
            "region": "SAC",
        },
    ],
}

# Thread-safe JWT cache & last 10 checks history
TOKEN_CACHE = {}  # pool_key -> {"token": str, "exp": int, "account_index": int}
TOKEN_LOCK = threading.Lock()
CHECK_HISTORY = deque(maxlen=10)
HISTORY_LOCK = threading.Lock()


# ==========================================
# URL & Pool Helpers
# ==========================================
def get_url_by_region(server_name: str) -> str:
    server_name = server_name.strip().upper()
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com"
    elif server_name in {"SG", "BD"}:
        return "https://clientbp.ppmainecoonghj.com"
    else:
        return "https://clientbp.ppmainecoonghj.com"


def get_login_urls(pool_key: str):
    if pool_key == "IND":
        return [
            "https://loginbp.ind.freefiremobile.com/MajorLogin",
            "https://loginbp.ppmainecoonghj.com/MajorLogin",
        ]
    elif pool_key == "SAC":
        return [
            "https://loginbp.us.freefiremobile.com/MajorLogin",
            "https://loginbp.ppmainecoonghj.com/MajorLogin",
        ]
    return ["https://loginbp.ppmainecoonghj.com/MajorLogin"]


def get_pool_key(region: str) -> str:
    region = region.strip().upper()
    if region == "IND":
        return "IND"
    if region in {"BR", "US", "SAC", "NA"}:
        return "SAC"
    return "BD"


# ==========================================
# Protobuf & AES Helpers
# ==========================================
def encrypt_payload(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(data, AES.block_size))


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def decode_varint(buf: bytes, pos: int):
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Truncated varint")


def skip_field(buf: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:
        _, pos = decode_varint(buf, pos)
        return pos
    elif wire_type == 1:
        return pos + 8
    elif wire_type == 2:
        length, pos = decode_varint(buf, pos)
        return pos + length
    elif wire_type == 5:
        return pos + 4
    else:
        raise ValueError(f"Unsupported wire type: {wire_type}")


def build_personal_show_req(account_id: int, call_sign_src: int = 1) -> bytes:
    payload = bytearray()
    payload += b"\x08" + encode_varint(account_id)
    payload += b"\x10" + encode_varint(call_sign_src)
    return bytes(payload)


def extract_credit_score(raw_proto: bytes):
    pos = 0
    credit_score_info_bytes = None

    while pos < len(raw_proto):
        tag, pos = decode_varint(raw_proto, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 11 and wire_type == 2:
            length, pos = decode_varint(raw_proto, pos)
            credit_score_info_bytes = raw_proto[pos:pos + length]
            break
        else:
            pos = skip_field(raw_proto, pos, wire_type)

    if not credit_score_info_bytes:
        return None

    pos = 0
    while pos < len(credit_score_info_bytes):
        tag, pos = decode_varint(credit_score_info_bytes, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 1 and wire_type == 0:
            score, _ = decode_varint(credit_score_info_bytes, pos)
            return score
        else:
            pos = skip_field(credit_score_info_bytes, pos, wire_type)

    return None


# ==========================================
# Guest OAuth -> MajorLogin -> JWT
# ==========================================
def build_major_login_payload(open_id: str, access_token: str, country_code: str) -> bytes:
    major_login = MajoRLoGinrEq_pb2.MajorLogin()

    major_login.open_id = open_id
    major_login.access_token = access_token
    major_login.client_version = VERSION

    major_login.event_time = "2026-09-16 10:32:36"
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.system_software = "Android OS 10 / API-29 (QP1A.190711.020/V12.0.26.0.QCDINXM)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Ncell"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1600
    major_login.screen_height = 720
    major_login.screen_dpi = "320"
    major_login.processor_details = "ARMv7 VFPv3 NEON | 2001 | 8"
    major_login.memory = 3790
    major_login.gpu_renderer = "PowerVR Rogue GE8320"
    major_login.gpu_version = "OpenGL ES 3.2 build 1.11@5425693"
    major_login.unique_device_id = "Google|00000000-0000-0000-0000-000000000000"
    major_login.client_ip = "111.119.38.133"
    major_login.language = "en"
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"

    major_login.device_model = "Xiaomi M2006C3LII"
    major_login.country_code = country_code

    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Ncell"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "1ac4b80ecf0478a44203bf8fac6120f5"

    major_login.external_storage_total = 53041
    major_login.external_storage_available = 7291
    major_login.internal_storage_total = 2176
    major_login.game_disk_storage_available = 7395
    major_login.game_disk_storage_total = 53041
    major_login.external_sdcard_avail_storage = 7395
    major_login.external_sdcard_total_storage = 53041

    major_login.field_70 = 4
    major_login.login_by = 2
    major_login.library_path = "/data/app/com.dts.freefireth-yAPXAhp2RyIlrtNAM0VzKQ==/lib/arm"
    major_login.reg_avatar = 1
    major_login.library_token = "066a589fa3f5658377634fe7b1d88556|/data/app/com.dts.freefireth-yAPXAhp2RyIlrtNAM0VzKQ==/base.apk"
    major_login.channel_type = 6
    major_login.cpu_type = 1
    major_login.cpu_architecture = "32"
    major_login.client_version_code = "2019121227"

    major_login.field_85 = 3
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 3071
    major_login.login_open_id_type = 4
    major_login.loading_time = 9329
    major_login.release_channel = "3rd_party"
    major_login.extra_info = "KqsHT3r+fXQIu/dyZrEa8fJBhbJ5uqDES7YsAUfu+Mck9A+Bly6lFfYk7Q7Nj68pqI8I3g4Oz3gLxWef6Eh/jKyzHug="
    major_login.android_engine_init_flag = 111207

    major_login.field_96 = json.dumps({"cur_rate": None, "support_etc2": False}, separators=(",", ":"))

    major_login.if_push = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"

    major_login.field_102 = bytes.fromhex("42 54 4c 10 53 0e 5b 04 30")
    major_login.field_104 = 47591
    major_login.field_105 = 1
    major_login.field_106 = "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|1c2462939e53942fc995400436a3dc7b"
    major_login.field_107 = "c8e41b7a93f02d56e1a94c7b8203f5d1"

    return encrypt_payload(major_login.SerializeToString())


def decode_jwt_exp(token: str) -> int:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return int(time.time()) + 3600
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        return int(payload.get("exp", time.time() + 3600))
    except Exception:
        return int(time.time()) + 3600


def fetch_jwt_for_account(account: dict, pool_key: str) -> str:
    oauth_payload = {
        "client_id": 100067,
        "client_secret": CLIENT_SECRET,
        "client_type": 2,
        "password": account["password"],
        "response_type": "token",
        "uid": int(account["uid"]),
    }

    r = requests.post(OAUTH_URL, json=oauth_payload, timeout=15)
    r.raise_for_status()
    res_data = r.json()
    inner = res_data.get("data", {})
    acc_token = inner.get("access_token")
    open_id = inner.get("open_id")

    if not acc_token or not open_id:
        raise RuntimeError(f"OAuth failed for UID {account['uid']}: {res_data}")

    country_map = {"IND": "IN", "SAC": "BR", "BD": "BD"}
    enc_data = build_major_login_payload(open_id, acc_token, country_map.get(pool_key, "BD"))

    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())),
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-Unity-Version": "2022.3.47f1",
        "X-GA": "v1 1",
        "ReleaseVersion": OB_VERSION,
    }

    last_err = None
    for login_url in get_login_urls(pool_key):
        try:
            resp = requests.post(login_url, data=enc_data, headers=headers, verify=False, timeout=15)
            if resp.status_code != 200:
                last_err = f"HTTP {resp.status_code}"
                continue

            candidates = [resp.content[64:], resp.content] if len(resp.content) > 64 else [resp.content]
            for proto_payload in candidates:
                res_msg = MajorLoginRes_pb2.MajorLoginRes()
                try:
                    res_msg.ParseFromString(proto_payload)
                    if res_msg.token:
                        return res_msg.token
                except Exception:
                    continue
        except Exception as exc:
            last_err = str(exc)

    raise RuntimeError(f"MajorLogin failed for UID {account['uid']}: {last_err}")


def get_jwt_token(region: str, start_index: int = 0, force_refresh: bool = False):
    pool_key = get_pool_key(region)
    accounts = GUEST_ACCOUNTS[pool_key]

    with TOKEN_LOCK:
        cached = TOKEN_CACHE.get(pool_key)
        now = int(time.time())
        if not force_refresh and cached and cached["exp"] > now + 60:
            return cached["token"], cached["account_index"]

        errors = []
        for offset in range(len(accounts)):
            idx = (start_index + offset) % len(accounts)
            acc = accounts[idx]
            try:
                token = fetch_jwt_for_account(acc, pool_key)
                TOKEN_CACHE[pool_key] = {
                    "token": token,
                    "exp": decode_jwt_exp(token),
                    "account_index": idx,
                }
                return token, idx
            except Exception as exc:
                errors.append(f"Account {idx + 1} ({acc['uid']}): {exc}")

        raise RuntimeError("All 3 guest accounts failed: " + " | ".join(errors))


def fetch_credit_score(region: str, target_account_id: int) -> int:
    url = f"{get_url_by_region(region)}/GetPlayerPersonalShow"
    encrypted_body = encrypt_payload(build_personal_show_req(target_account_id))
    pool_key = get_pool_key(region)
    max_attempts = len(GUEST_ACCOUNTS[pool_key])

    start_index = 0
    force_refresh = False

    for attempt in range(max_attempts):
        token, used_idx = get_jwt_token(region, start_index=start_index, force_refresh=force_refresh)

        headers = {
            "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip",
            "X-Ga-Sv": str(int(time.time())),
            "Authorization": f"Bearer {token}",
            "X-Ga": "v1 1",
            "Releaseversion": OB_VERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1",
        }

        resp = requests.post(url, headers=headers, data=encrypted_body, timeout=15)

        if resp.status_code in (401, 403) and attempt < max_attempts - 1:
            # Current guest token rejected -> rotate to next guest account
            start_index = (used_idx + 1) % max_attempts
            force_refresh = True
            continue

        resp.raise_for_status()
        score = extract_credit_score(resp.content)
        if score is None:
            raise ValueError("Credit score not found in server response.")
        return score

    raise RuntimeError("Unable to retrieve credit score after trying all guest accounts.")


# ==========================================
# Web UI & API Routes
# ==========================================
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Credit Score Checker</title>
  <style>
    :root {
      --bg: #090d16;
      --card: rgba(17, 24, 39, 0.78);
      --border: rgba(255, 255, 255, 0.08);
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent-2: #6366f1;
      --success: #22c55e;
      --warn: #f59e0b;
      --danger: #ef4444;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background:
        radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.14), transparent 40%),
        radial-gradient(circle at 85% 80%, rgba(99, 102, 241, 0.14), transparent 45%),
        var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .container {
      width: 100%;
      max-width: 520px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    .card {
      background: var(--card);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 26px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.45);
      transition: transform 0.25s ease, border-color 0.25s ease;
    }

    .header {
      text-align: center;
      margin-bottom: 22px;
    }

    .header h1 {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #f8fafc, #38bdf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .header p {
      color: var(--muted);
      font-size: 0.88rem;
      margin-top: 6px;
    }

    .form-grid {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 12px;
    }

    @media (max-width: 480px) {
      .form-grid { grid-template-columns: 1fr; }
    }

    .field label {
      display: block;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    select, input {
      width: 100%;
      height: 46px;
      padding: 0 14px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(15, 23, 42, 0.85);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }

    select:focus, input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.16);
    }

    .btn {
      margin-top: 14px;
      width: 100%;
      height: 48px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #fff;
      font-size: 0.98rem;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      transition: transform 0.15s ease, opacity 0.2s ease, box-shadow 0.2s ease;
      box-shadow: 0 10px 24px rgba(56, 189, 248, 0.22);
    }

    .btn:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 14px 28px rgba(56, 189, 248, 0.3);
    }

    .btn:active:not(:disabled) { transform: translateY(0); }
    .btn:disabled { opacity: 0.65; cursor: not-allowed; }

    .spinner {
      width: 18px;
      height: 18px;
      border: 2.5px solid rgba(255, 255, 255, 0.3);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      display: none;
    }

    .btn.loading .spinner { display: inline-block; }

    @keyframes spin { to { transform: rotate(360deg); } }

    .result-box {
      margin-top: 20px;
      padding: 22px;
      border-radius: 16px;
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid var(--border);
      text-align: center;
      display: none;
      animation: fadeUp 0.28s ease forwards;
    }

    .result-box.visible { display: block; }

    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .score-label {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }

    .score-value {
      font-size: 3.2rem;
      font-weight: 800;
      line-height: 1.1;
      margin-top: 6px;
      font-variant-numeric: tabular-nums;
      color: var(--success);
      transition: color 0.3s ease;
    }

    .score-value.warn { color: var(--warn); }
    .score-value.danger { color: var(--danger); }

    .error-msg {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 12px;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.35);
      color: #fca5a5;
      font-size: 0.88rem;
      display: none;
      animation: fadeUp 0.2s ease forwards;
    }

    .error-msg.visible { display: block; }

    .history-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }

    .history-header h2 {
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text);
    }

    .history-count {
      font-size: 0.78rem;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.06);
      padding: 3px 9px;
      border-radius: 999px;
    }

    .history-table {
      width: 100%;
      border-collapse: collapse;
    }

    .history-table th {
      text-align: left;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
    }

    .history-table th:last-child,
    .history-table td:last-child {
      text-align: right;
    }

    .history-table td {
      padding: 10px;
      font-size: 0.92rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      font-variant-numeric: tabular-nums;
    }

    .history-table tbody tr {
      transition: background 0.15s ease;
    }

    .history-table tbody tr:hover {
      background: rgba(255, 255, 255, 0.04);
    }

    .history-table tbody tr:last-child td {
      border-bottom: none;
    }

    .pill {
      display: inline-block;
      min-width: 44px;
      text-align: center;
      padding: 3px 10px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 0.85rem;
      background: rgba(34, 197, 94, 0.14);
      color: #4ade80;
    }

    .pill.warn {
      background: rgba(245, 158, 11, 0.14);
      color: #fbbf24;
    }

    .pill.danger {
      background: rgba(239, 68, 68, 0.14);
      color: #f87171;
    }

    .empty-history {
      text-align: center;
      color: var(--muted);
      font-size: 0.88rem;
      padding: 18px 0;
    }
  </style>
</head>
<body>
  <main class="container">
    <section class="card">
      <div class="header">
        <h1>Credit Score Checker</h1>
        <p>Select region and enter Account ID</p>
      </div>

      <form id="checkForm">
        <div class="form-grid">
          <div class="field">
            <label for="region">Region</label>
            <select id="region" name="region">
              <option value="BD" selected>BD</option>
              <option value="IND">IND</option>
              <option value="SG">SG</option>
              <option value="SAC">SAC</option>
              <option value="BR">BR</option>
              <option value="US">US</option>
              <option value="NA">NA</option>
            </select>
          </div>
          <div class="field">
            <label for="accountId">Account ID (UID)</label>
            <input
              id="accountId"
              name="account_id"
              type="text"
              inputmode="numeric"
              pattern="[0-9]+"
              placeholder="e.g. 18626997545"
              required
            />
          </div>
        </div>

        <button type="submit" class="btn" id="submitBtn">
          <span class="spinner"></span>
          <span id="btnText">Check Credit Score</span>
        </button>
      </form>

      <div id="errorBox" class="error-msg"></div>

      <div id="resultBox" class="result-box">
        <div class="score-label">Credit Score</div>
        <div id="scoreValue" class="score-value">--</div>
      </div>
    </section>

    <section class="card">
      <div class="history-header">
        <h2>Last 10 Checks</h2>
        <span class="history-count" id="historyCount">0 / 10</span>
      </div>
      <div id="historyContainer">
        <div class="empty-history">No checks yet.</div>
      </div>
    </section>
  </main>

  <script>
    const form = document.getElementById("checkForm");
    const submitBtn = document.getElementById("submitBtn");
    const btnText = document.getElementById("btnText");
    const resultBox = document.getElementById("resultBox");
    const scoreValueEl = document.getElementById("scoreValue");
    const errorBox = document.getElementById("errorBox");
    const historyContainer = document.getElementById("historyContainer");
    const historyCount = document.getElementById("historyCount");

    function scoreClass(score) {
      if (score >= 90) return "";
      if (score >= 70) return "warn";
      return "danger";
    }

    function animateScore(target) {
      scoreValueEl.className = "score-value " + scoreClass(target);
      const duration = 350;
      const start = performance.now();
      function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        scoreValueEl.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(tick);
        else scoreValueEl.textContent = target;
      }
      requestAnimationFrame(tick);
    }

    function renderHistory(items) {
      historyCount.textContent = `${items.length} / 10`;
      if (!items.length) {
        historyContainer.innerHTML = '<div class="empty-history">No checks yet.</div>';
        return;
      }

      const rows = items.map(item => `
        <tr>
          <td>${item.account_id}</td>
          <td><span class="pill ${scoreClass(item.credit_score)}">${item.credit_score}</span></td>
        </tr>
      `).join("");

      historyContainer.innerHTML = `
        <table class="history-table">
          <thead>
            <tr>
              <th>Account ID</th>
              <th>Credit Score</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      `;
    }

    async function loadHistory() {
      try {
        const res = await fetch("/api/history");
        const data = await res.json();
        renderHistory(data.history || []);
      } catch (_) {}
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const region = document.getElementById("region").value;
      const accountId = document.getElementById("accountId").value.trim();

      errorBox.classList.remove("visible");
      resultBox.classList.remove("visible");
      submitBtn.classList.add("loading");
      submitBtn.disabled = true;
      btnText.textContent = "Checking...";

      try {
        const res = await fetch("/api/check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ region, account_id: accountId })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || "Request failed");
        }

        resultBox.classList.add("visible");
        animateScore(data.credit_score);
        renderHistory(data.history || []);
      } catch (err) {
        errorBox.textContent = err.message;
        errorBox.classList.add("visible");
      } finally {
        submitBtn.classList.remove("loading");
        submitBtn.disabled = false;
        btnText.textContent = "Check Credit Score";
      }
    });

    loadHistory();
  </script>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_PAGE)


@app.route("/api/history", methods=["GET"])
def api_history():
    with HISTORY_LOCK:
        return jsonify({"history": list(CHECK_HISTORY)})


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    region = str(data.get("region", "BD")).strip().upper() or "BD"
    raw_uid = str(data.get("account_id", "")).strip()

    if not raw_uid.isdigit():
        return jsonify({"error": "Please enter a valid numeric Account ID."}), 400

    target_uid = int(raw_uid)

    try:
        score = fetch_credit_score(region, target_uid)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502

    with HISTORY_LOCK:
        CHECK_HISTORY.appendleft({
            "account_id": str(target_uid),
            "credit_score": score,
        })
        history_snapshot = list(CHECK_HISTORY)

    return jsonify({
        "credit_score": score,
        "history": history_snapshot,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)