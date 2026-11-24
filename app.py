#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import struct
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
def encode_pb_varint_field(field_num: int, value: int) -> bytes:
    if value == 0:
        return b""
    tag = encode_varint((field_num << 3) | 0)
    return tag + encode_varint(value)


def encode_pb_bytes_field(field_num: int, value: bytes) -> bytes:
    if not value:
        return b""
    tag = encode_varint((field_num << 3) | 2)
    return tag + encode_varint(len(value)) + value


def encode_pb_str_field(field_num: int, value: str) -> bytes:
    if not value:
        return b""
    return encode_pb_bytes_field(field_num, value.encode("utf-8"))


def extract_login_token(raw_proto: bytes):
    pos = 0
    while pos < len(raw_proto):
        tag, pos = decode_varint(raw_proto, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 8 and wire_type == 2:
            length, pos = decode_varint(raw_proto, pos)
            if pos + length > len(raw_proto):
                return None
            token = raw_proto[pos:pos + length].decode("utf-8")
            return token if token.count(".") == 2 else None
        else:
            pos = skip_field(raw_proto, pos, wire_type)
    return None


def build_major_login_payload(open_id: str, access_token: str, country_code: str) -> bytes:
    payload = bytearray()
    payload += encode_pb_str_field(3, "2026-09-16 10:32:36")
    payload += encode_pb_str_field(4, "free fire")
    payload += encode_pb_varint_field(5, 1)
    payload += encode_pb_str_field(7, VERSION)
    payload += encode_pb_str_field(8, "Android OS 10 / API-29 (QP1A.190711.020/V12.0.26.0.QCDINXM)")
    payload += encode_pb_str_field(9, "Handheld")
    payload += encode_pb_str_field(10, "Ncell")
    payload += encode_pb_str_field(11, "WIFI")
    payload += encode_pb_varint_field(12, 1600)
    payload += encode_pb_varint_field(13, 720)
    payload += encode_pb_str_field(14, "320")
    payload += encode_pb_str_field(15, "ARMv7 VFPv3 NEON | 2001 | 8")
    payload += encode_pb_varint_field(16, 3790)
    payload += encode_pb_str_field(17, "PowerVR Rogue GE8320")
    payload += encode_pb_str_field(18, "OpenGL ES 3.2 build 1.11@5425693")
    payload += encode_pb_str_field(19, "Google|00000000-0000-0000-0000-000000000000")
    payload += encode_pb_str_field(20, "111.119.38.133")
    payload += encode_pb_str_field(21, "en")
    payload += encode_pb_str_field(22, open_id)
    payload += encode_pb_str_field(23, "4")
    payload += encode_pb_str_field(24, "Handheld")
    payload += encode_pb_str_field(25, "Xiaomi M2006C3LII")
    payload += encode_pb_str_field(26, country_code)
    payload += encode_pb_str_field(29, access_token)
    payload += encode_pb_varint_field(30, 1)
    payload += encode_pb_str_field(41, "Ncell")
    payload += encode_pb_str_field(42, "WIFI")
    payload += encode_pb_str_field(57, "1ac4b80ecf0478a44203bf8fac6120f5")
    payload += encode_pb_varint_field(60, 53041)
    payload += encode_pb_varint_field(61, 7291)
    payload += encode_pb_varint_field(62, 2176)
    payload += encode_pb_varint_field(64, 7395)
    payload += encode_pb_varint_field(65, 53041)
    payload += encode_pb_varint_field(66, 7395)
    payload += encode_pb_varint_field(67, 53041)
    payload += encode_pb_varint_field(70, 4)
    payload += encode_pb_varint_field(73, 2)
    payload += encode_pb_str_field(74, "/data/app/com.dts.freefireth-yAPXAhp2RyIlrtNAM0VzKQ==/lib/arm")
    payload += encode_pb_varint_field(76, 1)
    payload += encode_pb_str_field(77, "066a589fa3f5658377634fe7b1d88556|/data/app/com.dts.freefireth-yAPXAhp2RyIlrtNAM0VzKQ==/base.apk")
    payload += encode_pb_varint_field(78, 6)
    payload += encode_pb_varint_field(79, 1)
    payload += encode_pb_str_field(81, "32")
    payload += encode_pb_str_field(83, "2019121227")
    payload += encode_pb_varint_field(85, 3)
    payload += encode_pb_str_field(86, "OpenGLES2")
    payload += encode_pb_varint_field(87, 3071)
    payload += encode_pb_varint_field(88, 4)
    payload += encode_pb_varint_field(92, 9329)
    payload += encode_pb_str_field(93, "3rd_party")
    payload += encode_pb_str_field(94, "KqsHT3r+fXQIu/dyZrEa8fJBhbJ5uqDES7YsAUfu+Mck9A+Bly6lFfYk7Q7Nj68pqI8I3g4Oz3gLxWef6Eh/jKyzHug=")
    payload += encode_pb_varint_field(95, 111207)
    payload += encode_pb_str_field(96, json.dumps({"cur_rate": None, "support_etc2": False}, separators=(",", ":")))
    payload += encode_pb_varint_field(97, 1)
    payload += encode_pb_str_field(99, "4")
    payload += encode_pb_str_field(100, "4")
    payload += encode_pb_bytes_field(102, bytes.fromhex("42 54 4c 10 53 0e 5b 04 30"))
    payload += encode_pb_varint_field(104, 47591)
    payload += encode_pb_varint_field(105, 1)
    payload += encode_pb_str_field(106, "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|1c2462939e53942fc995400436a3dc7b")
    payload += encode_pb_str_field(107, "c8e41b7a93f02d56e1a94c7b8203f5d1")
    return encrypt_payload(bytes(payload))


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
                try:
                    token = extract_login_token(proto_payload)
                    if token:
                        return token
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
# TC Stats (Pure-Python Protobuf -> JSON)
# ==========================================
def build_tc_stats_req(account_id: int, season_id: int = 0, game_mode: int = 15, match_mode: int = 6) -> bytes:
    payload = bytearray()
    payload += encode_pb_varint_field(1, account_id)
    payload += encode_pb_varint_field(2, season_id)
    payload += encode_pb_varint_field(3, game_mode)
    payload += encode_pb_varint_field(4, match_mode)
    return bytes(payload)


def parse_detailed_tc_stats(raw_proto: bytes) -> dict:
    field_map = {
        1: "mvp_count",
        2: "double_kills",
        3: "triple_kills",
        4: "four_kills",
        5: "damage",
        6: "head_shot_kills",
        7: "knock_downs",
        8: "revivals",
        9: "assists",
        10: "deaths",
        11: "streak_wins",
        12: "throwing_kills",
        13: "one_game_most_damage",
        14: "one_game_most_kills",
        16: "rating_enabled_games",
        17: "headshot_count",
        18: "hit_count",
        19: "gold_medal_cnt",
        20: "silver_medal_cnt",
    }
    stats = {}
    pos = 0
    while pos < len(raw_proto):
        tag, pos = decode_varint(raw_proto, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 15 and wire_type == 1:
            stats["rating_points"] = struct.unpack("<d", raw_proto[pos:pos + 8])[0]
            pos += 8
        elif field_num in field_map and wire_type == 0:
            val, pos = decode_varint(raw_proto, pos)
            stats[field_map[field_num]] = val
        else:
            pos = skip_field(raw_proto, pos, wire_type)
    return stats


def parse_account_tc_stats(raw_proto: bytes) -> dict:
    field_map = {
        1: "account_id",
        2: "games_played",
        3: "wins",
        4: "kills",
    }
    result = {}
    pos = 0
    while pos < len(raw_proto):
        tag, pos = decode_varint(raw_proto, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num in field_map and wire_type == 0:
            val, pos = decode_varint(raw_proto, pos)
            result[field_map[field_num]] = val
        elif field_num == 5 and wire_type == 2:
            length, pos = decode_varint(raw_proto, pos)
            result["detailed_stats"] = parse_detailed_tc_stats(raw_proto[pos:pos + length])
            pos += length
        else:
            pos = skip_field(raw_proto, pos, wire_type)
    return result


def parse_tc_stats_res(raw_proto: bytes) -> dict:
    result = {}
    pos = 0
    while pos < len(raw_proto):
        tag, pos = decode_varint(raw_proto, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if field_num == 1 and wire_type == 2:
            length, pos = decode_varint(raw_proto, pos)
            result["cs_stats"] = parse_account_tc_stats(raw_proto[pos:pos + length])
            pos += length
        else:
            pos = skip_field(raw_proto, pos, wire_type)
    return result


def fetch_tc_stats(region: str, target_account_id: int, season_id: int = 0, game_mode: int = 15, match_mode: int = 6) -> dict:
    url = f"{get_url_by_region(region)}/GetPlayerTCStats"
    encrypted_body = encrypt_payload(
        build_tc_stats_req(target_account_id, season_id, game_mode, match_mode)
    )
    pool_key = get_pool_key(region)
    max_attempts = len(GUEST_ACCOUNTS[pool_key])

    start_index = 0
    force_refresh = False

    for attempt in range(max_attempts):
        token, used_idx = get_jwt_token(region, start_index=start_index, force_refresh=force_refresh)

        headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip",
            "X-GA-SV": str(int(time.time())),
            "Authorization": f"Bearer {token}",
            "X-GA": "v1 1",
            "ReleaseVersion": OB_VERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1",
        }

        resp = requests.post(url, headers=headers, data=encrypted_body, timeout=15)

        if resp.status_code in (401, 403) and attempt < max_attempts - 1:
            start_index = (used_idx + 1) % max_attempts
            force_refresh = True
            continue

        resp.raise_for_status()
        parsed = parse_tc_stats_res(resp.content)
        if not parsed:
            raise ValueError("TC stats not found in server response.")
        return parsed

    raise RuntimeError("Unable to retrieve TC stats after trying all guest accounts.")


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

    .tabs {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      padding: 6px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid var(--border);
      border-radius: 14px;
    }

    .tab-btn {
      height: 40px;
      border: none;
      border-radius: 10px;
      background: transparent;
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s ease, color 0.2s ease;
    }

    .tab-btn.active {
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #fff;
    }

    .tab-panel { display: none; }
    .tab-panel.active { display: flex; flex-direction: column; gap: 18px; }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 12px;
    }

    @media (max-width: 480px) {
      .stats-grid { grid-template-columns: 1fr; }
    }

    .json-box {
      margin-top: 18px;
      padding: 14px;
      border-radius: 14px;
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border);
      display: none;
      animation: fadeUp 0.25s ease forwards;
    }

    .json-box.visible { display: block; }

    .json-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .json-header span {
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      font-weight: 600;
    }

    .copy-btn {
      border: 1px solid var(--border);
      background: rgba(255, 255, 255, 0.06);
      color: var(--text);
      font-size: 0.78rem;
      padding: 4px 10px;
      border-radius: 8px;
      cursor: pointer;
    }

    .json-pre {
      max-height: 340px;
      overflow: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.82rem;
      line-height: 1.5;
      color: #7dd3fc;
      white-space: pre-wrap;
      word-break: break-word;
    }
  </style>
</head>
<body>
  <main class="container">
    <div class="tabs">
      <button type="button" class="tab-btn active" data-tab="creditTab">Credit Score</button>
      <button type="button" class="tab-btn" data-tab="statsTab">TC Stats Viewer</button>
    </div>

    <div id="creditTab" class="tab-panel active">
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
    </div>

    <div id="statsTab" class="tab-panel">
      <section class="card">
        <div class="header">
          <h1>TC Stats Viewer</h1>
          <p>Fetch player TC stats in JSON</p>
        </div>

        <form id="statsForm">
          <div class="form-grid">
            <div class="field">
              <label for="statsRegion">Region</label>
              <select id="statsRegion" name="region">
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
              <label for="statsAccountId">Account ID (UID)</label>
              <input
                id="statsAccountId"
                name="account_id"
                type="text"
                inputmode="numeric"
                pattern="[0-9]+"
                placeholder="e.g. 3203014668"
                required
              />
            </div>
          </div>

          <div class="stats-grid">
            <div class="field">
              <label for="seasonId">Season ID</label>
              <input id="seasonId" type="number" min="0" value="0" required />
            </div>
            <div class="field">
              <label for="gameMode">Game Mode</label>
              <input id="gameMode" type="number" min="0" value="15" required />
            </div>
            <div class="field">
              <label for="matchMode">Match Mode</label>
              <input id="matchMode" type="number" min="0" value="6" required />
            </div>
          </div>

          <button type="submit" class="btn" id="statsSubmitBtn">
            <span class="spinner"></span>
            <span id="statsBtnText">Get TC Stats (JSON)</span>
          </button>
        </form>

        <div id="statsErrorBox" class="error-msg"></div>

        <div id="statsJsonBox" class="json-box">
          <div class="json-header">
            <span>JSON Response</span>
            <button type="button" class="copy-btn" id="copyJsonBtn">Copy JSON</button>
          </div>
          <pre id="statsJsonPre" class="json-pre"></pre>
        </div>
      </section>
    </div>
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

    const HISTORY_KEY = "credit_score_history_v1";

    function getLocalHistory() {
      try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      } catch (_) {
        return [];
      }
    }

    function saveLocalHistory(accountId, score) {
      const items = getLocalHistory();
      items.unshift({ account_id: String(accountId), credit_score: score });
      const trimmed = items.slice(0, 10);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
      } catch (_) {}
      return trimmed;
    }

    async function loadHistory() {
      const localItems = getLocalHistory();
      if (localItems.length) {
        renderHistory(localItems);
        return;
      }
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
        const updatedHistory = saveLocalHistory(accountId, data.credit_score);
        renderHistory(updatedHistory);
      } catch (err) {
        errorBox.textContent = err.message;
        errorBox.classList.add("visible");
      } finally {
        submitBtn.classList.remove("loading");
        submitBtn.disabled = false;
        btnText.textContent = "Check Credit Score";
      }
    });

    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(btn.dataset.tab).classList.add("active");
      });
    });

    const statsForm = document.getElementById("statsForm");
    const statsSubmitBtn = document.getElementById("statsSubmitBtn");
    const statsBtnText = document.getElementById("statsBtnText");
    const statsErrorBox = document.getElementById("statsErrorBox");
    const statsJsonBox = document.getElementById("statsJsonBox");
    const statsJsonPre = document.getElementById("statsJsonPre");
    const copyJsonBtn = document.getElementById("copyJsonBtn");

    statsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const region = document.getElementById("statsRegion").value;
      const accountId = document.getElementById("statsAccountId").value.trim();
      const seasonId = Number(document.getElementById("seasonId").value || 0);
      const gameMode = Number(document.getElementById("gameMode").value || 15);
      const matchMode = Number(document.getElementById("matchMode").value || 6);

      statsErrorBox.classList.remove("visible");
      statsJsonBox.classList.remove("visible");
      statsSubmitBtn.classList.add("loading");
      statsSubmitBtn.disabled = true;
      statsBtnText.textContent = "Fetching...";

      try {
        const res = await fetch("/api/tc-stats", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            region,
            account_id: accountId,
            season_id: seasonId,
            game_mode: gameMode,
            match_mode: matchMode
          })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || "Request failed");
        }

        statsJsonPre.textContent = JSON.stringify(data, null, 2);
        statsJsonBox.classList.add("visible");
      } catch (err) {
        statsErrorBox.textContent = err.message;
        statsErrorBox.classList.add("visible");
      } finally {
        statsSubmitBtn.classList.remove("loading");
        statsSubmitBtn.disabled = false;
        statsBtnText.textContent = "Get TC Stats (JSON)";
      }
    });

    copyJsonBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(statsJsonPre.textContent);
        copyJsonBtn.textContent = "Copied!";
        setTimeout(() => { copyJsonBtn.textContent = "Copy JSON"; }, 1200);
      } catch (_) {}
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


@app.route("/api/tc-stats", methods=["POST"])
def api_tc_stats():
    data = request.get_json(silent=True) or {}
    region = str(data.get("region", "BD")).strip().upper() or "BD"
    raw_uid = str(data.get("account_id", "")).strip()

    if not raw_uid.isdigit():
        return jsonify({"error": "Please enter a valid numeric Account ID."}), 400

    try:
        season_id = int(data.get("season_id", 0))
        game_mode = int(data.get("game_mode", 15))
        match_mode = int(data.get("match_mode", 6))
    except (TypeError, ValueError):
        return jsonify({"error": "season_id, game_mode, and match_mode must be integers."}), 400

    try:
        stats_json = fetch_tc_stats(region, int(raw_uid), season_id, game_mode, match_mode)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify(stats_json)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)