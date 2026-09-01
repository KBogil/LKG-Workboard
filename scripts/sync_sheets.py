"""
구글 시트(원본 파일들)를 읽어서 data/workboard.json 으로 변환하는 스크립트.

- OAuth Refresh Token으로 매번 새 Access Token을 발급받아 사용합니다.
- config/sources.json 에 등록된 각 source마다:
    - gid가 있으면: 그 gid(탭 고유번호)에 해당하는 탭을 읽습니다.
    - dynamic_month가 true이면: "OO년 O월" 형식의 "이번 달" 탭을 자동으로 찾아 읽습니다.
- 결과는 WORKBOARD_PIN(핀번호)으로 암호화되어 data/workboard.json에 저장됩니다.
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timezone, timedelta
import requests

TOKEN_URL = "https://oauth2.googleapis.com/token"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
PBKDF2_ITERATIONS = 200000
AES_KEY_LEN = 32  # AES-256


def encrypt_json(data: dict, passphrase: str) -> dict:
    """딕셔너리를 JSON 문자열로 만든 뒤, 핀번호(passphrase)로 AES-GCM 암호화합니다.
    브라우저(app.js)에서 같은 방식(PBKDF2 + AES-GCM)으로 복호화합니다."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_LEN
    )
    iv = os.urandom(12)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)

    return {
        "encrypted": True,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS,
    }


def get_access_token():
    """Refresh Token으로 새 Access Token을 발급받습니다."""
    client_id = os.environ["GOOGLE_CLIENT_ID"]
    client_secret = os.environ["GOOGLE_CLIENT_SECRET"]
    refresh_token = os.environ["GOOGLE_REFRESH_TOKEN"]

    resp = requests.post(
        TOKEN_URL,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_spreadsheet_meta(spreadsheet_id, access_token):
    """스프레드시트 안의 탭(시트) 목록/제목/gid 정보를 가져옵니다."""
    url = f"{SHEETS_API}/{spreadsheet_id}"
    resp = requests.get(
        url, headers={"Authorization": f"Bearer {access_token}"}, timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def find_title_by_gid(meta, gid):
    for sheet in meta.get("sheets", []):
        if sheet["properties"]["sheetId"] == gid:
            return sheet["properties"]["title"]
    return None


def find_title_by_exact_match(meta, target_title):
    for sheet in meta.get("sheets", []):
        title = sheet["properties"]["title"]
        if title.strip() == target_title.strip():
            return title
    return None


def current_month_title():
    """한국 시간(KST) 기준으로 '26년 8월' 같은 문자열을 만듭니다."""
    kst = timezone(timedelta(hours=9))
    now = datetime.now(kst)
    yy = now.year % 100
    return f"{yy}년 {now.month}월"


def get_values(spreadsheet_id, sheet_title, access_token):
    """특정 탭의 전체 값을 A~ZZ 범위로 읽어옵니다."""
    range_ = f"'{sheet_title}'!A:ZZ"
    url = f"{SHEETS_API}/{spreadsheet_id}/values/{range_}"
    resp = requests.get(
        url, headers={"Authorization": f"Bearer {access_token}"}, timeout=30
    )
    resp.raise_for_status()
    return resp.json().get("values", [])


def rows_to_records(rows):
    """완전히 빈 선행 행은 건너뛰고, 실제 내용이 있는 첫 행을 헤더(열 이름)로 보고
    나머지 행을 {열이름: 값} 형태로 변환합니다."""
    if not rows:
        return []

    header_idx = 0
    while header_idx < len(rows) and not any(
        cell.strip() for cell in rows[header_idx]
    ):
        header_idx += 1

    if header_idx >= len(rows):
        return []

    header = rows[header_idx]
    records = []
    for row in rows[header_idx + 1:]:
        if not any(cell.strip() for cell in row):
            continue
        record = {}
        for i, col_name in enumerate(header):
            record[col_name] = row[i] if i < len(row) else ""
        records.append(record)
    return records


def main():
    with open("config/sources.json", encoding="utf-8") as f:
        config = json.load(f)

    access_token = get_access_token()
    meta_cache = {}
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": {},
    }

    for key, source in config["sources"].items():
        spreadsheet_id = source["spreadsheet_id"]

        if spreadsheet_id not in meta_cache:
            meta_cache[spreadsheet_id] = get_spreadsheet_meta(
                spreadsheet_id, access_token
            )
        meta = meta_cache[spreadsheet_id]

        if source.get("dynamic_month"):
            target = current_month_title()
            title = find_title_by_exact_match(meta, target)
            if title is None:
                print(f"[경고] {key}: '{target}' 이름의 탭을 찾지 못했습니다.")
                output["data"][key] = []
                continue
        else:
            title = find_title_by_gid(meta, source["gid"])
            if title is None:
                print(f"[경고] {key}: gid {source['gid']} 탭을 찾지 못했습니다.")
                output["data"][key] = []
                continue

        rows = get_values(spreadsheet_id, title, access_token)
        records = rows_to_records(rows)
        output["data"][key] = records
        print(f"[완료] {key} ({title}): {len(records)}건")

    os.makedirs("data", exist_ok=True)
    passphrase = os.environ["WORKBOARD_PIN"]
    encrypted_output = encrypt_json(output, passphrase)
    with open("data/workboard.json", "w", encoding="utf-8") as f:
        json.dump(encrypted_output, f, ensure_ascii=False, indent=2)

    print("data/workboard.json 저장 완료 (암호화됨)")


if __name__ == "__main__":
    main()
