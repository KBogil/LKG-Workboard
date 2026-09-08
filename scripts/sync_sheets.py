"""
구글 시트(원본 파일들)를 읽어서 data/workboard.json 으로 변환하는 스크립트.

- OAuth Refresh Token으로 매번 새 Access Token을 발급받아 사용합니다.
- config/sources.json 에 등록된 각 source마다:
    - gid가 있으면: 그 gid(탭 고유번호)에 해당하는 탭을 읽습니다.
    - dynamic_month가 true이면: "OO년 O월" 형식의 "이번 달" 탭을 자동으로 찾아 읽습니다.
- 탕비실은 전용 처리(build_tangbisil_data)를 탑니다. A~F열은 고정 의미로 읽고,
  G열 이후의 "일자별 블록"은 위치를 하드코딩하지 않고 헤더에서 자동으로 찾아냅니다.
- 결과는 WORKBOARD_PIN(비밀번호)으로 암호화되어 data/workboard.json에 저장됩니다.
- 이 파일은 저장소에 커밋하지 않고, 워크플로가 GitHub Pages로 바로 배포합니다.
  (암호화된 데이터는 압축이 안 돼서, 커밋으로 쌓으면 저장소가 기가 단위로 불어납니다)
"""

import os
import re
import json
import hmac
import base64
import hashlib
from datetime import datetime, timezone, timedelta
import requests

TOKEN_URL = "https://oauth2.googleapis.com/token"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
PBKDF2_ITERATIONS = 600000
AES_KEY_LEN = 32  # AES-256
OUTPUT_PATH = "data/workboard.json"

# 탕비실 시트에서 고정으로 쓰는 부분 (스크린샷 기준)
TANGBISIL_HEADER_ROW = 4      # 4행: 상품명 / 박스당개입수 / 사용량 / 입고량 / (현)잔여재고 / 전월재고
TANGBISIL_FIRST_DATA_ROW = 5  # 5행부터 상품 데이터 시작
TANGBISIL_CHECK_ROW = 1       # 1행: 일자별 "진행" 체크박스
TANGBISIL_DATE_ROWS = (2, 3)  # 2~3행 병합 셀에 "2026-9-7(월)" 형태의 날짜

DATE_HEADER_RE = re.compile(r"(\d{4})[.\-/]\s*(\d{1,2})[.\-/]\s*(\d{1,2})")

# 회사 자체 휴무일(창립기념일, 단체 워크샵 등). 법정공휴일은 아래 holidays 라이브러리가
# 알아서 처리하므로, 여기에는 '달력에 없는 우리 회사만의 쉬는 날'만 적으면 됩니다.
# 예: EXTRA_HOLIDAYS = {"2026-10-16", "2026-12-24"}
EXTRA_HOLIDAYS = set()


# ---------------------------------------------------------------- 암호화

def encrypt_json(data: dict, passphrase: str) -> dict:
    """딕셔너리를 JSON 문자열로 만든 뒤, 비밀번호(passphrase)로 AES-GCM 암호화합니다.
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


def content_fingerprint(data: dict, passphrase: str) -> str:
    """실제 '내용'만 가지고 지문(fingerprint)을 만듭니다.

    암호화는 매번 임의의 salt/iv를 쓰기 때문에, 시트 내용이 하나도 안 바뀌어도
    파일 내용은 항상 달라집니다. 내용이 실제로 바뀌었는지 비교할 때 씁니다.

    비밀번호를 키로 하는 HMAC을 써서, 이 지문만 보고는 내용을 역추적할 수 없게 합니다.
    """
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hmac.new(passphrase.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- 구글 API

def get_access_token():
    """Refresh Token으로 새 Access Token을 발급받습니다."""
    resp = requests.post(
        TOKEN_URL,
        data={
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "refresh_token": os.environ["GOOGLE_REFRESH_TOKEN"],
            "grant_type": "refresh_token",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_spreadsheet_meta(spreadsheet_id, access_token):
    """스프레드시트 안의 탭(시트) 목록/제목/gid 정보를 가져옵니다."""
    resp = requests.get(
        f"{SHEETS_API}/{spreadsheet_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"fields": "sheets.properties(sheetId,title)"},
        timeout=30,
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


def month_of(offset=0):
    """한국 시간(KST) 기준, 이번 달에서 offset개월 떨어진 (연, 월)을 돌려줍니다."""
    kst = timezone(timedelta(hours=9))
    now = datetime.now(kst)
    total = now.year * 12 + (now.month - 1) + offset
    return total // 12, total % 12 + 1


def month_title_offset(offset=0):
    """'26년 9월' 형태의 표시용 문자열."""
    year, month = month_of(offset)
    return f"{year % 100}년 {month}월"


def current_month_title():
    return month_title_offset(0)


def find_month_tab(meta, offset=0):
    """'그 달의 탭'을 이름 형태에 너무 얽매이지 않고 찾아냅니다.

    '26년 9월', '2026년 9월', '26년 09월', '9월', '2026-09' 등 어떻게 적혀 있어도
    같은 달로 인식합니다. 공백은 무시합니다.
    """
    year, month = month_of(offset)
    yy = year % 100
    titles = [s["properties"]["title"] for s in meta.get("sheets", [])]

    pattern = re.compile(
        rf"^(?:{year}|{yy:02d}|{yy})?[년.\-/]?0?{month}월?$|^0?{month}월$"
    )
    for title in titles:
        if pattern.match(re.sub(r"\s+", "", title)):
            return title
    return None


def get_values(spreadsheet_id, sheet_title, access_token, cell_range="A:ZZ"):
    """특정 탭의 값을 읽어옵니다.

    FORMATTED_VALUE로 읽기 때문에 체크박스는 "TRUE"/"FALSE" 문자열로,
    날짜 헤더는 화면에 보이는 "2026-9-7(월)" 형태 그대로 들어옵니다.
    """
    resp = requests.get(
        f"{SHEETS_API}/{spreadsheet_id}/values/'{sheet_title}'!{cell_range}",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"valueRenderOption": "FORMATTED_VALUE"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("values", [])


def get_cell_colors(spreadsheet_id, sheet_title, cell_range, access_token):
    """지정한 범위의 각 셀이 '화면에 실제로 보이는' 배경색을 가져옵니다.
    조건부 서식이 적용된 결과 색상까지 포함됩니다 (effectiveFormat)."""
    resp = requests.get(
        f"{SHEETS_API}/{spreadsheet_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        params={
            "ranges": f"'{sheet_title}'!{cell_range}",
            "fields": "sheets.data.rowData.values.effectiveFormat.backgroundColor",
        },
        timeout=30,
    )
    resp.raise_for_status()
    sheets = resp.json().get("sheets", [])
    if not sheets:
        return []
    row_data = sheets[0].get("data", [{}])[0].get("rowData", [])
    colors = []
    for row in row_data:
        values = row.get("values", [])
        colors.append(
            values[0].get("effectiveFormat", {}).get("backgroundColor", {})
            if values else {}
        )
    return colors


def is_reddish(color):
    """배경색이 빨간/분홍 계열(재고 부족 경고색)인지 판단합니다.
    구글 시트는 색을 지정 안 하면 필드를 생략하므로, 기본값은 흰색(1,1,1)으로 봅니다."""
    r = color.get("red", 1.0)
    g = color.get("green", 1.0)
    b = color.get("blue", 1.0)
    return r > 0.80 and (r - g) > 0.08 and (r - b) > 0.08


# ---------------------------------------------------------------- 값 유틸

def cell(row, idx):
    """행 리스트에서 idx번째 값을 안전하게 꺼냅니다 (짧은 행 대비)."""
    return row[idx].strip() if idx < len(row) and isinstance(row[idx], str) else (
        row[idx] if idx < len(row) else ""
    )


def to_number(value):
    """'1,234' / '12' 같은 문자열을 숫자로. 숫자가 아니면 None."""
    if value is None:
        return None
    text = str(value).strip().replace(",", "")
    if text in ("", "-", "—"):
        return None
    try:
        num = float(text)
    except ValueError:
        return None
    return int(num) if num == int(num) else num


def is_checked(value):
    """체크박스 셀이 체크되어 있는지."""
    return str(value).strip().upper() in ("TRUE", "1", "Y", "예", "✔", "✓")


def korean_holidays(year):
    """그 해의 한국 법정공휴일 날짜 집합('YYYY-MM-DD' 문자열).

    설날·추석처럼 매년 날짜가 바뀌는 음력 공휴일과 대체공휴일까지 라이브러리가
    계산해 주므로, 해가 바뀌어도 손댈 것이 없습니다.
    라이브러리를 못 불러오면 공휴일 제외 없이 평일 전부를 근무일로 봅니다.
    """
    try:
        import holidays
    except ImportError:
        print("[주의] holidays 라이브러리가 없어 공휴일을 제외하지 못했습니다. "
              "requirements.txt 에 holidays 가 있는지 확인하세요.")
        return set()
    return {d.strftime("%Y-%m-%d") for d in holidays.SouthKorea(years=year)}


# ---------------------------------------------------------------- 탕비실

def detect_day_blocks(rows):
    """일자별 블록의 시작 열을 헤더에서 직접 찾아냅니다.

    시트가 달마다 새로 만들어지고 열 위치도 달라질 수 있어서, 열 번호를 코드에
    박아두지 않고 "2026-9-7(월)" 같은 날짜가 적힌 셀을 찾아 그 위치를 씁니다.
    병합 셀은 값이 좌상단 칸에만 들어오므로, 그 열이 곧 블록의 시작 열입니다.
    블록은 [사용량, 입고량, 입고] 3칸 묶음입니다.

    반환: [{"col": 20, "date": "2026-09-07", "weekday": 0, "label": "2026-9-7(월)"}, ...]
    """
    blocks = []
    for row_no in TANGBISIL_DATE_ROWS:
        row = rows[row_no - 1] if row_no - 1 < len(rows) else []
        for col_idx, raw in enumerate(row):
            if col_idx < 6:  # A~F는 고정 영역이라 건너뜁니다
                continue
            match = DATE_HEADER_RE.search(str(raw))
            if not match:
                continue
            year, month, day = (int(g) for g in match.groups())
            try:
                date = datetime(year, month, day)
            except ValueError:
                continue
            blocks.append({
                "col": col_idx,
                "date": date.strftime("%Y-%m-%d"),
                "weekday": date.weekday(),  # 0=월 ... 6=일
                "label": str(raw).strip(),
            })
        if blocks:
            break  # 날짜를 찾은 행 하나만 씁니다
    blocks.sort(key=lambda b: b["col"])
    return blocks


def read_tangbisil_sheet(spreadsheet_id, title, access_token, with_colors=True):
    """탕비실 한 달치 탭을 읽어서 {items, days, ...} 형태로 돌려줍니다."""
    rows = get_values(spreadsheet_id, title, access_token)
    if not rows:
        return None

    header = rows[TANGBISIL_HEADER_ROW - 1] if len(rows) >= TANGBISIL_HEADER_ROW else []
    if header and "사용량" not in str(header[2:4]):
        print(f"[주의] {title}: {TANGBISIL_HEADER_ROW}행 헤더가 예상과 다릅니다 -> {header[:6]}")

    items = []
    for row_no in range(TANGBISIL_FIRST_DATA_ROW, len(rows) + 1):
        row = rows[row_no - 1]
        name = cell(row, 0)
        if not name:
            break  # 상품명이 비면 표가 끝난 것으로 봅니다
        items.append({
            "row": row_no,
            "상품명": name,
            "박스당개입수": cell(row, 1),
            "사용량": to_number(cell(row, 2)) or 0,
            "입고량": to_number(cell(row, 3)) or 0,
            "현재고": to_number(cell(row, 4)),
            "전월재고": to_number(cell(row, 5)),
        })

    blocks = detect_day_blocks(rows)
    check_row = rows[TANGBISIL_CHECK_ROW - 1] if len(rows) >= TANGBISIL_CHECK_ROW else []
    days = []
    for block in blocks:
        days.append({
            "date": block["date"],
            "label": block["label"],
            "weekday": block["weekday"],
            "checked": is_checked(cell(check_row, block["col"])),
        })

    colors = []
    if with_colors and items:
        last_row = TANGBISIL_FIRST_DATA_ROW + len(items) - 1
        colors = get_cell_colors(
            spreadsheet_id, title, f"E{TANGBISIL_FIRST_DATA_ROW}:E{last_row}", access_token
        )
    for i, item in enumerate(items):
        item["발주필요"] = is_reddish(colors[i]) if i < len(colors) else False

    return {"title": title, "items": items, "days": days}


def build_tangbisil_data(spreadsheet_id, access_token, meta):
    """이번 달 + 지난 달 탭을 함께 읽어, 전월 대비 사용량 증감과
    '근무일 중 실제 진행한 날 수'까지 계산해서 돌려줍니다."""
    cur_title = find_month_tab(meta, 0)
    prev_title = find_month_tab(meta, -1)

    if cur_title is None:
        available = [s["properties"]["title"] for s in meta.get("sheets", [])]
        print(f"[경고] 탕비실: '{month_title_offset(0)}'에 해당하는 탭을 찾지 못했습니다.")
        print(f"[경고] 이 스프레드시트에 실제로 있는 탭 이름들: {available}")
        return {"items": [], "days": [], "month_title": month_title_offset(0),
                "prev_month_title": prev_title, "workdays_total": 0, "workdays_done": 0}

    current = read_tangbisil_sheet(spreadsheet_id, cur_title, access_token)
    previous = (
        read_tangbisil_sheet(spreadsheet_id, prev_title, access_token, with_colors=False)
        if prev_title else None
    )

    prev_usage = {}
    if previous:
        prev_usage = {i["상품명"]: i["사용량"] for i in previous["items"]}

    for item in current["items"]:
        before = prev_usage.get(item["상품명"])
        item["전월사용량"] = before
        item["사용량증감"] = (item["사용량"] - before) if before is not None else None
        item.pop("row", None)

    # 근무일 = 평일 중 공휴일(법정 + 회사 자체 휴무일)을 뺀 날.
    # 토/일 블록이 시트에 있더라도 평일만 세고, 추석·설날 같은 날은 분모에서 뺍니다.
    year, _ = month_of(0)
    off_days = korean_holidays(year) | EXTRA_HOLIDAYS

    weekday_blocks = [d for d in current["days"] if d["weekday"] < 5]
    for day in current["days"]:
        day["holiday"] = day["date"] in off_days

    workdays = [d for d in weekday_blocks if not d["holiday"]]
    done = [d for d in workdays if d["checked"]]
    skipped = [d for d in weekday_blocks if d["holiday"]]

    print(f"[탕비실] 탭 '{cur_title}' · 상품 {len(current['items'])}개 · "
          f"일자 블록 {len(current['days'])}개(평일 {len(weekday_blocks)}, "
          f"공휴일 {len(skipped)}일 제외 → 근무일 {len(workdays)}) · "
          f"진행 {len(done)}일 · 발주필요 {sum(1 for i in current['items'] if i['발주필요'])}건 · "
          f"전월탭 {prev_title or '없음'}")
    if skipped:
        print(f"[탕비실] 제외된 공휴일: {[d['date'] for d in skipped]}")
    if not current["days"]:
        print("[주의] 탕비실: 일자별 날짜 헤더를 못 찾았습니다. "
              f"{TANGBISIL_DATE_ROWS}행에 '2026-9-7(월)' 형태 날짜가 있는지 확인하세요.")

    return {
        "month_title": cur_title,
        "prev_month_title": prev_title,
        "items": current["items"],
        "days": current["days"],
        "workdays_total": len(workdays),
        "workdays_done": len(done),
        "holidays_excluded": [d["date"] for d in skipped],
    }


# ---------------------------------------------------------------- 일반 시트

def rows_to_records(rows):
    """완전히 빈 선행 행은 건너뛰고, 실제 내용이 있는 첫 행을 헤더(열 이름)로 보고
    나머지 행을 {열이름: 값} 형태로 변환합니다."""
    if not rows:
        return []

    header_idx = 0
    while header_idx < len(rows) and not any(str(c).strip() for c in rows[header_idx]):
        header_idx += 1
    if header_idx >= len(rows):
        return []

    header = rows[header_idx]
    records = []
    for row in rows[header_idx + 1:]:
        if not any(str(c).strip() for c in row):
            continue
        records.append({
            name: (row[i] if i < len(row) else "") for i, name in enumerate(header)
        })
    return records


# ---------------------------------------------------------------- 메인

def main():
    with open("config/sources.json", encoding="utf-8") as f:
        config = json.load(f)

    access_token = get_access_token()
    meta_cache = {}
    data = {}

    for key, source in config["sources"].items():
        spreadsheet_id = source["spreadsheet_id"]
        if spreadsheet_id not in meta_cache:
            meta_cache[spreadsheet_id] = get_spreadsheet_meta(spreadsheet_id, access_token)
        meta = meta_cache[spreadsheet_id]

        if key == "tangbisil":
            # 탕비실은 처리가 복잡해서, 여기서 문제가 생겨도 다른 카테고리는
            # 정상적으로 갱신되도록 오류를 가둬둡니다. 원인은 로그에 남깁니다.
            try:
                data[key] = build_tangbisil_data(spreadsheet_id, access_token, meta)
            except Exception:
                import traceback
                print(f"[오류] 탕비실 처리 중 문제가 발생했습니다. 아래 내용을 확인하세요.")
                traceback.print_exc()
                data[key] = {"items": [], "days": [], "month_title": current_month_title(),
                             "prev_month_title": None,
                             "workdays_total": 0, "workdays_done": 0}
            continue

        if source.get("dynamic_month"):
            title = find_month_tab(meta, 0)
            if title is None:
                available = [s["properties"]["title"] for s in meta.get("sheets", [])]
                print(f"[경고] {key}: '{current_month_title()}' 탭을 찾지 못했습니다. "
                      f"실제 탭 목록: {available}")
                data[key] = []
                continue
        else:
            title = find_title_by_gid(meta, source["gid"])
            if title is None:
                print(f"[경고] {key}: gid {source['gid']} 탭을 찾지 못했습니다.")
                data[key] = []
                continue

        records = rows_to_records(get_values(spreadsheet_id, title, access_token))
        data[key] = records
        print(f"[완료] {key} ({title}): {len(records)}건")

    passphrase = os.environ["WORKBOARD_PIN"]
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "data": data}
    encrypted = encrypt_json(payload, passphrase)
    encrypted["content_hash"] = content_fingerprint(data, passphrase)

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(encrypted, f, ensure_ascii=False)

    size_mb = os.path.getsize(OUTPUT_PATH) / 1024 / 1024
    print(f"{OUTPUT_PATH} 저장 완료 (암호화됨, {size_mb:.1f}MB). Pages로 배포합니다.")


if __name__ == "__main__":
    main()
