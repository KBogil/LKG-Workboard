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

# 소모품 "월별 불출량&검수" 시트 (가로로 월 블록이 이어지는 형태)
SOMOPUM_LABEL_ROW = 2       # 2행: "9월" 같은 월 표시와 "월별 불출량" 같은 구역 제목
SOMOPUM_HEADER_ROW = 3      # 3행: 품목 / 수량 / 재고 같은 열 이름
SOMOPUM_FIRST_DATA_ROW = 4  # 4행부터 데이터

MONTH_LABEL_RE = re.compile(r"^\s*(\d{1,2})\s*월\s*$")


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


# ------------------------------------------------ 소모품 월별 불출량 & 재고

def sheet_row(rows, one_based):
    """1부터 세는 행 번호로 행을 꺼냅니다. 없으면 빈 리스트."""
    idx = one_based - 1
    return rows[idx] if 0 <= idx < len(rows) else []


def label_positions(row, start, end):
    """구간 안에서 '글자가 적힌 칸'의 위치와 내용을 순서대로 돌려줍니다.
    병합된 제목은 맨 왼쪽 칸에만 값이 들어오므로, 이 위치가 곧 구역의 시작입니다."""
    found = []
    for i in range(start, min(end, len(row))):
        text = clean_cell(row[i])
        if text:
            found.append((i, text))
    return found


def find_col(head_row, start, end, *keywords, exclude=()):
    """구간 안에서 열 이름에 keyword가 들어간 첫 번째 열 번호를 찾습니다."""
    for i in range(start, min(end, len(head_row))):
        name = clean_cell(head_row[i]).replace(" ", "").replace("\n", "")
        if not name:
            continue
        if any(x in name for x in exclude):
            continue
        if any(k in name for k in keywords):
            return i
    return None


def build_somopum_stock(rows):
    """가로로 월 블록이 이어지는 시트를 월별 품목 목록으로 바꿉니다.

    한 달 블록은 보통 세 구역으로 나뉩니다.
      - "월별 불출량"      : 품목 / 수량(=불출량) / 평균
      - "상시 수량 조사"   : 재고 수량_ea 기준(=잔여 재고) / 입고 수량   (왼쪽 품목 행과 같은 줄)
      - "N월 재고 조사"    : No. / 품목 / N월 재고 / 실물 재고 / 불출수량
    열 위치는 달마다 다르므로 하드코딩하지 않고, 2행의 제목을 보고 매번 찾아냅니다.
    """
    label_row = sheet_row(rows, SOMOPUM_LABEL_ROW)
    head_row = sheet_row(rows, SOMOPUM_HEADER_ROW)
    if not label_row:
        return {"months": [], "note": "2행에서 월 표시를 찾지 못했습니다."}

    # 2행에서 "9월"처럼 월만 적힌 칸 = 그 달 블록의 시작
    anchors = []
    for i in range(len(label_row)):
        m = MONTH_LABEL_RE.match(clean_cell(label_row[i]))
        if m:
            anchors.append((i, int(m.group(1))))

    if not anchors:
        return {"months": [], "note": "2행에서 'N월' 형태의 칸을 찾지 못했습니다."}

    months = []
    for pos, (start, month_no) in enumerate(anchors):
        end = anchors[pos + 1][0] if pos + 1 < len(anchors) else len(head_row)

        # 블록 안의 구역 제목 위치 (월 표시 칸 자신은 제외)
        subs = [(i, t) for i, t in label_positions(label_row, start, end)
                if not MONTH_LABEL_RE.match(t)]

        def sub_range(*keywords, avoid=()):
            for idx, (col, text) in enumerate(subs):
                flat = text.replace(" ", "")
                if any(a in flat for a in avoid):
                    continue
                if any(k in flat for k in keywords):
                    stop = subs[idx + 1][0] if idx + 1 < len(subs) else end
                    return col, stop
            return None

        usage = sub_range("불출량")
        live = sub_range("수량조사")
        audit = sub_range("재고조사")

        items = {}   # 품목 -> 값 모음 (같은 품목이 두 구역에 나오므로 합쳐 담습니다)
        order = []

        def slot(name):
            if name not in items:
                items[name] = {"품목": name}
                order.append(name)
            return items[name]

        # ① 월별 불출량 (+ 같은 줄의 상시 수량 조사)
        if usage:
            u0, u1 = usage
            c_item = find_col(head_row, u0, u1, "품목")
            c_qty = find_col(head_row, u0, u1, "수량")
            c_avg = find_col(head_row, u0, u1, "평균")
            c_stock = c_in = None
            if live:
                l0, l1 = live
                c_stock = find_col(head_row, l0, l1, "재고")
                # "재고 수량 ... + 입고수량" 처럼 재고 열 이름에도 '입고'가 들어있어서,
                # 재고라는 말이 없는 열에서만 '입고'를 찾습니다.
                c_in = find_col(head_row, l0, l1, "입고", exclude=("재고",))
                if c_in is None and c_stock is not None and c_stock + 1 < l1:
                    c_in = c_stock + 1
            if c_item is not None:
                for row in rows[SOMOPUM_FIRST_DATA_ROW - 1:]:
                    name = clean_cell(cell(row, c_item))
                    if not name:
                        continue
                    it = slot(name)
                    it["불출량"] = to_number(cell(row, c_qty)) if c_qty is not None else None
                    it["평균"] = to_number(cell(row, c_avg)) if c_avg is not None else None
                    # "재고 수량_ea 기준 (잔여수량 + 입고수량)" 열이 실제 잔여 재고입니다.
                    if c_stock is not None:
                        it["잔여재고"] = to_number(cell(row, c_stock))
                    if c_in is not None:
                        it["입고수량"] = to_number(cell(row, c_in))

        # ② N월 재고 조사
        # 실물 재고 조사는 현장에서 눈으로 세는 값이라 대시보드에는 싣지 않습니다.
        # 여기서는 왼쪽 블록에 잔여 재고가 비어 있을 때만 'N월 재고'로 채웁니다.
        if audit:
            a0, a1 = audit
            c_item = find_col(head_row, a0, a1, "품목")
            c_remain = find_col(head_row, a0, a1, "재고", exclude=("실물",))
            if c_item is not None and c_remain is not None:
                for row in rows[SOMOPUM_FIRST_DATA_ROW - 1:]:
                    name = clean_cell(cell(row, c_item))
                    if not name:
                        continue
                    it = slot(name)
                    if it.get("잔여재고") is None:
                        it["잔여재고"] = to_number(cell(row, c_remain))

        rows_out = [items[n] for n in order]
        # 값이 하나도 없는(이름만 있는) 품목은 버립니다
        rows_out = [r for r in rows_out
                    if any(v is not None for k, v in r.items() if k != "품목")]
        if rows_out:
            months.append({"month": month_no, "label": f"{month_no}월", "items": rows_out})

    months.sort(key=lambda m: m["month"])
    return {"months": months, "latest": months[-1]["label"] if months else None}


# ---------------------------------------------------------------- 일반 시트

# 구글 시트의 수식 오류 값들. 값이 아니라 오류이므로 빈 칸으로 취급합니다.
SHEET_ERRORS = {"#REF!", "#N/A", "#VALUE!", "#DIV/0!", "#NAME?", "#NULL!",
                "#NUM!", "#ERROR!", "#SPILL!", "#CALC!"}

HEADER_SEARCH_ROWS = 12  # 헤더는 아무리 늦어도 이 안에 있다고 봅니다

# 이 값들만 들어 있는 행은 '빈 행'으로 봅니다. 체크박스는 값이 없어도 FALSE로 나옵니다.
CHECKBOX_ONLY = {"FALSE", "TRUE"}


def clean_cell(value):
    """셀 값을 정리합니다. 수식 오류는 빈 문자열로 바꿉니다."""
    text = str(value).strip()
    return "" if text in SHEET_ERRORS else text


def find_header_row(rows):
    """헤더 행을 찾습니다.

    첫 번째 '내용 있는 행'을 헤더로 쓰면, 시트 위쪽에 안내 문구(병합된 빨간 글씨 등)가
    있는 경우 그것을 열 이름으로 잘못 잡습니다. 헤더는 보통 칸이 촘촘히 채워져 있으므로,
    앞쪽 몇 행 중 '채워진 칸이 가장 많은 행'을 헤더로 봅니다.
    """
    best_idx, best_count = None, 0
    for idx, row in enumerate(rows[:HEADER_SEARCH_ROWS]):
        count = sum(1 for c in row if clean_cell(c))
        if count > best_count:
            best_idx, best_count = idx, count
    return best_idx


def rows_to_records(rows):
    """시트를 {열이름: 값} 목록으로 변환합니다.

    - 안내 문구 행을 헤더로 잘못 잡지 않도록 가장 촘촘한 행을 헤더로 씁니다.
    - 이름이 없는 열은 버립니다.
    - 수식 오류(#REF! 등)만 남은 행이나 완전히 빈 행은 버립니다.
      (시트 아래쪽에 수식만 늘어서 있는 수천 개의 빈 행이 그대로 딸려오는 것을 막습니다)
    - 체크박스 열의 FALSE/TRUE만 남은 행도 빈 행으로 봅니다.
      자산 지급대장처럼 '시트 반영' 체크박스가 시트 끝까지 깔려 있으면,
      내용이 없는 행에도 FALSE가 들어 있어서 수천 건이 그대로 딸려옵니다.
    """
    if not rows:
        return []

    header_idx = find_header_row(rows)
    if header_idx is None:
        return []

    header = [clean_cell(c) for c in rows[header_idx]]
    named = [(i, name) for i, name in enumerate(header) if name]
    if not named:
        return []

    records = []
    for row in rows[header_idx + 1:]:
        record = {name: clean_cell(row[i]) if i < len(row) else "" for i, name in named}
        # 체크박스 값(FALSE/TRUE)은 '내용'으로 치지 않습니다.
        meaningful = [
            v for v in record.values()
            if v and str(v).strip().upper() not in CHECKBOX_ONLY
        ]
        if not meaningful:
            continue  # 내용이 하나도 없는 행 (오류만·체크박스만 있던 행 포함)
        records.append(record)
    return records


# ------------------------------------------------ 공지 / 스케줄 (한 탭 두 구역)

# 한 탭 안에서 A~D열은 공지, F~J열은 스케줄로 나뉘어 있습니다(E열은 구분용 빈 열).
BOARD_NOTICE_COLS = (0, 4)     # A, B, C, D
BOARD_SCHEDULE_COLS = (5, 10)  # F, G, H, I, J


def slice_cols(rows, start, end):
    """행마다 지정한 열 구간만 잘라냅니다. 짧은 행은 빈 행으로 둡니다."""
    out = []
    for row in rows:
        out.append(row[start:end] if len(row) > start else [])
    return out


def build_board(rows):
    """공지 구역과 스케줄 구역을 각각 따로 표로 읽습니다.
    구역별로 헤더를 따로 찾기 때문에, 두 구역의 헤더 줄이 달라도 됩니다."""
    return {
        "notice": rows_to_records(slice_cols(rows, *BOARD_NOTICE_COLS)),
        "schedule": rows_to_records(slice_cols(rows, *BOARD_SCHEDULE_COLS)),
    }


# ---------------------------------------------------------------- 메인

def main():
    with open("config/sources.json", encoding="utf-8") as f:
        config = json.load(f)

    access_token = get_access_token()
    meta_cache = {}
    data = {}

    failed = []

    for key, source in config["sources"].items():
        try:
            load_source(key, source, access_token, meta_cache, data)
        except Exception:
            # 시트 하나가 문제여도(권한 없음, 탭 삭제, 서식 변경 등) 나머지는 계속 갱신되도록
            # 여기서 오류를 가둡니다. 이렇게 하지 않으면 워크플로 전체가 실패하고
            # 매 실행마다 실패 알림 메일이 옵니다.
            import traceback
            print(f"[오류] {key}: 이 시트를 읽지 못했습니다. 아래 내용을 확인하세요.")
            traceback.print_exc()
            failed.append(key)
            data.setdefault(key, [])

    if failed:
        print(f"[요약] 읽지 못한 시트: {failed} — 나머지는 정상 갱신했습니다.")

    save_output(data)


def load_source(key, source, access_token, meta_cache, data):
    """source 하나를 읽어 data에 담습니다. 문제가 생기면 예외를 그대로 올려보냅니다."""
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
        return

    if source.get("dynamic_month"):
        title = find_month_tab(meta, 0)
        if title is None:
            available = [s["properties"]["title"] for s in meta.get("sheets", [])]
            print(f"[경고] {key}: '{current_month_title()}' 탭을 찾지 못했습니다. "
                  f"실제 탭 목록: {available}")
            data[key] = []
            return
    else:
        title = find_title_by_gid(meta, source["gid"])
        if title is None:
            print(f"[경고] {key}: gid {source['gid']} 탭을 찾지 못했습니다.")
            data[key] = []
            return

    rows = get_values(spreadsheet_id, title, access_token)

    if source.get("special") == "board":
        # 공지 + 스케줄이 한 탭에 좌우로 나뉘어 있어 전용 처리를 탑니다.
        try:
            board = build_board(rows)
        except Exception:
            import traceback
            print("[오류] 공지/스케줄 시트 처리 중 문제가 발생했습니다.")
            traceback.print_exc()
            board = {"notice": [], "schedule": []}
        data["notice"] = board["notice"]
        data["schedule"] = board["schedule"]
        # 열 이름을 로그에 남겨둡니다. 화면에 값이 안 뜨면 여기부터 확인하세요.
        n_cols = list(board["notice"][0].keys()) if board["notice"] else []
        s_cols = list(board["schedule"][0].keys()) if board["schedule"] else []
        print(f"[완료] {key} ({title}): 공지 {len(board['notice'])}건 {n_cols} · "
              f"스케줄 {len(board['schedule'])}건 {s_cols}")
        return

    if source.get("special") == "somopum_stock":
        # 가로로 월 블록이 이어지는 시트라 전용 처리를 탑니다.
        try:
            stock = build_somopum_stock(rows)
        except Exception:
            import traceback
            print("[오류] 소모품 월별 불출량 시트 처리 중 문제가 발생했습니다.")
            traceback.print_exc()
            stock = {"months": []}
        data[key] = stock
        summary = ", ".join(f"{m['label']} {len(m['items'])}품목" for m in stock["months"])
        print(f"[완료] {key} ({title}): {summary or stock.get('note', '읽은 월 없음')}")
        return

    records = rows_to_records(rows)
    data[key] = records
    print(f"[완료] {key} ({title}): {len(records)}건")


def save_output(data):
    # 달력에서 주말·공휴일을 회색으로 칠하려면 브라우저도 공휴일을 알아야 해서,
    # 파이썬이 계산한 올해·내년 공휴일 목록을 같이 담아 보냅니다.
    this_year, _ = month_of(0)
    data["holidays"] = sorted(
        korean_holidays(this_year) | korean_holidays(this_year + 1) | EXTRA_HOLIDAYS
    )

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
