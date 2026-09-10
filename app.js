/* LKG Workboard - app.js
   암호화된 data/workboard.json 을 불러와서, 비밀번호 입력 후 복호화하여
   사이드바 카테고리별 화면을 그립니다. */

const DATA_URL = "./data/workboard.json";

let WORKBOARD = null; // 복호화된 { generated_at, data: { key: [records...] } }

const els = {
  sidebar: document.getElementById("sidebar"),
  hamburgerBtn: document.getElementById("hamburgerBtn"),
  navItems: document.querySelectorAll(".nav-item"),
  pageTitle: document.getElementById("pageTitle"),
  content: document.getElementById("content"),
  lastUpdated: document.getElementById("lastUpdated"),
  lockOverlay: document.getElementById("lockOverlay"),
  appRoot: document.getElementById("appRoot"),
  pinInput: document.getElementById("pinInput"),
  pinSubmit: document.getElementById("pinSubmit"),
  pinSpinner: document.getElementById("pinSpinner"),
  pinSubmitLabel: document.getElementById("pinSubmitLabel"),
  lockError: document.getElementById("lockError"),
  modalBackdrop: document.getElementById("modalBackdrop"),
  modalTitle: document.getElementById("modalTitle"),
  modalBody: document.getElementById("modalBody"),
  modalClose: document.getElementById("modalClose"),
  adminBadge: document.getElementById("adminBadge"),
  refreshPill: document.getElementById("refreshPill"),
};

let ENCRYPTED_BLOB = null;
let MAIL_MODAL_KIND = null; // 메일룸 팝업이 열려 있으면 그 대장 키
let CURRENT_VIEW = "overview";

/* 팝업에서 '이전/다음' 행으로 넘어가기 위한 정보.
   팝업을 새로 열 때마다 지워지고, 행 상세를 그린 쪽에서 다시 채웁니다.
   (지워두지 않으면 다른 종류의 팝업에서 방향키가 엉뚱한 행을 엽니다) */
let MODAL_NAV = null;

/* 행을 누른 표의 '화면에 보이는 순서'. 정렬을 바꿔 놓은 뒤에도
   '다음'이 화면에서 아래 있는 행이 되도록 기억해 둡니다. */
let NAV_ORDER = null;

/* 자동 갱신에 쓰려고 비밀번호를 기억해 둡니다.
   브라우저 메모리에만 있고 저장·전송되지 않습니다 (탭을 닫으면 사라집니다). */
let PASSPHRASE = null;

/* ---------------- 암호화/복호화 유틸 ---------------- */

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase, saltB64, iterations) {
  const enc = new TextEncoder();
  const salt = base64ToBytes(saltB64);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptBlob(blob, passphrase) {
  const key = await deriveKey(passphrase, blob.salt, blob.iterations);
  const iv = base64ToBytes(blob.iv);
  const ciphertext = base64ToBytes(blob.ciphertext);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

/* ---------------- 잠금 화면 처리 ---------------- */

/* 확인을 누르고 대시보드가 열릴 때까지 실제로 3~10초가 걸립니다
   (PBKDF2 60만 회로 키를 만들고, 약 4MB를 복호화한 뒤 JSON 으로 바꿉니다).
   예전에는 그동안 버튼이 흐려지기만 해서 눌린 건지 알 수 없었고,
   저사양 PC에서는 다시 누르게 되는 일이 있었습니다.
   그래서 버튼 글자를 두 단계로 바꿔 진행 중임을 알립니다. */
let UNLOCK_STAGE_TIMER = null;

function setUnlockBusy(busy) {
  els.pinSubmit.disabled = busy;
  els.pinInput.disabled = busy;
  els.pinSpinner.hidden = !busy;
  els.pinSubmitLabel.textContent = busy ? "확인 중…" : "확인";

  // 타이머는 매번 지우고 다시 겁니다. 안 지우면 실패한 뒤에도
  // 예전 타이머가 살아 있어 글자가 엉뚱하게 바뀝니다.
  if (UNLOCK_STAGE_TIMER) {
    clearTimeout(UNLOCK_STAGE_TIMER);
    UNLOCK_STAGE_TIMER = null;
  }
  if (busy) {
    // 1.5초가 지나도 안 끝나면 "멈춘 게 아니라 큰 파일을 여는 중"이라고 알립니다.
    UNLOCK_STAGE_TIMER = setTimeout(() => {
      els.pinSubmitLabel.textContent = "데이터를 여는 중입니다";
    }, 1500);
  }
}

/* 화면을 한 번 그리게 한 뒤에 무거운 일을 시작합니다.
   복호화 뒤의 JSON.parse(수 MB)가 메인 스레드를 막기 때문에,
   이 한 박자가 없으면 버튼 글자가 바뀌기도 전에 화면이 굳어서
   위에서 바꾼 문구가 사용자에게 보이지 않습니다. */
function nextPaint() {
  return new Promise((resolve) => {
    requestAnimationFrame(() => setTimeout(resolve, 0));
  });
}

async function tryUnlock() {
  const pin = els.pinInput.value;
  if (!pin) return;

  // 데이터 파일을 아직 못 받았으면 복호화를 시도조차 하지 않습니다.
  // 예전에는 그냥 시도했다가 예외가 나서, 맞는 비밀번호인데도
  // "비밀번호가 올바르지 않습니다"가 떴습니다.
  if (!ENCRYPTED_BLOB) {
    els.lockError.textContent = "데이터를 아직 받는 중입니다. 잠시 뒤 다시 눌러 주세요.";
    return;
  }

  els.lockError.textContent = "";
  setUnlockBusy(true);
  await nextPaint();

  try {
    WORKBOARD = await decryptBlob(ENCRYPTED_BLOB, pin);
    PASSPHRASE = pin;
    els.lockOverlay.style.display = "none";
    els.appRoot.style.display = "";
    els.lastUpdated.textContent = "마지막 업데이트: " + formatDateTime(WORKBOARD.generated_at);
    // 주소에 #jeonsan 처럼 화면 이름이 남아 있으면 그 화면부터 엽니다.
    // (새로고침하거나 즐겨찾기로 들어와도 보던 화면이 유지됩니다)
    applyView(viewFromHash() || "overview", true);
    refreshAdminBadge();
    startAutoRefresh();
  } catch (err) {
    els.lockError.textContent = "비밀번호가 올바르지 않습니다.";
  } finally {
    setUnlockBusy(false);
    // 입력칸을 잠갔다 푸는 사이에 초점이 날아갑니다.
    // 잠금 화면이 그대로면(=실패) 초점을 돌려줘야 Enter 로 바로 다시 시도할 수 있습니다.
    if (els.lockOverlay.style.display !== "none") els.pinInput.focus();
  }
}

els.pinSubmit.addEventListener("click", tryUnlock);
els.pinInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") tryUnlock();
});

const VIEW_TITLES = {
  overview: "개요",
  jeonsan: "전산 관리",
  tangbisil: "탕비실 관리",
  somopum: "소모품 관리",
  vehicle: "법인차량 관리",
  mail: "메일룸 관리",
  plant: "플랜트박스 관리",
  annual: "연간 통계",
  admin: "관리자 알림",
};

/* ---------------- 초기화 ---------------- */

els.hamburgerBtn.addEventListener("click", () => {
  els.sidebar.classList.toggle("collapsed");
});

/* ---------------- 화면 주소 기억 (#jeonsan) ---------------- */

/* 주소 끝의 #이름을 읽습니다. 우리가 아는 화면 이름이 아니면 null.
   (남이 보낸 이상한 주소로 빈 화면이 뜨는 것을 막습니다) */
function viewFromHash() {
  const name = decodeURIComponent(String(location.hash || "").replace(/^#/, "")).trim();
  return VIEW_TITLES[name] ? name : null;
}

/* 화면 하나를 여는 유일한 통로입니다. 사이드바 표시 · 제목 · 주소(#)를 함께 맞춥니다.
   writeHash=false 는 '주소가 이미 그 화면이라 다시 쓸 필요가 없을 때'(뒤로 가기 등)입니다. */
function applyView(view, writeHash) {
  if (!VIEW_TITLES[view]) view = "overview";
  els.navItems.forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  els.pageTitle.textContent = VIEW_TITLES[view] || "";
  renderView(view);
  if (writeHash && location.hash.replace(/^#/, "") !== view) {
    // 처음 들어올 때(주소에 #이 없을 때)는 방문 기록을 남기지 않고 조용히 바꿉니다.
    // 그래야 뒤로 가기를 눌렀을 때 대시보드 안에서 헛걸음하지 않습니다.
    if (!location.hash) history.replaceState(null, "", "#" + view);
    else location.hash = view;
  }
}

els.navItems.forEach((btn) => {
  btn.addEventListener("click", () => applyView(btn.dataset.view, true));
});

/* 뒤로/앞으로 가기, 주소를 직접 고친 경우.
   지금 보고 있는 화면과 같으면 다시 그리지 않습니다(사이드바 클릭 때 두 번 그리는 것 방지). */
window.addEventListener("hashchange", () => {
  if (!PASSPHRASE) return; // 아직 잠금 화면이면 나중에 열 때 반영됩니다
  const view = viewFromHash() || "overview";
  if (view !== CURRENT_VIEW) applyView(view, false);
});

async function init() {
  try {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) throw new Error("데이터를 불러오지 못했습니다.");
    ENCRYPTED_BLOB = await res.json();
    // 파일을 다 받은 지금에서야 입력을 엽니다(index.html 의 disabled 주석 참고).
    els.pinInput.disabled = false;
    els.pinSubmit.disabled = false;
    els.pinInput.placeholder = "비밀번호";
    els.pinInput.focus();
  } catch (err) {
    // 여기서 실패한 것은 비밀번호 문제가 아니므로 문구를 구분합니다.
    // 입력칸은 잠근 채로 둡니다(눌러 봐야 안 되니까요).
    els.pinInput.placeholder = "데이터를 불러오지 못했습니다";
    els.lockError.textContent =
      "데이터 파일을 불러오지 못했습니다. 새로고침해 주세요. (" + err.message + ")";
  }
}

function formatDateTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  const kst = new Date(d.getTime() + 9 * 60 * 60 * 1000);
  const y = kst.getUTCFullYear();
  const m = String(kst.getUTCMonth() + 1).padStart(2, "0");
  const day = String(kst.getUTCDate()).padStart(2, "0");
  const hh = String(kst.getUTCHours()).padStart(2, "0");
  const mm = String(kst.getUTCMinutes()).padStart(2, "0");
  return `${y}.${m}.${day} ${hh}:${mm}`;
}

/* ---------------- 상세 팝업 ---------------- */

function openModal(title, bodyHtml) {
  MAIL_MODAL_KIND = null; // 메일룸 팝업이 아니면 그쪽 클릭 처리를 꺼둡니다
  MODAL_NAV = null; // 이전/다음도 마찬가지. 상세를 그린 쪽에서 다시 켭니다
  els.modalTitle.textContent = title;
  els.modalBody.innerHTML = bodyHtml;
  els.modalBackdrop.hidden = false;
  document.body.classList.add("modal-open");
  els.modalClose.focus();
}

function closeModal() {
  els.modalBackdrop.hidden = true;
  els.modalBody.innerHTML = "";
  document.body.classList.remove("modal-open");
}

els.modalClose.addEventListener("click", closeModal);
els.modalBackdrop.addEventListener("click", (e) => {
  // 팝업 바깥(어두운 배경)을 눌렀을 때만 닫습니다.
  if (e.target === els.modalBackdrop) closeModal();
});
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !els.modalBackdrop.hidden) closeModal();
});

/* ---------------- 팝업 안에서 이전/다음 행 ---------------- */

/* 상세 팝업 맨 위에 붙는 이동 줄.
   위치를 "3 / 12" 글자로 같이 적어, 버튼이 흐려진 것만으로 끝을 알리지 않게 합니다. */
function navBar(pos, total) {
  if (!total || total < 2) return "";
  return `<div class="row-nav">
    <button class="row-nav-btn" data-row-nav="-1" ${pos <= 1 ? "disabled" : ""}
            title="이전 행 (← 방향키)">◀ 이전</button>
    <span class="row-nav-pos">${pos} / ${total}</span>
    <button class="row-nav-btn" data-row-nav="1" ${pos >= total ? "disabled" : ""}
            title="다음 행 (→ 방향키)">다음 ▶</button>
  </div>`;
}

/* 표시 순서(NAV_ORDER)가 있으면 그 순서로, 없으면 자료에 담긴 순서로 셉니다. */
function navSequence(total) {
  return NAV_ORDER && NAV_ORDER.length === total
    ? NAV_ORDER
    : Array.from({ length: total }, (_, i) => i);
}

function navPosition(index, total) {
  const seq = navSequence(total);
  const at = seq.indexOf(index);
  return { pos: (at === -1 ? index : at) + 1, total };
}

/* 지금 보고 있는 행에서 step(-1/1)만큼 움직인 '원래 행 번호'. 끝이면 null. */
function navStep(index, step, total) {
  const seq = navSequence(total);
  const at = seq.indexOf(index);
  const next = at === -1 ? index + step : seq[at + step];
  return next === undefined || next === null ? null : next;
}

/* 팝업 종류마다 '다음 행'을 여는 방법이 달라서 한곳에 모아둡니다. */
function stepModalRow(step) {
  const nav = MODAL_NAV;
  if (!nav) return;

  if (nav.mode === "table") {
    const state = TABLE_REGISTRY[nav.tableId];
    if (!state) return;
    const at = state.order.indexOf(nav.index);
    const next = state.order[at + step];
    if (next === undefined) return;
    openTableRowModal(state, next);
    return;
  }

  if (nav.mode === "tangbisil") {
    const next = nav.index + step;
    if (next < 0 || next >= TB_ITEMS.length) return;
    openTangbisilItem(TB_ITEMS[next], next);
    return;
  }

  if (nav.mode === "crew") {
    const active = crewMatches(CREW_QUERY)
      .filter((g) => g.rows.length)
      .find((g) => g.key === CREW_TAB);
    if (!active || CREW_ROW === null) return;
    const next = navStep(CREW_ROW, step, active.rows.length);
    if (next === null) return;
    CREW_ROW = next;
    refreshCrewModal();
    return;
  }

  if (nav.mode === "somopum") {
    if (SOM_ROW === null) return;
    const next = navStep(SOM_ROW, step, SOM_MATCH.length);
    if (next === null) return;
    SOM_ROW = next;
    refreshSomModal();
    return;
  }

  if (nav.mode === "mail") {
    const kind = nav.kind;
    const state = MAIL_STATE[kind];
    if (!state || state.row === null) return;
    const next = navStep(state.row, step, state.match.length);
    if (next === null) return;
    state.row = next;
    refreshMailModal(kind);
  }
}

els.modalBody.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-row-nav]");
  if (btn) stepModalRow(Number(btn.dataset.rowNav));
});

/* 방향키로도 넘길 수 있게 합니다. 글자를 입력하는 중에는 끄고요. */
window.addEventListener("keydown", (e) => {
  if (els.modalBackdrop.hidden || !MODAL_NAV) return;
  const tag = document.activeElement ? document.activeElement.tagName : "";
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
  if (e.key === "ArrowLeft") {
    e.preventDefault();
    stepModalRow(-1);
  } else if (e.key === "ArrowRight") {
    e.preventDefault();
    stepModalRow(1);
  }
});

/* 레코드 하나를 "항목: 값" 목록으로 펼쳐 보여줍니다. */
function recordDetailHtml(record) {
  const rows = Object.entries(record)
    .filter(([k]) => k && k.trim())
    .map(([k, v]) => {
      const value = v === null || v === undefined || v === "" ? "-" : String(v);
      return `<div class="detail-row">
        <div class="detail-key">${escapeHtml(k)}</div>
        <div class="detail-value">${escapeHtml(value)}</div>
      </div>`;
    })
    .join("");
  return `<div class="detail-list">${rows}</div>`;
}

/* ---------------- 공용 유틸 ---------------- */

function getRecords(key) {
  if (!WORKBOARD || !WORKBOARD.data) return [];
  const value = WORKBOARD.data[key];
  return Array.isArray(value) ? value : [];
}

/* 탕비실처럼 배열이 아니라 객체({items, days, ...})로 들어오는 데이터를 꺼냅니다. */
function getObject(key) {
  if (!WORKBOARD || !WORKBOARD.data) return null;
  const value = WORKBOARD.data[key];
  return value && !Array.isArray(value) ? value : null;
}

function getTangbisil() {
  return (
    getObject("tangbisil") || {
      items: [],
      days: [],
      workdays_total: 0,
      workdays_done: 0,
      holidays_excluded: [],
      month_title: "",
      prev_month_title: null,
    }
  );
}

function countBy(records, field) {
  const map = {};
  records.forEach((r) => {
    const v = (r[field] || "").trim();
    if (!v) return;
    map[v] = (map[v] || 0) + 1;
  });
  return Object.entries(map).sort((a, b) => b[1] - a[1]);
}

/* "이재환(Jetty) 정성훈(Martin)" 처럼 담당자 셀 하나에 여러 명이 들어있는 경우,
   "이름(영문)" 단위로 쪼갭니다. */
function splitNames(raw) {
  const text = (raw || "").trim();
  if (!text) return [];
  return text.match(/[^\s,\/、]+\([^()]*\)/g) || [text];
}

function countByMultiName(records, field) {
  const map = {};
  records.forEach((r) => {
    splitNames(r[field]).forEach((n) => {
      map[n] = (map[n] || 0) + 1;
    });
  });
  return Object.entries(map).sort((a, b) => b[1] - a[1]);
}

/* "이재환(Jetty)" -> { name: "이재환", nick: "Jetty" } */
function parsePerson(label) {
  const m = String(label).match(/^(.*?)\s*\(([^()]*)\)\s*$/);
  return m ? { name: m[1].trim(), nick: m[2].trim() } : { name: String(label).trim(), nick: "" };
}

/* "2026. 9. 1" 같은 날짜 문자열을 Date 객체로 변환. 형식이 안 맞으면 null. */
function parseKDate(str) {
  if (!str) return null;
  const m = String(str).trim().match(/^(\d{2,4})[.\-/]\s*(\d{1,2})[.\-/]\s*(\d{1,2})/);
  if (!m) return null;
  let year = Number(m[1]);
  if (year < 100) year += 2000; // "26. 09. 01" -> 2026년
  return new Date(year, Number(m[2]) - 1, Number(m[3]));
}

function monthKey(date) {
  return `${date.getFullYear()}.${String(date.getMonth() + 1).padStart(2, "0")}`;
}

function isSameMonth(d, ref) {
  return d && d.getFullYear() === ref.getFullYear() && d.getMonth() === ref.getMonth();
}

/* 전산 데이터를 요청일자(없으면 완료일자) 기준으로 이번 달만 필터링 */
function filterCurrentMonthJeonsan(records) {
  const now = new Date();
  return records.filter((r) => {
    const d = parseKDate(r["요청일자"]) || parseKDate(r["완료일자"]);
    return isSameMonth(d, now);
  });
}

/* 날짜 열 이름을 모르는 카테고리용: "일자"/"날짜"가 들어간 열을 자동으로 찾아 이번 달만 필터.
   그런 열을 못 찾으면 null을 반환합니다 (필터 불가 신호). */
function filterCurrentMonthGeneric(records) {
  if (!records.length) return records;
  const field = Object.keys(records[0]).find((k) => k.includes("일자") || k.includes("날짜"));
  if (!field) return null;
  const now = new Date();
  return records.filter((r) => isSameMonth(parseKDate(r[field]), now));
}

/* 날짜 열을 보고 최신순으로 정렬합니다. 날짜를 못 읽은 행은 뒤로 보냅니다.
   시트에 적힌 순서를 그냥 뒤집으면, 아래쪽 빈 줄이나 나중에 끼워 넣은 행 때문에
   순서가 어긋나기 때문입니다. */
function sortByDateDesc(records, ...fields) {
  return records
    .slice()
    .sort((a, b) => {
      const da = fields.map((f) => parseKDate(pick(a, f))).find(Boolean);
      const db = fields.map((f) => parseKDate(pick(b, f))).find(Boolean);
      return (db ? db.getTime() : 0) - (da ? da.getTime() : 0);
    });
}

function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/* ---------------- 표 ---------------- */

/* 표에 그려진 행과 정렬 상태를 다시 찾아갈 수 있도록 보관합니다.
   화면을 새로 그릴 때마다 비웁니다. */
let TABLE_REGISTRY = {};
let TABLE_SEQ = 0;

/* 한 번에 그릴 행 수. 업무현황 로그·자산 지급대장처럼 수천 건인 표를 전부
   한 번에 그리면 화면을 열 때 눈에 보이게 멈칫합니다. 처음에는 이만큼만 그리고
   '더 보기'로 이어서 붙입니다.
   정렬·검색은 늘 '전체'를 기준으로 하고 보여주는 개수만 자릅니다.
   (반대로 하면 정렬했는데 맨 위에 와야 할 행이 없는 표가 됩니다) */
const TABLE_PAGE = 200;

function isNumericColumn(name) {
  return /수량|건수|개수|사용량|입고량|재고|금액|개입/.test(name);
}

/* 진행상태·전달여부 같은 열은 배지로 그려서 눈에 잘 띄게 합니다.
   반송/반려는 놓치면 안 되는 건이라 가장 강한 색(채워진 빨강)으로 칠합니다. */
function statusCellHtml(value) {
  const text = String(value ?? "").trim();
  if (!text) return "-";
  if (/반송|반려|실패|미전달/.test(text)) {
    return `<span class="badge danger">${escapeHtml(text)}</span>`;
  }
  const done = /완료|정상|반납|지급|전달/.test(text);
  return `<span class="badge ${done ? "done" : "warn"}">${escapeHtml(text)}</span>`;
}

/* 열 이름 비교용으로 단순화합니다.
   시트 헤더에 메모 표시나 이모지, 줄바꿈이 섞여 있어도 같은 열로 보게 하려는 것입니다.
   예: "🟧 업무내용" 과 "업무내용" 을 같은 열로 취급 */
function normalizeColumn(name) {
  return String(name).replace(/[^0-9A-Za-z가-힣()]/g, "").toLowerCase();
}

/* 시트 열 이름이 "불출 대상\n(한글명(영문명)_소속팀명)" 처럼 길고 줄바꿈까지 섞여 있어서,
   기호를 무시하고 이름이 들어간 열을 찾아 값을 꺼냅니다. */
function pick(record, ...names) {
  const keys = Object.keys(record);
  for (const want of names) {
    const target = normalizeColumn(want);
    const hit = keys.find((k) => normalizeColumn(k).includes(target));
    if (hit) return record[hit];
  }
  return "";
}

/* 정렬용 값으로 바꿉니다. 날짜 · 숫자 · 글자를 구분합니다.
   한 표에 "2026. 9. 1", "1,234", "완료"가 섞여 있어서 전부 글자로 비교하면
   10이 9보다 앞에 오고, 날짜도 연-월-일 순서로 서지 않습니다. */
function sortKey(raw) {
  const text = String(raw ?? "").trim();
  if (!text || text === "-") return { empty: true };
  const date = parseKDate(text);
  if (date) return { num: date.getTime() };
  const clean = text.replace(/,/g, "");
  if (/^-?\d+(?:\.\d+)?$/.test(clean)) return { num: Number(clean) };
  return { text };
}

function compareKeys(a, b) {
  if (a.empty || b.empty) {
    if (a.empty && b.empty) return 0;
    return a.empty ? 1 : -1; // 빈 칸은 오름·내림과 상관없이 늘 아래
  }
  if ("num" in a && "num" in b) return a.num - b.num;
  if ("num" in a) return -1; // 숫자 · 날짜를 글자보다 앞에
  if ("num" in b) return 1;
  return a.text.localeCompare(b.text, "ko");
}

/* 표를 실제로 다시 그리지 않고, '그릴 순서'만 새로 만듭니다.
   행 번호(data-row)는 원래 자료의 번호를 그대로 쓰기 때문에,
   정렬을 바꿔도 행을 눌렀을 때 열리는 상세 내용이 어긋나지 않습니다. */
function applyTableSort(state) {
  const base = state.records.map((_, i) => i);
  const col = state.sortCol === null ? null : state.cols[state.sortCol];
  if (!col) {
    state.order = base;
    return;
  }
  const keys = state.records.map((r) => sortKey(r[col]));
  state.order = base.sort((x, y) => {
    const kx = keys[x];
    const ky = keys[y];
    if (kx.empty || ky.empty) return compareKeys(kx, ky) || x - y;
    const d = compareKeys(kx, ky);
    return d !== 0 ? d * state.sortDir : x - y; // 값이 같으면 원래 순서 유지
  });
}

function tableHtml(state) {
  const { id, cols, options, clickable } = state;

  const thead =
    "<tr>" +
    cols
      .map((c, ci) => {
        const on = state.sortCol === ci;
        // 화살표는 색이 아니라 모양으로 구분됩니다. ↕는 '정렬할 수 있다'는 뜻입니다.
        const arrow = on ? (state.sortDir > 0 ? "▲" : "▼") : "↕";
        const aria = on ? (state.sortDir > 0 ? "ascending" : "descending") : "none";
        return `<th class="${isNumericColumn(c) ? "num " : ""}${on ? "sorted" : ""}" aria-sort="${aria}">
          <button class="th-sort" data-sort-table="${id}" data-sort-col="${ci}"
                  title="${escapeHtml(c)} 기준으로 정렬">
            <span class="th-text">${escapeHtml(c)}</span><span class="th-arrow" aria-hidden="true">${arrow}</span>
          </button>
        </th>`;
      })
      .join("") +
    "</tr>";

  const body = rowsHtml(state, visibleOrder(state));

  const sortedNote =
    state.sortCol === null
      ? ""
      : ` 지금은 <strong>${escapeHtml(cols[state.sortCol])}</strong> ${
          state.sortDir > 0 ? "오름차순" : "내림차순"
        }입니다 (한 번 더 누르면 반대, 세 번째에 원래 순서).`;
  const hint = `<div class="table-hint">${
    clickable ? "행을 누르면 전체 내용을 볼 수 있습니다. " : ""
  }열 머리글을 누르면 그 열 기준으로 정렬됩니다.${sortedNote}</div>`;

  const centerClass = options.center ? " center-all" : "";
  return `<div class="table-block" id="${id}">${hint}<div class="table-scroll"><table class="data-table${centerClass}"><thead>${thead}</thead><tbody>${body}</tbody></table></div>${tableMoreHtml(state)}</div>`;
}

/* 지금 화면에 그릴 행 번호들. limit이 0이면 전체를 그립니다. */
function visibleOrder(state) {
  if (!state.limit || state.shown >= state.order.length) return state.order;
  return state.order.slice(0, state.shown);
}

/* 행(<tr>)만 만듭니다. '더 보기'가 이 함수로 다음 묶음만 덧붙입니다.
   (표 전체를 다시 그리면 스크롤 위치가 튀고, 긴 표에서는 멈칫합니다) */
function rowsHtml(state, order) {
  const { id, records, cols, options, clickable } = state;
  return order
    .map((rowIdx) => {
      const r = records[rowIdx];
      const cells = cols
        .map((c) => {
          const raw = r[c] ?? "";
          if (/상태|여부/.test(c)) return `<td>${statusCellHtml(raw)}</td>`;
          const text = raw === "" ? "-" : String(raw);
          // title 속성을 넣어두면 잘린 내용도 마우스를 올려 확인할 수 있습니다.
          return `<td class="${isNumericColumn(c) ? "num" : ""}" title="${escapeHtml(text)}">${escapeHtml(text)}</td>`;
        })
        .join("");
      // 반송 건처럼 눈에 띄어야 하는 행은 rowClass로 배경·왼쪽 띠를 줍니다.
      const rowClass = [
        clickable ? "row-clickable" : "",
        options.rowClass ? options.rowClass(r) || "" : "",
      ]
        .filter(Boolean)
        .join(" ");
      const attrs =
        (rowClass ? ` class="${rowClass}"` : "") +
        (clickable ? ` data-table="${id}" data-row="${rowIdx}"` : "");
      return `<tr${attrs}>${cells}</tr>`;
    })
    .join("");
}

/* 표 아래의 '더 보기' 줄.
   숫자를 글자로 같이 적어둡니다. 버튼만 있으면 "얼마가 남았는지"를 모르고,
   표가 잘려 있다는 사실 자체를 놓치기 쉽습니다. */
function tableMoreHtml(state) {
  const total = state.order.length;
  if (!state.limit || total <= state.limit) return ""; // 짧은 표에는 아무것도 안 붙입니다

  if (state.shown >= total) {
    return `<div class="table-more">
      <span class="table-more-pos">전체 ${total.toLocaleString()}건을 모두 표시했습니다.</span>
    </div>`;
  }

  const left = total - state.shown;
  const next = Math.min(state.limit, left);
  return `<div class="table-more">
    <button class="table-more-btn" data-more-table="${state.id}">
      ${next.toLocaleString()}건 더 보기
    </button>
    <span class="table-more-pos">전체 ${total.toLocaleString()}건 중 ${state.shown.toLocaleString()}건 표시 · 남은 ${left.toLocaleString()}건</span>
  </div>`;
}

function renderTable(records, columns, opts) {
  const options = opts || {};
  if (!records.length) {
    return `<div class="empty-note">${escapeHtml(options.emptyText || "표시할 데이터가 없습니다.")}</div>`;
  }

  // 데이터에 실제로 있는 열 이름을 모읍니다.
  const available = [];
  const seen = new Set();
  records.forEach((r) =>
    Object.keys(r).forEach((k) => {
      if (k && k.trim() && !seen.has(k)) {
        seen.add(k);
        available.push(k);
      }
    })
  );

  // 보고 싶은 열 이름을 실제 열 이름에 느슨하게 맞춥니다.
  const byNormalized = new Map(available.map((k) => [normalizeColumn(k), k]));
  const findColumn = (want) => {
    const target = normalizeColumn(want);
    return (
      byNormalized.get(target) ||
      available.find((k) => normalizeColumn(k).startsWith(target)) ||
      available.find((k) => normalizeColumn(k).includes(target))
    );
  };
  const cols = columns ? columns.map(findColumn).filter(Boolean) : available;
  if (!cols.length) return `<div class="empty-note">표시할 열이 없습니다.</div>`;

  // 정렬을 다시 그릴 때 필요한 것들을 한 덩어리로 보관합니다.
  // (정렬은 화면 전체를 다시 그리지 않고 이 표만 다시 그립니다)
  // limit: 한 번에 그릴 행 수 (options.limit: 0 을 주면 전체를 한 번에 그립니다)
  // shown: 지금까지 그린 행 수 ('더 보기'를 누르면 limit만큼 늘어납니다)
  const limit = options.limit === undefined ? TABLE_PAGE : options.limit;
  const state = {
    id: "tbl" + ++TABLE_SEQ,
    records,
    cols,
    options,
    clickable: options.clickable !== false,
    title: options.detailTitle || "상세 내용",
    sortCol: null,
    sortDir: 1,
    order: records.map((_, i) => i),
    limit,
    shown: limit ? Math.min(limit, records.length) : records.length,
  };
  TABLE_REGISTRY[state.id] = state;
  return tableHtml(state);
}

/* 열 머리글을 눌렀을 때: 오름차순 → 내림차순 → 원래 순서로 돌아갑니다.
   표 한 덩어리만 다시 그리므로, 화면 위치나 다른 표의 정렬은 그대로 남습니다.
   본문과 팝업에 모두 표가 있어서 document에서 한 번에 받습니다. */
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-sort-table]");
  if (!btn) return;
  const state = TABLE_REGISTRY[btn.dataset.sortTable];
  if (!state) return;

  const col = Number(btn.dataset.sortCol);
  if (state.sortCol === col) {
    if (state.sortDir === 1) state.sortDir = -1;
    else {
      state.sortCol = null;
      state.sortDir = 1;
    }
  } else {
    state.sortCol = col;
    state.sortDir = 1;
  }

  applyTableSort(state);
  const box = document.getElementById(state.id);
  // 정렬은 전체를 기준으로 다시 하고, 보여주는 개수(shown)는 그대로 둡니다.
  if (box) box.outerHTML = tableHtml(state);
});

/* '더 보기'를 눌렀을 때: 이미 그려진 행은 그대로 두고 다음 묶음만 덧붙입니다.
   표 전체를 다시 그리면 보고 있던 자리에서 화면이 튀기 때문입니다.
   본문과 팝업에 모두 표가 있어서 document에서 한 번에 받습니다. */
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-more-table]");
  if (!btn) return;
  const state = TABLE_REGISTRY[btn.dataset.moreTable];
  if (!state) return;

  const box = document.getElementById(state.id);
  const tbody = box ? box.querySelector("tbody") : null;
  if (!tbody) return;

  const next = state.order.slice(state.shown, state.shown + state.limit);
  tbody.insertAdjacentHTML("beforeend", rowsHtml(state, next));
  state.shown += next.length;

  // 안내 줄만 새로 그립니다 (남은 건수 갱신 · 다 보여줬으면 버튼이 사라집니다)
  const foot = box.querySelector(".table-more");
  if (foot) {
    foot.outerHTML = tableMoreHtml(state);
    // 버튼을 다시 만들었으므로 키보드 초점을 새 버튼으로 옮겨줍니다.
    const again = box.querySelector("[data-more-table]");
    if (again) again.focus();
  }
});

/* 표의 행을 눌렀을 때 팝업을 띄웁니다 (화면을 새로 그려도 계속 동작하도록 위임 처리). */
function openTableRowModal(state, rowIdx) {
  const record = state.records[rowIdx];
  if (!record) return;
  const at = state.order.indexOf(rowIdx);
  openModal(
    state.title,
    navBar(at + 1, state.order.length) + recordDetailHtml(record)
  );
  // openModal이 지운 뒤에 다시 켭니다 (이전/다음 · 방향키용)
  MODAL_NAV = { mode: "table", tableId: state.id, index: rowIdx };
}

els.content.addEventListener("click", (e) => {
  const row = e.target.closest("tr[data-table]");
  if (!row) return;
  const state = TABLE_REGISTRY[row.dataset.table];
  if (!state) return;
  NAV_ORDER = state.order;
  openTableRowModal(state, Number(row.dataset.row));
});

/* ---------------- 카드 ---------------- */

function kpiCard(label, value, sub) {
  return `<div class="kpi-card">
    <div class="kpi-label">${label}</div>
    <div class="kpi-value">${value}</div>
    ${sub ? `<div class="kpi-sub">${sub}</div>` : ""}
  </div>`;
}

function rankCard(name, count, max, sub) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return `<div class="rank-card">
    <div class="rank-name">${escapeHtml(name)}</div>
    <div class="rank-sub">${escapeHtml(sub || "처리 건수")}</div>
    <div class="rank-count">${count}건</div>
    <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  </div>`;
}

/* 카테고리 이름을 세미 타이틀로 얹은 담당자 카드.
   sub를 넘기면 '담당' 대신 그 글자를 씁니다 (담당자 탭의 비고를 보여줄 때 사용). */
function ownerCard(category, owner, countLabel, sub) {
  return `<div class="owner-block">
    <h3 class="owner-category">${escapeHtml(category)}</h3>
    <div class="rank-card">
      <div class="rank-name">${escapeHtml(owner)}</div>
      <div class="rank-sub">${escapeHtml(sub || "담당")}</div>
      <div class="rank-count">${escapeHtml(countLabel)}</div>
    </div>
  </div>`;
}

/* ---------------- 직무별 담당자 ---------------- */

/* 담당자 이름을 코드에 박아두면 인사 이동 때마다 코드를 고쳐야 해서,
   시트의 '담당자' 탭에서 읽어옵니다. 탭이 없거나 그 구분이 비어 있을 때만
   아래 기본값을 씁니다 (탭을 만들기 전에도 개요가 비지 않게 하려는 것입니다). */
const OWNER_FALLBACK = {
  전산: "이재환(Jetty)",
  탕비실: "박동국(Kaju)",
  소모품: "박동국(Kaju)",
  법인차량: "박동국(Kaju)",
  메일룸: "박동국(Kaju)",
};

/* 개요에서 건수를 세는 방법이 정해져 있는 구분들. 이 순서대로 카드를 그립니다. */
const OWNER_CATEGORIES = ["전산", "탕비실", "소모품", "법인차량", "메일룸"];

/* 시트에서 읽은 담당자를 '구분(기호 무시) -> {label, person, note}'로 정리합니다.
   "법인 차량"처럼 띄어쓰기가 달라도 같은 구분으로 봅니다. */
function ownerMap() {
  const map = {};
  getRecords("owners").forEach((o) => {
    const label = String(o["구분"] || "").trim();
    const person = String(o["담당자"] || "").trim();
    if (!label || !person) return;
    map[normalizeColumn(label)] = { label, person, note: String(o["비고"] || "").trim() };
  });
  return map;
}

function ownerOf(map, category) {
  return map[normalizeColumn(category)] || null;
}

/* ---------------- 화면별 렌더링 ---------------- */

function renderView(view) {
  const renderers = {
    overview: renderOverview,
    jeonsan: renderJeonsan,
    tangbisil: renderTangbisil,
    somopum: renderSomopum,
    vehicle: renderVehicle,
    mail: renderMail,
    plant: renderPlant,
    annual: renderAnnual,
    admin: renderAdmin,
  };
  CURRENT_VIEW = view;
  TABLE_REGISTRY = {}; // 이전 화면의 표 정보는 버립니다
  NAV_ORDER = null;
  closeModal();
  stopNoticeRotation();
  const fn = renderers[view] || renderOverview;
  els.content.innerHTML = fn();
  if (view === "overview") {
    startNoticeRotation();
    // 달력은 폭이 넓어 가로로 스크롤됩니다. 그려진 뒤에 오늘 칸이 보이도록 옮깁니다.
    scrollCalendarToToday();
  }
}

/* 이번 달 건수를 셉니다. 각 대장의 실제 날짜 열 이름을 넘겨받습니다.
   어떤 행에서도 날짜를 못 읽으면 null을 돌려줍니다.
   (예전에는 이 경우 '전체 건수'로 넘어가서, 월 기준이라면서 누적 숫자를 보여줬습니다) */
function countThisMonth(records, ...fields) {
  const now = new Date();
  let readable = false;
  const n = records.filter((r) => {
    for (const f of fields) {
      const d = parseKDate(pick(r, f));
      if (d) {
        readable = true;
        return isSameMonth(d, now);
      }
    }
    return false;
  }).length;
  if (!records.length) return 0;
  return readable ? n : null;
}

function countLabel(n) {
  return n === null ? "-" : n + "건";
}

function renderOverview() {
  const now = new Date();
  const monthLabel = `${now.getFullYear()}년 ${now.getMonth() + 1}월`;

  const tangbisil = getTangbisil();
  const jeonsanCount = countThisMonth(getRecords("jeonsan_status"), "요청일자", "완료일자");
  const somopumCount = countThisMonth(getRecords("somopum"), "날짜");
  const vehicleCount = countThisMonth(getRecords("vehicle_log"), "운행일", "이용일", "일자", "날짜");
  const postCount = countThisMonth(getRecords("mail_log"), "도달일");
  const printCount = countThisMonth(getRecords("namecard"), "전달일");
  const mailCount =
    postCount === null && printCount === null ? null : (postCount || 0) + (printCount || 0);

  // 구분별 건수 표시. 탕비실만 '진행일수 / 근무일수' 형태입니다.
  const counts = {
    전산: countLabel(jeonsanCount),
    탕비실: tangbisil.workdays_total
      ? `${tangbisil.workdays_done} / ${tangbisil.workdays_total}일`
      : "-",
    소모품: countLabel(somopumCount),
    법인차량: countLabel(vehicleCount),
    메일룸: countLabel(mailCount),
  };

  // 담당자는 시트에서 읽고, 그 구분이 시트에 없으면 기본값을 씁니다.
  const owners = ownerMap();
  const cards = OWNER_CATEGORIES.map((category) => {
    const found = ownerOf(owners, category);
    return ownerCard(
      category,
      found ? found.person : OWNER_FALLBACK[category] || "-",
      counts[category],
      found && found.note ? found.note : ""
    );
  });

  // 시트에만 있는 구분(예: 플랜트박스)도 카드로 보여줍니다.
  // 건수를 세는 방법은 구분마다 달라서, 아직 정해지지 않은 구분은 '-'로 둡니다.
  Object.keys(owners)
    .filter((k) => !OWNER_CATEGORIES.some((c) => normalizeColumn(c) === k))
    .forEach((k) => {
      const o = owners[k];
      cards.push(ownerCard(o.label, o.person, "-", o.note || ""));
    });

  const ownerNote = Object.keys(owners).length
    ? "담당자 이름은 시트의 '담당자' 탭에서 읽어옵니다."
    : "";

  return `
    <div class="banner-row">
      <div class="banner-card">
        <h2>LKG Workboard 개요</h2>
        <p>${monthLabel} 기준 · 전산 · 탕비실 · 소모품 · 법인차량 · 메일룸 관리 현황을 한눈에 확인하세요.</p>
      </div>
      <div class="banner-side">
        <h3>자동 업데이트</h3>
        <p>구글 시트 입력 내용이 15분마다 자동으로 이 화면에 반영됩니다. 전체 누적 통계는 왼쪽 '연간 통계' 메뉴에서 확인하세요.</p>
      </div>
    </div>

    ${noticeBar()}

    <h2 class="section-title">직무별 업무 처리 현황</h2>
    <p class="section-note">${monthLabel} 한 달 동안 처리된 건수입니다.${
      ownerNote ? " " + ownerNote : ""
    }</p>
    <div class="owner-grid">
      ${cards.join("")}
    </div>

    ${schedulePanel()}
  `;
}

/* ---------------- 공지사항 (자동으로 위로 넘어가는 띠) ---------------- */

/* 공지는 별도 DB 없이 시트 한 탭(A~D열)으로 관리합니다.
   시트에 한 줄 쓰면 15분 안에 여기에 뜹니다.
   열 이름은 공지(내용) / 시작일 / 종료일 / 중요 / 링크 를 알아봅니다. */
let NOTICE_TIMER = null;
let NOTICE_INDEX = 0;

function noticeRows() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return getRecords("notice")
    .map((r) => ({
      text: String(pick(r, "공지", "내용", "제목", "안내") || "").trim(),
      from: parseKDate(pick(r, "시작일", "게시일", "등록일")),
      to: parseKDate(pick(r, "종료일", "마감일")),
      important: /true|y|중요|고정|✓/i.test(String(pick(r, "중요", "고정"))),
      link: String(pick(r, "링크", "url") || "").trim(),
    }))
    .filter((n) => n.text)
    // 게시 기간이 적혀 있으면 그 기간에만 보여줍니다 (비어 있으면 항상)
    .filter((n) => (!n.from || n.from <= today) && (!n.to || n.to >= today))
    .sort((a, b) => (b.important ? 1 : 0) - (a.important ? 1 : 0));
}

function noticeBar() {
  const list = noticeRows();
  if (!list.length) return ""; // 공지가 없으면 띠 자체를 그리지 않습니다
  const items = list
    .map(
      (n) => `<li class="notice-item">
        ${n.important ? `<span class="notice-flag">중요</span>` : ""}
        ${
          n.link
            ? `<a href="${escapeHtml(n.link)}" target="_blank" rel="noopener">${escapeHtml(n.text)}</a>`
            : escapeHtml(n.text)
        }
      </li>`
    )
    .join("");
  const dots =
    list.length > 1
      ? `<div class="notice-dots">${list
          .map((_, i) => `<span class="notice-dot${i ? "" : " on"}"></span>`)
          .join("")}</div>`
      : "";
  return `<div class="notice-bar" id="noticeBar" data-notice-all title="누르면 진행 중인 공지를 모두 봅니다">
    <span class="notice-tag">공지</span>
    <div class="notice-view"><ul class="notice-list" id="noticeList">${items}</ul></div>
    ${dots}
    <button class="notice-more" data-notice-all>전체 보기</button>
  </div>`;
}

/* 공지 띠를 누르면 '진행 중인' 공지를 한 번에 펼쳐 봅니다.
   게시 기간이 끝난 공지는 noticeRows()에서 이미 걸러져 있습니다. */
function noticeModalHtml() {
  const list = noticeRows();
  if (!list.length) return `<div class="empty-note">진행 중인 공지가 없습니다.</div>`;

  const period = (n) => {
    if (!n.from && !n.to) return "상시 게시";
    const f = n.from ? `${n.from.getFullYear()}.${n.from.getMonth() + 1}.${n.from.getDate()}` : "";
    const t = n.to ? `${n.to.getFullYear()}.${n.to.getMonth() + 1}.${n.to.getDate()}` : "";
    if (f && t) return `${f} ~ ${t}`;
    return f ? `${f}부터` : `${t}까지`;
  };

  return `<p class="modal-note">진행 중인 공지 ${list.length}건 · 게시 기간이 끝난 공지는 빠져 있습니다.</p>
    <div class="notice-full">${list
      .map(
        (n) => `<div class="notice-card${n.important ? " important" : ""}">
          <div class="notice-card-head">
            ${n.important ? `<span class="notice-flag">중요</span>` : ""}
            <span class="notice-card-when">${escapeHtml(period(n))}</span>
          </div>
          <div class="notice-card-text">${
            n.link
              ? `<a href="${escapeHtml(n.link)}" target="_blank" rel="noopener">${escapeHtml(n.text)}</a>`
              : escapeHtml(n.text)
          }</div>
        </div>`
      )
      .join("")}</div>`;
}

els.content.addEventListener("click", (e) => {
  // 공지 안의 링크를 눌렀을 때는 그 링크로 가야 하므로 팝업을 열지 않습니다.
  if (e.target.closest("#noticeBar a")) return;
  if (e.target.closest("[data-notice-all]")) {
    openModal("공지사항", noticeModalHtml());
  }
});

function showNotice(index) {
  const list = document.getElementById("noticeList");
  if (!list || !list.children.length) return;
  const count = list.children.length;
  NOTICE_INDEX = ((index % count) + count) % count;
  const step = list.children[0].offsetHeight || 24;
  list.style.transform = `translateY(-${NOTICE_INDEX * step}px)`;
  document
    .querySelectorAll("#noticeBar .notice-dot")
    .forEach((d, i) => d.classList.toggle("on", i === NOTICE_INDEX));
}

function stopNoticeRotation() {
  if (NOTICE_TIMER) clearInterval(NOTICE_TIMER);
  NOTICE_TIMER = null;
}

function startNoticeRotation() {
  stopNoticeRotation();
  const bar = document.getElementById("noticeBar");
  const list = document.getElementById("noticeList");
  if (!bar || !list || list.children.length < 2) return;

  NOTICE_INDEX = 0;
  showNotice(0);
  const tick = () => showNotice(NOTICE_INDEX + 1);
  NOTICE_TIMER = setInterval(tick, 4500);

  // 읽는 중에 넘어가면 곤란하니, 마우스를 올리면 멈춥니다.
  bar.addEventListener("mouseenter", stopNoticeRotation);
  bar.addEventListener("mouseleave", () => {
    stopNoticeRotation();
    NOTICE_TIMER = setInterval(tick, 4500);
  });
}

/* ---------------- 팀 스케줄 달력 ---------------- */

/* 일정 유형별 색. 네 가지 + 기타(회색)로 묶었습니다.
   색각이상까지 포함한 구분 검증(전체 쌍)을 통과한 조합이고,
   막대 안에 유형 글자를 같이 적기 때문에 색만으로 읽지 않아도 됩니다. */
const SCHEDULE_TYPES = [
  { test: /연차|휴가|반차|월차|보상/, label: "연차 · 휴가", color: "#2a78d6" },
  { test: /외근|출장|미팅|방문/, label: "외근 · 출장", color: "#eb6834" },
  { test: /재택|원격/, label: "재택", color: "#1baf7a" },
  { test: /교육|워크샵|워크숍|세미나|회의|연수/, label: "교육 · 회의", color: "#4a3aa7" },
];
const SCHEDULE_OTHER = { label: "기타", color: "#8A8171" };

function scheduleStyle(type) {
  const hit = SCHEDULE_TYPES.find((t) => t.test.test(type));
  return hit || SCHEDULE_OTHER;
}

/* #2a78d6 -> "42,120,214" (반투명 배경을 만들기 위해) */
function hexToRgb(hex) {
  const h = hex.replace("#", "");
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)).join(",");
}

function scheduleRows() {
  return getRecords("schedule")
    .map((r) => {
      const from = parseKDate(pick(r, "시작일", "시작", "일자", "날짜"));
      const to = parseKDate(pick(r, "종료일", "종료", "복귀")) || from;
      return {
        raw: r,
        name: String(pick(r, "이름", "성명", "크루", "담당자") || "").trim(),
        type: String(pick(r, "유형", "구분", "일정", "종류") || "").trim() || "기타",
        note: String(pick(r, "비고", "메모") || "").trim(),
        from,
        to,
      };
    })
    .filter((x) => x.name && x.from);
}

function holidaySet() {
  const list = getRecords("holidays");
  return new Set(list.filter((x) => typeof x === "string"));
}

function ymd(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate()
  ).padStart(2, "0")}`;
}

function dayLabel(d) {
  return `${d.getMonth() + 1}.${d.getDate()}`;
}

/* 보고 있는 달 (처음엔 이번 달) */
let SCHED_YEAR = null;
let SCHED_MONTH = null;
let SCHED_VISIBLE = []; // 지금 화면에 그려진 일정 (막대 클릭용)
let SCHED_PICK = false; // 연·월 선택창을 펼쳤는지
let SCHED_PICK_YEAR = null; // 선택창에서 보고 있는 해

/* 연·월 선택창. 제목을 누르면 펼쳐집니다.
   화살표로 한 달씩 넘기지 않고 다른 해로도 바로 갈 수 있게 하려는 것입니다. */
function schedulePicker() {
  if (!SCHED_PICK) return "";
  const months = Array.from({ length: 12 }, (_, i) => {
    const on = SCHED_PICK_YEAR === SCHED_YEAR && i === SCHED_MONTH;
    return `<button class="cal-pick-m${on ? " active" : ""}" data-sched-month="${i}">${i + 1}월</button>`;
  }).join("");
  return `<div class="cal-picker">
    <div class="cal-picker-year">
      <button class="cal-nav-btn" data-sched-year="-1" aria-label="이전 해">◀</button>
      <span class="cal-picker-y">${SCHED_PICK_YEAR}년</span>
      <button class="cal-nav-btn" data-sched-year="1" aria-label="다음 해">▶</button>
    </div>
    <div class="cal-picker-months">${months}</div>
  </div>`;
}

function scheduleCalendar() {
  // 일정이 하나도 없어도 달력은 그대로 띄웁니다.
  const all = scheduleRows();

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (SCHED_YEAR === null) {
    SCHED_YEAR = today.getFullYear();
    SCHED_MONTH = today.getMonth();
  }

  const first = new Date(SCHED_YEAR, SCHED_MONTH, 1);
  const dayCount = new Date(SCHED_YEAR, SCHED_MONTH + 1, 0).getDate();
  const last = new Date(SCHED_YEAR, SCHED_MONTH, dayCount);
  const holidays = holidaySet();
  const WEEK = ["일", "월", "화", "수", "목", "금", "토"];

  // 이 달과 겹치는 일정만 남기고, 달 밖으로 삐져나간 부분은 잘라 그립니다.
  SCHED_VISIBLE = all
    .filter((e) => e.from <= last && e.to >= first)
    .map((e) => {
      const s = e.from < first ? 1 : e.from.getDate();
      const t = e.to > last ? dayCount : e.to.getDate();
      return { ...e, startDay: s, endDay: t };
    });

  const todayCount = all.filter((e) => e.from <= today && e.to >= today).length;

  const headCells = [];
  for (let d = 1; d <= dayCount; d++) {
    const date = new Date(SCHED_YEAR, SCHED_MONTH, d);
    const wd = date.getDay();
    const cls = [
      "cal-day",
      wd === 0 || wd === 6 ? "off" : "",
      holidays.has(ymd(date)) ? "off holiday" : "",
      date.getTime() === today.getTime() ? "today" : "",
    ]
      .filter(Boolean)
      .join(" ");
    headCells.push(
      `<div class="${cls}" style="grid-column:${d + 1}"><span class="cal-wd">${WEEK[wd]}</span><span class="cal-dd">${d}</span></div>`
    );
  }

  const bgCells = (extra) => {
    const out = [];
    for (let d = 1; d <= dayCount; d++) {
      const date = new Date(SCHED_YEAR, SCHED_MONTH, d);
      const wd = date.getDay();
      const cls = [
        "cal-cell",
        wd === 0 || wd === 6 || holidays.has(ymd(date)) ? "off" : "",
        date.getTime() === today.getTime() ? "today" : "",
      ]
        .filter(Boolean)
        .join(" ");
      out.push(`<div class="${cls}" style="grid-column:${d + 1}"></div>`);
    }
    return out.join("") + (extra || "");
  };

  // 크루별로 묶고, 같은 사람의 일정이 겹치면 줄을 나눠 그립니다.
  const byName = new Map();
  SCHED_VISIBLE.forEach((e, i) => {
    if (!byName.has(e.name)) byName.set(e.name, []);
    byName.get(e.name).push({ ...e, index: i });
  });

  const crewRows = [...byName.entries()]
    .sort((a, b) => a[0].localeCompare(b[0], "ko"))
    .map(([name, items]) => {
      const lanes = [];
      items
        .slice()
        .sort((a, b) => a.startDay - b.startDay)
        .forEach((item) => {
          let lane = lanes.find((l) => l.every((x) => x.endDay < item.startDay || x.startDay > item.endDay));
          if (!lane) {
            lane = [];
            lanes.push(lane);
          }
          lane.push(item);
        });

      return lanes
        .map((lane, li) => {
          const bars = lane
            .map((item) => {
              const st = scheduleStyle(item.type);
              const rgb = hexToRgb(st.color);
              const span = item.endDay - item.startDay + 1;
              const title = `${item.name} · ${item.type} · ${dayLabel(item.from)}${
                item.to.getTime() !== item.from.getTime() ? ` ~ ${dayLabel(item.to)}` : ""
              }${item.note ? ` · ${item.note}` : ""}`;
              return `<button class="cal-bar" data-sched-row="${item.index}" title="${escapeHtml(title)}"
                style="grid-column:${item.startDay + 1} / span ${span};
                       background:rgba(${rgb},0.16); border-color:rgba(${rgb},0.55);
                       box-shadow: inset 3px 0 0 ${st.color};">
                <span class="cal-bar-text">${escapeHtml(item.type)}${
                  item.note ? ` · ${escapeHtml(item.note)}` : ""
                }</span>
              </button>`;
            })
            .join("");
          return `<div class="cal-row">
            <div class="cal-name">${li === 0 ? escapeHtml(name) : ""}</div>
            ${bgCells(bars)}
          </div>`;
        })
        .join("");
    })
    .join("");

  const legend = `<div class="cal-legend">
    ${[...SCHEDULE_TYPES, SCHEDULE_OTHER]
      .map(
        (t) => `<span class="legend-item"><span class="cal-swatch"
          style="background:rgba(${hexToRgb(t.color)},0.16); box-shadow: inset 3px 0 0 ${t.color};"></span>${escapeHtml(
          t.label
        )}</span>`
      )
      .join("")}
  </div>`;

  const body = `<div class="cal-scroll"><div class="cal" style="--cal-days:${dayCount}">
      <div class="cal-row cal-head"><div class="cal-name">크루</div>${headCells.join("")}</div>
      ${crewRows}
    </div></div>${
      crewRows
        ? legend
        : `<div class="empty-note">${SCHED_YEAR}년 ${SCHED_MONTH + 1}월에 등록된 일정이 없습니다.</div>`
    }`;

  return `
    <div class="cal-nav">
      <button class="cal-nav-btn" data-sched-nav="prev" aria-label="지난달">◀</button>
      <div class="cal-title-wrap">
        <button class="cal-title" data-sched-pick aria-expanded="${SCHED_PICK}"
                title="누르면 연·월을 골라서 이동합니다">${SCHED_YEAR}년 ${SCHED_MONTH + 1}월 <span class="cal-caret">▾</span></button>
        ${schedulePicker()}
      </div>
      <button class="cal-nav-btn" data-sched-nav="next" aria-label="다음달">▶</button>
      <button class="cal-nav-btn cal-today-btn" data-sched-nav="today">오늘</button>
      <span class="cal-note">오늘 일정 ${todayCount}건 · 막대를 누르면 상세</span>
    </div>
    ${body}
  `;
}

function schedulePanel() {
  // panel-open: 연·월 선택창이 패널 밖으로 나올 수 있게 잘림을 풀어줍니다
  return `<div class="panel panel-open">
    <div class="panel-header">
      <h2>팀 스케줄</h2>
      <span class="panel-meta">연차 · 외근 · 재택 등 크루별 일정</span>
    </div>
    <div class="panel-body" id="schedBox">${scheduleCalendar()}</div>
  </div>`;
}

/* 달력을 열면 오늘 칸이 보이는 자리로 가로 스크롤을 옮깁니다.
   달력은 한 달 전체(1080px 이상)를 가로로 늘어놓기 때문에, 월 후반에는
   오늘이 화면 밖에 있어서 매번 손으로 밀어야 했습니다.

   - 보고 있는 달이 이번 달이 아닐 때는 1일부터 보이게 왼쪽 끝으로 둡니다.
   - 왼쪽 크루 이름칸은 sticky로 떠 있어서, 그 폭만큼 빼고 가운데를 계산합니다. */
function scrollCalendarToToday() {
  // 글꼴이 늦게 적용되면 칸 폭이 조금 달라지므로, 한 번 그려진 다음에 위치를 잡습니다.
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(placeCalendarScroll);
  } else {
    placeCalendarScroll();
  }
}

function placeCalendarScroll() {
  const scroller = document.querySelector("#schedBox .cal-scroll");
  if (!scroller) return;

  const today = new Date();
  if (SCHED_YEAR !== today.getFullYear() || SCHED_MONTH !== today.getMonth()) {
    scroller.scrollLeft = 0;
    return;
  }

  const cell = scroller.querySelector(".cal-head .cal-day.today");
  if (!cell) return;

  const nameCol = scroller.querySelector(".cal-head .cal-name");
  const stickyWidth = nameCol ? nameCol.getBoundingClientRect().width : 0;
  const cellBox = cell.getBoundingClientRect();
  const viewBox = scroller.getBoundingClientRect();

  // 지금 스크롤 위치를 기준으로, 오늘 칸을 '이름칸 오른쪽 영역'의 가운데에 놓습니다.
  const room = scroller.clientWidth - stickyWidth - cellBox.width;
  const target =
    scroller.scrollLeft + (cellBox.left - viewBox.left) - stickyWidth - Math.max(room, 0) / 2;

  scroller.scrollLeft = Math.max(0, target);
}

function redrawCalendar() {
  const box = document.getElementById("schedBox");
  if (!box) return;
  box.innerHTML = scheduleCalendar();
  // 달을 바꿀 때마다 위치를 다시 잡습니다 (이번 달이면 오늘, 아니면 1일부터).
  scrollCalendarToToday();
}

els.content.addEventListener("click", (e) => {
  // 제목을 눌러 연·월 선택창 열기/닫기
  if (e.target.closest("[data-sched-pick]")) {
    SCHED_PICK = !SCHED_PICK;
    if (SCHED_PICK) SCHED_PICK_YEAR = SCHED_YEAR;
    redrawCalendar();
    return;
  }

  // 선택창에서 해 바꾸기
  const yearBtn = e.target.closest("[data-sched-year]");
  if (yearBtn) {
    SCHED_PICK_YEAR += Number(yearBtn.dataset.schedYear);
    redrawCalendar();
    return;
  }

  // 선택창에서 달 고르기
  const monthBtn = e.target.closest("[data-sched-month]");
  if (monthBtn) {
    SCHED_YEAR = SCHED_PICK_YEAR;
    SCHED_MONTH = Number(monthBtn.dataset.schedMonth);
    SCHED_PICK = false;
    redrawCalendar();
    return;
  }

  const nav = e.target.closest("[data-sched-nav]");
  if (nav) {
    const now = new Date();
    if (nav.dataset.schedNav === "prev") SCHED_MONTH -= 1;
    else if (nav.dataset.schedNav === "next") SCHED_MONTH += 1;
    else {
      SCHED_YEAR = now.getFullYear();
      SCHED_MONTH = now.getMonth();
    }
    // 12월 다음은 다음 해 1월이 되도록 정리합니다 (해가 바뀌어도 계속 넘어갑니다)
    const norm = new Date(SCHED_YEAR, SCHED_MONTH, 1);
    SCHED_YEAR = norm.getFullYear();
    SCHED_MONTH = norm.getMonth();
    SCHED_PICK = false;
    redrawCalendar();
    return;
  }

  const bar = e.target.closest("[data-sched-row]");
  if (bar) {
    const item = SCHED_VISIBLE[Number(bar.dataset.schedRow)];
    if (item) openModal(`${item.name} · ${item.type}`, recordDetailHtml(item.raw));
    return;
  }

  // 선택창 바깥을 누르면 닫습니다
  if (SCHED_PICK && !e.target.closest(".cal-picker")) {
    SCHED_PICK = false;
    redrawCalendar();
  }
});

/* ---------------- 데이터 점검 · 관리자 알림 ---------------- */

/* 각 시트가 제대로 읽혔는지 확인할 항목입니다.
   need에 적은 열이 사라지면(시트 서식이 바뀌면) 화면이 조용히 비게 되므로,
   여기서 잡아 관리자 알림으로 띄웁니다. */
const SOURCE_CHECKS = [
  { key: "jeonsan_status", label: "전산 업무현황", need: ["요청자", "담당자", "진행상태"] },
  { key: "jeonsan_asset", label: "자산 지급대장", need: ["한글이름"] },
  { key: "jeonsan_io", label: "전산 입출고 · 대여", need: ["이름"] },
  { key: "somopum", label: "소모품 불출 대장", need: ["품목", "수량", "불출 대상"] },
  { key: "vehicle_parking", label: "정기주차 차량", need: [] },
  { key: "vehicle_log", label: "운행일지", need: [] },
  { key: "mail_log", label: "우편물 대장", need: ["도달일", "수령자"] },
  { key: "namecard", label: "인쇄물 대장", need: ["전달일"] },
  { key: "notice", label: "공지 (시트 A~D열)", need: [] },
  { key: "schedule", label: "팀 스케줄 (시트 F~J열)", need: ["이름", "유형"] },
];

/* 레코드에 그 열이 있는지 (이름 표기가 조금 달라도 찾습니다) */
function hasColumn(record, want) {
  const target = normalizeColumn(want);
  return Object.keys(record).some((k) => normalizeColumn(k).includes(target));
}

/* 데이터가 얼마나 오래됐는지 (분) */
function dataAgeMinutes() {
  if (!WORKBOARD || !WORKBOARD.generated_at) return null;
  return (Date.now() - new Date(WORKBOARD.generated_at).getTime()) / 60000;
}

/* 지금 알려야 할 문제들. 배지 숫자이자 관리자 알림 화면의 내용입니다. */
function dataAlerts() {
  const out = [];
  const add = (level, title, detail) => out.push({ level, title, detail });

  // ① 자동 갱신이 멈췄는지 (15분마다 도는 작업이 90분 넘게 안 돌면 이상)
  const age = dataAgeMinutes();
  if (age !== null && age > 90) {
    const h = Math.floor(age / 60);
    add(
      "danger",
      "데이터가 갱신되지 않고 있습니다",
      `마지막 갱신이 약 ${h ? h + "시간 " : ""}${Math.round(age % 60)}분 전입니다. ` +
        "GitHub Actions 실행 기록을 확인해주세요."
    );
  }

  // ② 시트별 점검
  SOURCE_CHECKS.forEach((c) => {
    const rows = getRecords(c.key);
    if (!rows.length) {
      add("danger", `${c.label} — 읽은 기록이 0건입니다`,
          "시트 접근 권한, 탭 삭제, gid 변경 중 하나일 수 있습니다.");
      return;
    }
    const missing = c.need.filter((n) => !hasColumn(rows[0], n));
    if (missing.length) {
      add("warn", `${c.label} — 열 이름을 찾지 못했습니다`,
          `찾는 열: ${missing.join(", ")} · 시트에서 열 이름이 바뀌었는지 확인해주세요.`);
    }
  });

  // ③ 탕비실 (구조가 달라 따로 봅니다)
  const tb = getTangbisil();
  if (!(tb.items || []).length) {
    add("danger", "탕비실 — 상품 목록이 비어 있습니다",
        `이번 달 탭(${tb.month_title || "이름 확인 필요"})을 못 찾았거나 서식이 바뀌었을 수 있습니다.`);
  } else if (!(tb.days || []).length) {
    add("warn", "탕비실 — 일자별 진열 체크를 못 읽었습니다",
        "시트 2~3행에 '2026-9-7(월)' 형태의 날짜가 있는지 확인해주세요.");
  }

  // ④ 소모품 월별 재고
  const stock = somopumStock();
  if (!stock.months.length) {
    add("warn", "소모품 — 월별 잔여 재고를 못 읽었습니다",
        "'월별 불출량&검수' 탭의 2행 월 표시와 3행 열 이름을 확인해주세요.");
  }

  return out;
}

/* 사이드바 배지 갱신 */
function refreshAdminBadge() {
  if (!els.adminBadge) return;
  const n = dataAlerts().length;
  els.adminBadge.textContent = n;
  els.adminBadge.hidden = n === 0;
}

/* 관리자 알림은 간단한 번호 잠금을 둡니다.
   번호를 코드에 그대로 적지 않으려고 지문(SHA-256)만 넣어둡니다.
   화면 자체가 이미 대시보드 비밀번호 안쪽이라, 이 잠금은 '실수로 들어가는 것'을
   막는 용도입니다. */
const ADMIN_PIN_HASH =
  "3e34b5dc434bcf3186f089d362691cfac1b17231601f2f402dc79015be878d83";
let ADMIN_UNLOCKED = false;
let ADMIN_ERROR = "";

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function adminLockHtml() {
  return `<div class="panel">
    <div class="panel-header">
      <h2>관리자 확인</h2>
      <span class="panel-meta">관리자 번호를 입력하세요</span>
    </div>
    <div class="panel-body">
      <div class="admin-lock">
        <p class="section-note" style="margin:0 0 14px;">
          데이터 점검 결과는 관리자만 확인합니다.
        </p>
        <div class="search-bar" style="margin:0;">
          <input type="password" id="adminPin" inputmode="numeric"
                 placeholder="관리자 번호" autocomplete="off" />
          <button class="crew-search-btn" id="adminPinBtn">확인</button>
        </div>
        ${ADMIN_ERROR ? `<p class="lock-error" style="margin-top:12px !important;">${escapeHtml(ADMIN_ERROR)}</p>` : ""}
      </div>
    </div>
  </div>`;
}

function renderAdmin() {
  if (!ADMIN_UNLOCKED) return adminLockHtml();

  const alerts = dataAlerts();
  const age = dataAgeMinutes();

  const cards = alerts.length
    ? `<div class="alert-cards">${alerts
        .map(
          (a) => `<div class="alert-card ${a.level}">
            <div class="alert-card-head">
              <span class="alert-chip ${a.level}">${a.level === "danger" ? "확인 필요" : "주의"}</span>
              <strong>${escapeHtml(a.title)}</strong>
            </div>
            <p class="alert-card-body">${escapeHtml(a.detail)}</p>
          </div>`
        )
        .join("")}</div>`
    : `<div class="ok-panel" style="margin:16px 20px;">지금 확인할 문제가 없습니다. 모든 시트가 정상적으로 읽혔습니다.</div>`;

  // 점검 항목을 전부 보여줍니다 (문제 없는 것도 같이 봐야 안심이 됩니다)
  const rows = SOURCE_CHECKS.map((c) => {
    const list = getRecords(c.key);
    const missing = list.length ? c.need.filter((n) => !hasColumn(list[0], n)) : c.need;
    const ok = list.length && !missing.length;
    return `<tr>
      <td class="cell-strong">${escapeHtml(c.label)}</td>
      <td>${list.length.toLocaleString()}건</td>
      <td>${
        ok
          ? `<span class="badge done">정상</span>`
          : `<span class="badge warn">${list.length ? "열 확인" : "0건"}</span>`
      }</td>
      <td class="muted">${missing.length ? escapeHtml(missing.join(", ")) : "-"}</td>
    </tr>`;
  }).join("");

  const tb = getTangbisil();

  return `
    <div class="kpi-grid">
      ${kpiCard("확인 필요", alerts.filter((a) => a.level === "danger").length + "건", "바로 조치")}
      ${kpiCard("주의", alerts.filter((a) => a.level === "warn").length + "건", "서식 확인")}
      ${kpiCard("마지막 갱신", age === null ? "-" : `${Math.round(age)}분 전`, "15분마다 자동 갱신")}
      ${kpiCard("점검 대상", SOURCE_CHECKS.length + "개", "시트 · 탭 기준")}
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>알림</h2>
        <span class="panel-meta">${alerts.length}건</span>
      </div>
      <div class="panel-body">${cards}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>시트 점검 결과</h2>
        <span class="panel-meta">읽은 건수와 필수 열 확인</span>
      </div>
      <div class="panel-body">
        <div class="table-scroll"><table class="data-table center-all">
          <thead><tr><th>시트 · 대장</th><th>읽은 건수</th><th>상태</th><th>못 찾은 열</th></tr></thead>
          <tbody>${rows}
            <tr>
              <td class="cell-strong">탕비실 (이번 달 탭)</td>
              <td>${(tb.items || []).length}종</td>
              <td>${
                (tb.items || []).length
                  ? `<span class="badge done">정상</span>`
                  : `<span class="badge warn">0종</span>`
              }</td>
              <td class="muted">${escapeHtml(tb.month_title || "탭 이름 확인 필요")}</td>
            </tr>
            <tr>
              <td class="cell-strong">소모품 월별 재고</td>
              <td>${somopumStock().months.length}개월</td>
              <td>${
                somopumStock().months.length
                  ? `<span class="badge done">정상</span>`
                  : `<span class="badge warn">0개월</span>`
              }</td>
              <td class="muted">-</td>
            </tr>
            <!-- 담당자 탭은 없어도 기본값으로 도니까 '문제'로 세지 않습니다.
                 대신 지금 어디서 읽고 있는지만 여기서 확인할 수 있게 둡니다. -->
            <tr>
              <td class="cell-strong">직무별 담당자 (담당자 탭)</td>
              <td>${getRecords("owners").length}명</td>
              <td>${
                getRecords("owners").length
                  ? `<span class="badge done">시트에서 읽음</span>`
                  : `<span class="badge plain">기본값 사용</span>`
              }</td>
              <td class="muted">${
                getRecords("owners").length
                  ? escapeHtml(getRecords("owners").map((o) => o["구분"]).join(", "))
                  : "담당자 탭을 만들면 시트에서 읽습니다"
              }</td>
            </tr>
          </tbody>
        </table></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>점검 기준</h2></div>
      <div class="panel-body">
        <div class="detail-list" style="padding: 4px 20px 16px;">
          <div class="detail-row"><div class="detail-key">0건</div>
            <div class="detail-value">시트를 아예 못 읽었습니다. 공유 권한 · 탭 삭제 · gid 변경을 확인하세요.</div></div>
          <div class="detail-row"><div class="detail-key">열 확인</div>
            <div class="detail-value">시트는 읽었지만 화면이 기대하는 열 이름이 없습니다. 열 이름이 바뀌면 그 칸이 빈 채로 나옵니다.</div></div>
          <div class="detail-row"><div class="detail-key">갱신 지연</div>
            <div class="detail-value">마지막 갱신이 90분을 넘으면 알립니다. GitHub Actions 실행 기록을 확인하세요.</div></div>
        </div>
      </div>
    </div>
  `;
}

/* 관리자 번호 입력 처리 */
async function tryAdminUnlock() {
  const input = document.getElementById("adminPin");
  if (!input) return;
  const value = input.value.trim();
  if (!value) return;
  const hash = await sha256Hex(value);
  if (hash === ADMIN_PIN_HASH) {
    ADMIN_UNLOCKED = true;
    ADMIN_ERROR = "";
  } else {
    ADMIN_ERROR = "번호가 올바르지 않습니다.";
  }
  els.content.innerHTML = renderAdmin();
  if (!ADMIN_UNLOCKED) {
    const again = document.getElementById("adminPin");
    if (again) again.focus();
  }
}

els.content.addEventListener("click", (e) => {
  if (e.target.closest("#adminPinBtn")) tryAdminUnlock();
});

els.content.addEventListener("keydown", (e) => {
  if (e.target.id === "adminPin" && e.key === "Enter") {
    e.preventDefault();
    tryAdminUnlock();
  }
});

/* ---------------- 자동 갱신 ---------------- */

/* 시트는 15분마다 갱신되는데 브라우저는 새로고침해야 보였습니다.
   5분마다 파일이 바뀌었는지만 확인하고, 바뀌었으면 화면을 다시 그립니다.
   내용 비교는 파일 안의 content_hash로 합니다 (암호문은 매번 달라지므로). */
const REFRESH_MS = 5 * 60 * 1000;
let REFRESH_TIMER = null;
let PENDING_DATA = null;

function canRefreshNow() {
  if (!els.modalBackdrop.hidden) return false; // 팝업을 보고 있는 중
  const active = document.activeElement;
  if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA")) return false;
  return true;
}

function applyUpdate() {
  if (!PENDING_DATA) return;
  WORKBOARD = PENDING_DATA;
  PENDING_DATA = null;
  if (els.refreshPill) els.refreshPill.hidden = true;
  els.lastUpdated.textContent = "마지막 업데이트: " + formatDateTime(WORKBOARD.generated_at);
  refreshAdminBadge();
  renderView(CURRENT_VIEW);
}

async function checkForUpdate() {
  if (!PASSPHRASE) return;
  try {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) return;
    const blob = await res.json();
    const same =
      blob.content_hash && ENCRYPTED_BLOB.content_hash
        ? blob.content_hash === ENCRYPTED_BLOB.content_hash
        : blob.ciphertext === ENCRYPTED_BLOB.ciphertext;
    if (same) return;

    const fresh = await decryptBlob(blob, PASSPHRASE);
    ENCRYPTED_BLOB = blob;
    PENDING_DATA = fresh;

    // 보고 있는 중이면 방해하지 않고, 위쪽에 알림만 띄웁니다.
    if (canRefreshNow()) applyUpdate();
    else if (els.refreshPill) els.refreshPill.hidden = false;
  } catch (err) {
    // 네트워크가 잠깐 끊긴 경우 등. 다음 주기에 다시 시도합니다.
  }
}

function startAutoRefresh() {
  if (REFRESH_TIMER) clearInterval(REFRESH_TIMER);
  // 배지도 같이 다시 셉니다. 갱신이 멈춘 경우는 새 데이터가 없어도 알려야 하니까요.
  REFRESH_TIMER = setInterval(() => {
    refreshAdminBadge();
    checkForUpdate();
  }, REFRESH_MS);

  // 다른 탭을 보다가 돌아왔을 때도 한 번 확인합니다.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) checkForUpdate();
  });

  if (els.refreshPill) {
    els.refreshPill.addEventListener("click", applyUpdate);
  }
}

/* ---------------- 플랜트박스 ---------------- */

function renderPlant() {
  const rows = getRecords("plant");
  if (!rows.length) {
    return `
      <div class="panel">
        <div class="panel-header">
          <h2>플랜트박스 관리</h2>
          <span class="panel-meta">시트 연결 대기 중</span>
        </div>
        <div class="panel-body">
          <div class="empty-note" style="text-align:left; padding:22px 24px; line-height:1.7;">
            아직 연결된 시트가 없습니다. 시트 링크(탭 주소)를 주시면 이 화면을 채우겠습니다.<br />
            표에 <strong>날짜</strong>가 들어간 열과 <strong>담당자 · 크루 이름</strong> 열이 있으면,
            다른 카테고리처럼 월별 기록과 크루별 조회를 그대로 붙일 수 있습니다.
          </div>
        </div>
      </div>
    `;
  }
  return `
    <div class="kpi-grid">${kpiCard("전체 기록", rows.length + "건", "누적")}</div>
    <div class="panel">
      <div class="panel-header"><h2>플랜트박스 관리</h2><span class="panel-meta">${rows.length}건</span></div>
      <div class="panel-body">
        ${renderTable(rows.slice().reverse(), null, { detailTitle: "플랜트박스 상세", center: true })}
      </div>
    </div>
  `;
}

/* ---------------- 전산 ---------------- */

/* 담당자별 월별 처리 건수. { "이재환(Jetty)": { total, months: {"2026.09": 12, ...} } } */
function handlerMonthlyStats(records) {
  const stats = {};
  records.forEach((r) => {
    const date = parseKDate(r["요청일자"]) || parseKDate(r["완료일자"]);
    splitNames(r["담당자"]).forEach((person) => {
      if (!stats[person]) stats[person] = { total: 0, months: {}, records: [] };
      stats[person].total += 1;
      stats[person].records.push(r);
      const key = date ? monthKey(date) : "날짜 없음";
      stats[person].months[key] = (stats[person].months[key] || 0) + 1;
    });
  });
  return stats;
}

let HANDLER_STATS = {};

function personCard(label, stat) {
  const person = parsePerson(label);
  return `<button class="person-card" data-person="${escapeHtml(label)}">
    <div class="person-name">${escapeHtml(person.name)}</div>
    <div class="person-nick">${escapeHtml(person.nick || "-")}</div>
    <div class="person-hint">월별 보기</div>
  </button>`;
}

/* 담당자 카드를 누르면 월별 처리 건수를 팝업으로 보여줍니다. */
els.content.addEventListener("click", (e) => {
  const card = e.target.closest(".person-card");
  if (!card) return;
  const label = card.dataset.person;
  const stat = HANDLER_STATS[label];
  if (!stat) return;

  const entries = Object.entries(stat.months).sort((a, b) => (a[0] < b[0] ? 1 : -1));
  const max = Math.max(...entries.map(([, c]) => c), 1);
  const person = parsePerson(label);

  const rows = entries
    .map(
      ([month, count]) => `
      <div class="bar-row">
        <div class="bar-label">${escapeHtml(month)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((count / max) * 100)}%"></div></div>
        <div class="bar-count">${count}건</div>
      </div>`
    )
    .join("");

  openModal(
    `${person.name}${person.nick ? ` (${person.nick})` : ""} · 월별 처리 건수`,
    `<div class="modal-kpi">${kpiCard("전체 누적", stat.total + "건")}${kpiCard("집계된 개월 수", entries.length + "개월")}</div>
     <div class="bar-chart">${rows}</div>`
  );
});

/* ---------------- 크루별 조회 ---------------- */

/* 각 대장에서 찾아볼 열입니다. 시트 서식 기준.
   - nameFields: 사람 이름이 들어있는 열
   - codeFields: 자산번호처럼 물건을 가리키는 번호가 들어있는 열
   이 열들만 보기 때문에, 비고란에 우연히 이름이 섞여도 딸려오지 않습니다. */
const CREW_SOURCES = [
  {
    key: "jeonsan_status",
    label: "전산 업무현황",
    nameFields: ["요청자", "담당자"],
    codeFields: ["자산번호", "관리번호", "시리얼"],
    columns: ["유형","요청자","부서","자산번호","업무내용","조치사항","담당자",
              "요청일자","착수일자","완료일자","진행상태","비고"],
    detailTitle: "전산 업무 상세",
  },
  {
    key: "jeonsan_asset",
    label: "자산 지급대장",
    nameFields: ["한글이름", "영어이름"],
    codeFields: ["자산번호", "관리번호", "시리얼"],
    columns: null, // 열이 많아 시트에 있는 그대로 보여줍니다
    detailTitle: "자산 지급 상세",
  },
  {
    key: "jeonsan_io",
    label: "입출고 · 대여",
    nameFields: ["이름", "영문명"],
    codeFields: ["자산번호", "관리번호", "시리얼"],
    columns: null,
    detailTitle: "입출고 상세",
  },
];

/* 찾을 열들을 실제 시트 열 이름에 느슨하게 맞춥니다.
   시트 헤더가 "자산번호(태그)"처럼 적혀 있어도 같은 열로 봅니다. */
function searchFields(record, wants) {
  const keys = Object.keys(record);
  const hits = [];
  wants.forEach((want) => {
    const target = normalizeColumn(want);
    if (!target) return;
    keys.forEach((k) => {
      if (normalizeColumn(k).includes(target) && !hits.includes(k)) hits.push(k);
    });
  });
  return hits;
}

/* 기호를 뺀 형태. 자산번호를 "LKG-NB-021"로 적었는지 "lkg nb 021"로 적었는지
   사람마다 달라서, 둘 다 찾히도록 붙임 형태로도 비교합니다. */
function flatCode(value) {
  return String(value ?? "").toLowerCase().replace(/[\s\-_/.()]/g, "");
}

/* 이름 열 · 자산번호 열에서 찾습니다.
   그 열들을 하나도 못 찾았을 때만 모든 값에서 찾습니다 (안전장치). */
function matchesCrew(record, needle, source) {
  const wants = (source.nameFields || []).concat(source.codeFields || []);
  const keys = searchFields(record, wants);
  const values = keys.length ? keys.map((k) => record[k]) : Object.values(record);
  const flatNeedle = flatCode(needle);
  return values.some((v) => {
    const text = String(v ?? "").toLowerCase();
    if (text.includes(needle)) return true;
    return flatNeedle.length >= 2 && flatCode(text).includes(flatNeedle);
  });
}

let CREW_QUERY = "";
let CREW_TAB = null;  // 팝업에서 고른 대장. null이면 아직 안 고름
let CREW_ROW = null;  // 팝업 표에서 펼쳐 본 행 번호

function crewMatches(query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return CREW_SOURCES.map((source) => ({
    ...source,
    rows: getRecords(source.key).filter((r) => matchesCrew(r, needle, source)),
  }));
}

/* 팝업 안에 그릴 내용. 세 단계를 상황에 따라 바꿔 보여줍니다.
   ① 대장 고르기 → ② 그 대장의 표 → ③ 행 하나의 전체 내용 */
function crewModalBody() {
  const query = CREW_QUERY.trim();
  const found = crewMatches(query).filter((g) => g.rows.length);

  if (!found.length) {
    return `<div class="empty-note">'${escapeHtml(query)}' 와(과) 일치하는 기록이 없습니다.</div>`;
  }

  const active = found.find((g) => g.key === CREW_TAB);

  // ③ 행 상세 (목록으로 돌아가지 않고 이전/다음 행으로 바로 넘어갈 수 있습니다)
  if (active && CREW_ROW !== null && active.rows[CREW_ROW]) {
    const at = navPosition(CREW_ROW, active.rows.length);
    return `<button class="modal-back" data-crew-back>◀ ${escapeHtml(active.label)} 목록으로</button>
      ${navBar(at.pos, at.total)}
      ${recordDetailHtml(active.rows[CREW_ROW])}`;
  }

  // ② 선택한 대장의 표
  if (active) {
    const backLabel = found.length > 1 ? "◀ 다른 대장 선택" : "◀ 처음으로";
    return `<button class="modal-back" data-crew-back>${backLabel}</button>
      <div class="modal-sub">${escapeHtml(active.label)} · ${active.rows.length}건</div>
      ${renderTable(active.rows, active.columns, {
        detailTitle: active.detailTitle,
        center: true,
        emptyText: "기록이 없습니다.",
      })}`;
  }

  // ① 기록이 있는 대장만 골라서 보여줍니다
  const picks = found
    .map(
      (g) => `<button class="crew-pick" data-crew-tab="${g.key}">
        <span class="crew-pick-label">${escapeHtml(g.label)}</span>
        <span class="crew-pick-count">${g.rows.length}건</span>
        <span class="crew-pick-arrow" aria-hidden="true">›</span>
      </button>`
    )
    .join("");

  return `<p class="modal-note">기록이 있는 대장입니다. 보고 싶은 대장을 선택하세요.</p>
    <div class="crew-picks">${picks}</div>`;
}

/* 표를 보여줄 때만 팝업을 넓게 씁니다. */
function refreshCrewModal() {
  const query = CREW_QUERY.trim();
  const modal = document.querySelector(".modal");
  const wide = CREW_TAB !== null && CREW_ROW === null;
  if (modal) modal.classList.toggle("modal-wide", wide);
  openModal(`${query} · 조회 결과`, crewModalBody());
  // 행 상세를 보고 있을 때만 이전/다음을 켭니다 (openModal이 지운 뒤에 다시 켭니다)
  if (CREW_TAB !== null && CREW_ROW !== null) MODAL_NAV = { mode: "crew" };
}

function openCrewModal() {
  const query = CREW_QUERY.trim();
  const box = document.getElementById("crewResult");
  if (!query) {
    if (box) {
      box.innerHTML = `<div class="empty-note">조회할 이름이나 자산번호를 입력해주세요.</div>`;
    }
    return;
  }
  const found = crewMatches(query).filter((g) => g.rows.length);
  if (!found.length) {
    if (box) {
      box.innerHTML = `<div class="empty-note">'${escapeHtml(query)}' 와(과) 일치하는 기록이 없습니다. 한글 이름 · 영문 닉네임 · 자산번호로 찾아보세요.</div>`;
    }
    return;
  }
  if (box) {
    const total = found.reduce((sum, g) => sum + g.rows.length, 0);
    box.innerHTML = `<div class="crew-recall">
      <span>'${escapeHtml(query)}' · ${total}건 조회됨</span>
      <button class="crew-recall-btn" id="crewReopen">조회 창 다시 열기</button>
    </div>`;
  }
  CREW_TAB = null;
  CREW_ROW = null;
  refreshCrewModal();
}

/* 검색어를 기억해 둡니다. 팝업은 조회 버튼이나 Enter를 눌렀을 때만 엽니다. */
els.content.addEventListener("input", (e) => {
  if (e.target.id !== "crewSearch") return;
  CREW_QUERY = e.target.value;
});

els.content.addEventListener("keydown", (e) => {
  if (e.target.id === "crewSearch" && e.key === "Enter") {
    e.preventDefault();
    openCrewModal();
  }
});

els.content.addEventListener("click", (e) => {
  if (e.target.closest("#crewSearchBtn") || e.target.closest("#crewReopen")) {
    openCrewModal();
  }
});

/* 팝업 안에서의 이동: 대장 선택 / 행 펼치기 / 뒤로 가기 */
els.modalBody.addEventListener("click", (e) => {
  if (e.target.closest("[data-crew-back]")) {
    if (CREW_ROW !== null) CREW_ROW = null;
    else CREW_TAB = null;
    refreshCrewModal();
    return;
  }
  const pick = e.target.closest("[data-crew-tab]");
  if (pick) {
    CREW_TAB = pick.dataset.crewTab;
    CREW_ROW = null;
    refreshCrewModal();
    return;
  }
  const row = e.target.closest("tr[data-table]");
  if (row && CREW_TAB !== null) {
    // 이전/다음이 '화면에 보이는 순서'대로 움직이게, 그 표의 정렬 순서를 기억합니다.
    const state = TABLE_REGISTRY[row.dataset.table];
    NAV_ORDER = state ? state.order : null;
    CREW_ROW = Number(row.dataset.row);
    refreshCrewModal();
  }
});

function renderJeonsan() {
  const status = getRecords("jeonsan_status");
  const asset = getRecords("jeonsan_asset");
  const io = getRecords("jeonsan_io");

  const doneCount = status.filter((r) => (r["진행상태"] || "").includes("완료")).length;
  const ingCount = status.length - doneCount;

  const now = new Date();
  const monthLabel = `${now.getFullYear()}년 ${now.getMonth() + 1}월`;
  const thisMonth = filterCurrentMonthJeonsan(status);

  HANDLER_STATS = handlerMonthlyStats(status);
  const people = Object.entries(HANDLER_STATS).sort((a, b) => b[1].total - a[1].total);

  CREW_QUERY = "";
  CREW_TAB = null;
  CREW_ROW = null;

  return `
    <div class="kpi-grid">
      ${kpiCard("총 업무 건수", status.length + "건")}
      ${kpiCard("완료", doneCount + "건")}
      ${kpiCard("진행중/미완료", ingCount + "건")}
      ${kpiCard("자산 지급대장 건수", asset.length + "건")}
    </div>

    <h2 class="section-title">담당자</h2>
    <p class="section-note">이름을 누르면 월별 처리 건수를 볼 수 있습니다.</p>
    <div class="person-grid">
      ${
        people.length
          ? people.map(([label, stat]) => personCard(label, stat)).join("")
          : `<div class="empty-note">담당자 데이터가 없습니다.</div>`
      }
    </div>

    <div class="crew-panel">
      <h2 class="section-title">크루 · 자산번호 조회</h2>
      <p class="section-note">아래 세 표는 그대로 두고, 별도 창에서 해당 기록만 따로 찾아봅니다.
        자산번호로 찾으면 그 자산이 오간 기록(업무 · 지급 · 입출고)을 함께 볼 수 있습니다.
        기호는 무시하므로 <strong>LKG-NB-021</strong> 과 <strong>lkgnb021</strong> 이 같게 찾힙니다.</p>

      <div class="search-bar">
        <input type="search" id="crewSearch" placeholder="이름 · 닉네임 · 자산번호 (예: 곽보길 / Charles / LKG-NB-021)" autocomplete="off" />
        <button class="crew-search-btn" id="crewSearchBtn">조회</button>
      </div>

      <div class="crew-result-box" id="crewResult"></div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>최근 전산 업무 (최신 10건)</h2>
        <span class="panel-meta">${monthLabel} 기준</span>
      </div>
      <div class="panel-body">
        ${renderTable(thisMonth.slice(-10).reverse(),
          ["유형","요청자","부서","자산번호","업무내용","담당자","완료일자","진행상태"],
          { detailTitle: "전산 업무 상세", center: true,
            emptyText: monthLabel + "에 등록된 업무가 없습니다." })}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>업무현황 로그</h2><span class="panel-meta">${status.length}건</span></div>
      <div class="panel-body">
        ${renderTable(status.slice().reverse(),
          ["유형","요청자","부서","자산번호","업무내용","조치사항","담당자","요청일자","착수일자","완료일자","진행상태","비고"],
          { detailTitle: "전산 업무 상세", center: true })}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>자산 지급대장</h2><span class="panel-meta">${asset.length}건</span></div>
      <div class="panel-body">${renderTable(sortByDateDesc(asset, "완료일자"), null, { detailTitle: "자산 지급 상세", center: true })}</div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>입출고 · 대여 로그</h2><span class="panel-meta">${io.length}건</span></div>
      <div class="panel-body">${renderTable(io.slice().reverse(), null, { detailTitle: "입출고 상세", center: true })}</div>
    </div>
  `;
}

/* ---------------- 탕비실 ---------------- */

/* 전월 대비 사용량 증감을 가운데 기준선 양쪽으로 뻗는 막대로 그립니다.
   증가는 앰버, 감소는 청록. 색만으로 구분되지 않도록 숫자를 항상 같이 적습니다. */
function usageChangeChart(items) {
  const changed = items
    .filter((i) => typeof i["사용량증감"] === "number" && i["사용량증감"] !== 0)
    .sort((a, b) => Math.abs(b["사용량증감"]) - Math.abs(a["사용량증감"]))
    .slice(0, 12);

  if (!changed.length) {
    return `<div class="empty-note">전월과 비교할 사용량 변화가 없습니다.</div>`;
  }

  const max = Math.max(...changed.map((i) => Math.abs(i["사용량증감"])));
  const rows = changed
    .map((item) => {
      const delta = item["사용량증감"];
      const up = delta > 0;
      const width = (Math.abs(delta) / max) * 50;
      const bar = up ? `left:50%; width:${width}%;` : `left:${50 - width}%; width:${width}%;`;
      return `<div class="div-row">
        <div class="div-label" title="${escapeHtml(item["상품명"])}">${escapeHtml(item["상품명"])}</div>
        <div class="div-track">
          <div class="div-axis"></div>
          <div class="div-bar ${up ? "up" : "down"}" style="${bar}"></div>
          <div class="div-tip">전월 ${item["전월사용량"]} → 이번 달 ${item["사용량"]}</div>
        </div>
        <div class="div-value ${up ? "up" : "down"}">${up ? "+" : ""}${delta}</div>
      </div>`;
    })
    .join("");

  return `<div class="div-chart">
    <div class="chart-legend">
      <span class="legend-item"><span class="legend-swatch up"></span>사용량 증가</span>
      <span class="legend-item"><span class="legend-swatch down"></span>사용량 감소</span>
    </div>
    ${rows}
  </div>`;
}

function renderTangbisil() {
  const tb = getTangbisil();
  const items = tb.items || [];
  const reorder = items.filter((i) => i["발주필요"]);
  const totalUsage = items.reduce((sum, i) => sum + (Number(i["사용량"]) || 0), 0);
  const totalIn = items.reduce((sum, i) => sum + (Number(i["입고량"]) || 0), 0);

  const reorderPanel = reorder.length
    ? `<div class="alert-panel">
        <div class="alert-head">
          <span class="alert-icon" aria-hidden="true">!</span>
          <strong>발주 필요 ${reorder.length}건</strong>
          <span class="alert-note">구글 시트에서 잔여 재고가 빨간색으로 표시된 품목입니다.</span>
        </div>
        <ul class="alert-list">
          ${reorder
            .map(
              (i) => `<li>
                <span class="alert-name">${escapeHtml(i["상품명"])}</span>
                <span class="alert-stock">잔여 ${i["현재고"] ?? "-"}</span>
              </li>`
            )
            .join("")}
        </ul>
      </div>`
    : `<div class="ok-panel">현재 발주가 필요한 품목이 없습니다.</div>`;

  return `
    <div class="kpi-grid">
      ${kpiCard("관리 품목", items.length + "종", tb.month_title || "")}
      ${kpiCard("발주 필요", reorder.length + "건", "잔여 재고 경고 표시 기준")}
      ${kpiCard("이번 달 사용량", totalUsage.toLocaleString() + "개", "전 품목 합계")}
      ${kpiCard("이번 달 입고량", totalIn.toLocaleString() + "개", "전 품목 합계")}
      ${kpiCard(
        "진열 진행",
        `${tb.workdays_done} / ${tb.workdays_total}일`,
        (tb.holidays_excluded || []).length
          ? `주말·공휴일 ${tb.holidays_excluded.length}일 제외`
          : "주말·공휴일 제외 근무일 기준"
      )}
    </div>

    ${reorderPanel}

    <div class="panel">
      <div class="panel-header">
        <h2>재고 현황</h2>
        <span class="panel-meta">${items.length}종 · 품목을 누르면 사용량 · 입고량 · 전월 재고</span>
      </div>
      <div class="panel-body">${stockTable(items)}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>전월 대비 사용량 증감</h2>
        <span class="panel-meta">${escapeHtml(tb.prev_month_title || "전월 자료 없음")} 대비</span>
      </div>
      <div class="panel-body">${usageChangeChart(items)}</div>
    </div>
  `;
}

/* 이번 달 쓰는 속도로 지금 재고가 몇 달이나 갈지 봅니다.
   (잔여 재고 ÷ 이번 달 사용량). 이번 달에 안 쓴 품목은 계산하지 않습니다. */
function coverMonths(item) {
  const use = Number(item["사용량"]) || 0;
  const stock = Number(item["현재고"]);
  if (!use || !Number.isFinite(stock)) return null;
  return stock / use;
}

/* 소진까지 남은 기간을 네 등급으로 나눕니다.
   등급 순서(0→3)가 곧 표의 정렬 순서라서, 급한 품목이 위로 올라옵니다. */
const COVER_BANDS = [
  { cls: "danger", label: "1개월 미만" },
  { cls: "warn", label: "2개월 미만" },
  { cls: "ok", label: "여유" },
  { cls: "none", label: "사용 기록 없음" },
];

function coverBand(months) {
  if (months === null) return COVER_BANDS[3];
  if (months < 1) return COVER_BANDS[0];
  if (months < 2) return COVER_BANDS[1];
  return COVER_BANDS[2];
}

const COVER_CAP = 6; // 6개월 넘게 남은 품목은 막대를 꽉 채웁니다

function coverText(months) {
  if (months === null) return "-";
  return months >= COVER_CAP ? "6개월 이상" : `약 ${months.toFixed(1)}개월치`;
}

/* 화면에 그린 재고 표의 품목을 팝업에서 다시 찾기 위해 보관합니다. */
let TB_ITEMS = [];

/* 재고 표 하나로 모두 봅니다.
   - 품목 앞의 점 = 소진 임박 정도 (칸 안의 막대·글자와 같은 뜻이라, 색을 못 읽어도 됩니다)
   - 잔여 재고 / 상태(발주 필요) / 소진 예상까지 한 줄에
   - 사용량 · 입고량 · 전월 재고는 품목을 눌러 팝업으로
   정렬은 '급한 순'입니다. 시트 순서대로 보면 발주할 것을 찾으려고 눈이 위아래로 헤매게 됩니다. */
function stockTable(items) {
  if (!items.length) {
    return `<div class="empty-note">탕비실 데이터를 불러오지 못했습니다.</div>`;
  }

  // 시트에서 빨갛게 칠한 '발주 필요'는 계산과 상관없이 맨 위로 올립니다.
  const rank = (i) =>
    i["발주필요"] ? -1 : COVER_BANDS.indexOf(coverBand(coverMonths(i)));

  const sorted = items
    .slice()
    .sort((a, b) => {
      const d = rank(a) - rank(b);
      if (d !== 0) return d;
      const ma = coverMonths(a), mb = coverMonths(b);
      if (ma === null) return mb === null ? 0 : 1;
      if (mb === null) return -1;
      return ma - mb;
    });

  TB_ITEMS = sorted;

  const need = items.filter((i) => i["발주필요"]).length;
  const legend = `<div class="stock-legend">
    <span class="sl-count">전체 ${items.length}종 · 정상 ${items.length - need}종 · <strong>발주 필요 ${need}종</strong></span>
    <span class="sl-dots">
      ${COVER_BANDS.map(
        (b) => `<span class="legend-item"><span class="dot ${b.cls}"></span>${b.label}</span>`
      ).join("")}
    </span>
  </div>`;

  const rows = sorted
    .map((i, idx) => {
      const months = coverMonths(i);
      const band = coverBand(months);
      const width = months === null ? 0 : Math.max(Math.min(months / COVER_CAP, 1) * 100, 3);
      const badge = i["발주필요"]
        ? `<span class="badge warn">발주 필요</span>`
        : `<span class="badge done">정상</span>`;
      return `<tr class="row-clickable ${i["발주필요"] ? "row-alert" : ""}" data-tb-row="${idx}">
        <td class="cell-strong" title="${escapeHtml(i["상품명"])} · ${band.label}">
          <span class="stock-name"><span class="dot ${band.cls}" aria-hidden="true"></span>${escapeHtml(i["상품명"])}</span>
        </td>
        <td class="cover-cell">
          <div class="cover-wrap">
            <span class="cover-mini"><span class="cover-fill ${band.cls}" style="width:${width}%"></span></span>
            <span class="cover-text ${months === null ? "muted" : ""}">${coverText(months)}</span>
          </div>
        </td>
        <td class="cell-stock ${i["발주필요"] ? "danger" : ""}">${escapeHtml(i["현재고"] ?? "-")}</td>
        <td>${badge}</td>
      </tr>`;
    })
    .join("");

  return `${legend}
    <div class="table-hint">소진이 급한 순 · 품목을 누르면 사용량 · 입고량 · 전월 재고를 볼 수 있습니다.
      (소진 예상 = 잔여 재고 ÷ 이번 달 사용량)</div>
    <div class="table-scroll"><table class="data-table stock-table center-all">
    <thead><tr>
      <th class="col-name">상품명</th><th class="cover-th">재고 소진 예상</th>
      <th class="col-stock">잔여 재고</th><th class="col-status">상태</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

/* 탕비실 품목 상세 팝업. index는 표에서 몇 번째 행인지(이전/다음 이동용)입니다. */
function openTangbisilItem(item, index) {
  if (!item) return;
  const delta = item["사용량증감"];
  const deltaText =
    typeof delta === "number" ? (delta > 0 ? `+${delta}` : String(delta)) : "-";
  const months = coverMonths(item);
  const band = coverBand(months);
  const need = item["발주필요"];

  const line = (k, v, cls) =>
    `<div class="detail-row"><div class="detail-key">${k}</div>
      <div class="detail-value ${cls || ""}">${v}</div></div>`;

  const hasIndex = typeof index === "number";
  openModal(
    item["상품명"],
    `${hasIndex ? navBar(index + 1, TB_ITEMS.length) : ""}
     <div class="modal-kpi">
       ${kpiCard("잔여 재고", numText(item["현재고"]) + "개", need ? "발주 필요" : "정상")}
       ${kpiCard("이번 달 사용량", numText(item["사용량"]) + "개")}
       ${kpiCard("이번 달 입고량", numText(item["입고량"]) + "개")}
     </div>
     <div class="detail-list">
       ${line("전월 재고", numText(item["전월재고"]))}
       ${line("전월 사용량", numText(item["전월사용량"]))}
       ${line("전월 대비 사용량", deltaText,
              typeof delta === "number" && delta !== 0 ? (delta > 0 ? "delta up" : "delta down") : "")}
       ${line("박스당 개입수", numText(item["박스당개입수"]))}
       ${line("재고 소진 예상",
              `<span class="dot ${band.cls}"></span>${escapeHtml(coverText(months))}` +
              (months === null ? "" : ` <span class="muted">(${band.label})</span>`))}
     </div>`
  );
  // 재고 표는 '급한 순'으로 이미 정렬돼 있어서, 이전/다음이 곧 급한 순서입니다.
  if (hasIndex) MODAL_NAV = { mode: "tangbisil", index };
}

els.content.addEventListener("click", (e) => {
  const row = e.target.closest("tr[data-tb-row]");
  if (row) {
    const idx = Number(row.dataset.tbRow);
    NAV_ORDER = null; // 표에 그려진 순서 = TB_ITEMS 순서
    openTangbisilItem(TB_ITEMS[idx], idx);
  }
});

/* ---------------- 소모품 ---------------- */

/* "김예림(Rimmy)_정보보안팀/휴직" -> 이름 / 닉네임 / 소속 */
function parseTarget(raw) {
  const text = String(raw || "").trim();
  if (!text) return { label: "", name: "", nick: "", team: "" };
  const cut = text.indexOf("_");
  const who = cut === -1 ? text : text.slice(0, cut);
  const team = cut === -1 ? "" : text.slice(cut + 1);
  const m = who.match(/^(.*?)\s*\(([^()]*)\)\s*$/);
  return {
    label: text,
    name: (m ? m[1] : who).trim(),
    nick: (m ? m[2] : "").trim(),
    team: team.trim(),
  };
}

/* 불출 대장 한 줄을 다루기 쉬운 형태로 바꿉니다. */
function somopumRows() {
  return getRecords("somopum")
    .map((r) => ({
      raw: r,
      date: parseKDate(pick(r, "날짜")),
      item: String(pick(r, "품목") || "").trim(),
      qty: Number(String(pick(r, "수량")).replace(/,/g, "")) || 0,
      target: parseTarget(pick(r, "불출 대상")),
      issued: /true|y|완료|✓/i.test(String(pick(r, "불출 여부"))),
    }))
    .filter((x) => x.item);
}

function somopumStock() {
  const s = getObject("somopum_stock");
  return s && Array.isArray(s.months) ? s : { months: [], latest: null };
}

function numText(v) {
  if (v === null || v === undefined || v === "") return "-";
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString() : String(v);
}

/* 같은 기준으로 묶어 수량과 건수를 더합니다. */
function sumBy(rows, keyFn) {
  const map = new Map();
  rows.forEach((r) => {
    const k = keyFn(r);
    if (!k) return;
    const cur = map.get(k) || { key: k, qty: 0, count: 0 };
    cur.qty += r.qty;
    cur.count += 1;
    map.set(k, cur);
  });
  return [...map.values()].sort((a, b) => b.qty - a.qty || b.count - a.count);
}

/* 순위 막대. 품목/크루 이름을 누르면 상세 팝업이 열립니다.
   막대 길이는 '건수'입니다. 수량은 품목마다 표기 단위가 달라서(묶음/개/박스)
   서로 더하면 뜻이 없어지기 때문입니다. */
function rankBars(entries, attr) {
  if (!entries.length) return `<div class="empty-note">집계할 자료가 없습니다.</div>`;
  const max = Math.max(...entries.map((e) => e.count), 1);
  return `<div class="bar-chart rank-chart">${entries
    .map(
      (e, i) => `<div class="bar-row">
        <button class="bar-link" ${attr}="${escapeHtml(e.key)}" title="${escapeHtml(e.key)} 상세 보기">
          <span class="bar-rank">${i + 1}</span>${escapeHtml(e.key)}
        </button>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((e.count / max) * 100)}%"></div></div>
        <div class="bar-count">${e.count}건</div>
      </div>`
    )
    .join("")}</div>`;
}

/* 축 눈금이 예쁘게 떨어지도록 최댓값을 올림합니다. (7 -> 10, 23 -> 25 처럼) */
function niceMax(value) {
  if (value <= 5) return 5;
  const exp = Math.pow(10, Math.floor(Math.log10(value)));
  const unit = value / exp;
  const step = unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 2.5 ? 2.5 : unit <= 5 ? 5 : 10;
  return step * exp;
}

/* 시간 흐름은 막대보다 선이 읽기 쉬워서, 월별 추이는 면적 선그래프로 그립니다.
   점 위에 마우스를 올리면 그 달의 값이 뜹니다. */
function trendAreaChart(entries, unit) {
  if (!entries.length) {
    return `<div class="empty-note">날짜를 읽을 수 있는 기록이 없습니다.</div>`;
  }
  if (entries.length === 1) {
    // 한 달치뿐이면 선그래프가 의미 없으므로 숫자 하나로 보여줍니다.
    return `<div class="single-stat">
      <div class="single-stat-label">${escapeHtml(entries[0][0])}</div>
      <div class="single-stat-value">${entries[0][1].toLocaleString()}${unit}</div>
    </div>`;
  }

  const W = 760, H = 240, PL = 54, PR = 20, PT = 24, PB = 36;
  const top = niceMax(Math.max(...entries.map((e) => e[1])));
  const px = (i) => PL + (i * (W - PL - PR)) / (entries.length - 1);
  const py = (v) => PT + (1 - v / top) * (H - PT - PB);

  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((f) => {
      const v = top * f;
      const y = py(v);
      return `<line class="tc-grid" x1="${PL}" x2="${W - PR}" y1="${y}" y2="${y}" />
        <text class="tc-ytick" x="${PL - 10}" y="${y + 4}" text-anchor="end">${Math.round(v).toLocaleString()}</text>`;
    })
    .join("");

  const line = entries.map((e, i) => `${i ? "L" : "M"}${px(i)},${py(e[1])}`).join(" ");
  const area = `${line} L${px(entries.length - 1)},${py(0)} L${px(0)},${py(0)} Z`;

  const maxIdx = entries.reduce((b, e, i) => (e[1] > entries[b][1] ? i : b), 0);
  const step = (W - PL - PR) / (entries.length - 1);

  const points = entries
    .map(([label, value], i) => {
      const cx = px(i), cy = py(value);
      const tx = Math.min(Math.max(cx, PL + 62), W - PR - 62);
      // 값이 항상 보이는 것은 최댓값과 마지막 달 두 개뿐입니다 (전부 적으면 지저분해집니다)
      const hasLabel = i === maxIdx || i === entries.length - 1;
      const fixed = hasLabel
        ? `<text class="tc-value" x="${cx}" y="${cy - 12}" text-anchor="middle">${value.toLocaleString()}</text>`
        : "";
      // 고정 라벨이 있는 점은 말풍선을 한 단 더 올려서 숫자를 가리지 않게 합니다.
      const lift = hasLabel ? 18 : 0;
      return `<g class="tc-pt">
        <rect class="tc-hit" x="${cx - step / 2}" y="${PT}" width="${step}" height="${H - PT - PB}" />
        <line class="tc-cross" x1="${cx}" x2="${cx}" y1="${PT}" y2="${H - PB}" />
        <circle class="tc-dot" cx="${cx}" cy="${cy}" r="4" />
        ${fixed}
        <g class="tc-tip" transform="translate(${tx},${cy - lift})">
          <rect x="-60" y="-42" width="120" height="26" rx="6" />
          <text x="0" y="-24" text-anchor="middle">${escapeHtml(label)} · ${value.toLocaleString()}${unit}</text>
        </g>
      </g>
      <text class="tc-xtick" x="${cx}" y="${H - PB + 20}" text-anchor="middle">${escapeHtml(label)}</text>`;
    })
    .join("");

  return `<div class="trend-chart">
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="월별 추이">
      ${grid}
      <path class="tc-area" d="${area}" />
      <path class="tc-line" d="${line}" />
      ${points}
    </svg>
  </div>`;
}

/* 크루 x 월 히트맵. 총 건수 순으로 줄을 세워서 '순위'까지 이 한 판이 대신합니다.
   '누가 많이 쓰나'(위에서부터)와 '언제 몰리나'(색 진하기)를 같이 봅니다.
   색은 한 가지 색조의 명암 5단계이고, 칸마다 숫자를 같이 적어 색만으로 읽지 않게 했습니다. */
const HEAT_STEPS = ["#8FBBAF", "#6CA697", "#4E8F7E", "#377566", "#254741"];

function heatLevel(value, max) {
  if (!value) return -1;
  const idx = Math.ceil((value / max) * HEAT_STEPS.length) - 1;
  return Math.min(Math.max(idx, 0), HEAT_STEPS.length - 1);
}

function crewMonthHeatmap(rows, months) {
  const byCrew = new Map();
  rows.forEach((r) => {
    const name = r.target.nick ? `${r.target.name}(${r.target.nick})` : r.target.name;
    if (!name || !r.date) return;
    const key = monthKey(r.date);
    if (!byCrew.has(name)) byCrew.set(name, { name, total: 0, months: {} });
    const slot = byCrew.get(name);
    slot.total += 1;
    slot.months[key] = (slot.months[key] || 0) + 1;
  });

  const list = [...byCrew.values()].sort((a, b) => b.total - a.total).slice(0, 12);
  if (!list.length || !months.length) {
    return `<div class="empty-note">집계할 자료가 없습니다.</div>`;
  }

  const max = Math.max(...list.flatMap((c) => months.map((m) => c.months[m] || 0)), 1);

  const head = `<div class="hm-row hm-head">
    <div class="hm-name">순위 · 크루</div>
    ${months.map((m) => `<div class="hm-cell-head">${escapeHtml(m.slice(5))}월</div>`).join("")}
    <div class="hm-total">총 건수</div>
  </div>`;

  const body = list
    .map(
      (c, i) => `<div class="hm-row">
        <button class="hm-name hm-link" data-som-crew="${escapeHtml(c.name)}" title="${escapeHtml(c.name)} 상세 보기"><span class="bar-rank">${i + 1}</span>${escapeHtml(c.name)}</button>
        ${months
          .map((m) => {
            const v = c.months[m] || 0;
            const lv = heatLevel(v, max);
            const style = lv < 0 ? "" : `background:${HEAT_STEPS[lv]};`;
            const cls = lv < 0 ? "hm-cell zero" : `hm-cell${lv >= 2 ? " on-dark" : ""}`;
            return `<div class="${cls}" style="${style}" title="${escapeHtml(m)} · ${v}건">${v || ""}</div>`;
          })
          .join("")}
        <div class="hm-total">${c.total}</div>
      </div>`
    )
    .join("");

  const legend = `<div class="hm-legend">
    <span>적음</span>
    ${HEAT_STEPS.map((c) => `<span class="hm-swatch" style="background:${c}"></span>`).join("")}
    <span>많음 · 칸 안 숫자는 그 달의 불출 건수, 오른쪽 끝은 총 건수(=순위 기준)</span>
  </div>`;

  return `<div class="heatmap" style="--hm-cols:${months.length}">${head}${body}</div>${legend}`;
}

/* --- 월별 잔여 재고 --- */
let SOM_MONTH = null;

function somStockPanel() {
  const stock = somopumStock();
  if (!stock.months.length) {
    return `<div class="empty-note">월별 재고 자료를 아직 불러오지 못했습니다. (시트의 '월별 불출량&amp;검수' 탭을 읽는 중일 수 있습니다)</div>`;
  }
  if (!stock.months.some((m) => m.label === SOM_MONTH)) {
    SOM_MONTH = stock.latest || stock.months[stock.months.length - 1].label;
  }
  const cur = stock.months.find((m) => m.label === SOM_MONTH);

  const tabs = stock.months
    .map(
      (m) => `<button class="month-tab ${m.label === SOM_MONTH ? "active" : ""}"
        data-som-month="${escapeHtml(m.label)}">${escapeHtml(m.label)}</button>`
    )
    .join("");

  const items = cur.items;
  const totalRemain = items.reduce((s, i) => s + (Number(i["잔여재고"]) || 0), 0);

  // 기본 화면에는 품목과 잔여 재고만. 나머지(불출량 · 입고량)는 품목을 눌러 봅니다.
  const body = items.length
    ? `<div class="table-hint">품목을 누르면 그 품목의 불출량 · 입고량을 볼 수 있습니다.</div>
      <div class="table-scroll"><table class="data-table center-all">
        <thead><tr><th>품목</th><th class="num">잔여 재고</th></tr></thead>
        <tbody>${items
          .map(
            (i) => `<tr class="row-clickable" data-som-stock="${escapeHtml(i["품목"])}">
              <td class="cell-strong">${escapeHtml(i["품목"])}</td>
              <td class="num cell-stock">${numText(i["잔여재고"])}</td>
            </tr>`
          )
          .join("")}</tbody>
      </table></div>`
    : `<div class="empty-note">${escapeHtml(cur.label)}에 기록된 품목이 없습니다.</div>`;

  return `<div class="month-tabs">${tabs}</div>
    <div class="month-summary">${escapeHtml(cur.label)} · 품목 ${items.length}종 · 잔여 재고 합계 ${totalRemain.toLocaleString()}개</div>
    ${body}`;
}

/* 재고 표에서 품목을 눌렀을 때: 그 품목의 월별 불출량 · 입고량만 보여줍니다. */
function openStockItemModal(name) {
  const stock = somopumStock();
  const rows = stock.months
    .map((m) => ({ label: m.label, item: m.items.find((i) => i["품목"] === name) }))
    .filter((r) => r.item);

  if (!rows.length) {
    openModal(name, `<div class="empty-note">기록이 없습니다.</div>`);
    return;
  }

  const cur = rows.find((r) => r.label === SOM_MONTH) || rows[rows.length - 1];
  const sum = (field) => rows.reduce((s, r) => s + (Number(r.item[field]) || 0), 0);

  openModal(
    `${name} · 불출량 · 입고량`,
    `<div class="modal-kpi">
       ${kpiCard("불출량", numText(cur.item["불출량"]) + "개", cur.label)}
       ${kpiCard("입고량", numText(cur.item["입고수량"]) + "개", cur.label)}
       ${kpiCard("잔여 재고", numText(cur.item["잔여재고"]) + "개", cur.label + " 기준")}
     </div>
     <div class="modal-sub">월별</div>
     <div class="table-scroll"><table class="data-table center-all">
       <thead><tr><th>월</th><th class="num">불출량</th><th class="num">입고량</th></tr></thead>
       <tbody>${rows
         .map(
           (r) => `<tr${r.label === cur.label ? ' class="row-current"' : ""}>
             <td class="cell-strong">${escapeHtml(r.label)}</td>
             <td class="num">${numText(r.item["불출량"])}</td>
             <td class="num">${numText(r.item["입고수량"])}</td>
           </tr>`
         )
         .join("")}
         <tr class="row-total"><td class="cell-strong">합계</td>
           <td class="num">${sum("불출량").toLocaleString()}</td>
           <td class="num">${sum("입고수량").toLocaleString()}</td></tr>
       </tbody>
     </table></div>`
  );
}

/* 월별 불출 '건수'를 [["2026.09", 12], ...] 형태로 만듭니다. */
function monthlyCounts(rows) {
  const map = new Map();
  rows.forEach((r) => {
    if (!r.date) return;
    const k = monthKey(r.date);
    map.set(k, (map.get(k) || 0) + 1);
  });
  return [...map.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
}

/* 품목 하나의 월별 불출 상세 팝업 */
function openItemModal(itemName) {
  const rows = somopumRows().filter((r) => r.item === itemName);
  const modal = document.querySelector(".modal");
  if (modal) modal.classList.add("modal-wide");

  if (!rows.length) {
    openModal(`${itemName} · 월별 불출량`, `<div class="empty-note">기록이 없습니다.</div>`);
    return;
  }

  const counts = monthlyCounts(rows);
  const qtyByMonth = new Map();
  rows.forEach((r) => {
    if (!r.date) return;
    const k = monthKey(r.date);
    qtyByMonth.set(k, (qtyByMonth.get(k) || 0) + r.qty);
  });

  const table = `<div class="table-scroll"><table class="data-table center-all">
      <thead><tr><th>월</th><th class="num">불출 건수</th><th class="num">수량 합계</th></tr></thead>
      <tbody>${counts
        .map(
          ([m, c]) => `<tr><td class="cell-strong">${escapeHtml(m)}</td>
            <td class="num">${c}</td><td class="num">${(qtyByMonth.get(m) || 0).toLocaleString()}</td></tr>`
        )
        .join("")}</tbody>
    </table></div>`;

  const log = `<div class="table-scroll"><table class="data-table center-all">
      <thead><tr><th>날짜</th><th class="num">수량</th><th>불출 대상</th><th>불출 여부</th></tr></thead>
      <tbody>${rows
        .slice()
        .reverse()
        .map(
          (r) => `<tr>
            <td>${escapeHtml(pick(r.raw, "날짜") || "-")}</td>
            <td class="num">${r.qty}</td>
            <td title="${escapeHtml(r.target.label)}">${escapeHtml(r.target.label || "-")}</td>
            <td>${r.issued ? '<span class="badge done">불출 완료</span>' : '<span class="badge warn">대기</span>'}</td>
          </tr>`
        )
        .join("")}</tbody>
    </table></div>`;

  openModal(
    `${itemName} · 월별 불출량`,
    `<p class="modal-note">총 ${rows.length}건 · 받은 크루 ${
      new Set(rows.map((r) => r.target.label)).size
    }명</p>
     <div class="modal-sub">월별 불출 건수</div>
     ${trendAreaChart(counts, "건")}
     <div class="modal-sub" style="margin-top:22px;">월별 집계</div>
     ${table}
     <div class="modal-sub" style="margin-top:22px;">불출 내역</div>
     ${log}`
  );
}

/* --- 크루별 불출 조회 (별도 팝업) --- */
let SOM_QUERY = "";
let SOM_ROW = null;
let SOM_MATCH = [];

function somModalBody() {
  const rows = SOM_MATCH;
  if (!rows.length) return `<div class="empty-note">기록이 없습니다.</div>`;

  if (SOM_ROW !== null && rows[SOM_ROW]) {
    const at = navPosition(SOM_ROW, rows.length);
    return `<button class="modal-back" data-som-back>◀ 목록으로</button>
      ${navBar(at.pos, at.total)}
      ${recordDetailHtml(rows[SOM_ROW].raw)}`;
  }

  const byItem = sumBy(rows, (r) => r.item);
  const pending = rows.filter((r) => !r.issued).length;
  const who = [...new Set(rows.map((r) => r.target.label))].slice(0, 4).join(", ");

  const summary = `<div class="table-scroll"><table class="data-table center-all">
      <thead><tr><th>소모품 종류</th><th class="num">총 수량</th><th class="num">불출 횟수</th></tr></thead>
      <tbody>${byItem
        .map(
          (e) => `<tr><td class="cell-strong">${escapeHtml(e.key)}</td>
            <td class="num">${e.qty.toLocaleString()}</td><td class="num">${e.count}</td></tr>`
        )
        .join("")}</tbody>
    </table></div>`;

  const log = `<div class="table-scroll"><table class="data-table center-all">
      <thead><tr><th>날짜</th><th>품목</th><th class="num">수량</th><th>불출 대상</th><th>불출 여부</th></tr></thead>
      <tbody>${rows
        .map(
          (r, i) => `<tr class="row-clickable" data-som-row="${i}">
            <td>${escapeHtml(pick(r.raw, "날짜") || "-")}</td>
            <td title="${escapeHtml(r.item)}">${escapeHtml(r.item)}</td>
            <td class="num">${r.qty}</td>
            <td title="${escapeHtml(r.target.label)}">${escapeHtml(r.target.label || "-")}</td>
            <td>${r.issued ? '<span class="badge done">불출 완료</span>' : '<span class="badge warn">대기</span>'}</td>
          </tr>`
        )
        .join("")}</tbody>
    </table></div>`;

  return `<p class="modal-note">${escapeHtml(who)} · 총 ${rows.length}건${
    pending ? ` · <strong>미불출 ${pending}건</strong>` : ""
  }</p>
    <div class="modal-sub">월별 불출 건수</div>
    ${trendAreaChart(monthlyCounts(rows), "건")}
    <div class="modal-sub" style="margin-top:22px;">소모품 종류별 합계</div>
    ${summary}
    <div class="modal-sub" style="margin-top:22px;">전체 불출 내역 (행을 누르면 상세)</div>
    ${log}`;
}

function refreshSomModal() {
  const modal = document.querySelector(".modal");
  if (modal) modal.classList.toggle("modal-wide", SOM_ROW === null);
  openModal(`${SOM_QUERY.trim()} · 소모품 불출 내역`, somModalBody());
  if (SOM_ROW !== null) MODAL_NAV = { mode: "somopum" };
}

function openSomModal() {
  const query = SOM_QUERY.trim();
  const box = document.getElementById("somResult");
  if (!query) {
    if (box) box.innerHTML = `<div class="empty-note">조회할 크루 이름을 입력해주세요.</div>`;
    return;
  }
  const needle = query.toLowerCase();
  SOM_MATCH = somopumRows().filter((r) => r.target.label.toLowerCase().includes(needle));
  if (!SOM_MATCH.length) {
    if (box) {
      box.innerHTML = `<div class="empty-note">'${escapeHtml(query)}' 에게 불출된 기록이 없습니다. 한글 이름이나 영문 닉네임으로 찾아보세요.</div>`;
    }
    return;
  }
  if (box) {
    const qty = SOM_MATCH.reduce((s, r) => s + r.qty, 0);
    box.innerHTML = `<div class="crew-recall">
      <span>'${escapeHtml(query)}' · ${SOM_MATCH.length}건 / ${qty.toLocaleString()}개</span>
      <button class="crew-recall-btn" id="somReopen">조회 창 다시 열기</button>
    </div>`;
  }
  SOM_ROW = null;
  refreshSomModal();
}

els.content.addEventListener("input", (e) => {
  if (e.target.id === "somSearch") SOM_QUERY = e.target.value;
});

els.content.addEventListener("keydown", (e) => {
  if (e.target.id === "somSearch" && e.key === "Enter") {
    e.preventDefault();
    openSomModal();
  }
});

els.content.addEventListener("click", (e) => {
  if (e.target.closest("#somSearchBtn") || e.target.closest("#somReopen")) {
    openSomModal();
    return;
  }
  const monthBtn = e.target.closest("[data-som-month]");
  if (monthBtn) {
    SOM_MONTH = monthBtn.dataset.somMonth;
    const box = document.getElementById("somStockBox");
    if (box) box.innerHTML = somStockPanel();
    return;
  }
  // 월별 잔여 재고 표에서 품목을 누르면 불출량 · 입고량
  const stockRow = e.target.closest("tr[data-som-stock]");
  if (stockRow) {
    openStockItemModal(stockRow.dataset.somStock);
    return;
  }
  // 순위에서 품목 이름을 누르면 그 품목의 월별 불출량
  const itemBtn = e.target.closest("[data-som-item]");
  if (itemBtn) {
    openItemModal(itemBtn.dataset.somItem);
    return;
  }
  // 순위/히트맵에서 크루 이름을 누르면 그 크루의 불출 내역
  const crewBtn = e.target.closest("[data-som-crew]");
  if (crewBtn) {
    SOM_QUERY = crewBtn.dataset.somCrew;
    const input = document.getElementById("somSearch");
    if (input) input.value = SOM_QUERY;
    openSomModal();
  }
});

els.modalBody.addEventListener("click", (e) => {
  if (e.target.closest("[data-som-back]")) {
    SOM_ROW = null;
    refreshSomModal();
    return;
  }
  const row = e.target.closest("tr[data-som-row]");
  if (row) {
    NAV_ORDER = null; // 이 표는 자료에 담긴 순서대로 그립니다
    SOM_ROW = Number(row.dataset.somRow);
    refreshSomModal();
  }
});

function renderSomopum() {
  const rows = somopumRows();
  const stock = somopumStock();
  SOM_QUERY = "";
  SOM_ROW = null;
  SOM_MATCH = [];
  CREW_TAB = null;

  const now = new Date();
  const monthLabel = `${now.getFullYear()}년 ${now.getMonth() + 1}월`;
  const thisMonth = rows.filter((r) => isSameMonth(r.date, now));
  const pending = rows.filter((r) => !r.issued).length;

  const latest = stock.months.length ? stock.months[stock.months.length - 1] : null;
  const remainTotal = latest
    ? latest.items.reduce((s, i) => s + (Number(i["잔여재고"]) || 0), 0)
    : 0;

  const monthCounts = monthlyCounts(rows);
  const months = monthCounts.map(([m]) => m);

  // 순위는 '건수' 기준입니다. 수량은 품목마다 단위가 달라서(묶음/개/박스) 합치면 뜻이 없어집니다.
  // 크루 순위는 아래 히트맵이 총 건수 순으로 줄을 세우면서 겸하고 있습니다.
  const itemRank = sumBy(rows, (r) => r.item)
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  return `
    <div class="kpi-grid">
      ${kpiCard("이번 달 불출", thisMonth.length + "건", monthLabel + " 기준")}
      ${kpiCard("전체 불출 기록", rows.length + "건", "누적")}
      ${kpiCard("미불출 대기", pending + "건", "불출 여부 미체크")}
      ${kpiCard("관리 품목", (latest ? latest.items.length : 0) + "종", latest ? latest.label + " 재고 조사" : "재고 자료 없음")}
      ${kpiCard("잔여 재고 합계", remainTotal.toLocaleString() + "개", latest ? latest.label + " 기준" : "-")}
    </div>

    <div class="crew-panel">
      <h2 class="section-title">크루별 불출 조회</h2>
      <p class="section-note">크루 이름으로 찾으면, 그 크루에게 나간 소모품 종류와 수량을 별도 창에서 보여줍니다.</p>

      <div class="search-bar">
        <input type="search" id="somSearch" placeholder="한글 이름 또는 영문 닉네임 (예: 곽보길 / Charles)" autocomplete="off" />
        <button class="crew-search-btn" id="somSearchBtn">조회</button>
      </div>

      <div class="crew-result-box" id="somResult"></div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>월별 불출 추이</h2>
        <span class="panel-meta">불출 대장 날짜 기준 · 건수</span>
      </div>
      <div class="panel-body">${trendAreaChart(monthCounts, "건")}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>월별 잔여 재고</h2>
        <span class="panel-meta">월을 선택하세요</span>
      </div>
      <div class="panel-body" id="somStockBox">${somStockPanel()}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>많이 나가는 품목 순위</h2>
        <span class="panel-meta">불출 건수 기준 · 상위 12 · 품목명을 누르면 월별 상세</span>
      </div>
      <div class="panel-body">${rankBars(itemRank, "data-som-item")}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>많이 요청하는 크루 순위</h2>
        <span class="panel-meta">총 불출 건수 순 · 상위 12명 · 이름을 누르면 상세 내역</span>
      </div>
      <div class="panel-body">${crewMonthHeatmap(rows, months)}</div>
    </div>
  `;
}

/* ---------------- 나머지 화면 ---------------- */

function renderGeneric(title, key) {
  const records = getRecords(key);
  return `
    <div class="kpi-grid">
      ${kpiCard("총 기록 건수", records.length + "건")}
    </div>
    <div class="panel">
      <div class="panel-header"><h2>${title}</h2><span class="panel-meta">${records.length}건</span></div>
      <div class="panel-body">
        ${renderTable(records.slice().reverse(), null, { detailTitle: title + " 상세" })}
      </div>
    </div>
  `;
}

function renderVehicle() {
  const parking = getRecords("vehicle_parking");
  const log = getRecords("vehicle_log");
  return `
    <div class="kpi-grid">
      ${kpiCard("정기주차 등록 차량", parking.length + "대")}
      ${kpiCard("운행일지 기록", log.length + "건")}
    </div>
    <div class="panel">
      <div class="panel-header"><h2>정기주차 차량 현황</h2><span class="panel-meta">${parking.length}건</span></div>
      <div class="panel-body">${renderTable(parking, null, { detailTitle: "정기주차 상세" })}</div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>운행일지 검수</h2><span class="panel-meta">${log.length}건</span></div>
      <div class="panel-body">${renderTable(log.slice().reverse(), null, { detailTitle: "운행일지 상세" })}</div>
    </div>
  `;
}

/* ---------------- 메일룸 (우편물 / 인쇄물) ---------------- */

/* 두 대장은 시트 서식이 달라서, 다른 점만 여기 표로 적어두고
   화면 그리는 코드는 하나만 씁니다. */
const MAIL_SOURCES = {
  post: {
    key: "mail_log",
    label: "우편물 · 등기 · 택배",
    short: "우편물",
    dateField: "도달일",
    nameFields: ["수령자", "수신자", "전달자"],
    columns: ["유형", "도달일", "수령자", "수신자", "발신처", "등기번호(운송장)",
              "전달자", "전달/반송여부", "비고"],
    statusField: "전달/반송여부",
    detailTitle: "우편물 상세",
    emptyThisMonth: "해당 월 도착한 우편물이 없습니다.",
  },
  print: {
    key: "namecard",
    label: "인쇄물 · 네임플레이트 · 명함",
    short: "인쇄물",
    dateField: "전달일",
    nameFields: ["전달자(영어명)", "수령자(영어명)"],
    columns: ["유형", "전달일", "전달자(영어명)", "수령자(영어명)", "부서", "개수",
              "전달여부", "요청 링크", "비고"],
    statusField: "전달여부",
    detailTitle: "인쇄물 상세",
    emptyThisMonth: "해당 월 지급 건이 없습니다.",
  },
};

/* 검색어 / 선택한 달 / 팝업에서 펼쳐 본 행을 대장별로 따로 기억합니다. */
const MAIL_STATE = {
  post: { query: "", month: null, match: [], row: null },
  print: { query: "", month: null, match: [], row: null },
};

function mailRecords(kind) {
  const src = MAIL_SOURCES[kind];
  return getRecords(src.key).map((r) => ({ raw: r, date: parseKDate(pick(r, src.dateField)) }));
}

/* 최신 날짜가 맨 위로. 날짜를 못 읽은 행은 맨 아래로 보냅니다. */
function sortNewestFirst(list) {
  return list
    .slice()
    .sort((a, b) => (b.date ? b.date.getTime() : 0) - (a.date ? a.date.getTime() : 0));
}

function isReturned(record) {
  return /반송|반려/.test(String(pick(record, "전달/반송여부", "전달여부", "여부")));
}

/* 자료에 실제로 있는 달 목록 (최근 것부터, 최대 12개) */
function mailMonths(list) {
  const set = new Set();
  list.forEach((r) => {
    if (r.date) set.add(monthKey(r.date));
  });
  return [...set].sort((a, b) => (a < b ? 1 : -1)).slice(0, 12);
}

function mailMonthLabel(key) {
  const [y, m] = key.split(".");
  return `${y}년 ${Number(m)}월`;
}

/* 월 선택 + 그 달의 기록 전체 */
function mailMonthPanel(kind) {
  const src = MAIL_SOURCES[kind];
  const state = MAIL_STATE[kind];
  const all = mailRecords(kind);
  const months = mailMonths(all);

  if (!months.length) {
    return `<div class="empty-note">날짜를 읽을 수 있는 기록이 없습니다.</div>`;
  }
  if (!months.includes(state.month)) {
    const now = new Date();
    const thisKey = monthKey(now);
    state.month = months.includes(thisKey) ? thisKey : months[0];
  }

  const tabs = months
    .map(
      (m) => `<button class="month-tab ${m === state.month ? "active" : ""}"
        data-mail-month="${kind}" data-month="${m}">${escapeHtml(mailMonthLabel(m))}</button>`
    )
    .join("");

  const rows = sortNewestFirst(all.filter((r) => r.date && monthKey(r.date) === state.month));
  const returned = rows.filter((r) => isReturned(r.raw)).length;

  const summary = `<div class="month-summary">${escapeHtml(mailMonthLabel(state.month))} · ${rows.length}건${
    returned ? ` · <strong style="color:var(--danger)">반송 ${returned}건</strong>` : ""
  }</div>`;

  const table = renderTable(
    rows.map((r) => r.raw),
    src.columns,
    {
      detailTitle: src.detailTitle,
      center: true,
      emptyText: src.emptyThisMonth,
      rowClass: (rec) => (isReturned(rec) ? "row-alert" : ""),
    }
  );

  return `<div class="month-tabs">${tabs}</div>${summary}${table}`;
}

/* --- 크루 검색 팝업 --- */

function mailModalBody(kind) {
  const src = MAIL_SOURCES[kind];
  const state = MAIL_STATE[kind];
  const rows = state.match;
  if (!rows.length) return `<div class="empty-note">기록이 없습니다.</div>`;

  if (state.row !== null && rows[state.row]) {
    const at = navPosition(state.row, rows.length);
    return `<button class="modal-back" data-mail-back>◀ 목록으로</button>
      ${navBar(at.pos, at.total)}
      ${recordDetailHtml(rows[state.row])}`;
  }

  const returned = rows.filter(isReturned).length;

  return `<p class="modal-note">'${escapeHtml(state.query)}' · 총 ${rows.length}건 · 최신순${
    returned ? ` · <strong>반송 ${returned}건</strong>` : ""
  }</p>
    ${renderTable(rows, src.columns, {
      detailTitle: src.detailTitle,
      center: true,
      emptyText: "기록이 없습니다.",
      rowClass: (rec) => (isReturned(rec) ? "row-alert" : ""),
    })}`;
}

function refreshMailModal(kind) {
  const src = MAIL_SOURCES[kind];
  const state = MAIL_STATE[kind];
  const modal = document.querySelector(".modal");
  if (modal) modal.classList.toggle("modal-wide", state.row === null);
  openModal(`${state.query} · ${src.short} 조회`, mailModalBody(kind));
  MAIL_MODAL_KIND = kind; // openModal이 끈 뒤에 다시 켭니다
  if (state.row !== null) MODAL_NAV = { mode: "mail", kind };
}

function openMailModal(kind) {
  const src = MAIL_SOURCES[kind];
  const state = MAIL_STATE[kind];
  const box = document.getElementById(`mailResult-${kind}`);
  const query = state.query.trim();

  if (!query) {
    if (box) box.innerHTML = `<div class="empty-note">조회할 크루 이름을 입력해주세요.</div>`;
    return;
  }

  const needle = query.toLowerCase();
  state.match = sortNewestFirst(
    mailRecords(kind).filter((r) => matchesCrew(r.raw, needle, src.nameFields))
  ).map((r) => r.raw);

  if (!state.match.length) {
    if (box) {
      box.innerHTML = `<div class="empty-note">'${escapeHtml(query)}' 와(과) 일치하는 ${escapeHtml(src.short)} 기록이 없습니다.</div>`;
    }
    return;
  }

  if (box) {
    const returned = state.match.filter(isReturned).length;
    box.innerHTML = `<div class="crew-recall">
      <span>'${escapeHtml(query)}' · ${state.match.length}건${returned ? ` · 반송 ${returned}건` : ""}</span>
      <button class="crew-recall-btn" data-mail-go="${kind}">조회 창 다시 열기</button>
    </div>`;
  }
  state.row = null;
  refreshMailModal(kind);
}

els.content.addEventListener("input", (e) => {
  const kind = e.target.dataset && e.target.dataset.mailSearch;
  if (kind) MAIL_STATE[kind].query = e.target.value;
});

els.content.addEventListener("keydown", (e) => {
  const kind = e.target.dataset && e.target.dataset.mailSearch;
  if (kind && e.key === "Enter") {
    e.preventDefault();
    openMailModal(kind);
  }
});

els.content.addEventListener("click", (e) => {
  const go = e.target.closest("[data-mail-go]");
  if (go) {
    openMailModal(go.dataset.mailGo);
    return;
  }
  const tab = e.target.closest("[data-mail-month]");
  if (tab) {
    const kind = tab.dataset.mailMonth;
    MAIL_STATE[kind].month = tab.dataset.month;
    const box = document.getElementById(`mailBox-${kind}`);
    if (box) box.innerHTML = mailMonthPanel(kind);
  }
});

els.modalBody.addEventListener("click", (e) => {
  if (!MAIL_MODAL_KIND) return;
  const kind = MAIL_MODAL_KIND;
  if (e.target.closest("[data-mail-back]")) {
    MAIL_STATE[kind].row = null;
    refreshMailModal(kind);
    return;
  }
  const row = e.target.closest("tr[data-table]");
  if (row) {
    const state = TABLE_REGISTRY[row.dataset.table];
    NAV_ORDER = state ? state.order : null;
    MAIL_STATE[kind].row = Number(row.dataset.row);
    refreshMailModal(kind);
  }
});

/* 한 대장(우편물 또는 인쇄물)의 화면 한 덩어리 */
function mailSection(kind) {
  const src = MAIL_SOURCES[kind];
  return `
    <h2 class="section-title">${escapeHtml(src.label)}</h2>

    <div class="crew-panel">
      <h3 class="section-title" style="font-size:15px;">${escapeHtml(src.short)} 크루별 조회</h3>
      <p class="section-note">이름으로 찾으면 최신 기록부터 별도 창에 모아 보여줍니다.</p>

      <div class="search-bar">
        <input type="search" id="mailSearch-${kind}" data-mail-search="${kind}"
               placeholder="한글 이름 또는 영문 닉네임 (예: 곽보길 / Charles)" autocomplete="off" />
        <button class="crew-search-btn" data-mail-go="${kind}">조회</button>
      </div>

      <div class="crew-result-box" id="mailResult-${kind}"></div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>${escapeHtml(src.short)} 월별 기록</h2>
        <span class="panel-meta">달을 선택하면 그 달 기록 전체가 나옵니다</span>
      </div>
      <div class="panel-body" id="mailBox-${kind}">${mailMonthPanel(kind)}</div>
    </div>
  `;
}

function renderMail() {
  // 다른 화면의 검색 상태가 남아 팝업이 헷갈리지 않도록 초기화합니다.
  CREW_TAB = null;
  MAIL_MODAL_KIND = null;
  Object.keys(MAIL_STATE).forEach((k) => {
    MAIL_STATE[k].query = "";
    MAIL_STATE[k].match = [];
    MAIL_STATE[k].row = null;
  });

  const now = new Date();
  const thisKey = monthKey(now);
  const monthLabel = `${now.getFullYear()}년 ${now.getMonth() + 1}월`;

  const post = mailRecords("post");
  const print = mailRecords("print");
  const postNow = post.filter((r) => r.date && monthKey(r.date) === thisKey);
  const printNow = print.filter((r) => r.date && monthKey(r.date) === thisKey);
  const returnedNow = postNow.filter((r) => isReturned(r.raw)).length;
  const printQty = printNow.reduce(
    (s, r) => s + (Number(String(pick(r.raw, "개수")).replace(/,/g, "")) || 0), 0
  );

  const returnAlert = returnedNow
    ? `<div class="alert-panel">
        <div class="alert-head">
          <span class="alert-icon" aria-hidden="true">!</span>
          <strong>이번 달 반송 ${returnedNow}건</strong>
          <span class="alert-note">아래 표에서 붉게 표시된 행입니다.</span>
        </div>
      </div>`
    : "";

  return `
    <div class="kpi-grid">
      ${kpiCard("이번 달 우편물", postNow.length + "건", monthLabel + " 도달일 기준")}
      ${kpiCard("이번 달 반송", returnedNow + "건", "전달/반송여부 기준")}
      ${kpiCard("이번 달 인쇄물", printNow.length + "건", monthLabel + " 전달일 기준")}
      ${kpiCard("인쇄물 수량", printQty.toLocaleString() + "개", "이번 달 합계")}
      ${kpiCard("전체 기록", (post.length + print.length).toLocaleString() + "건", "우편물 + 인쇄물 누적")}
    </div>

    ${returnAlert}

    ${mailSection("post")}

    <div style="height:14px;"></div>

    ${mailSection("print")}
  `;
}

function monthBarChart(records, dateField) {
  const counts = {};
  records.forEach((r) => {
    const d = parseKDate(r[dateField]);
    if (!d) return;
    const key = monthKey(d);
    counts[key] = (counts[key] || 0) + 1;
  });
  const entries = Object.entries(counts).sort((a, b) => (a[0] < b[0] ? -1 : 1));
  if (!entries.length) return `<div class="empty-note">날짜 데이터를 찾을 수 없습니다.</div>`;
  const max = Math.max(...entries.map(([, c]) => c));
  const rows = entries
    .map(
      ([label, count]) => `
      <div class="bar-row">
        <div class="bar-label">${label}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((count / max) * 100)}%"></div></div>
        <div class="bar-count">${count}건</div>
      </div>`
    )
    .join("");
  return `<div class="bar-chart">${rows}</div>`;
}

function renderAnnual() {
  const jeonsan = getRecords("jeonsan_status");
  const tangbisil = getTangbisil();
  const somopum = getRecords("somopum");
  const vehicleLog = getRecords("vehicle_log");
  const mail = getRecords("mail_log");
  const namecard = getRecords("namecard");

  return `
    <div class="kpi-grid">
      ${kpiCard("전산 업무", jeonsan.length + "건", "전체 누적")}
      ${kpiCard(
        "탕비실 진열",
        `${tangbisil.workdays_done} / ${tangbisil.workdays_total}일`,
        "이번 달 근무일 기준"
      )}
      ${kpiCard("소모품", somopum.length + "건", "전체 누적")}
      ${kpiCard("법인차량", vehicleLog.length + "건", "전체 누적")}
      ${kpiCard("메일룸", (mail.length + namecard.length).toLocaleString() + "건", "우편물 + 인쇄물 누적")}
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>전산 업무 월별 추이</h2>
        <span class="panel-meta">요청일자 기준</span>
      </div>
      <div class="panel-body">
        ${monthBarChart(jeonsan, "요청일자")}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>소모품 불출 월별 추이</h2>
        <span class="panel-meta">불출 대장 날짜 기준</span>
      </div>
      <div class="panel-body">
        ${trendAreaChart(monthlyCounts(somopumRows()), "건")}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>우편물 월별 추이</h2>
        <span class="panel-meta">도달일 기준</span>
      </div>
      <div class="panel-body">
        ${trendAreaChart(monthlyCounts(mailRecords("post")), "건")}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>전년 동월 대비</h2>
        <span class="panel-meta">같은 달끼리 올해와 작년을 나란히 봅니다</span>
      </div>
      <div class="panel-body" id="yoyBox">${yoyPanel()}</div>
    </div>

    <div class="empty-note" style="text-align:left; padding: 4px 4px 0;">
      탕비실 · 법인차량의 월별 그래프는 각 시트의 날짜 열 이름을 확인한 뒤 추가할 예정이에요.
    </div>
  `;
}

/* ---------------- 전년 동월 대비 ---------------- */

/* 날짜 목록을 "2026.09" -> 건수 로 셉니다. */
function monthCountMap(dates) {
  const map = new Map();
  dates.forEach((d) => {
    if (!d) return;
    const k = monthKey(d);
    map.set(k, (map.get(k) || 0) + 1);
  });
  return map;
}

const YOY_SOURCES = [
  {
    key: "jeonsan",
    label: "전산 업무",
    note: "요청일자 기준",
    dates: () =>
      getRecords("jeonsan_status").map(
        (r) => parseKDate(r["요청일자"]) || parseKDate(r["완료일자"])
      ),
  },
  {
    key: "somopum",
    label: "소모품 불출",
    note: "불출 대장 날짜 기준",
    dates: () => somopumRows().map((r) => r.date),
  },
  {
    key: "mail",
    label: "우편물",
    note: "도달일 기준",
    dates: () => mailRecords("post").map((r) => r.date),
  },
];

let YOY_TAB = "jeonsan";

function yoyPanel() {
  const src = YOY_SOURCES.find((s) => s.key === YOY_TAB) || YOY_SOURCES[0];
  const map = monthCountMap(src.dates());

  const now = new Date();
  const year = now.getFullYear();
  const pad = (n) => String(n).padStart(2, "0");

  // 이번 달까지만 봅니다. 아직 오지 않은 달을 0으로 그리면 실적이 떨어진 것처럼 보입니다.
  let rows = [];
  for (let mo = 1; mo <= now.getMonth() + 1; mo++) {
    rows.push({
      month: mo,
      cur: map.get(`${year}.${pad(mo)}`) || 0,
      prev: map.get(`${year - 1}.${pad(mo)}`) || 0,
    });
  }
  // 기록이 시작되기 전의 빈 달은 지웁니다 (0으로 채운 줄이 앞에 쌓이면 읽기 어렵습니다)
  const first = rows.findIndex((r) => r.cur > 0 || r.prev > 0);
  rows = first === -1 ? rows.slice(-1) : rows.slice(first);

  const tabs = YOY_SOURCES.map(
    (s) => `<button class="month-tab ${s.key === YOY_TAB ? "active" : ""}"
      data-yoy="${s.key}">${escapeHtml(s.label)}</button>`
  ).join("");

  const hasPrev = rows.some((r) => r.prev > 0);
  const max = Math.max(...rows.flatMap((r) => [r.cur, r.prev]), 1);
  const w = (v) => (v ? Math.max((v / max) * 100, 2) : 0);

  const body = rows
    .map((r) => {
      const diff = r.cur - r.prev;
      let delta = "-";
      let cls = "muted";
      if (r.prev > 0) {
        cls = diff > 0 ? "up" : diff < 0 ? "down" : "";
        delta = `${diff > 0 ? "+" : ""}${diff}`;
      } else if (hasPrev && r.cur > 0) {
        // 다른 달에는 작년 기록이 있는데 이 달만 없는 경우
        delta = "작년 없음";
      }
      const pct = r.prev > 0 ? ` (${Math.round((diff / r.prev) * 100)}%)` : "";
      // 작년 자료가 아예 없으면 아랫줄을 그리지 않습니다 (0만 늘어서면 읽기 어렵습니다)
      const prevLine = hasPrev
        ? `<div class="yoy-line">
            <span class="yoy-bar prev" style="width:${w(r.prev)}%"></span>
            <span class="yoy-num muted">${r.prev}</span>
          </div>`
        : "";
      return `<div class="yoy-row">
        <div class="yoy-month">${r.month}월</div>
        <div class="yoy-bars">
          <div class="yoy-line">
            <span class="yoy-bar cur" style="width:${w(r.cur)}%"></span>
            <span class="yoy-num">${r.cur}</span>
          </div>
          ${prevLine}
        </div>
        <div class="yoy-delta ${cls}" title="${escapeHtml(delta + pct)}">${escapeHtml(delta)}</div>
      </div>`;
    })
    .join("");

  const legend = `<div class="chart-legend" style="padding:12px 20px 4px;">
    <span class="legend-item"><span class="legend-swatch yoy-cur"></span>${year}년</span>
    ${hasPrev ? `<span class="legend-item"><span class="legend-swatch yoy-prev"></span>${year - 1}년</span>` : ""}
    <span class="legend-item muted">${escapeHtml(src.note)}</span>
  </div>`;

  const notice = hasPrev
    ? ""
    : `<div class="empty-note" style="text-align:left; padding:6px 20px 0;">
        ${year - 1}년 자료가 아직 없습니다. 해가 넘어가면 이 자리에 전년 동월 비교가 채워집니다.
      </div>`;

  return `<div class="month-tabs">${tabs}</div>${legend}${notice}
    <div class="yoy-chart">${body}</div>`;
}

els.content.addEventListener("click", (e) => {
  const tab = e.target.closest("[data-yoy]");
  if (!tab) return;
  YOY_TAB = tab.dataset.yoy;
  const box = document.getElementById("yoyBox");
  if (box) box.innerHTML = yoyPanel();
});

init();
