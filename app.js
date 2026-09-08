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
  lockError: document.getElementById("lockError"),
  modalBackdrop: document.getElementById("modalBackdrop"),
  modalTitle: document.getElementById("modalTitle"),
  modalBody: document.getElementById("modalBody"),
  modalClose: document.getElementById("modalClose"),
};

let ENCRYPTED_BLOB = null;

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

async function tryUnlock() {
  const pin = els.pinInput.value;
  if (!pin) return;
  els.lockError.textContent = "";
  els.pinSubmit.disabled = true;
  try {
    WORKBOARD = await decryptBlob(ENCRYPTED_BLOB, pin);
    els.lockOverlay.style.display = "none";
    els.appRoot.style.display = "";
    els.lastUpdated.textContent = "마지막 업데이트: " + formatDateTime(WORKBOARD.generated_at);
    renderView("overview");
  } catch (err) {
    els.lockError.textContent = "비밀번호가 올바르지 않습니다.";
  } finally {
    els.pinSubmit.disabled = false;
  }
}

els.pinSubmit.addEventListener("click", tryUnlock);
els.pinInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") tryUnlock();
});

const VIEW_TITLES = {
  overview: "개요",
  jeonsan: "전산",
  tangbisil: "탕비실",
  somopum: "소모품",
  vehicle: "법인차량",
  mail: "우편물",
  annual: "연간 통계",
};

/* ---------------- 초기화 ---------------- */

els.hamburgerBtn.addEventListener("click", () => {
  els.sidebar.classList.toggle("collapsed");
});

els.navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    els.navItems.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const view = btn.dataset.view;
    els.pageTitle.textContent = VIEW_TITLES[view] || "";
    renderView(view);
  });
});

async function init() {
  try {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) throw new Error("데이터를 불러오지 못했습니다.");
    ENCRYPTED_BLOB = await res.json();
    els.pinInput.disabled = false;
    els.pinInput.focus();
  } catch (err) {
    els.lockError.textContent = "데이터 파일을 불러오지 못했습니다. (" + err.message + ")";
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

function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/* ---------------- 표 ---------------- */

/* 표에 그려진 행을 다시 찾아갈 수 있도록 보관합니다.
   화면을 새로 그릴 때마다 비웁니다. */
let TABLE_REGISTRY = {};
let TABLE_SEQ = 0;

function isNumericColumn(name) {
  return /수량|건수|개수|사용량|입고량|재고|금액|개입/.test(name);
}

/* 진행상태 같은 열은 배지로 그려서 눈에 잘 띄게 합니다. */
function statusCellHtml(value) {
  const text = String(value ?? "").trim();
  if (!text) return "-";
  const done = /완료|정상|반납|지급/.test(text);
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

  const clickable = options.clickable !== false;
  const tableId = "tbl" + ++TABLE_SEQ;
  if (clickable) {
    TABLE_REGISTRY[tableId] = { records, title: options.detailTitle || "상세 내용" };
  }

  const thead =
    "<tr>" +
    cols
      .map((c) => `<th class="${isNumericColumn(c) ? "num" : ""}">${escapeHtml(c)}</th>`)
      .join("") +
    "</tr>";

  const body = records
    .map((r, i) => {
      const cells = cols
        .map((c) => {
          const raw = r[c] ?? "";
          if (/상태/.test(c)) return `<td>${statusCellHtml(raw)}</td>`;
          const text = raw === "" ? "-" : String(raw);
          // title 속성을 넣어두면 잘린 내용도 마우스를 올려 확인할 수 있습니다.
          return `<td class="${isNumericColumn(c) ? "num" : ""}" title="${escapeHtml(text)}">${escapeHtml(text)}</td>`;
        })
        .join("");
      const attrs = clickable ? ` class="row-clickable" data-table="${tableId}" data-row="${i}"` : "";
      return `<tr${attrs}>${cells}</tr>`;
    })
    .join("");

  const hint = clickable
    ? `<div class="table-hint">행을 누르면 전체 내용을 볼 수 있습니다.</div>`
    : "";

  const centerClass = options.center ? " center-all" : "";
  return `${hint}<div class="table-scroll"><table class="data-table${centerClass}"><thead>${thead}</thead><tbody>${body}</tbody></table></div>`;
}

/* 표의 행을 눌렀을 때 팝업을 띄웁니다 (화면을 새로 그려도 계속 동작하도록 위임 처리). */
els.content.addEventListener("click", (e) => {
  const row = e.target.closest("tr[data-table]");
  if (!row) return;
  const source = TABLE_REGISTRY[row.dataset.table];
  if (!source) return;
  const record = source.records[Number(row.dataset.row)];
  if (record) openModal(source.title, recordDetailHtml(record));
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

/* 카테고리 이름을 세미 타이틀로 얹은 담당자 카드 */
function ownerCard(category, owner, countLabel) {
  return `<div class="owner-block">
    <h3 class="owner-category">${escapeHtml(category)}</h3>
    <div class="rank-card">
      <div class="rank-name">${escapeHtml(owner)}</div>
      <div class="rank-sub">담당</div>
      <div class="rank-count">${escapeHtml(countLabel)}</div>
    </div>
  </div>`;
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
    annual: renderAnnual,
  };
  TABLE_REGISTRY = {}; // 이전 화면의 표 정보는 버립니다
  closeModal();
  const fn = renderers[view] || renderOverview;
  els.content.innerHTML = fn();
}

function renderOverview() {
  const jeonsanAll = getRecords("jeonsan_status");
  const jeonsan = filterCurrentMonthJeonsan(jeonsanAll);
  const tangbisil = getTangbisil();
  const somopumAll = getRecords("somopum");
  const vehicleLogAll = getRecords("vehicle_log");
  const mailAll = getRecords("mail_log");

  const somopum = filterCurrentMonthGeneric(somopumAll);
  const vehicleLog = filterCurrentMonthGeneric(vehicleLogAll);
  const mail = filterCurrentMonthGeneric(mailAll);

  const now = new Date();
  const monthLabel = `${now.getFullYear()}년 ${now.getMonth() + 1}월`;

  return `
    <div class="banner-row">
      <div class="banner-card">
        <h2>LKG Workboard 개요</h2>
        <p>${monthLabel} 기준 · 전산 · 탕비실 · 소모품 · 법인차량 · 우편물 업무 현황을 한눈에 확인하세요.</p>
      </div>
      <div class="banner-side">
        <h3>자동 업데이트</h3>
        <p>구글 시트 입력 내용이 15분마다 자동으로 이 화면에 반영됩니다. 전체 누적 통계는 왼쪽 '연간 통계' 메뉴에서 확인하세요.</p>
      </div>
    </div>

    <div class="kpi-grid">
      ${kpiCard("전산 업무", jeonsan.length + "건", monthLabel + " 기준")}
      ${kpiCard(
        "탕비실 진열",
        `${tangbisil.workdays_done} / ${tangbisil.workdays_total}일`,
        tangbisil.workdays_total ? `${monthLabel} 근무일 기준 진행` : "일자별 진행 기록 없음"
      )}
      ${
        somopum === null
          ? kpiCard("소모품", somopumAll.length + "건", "전체 누적 (날짜 열 미확인)")
          : kpiCard("소모품", somopum.length + "건", monthLabel + " 기준")
      }
      ${
        vehicleLog === null
          ? kpiCard("법인차량", vehicleLogAll.length + "건", "전체 누적 (날짜 열 미확인)")
          : kpiCard("법인차량", vehicleLog.length + "건", monthLabel + " 기준")
      }
      ${
        mail === null
          ? kpiCard("우편물", mailAll.length + "건", "전체 누적 (날짜 열 미확인)")
          : kpiCard("우편물", mail.length + "건", monthLabel + " 기준")
      }
    </div>

    <h2 class="section-title">업무 처리 담당자 (${monthLabel})</h2>
    <div class="owner-grid">
      ${ownerCard("전산", "이재환(Jetty)", jeonsan.length + "건")}
      ${ownerCard(
        "탕비실",
        "박동국(Kaju)",
        tangbisil.workdays_total ? `${tangbisil.workdays_done} / ${tangbisil.workdays_total}일` : "-"
      )}
      ${ownerCard("소모품", "박동국(Kaju)", (somopum === null ? somopumAll : somopum).length + "건")}
      ${ownerCard("법인차량", "박동국(Kaju)", (vehicleLog === null ? vehicleLogAll : vehicleLog).length + "건")}
      ${ownerCard("우편물", "박동국(Kaju)", (mail === null ? mailAll : mail).length + "건")}
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>최근 전산 업무 (최신 10건)</h2>
        <span class="panel-meta">${monthLabel} 기준</span>
      </div>
      <div class="panel-body">
        ${renderTable(jeonsan.slice(-10).reverse(),
          ["유형","요청자","부서","자산번호","업무내용","담당자","완료일자","진행상태"],
          { detailTitle: "전산 업무 상세", center: true })}
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

/* 각 대장에서 '사람 이름'이 들어있는 열. 시트 서식 기준입니다.
   이 열들만 보고 찾기 때문에, 비고란에 우연히 이름이 섞여도 딸려오지 않습니다. */
const CREW_SOURCES = [
  {
    key: "jeonsan_status",
    label: "전산 업무현황",
    nameFields: ["요청자", "담당자"],
    columns: ["유형","요청자","부서","자산번호","업무내용","조치사항","담당자",
              "요청일자","착수일자","완료일자","진행상태","비고"],
    detailTitle: "전산 업무 상세",
  },
  {
    key: "jeonsan_asset",
    label: "자산 지급대장",
    nameFields: ["한글이름", "영어이름"],
    columns: null, // 열이 많아 시트에 있는 그대로 보여줍니다
    detailTitle: "자산 지급 상세",
  },
  {
    key: "jeonsan_io",
    label: "입출고 · 대여",
    nameFields: ["이름", "영문명"],
    columns: null,
    detailTitle: "입출고 상세",
  },
];

/* 지정한 이름 열에서 찾습니다. 그 열이 시트에 없으면 모든 값에서 찾습니다(안전장치). */
function matchesCrew(record, needle, nameFields) {
  const fields = nameFields.filter((f) => f in record);
  const values = fields.length ? fields.map((f) => record[f]) : Object.values(record);
  return values.some((v) => String(v ?? "").toLowerCase().includes(needle));
}

let CREW_QUERY = "";
let CREW_TAB = null;  // 팝업에서 고른 대장. null이면 아직 안 고름
let CREW_ROW = null;  // 팝업 표에서 펼쳐 본 행 번호

function crewMatches(query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return CREW_SOURCES.map((source) => ({
    ...source,
    rows: getRecords(source.key).filter((r) => matchesCrew(r, needle, source.nameFields)),
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

  // ③ 행 상세
  if (active && CREW_ROW !== null && active.rows[CREW_ROW]) {
    return `<button class="modal-back" data-crew-back>◀ ${escapeHtml(active.label)} 목록으로</button>
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
  openModal(`${query} · 크루 조회`, crewModalBody());
}

function openCrewModal() {
  const query = CREW_QUERY.trim();
  const box = document.getElementById("crewResult");
  if (!query) {
    if (box) box.innerHTML = `<div class="empty-note">조회할 크루 이름을 입력해주세요.</div>`;
    return;
  }
  const found = crewMatches(query).filter((g) => g.rows.length);
  if (!found.length) {
    if (box) {
      box.innerHTML = `<div class="empty-note">'${escapeHtml(query)}' 와(과) 일치하는 기록이 없습니다. 한글 이름이나 영문 닉네임으로 찾아보세요.</div>`;
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
      <h2 class="section-title">크루별 조회</h2>
      <p class="section-note">아래 세 표는 그대로 두고, 별도 창에서 크루별 기록만 따로 찾아봅니다.</p>

      <div class="search-bar">
        <input type="search" id="crewSearch" placeholder="한글 이름 또는 영문 닉네임 (예: 이재환 / Jetty)" autocomplete="off" />
        <button class="crew-search-btn" id="crewSearchBtn">조회</button>
      </div>

      <div class="crew-result-box" id="crewResult">
        <div class="empty-note">이름을 입력하고 조회를 누르면, 기록이 있는 대장을 별도 창에서 골라볼 수 있습니다.</div>
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
      <div class="panel-body">${renderTable(asset, null, { detailTitle: "자산 지급 상세", center: true })}</div>
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
        <span class="panel-meta">${items.length}종</span>
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

/* 재고 표. 발주 필요 행은 배지와 배경으로 색 없이도 구분되게 합니다. */
function stockTable(items) {
  if (!items.length) {
    return `<div class="empty-note">탕비실 데이터를 불러오지 못했습니다.</div>`;
  }
  const head = [
    { label: "상품명", num: false },
    { label: "박스당 개입수", num: true },
    { label: "사용량", num: true },
    { label: "입고량", num: true },
    { label: "잔여 재고", num: true },
    { label: "전월 재고", num: true },
    { label: "전월 대비", num: true },
    { label: "상태", num: false },
  ];
  const rows = items
    .map((i) => {
      const delta = i["사용량증감"];
      const deltaText =
        typeof delta === "number" ? (delta > 0 ? `+${delta}` : String(delta)) : "-";
      const deltaClass =
        typeof delta === "number" && delta !== 0 ? (delta > 0 ? "up" : "down") : "";
      const need = i["발주필요"];
      const badge = need
        ? `<span class="badge warn">발주 필요</span>`
        : `<span class="badge done">정상</span>`;
      return `<tr class="${need ? "row-alert" : ""}">
        <td class="cell-strong" title="${escapeHtml(i["상품명"])}">${escapeHtml(i["상품명"])}</td>
        <td class="num">${escapeHtml(i["박스당개입수"] ?? "-")}</td>
        <td class="num">${escapeHtml(i["사용량"] ?? "-")}</td>
        <td class="num">${escapeHtml(i["입고량"] ?? "-")}</td>
        <td class="num cell-stock ${need ? "danger" : ""}">${escapeHtml(i["현재고"] ?? "-")}</td>
        <td class="num muted">${escapeHtml(i["전월재고"] ?? "-")}</td>
        <td class="num delta ${deltaClass}">${deltaText}</td>
        <td>${badge}</td>
      </tr>`;
    })
    .join("");
  return `<div class="table-scroll"><table class="data-table stock-table">
    <thead><tr>${head
      .map((h) => `<th class="${h.num ? "num" : ""}">${h.label}</th>`)
      .join("")}</tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

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

/* 순위 막대. 색만으로 읽히지 않도록 숫자를 항상 같이 적습니다. */
function rankBars(entries, unit) {
  if (!entries.length) return `<div class="empty-note">집계할 자료가 없습니다.</div>`;
  const max = Math.max(...entries.map((e) => e.qty), 1);
  return `<div class="bar-chart rank-chart">${entries
    .map(
      (e, i) => `<div class="bar-row">
        <div class="bar-label" title="${escapeHtml(e.key)}"><span class="bar-rank">${i + 1}</span>${escapeHtml(e.key)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((e.qty / max) * 100)}%"></div></div>
        <div class="bar-count">${e.qty.toLocaleString()}${unit} · ${e.count}건</div>
      </div>`
    )
    .join("")}</div>`;
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
  const totalRemain = items.reduce(
    (s, i) => s + (Number(i["잔여재고"] ?? i["재고수량"]) || 0), 0
  );

  const body = items.length
    ? `<div class="table-scroll"><table class="data-table center-all">
        <thead><tr>
          <th>품목</th><th class="num">잔여 재고</th><th class="num">실물 재고</th>
          <th class="num">상시 재고수량</th><th class="num">입고 수량</th><th class="num">불출량</th>
        </tr></thead>
        <tbody>${items
          .map(
            (i) => `<tr>
              <td class="cell-strong">${escapeHtml(i["품목"])}</td>
              <td class="num">${numText(i["잔여재고"])}</td>
              <td class="num">${numText(i["실물재고"])}</td>
              <td class="num">${numText(i["재고수량"])}</td>
              <td class="num">${numText(i["입고수량"])}</td>
              <td class="num">${numText(i["불출량"] ?? i["검수불출량"])}</td>
            </tr>`
          )
          .join("")}</tbody>
      </table></div>`
    : `<div class="empty-note">${escapeHtml(cur.label)}에 기록된 품목이 없습니다.</div>`;

  return `<div class="month-tabs">${tabs}</div>
    <div class="month-summary">${escapeHtml(cur.label)} · 품목 ${items.length}종 · 잔여 재고 합계 ${totalRemain.toLocaleString()}개</div>
    ${body}`;
}

/* --- 크루별 불출 조회 (별도 팝업) --- */
let SOM_QUERY = "";
let SOM_ROW = null;
let SOM_MATCH = [];

function somModalBody() {
  const rows = SOM_MATCH;
  if (!rows.length) return `<div class="empty-note">기록이 없습니다.</div>`;

  if (SOM_ROW !== null && rows[SOM_ROW]) {
    return `<button class="modal-back" data-som-back>◀ 목록으로</button>
      ${recordDetailHtml(rows[SOM_ROW].raw)}`;
  }

  const byItem = sumBy(rows, (r) => r.item);
  const totalQty = rows.reduce((s, r) => s + r.qty, 0);
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

  return `<p class="modal-note">${escapeHtml(who)} · 총 ${rows.length}건 / ${totalQty.toLocaleString()}개${
    pending ? ` · <strong>미불출 ${pending}건</strong>` : ""
  }</p>
    <div class="modal-sub">소모품 종류별 합계</div>
    ${summary}
    <div class="modal-sub" style="margin-top:22px;">전체 불출 내역 (행을 누르면 상세)</div>
    ${log}`;
}

function refreshSomModal() {
  const modal = document.querySelector(".modal");
  if (modal) modal.classList.toggle("modal-wide", SOM_ROW === null);
  openModal(`${SOM_QUERY.trim()} · 소모품 불출 내역`, somModalBody());
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
  const thisQty = thisMonth.reduce((s, r) => s + r.qty, 0);
  const pending = rows.filter((r) => !r.issued).length;

  const latest = stock.months.length ? stock.months[stock.months.length - 1] : null;
  const remainTotal = latest
    ? latest.items.reduce((s, i) => s + (Number(i["잔여재고"] ?? i["재고수량"]) || 0), 0)
    : 0;

  // 월별 불출량 추이
  const byMonth = new Map();
  rows.forEach((r) => {
    if (!r.date) return;
    const k = monthKey(r.date);
    byMonth.set(k, (byMonth.get(k) || 0) + r.qty);
  });
  const monthEntries = [...byMonth.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const monthMax = Math.max(...monthEntries.map(([, v]) => v), 1);
  const monthChart = monthEntries.length
    ? `<div class="bar-chart">${monthEntries
        .map(
          ([label, qty]) => `<div class="bar-row">
            <div class="bar-label">${label}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${Math.round((qty / monthMax) * 100)}%"></div></div>
            <div class="bar-count">${qty.toLocaleString()}개</div>
          </div>`
        )
        .join("")}</div>`
    : `<div class="empty-note">날짜를 읽을 수 있는 기록이 없습니다.</div>`;

  return `
    <div class="kpi-grid">
      ${kpiCard("이번 달 불출", thisMonth.length + "건", monthLabel + " 기준")}
      ${kpiCard("이번 달 불출 수량", thisQty.toLocaleString() + "개", "전 품목 합계")}
      ${kpiCard("미불출 대기", pending + "건", "불출 여부 미체크")}
      ${kpiCard("관리 품목", (latest ? latest.items.length : 0) + "종", latest ? latest.label + " 재고 조사" : "재고 자료 없음")}
      ${kpiCard("잔여 재고 합계", remainTotal.toLocaleString() + "개", latest ? latest.label + " 기준" : "-")}
    </div>

    <div class="crew-panel">
      <h2 class="section-title">크루별 불출 조회</h2>
      <p class="section-note">크루 이름으로 찾으면, 그 크루에게 나간 소모품 종류와 수량을 별도 창에서 보여줍니다.</p>

      <div class="search-bar">
        <input type="search" id="somSearch" placeholder="한글 이름 또는 영문 닉네임 (예: 김예림 / Rimmy)" autocomplete="off" />
        <button class="crew-search-btn" id="somSearchBtn">조회</button>
      </div>

      <div class="crew-result-box" id="somResult">
        <div class="empty-note">이름을 입력하고 조회를 누르면, 불출된 품목과 수량을 별도 창에서 볼 수 있습니다.</div>
      </div>
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
        <span class="panel-meta">전체 누적 · 상위 12</span>
      </div>
      <div class="panel-body">${rankBars(sumBy(rows, (r) => r.item).slice(0, 12), "개")}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>많이 요청하는 크루 순위</h2>
        <span class="panel-meta">전체 누적 · 상위 12</span>
      </div>
      <div class="panel-body">${rankBars(
        sumBy(rows, (r) => (r.target.nick ? `${r.target.name}(${r.target.nick})` : r.target.name)).slice(0, 12),
        "개"
      )}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>월별 불출량 추이</h2>
        <span class="panel-meta">불출 대장 날짜 기준</span>
      </div>
      <div class="panel-body">${monthChart}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>불출 대장</h2>
        <span class="panel-meta">${rows.length}건</span>
      </div>
      <div class="panel-body">
        ${renderTable(getRecords("somopum").slice().reverse(),
          ["날짜","품목","수량","불출 대상","물품 전달 구역","불출 여부","비고(특이사항)"],
          { detailTitle: "소모품 불출 상세", center: true })}
      </div>
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

function renderMail() {
  const mail = getRecords("mail_log");
  const namecard = getRecords("namecard");
  return `
    <div class="kpi-grid">
      ${kpiCard("등기/택배/우편물", mail.length + "건")}
      ${kpiCard("명함/네임플레이트", namecard.length + "건")}
    </div>
    <div class="panel">
      <div class="panel-header"><h2>우편물 불출 기록</h2><span class="panel-meta">${mail.length}건</span></div>
      <div class="panel-body">${renderTable(mail.slice().reverse(), null, { detailTitle: "우편물 상세" })}</div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>명함 · 네임플레이트 관리</h2><span class="panel-meta">${namecard.length}건</span></div>
      <div class="panel-body">${renderTable(namecard, null, { detailTitle: "명함 상세" })}</div>
    </div>
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
      ${kpiCard("우편물", mail.length + "건", "전체 누적")}
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
        ${monthBarChart(somopum, "날짜")}
      </div>
    </div>

    <div class="empty-note" style="text-align:left; padding: 4px 4px 0;">
      탕비실 · 법인차량 · 우편물의 월별 그래프는 각 시트의 날짜 열 이름을 확인한 뒤 추가할 예정이에요.
    </div>
  `;
}

init();
