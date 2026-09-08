/* LKG Workboard - app.js
   암호화된 data/workboard.json 을 불러와서, 핀번호 입력 후 복호화하여
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

/* ---------------- 시작 인트로 화면 ---------------- */

const INTRO_MIN_MS = 1900;   // 이미지가 떠 있는 최소 시간
const INTRO_MAX_MS = 6000;   // 이미지가 안 떠도 이 시간이 지나면 무조건 넘어감
const INTRO_FADE_MS = 500;   // 사라지는 데 걸리는 시간

let INTRO_DONE = false;
let DATA_READY = false;

/* 인트로가 끝났고 데이터도 준비됐을 때만 핀 입력칸에 커서를 놓습니다. */
function focusPinIfReady() {
  if (INTRO_DONE && DATA_READY) els.pinInput.focus();
}

function setupIntro() {
  const overlay = document.getElementById("introOverlay");
  const img = document.getElementById("introImg");
  if (!overlay || !img) {
    INTRO_DONE = true;
    return;
  }

  const startedAt = Date.now();
  let dismissed = false;

  function dismiss(immediately) {
    if (dismissed) return;
    const shown = Date.now() - startedAt;
    // 이미지가 너무 빨리 떠도 최소 시간만큼은 보여줍니다 (깜빡이는 느낌 방지).
    if (!immediately && shown < INTRO_MIN_MS) {
      setTimeout(() => dismiss(true), INTRO_MIN_MS - shown);
      return;
    }
    dismissed = true;
    overlay.classList.add("hide");
    setTimeout(() => {
      overlay.remove();
      INTRO_DONE = true;
      focusPinIfReady();
    }, INTRO_FADE_MS);
  }

  if (img.complete && img.naturalWidth) {
    dismiss(false);
  } else {
    img.addEventListener("load", () => dismiss(false));
    img.addEventListener("error", () => dismiss(true)); // 이미지가 없으면 그냥 넘어감
  }

  setTimeout(() => dismiss(true), INTRO_MAX_MS);
  overlay.addEventListener("click", () => dismiss(true));
  window.addEventListener("keydown", () => dismiss(true), { once: true });
}

async function init() {
  setupIntro();
  try {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) throw new Error("데이터를 불러오지 못했습니다.");
    ENCRYPTED_BLOB = await res.json();
    els.pinInput.disabled = false;
    DATA_READY = true;
    focusPinIfReady();
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
   "이름(영문)" 단위로 쪼개서 각각 따로 집계합니다. */
function countByMultiName(records, field) {
  const map = {};
  records.forEach((r) => {
    const raw = (r[field] || "").trim();
    if (!raw) return;
    const names = raw.match(/[^\s,\/、]+\([^()]*\)/g) || [raw];
    names.forEach((n) => {
      map[n] = (map[n] || 0) + 1;
    });
  });
  return Object.entries(map).sort((a, b) => b[1] - a[1]);
}

/* "2026. 9. 1" 같은 날짜 문자열을 Date 객체로 변환. 형식이 안 맞으면 null. */
function parseKDate(str) {
  if (!str) return null;
  const m = String(str).trim().match(/^(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})/);
  if (!m) return null;
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
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

function renderTable(records, columns) {
  if (!records.length) {
    return `<div class="empty-note">표시할 데이터가 없습니다.</div>`;
  }
  const cols = columns || Object.keys(records[0]).filter((c) => c !== "");
  let thead = "<tr>" + cols.map((c) => `<th>${escapeHtml(c)}</th>`).join("") + "</tr>";
  let rows = records
    .map((r) => {
      return "<tr>" + cols.map((c) => `<td>${escapeHtml(r[c] ?? "")}</td>`).join("") + "</tr>";
    })
    .join("");
  return `<div class="table-scroll"><table class="data-table"><thead>${thead}</thead><tbody>${rows}</tbody></table></div>`;
}

function escapeHtml(v) {
  return String(v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

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
    somopum: () => renderGeneric("소모품 현황", "somopum"),
    vehicle: renderVehicle,
    mail: renderMail,
    annual: renderAnnual,
  };
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
        tangbisil.workdays_total
          ? `${monthLabel} 근무일 기준 진행`
          : "일자별 진행 기록 없음"
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
        tangbisil.workdays_total
          ? `${tangbisil.workdays_done} / ${tangbisil.workdays_total}일`
          : "-"
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
        ${renderTable(jeonsan.slice(-10).reverse(), ["유형","요청자","부서","자산번호","업무내용","담당자","완료일자","진행상태"])}
      </div>
    </div>
  `;
}

function renderJeonsan() {
  const status = getRecords("jeonsan_status");
  const asset = getRecords("jeonsan_asset");
  const io = getRecords("jeonsan_io");

  const doneCount = status.filter((r) => (r["진행상태"] || "").includes("완료")).length;
  const ingCount = status.length - doneCount;

  const byDept = countBy(asset, "부서").slice(0, 4);
  const maxDept = byDept.length ? byDept[0][1] : 0;

  const byHandler = countByMultiName(status, "담당자").slice(0, 6);
  const maxHandler = byHandler.length ? byHandler[0][1] : 0;

  return `
    <div class="kpi-grid">
      ${kpiCard("총 업무 건수", status.length + "건")}
      ${kpiCard("완료", doneCount + "건")}
      ${kpiCard("진행중/미완료", ingCount + "건")}
      ${kpiCard("자산 지급대장 건수", asset.length + "건")}
    </div>

    <h2 class="section-title">담당자별 처리 건수 (전체 누적)</h2>
    <div class="rank-grid">
      ${
        byHandler.length
          ? byHandler.map(([name, count]) => rankCard(name, count, maxHandler)).join("")
          : `<div class="empty-note">담당자 데이터가 없습니다.</div>`
      }
    </div>

    <h2 class="section-title">부서별 자산 보유</h2>
    <div class="rank-grid">
      ${
        byDept.length
          ? byDept.map(([name, count]) => rankCard(name, count, maxDept)).join("")
          : `<div class="empty-note">부서 데이터가 없습니다.</div>`
      }
    </div>

    <div class="panel">
      <div class="panel-header"><h2>업무현황 로그</h2><span class="panel-meta">${status.length}건</span></div>
      <div class="panel-body">
        ${renderTable(status.slice().reverse(), ["유형","요청자","부서","자산번호","업무내용","조치사항","담당자","요청일자","완료일자","진행상태","비고"])}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>자산 지급대장</h2><span class="panel-meta">${asset.length}건</span></div>
      <div class="panel-body">
        ${renderTable(asset)}
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>입출고 · 대여 로그</h2><span class="panel-meta">${io.length}건</span></div>
      <div class="panel-body">
        ${renderTable(io.slice().reverse())}
      </div>
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
      const bar = up
        ? `left:50%; width:${width}%;`
        : `left:${50 - width}%; width:${width}%;`;
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
        <h2>전월 대비 사용량 증감</h2>
        <span class="panel-meta">${escapeHtml(tb.prev_month_title || "전월 자료 없음")} 대비</span>
      </div>
      <div class="panel-body">${usageChangeChart(items)}</div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>재고 현황</h2>
        <span class="panel-meta">${items.length}종</span>
      </div>
      <div class="panel-body">${stockTable(items)}</div>
    </div>
  `;
}

/* 재고 표. 발주 필요 행은 배지를 붙여 색 없이도 구분되게 합니다. */
function stockTable(items) {
  if (!items.length) {
    return `<div class="empty-note">탕비실 데이터를 불러오지 못했습니다.</div>`;
  }
  const head = ["상품명", "박스당 개입수", "사용량", "입고량", "잔여 재고", "전월 재고", "전월 대비", "상태"];
  const rows = items
    .map((i) => {
      const delta = i["사용량증감"];
      const deltaText =
        typeof delta === "number" ? (delta > 0 ? `+${delta}` : String(delta)) : "-";
      const deltaClass = typeof delta === "number" && delta !== 0 ? (delta > 0 ? "up" : "down") : "";
      const badge = i["발주필요"]
        ? `<span class="badge warn">발주 필요</span>`
        : `<span class="badge done">정상</span>`;
      return `<tr>
        <td>${escapeHtml(i["상품명"])}</td>
        <td>${escapeHtml(i["박스당개입수"] ?? "")}</td>
        <td>${escapeHtml(i["사용량"] ?? "")}</td>
        <td>${escapeHtml(i["입고량"] ?? "")}</td>
        <td>${escapeHtml(i["현재고"] ?? "")}</td>
        <td>${escapeHtml(i["전월재고"] ?? "")}</td>
        <td class="delta ${deltaClass}">${deltaText}</td>
        <td>${badge}</td>
      </tr>`;
    })
    .join("");
  return `<div class="table-scroll"><table class="data-table">
    <thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function renderGeneric(title, key) {
  const records = getRecords(key);
  return `
    <div class="kpi-grid">
      ${kpiCard("총 기록 건수", records.length + "건")}
    </div>
    <div class="panel">
      <div class="panel-header"><h2>${title}</h2><span class="panel-meta">${records.length}건</span></div>
      <div class="panel-body">
        ${renderTable(records.slice().reverse())}
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
      <div class="panel-body">${renderTable(parking)}</div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>운행일지 검수</h2><span class="panel-meta">${log.length}건</span></div>
      <div class="panel-body">${renderTable(log.slice().reverse())}</div>
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
      <div class="panel-body">${renderTable(mail.slice().reverse())}</div>
    </div>
    <div class="panel">
      <div class="panel-header"><h2>명함 · 네임플레이트 관리</h2><span class="panel-meta">${namecard.length}건</span></div>
      <div class="panel-body">${renderTable(namecard)}</div>
    </div>
  `;
}

function monthBarChart(records, dateField) {
  const counts = {};
  records.forEach((r) => {
    const d = parseKDate(r[dateField]);
    if (!d) return;
    const key = `${d.getFullYear()}.${String(d.getMonth() + 1).padStart(2, "0")}`;
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

    <div class="empty-note" style="text-align:left; padding: 4px 4px 0;">
      탕비실 · 소모품 · 법인차량 · 우편물의 월별 그래프는 각 시트의 날짜 열 이름을 확인한 뒤 추가할 예정이에요.
    </div>
  `;
}

init();
