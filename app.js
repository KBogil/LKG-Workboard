/* LKG Workboard - app.js
   data/workboard.json 을 불러와서 사이드바 카테고리별 화면을 그립니다. */

const DATA_URL = "./data/workboard.json";

let WORKBOARD = null; // { generated_at, data: { key: [records...] } }

const els = {
  sidebar: document.getElementById("sidebar"),
  hamburgerBtn: document.getElementById("hamburgerBtn"),
  navItems: document.querySelectorAll(".nav-item"),
  pageTitle: document.getElementById("pageTitle"),
  content: document.getElementById("content"),
  lastUpdated: document.getElementById("lastUpdated"),
};

const VIEW_TITLES = {
  overview: "개요",
  jeonsan: "전산",
  tangbisil: "탕비실",
  somopum: "소모품",
  vehicle: "법인차량",
  mail: "우편물",
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
    WORKBOARD = await res.json();
    els.lastUpdated.textContent = "마지막 업데이트: " + formatDateTime(WORKBOARD.generated_at);
    renderView("overview");
  } catch (err) {
    els.content.innerHTML = `<p class="empty-note">데이터를 불러오지 못했습니다. (${err.message})<br>data/workboard.json 파일이 있는지 확인해주세요.</p>`;
    els.lastUpdated.textContent = "업데이트 확인 실패";
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
  return WORKBOARD.data[key] || [];
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

function el(tag, className, html) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (html !== undefined) node.innerHTML = html;
  return node;
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

function rankCard(name, count, max) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return `<div class="rank-card">
    <div class="rank-name">${escapeHtml(name)}</div>
    <div class="rank-sub">처리 건수</div>
    <div class="rank-count">${count}건</div>
    <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  </div>`;
}

/* ---------------- 화면별 렌더링 ---------------- */

function renderView(view) {
  const renderers = {
    overview: renderOverview,
    jeonsan: renderJeonsan,
    tangbisil: () => renderGeneric("탕비실 현황", "tangbisil"),
    somopum: () => renderGeneric("소모품 현황", "somopum"),
    vehicle: renderVehicle,
    mail: renderMail,
  };
  const fn = renderers[view] || renderOverview;
  els.content.innerHTML = fn();
}

function renderOverview() {
  const jeonsan = getRecords("jeonsan_status");
  const tangbisil = getRecords("tangbisil");
  const somopum = getRecords("somopum");
  const vehicleLog = getRecords("vehicle_log");
  const mail = getRecords("mail_log");

  const rankData = countBy(jeonsan, "담당자").slice(0, 4);
  const maxCount = rankData.length ? rankData[0][1] : 0;

  return `
    <div class="banner-row">
      <div class="banner-card">
        <h2>LKG Workboard 개요</h2>
        <p>전산 · 탕비실 · 소모품 · 법인차량 · 우편물 업무 현황을 한눈에 확인하세요.</p>
      </div>
      <div class="banner-side">
        <h3>자동 업데이트</h3>
        <p>구글 시트 입력 내용이 30분마다 자동으로 이 화면에 반영됩니다.</p>
      </div>
    </div>

    <div class="kpi-grid">
      ${kpiCard("전산 업무", jeonsan.length + "건", "누적 업무현황 로그")}
      ${kpiCard("탕비실", tangbisil.length + "건", "이번 달 기록")}
      ${kpiCard("소모품", somopum.length + "건", "누적 불출/요청")}
      ${kpiCard("법인차량", vehicleLog.length + "건", "운행일지 기록")}
      ${kpiCard("우편물", mail.length + "건", "누적 접수 기록")}
    </div>

    <h2 class="section-title">전산 업무 처리 Top 담당자</h2>
    <div class="rank-grid">
      ${
        rankData.length
          ? rankData.map(([name, count]) => rankCard(name, count, maxCount)).join("")
          : `<div class="empty-note">담당자 데이터가 없습니다.</div>`
      }
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>최근 전산 업무 (최신 10건)</h2>
        <span class="panel-meta">업무현황 로그 기준</span>
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

  return `
    <div class="kpi-grid">
      ${kpiCard("총 업무 건수", status.length + "건")}
      ${kpiCard("완료", doneCount + "건")}
      ${kpiCard("진행중/미완료", ingCount + "건")}
      ${kpiCard("자산 지급대장 건수", asset.length + "건")}
    </div>

    <h2 class="section-title">부서별 자산 보유 Top</h2>
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

init();
