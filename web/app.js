/* d4d-scce SOC 콘솔 렌더러 — vanilla JS, 의존성 0 */
(function () {
  "use strict";

  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, cls, html) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html;
    return n;
  };
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  // 콘텐츠 교체 시 페이드 재생(순간전환 방지)
  function retrigger(node) {
    if (!node) return;
    node.classList.remove("js-fade");
    void node.offsetWidth; // force reflow
    node.classList.add("js-fade");
  }

  // 숫자 카운트업
  function animateNumber(node, to, opts) {
    if (!node) return;
    const dur = (opts && opts.dur) || 650;
    const decimals = (opts && opts.decimals) || 0;
    const unit = (opts && opts.unit) || "";
    const from = 0;
    const t0 = performance.now();
    const ease = t => 1 - Math.pow(1 - t, 3); // easeOutCubic
    function tick(now) {
      const p = Math.min(1, (now - t0) / dur);
      const v = from + (to - from) * ease(p);
      node.textContent = v.toFixed(decimals) + unit;
      if (p < 1) requestAnimationFrame(tick);
      else node.textContent = to.toFixed(decimals) + unit;
    }
    requestAnimationFrame(tick);
  }

  let REPORT = null;

  async function loadReport() {
    // API 우선(서버 실행 시), 실패하면 오프라인 폴백(report_data.js).
    try {
      const r = await fetch("/api/report", { cache: "no-store" });
      if (r.ok) return await r.json();
    } catch (e) { /* file:// 또는 서버 없음 → 폴백 */ }
    return window.__REPORT__ || null;
  }

  // ---- KPI -----------------------------------------------------------------
  function heroSparkSvg(snaps) {
    if (!snaps || snaps.length < 2) return "";
    const W = 300, H = 50, pad = 2;
    const max = Math.max(1, ...snaps.map(s => s.risk_index));
    const pts = snaps.map((s, i) => [
      (i / (snaps.length - 1)) * W,
      H - pad - (s.risk_index / max) * (H - pad * 2),
    ]);
    const line = pts.map(p => p.join(",")).join(" ");
    const area = `0,${H} ${line} ${W},${H}`;
    return `<svg class="kh-spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <polyline points="${area}" fill="var(--critical)" opacity="0.16" stroke="none"></polyline>
      <polyline points="${line}" fill="none" stroke="var(--critical)" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"></polyline>
    </svg>`;
  }

  function renderKpis(k) {
    const tiles = [
      { label: "CRITICAL", val: k.critical_count, note: "즉시 조치 협력사", cls: "alert" },
      { label: "활성 침해", val: k.active_compromises, note: "VPN·SSO·코드저장소 등 HIGH 크리덴셜", cls: "alert" },
      { label: "캠페인 탐지", val: k.campaigns_detected, note: "동일 스틸러+C2 공급망 확산", cls: "warn" },
      { label: "매칭 유출", val: k.matched_exposed_credentials ?? k.exposed_credentials, note: `협력사 도메인 기준 / 전체 ${k.total_observed_credentials ?? "—"}`, cls: "warn" },
      { label: "검증 정확도", val: k.active_precision_pct ?? 100, unit: "%", note: `합성 정답셋 기준 / 협력사 ${k.vendor_count}개`, cls: "" },
    ];
    const box = $("#kpis"); box.innerHTML = "";
    tiles.forEach((t, i) => {
      const n = el("div", "kpi " + t.cls);
      n.style.setProperty("--i", i);
      const isNum = typeof t.val === "number";
      n.innerHTML = `<div class="label">${esc(t.label)}</div>
        <div class="val"><span class="val-n">${isNum ? "0" : esc(t.val ?? "—")}</span>${t.unit ? `<span class="unit">${esc(t.unit)}</span>` : ""}</div>
        <div class="knote">${esc(t.note)}</div>`;
      box.appendChild(n);
      if (isNum) animateNumber(n.querySelector(".val-n"), t.val, { dur: 700 + i * 80 });
    });
  }

  // ---- demo thesis (미션 스트립 + 히어로 스탯 병합) --------------------------
  function renderMission(R) {
    const rp = R.replay || {}, k = R.kpis || {};
    const claim = R.meta.demo_claim || (rp.lead_days != null
      ? `${rp.crown_jewel || "crown-jewel"} 침해 ${rp.lead_days}일 전, 동일 공급망 캠페인 조기 탐지`
      : "유출 자격증명과 스틸러 감염기기 상관 기반 조기경보");
    const c = $("#mission-claim"), s = $("#mission-scope"), sub = $("#mission-sub");
    if (c) c.textContent = claim;
    if (s) s.textContent = R.meta.data_scope || "합성/가공 데이터 · 오프라인 재현";

    const hero = $("#ms-hero");
    if (hero) {
      hero.innerHTML = `
        <div class="eyebrow">EARLY WARNING LEAD TIME</div>
        <div class="kh-val"><span class="val-n">0</span><span class="unit">일</span></div>
        <div class="kh-note">태성회로 crown-jewel 침해 전 동일 RedLine+C2 캠페인 조기 탐지</div>
        ${heroSparkSvg(rp.snapshots)}`;
      animateNumber(hero.querySelector(".val-n"), k.early_warning_lead_days || 0, { dur: 900 });
    }

    if (sub && rp.early_warning_day && rp.hero_peak_day) {
      sub.textContent = `${rp.early_warning_day}에 동일 스틸러+C2가 2개 이상 협력사로 확산된 것을 포착했고, ${rp.hero_peak_day} crown-jewel 침해 전에 대응 여유를 확보했습니다.`;
    }
  }

  // ---- ranked table --------------------------------------------------------
  function meterClass(status) {
    if (status.startsWith("CRITICAL")) return "crit";
    if (status === "HIGH") return "high";
    if (status === "MEDIUM") return "med";
    if (status.startsWith("NO SIGNAL")) return "nosignal";
    return "";
  }
  function statusKey(s) {
    if (s.startsWith("CRITICAL")) return "CRITICAL";
    if (s.startsWith("NO SIGNAL")) return "NOSIGNAL";
    return s;
  }

  const rankState = { status: "ALL", q: "", sort: "score_desc" };

  function initRankToolbar() {
    const statuses = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NOSIGNAL"];
    const STATUS_KO = { ALL: "전체", CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", NOSIGNAL: "NO SIGNAL" };
    const box = $("#rank-status-filters");
    box.innerHTML = statuses.map(s =>
      `<span class="sfilter${s === "ALL" ? " on" : ""}" data-status="${s}">${STATUS_KO[s]}</span>`).join("");
    box.addEventListener("click", e => {
      const c = e.target.closest(".sfilter"); if (!c) return;
      rankState.status = c.dataset.status;
      box.querySelectorAll(".sfilter").forEach(x => x.classList.toggle("on", x === c));
      applyRankFilter();
    });
    $("#rank-search").addEventListener("input", e => { rankState.q = e.target.value; applyRankFilter(); });
    $("#rank-sort").addEventListener("change", e => { rankState.sort = e.target.value; applyRankFilter(); });
  }

  function applyRankFilter() {
    if (!REPORT) return;
    const q = rankState.q.trim().toLowerCase();
    let list = REPORT.ranked_vendors.filter(v => {
      if (rankState.status !== "ALL" && statusKey(v.status) !== rankState.status) return false;
      if (q && !v.name.toLowerCase().includes(q) && !v.vendor_id.toLowerCase().includes(q)) return false;
      return true;
    });
    if (rankState.sort === "score_asc") list = list.slice().sort((a, b) => a.risk_score - b.risk_score);
    else if (rankState.sort === "name") list = list.slice().sort((a, b) => a.name.localeCompare(b.name, "ko"));
    else list = list.slice().sort((a, b) => b.risk_score - a.risk_score);
    const maxScore = Math.max(1, ...REPORT.ranked_vendors.map(v => v.risk_score));
    renderRanked(list, maxScore);
  }

  function renderRanked(vendors, maxScore) {
    const body = $("#rank-body"); body.innerHTML = "";
    $("#rank-count").textContent = `${vendors.length}개`;
    if (!vendors.length) {
      body.innerHTML = `<div class="detail-empty">조건에 맞는 협력사가 없습니다.</div>`;
      return;
    }
    vendors.forEach((v, i) => {
      const pct = Math.max(3, Math.round((v.risk_score / maxScore) * 100));
      const crit = v.status.startsWith("CRITICAL");
      const row = el("div", "vrow" + (crit ? " crit" : ""));
      row.dataset.vid = v.vendor_id;
      row.style.setProperty("--i", i);
      const mitres = (v.mitre || []).slice(0, 3)
        .map(m => `<span class="chip mitre">${esc(m.technique_id)}</span>`).join("");
      row.innerHTML = `
        <div class="rank">${String(i + 1).padStart(2, "0")}</div>
        <div class="vmain">
          <div class="name">${esc(v.name)}</div>
          <div class="meta">${v.tier}차 · ${esc(v.criticality)} · conf ${v.confidence.score}</div>
          <div class="chips" style="margin-top:6px">${mitres}</div>
        </div>
        <div>
          <div class="meter ${meterClass(v.status)}"><i style="width:${pct}%"></i></div>
          <div class="risknum">${v.risk_score.toFixed(1)}</div>
        </div>
        <div class="badge ${statusKey(v.status)}">${esc(v.status.replace(" — 즉시 조치", "").replace(" — 관측 공백", ""))}</div>`;
      row.addEventListener("click", () => selectVendor(v.vendor_id));
      body.appendChild(row);
    });
  }

  // ---- detail --------------------------------------------------------------
  function selectVendor(vid) {
    document.querySelectorAll(".vrow").forEach(r =>
      r.classList.toggle("sel", r.dataset.vid === vid));
    const v = REPORT.ranked_vendors.find(x => x.vendor_id === vid);
    if (!v) return;
    const adv = (REPORT.advisories || []).find(a => a.vendor_id === vid);
    renderDetail(v, adv);
  }

  const CAT_KO = { vpn: "VPN", sso: "SSO", admin_panel: "ERP/관리자", cloud_console: "클라우드콘솔",
    code_repo: "코드저장소", webmail: "웹메일", saas: "SaaS", generic: "포털" };

  function renderDetail(v, adv) {
    $("#detail-hint").textContent = v.vendor_id;
    const b = $("#detail-body"); b.innerHTML = "";

    const head = el("div", "dt-head");
    head.innerHTML = `
      <div>
        <div class="dt-name">${esc(v.name)}</div>
        <div class="dt-crit">${v.tier}차 협력사 · ${esc(v.criticality)}</div>
        <div class="conf"><div class="track"><i style="width:${Math.round(v.confidence.score*100)}%"></i></div>
          <span class="pct">신뢰도 ${Math.round(v.confidence.score*100)}%</span></div>
      </div>
      <div class="dt-score"><div class="n" style="color:${v.status.startsWith("CRITICAL")?"var(--critical)":"var(--ink)"}">${v.risk_score.toFixed(1)}</div>
        <div class="l">RISK SCORE</div></div>`;
    b.appendChild(head);
    b.appendChild(el("div", "score-def",
      "이 점수는 <b>보안 수준</b>이 아니라 <b>현재 침해 가능성(Compromise Likelihood)</b>을 평가합니다 — " +
      "MFA·장비 유무가 아니라 유출·감염·상관 <b>증거</b>만 봅니다."));

    // score anatomy — 활성침해 지배 스코어링을 시각적으로 증명
    const bd = v.breakdown;
    b.appendChild(el("div", "section-t", "위험 점수 분해 · 왜 이 순위인가"));
    const raw = Math.max(bd.active_compromise + bd.leaked_credentials + bd.stealer_infections, 0.001);
    const segs = [
      { k: "active", label: "활성침해", val: bd.active_compromise },
      { k: "leak", label: "유출", val: bd.leaked_credentials },
      { k: "stealer", label: "감염기기", val: bd.stealer_infections },
    ];
    const anatomy = el("div", "anatomy");
    anatomy.innerHTML = segs.map(s => {
      const pct = Math.max((s.val / raw) * 100, s.val > 0 ? 1.5 : 0);
      return `<i class="a-${s.k}" style="width:${pct}%" title="${s.label} ${s.val}"></i>`;
    }).join("");
    b.appendChild(anatomy);
    const legend = el("div", "anatomy-legend");
    legend.innerHTML = segs.map(s =>
      `<span><i class="a-${s.k}"></i>${s.label} <b>${s.val}</b></span>`).join("") +
      `<span class="mult">raw ${raw.toFixed(1)} <span class="op">×</span> 임무영향 ${bd.mission_multiplier}
         <span class="op">=</span> <b class="final">${v.risk_score.toFixed(1)}</b></span>`;
    b.appendChild(legend);

    // 킬체인 도달성 + 순위 분석 (branch 3·4)
    const ra = v.rank_analytics, reach = v.reach;
    if (ra || reach) {
      const strip = el("div", "reach-strip");
      const chips = [];
      if (reach) {
        const rc = reach.full_chain ? "full" : (reach.layers && reach.layers.length ? "part" : "none");
        chips.push(`<span class="rc rc-${rc}" title="노출된 킬체인 계층">${esc(reach.label)}</span>`);
      }
      if (ra) {
        const t = ra.trajectory || {};
        chips.push(`<span class="rc rc-rank">순위 ${ra.rank}/${ra.of} · 상위 ${100 - ra.percentile + Math.round(100/ra.of)}%</span>`);
        chips.push(`<span class="rc rc-share">포트폴리오 위험 ${ra.portfolio_share_pct}%</span>`);
        chips.push(`<span class="rc rc-traj rc-${t.state}">${esc(t.label || "")}</span>`);
      }
      strip.innerHTML = chips.join("");
      b.appendChild(strip);
    }

    // 크리덴셜 종류별 기여도 — 신호 출처 축(위 anatomy)과 다른 축으로 "왜 이 점수인가"를 보여준다
    const catBd = v.category_breakdown;
    if (catBd && Object.keys(catBd).length) {
      b.appendChild(el("div", "section-t", "크리덴셜 종류별 기여도"));
      const maxCat = Math.max(...Object.values(catBd));
      const catBox = el("div", "catbd");
      catBox.innerHTML = Object.entries(catBd).map(([cat, val]) => `
        <div class="catbd-row">
          <span class="catbd-label">${CAT_KO[cat] || cat}</span>
          <div class="catbd-bar"><i style="width:${Math.max(val / maxCat * 100, 4)}%"></i></div>
          <span class="catbd-val">${val}</span>
        </div>`).join("");
      b.appendChild(catBox);
      b.appendChild(el("div", "catbd-note",
        "활성침해 기여도를 노출된 카테고리 수만큼 균등 배분한 값 — 별도로 보정된 카테고리별 가중치 표가 아니라 " +
        "위 점수 분해(활성침해 " + bd.active_compromise + ")를 다른 축으로 나눠본 것입니다."));
    }

    if (v.evidence_ledger && v.evidence_ledger.length) {
      b.appendChild(el("div", "section-t", "Evidence Ledger · 판정 근거 장부"));
      const led = el("div", "ledger");
      led.innerHTML = v.evidence_ledger.map(item => `
        <div class="ledger-row kind-${esc(item.kind)}">
          <div class="ledger-score">${esc(item.score_effect)}</div>
          <div class="ledger-main"><b>${esc(item.title)}</b><p>${esc(item.why)}</p>
            <div class="ledger-src">${(item.evidence || []).map(x => `<span>${esc(x)}</span>`).join("")}</div></div>
          <div class="ledger-conf">${esc(item.confidence)}</div>
        </div>`).join("");
      b.appendChild(led);
    }

    if (v.attack_path && v.attack_path.length) {
      b.appendChild(el("div", "section-t", "Attack Path · 유출 → 침투 경로"));
      const ap = el("div", "attack-path");
      ap.innerHTML = v.attack_path.map((step, idx) => `
        <div class="ap-step st-${esc(step.status)}"><span>${idx + 1}</span><b>${esc(step.label)}</b><small>${esc(step.stage)}</small></div>`).join(`<i class="ap-arrow">→</i>`);
      b.appendChild(ap);
    }

    // active incidents (evidence)
    if (v.active_incidents && v.active_incidents.length) {
      b.appendChild(el("div", "section-t", "활성 침해 근거"));
      v.active_incidents.forEach(inc => {
        const e = el("div", "evi");
        const cats = inc.high_categories.map(c => CAT_KO[c] || c).join(", ");
        const urls = (inc.exposed_urls || []).map(u => `<code>${esc(u)}</code>`).join("");
        e.innerHTML = `
          <div class="row"><span>스틸러</span><b>${esc(inc.stealer_family)}</b></div>
          <div class="row"><span>감염일</span><b>${esc(inc.infection_date)} · ${inc.age_days}일 전</b></div>
          <div class="row"><span>단말</span><b>${esc(inc.machine_id)}</b></div>
          <div class="row"><span>유출 유형</span><b>${esc(cats)}</b></div>
          <div class="urls">${urls}</div>`;
        b.appendChild(e);
      });
    }

    // MITRE
    if (v.mitre && v.mitre.length) {
      b.appendChild(el("div", "section-t", "MITRE ATT&CK"));
      const mc = el("div", "chips");
      mc.innerHTML = v.mitre.slice(0, 7).map(m =>
        `<span class="chip mitre" title="${esc(m.name)}">${esc(m.technique_id)} · ${esc(m.name)}</span>`).join("");
      b.appendChild(mc);
    }

    // timeline
    if (v.timeline && v.timeline.length) {
      b.appendChild(el("div", "section-t", "사건 타임라인"));
      const tl = el("div", "tl");
      v.timeline.slice(0, 8).forEach(ev => {
        const e = el("div", "ev " + ev.kind);
        e.innerHTML = `<div class="d">${esc(ev.date)}</div>
          <div class="l">${esc(ev.label)}</div><div class="x">${esc(ev.detail)}</div>`;
        tl.appendChild(e);
      });
      b.appendChild(tl);
    }

    // provenance
    if (v.provenance && v.provenance.length) {
      b.appendChild(el("div", "section-t", "출처 (citation)"));
      const pc = el("div", "chips");
      pc.innerHTML = v.provenance.slice(0, 8).map(p =>
        `<span class="chip">${esc(p.source)} ×${p.count}</span>`).join("");
      b.appendChild(pc);
    }

    // advisory
    if (adv) {
      b.appendChild(el("div", "section-t", "자동 생성 조치 권고 통보문"));
      const box = el("div", "advisory");
      const ah = el("div", "ah");
      ah.innerHTML = `<span class="t">${esc(adv.title)}</span>`;
      const btn = el("button", "btn", "통보문 복사");
      btn.addEventListener("click", () => {
        navigator.clipboard && navigator.clipboard.writeText(adv.notice_draft);
        btn.textContent = "복사됨 ✓";
        setTimeout(() => (btn.textContent = "통보문 복사"), 1500);
      });
      ah.appendChild(btn);
      box.appendChild(ah);
      box.appendChild(el("pre", null, esc(adv.notice_draft)));
      b.appendChild(box);
    }
    retrigger(b);
  }

  // ---- campaigns -----------------------------------------------------------
  function renderCampaigns(camps) {
    $("#camp-count").textContent = `${camps.length}건`;
    const b = $("#camp-body"); b.innerHTML = "";
    if (!camps.length) { b.innerHTML = `<div class="detail-empty">탐지된 캠페인 없음</div>`; return; }
    camps.forEach(c => {
      const n = el("div", "camp");
      const vs = c.affected_vendors.map(v => `<span class="v">${esc(v.name)}</span>`).join("");
      n.innerHTML = `
        <div class="ct">
          <span class="id">${esc(c.campaign_id)}</span>
          ${c.threat_actor ? `<span class="chip hot">${esc(c.threat_actor)}</span>` : ""}
          <span class="conf-t">conf ${c.confidence}</span>
        </div>
        <div class="note">${esc(c.note)}</div>
        <div class="vs">${vs}</div>`;
      b.appendChild(n);
    });
  }

  // ---- 다음 표적 확산 예측 -------------------------------------------------
  function renderForecast(fc) {
    const b = $("#forecast-body"); if (!b) return;
    fc = fc || {};
    const preds = fc.predictions || [];
    const sp = fc.spread;
    $("#forecast-spread").textContent = sp
      ? `확산 ${sp.vendors_per_day}개사/일 · 다음 감염 투영 ${sp.projected_next_hit || "—"}`
      : "";
    if (!preds.length) {
      b.innerHTML = `<div class="detail-empty">예측 대상 없음</div>`;
      return;
    }
    const head = `<div class="fc-lead">
      <b>${esc(fc.primary_campaign || "")}</b> 확산 패턴 기준 —
      아직 활성 침해가 아닌 협력사 중 <b>다음 표적 가능성</b> 상위 ${preds.length}개.
      <span class="fc-caveat">다중 신호 휴리스틱(확정 아님) · 근거 명시</span></div>`;
    const cards = preds.map(p => `
      <div class="fc-card fc-${p.band}">
        <div class="fc-top">
          <span class="fc-name">${esc(p.name)}</span>
          <span class="fc-meta">${p.tier}차 · ${esc(p.criticality)}</span>
          <span class="fc-score">${p.escalation_risk}<small>/100</small></span>
        </div>
        <div class="fc-bar"><i style="width:${p.escalation_risk}%"></i></div>
        <ul class="fc-reasons">${p.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>
      </div>`).join("");
    b.innerHTML = head + `<div class="fc-grid">${cards}</div>`;
  }

  // ---- correlation graph (SVG, layered by type) ----------------------------
  const SVGNS = "http://www.w3.org/2000/svg";
  const COL = { actor: "#FF5A54", campaign: "#F2A93B", c2: "#57C4D6", vendor: "#6E8496" };
  function sn(tag, attrs) {
    const n = document.createElementNS(SVGNS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }
  function graphEntityKey(n) {
    if (n.type === "campaign") return "camp:" + n.id;
    if (n.type === "vendor") return "vendor:" + n.id;
    return n.id; // actor:xxx / c2:xxx already prefixed
  }

  function renderGraph(graph) {
    const svg = $("#graph"); svg.innerHTML = "";
    const W = 640, H = 340;
    const cols = { actor: 70, campaign: 235, c2: 400, vendor: 565 };
    const byType = { actor: [], campaign: [], c2: [], vendor: [] };
    graph.nodes.forEach(n => (byType[n.type] || byType.vendor).push(n));
    const pos = {};
    Object.keys(byType).forEach(t => {
      const arr = byType[t];
      arr.forEach((n, i) => {
        const gap = H / (arr.length + 1);
        pos[n.id] = { x: cols[t] || 300, y: gap * (i + 1), node: n };
      });
    });

    const adj = {}; // id -> Set of connected ids
    graph.nodes.forEach(n => (adj[n.id] = new Set([n.id])));
    graph.edges.forEach(e => {
      if (adj[e.source]) adj[e.source].add(e.target);
      if (adj[e.target]) adj[e.target].add(e.source);
    });

    const edgeEls = [];
    graph.edges.forEach(e => {
      const a = pos[e.source], b = pos[e.target];
      if (!a || !b) return;
      const mx = (a.x + b.x) / 2;
      const path = sn("path", {
        d: `M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`,
        fill: "none", stroke: "#1F2A34", "stroke-width": 1.2, opacity: 0.8,
      });
      path.dataset.source = e.source; path.dataset.target = e.target;
      path.style.transition = "opacity .2s ease, stroke .2s ease";
      svg.appendChild(path);
      edgeEls.push(path);
    });

    const nodeEls = {}; // id -> {circle,label,group}
    Object.values(pos).forEach(p => {
      const n = p.node;
      const crit = n.type === "vendor" && n.status && n.status.startsWith("CRITICAL");
      const r = n.type === "campaign" ? 9 : (n.type === "vendor" ? 6 : 7);
      const g = sn("g", { class: "gnode" });
      g.style.cursor = "pointer";
      g.style.transition = "opacity .2s ease";

      const halo = sn("circle", { cx: p.x, cy: p.y, r: r + 7, fill: COL[n.type] || "#6E8496", opacity: 0 });
      halo.style.transition = "opacity .2s ease";
      g.appendChild(halo);

      const circle = sn("circle", {
        cx: p.x, cy: p.y, r: r + (crit ? 2 : 0),
        fill: crit ? "#FF5A54" : (COL[n.type] || "#6E8496"),
        stroke: "#080B0F", "stroke-width": 2,
      });
      circle.style.transition = "r .15s ease";
      g.appendChild(circle);

      const title = sn("title", {});
      const extra = n.type === "vendor" ? ` · risk ${n.risk ?? "-"} · ${n.status || ""}`
        : n.type === "campaign" ? ` · confidence ${n.confidence ?? "-"}` : "";
      title.textContent = `${ETYPE_KO[n.type] || n.type}: ${n.label}${extra}`;
      g.appendChild(title);

      const label = sn("text", {
        x: p.x + 11, y: p.y + 3.5,
        "font-family": "ui-monospace, SF Mono, Menlo, monospace",
        "font-size": 10, fill: crit ? "#ff9a95" : "#A4B5C4",
      });
      label.style.transition = "fill .2s ease, opacity .2s ease";
      label.textContent = n.label.length > 20 ? n.label.slice(0, 19) + "…" : n.label;
      g.appendChild(label);

      g.addEventListener("mouseenter", () => {
        const near = adj[n.id] || new Set([n.id]);
        edgeEls.forEach(e => {
          const on = e.dataset.source === n.id || e.dataset.target === n.id;
          e.style.opacity = on ? "1" : ".08";
          e.style.stroke = on ? (COL[n.type] || "var(--amber)") : "#1F2A34";
        });
        Object.entries(nodeEls).forEach(([id, ne]) => {
          ne.group.style.opacity = near.has(id) ? "1" : ".22";
        });
        halo.setAttribute("opacity", "0.16");
        circle.setAttribute("r", r + (crit ? 2 : 0) + 2);
      });
      g.addEventListener("mouseleave", () => {
        edgeEls.forEach(e => { e.style.opacity = "0.8"; e.style.stroke = "#1F2A34"; });
        Object.values(nodeEls).forEach(ne => { ne.group.style.opacity = "1"; });
        halo.setAttribute("opacity", "0");
        circle.setAttribute("r", r + (crit ? 2 : 0));
      });
      g.addEventListener("click", () => {
        const key = graphEntityKey(n);
        showView("investigate");
        if (!Object.keys(entityIndex).length) buildEntities();
        if (entityIndex[key]) selectEntity(key);
      });

      svg.appendChild(g);
      nodeEls[n.id] = { circle, label, group: g };
    });
  }

  // ---- tables --------------------------------------------------------------
  function renderMitre(rows) {
    $("#mitre-count").textContent = `${rows.length}종`;
    const t = $("#mitre-tbl");
    t.innerHTML = `<tr><th>기법 ID</th><th>이름</th><th style="text-align:right">관측</th></tr>` +
      rows.map(r => `<tr><td><span class="id">${esc(r.technique_id)}</span></td>
        <td>${esc(r.name)}</td><td class="cnt">${r.count}</td></tr>`).join("");
  }
  function renderIoc(rows) {
    $("#ioc-count").textContent = `${rows.length}건`;
    const t = $("#ioc-tbl");
    t.innerHTML = `<tr><th>유형</th><th>지표</th><th>맥락</th><th style="text-align:right">건수</th></tr>` +
      rows.map(r => `<tr><td class="mono">${esc(r.type)}</td>
        <td><span class="id">${esc(r.value)}</span></td>
        <td>${esc(r.context)}</td><td class="cnt">${r.count}</td></tr>`).join("");
  }

  // ---- replay (time machine) ----------------------------------------------
  const replayState = { snaps: [], idx: 0, playing: false, timer: null,
                        ewIdx: -1, heroIdx: -1, lead: null };

  function renderReplay(rp) {
    if (!rp || !rp.snapshots || !rp.snapshots.length) {
      $("#replay-panel").style.display = "none"; return;
    }
    const st = replayState;
    st.snaps = rp.snapshots;
    st.ewIdx = st.snaps.findIndex(s => s.date === rp.early_warning_day);
    st.heroIdx = st.snaps.findIndex(s => s.date === rp.hero_peak_day);
    st.lead = rp.lead_days;
    st.primary = rp.primary_campaign;

    const lead = rp.lead_days != null
      ? `리드타임 ${rp.lead_days}일 — crown-jewel 침해 이전 탐지` : "";
    $("#replay-lead").textContent = lead;

    const intro = $("#replay-intro");
    if (intro) {
      intro.innerHTML = (rp.early_warning_day && rp.hero_peak_day && rp.lead_days != null)
        ? `이건 "과거 다시보기"가 아니라 <b>조기경보가 실제로 앞서 발령됐다는 증거</b>입니다 — ` +
          `동일 캠페인이 <b>${esc(rp.early_warning_day)}</b>에 2개 이상 협력사로 확산 요건을 충족했고, ` +
          `crown-jewel(<b>${esc(rp.crown_jewel || "")}</b>) 실제 침해(<b>${esc(rp.hero_peak_day)}</b>)보다 ` +
          `<b>${rp.lead_days}일</b> 먼저 이 화면에 나타났습니다. 아래 스크럽을 움직이면 그 순간을 그대로 재생합니다.`
        : "";
    }

    const scrub = $("#replay-scrub");
    scrub.max = st.snaps.length - 1;
    scrub.value = st.idx = 0;
    scrub.oninput = () => { pause(); setIdx(+scrub.value); };
    $("#replay-play").onclick = togglePlay;

    drawSpark();
    setIdx(0);
  }

  function drawSpark() {
    const st = replayState, svg = $("#replay-spark");
    svg.innerHTML = "";
    const W = 1000, H = 120, pad = 12;
    const n = st.snaps.length;
    const maxR = Math.max(1, ...st.snaps.map(s => s.risk_index));
    const X = i => (i / (n - 1)) * W;
    const Y = r => H - pad - (r / maxR) * (H - pad * 2);
    const pts = st.snaps.map((s, i) => [X(i), Y(s.risk_index)]);

    // full dim line
    const dim = sn("polyline", { points: pts.map(p => p.join(",")).join(" "),
      fill: "none", stroke: "#1F2A34", "stroke-width": 1.5 });
    svg.appendChild(dim);

    // EW + hero vertical markers
    if (st.ewIdx >= 0) {
      svg.appendChild(sn("line", { x1: X(st.ewIdx), y1: 6, x2: X(st.ewIdx), y2: H - 6,
        stroke: "#F2A93B", "stroke-width": 1.5, "stroke-dasharray": "3 3", opacity: .8 }));
    }
    if (st.heroIdx >= 0) {
      svg.appendChild(sn("line", { x1: X(st.heroIdx), y1: 6, x2: X(st.heroIdx), y2: H - 6,
        stroke: "#FF5A54", "stroke-width": 1.5, "stroke-dasharray": "3 3", opacity: .8 }));
    }
    st._geo = { X, Y, pts, W, H };
    // bright progress overlay (updated per idx)
    st._progress = sn("polyline", { points: "", fill: "none", stroke: "#F2A93B", "stroke-width": 2.5 });
    svg.appendChild(st._progress);
    st._dot = sn("circle", { r: 4.5, fill: "#F2A93B", stroke: "#080B0F", "stroke-width": 2 });
    svg.appendChild(st._dot);
  }

  function setIdx(i) {
    const st = replayState;
    st.idx = Math.max(0, Math.min(i, st.snaps.length - 1));
    const s = st.snaps[st.idx];
    $("#replay-scrub").value = st.idx;
    $("#replay-date").textContent = s.date;

    // progress overlay
    const g = st._geo;
    st._progress.setAttribute("points",
      g.pts.slice(0, st.idx + 1).map(p => p.join(",")).join(" "));
    const cur = g.pts[st.idx];
    st._dot.setAttribute("cx", cur[0]); st._dot.setAttribute("cy", cur[1]);
    st._dot.setAttribute("fill", s.status === "critical" ? "#FF5A54" : "#F2A93B");

    // stats
    $("#replay-stats").innerHTML =
      `<span class="s">유출 <b>${s.exposed_credentials}</b></span>
       <span class="s">감염기기 <b>${s.infected_machines}</b></span>
       <span class="s ${s.active_compromises ? "hot" : ""}">활성침해 <b>${s.active_compromises}</b></span>
       <span class="s ${s.campaign_detected ? "hot" : ""}">캠페인 확산 <b>${s.campaign_spread}</b></span>`;

    // early-warning banner
    const ew = $("#replay-ew");
    if (st.ewIdx >= 0 && st.idx >= st.ewIdx) {
      const fam = st.primary ? st.primary.stealer_family : "campaign";
      ew.classList.add("show");
      ew.innerHTML = `<span class="dot"></span>조기경보 · 조율된 ${esc(fam)} 공급망 캠페인 탐지` +
        (st.lead != null && st.idx < st.heroIdx
          ? ` · crown-jewel 침해 ${st.heroIdx - st.idx}일 전`
          : (st.lead != null ? ` · 리드타임 ${st.lead}일` : ""));
    } else {
      ew.classList.remove("show");
    }

    // ticker
    $("#replay-ticker").innerHTML = s.events.length
      ? s.events.map(e => `<span class="tk ${e.campaign ? "camp" : e.kind}">${esc(e.label)}</span>`).join("")
      : `<span class="tk" style="opacity:.5">이 날짜에 신규 이벤트 없음</span>`;
  }

  function togglePlay() { replayState.playing ? pause() : play(); }
  function play() {
    const st = replayState;
    if (st.idx >= st.snaps.length - 1) setIdx(0);
    st.playing = true; $("#replay-play").textContent = "⏸";
    st.timer = setInterval(() => {
      if (st.idx >= st.snaps.length - 1) { pause(); return; }
      setIdx(st.idx + 1);
    }, 420);
  }
  function pause() {
    const st = replayState;
    st.playing = false; $("#replay-play").textContent = "▶";
    if (st.timer) { clearInterval(st.timer); st.timer = null; }
  }

  // ---- toast ---------------------------------------------------------------
  let _toastEl = null;
  function toast(msg) {
    if (!_toastEl) {
      _toastEl = el("div");
      _toastEl.style.cssText = "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);" +
        "background:#141E27;border:1px solid #1F2A34;color:#EAF1F7;font-family:var(--font-mono);" +
        "font-size:12px;padding:10px 16px;border-radius:8px;z-index:99;box-shadow:0 10px 30px rgba(0,0,0,.5);" +
        "transition:opacity .3s;opacity:0";
      document.body.appendChild(_toastEl);
    }
    _toastEl.textContent = msg; _toastEl.style.opacity = "1";
    clearTimeout(_toastEl._t);
    _toastEl._t = setTimeout(() => (_toastEl.style.opacity = "0"), 1900);
  }

  // ---- router + clock ------------------------------------------------------
  const views = {};
  function initSpotlight() {
    const strip = $("#mission-strip");
    if (!strip) return;
    strip.addEventListener("mousemove", e => {
      const r = strip.getBoundingClientRect();
      strip.style.setProperty("--mx", ((e.clientX - r.left) / r.width * 100) + "%");
      strip.style.setProperty("--my", ((e.clientY - r.top) / r.height * 100) + "%");
    });
  }

  function moveNavIndicator(btn) {
    const ind = $("#nav-indicator");
    if (!ind || !btn) return;
    ind.style.top = (btn.offsetTop + 8) + "px";
    ind.style.height = (btn.offsetHeight - 16) + "px";
    ind.classList.add("on");
  }
  const VIEW_LABELS = { overview: "개요", siem: "SIEM", triage: "인시던트 대응", investigate: "조사", brief: "보고서·탐지룰" };

  function showView(name) {
    document.querySelectorAll(".view").forEach(v => v.classList.add("hidden"));
    const v = $("#view-" + name); if (v) v.classList.remove("hidden");
    let activeBtn = null;
    document.querySelectorAll(".nav").forEach(n => {
      const active = n.dataset.view === name;
      n.classList.toggle("active", active);
      if (active) activeBtn = n;
    });
    moveNavIndicator(activeBtn);
    const crumb = $("#view-crumb"); if (crumb) crumb.textContent = VIEW_LABELS[name] || name;
    if (views[name]) views[name]();          // lazy re-render hook
    window.scrollTo(0, 0);
  }
  function initRouter() {
    document.querySelectorAll(".nav").forEach(n =>
      n.addEventListener("click", () => showView(n.dataset.view)));
    moveNavIndicator($(".nav.active"));
  }

  // ==========================================================================
  //  커맨드 팔레트 (⌘K 빠른 이동) — 화면/협력사/캠페인/C2/행위자를 한 번에 검색·이동
  // ==========================================================================
  const cmdk = { items: [], filtered: [], sel: 0, open: false };

  function buildCmdkItems() {
    const R = REPORT;
    const items = [
      { type: "화면", label: "개요", sub: "전체 KPI · 공격 타임라인 · 순위", go: () => showView("overview") },
      { type: "화면", label: "SIEM", sub: "보안 이벤트 스트림", go: () => showView("siem") },
      { type: "화면", label: "인시던트 대응", sub: "P1 대응 큐 · SLA", go: () => showView("triage") },
      { type: "화면", label: "조사", sub: "엔티티 피벗 · 설명가능성", go: () => showView("investigate") },
      { type: "화면", label: "보고서·탐지룰", sub: "브리프 · IOC · Sigma · STIX", go: () => showView("brief") },
    ];
    (R.ranked_vendors || []).forEach(v => items.push({
      type: "협력사", label: v.name, sub: `${v.status.replace(" — 즉시 조치", "").replace(" — 관측 공백", "")} · risk ${v.risk_score.toFixed(1)}`,
      go: () => { showView("overview"); selectVendor(v.vendor_id);
        document.querySelector(`.vrow[data-vid="${v.vendor_id}"]`)?.scrollIntoView({ block: "center" }); },
    }));
    (R.campaigns || []).forEach(c => items.push({
      type: "캠페인", label: c.campaign_id, sub: `${c.stealer_family} · ${c.affected_count}개 협력사`,
      go: () => { showView("investigate"); if (!Object.keys(entityIndex).length) buildEntities();
        selectEntity("camp:" + c.campaign_id); },
    }));
    const seen = new Set();
    (R.campaigns || []).forEach(c => {
      if (c.c2_host && !seen.has("c2:" + c.c2_host)) {
        seen.add("c2:" + c.c2_host);
        items.push({
          type: "C2", label: c.c2_host, sub: "Command & Control 인프라",
          go: () => { showView("investigate"); if (!Object.keys(entityIndex).length) buildEntities();
            selectEntity("c2:" + c.c2_host); },
        });
      }
      if (c.threat_actor && !seen.has("actor:" + c.threat_actor)) {
        seen.add("actor:" + c.threat_actor);
        items.push({
          type: "행위자", label: c.threat_actor, sub: "위협 행위자(추정)",
          go: () => { showView("investigate"); if (!Object.keys(entityIndex).length) buildEntities();
            selectEntity("actor:" + c.threat_actor); },
        });
      }
    });
    cmdk.items = items;
  }

  function cmdkRender() {
    const box = $("#cmdk-results");
    if (!cmdk.filtered.length) {
      box.innerHTML = `<div class="cmdk-empty">일치하는 항목이 없습니다</div>`;
      return;
    }
    box.innerHTML = cmdk.filtered.slice(0, 40).map((it, i) => `
      <div class="cmdk-item${i === cmdk.sel ? " sel" : ""}" data-i="${i}">
        <span class="ck-type">${esc(it.type)}</span>
        <span class="ck-label">${esc(it.label)}</span>
        <span class="ck-sub">${esc(it.sub || "")}</span>
      </div>`).join("");
    box.querySelectorAll(".cmdk-item").forEach(el =>
      el.addEventListener("click", () => cmdkExecute(+el.dataset.i)));
  }

  function cmdkFilter(q) {
    q = q.trim().toLowerCase();
    cmdk.filtered = !q ? cmdk.items :
      cmdk.items.filter(it => (it.label + " " + (it.sub || "")).toLowerCase().includes(q));
    cmdk.sel = 0;
    cmdkRender();
  }

  function cmdkExecute(i) {
    const it = cmdk.filtered[i];
    if (!it) return;
    cmdkClose();
    it.go();
  }

  function cmdkOpen() {
    if (!cmdk.items.length) buildCmdkItems();
    cmdk.open = true;
    $("#cmdk-backdrop").style.display = "flex";
    const input = $("#cmdk-input");
    input.value = "";
    cmdkFilter("");
    setTimeout(() => input.focus(), 0);
  }
  function cmdkClose() {
    cmdk.open = false;
    $("#cmdk-backdrop").style.display = "none";
  }

  function initCommandPalette() {
    $("#cmdk-open").addEventListener("click", cmdkOpen);
    $("#cmdk-backdrop").addEventListener("mousedown", e => {
      if (e.target.id === "cmdk-backdrop") cmdkClose();
    });
    $("#cmdk-input").addEventListener("input", e => cmdkFilter(e.target.value));
    document.addEventListener("keydown", e => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.key.toLowerCase() === "k") {
        e.preventDefault();
        cmdk.open ? cmdkClose() : cmdkOpen();
        return;
      }
      if (!cmdk.open) return;
      if (e.key === "Escape") { e.preventDefault(); cmdkClose(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); cmdk.sel = Math.min(cmdk.sel + 1, cmdk.filtered.length - 1); cmdkRender(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); cmdk.sel = Math.max(cmdk.sel - 1, 0); cmdkRender(); }
      else if (e.key === "Enter") { e.preventDefault(); cmdkExecute(cmdk.sel); }
    });
  }
  function startClock() {
    const c = $("#ops-clock");
    const tick = () => {
      const d = new Date();
      c.textContent = d.toLocaleTimeString("ko-KR", { hour12: false }) + " KST";
    };
    tick(); setInterval(tick, 1000);
  }

  // ==========================================================================
  //  인시던트 대응 큐 (상태머신 + SLA)
  // ==========================================================================
  const TRIAGE_KEY = "scce_triage";
  const ANALYSTS = ["김분석", "이대응", "박관제"];
  const SLA_MIN = 15;                          // CRITICAL 초동 대응 목표(분)
  let incidents = [];

  function loadTriageState() { try { return JSON.parse(sessionStorage.getItem(TRIAGE_KEY) || "{}"); } catch (e) { return {}; } }
  function saveTriageState(s) { try { sessionStorage.setItem(TRIAGE_KEY, JSON.stringify(s)); } catch (e) {} }

  function buildIncidents() {
    const state = loadTriageState();
    const now = Date.now();
    incidents = [];
    REPORT.ranked_vendors.forEach(v => {
      (v.active_incidents || []).forEach(inc => {
        const camp = (REPORT.campaigns || []).find(c =>
          (c.machines || []).includes(inc.machine_id) ||
          (c.affected_vendors || []).some(a => a.vendor_id === v.vendor_id));
        const adv = (REPORT.advisories || []).find(a => a.vendor_id === v.vendor_id);
        const id = inc.log_id;
        if (!state[id]) state[id] = { status: "NEW", assignee: null, deadline: now + SLA_MIN * 60000, dispatched: false };
        incidents.push({
          id, vendor: v.name, vendor_id: v.vendor_id, criticality: v.criticality, tier: v.tier,
          stealer: inc.stealer_family, machine: inc.machine_id, infection_date: inc.infection_date,
          age: inc.age_days, cats: inc.high_categories, urls: inc.exposed_urls || [],
          campaign: camp ? camp.campaign_id : null, actor: camp ? camp.threat_actor : null,
          advisory: adv, risk: v.risk_score, response_impact: v.response_impact,
        });
      });
    });
    // 위험 높은 순
    incidents.sort((a, b) => b.risk - a.risk);
    saveTriageState(state);
  }

  function incState(id) { return loadTriageState()[id]; }
  function setIncState(id, patch) {
    const s = loadTriageState(); s[id] = Object.assign(s[id] || {}, patch); saveTriageState(s);
  }

  const CAT_KO2 = { vpn: "VPN", sso: "SSO", admin_panel: "ERP/관리자", cloud_console: "클라우드콘솔",
    code_repo: "코드저장소", webmail: "웹메일", saas: "SaaS", generic: "포털" };
  const ST_KO = { NEW: "신규", INVESTIGATING: "조사중", CONTAINED: "조치완료", ESCALATED: "에스컬레이션" };

  function fmtClock(ms) {
    if (ms <= 0) return "00:00";
    const s = Math.floor(ms / 1000), m = Math.floor(s / 60);
    return String(m).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
  }

  function renderTriage() {
    if (!incidents.length) buildIncidents();
    const state = loadTriageState();
    // stats
    const cnt = { NEW: 0, INVESTIGATING: 0, CONTAINED: 0, ESCALATED: 0 };
    let breaches = 0;
    incidents.forEach(i => {
      const st = state[i.id]; cnt[st.status]++;
      if ((st.status === "NEW" || st.status === "INVESTIGATING") && Date.now() > st.deadline) breaches++;
    });
    $("#triage-stats").innerHTML =
      `<span class="ts">신규 <b>${cnt.NEW}</b></span>
       <span class="ts">조사중 <b>${cnt.INVESTIGATING}</b></span>
       <span class="ts">조치완료 <b>${cnt.CONTAINED}</b></span>
       <span class="ts">에스컬레이션 <b>${cnt.ESCALATED}</b></span>
       <span class="ts breach">SLA 위반 <b>${breaches}</b></span>`;
    const open = cnt.NEW + cnt.INVESTIGATING;
    $("#nav-triage-badge").textContent = open ? String(open) : "";

    const list = $("#triage-list"); list.innerHTML = "";
    incidents.forEach(i => {
      const st = state[i.id];
      const done = st.status === "CONTAINED";
      const node = el("div", `inc sev-critical st-${st.status}`);
      const catTxt = i.cats.map(c => CAT_KO2[c] || c).join(", ");
      const campLine = i.campaign
        ? `<span class="chip hot">${esc(i.campaign)}${i.actor ? " · " + esc(i.actor) : ""}</span>` : "";
      node.innerHTML = `
        <div class="inc-main">
          <div class="inc-top">
            <span class="inc-vendor">${esc(i.vendor)}</span>
            <span class="st-pill st-${st.status}">${ST_KO[st.status]}</span>
            <span class="inc-id">${esc(i.id)} · ${i.tier}차 · ${esc(i.criticality)}</span>
          </div>
          <div class="inc-desc">${esc(i.stealer)} 감염(${esc(i.machine)}, ${i.age}일 전) ·
            내부망 유출: <code>${esc(catTxt)}</code></div>
          <div class="inc-tags">${campLine}
            <span class="assignee">담당: <b>${st.assignee || "미지정"}</b></span></div>
        </div>
        <div class="inc-side">
          <div class="sla">
            <div class="lbl">초동 대응 SLA</div>
            <div class="clock" data-clock="${i.id}">--:--</div>
          </div>
          ${i.response_impact ? `<div class="impact-mini">
            <span>조치 전 <b>${i.response_impact.pre_risk}</b></span>
            <i></i>
            <span>조치 후 <b>${i.response_impact.residual_risk}</b></span>
            <em>-${i.response_impact.risk_reduction_pct}%</em>
          </div>` : ""}
          <div class="inc-actions" data-id="${i.id}">
            <button class="act" data-a="ack" ${st.status !== "NEW" ? "disabled" : ""}>접수</button>
            <button class="act" data-a="assign">담당지정</button>
            <button class="act" data-a="dispatch" ${!i.advisory || st.dispatched ? "disabled" : ""}>${st.dispatched ? "발송됨✓" : "통보문 발송"}</button>
            <button class="act go" data-a="contain" ${done ? "disabled" : ""}>조치완료</button>
            <button class="act danger" data-a="escalate">에스컬레이션</button>
          </div>
        </div>`;
      node.querySelector(".inc-actions").addEventListener("click", (e) => {
        const b = e.target.closest("button"); if (!b) return;
        triageAction(i, b.dataset.a);
      });
      list.appendChild(node);
    });
    updateSlaClocks();
  }

  function triageAction(i, a) {
    if (a === "ack") { setIncState(i.id, { status: "INVESTIGATING" }); toast(`${i.vendor} 인시던트 접수 → 조사중`); }
    else if (a === "assign") {
      const cur = incState(i.id).assignee;
      const next = ANALYSTS[(ANALYSTS.indexOf(cur) + 1) % ANALYSTS.length];
      setIncState(i.id, { assignee: next }); toast(`담당 배정: ${next}`);
    }
    else if (a === "dispatch") { setIncState(i.id, { dispatched: true }); toast(`${i.vendor} 통보문 발송 완료`); }
    else if (a === "contain") { setIncState(i.id, { status: "CONTAINED" }); toast(`${i.vendor} 조치완료 처리`); }
    else if (a === "escalate") { setIncState(i.id, { status: "ESCALATED" }); toast(`${i.vendor} 상위기관 에스컬레이션`); }
    renderTriage();
  }

  function updateSlaClocks() {
    const state = loadTriageState();
    document.querySelectorAll("[data-clock]").forEach(elc => {
      const st = state[elc.dataset.clock]; if (!st) return;
      if (st.status === "CONTAINED") { elc.textContent = "완료 ✓"; elc.className = "clock done"; return; }
      if (st.status === "ESCALATED") { elc.textContent = "이관됨"; elc.className = "clock warn"; return; }
      const left = st.deadline - Date.now();
      elc.textContent = left > 0 ? fmtClock(left) : "SLA 위반";
      elc.className = "clock" + (left <= 0 ? " breach" : (left < 5 * 60000 ? " warn" : ""));
    });
  }

  // ==========================================================================
  //  조사 (Investigation) — 엔티티 피벗 + 설명가능성
  // ==========================================================================
  let entityIndex = {};
  function buildEntities() {
    entityIndex = {};
    const R = REPORT;
    (R.campaigns || []).forEach(c => entityIndex["camp:" + c.campaign_id] =
      { type: "campaign", label: c.campaign_id, data: c });
    (R.campaigns || []).forEach(c => {
      if (c.c2_host) entityIndex["c2:" + c.c2_host] = entityIndex["c2:" + c.c2_host] ||
        { type: "c2", label: c.c2_host, data: { c2: c.c2_host } };
      if (c.threat_actor) entityIndex["actor:" + c.threat_actor] = entityIndex["actor:" + c.threat_actor] ||
        { type: "actor", label: c.threat_actor, data: { actor: c.threat_actor } };
    });
    R.ranked_vendors.filter(v => v.status.startsWith("CRITICAL")).forEach(v =>
      entityIndex["vendor:" + v.vendor_id] = { type: "vendor", label: v.name, data: v });
  }
  const ETYPE_COL = { campaign: "#F2A93B", c2: "#57C4D6", actor: "#FF5A54", vendor: "#6E8496" };
  const ETYPE_KO = { campaign: "캠페인", c2: "C2", actor: "행위자", vendor: "협력사" };

  function renderInvestigate() {
    if (!Object.keys(entityIndex).length) buildEntities();
    const keys = Object.keys(entityIndex);
    $("#entity-count").textContent = `${keys.length}개`;
    const list = $("#entity-list"); list.innerHTML = "";
    keys.forEach(k => {
      const e = entityIndex[k];
      const row = el("div", "ent"); row.dataset.k = k;
      row.innerHTML = `<span class="etype" style="background:${ETYPE_COL[e.type]}"></span>
        <span class="en">${esc(e.label)}</span><span class="em">${ETYPE_KO[e.type]}</span>`;
      row.addEventListener("click", () => selectEntity(k));
      list.appendChild(row);
    });
    renderCrossLinks();
    renderLookalikes();
  }

  // 공급망 횡단 상관 (branch 2)
  function renderCrossLinks() {
    const links = REPORT.cross_vendor_links || [];
    $("#xlink-count").textContent = `${links.length}건`;
    const b = $("#xlink-body"); if (!b) return;
    if (!links.length) { b.innerHTML = `<div class="detail-empty">횡단 신호 없음</div>`; return; }
    const KO = { credential_reuse: "계정 재사용", shared_machine: "단말 공유" };
    b.innerHTML = links.slice(0, 12).map(l => `
      <div class="xlink">
        <div class="xl-top"><span class="xl-type xl-${l.type}">${KO[l.type] || l.type}</span>
          <span class="xl-key mono">${esc(l.key)}</span>
          <span class="xl-n">${l.vendors.length}개 협력사</span></div>
        <div class="xl-vs">${l.vendors.map(v => `<span>${esc(v)}</span>`).join("")}</div>
      </div>`).join("");
  }

  // 협력사 사칭 도메인 (branch 1)
  function renderLookalikes() {
    const items = REPORT.lookalike_domains || [];
    $("#lookalike-count").textContent = `${items.length}건`;
    const b = $("#lookalike-body"); if (!b) return;
    if (!items.length) { b.innerHTML = `<div class="detail-empty">탐지된 사칭 도메인 없음</div>`; return; }
    b.innerHTML = items.map(l => `
      <div class="lookalike">
        <div class="la-dom mono">${esc(l.lookalike)}</div>
        <div class="la-real">사칭 대상: <b>${esc(l.mimics_vendor)}</b></div>
        <div class="la-src">${(l.seen_in || []).join(", ")} · ${l.count}건 관측</div>
      </div>`).join("");
  }

  function selectEntity(k) {
    document.querySelectorAll(".ent").forEach(r => r.classList.toggle("sel", r.dataset.k === k));
    const e = entityIndex[k]; if (!e) return;
    const b = $("#invest-detail"); b.innerHTML = "";
    $("#invest-hint").textContent = ETYPE_KO[e.type];
    const pv = (key, label) => `<a class="pivot" data-k="${key}">${esc(label)}</a>`;

    if (e.type === "vendor") {
      const v = e.data, bd = v.breakdown;
      b.appendChild(el("div", "dt-head",
        `<div><div class="dt-name">${esc(v.name)}</div>
         <div class="dt-crit">${v.tier}차 · ${esc(v.criticality)} · 신뢰도 ${Math.round(v.confidence.score*100)}%</div></div>
         <div class="dt-score"><div class="n" style="color:var(--critical)">${v.risk_score.toFixed(1)}</div><div class="l">RISK</div></div>`));
      b.appendChild(el("div", "section-t", "설명가능성 — 점수는 왜 이렇게 나왔나"));
      const total = v.risk_score || 1;
      const rows = [
        ["활성 침해", bd.active_compromise], ["유출 자격증명", bd.leaked_credentials],
        ["감염기기", bd.stealer_infections],
      ];
      const ex = el("div", "explain");
      rows.forEach(([n, val]) => {
        const pct = Math.min(100, Math.round((val / total) * 100));
        ex.appendChild(el("div", "er",
          `<span class="ename">${n}</span><span class="ebar"><i style="width:${pct}%"></i></span><span class="eval">${val}</span>`));
      });
      ex.appendChild(el("div", "er",
        `<span class="ename">임무 영향 승수</span><span class="ebar"><i style="width:${Math.round((bd.mission_multiplier-1)/0.4*100)}%"></i></span><span class="eval">×${bd.mission_multiplier}</span>`));
      b.appendChild(ex);
      const camp = (REPORT.campaigns || []).find(c => c.affected_vendors.some(a => a.vendor_id === v.vendor_id));
      if (camp) {
        b.appendChild(el("div", "section-t", "연결"));
        b.appendChild(el("div", "chips", `${pv("camp:" + camp.campaign_id, camp.campaign_id)} &nbsp; ${pv("c2:" + camp.c2_host, camp.c2_host)}${camp.threat_actor ? " &nbsp; " + pv("actor:" + camp.threat_actor, camp.threat_actor) : ""}`));
      }
    }
    else if (e.type === "campaign") {
      const c = e.data;
      b.appendChild(el("div", "dt-head",
        `<div><div class="dt-name">${esc(c.campaign_id)}</div>
         <div class="dt-crit">${esc(c.stealer_family)} · ${c.affected_count}개 협력사 · 신뢰도 ${c.confidence}</div></div>`));
      b.appendChild(el("div", "section-t", "평가"));
      b.appendChild(el("p", null, esc(c.note)).cloneNode(true));
      const p = el("div"); p.style.cssText = "font-size:13px;color:var(--ink-dim);line-height:1.7"; p.textContent = c.note; b.appendChild(p);
      b.appendChild(el("div", "section-t", "연결 · 피벗"));
      const conns = [];
      if (c.threat_actor) conns.push(pv("actor:" + c.threat_actor, "행위자 " + c.threat_actor));
      if (c.c2_host) conns.push(pv("c2:" + c.c2_host, "C2 " + c.c2_host));
      c.affected_vendors.forEach(a => conns.push(pv("vendor:" + a.vendor_id, a.name)));
      b.appendChild(el("div", "chips", conns.join(" &nbsp; ")));
      b.appendChild(el("div", "section-t", "관측 기간"));
      b.appendChild(el("div", "chips", `<span class="chip">${esc(c.first_seen)} ~ ${esc(c.last_seen)} (${c.span_days}일)</span>`));
    }
    else if (e.type === "c2") {
      const host = e.data.c2;
      const camps = (REPORT.campaigns || []).filter(c => c.c2_host === host);
      b.appendChild(el("div", "dt-head", `<div><div class="dt-name mono">${esc(host)}</div><div class="dt-crit">Command &amp; Control 인프라</div></div>`));
      b.appendChild(el("div", "section-t", "이 인프라를 쓰는 캠페인"));
      b.appendChild(el("div", "chips", camps.map(c => pv("camp:" + c.campaign_id, c.campaign_id)).join(" &nbsp; ")));
      const vs = new Set(); camps.forEach(c => c.affected_vendors.forEach(a => vs.add(a.vendor_id)));
      b.appendChild(el("div", "section-t", "이 C2로 감염된 협력사"));
      b.appendChild(el("div", "chips", [...vs].map(id => {
        const v = REPORT.ranked_vendors.find(x => x.vendor_id === id);
        return pv("vendor:" + id, v ? v.name : id);
      }).join(" &nbsp; ")));
    }
    else if (e.type === "actor") {
      const actor = e.data.actor;
      const camps = (REPORT.campaigns || []).filter(c => c.threat_actor === actor);
      b.appendChild(el("div", "dt-head", `<div><div class="dt-name">${esc(actor)}</div><div class="dt-crit">위협 행위자 (추정)</div></div>`));
      b.appendChild(el("div", "section-t", "운용 캠페인"));
      b.appendChild(el("div", "chips", camps.map(c => pv("camp:" + c.campaign_id, c.campaign_id)).join(" &nbsp; ")));
    }
    // pivot wiring
    b.querySelectorAll(".pivot").forEach(a =>
      a.addEventListener("click", () => selectEntity(a.dataset.k)));
    retrigger(b);
  }

  // ==========================================================================
  //  인텔 브리프
  // ==========================================================================
  function renderBrief() {
    const R = REPORT, k = R.kpis, rp = R.replay || {};
    const crit = R.ranked_vendors.filter(v => v.status.startsWith("CRITICAL"));
    const lead = rp.lead_days;
    const primary = (R.campaigns || [])[0];

    const vendorRows = crit.map(v =>
      `<tr><td>${esc(v.name)}</td><td class="mono">${v.tier}차</td><td>${esc(v.criticality)}</td>
       <td class="mono">${v.risk_score.toFixed(1)}</td><td class="mono">${Math.round(v.confidence.score*100)}%</td></tr>`).join("");
    const mitreRows = (R.mitre_summary || []).slice(0, 8).map(m =>
      `<tr><td class="mono">${esc(m.technique_id)}</td><td>${esc(m.name)}</td><td class="mono">${m.count}</td></tr>`).join("");
    const iocRows = (R.iocs || []).slice(0, 8).map(i =>
      `<tr><td class="mono">${esc(i.type)}</td><td class="mono">${esc(i.value)}</td><td>${esc(i.context)}</td></tr>`).join("");
    const ev = R.evaluation || {};
    const cd = ev.campaign_detection || {};
    const ac = ev.active_compromise_detection || {};
    const lt = ev.lead_time || {};

    const summary = primary
      ? `동일 C2(<b>${esc(primary.c2_host)}</b>)와 동일 인포스틸러(<b>${esc(primary.stealer_family)}</b>)를 이용한 ` +
        `<b>조율된 공급망 캠페인</b>이 방산 협력사 <b>${primary.affected_count}개사</b>에서 확인되었다. ` +
        `본 캠페인은 crown-jewel 협력사 침해 <b>${lead != null ? lead + "일" : "수일"} 전</b>에 조기 탐지되었으며, ` +
        `현재 활성 침해 <b>${k.active_compromises}건</b>, CRITICAL 등급 협력사 <b>${k.critical_count}개사</b>가 즉시 조치 대상이다. ` +
        `판정 규칙은 <b>최근 스틸러 감염 + HIGH 크리덴셜 + 동일 C2/스틸러 상관</b>이다.`
      : `현재 활성 침해 ${k.active_compromises}건, CRITICAL 등급 협력사 ${k.critical_count}개사가 확인되었다.`;

    const html = `
      <div class="brief">
        <span class="b-class">CONFIDENTIAL · 방산 공급망 위협 인텔</span>
        <h1>${esc(R.meta.title)} — 위협 인텔리전스 브리프</h1>
        <div class="b-meta">문서번호 SCCE-INT-${(rp.early_warning_day || "").replace(/-/g,"")} ·
          기준일 ${esc(R.meta.generated_today)} · 분류: 대외비 · 출처: 합성/공개(가공)</div>

        <h3>1. 핵심 요약 (Executive Summary)</h3>
        <p>${summary}</p>

        <h3>2. 위협 평가</h3>
        <p>${primary ? esc(primary.note) : "개별 협력사 단위 자격증명 노출이 확인되었다."}
        공격 타임라인 분석 결과, 본 캠페인은 <b>${esc(rp.early_warning_day||"-")}</b>에
        최초 탐지 요건(2개 이상 협력사 동시 감염)을 충족하여, crown-jewel(<b>${esc(rp.crown_jewel||"-")}</b>)
        침해(${esc(rp.hero_peak_day||"-")}) 대비 <b>${lead!=null?lead+"일":"수일"}의 대응 여유</b>를 제공하였다.</p>

        <h3>3. 성능 검증 (독립 정답셋 · 나이브 베이스라인 대조)</h3>
        <div class="eval-grid">
          <div><span>Campaign Recall</span><b>${Math.round((cd.recall ?? 0) * 100)}%</b><small>${cd.true_positive ?? "-"}/${cd.ground_truth ?? "-"} campaigns</small></div>
          <div><span>활성판정 Precision</span><b>${Math.round((ac.precision ?? 0) * 100)}%</b><small>우리 규칙 · FP ${ac.false_positive ?? 0} / F1 ${ac.f1 ?? "-"}</small></div>
          <div><span>Lead Time</span><b>${lt.primary_lead_days ?? "-"}일</b><small>${esc(lt.early_warning_day || "-")} → ${esc(lt.hero_peak_day || "-")}</small></div>
        </div>
        ${ac.naive_baseline ? `<p style="margin-top:10px">
          나이브 탐지('회사 도메인 감염이면 활성')는 함정 <b>${ac.decoy_cases}건</b>(오래된 감염·LOW 전용 크리덴셜)을
          모두 오탐해 정밀도 <b>${Math.round(ac.naive_baseline.precision * 100)}%</b>(오탐 ${ac.naive_baseline.false_positive}건)에 그친다.
          우리 스코어링 규칙(최근 30일 + HIGH 크리덴셜)은 이 오탐을
          <b>${ac.false_positive_reduction_pct}% (${ac.false_positive_reduction}건)</b> 제거하여 정밀도 ${Math.round(ac.precision * 100)}%를 달성한다.
          → 정답셋이 탐지기와 독립이므로 '셀프 채점'이 아니다.</p>` : ""}

        <h3>4. 즉시 조치 대상 협력사</h3>
        <table><thead><tr><th>협력사</th><th>구분</th><th>공급 품목</th><th>위험점수</th><th>신뢰도</th></tr></thead>
          <tbody>${vendorRows}</tbody></table>

        <h3>5. 관측 전술·기법 (MITRE ATT&CK)</h3>
        <table><thead><tr><th>기법 ID</th><th>이름</th><th>관측</th></tr></thead><tbody>${mitreRows}</tbody></table>

        <h3>6. 침해지표 (IOC)</h3>
        <table><thead><tr><th>유형</th><th>지표</th><th>맥락</th></tr></thead><tbody>${iocRows}</tbody></table>

        <h3>7. 판정 규칙</h3>
        <p>${esc(R.meta.decision_rule || "최근 스틸러 감염과 내부망 크리덴셜 노출을 중심으로 활성 침해를 판정")}</p>

        <h3>8. 권고 사항</h3>
        <ul>
          <li>CRITICAL 협력사 대상 유출 계정(VPN·SSO·클라우드·코드저장소) 즉시 초기화 및 세션 강제 만료.</li>
          <li>감염 단말 네트워크 격리·포렌식 확보, 동일 스틸러 IOC 기반 사내 스윕.</li>
          <li>식별된 C2(${primary ? esc(primary.c2_host) : "-"}) 경계 차단 및 소급 접근로그 조사.</li>
          <li>1·2차 협력사 전수 대상 자격증명 노출 모니터링 상시화(조기경보 유지).</li>
        </ul>
        <p style="color:var(--ink-faint);font-size:11px;margin-top:20px">
          ※ 본 브리프의 모든 개체(협력사·행위자·C2)는 합성/가공 데이터이며 실제와 무관하다.</p>
      </div>`;
    $("#brief-body").innerHTML = html;
    retrigger($("#brief-body"));
  }

  function briefPlainText() {
    // 복사용 텍스트(마크다운 유사)
    const t = $("#brief-body").innerText || "";
    return t.replace(/\n{3,}/g, "\n\n");
  }

  // ==========================================================================
  //  IOC · 탐지룰 내보내기
  // ==========================================================================
  function renderIocView() {
    const rows = REPORT.iocs || [];
    $("#ioc-count2").textContent = `${rows.length}건`;
    $("#ioc-tbl2").innerHTML =
      `<tr><th>유형</th><th>지표</th><th>맥락</th><th style="text-align:right">건수</th></tr>` +
      rows.map(r => `<tr><td class="mono">${esc(r.type)}</td>
        <td><span class="id">${esc(r.value)}</span></td><td>${esc(r.context)}</td>
        <td class="cnt">${r.count}</td></tr>`).join("");
  }

  function genExport(kind) {
    const iocs = REPORT.iocs || [];
    const hosts = iocs.filter(i => i.type === "domain" || i.type === "ipv4").map(i => i.value);
    const fams = iocs.filter(i => i.type === "malware_family").map(i => i.value);
    if (kind === "sigma") {
      return `title: 방산 공급망 인포스틸러 C2 통신 탐지
id: scce-${Date.now().toString(16)}
status: experimental
description: SCCE 조기경보에서 식별된 공급망 캠페인 C2/스틸러 지표
logsource:
  category: proxy
detection:
  selection_c2:
    dst_host:
${hosts.map(h => "      - '" + h + "'").join("\n")}
  condition: selection_c2
falsepositives:
  - 정상 CDN 오탐 가능 — 협력사 자산 컨텍스트로 검증
level: high
tags:
${fams.map(f => "  - attack.stealer." + f.toLowerCase()).join("\n")}`;
    }
    if (kind === "blocklist") {
      return "# SCCE C2/exfil 차단 리스트\n# 기준일 " + REPORT.meta.generated_today + "\n" +
        hosts.map(h => h).join("\n");
    }
    if (kind === "stix") {
      const objs = iocs.filter(i => i.type === "domain" || i.type === "ipv4").map((i, n) => ({
        type: "indicator", spec_version: "2.1",
        id: "indicator--scce-" + n,
        created: REPORT.meta.generated_today + "T00:00:00Z",
        name: i.context, pattern_type: "stix",
        pattern: i.type === "ipv4"
          ? `[ipv4-addr:value = '${i.value}']`
          : `[domain-name:value = '${i.value}']`,
        labels: ["malicious-activity"],
      }));
      return JSON.stringify({ type: "bundle", id: "bundle--scce", objects: objs }, null, 2);
    }
    return "";
  }

  function initIocExports() {
    document.querySelectorAll("[data-export]").forEach(btn =>
      btn.addEventListener("click", () => {
        $("#export-pre").textContent = genExport(btn.dataset.export);
        toast(btn.dataset.export.toUpperCase() + " 형식 생성");
      }));
    $("#export-copy").addEventListener("click", () => {
      navigator.clipboard && navigator.clipboard.writeText($("#export-pre").textContent);
      toast("클립보드에 복사됨");
    });
  }

  // ==========================================================================
  //  SOC 워룸 — 멀티에이전트 심의
  // ==========================================================================
  //  SIEM · 보안 이벤트 스트림
  // ==========================================================================
  const siemState = { sev: "all", src: "all", q: "", timer: null, live: false };
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const SRC_KO = { stealer: "스틸러", cred_leak: "유출", c2: "C2", correlation: "상관", early_warning: "조기경보" };

  function siemFiltered() {
    const s = REPORT.siem; if (!s) return [];
    return s.events.filter(e => {
      if (siemState.sev !== "all" && e.severity !== siemState.sev) return false;
      if (siemState.src !== "all" && e.source !== siemState.src) return false;
      if (siemState.q) {
        const hay = (e.message + " " + (e.vendor || "") + " " + (e.rule || "")).toLowerCase();
        if (!hay.includes(siemState.q.toLowerCase())) return false;
      }
      return true;
    });
  }

  function slogHtml(e, entering) {
    const mit = e.mitre && e.mitre.length ? `<span class="mit">${e.mitre.map(esc).join(" ")}</span>` : "";
    return `<div class="slog sev-${e.severity}${entering ? " enter" : ""}">
      <span class="s-ts">${esc(e.ts)}</span>
      <span>${e.rule ? `<span class="s-rule r-${esc(e.rule)}">${esc(e.rule)}</span>` : "<span class='s-rule'>—</span>"}</span>
      <span class="s-vendor">${esc(e.vendor || "—")}</span>
      <span class="s-msg">${esc(e.message)}${mit}</span></div>`;
  }

  function renderSiem() {
    const s = REPORT.siem;
    if (!s) { $("#siem-log").innerHTML = `<div class="detail-empty">SIEM 데이터 없음</div>`; return; }
    const st = s.stats;
    $("#siem-stats").innerHTML = `
      <div class="ss"><div class="l">총 이벤트</div><div class="v">${st.total}</div></div>
      <div class="ss crit"><div class="l">Critical</div><div class="v">${st.by_severity.critical}</div></div>
      <div class="ss high"><div class="l">High</div><div class="v">${st.by_severity.high}</div></div>
      <div class="ss"><div class="l">Medium</div><div class="v">${st.by_severity.medium}</div></div>
      <div class="ss"><div class="l">탐지 룰 발화</div><div class="v">${st.rules_fired.length}</div></div>`;
    $("#siem-window").textContent = st.window;

    // 필터 칩 (최초 1회)
    if (!$("#siem-sev-filters").dataset.built) {
      const sevs = ["all", "critical", "high", "medium"];
      $("#siem-sev-filters").innerHTML = sevs.map(v =>
        `<span class="sfilter${v === "all" ? " on" : ""}" data-sev="${v}">${v === "all" ? "전체" : v}</span>`).join("");
      const srcs = ["all"].concat(Object.keys(st.by_source));
      $("#siem-src-filters").innerHTML = srcs.map(v =>
        `<span class="sfilter${v === "all" ? " on" : ""}" data-src="${v}">${v === "all" ? "모든소스" : (SRC_KO[v] || v)}</span>`).join("");
      $("#siem-sev-filters").addEventListener("click", e => {
        const c = e.target.closest("[data-sev]"); if (!c) return;
        siemState.sev = c.dataset.sev;
        $("#siem-sev-filters").querySelectorAll(".sfilter").forEach(x => x.classList.toggle("on", x === c));
        siemRenderLog();
      });
      $("#siem-src-filters").addEventListener("click", e => {
        const c = e.target.closest("[data-src]"); if (!c) return;
        siemState.src = c.dataset.src;
        $("#siem-src-filters").querySelectorAll(".sfilter").forEach(x => x.classList.toggle("on", x === c));
        siemRenderLog();
      });
      $("#siem-search").addEventListener("input", e => { siemState.q = e.target.value; siemRenderLog(); });
      $("#siem-play").addEventListener("click", siemToggleLive);
      $("#siem-sev-filters").dataset.built = "1";
    }
    siemRenderLog();
  }

  function siemRenderLog() {
    if (siemState.live) return; // 라이브 중엔 정적 렌더 건너뜀
    const rows = siemFiltered().slice().reverse(); // 최신 위로
    $("#siem-count").textContent = `${rows.length}건`;
    $("#siem-log").innerHTML = rows.map(e => slogHtml(e, false)).join("") ||
      `<div class="detail-empty">조건에 맞는 이벤트 없음</div>`;
  }

  function siemToggleLive() {
    if (siemState.live) { siemStopLive(); return; }
    siemState.live = true;
    $("#siem-play").textContent = "⏸ 정지";
    $("#siem-live-dot").classList.remove("off");
    const rows = siemFiltered(); // 오래된→최신
    $("#siem-log").innerHTML = "";
    let i = 0;
    siemState.timer = setInterval(() => {
      if (i >= rows.length) { siemStopLive(); return; }
      $("#siem-log").insertAdjacentHTML("afterbegin", slogHtml(rows[i], true)); // 최신을 위로 prepend
      $("#siem-count").textContent = `${i + 1}건 수신`;
      i++;
    }, 180);
  }
  function siemStopLive() {
    siemState.live = false;
    if (siemState.timer) { clearInterval(siemState.timer); siemState.timer = null; }
    $("#siem-play").textContent = "▶ 라이브 재생";
    siemRenderLog();
  }

  // ---- boot ----------------------------------------------------------------
  const AUTH_KEY = "scce_auth";
  function currentUser() { try { return sessionStorage.getItem(AUTH_KEY); } catch (e) { return null; } }
  function logout() { try { sessionStorage.removeItem(AUTH_KEY); } catch (e) {} location.replace("login.html"); }

  function mountSession(user) {
    const chip = $("#user-chip"), name = $("#user-name"), av = $("#user-av"), out = $("#btn-logout");
    if (!chip) return;
    chip.style.display = "flex"; out.style.display = "inline-block";
    name.textContent = user;
    av.textContent = (user[0] || "A").toUpperCase();
    out.addEventListener("click", logout);
  }

  async function boot() {
    // 인증 게이트: 세션 없으면 로그인 화면으로
    const user = currentUser();
    if (!user) { location.replace("login.html"); return; }
    mountSession(user);

    REPORT = await loadReport();
    if (!REPORT) {
      $("#detail-body").innerHTML = `<div class="detail-empty">report 데이터를 찾을 수 없습니다.<br>
        <code>python pipeline.py</code> 를 먼저 실행하세요.</div>`;
      return;
    }
    const R = REPORT;
    $("#meta-line").textContent = "방산 공급망 자격증명 노출 조기경보";
    $("#meta-line").title = `${R.meta.title} · ${R.meta.problem} · 기준일 ${R.meta.generated_today}`;
    $("#tag-source").textContent = "SOURCE: " + String(R.meta.source).toUpperCase();

    renderKpis(R.kpis);
    renderMission(R);
    initRankToolbar();
    applyRankFilter();
    renderCampaigns(R.campaigns || []);
    renderGraph(R.graph || { nodes: [], edges: [] });
    renderMitre(R.mitre_summary || []);
    renderReplay(R.replay);
    renderForecast(R.forecast);
    const rp = R.replay || {};
    const ew = $("#ew-summary");
    if (ew) {
      ew.innerHTML = rp.lead_days != null
        ? `<div style="font-size:34px;font-weight:720;color:var(--amber);letter-spacing:-.02em">${rp.lead_days}<span style="font-size:15px;color:var(--ink-dim);font-weight:500;margin-left:6px">일 조기 탐지</span></div>
           <p style="font-size:12.5px;color:var(--ink-dim);line-height:1.6;margin:10px 0 0">
           조율된 <b style="color:var(--ink)">${esc(rp.primary_campaign ? rp.primary_campaign.stealer_family : "")}</b> 공급망 캠페인을
           <b style="color:var(--ink)">${esc(rp.early_warning_day || "")}</b>에 탐지 —
           crown-jewel(<b style="color:var(--ink)">${esc(rp.crown_jewel || "")}</b>) 침해
           <b style="color:var(--ink)">${esc(rp.hero_peak_day || "")}</b>보다 앞섰습니다.</p>`
        : `<p style="color:var(--ink-faint)">탐지된 조율 캠페인 없음</p>`;
    }
    $("#foot").innerHTML =
      `SCCE · ${esc(R.meta.problem)} · 합성/공개 데이터 기반 · 회사명·도메인·행위자·C2 전부 가공(fictional) · ` +
      `기준일 ${esc(R.meta.generated_today)}<br>` +
      `<span style="color:var(--ink-faint)">⚠ 관측범위 고지 — SCCE는 다크웹·인포스틸러 채널에 노출된 신호만 봅니다. ` +
      `"NO SIGNAL"은 안전 확인이 아니라 관측된 증거가 없다는 뜻이며, 회사가 공개했는지 여부와 무관하게 ` +
      `공격자 쪽 유통망에 흔적이 나타나지 않은 침해는 탐지되지 않을 수 있습니다.</span>`;

    // 데모: 첫 CRITICAL(=히어로) 자동 선택
    const hero = R.ranked_vendors.find(v => v.status.startsWith("CRITICAL")) || R.ranked_vendors[0];
    if (hero) selectVendor(hero.vendor_id);

    // ---- 멀티뷰 워크스페이스 활성화 ----
    initRouter();
    startClock();
    initSpotlight();
    initCommandPalette();
    buildIncidents();
    const openCnt = incidents.filter(i => {
      const s = incState(i.id).status; return s === "NEW" || s === "INVESTIGATING";
    }).length;
    $("#nav-triage-badge").textContent = openCnt ? String(openCnt) : "";

    views.siem = renderSiem;
    views.triage = renderTriage;
    views.investigate = renderInvestigate;
    views.brief = () => { renderBrief(); renderIocView(); };

    $("#brief-copy").addEventListener("click", () => {
      navigator.clipboard && navigator.clipboard.writeText(briefPlainText()); toast("브리프 복사됨");
    });
    $("#brief-print").addEventListener("click", () => window.print());
    initIocExports();
    setInterval(updateSlaClocks, 1000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
