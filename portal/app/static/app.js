/* VOC Portal SPA — professional SOC frontend */
const $ = (s, el=document) => el.querySelector(s);
const $$ = (s, el=document) => [...el.querySelectorAll(s)];
const SEV = { critical:'critical', high:'high', medium:'medium', low:'low' };
const SEV_COLOR = { critical:'#ff4d5e', high:'#ff9f43', medium:'#f5d34a', low:'#3ddc84' };

let TOKEN = localStorage.getItem('voc_token') || '';
let ME = null;
function hasCap(cap) { return !!(ME && ME.caps && ME.caps.includes(cap)); }
function roleLabel(r) {
  return ({ admin:'Admin', voc:'VOC Ops', soc3:'SOC L3 · Senior', soc2:'SOC L2', soc1:'SOC L1 · Junior', noc:'NOC' })[r] || ((r||'').replace('_',' ').toUpperCase() || '?');
}
const ROLE_TIER = { admin:'critical', voc:'high', soc3:'high', soc2:'medium', soc1:'medium', noc:'low' };
let HEALTH = {};
let dashTimer = null, healthTimer = null, clockTimer = null;
let ALL_TICKETS = [];
let MY_TICKETS = [];
let RECENT_TICKETS = [];
const state = { q:'', sev:'all', st:'all' };

/* ---------------- API ---------------- */
async function api(path, opts={}) {
  const headers = { 'Content-Type':'application/json', ...(opts.headers||{}) };
  if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401) { logout(); throw new Error('Session expired — sign in again'); }
  const data = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error(data.detail || data.error || r.statusText);
  return data;
}

/* ---------------- toast ---------------- */
function toast(msg, type='info', ms=4200) {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(()=>t.remove(), 320); }, ms);
}

/* ---------------- modal ---------------- */
function openModal(html) {
  $('#modal-card').innerHTML = html;
  $('#modal').classList.remove('hidden');
  $$('#modal [data-close]').forEach(el => el.addEventListener('click', closeModal));
}
function closeModal() { $('#modal').classList.add('hidden'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

/* ---------------- auth ---------------- */
function logout() {
  localStorage.removeItem('voc_token'); TOKEN=''; ME=null;
  ['dashboard','clock','status-dots','kpis','trend-chart','sev-chart','blast','topcves','prediction','recent','mytickets-body','tickets-body','users-body'].forEach(id=>{ const el=$('#'+id); if(el) el.innerHTML=''; });
  $('#login-view').classList.remove('hidden');
  $('#app-view').classList.add('hidden');
  [dashTimer, healthTimer, clockTimer].forEach(t=>clearInterval(t));
}

$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('#login-err').textContent = '';
  try {
    const res = await api('/api/login', { method:'POST', body: JSON.stringify({ username:$('#login-user').value.trim(), password:$('#login-pass').value }) });
    TOKEN = res.token; localStorage.setItem('voc_token', TOKEN); ME = res.user;
    ME = await api('/api/me');
    enterApp();
  } catch (err) { $('#login-err').textContent = err.message; }
});

function enterApp() {
  $('#login-view').classList.add('hidden');
  $('#app-view').classList.remove('hidden');
  $('#whoami').textContent = ME.username;
  $('#role-tag').textContent = roleLabel(ME.role);
  $('#avatar').textContent = (ME.username[0]||'?').toUpperCase();
  $$('.cap-btn').forEach(el => el.classList.toggle('hidden', !hasCap(el.dataset.cap)));
  if ($('#btn-sync')) $('#btn-sync').classList.toggle('hidden', !hasCap('tickets.import'));
  if ($('#btn-new')) $('#btn-new').classList.toggle('hidden', !hasCap('tickets.create'));
  if ($('#services-btn')) $('#services-btn').classList.toggle('hidden', !hasCap('services.view'));
  switchTab('dashboard');
  startClock();
  loadServices();
  refreshHealth();
  healthTimer = setInterval(refreshHealth, 30000);
  if (dashTimer) clearInterval(dashTimer);
  dashTimer = setInterval(() => { if (ME && activeTab==='dashboard') loadDashboard(); }, 30000);
}

$('#logout').addEventListener('click', logout);
$('#services-btn').addEventListener('click', e => { e.stopPropagation(); $('#services-menu').classList.toggle('hidden'); });
document.addEventListener('click', e => { if (!$('#services-menu').contains(e.target)) $('#services-menu').classList.add('hidden'); });
$$('#tabs button').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));

let activeTab = 'dashboard';
function switchTab(tab) {
  activeTab = tab;
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.tab').forEach(s => s.classList.toggle('hidden', s.id !== 'tab-' + tab));
  $('#page-title').textContent = ({ dashboard:'SOC Overview', vulns:'Vulnerabilities', mytickets:'My Tickets', threatintel:'Threat Intel', infra:'Infrastructure', tickets:'All Tickets', users:'Team & Access', services:'Tools Hub', attack:'MITRE ATT&CK', account:'My Account', assets:'Asset Inventory', audit:'Audit Trail', roles:'Rôles & Permissions', dashboards:'Dashboards', endpoints:'Endpoint Activity', hostintel:'Host Intel' })[tab];
  if (tab === 'dashboard') loadDashboard();
  if (tab === 'vulns') loadVulns();
  if (tab === 'mytickets') loadTickets('mine');
  if (tab === 'threatintel') loadThreatIntel();
  if (tab === 'infra') loadInfra();
  if (tab === 'tickets') loadTickets('all');
  if (tab === 'users') loadUsers();
  if (tab === 'users' || tab === 'roles') refreshRoleOptions();
  if (tab === 'attack') loadAttack();
  if (tab === 'account') loadAccount();
  if (tab === 'assets') loadAssets();
  if (tab === 'audit') loadAudit();
  if (tab === 'roles') loadRoles();
  if (tab === 'endpoints') loadEndpoints();
  if (tab === 'hostintel') loadHostIntel();
  if (tab === 'services') loadToolsHub();
  if (tab === 'dashboards') loadDashboardsTab();
}

/* ---------------- clock & health ---------------- */
function startClock() {
  const tick = () => $('#clock').textContent = new Date().toLocaleTimeString('en-GB');
  tick(); clockTimer = setInterval(tick, 1000);
}
async function refreshHealth() {
  try {
    HEALTH = await api('/api/health');
    const map = { up:'up', down:'down', green:'up', yellow:'warn', red:'down' };
    $('#status-dots').innerHTML = Object.entries(HEALTH).map(([k,v]) =>
      `<span class="dot ${map[v]||'unknown'}" title="${k}: ${v}"><span>${k}</span></span>`).join('');
    $('#status-dots').onclick = () => switchTab('services');
  } catch (e) {}
}

/* ---------------- SVG charts ---------------- */
function skel() {
  return `<div class="skel skel-block"></div><div style="height:10px"></div>
    <div class="skel skel-line" style="width:80%"></div><div style="height:8px"></div>
    <div class="skel skel-line" style="width:60%"></div>`;
}
function svg(w, h, inner) {
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">${inner}</svg>`;
}

function donutChart(items) {
  const W = 200, H = 200, C = 90, R = 62, total = items.reduce((s,i)=>s+i[1],0);
  if (!total) return `<div class="empty">No data</div>`;
  let acc = 0;
  const segs = items.map(([k,v]) => {
    const a0 = acc, a1 = acc + v / total * 360; acc = a1;
    const large = (a1 - a0) > 180 ? 1 : 0;
    const x0 = C + R * Math.cos(a0 * Math.PI/180), y0 = C + R * Math.sin(a0 * Math.PI/180);
    const x1 = C + R * Math.cos(a1 * Math.PI/180), y1 = C + R * Math.sin(a1 * Math.PI/180);
    const col = SEV_COLOR[k.toLowerCase()] || '#4f8cff';
    return `<path d="M${C} ${C} L${x0.toFixed(1)} ${y0.toFixed(1)} A${R} ${R} 0 ${large} 1 ${x1.toFixed(1)} ${y1.toFixed(1)} Z" fill="${col}" opacity=".92"><title>${k}: ${v}</title></path>`;
  }).join('');
  return `<div style="display:flex;gap:16px;align-items:center;height:100%">
    <svg viewBox="0 0 200 200" style="width:170px;flex-shrink:0">
      ${segs}
      <circle cx="${C}" cy="${C}" r="${R-18}" fill="var(--panel)"/>
      <text x="${C}" y="${C+2}" class="donut-center">${total}</text>
      <text x="${C}" y="${C+18}" class="donut-sub">findings</text>
    </svg>
    <div style="display:flex;flex-direction:column;gap:6px;min-width:0">
      ${items.map(([k,v]) => `<div style="display:flex;justify-content:space-between;gap:8px;font-size:12px">
        <span style="color:var(--muted)"><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${SEV_COLOR[k.toLowerCase()]||'#4f8cff'};margin-right:6px"></i>${k}</span>
        <b>${v}</b></div>`).join('')}
    </div></div>`;
}

function lineChart(rows) {
  const W = 700, H = 210, P = { l:34, r:12, t:12, b:26 };
  const dates = rows.map(r => r.date.slice(5));
  const max = Math.max(1, ...rows.map(r => Math.max(r.critical, r.high)));
  const iw = W - P.l - P.r, ih = H - P.t - P.b;
  const x = i => P.l + (dates.length <= 1 ? 0 : i * iw / (dates.length - 1));
  const y = v => P.t + ih - (v / max) * ih;
  const path = (field) => rows.map((r,i) => `${i?'L':'M'}${x(i).toFixed(1)} ${y(r[field]).toFixed(1)}`).join(' ');
  const area = rows.map((r,i) => `${i?'L':'M'}${x(i).toFixed(1)} ${y(r.critical).toFixed(1)}`).join(' ') + ` L${x(rows.length-1)} ${P.t+ih} L${x(0)} ${P.t+ih} Z`;
  const yTicks = Array.from({length:4}, (_,i) => Math.round(max * i / 3));
  return svg(W, H, `
    ${yTicks.map(t => `<line x1="${P.l}" y1="${y(t)}" x2="${W-P.r}" y2="${y(t)}" stroke="rgba(139,155,184,.14)" stroke-dasharray="3 3"/>
      <text x="${P.l-6}" y="${y(t)+3}" text-anchor="end" class="axis">${t}</text>`).join('')}
    <path d="${area}" fill="rgba(79,140,255,.12)" stroke="none"/>
    <path d="${path('critical')}" fill="none" stroke="${SEV_COLOR.critical}" stroke-width="2"/>
    <path d="${path('high')}" fill="none" stroke="${SEV_COLOR.high}" stroke-width="2"/>
    ${dates.map((d,i) => i % Math.max(1, Math.floor(dates.length/7)) === 0 ? `<text x="${x(i)}" y="${H-P.b+16}" text-anchor="middle" class="axis">${d}</text>` : '').join('')}
  `);
}

function sparkline(arr, color) {
  if (!arr || !arr.length) return '';
  const W = 110, H = 34;
  const max = Math.max(1, ...arr), min = 0;
  const x = i => i * (W-4) / (arr.length - 1 || 1) + 2;
  const y = v => H - 4 - (v - min) / (max - min) * (H - 8);
  const d = arr.map((v,i) => `${i?'L':'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
  return svg(W, H, `<path d="${d}" fill="none" stroke="${color}" stroke-width="1.8"/>`);
}

/* ---------------- dashboard ---------------- */
const SLA_ROW_CLS = { eligible:'low', high:'high', critical:'critical' };
function slaRow(label, n, cls) {
  return `<div class="row"><span class="grow">${label}</span><span class="badge ${SLA_ROW_CLS[cls]||''}">${n ?? 0}</span></div>`;
}
/* stacked area: critical over high over medium */
function stackedTrendChart(rows) {
  if (!rows.length) return '<div class="empty">No data</div>';
  const W = 600, H = 190, P = 6;
  const max = Math.max(1, ...rows.map(r => (r.critical||0)+(r.high||0)+(r.medium||0)));
  let paths = { critical:'', high:'', medium:'' };
  rows.forEach((r, i) => {
    const x = P + i * ((W - 2*P) / Math.max(rows.length - 1, 1));
    const m = H - P - ((r.medium||0) / max) * (H - 2*P);
    const mh = m - ((r.high||0) / max) * (H - 2*P);
    const hc = mh - ((r.critical||0) / max) * (H - 2*P);
    paths.medium += `${i?'L':'M'}${x.toFixed(1)},${H-P} `;
    paths.medium += `L${x.toFixed(1)},${m.toFixed(1)} `;
    paths.high += `${i?'L':'M'}${x.toFixed(1)},${m.toFixed(1)} `;
    paths.high += `L${x.toFixed(1)},${mh.toFixed(1)} `;
    paths.critical += `${i?'L':'M'}${x.toFixed(1)},${mh.toFixed(1)} `;
    paths.critical += `L${x.toFixed(1)},${Math.max(hc, P).toFixed(1)} `;
  });
  const close = ` L${(W-P).toFixed(1)},${H-P} Z`;
  return svg(W, H, `
    <path d="${paths.medium}${close}" fill="rgba(245,211,74,.25)" />
    <path d="${paths.high}${close}" fill="rgba(255,159,67,.3)" />
    <path d="${paths.critical}${close}" fill="rgba(255,77,94,.35)" />`);
}

async function loadDashboard() {
  const wrap = (html, err) => err ? `<div class="empty">${err}</div>` : html;
  try {
    ['kpis','trend-chart','sev-chart','blast','topcves','prediction','recent'].forEach(id => { const el=$('#'+id); if (el) el.innerHTML = id==='kpis' ? '<div class="skel skel-line"></div>' : skel(); });
    const d = await api('/api/dashboard');
    const v = d.vulns || {};
    const t = d.tickets || {};
    const trend = d.trend || [];
    const criticalSeries = trend.map(r => r.critical), highSeries = trend.map(r => r.high);
    const critToday = criticalSeries[criticalSeries.length-1] || 0;
    const critBefore = criticalSeries[criticalSeries.length-2] || 0;

    const sla = d.sla || {};
    const confSeries = trend.map(r => r.total ? Math.round(((r.confirmed||0)/r.total)*100) : 0);
    $('#kpis').innerHTML = [
      { l:'Critical findings', v:v.critical ?? '–', d: sparkline(criticalSeries, SEV_COLOR.critical), c:'crit', open:'findings' },
      { l:'Confirmed by scanner', v:d.vulns?.confirmed ?? '–', d:'NSE active checks', c:'crit', open:'findings-confirmed' },
      { l:'KEV exploited', v:d.kev?.count ?? 0, d:'CISA actively exploited', c:'crit', open:'findings-kev' },
      { l:'Internet-exposed', v:d.exposure?.internet_exposed_vulns ?? 0, d:`${d.exposure?.with_public_exploit ?? 0} w/ public exploit`, c:'high', open:'findings' },
      { l:'SLA compliance', v:(sla.sla_compliance_pct ?? '–')+'%', d:`${sla.overdue||0} overdue · ${sla.due_within_24h||0} due <24h`, c: (sla.sla_compliance_pct??100)>=90?'low':'high', open:'tickets-open' },
      { l:'Avg MTTR', v: sla.avg_remediation_hours!=null ? sla.avg_remediation_hours+'h' : '–', d:`${sla.breached_total||0} SLA breached`, c:'fg', open:'tickets-solved' },
      { l:'Open tickets', v:t.open ?? '–', d:`${t.queue||0} unassigned queue`, c:'fg', open:'tickets-open' },
      { l:'Assets inventoried', v:d.assets_total ?? '–', d:(d.critical_assets||[]).length+' critical assets', c:'fg', open:'blast' },
    ].map(k => `<div class="kpi clickable" data-open="${k.open}"><div class="l">${k.l}</div><div class="v" style="color:var(--${k.c})">${k.v}</div><div class="d">${k.d}</div></div>`).join('');
    $$('#kpis .kpi').forEach(el => el.addEventListener('click', () => kpiDrill(el.dataset.open, d)));

    $('#trend-chart').innerHTML = trend.length ? stackedTrendChart(trend) : '<div class="empty">No trend data yet</div>';
    // confidence split
    const cf = d.confidence || {};
    $('#conf-chart').innerHTML = (cf.confirmed || cf.potential) ? donutChart([
        ['confirmed', cf.confirmed || 0], ['potential', cf.potential || 0]]) : '<div class="empty">No scan data yet</div>';
    // SLA posture panel
    $('#sla-panel').innerHTML = `
      ${slaRow('On track', sla.open_tickets - (sla.overdue||0) - (sla.due_within_24h||0), 'eligible')}
      ${slaRow('Due <24h', sla.due_within_24h||0, 'high')}
      ${slaRow('Overdue', sla.overdue||0, 'critical')}
      ${slaRow('Breached (resolved late)', sla.breached_total||0, 'critical')}
      <div class="row" style="margin-top:8px"><span class="grow m">Compliance</span><b>${sla.sla_compliance_pct ?? '–'}%</b></div>
      <div class="bar" style="width:100%"><i style="width:${sla.sla_compliance_pct ?? 0}%"></i></div>`;
    // live activity feed (admins)
    if (hasCap('audit.view')) {
      api('/api/audit?limit=10').then(rows => {
        $('#activity').innerHTML = rows.length ? rows.map(a =>
          `<div class="row" title="${(a.detail||'').replace(/"/g,'&quot;')}"><span class="grow" style="font-size:12px"><code>${a.action}</code> ${(a.detail||'').slice(0,40)}</span><span class="m" style="font-size:10.5px">${(a.at||'').slice(11,16)}</span></div>`).join('')
          : '<div class="empty">No events yet</div>';
      }).catch(() => { $('#activity').innerHTML = '<div class="empty">—</div>'; });
    } else $('#activity').innerHTML = '<div class="empty">audit.view required</div>';
    $('#trend-chart').onclick = () => trendModal(trend);
    $('#trend-chart').classList.add('clickable');
    $('#sev-chart').innerHTML = (d.severity_dist||[]).length ? donutChart(d.severity_dist) : '<div class="empty">No data</div>';
    $('#sev-chart').onclick = () => findingsModal(d);
    $('#sev-chart').classList.add('clickable');

    $('#blast').innerHTML = (d.critical_assets||[]).map(n =>
      `<div class="row clickable" data-asset="${n.host}"><span class="grow"><b>${n.host}</b> ${n.critical?'<span class="badge critical">CRIT</span>':''}</span><span class="m">risk ${n.risk} · blast ${n.blast}</span>
       <div class="bar" style="width:100%"><i style="width:${Math.min(100, n.blast*10)}%"></i></div></div>`).join('') || '<div class="empty">No graph data yet</div>';
    $$('#blast .row[data-asset]').forEach(r => r.addEventListener('click', () => assetModal(r.dataset.asset, d)));

    $('#topcves').innerHTML = (d.top_cves||[]).map(t =>
      `<div class="row clickable" data-cve="${t.cve}"><span class="grow cve-cell"><b>${t.cve}</b></span><span class="m">risk ${t.risk}</span>
       <div class="bar" style="width:100%"><i style="width:${Math.min(100, t.risk*10)}%"></i></div></div>`).join('') || '<div class="empty">No vulnerabilities indexed</div>';
    $$('#topcves .row[data-cve]').forEach(r => r.addEventListener('click', () => cveModal(r.dataset.cve)));

    const p = d.prediction;
    $('#prediction').innerHTML = p ? p.top10.slice(0,5).map((t,i) =>
      `<div class="row clickable" data-pred="${i}"><span class="grow"><b>${i+1}.</b> <span class="cve-cell">${t.cve}</span> ${t.in_kev?'<span class="badge kev">KEV</span>':''}</span><span class="m">${(t.score*100).toFixed(0)}%</span></div>`).join('')
      : '<div class="empty">Next forecast: Sunday 06:00</div>';
    $$('#prediction .row[data-pred]').forEach(r => r.addEventListener('click', () => predictionModal(p)));

    $('#recent').innerHTML = (t.recent||[]).length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Sev</th><th>Title</th><th>Status</th><th>Assignee</th><th>Est.</th></tr></thead><tbody>
      ${t.recent.map(x => `<tr data-id="${x.id}"><td><b>#${x.id}</b></td><td><span class="badge ${SEV[x.severity]}">${x.severity}</span></td>
        <td><span class="grow">${x.title}</span></td><td><span class="badge ${x.status}">${x.status.replace('_',' ')}</span></td>
        <td>${x.assignee?x.assignee.username:'—'}</td><td>${x.est_hours!=null?x.est_hours+'h':'—'}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No tickets yet — click <b>Import auto tickets</b> or create one</div>';
    RECENT_TICKETS = t.recent || [];
    $$('#recent tbody tr').forEach(tr => tr.addEventListener('click', () => ticketModal(+tr.dataset.id)));

    $('#attack-mix').innerHTML = (d.attack||[]).length
      ? `<div style="display:flex;flex-wrap:wrap;gap:8px">
          ${d.attack.map(a => `<button class="tech-chip" data-tac="${a.tactic}" style="--tc:${TACTIC_COLOR[a.tactic]||'#4f8cff'}">
            <b class="mono">${a.id}</b> <span class="m">${a.name}</span> <b>${a.c}</b></button>`).join('')}
        </div>`
      : '<div class="empty">No open tickets mapped to techniques yet</div>';
    $$('#attack-mix .tech-chip').forEach(ch => ch.addEventListener('click', () => switchTab('attack')));
  } catch (e) { console.error(e); }
}

/* ---------------- dashboard drill-downs ---------------- */
async function ticketsBy(fn) {
  let list = ALL_TICKETS.length ? ALL_TICKETS : (MY_TICKETS.length ? MY_TICKETS : null);
  if (!list && hasCap('tickets.view_all')) { try { list = await api('/api/tickets?scope=all'); ALL_TICKETS = list; } catch (e) {} }
  else if (!list) { try { list = await api('/api/tickets?scope=mine'); MY_TICKETS = list; } catch (e) {} }
  return (list || []).filter(fn);
}

function detailModal(title, inner, opts={}) {
  openModal(`
    <div class="modal-head"><h3>${title}</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body">${inner}
      <div style="display:flex;gap:8px;margin-top:16px">${opts.footer || '<button class="btn-ghost" id="modal-close" style="flex:1">Close</button>'}</div>
    </div>`);
  if (opts.footer) opts.footerInit && opts.footerInit();
  else $('#modal-close').addEventListener('click', closeModal);
}

function ticketTableHtml(list) {
  if (!list.length) return '<div class="empty">No matching tickets</div>';
  return `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>#</th><th>Sev</th><th>Title</th><th>Status</th><th>Assignee</th></tr></thead><tbody>
    ${list.slice(0,12).map(x => `<tr data-id="${x.id}"><td><b>#${x.id}</b></td><td><span class="badge ${SEV[x.severity]}">${x.severity}</span></td>
      <td>${x.title}</td><td><span class="badge ${x.status}">${x.status.replace('_',' ')}</span></td><td>${x.assignee?x.assignee.username:'—'}</td></tr>`).join('')}
  </tbody></table></div>`;
}
function wireTicketTable() { $$('#modal tbody tr[data-id]').forEach(tr => tr.addEventListener('click', () => { closeModal(); ticketModal(+tr.dataset.id); })); }

function kpiDrill(what, d) {
  if (what === 'findings') return findingsModal(d);
  if (what === 'tickets-open') return ticketsListModal(d, 'open');
  if (what === 'tickets-solved') return ticketsListModal(d, 'solved');
  if (what === 'blast') return assetModal(null, d);
}

function findingsModal(d) {
  const dist = d.severity_dist || [];
  const top = d.top_cves || [];
  const sevCol = { critical:'#ff4d5e', high:'#ff9f43', medium:'#f5d34a', low:'#3ddc84' };
  detailModal('Vulnerability findings', `
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
      <span class="stat-chip">Total <b>${d.vulns?.total ?? '—'}</b></span>
      <span class="stat-chip"><i class="dot" style="background:#ff4d5e"></i> Critical <b>${d.vulns?.critical ?? '—'}</b></span>
      <span class="stat-chip"><i class="dot" style="background:#ff9f43"></i> High <b>${d.vulns?.high ?? '—'}</b></span>
    </div>
    <div class="table-wrap"><table class="no-row-click"><thead><tr><th>Severity</th><th>Findings</th><th>Share</th></tr></thead><tbody>
      ${dist.map(([k,v]) => `<tr><td><span class="badge ${SEV[k.toLowerCase()]||'medium'}">${k}</span></td><td><b>${v}</b></td>
        <td><div class="bar" style="width:100%;min-width:120px"><i style="width:${Math.round(100*v/(d.vulns?.total||1))}%;background:${sevCol[k.toLowerCase()]||'#4f8cff'}"></i></div></td></tr>`).join('')}
    </tbody></table></div>
    <div style="font-size:12px;color:var(--muted);margin:14px 0 6px">Top CVEs by risk</div>
    <div>${top.map(t => `<div class="row clickable" data-cve="${t.cve}" style="margin-bottom:6px"><span class="grow cve-cell"><b>${t.cve}</b></span><span class="m">risk ${t.risk}</span></div>`).join('')}</div>`);
  $$('#modal .row[data-cve]').forEach(r => r.addEventListener('click', () => { closeModal(); cveModal(r.dataset.cve); }));
}

function trendModal(trend) {
  const total = trend.reduce((s,r)=>s+r.total,0);
  detailModal('Vulnerability trend · 14 days', `
    <div class="chart" style="height:200px;margin-bottom:14px">${lineChart(trend)}</div>
    <div class="table-wrap"><table class="no-row-click"><thead><tr><th>Date</th><th>Critical</th><th>High</th><th>Total</th></tr></thead><tbody>
      ${trend.slice().reverse().map(r => `<tr><td class="mono">${r.date}</td><td><b style="color:var(--crit)">${r.critical}</b></td><td><b style="color:var(--high)">${r.high}</b></td><td>${r.total}</td></tr>`).join('')}
    </tbody></table></div>`);
}

async function ticketsListModal(d, status) {
  const list = await ticketsBy(x => status === 'open' ? x.status !== 'solved' : x.status === 'solved');
  detailModal(status==='open' ? `Open tickets (${d.tickets?.open || list.length})` : `Solved tickets (${d.tickets?.solved || list.length})`,
    ticketTableHtml(list) + (hasCap('tickets.view_all') && list.length ? '<div style="font-size:11.5px;color:var(--muted);margin-top:6px">Full list in <b>All Tickets</b> with filters</div>' : ''));
  wireTicketTable();
}

async function assetModal(host, d) {
  const assets = d.critical_assets || [];
  const list = host ? await ticketsBy(x => x.host === host) : null;
  const inner = host ? (() => {
    const a = assets.find(x => x.host === host) || {};
    return `<div class="detail-grid" style="grid-template-columns:1fr 1fr">
        <div class="detail"><div class="k">Host</div><div class="val mono">${host}</div></div>
        <div class="detail"><div class="k">Risk score</div><div class="val">${a.risk ?? '—'}</div></div>
        <div class="detail"><div class="k">Blast radius</div><div class="val">${a.blast ?? '—'}</div></div>
        <div class="detail"><div class="k">Critical</div><div class="val">${a.critical ? 'Yes' : 'No'}</div></div>
      </div>
      <div style="font-size:12px;color:var(--muted);margin:12px 0 6px">Tickets on this host</div>
      ${ticketTableHtml(list || [])}`;
  })() : `
    <div>${assets.map(a => `<div class="row clickable" data-asset="${a.host}" style="margin-bottom:6px"><span class="grow"><b>${a.host}</b> ${a.critical?'<span class="badge critical">CRIT</span>':''}</span><span class="m">risk ${a.risk} · blast ${a.blast}</span></div>`).join('')}</div>`;
  detailModal(host ? `Asset — ${host}` : 'Critical assets · blast radius', inner, host ? {} : {});
  if (!host) $$('#modal .row[data-asset]').forEach(r => r.addEventListener('click', () => { closeModal(); assetModal(r.dataset.asset, d); }));
  else wireTicketTable();
}

async function cveModal(cve) {
  const list = await ticketsBy(x => x.cve === cve);
  detailModal(`CVE — <span class="mono">${cve}</span>`, `
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <span class="stat-chip">Affected hosts <b>${new Set(list.map(t=>t.host).filter(Boolean)).size}</b></span>
      <span class="stat-chip">Tickets <b>${list.length}</b></span>
      <span class="stat-chip">Open <b>${list.filter(t=>t.status!=='solved').length}</b></span>
    </div>
    ${ticketTableHtml(list)}
    ${!list.length ? '<div class="empty">No portal tickets reference this CVE (scanner data only)</div>' : ''}`);
  wireTicketTable();
}

function predictionModal(p) {
  detailModal(`Exploitation forecast — ${(p.date||'').slice(0,10)}`, `
    <div style="font-size:12px;color:var(--muted);margin-bottom:10px">Ranked by predicted exploitation likelihood (self-validated weekly). Click a row to see related tickets.</div>
    <div class="table-wrap"><table class="no-row-click"><thead><tr><th>#</th><th>CVE</th><th>Score</th><th>EPSS</th><th>KEV</th></tr></thead><tbody>
      ${p.top10.map((t,i) => `<tr data-cve="${t.cve}" class="clickable"><td>${i+1}</td><td class="cve-cell"><b>${t.cve}</b></td>
        <td><b>${(t.score*100).toFixed(0)}%</b></td><td class="mono">${(t.epss*100).toFixed(1)}%</td>
        <td>${t.in_kev?'<span class="badge kev">in KEV</span>':'<span class="badge">—</span>'}</td></tr>`).join('')}
    </tbody></table></div>`);
  $$('#modal tr[data-cve]').forEach(tr => tr.addEventListener('click', async () => { closeModal(); await cveModal(tr.dataset.cve); }));
}

/* ---------------- tickets ---------------- */
let scopeCache = 'mine';
const SLA_CLASS = { on_track:'', due_soon:'high', overdue:'critical', completed:'', breached:'critical' };
function slaCell(t) {
  if (!t.sla_deadline) return '<span class="m">—</span>';
  const st = (t.sla_status || '').toLowerCase();
  const rem = t.remaining_hours;
  const sub = t.status === 'solved'
    ? ((t.resolved_by === 'scanner') ? '<span class="badge solved">scanner-verified</span>'
       : t.resolved_by === 'admin_override' ? '<span class="badge blocked">override</span>' : '')
    : (rem != null ? `${rem < 0 ? '+' : ''}${rem.toFixed(0)}h left` : '');
  return `<span class="badge ${SLA_CLASS[st]||''}" title="deadline ${t.sla_deadline}">${(st||'—').toUpperCase()}</span><div class="sub">${sub}</div>`;
}
function ticketRow(t) {
  const mine = ME && t.assignee && t.assignee.id === ME.id;
  let actions = '';
  if (mine && t.status === 'assigned') actions += `<button class="small primary" data-start="${t.id}" title="Start working">▶ Start</button> `;
  if (mine && t.status === 'in_progress') actions += `<button class="small primary" data-solve="${t.id}" title="Record remediation - a verification scan will confirm it">✓ Remediated</button> `;
  if (hasCap('tickets.assign') && !t.assignee && t.status !== 'remediated') actions += `<button class="small" data-assign="${t.id}">Assign</button> `;
  if (hasCap('tickets.reopen') && (t.status === 'solved')) actions += `<button class="small" data-reopen="${t.id}">Reopen</button> `;
  if (hasCap('tickets.verify_force') && ['in_progress','remediated','reopened'].includes(t.status)) actions += `<button class="small" data-closeforce="${t.id}" title="Override closure without scanner verification (audited)">Force close</button> `;
  const statusLabel = { remediated:'remediated · verifying', rescan_pending:'rescan pending', reopened:'REOPENED' }[t.status] || t.status.replace('_',' ');
  return `<tr data-id="${t.id}">
    <td><b>#${t.id}</b><div class="sub">${t.source}</div></td>
    <td><span class="badge ${SEV[t.severity]}">${t.severity}</span></td>
    <td class="grow">${t.title}<div class="sub">${t.cve||''} ${t.host? '· <span class="mono">'+t.host+'</span>':''}${t.hostname? ` · 🖥 ${t.hostname}`:''}${t.risk_score!=null? ' · risk '+t.risk_score:''}</div></td>
    <td><span class="badge ${t.status}">${statusLabel}</span></td>
    <td>${slaCell(t)}</td>
    <td>${t.assignee ? t.assignee.username + (t.assignee_rate!=null?` <span class="sub">${(t.assignee_rate*100).toFixed(0)}%</span>`:'') : '<span class="m">—</span>'}</td>
    <td>${t.est_hours!=null ? '<b>'+t.est_hours+'h</b>' : '—'}</td>
    <td style="white-space:nowrap">${actions||''}</td>
  </tr>`;
}

function filteredTickets(list) {
  const q = state.q.toLowerCase();
  return list.filter(t =>
    (state.sev === 'all' || t.severity === state.sev) &&
    (state.st === 'all' || t.status === state.st) &&
    (!q || (t.title+' '+ (t.cve||'') +' '+ (t.host||'') +' '+(t.assignee?t.assignee.username:'')).toLowerCase().includes(q)));
}

async function loadTickets(scope) {
  scopeCache = scope;
  const target = scope === 'mine' ? '#mytickets-body' : '#tickets-body';
  $(target).innerHTML = skel();
  try {
    const ts = await api('/api/tickets?scope=' + scope);
    if (scope === 'all') ALL_TICKETS = ts;
    if (scope === 'mine') MY_TICKETS = ts;
    renderTickets(scope);
  } catch (e) { $(target).innerHTML = `<div class="empty">${e.message}</div>`; }
}

function renderTickets(scope) {
  const target = scope === 'mine' ? '#mytickets-body' : '#tickets-body';
  const list = scope === 'all' ? filteredTickets(ALL_TICKETS) : filteredTickets(MY_TICKETS);
  const cnt = $('#filterbar-count');
  if (cnt) cnt.textContent = `${list.length} shown`;
  $(target).innerHTML = list.length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Sev</th><th>Title</th><th>Status</th><th>SLA</th><th>Assignee</th><th>Est.</th><th></th></tr></thead><tbody>
    ${list.map(ticketRow).join('')}</tbody></table></div>` : '<div class="empty">No tickets match</div>';
  $$(`${target} tbody tr`).forEach(tr => tr.addEventListener('click', e => { if (!e.target.closest('button')) ticketModal(+tr.dataset.id); }));
  wireTicketButtons(scope);
}

function wireTicketButtons(scope) {
  $$('#tickets-body button, #mytickets-body button').forEach(b => {
    b.onclick = async e => {
      e.stopPropagation();
      const id = b.dataset.start || b.dataset.solve || b.dataset.assign || b.dataset.reopen;
      try {
        if (b.dataset.start) { await api(`/api/tickets/${id}/start`, {method:'POST', body:'{}'}); toast(`Ticket #${id} started`, 'ok'); }
        if (b.dataset.solve) {
          const r = await api(`/api/tickets/${id}/solve`, {method:'POST', body:'{}'});
          toast(r.message || `Ticket #${id} remediated - verification scan scheduled`, 'info', 7000);
          const n = (r.auto_assigned||[]).filter(Boolean).length;
          if (n) toast(`${n} queued ticket(s) auto-assigned`, 'info');
        }
        if (b.dataset.closeforce) {
          const reason = prompt('Override closure reason (audited):');
          if (!reason) return;
          await api(`/api/tickets/${id}/close`, {method:'POST', body: JSON.stringify({reason})});
          toast(`Ticket #${id} closed by override (audited)`, 'ok');
        }
        if (b.dataset.reopen) { await api(`/api/tickets/${id}/reopen`, {method:'POST', body:'{}'}); toast(`Ticket #${id} reopened`, 'info'); }
        if (b.dataset.assign) {
          const t = ALL_TICKETS.find(x => x.id === id) || MY_TICKETS.find(x => x.id === id);
          assignModal(t || { id });
        }
        await loadTickets(scope);
        if (activeTab === 'dashboard') loadDashboard();
      } catch (e) { toast(e.message, 'err'); }
    };
  });
}

$('#filter-q').addEventListener('input', e => { state.q = e.target.value; if (scopeCache==='all') renderTickets('all'); });
$$('#filter-sev .pill').forEach(p => p.addEventListener('click', () => {
  $$('#filter-sev .pill').forEach(x => x.classList.remove('active')); p.classList.add('active');
  state.sev = p.dataset.sev; if (scopeCache==='all') renderTickets('all');
}));
$$('#filter-status .pill').forEach(p => p.addEventListener('click', () => {
  $$('#filter-status .pill').forEach(x => x.classList.remove('active')); p.classList.add('active');
  state.st = p.dataset.st; if (scopeCache==='all') renderTickets('all');
}));

$('#btn-sync').addEventListener('click', async () => {
  try { const r = await api('/api/sync', {method:'POST', body:'{}'}); toast(`Imported ${r.imported} high-risk findings, ${r.auto_assigned} auto-assigned ✓`, 'ok'); await loadTickets('all'); if(activeTab==='dashboard') loadDashboard(); } catch(e){ toast(e.message,'err'); }
});
$('#btn-new').addEventListener('click', () => {
  openModal(`
    <div class="modal-head"><h3>New ticket</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body"><form id="newt-form" class="form">
      <label>Title <input id="nt-title" required placeholder="[HIGH] CVE-2024-6387 on 192.168.1.18"></label>
      <label>Severity <select id="nt-sev"><option>critical</option><option selected>high</option><option>medium</option><option>low</option></select></label>
      <label>CVE <input id="nt-cve" placeholder="CVE-YYYY-XXXX (optional)"></label>
      <label>Host <input id="nt-host" placeholder="IP / hostname (optional)"></label>
      <label>ATT&CK technique <select id="nt-tech"><option value="">— auto-suggest from CVE —</option></select></label>
      <button type="submit" class="btn-primary">Create ticket</button>
    </form></div>`);
  api('/api/attack').then(data => {
    const techs = Object.values(data.tactics||{}).flat();
    $('#nt-tech').innerHTML = `<option value="">— auto-suggest from CVE —</option>` + techs.map(x =>
      `<option value="${x.id}">${x.id} · ${x.name}</option>`).join('');
  }).catch(()=>{});
  $('#newt-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api('/api/tickets', { method:'POST', body: JSON.stringify({ title:$('#nt-title').value, severity:$('#nt-sev').value, cve:$('#nt-cve').value, host:$('#nt-host').value, technique_id:$('#nt-tech').value||null }) });
      closeModal(); toast('Ticket created — auto-assignment rule applied ✓', 'ok');
      await loadTickets('all'); if (activeTab==='dashboard') loadDashboard();
    } catch (err) { toast(err.message, 'err'); }
  });
});

function ticketModal(id) {
  const t = ALL_TICKETS.find(x => x.id === id) || RECENT_TICKETS.find(x => x.id === id);
  if (!t) return;
  const canEdit = hasCap('tickets.edit'), canAssign = hasCap('tickets.assign'), canDelete = hasCap('tickets.delete');
  openModal(`
    <div class="modal-head"><h3>Ticket #${t.id} <span class="badge ${SEV[t.severity]}">${t.severity}</span> <span class="badge ${t.status}">${t.status.replace('_',' ')}</span></h3><button class="close" data-close>✕</button></div>
    <div class="modal-body">
      <div style="font-size:15px;font-weight:600">${t.title}</div>
      ${t.description?`<div style="color:var(--muted);margin-top:8px;font-size:13px">${t.description}</div>`:''}
      <div class="detail-grid">
        ${t.cve?`<div class="detail"><div class="k">CVE</div><div class="val mono">${t.cve}</div></div>`:''}
        ${t.host?`<div class="detail"><div class="k">Host</div><div class="val mono">${t.host}</div></div>`:''}
        ${t.risk_score!=null?`<div class="detail"><div class="k">Risk score</div><div class="val">${t.risk_score} / 10</div></div>`:''}
        ${t.cvss!=null?`<div class="detail"><div class="k">CVSS</div><div class="val">${t.cvss}</div></div>`:''}
        <div class="detail"><div class="k">Source</div><div class="val">${t.source==='auto'?'Automated scan':'Admin'}</div></div>
        ${t.technique?`<div class="detail"><div class="k">ATT&CK technique</div><div class="val mono" style="font-size:13px">${t.technique.id} <span class="sub" style="font-size:11px;color:var(--muted)">${t.technique.name}</span></div></div>`:''}
        <div class="detail"><div class="k">Created</div><div class="val mono" style="font-size:12px">${(t.created_at||'').replace('T',' ').slice(0,16)}</div></div>
        <div class="detail"><div class="k">Assignee</div><div class="val">${t.assignee? t.assignee.username + ` <span class="sub">(${(t.assignee_rate*100).toFixed(0)}% rate)</span>` : 'Unassigned'}</div></div>
        <div class="detail"><div class="k">Est. resolution</div><div class="val">${t.est_hours!=null? t.est_hours+'h':'—'}</div></div>
        ${t.assigned_at?`<div class="detail"><div class="k">Assigned</div><div class="val mono" style="font-size:12px">${t.assigned_at.replace('T',' ').slice(0,16)}</div></div>`:''}
        ${t.solved_at?`<div class="detail"><div class="k">Solved</div><div class="val mono" style="font-size:12px">${t.solved_at.replace('T',' ').slice(0,16)}</div></div>`:''}
      </div>
      ${hasCap('glpi.view') && t.cve && t.host ? '<div id="modal-glpi" style="margin-top:6px"></div>' : ''}
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:16px">
        <button class="btn-ghost" id="modal-close" style="flex:1">Close</button>
        ${canEdit?`<button class="btn-ghost" id="modal-edit" data-close>✎ Edit</button>`:''}
        ${canAssign&&!t.assignee?`<button class="btn-ghost" id="modal-assign" data-close>Assign</button>`:''}
        ${canDelete?`<button class="btn-danger" id="modal-del" data-close>Delete</button>`:''}
      </div>
    </div>`);
  $('#modal-close').addEventListener('click', closeModal);
  if (hasCap('glpi.view') && t.cve && t.host) loadGlpiPanel(t);
  if (canEdit) $('#modal-edit').addEventListener('click', () => editTicketModal(t));
  if (canDelete) $('#modal-del').addEventListener('click', () => confirmModal(
      `Delete ticket #${t.id}?`,
      `"${t.title}" will be permanently removed. This cannot be undone.`,
      async () => {
        try { await api(`/api/tickets/${t.id}`, { method:'DELETE' }); toast(`Ticket #${t.id} deleted`, 'ok'); closeModal(); await loadTickets(scopeCache==='all'?'all':'mine'); if (activeTab==='dashboard') loadDashboard(); }
        catch (e) { toast(e.message, 'err'); }
      }));
  if (canAssign && !t.assignee) $('#modal-assign').addEventListener('click', () => assignModal(t));
}

function editTicketModal(t) {
  openModal(`
    <div class="modal-head"><h3>Edit ticket #${t.id}</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body"><form id="edit-form" class="form">
      <label>Title <input id="et-title" required value="${(t.title||'').replace(/"/g,'&quot;')}"></label>
      <label>Severity <select id="et-sev">
        ${['critical','high','medium','low'].map(s=>`<option ${s===t.severity?'selected':''}>${s}</option>`).join('')}
      </select></label>
      <label>CVE <input id="et-cve" value="${t.cve||''}"></label>
      <label>Host <input id="et-host" value="${t.host||''}"></label>
      <label>CVSS <input id="et-cvss" type="number" step="0.1" min="0" max="10" value="${t.cvss??''}"></label>
      <label>Risk score <input id="et-risk" type="number" step="0.1" min="0" max="10" value="${t.risk_score??''}"></label>
      <label>ATT&CK technique <select id="et-tech"><option value="">— none —</option></select></label>
      <label>Description <textarea id="et-desc" rows="3" style="resize:vertical;background:var(--bg2);border:1px solid var(--border);border-radius:8px;color:var(--fg);padding:10px 12px;font-family:inherit">${(t.description||'').replace(/</g,'&lt;')}</textarea></label>
      <div style="display:flex;gap:8px">
        <button type="submit" class="btn-primary" style="flex:1">Save changes</button>
        <button type="button" class="btn-ghost" data-close>Cancel</button>
      </div>
    </form></div>`);
  api('/api/attack').then(data => {
    const techs = Object.values(data.tactics||{}).flat();
    $('#et-tech').innerHTML = `<option value="">— none —</option>` + techs.map(x =>
      `<option value="${x.id}" ${x.id===t.technique_id?'selected':''}>${x.id} · ${x.name}</option>`).join('');
  }).catch(()=>{});
  $('#edit-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api(`/api/tickets/${t.id}`, { method:'PUT', body: JSON.stringify({
        title:$('#et-title').value.trim(), severity:$('#et-sev').value,
        cve:$('#et-cve').value.trim(), host:$('#et-host').value.trim(),
        cvss:$('#et-cvss').value===''?null:+$('#et-cvss').value,
        risk_score:$('#et-risk').value===''?null:+$('#et-risk').value,
        technique_id:$('#et-tech').value||null,
        description:$('#et-desc').value }) });
      closeModal(); toast(`Ticket #${t.id} updated ✓`, 'ok');
      await loadTickets(scopeCache==='all'?'all':'mine'); if (activeTab==='dashboard') loadDashboard();
    } catch (err) { toast(err.message, 'err'); }
  });
}

function assignModal(t) {
  openModal(`
    <div class="modal-head"><h3>Assign ticket #${t.id}</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body"><form id="assign-form" class="form">
      <label>Assignee <select id="as-user"></select></label>
      <div style="font-size:12px;color:var(--muted)">Unassigned tickets are auto-assigned by the &gt;50% rule. Picking a user here overrides that.</div>
      <div style="display:flex;gap:8px">
        <button type="submit" class="btn-primary" style="flex:1">Assign</button>
        <button type="button" class="btn-ghost" data-close>Cancel</button>
      </div>
    </form></div>`);
  api('/api/users').then(users => {
    $('#as-user').innerHTML = users.filter(u=>u.role!=='admin').map(u =>
      `<option value="${u.id}">${u.username} — ${(u.resolution_rate*100).toFixed(0)}% rate · ${u.open} open</option>`).join('');
  }).catch(()=>{});
  $('#assign-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api(`/api/tickets/${t.id}/assign`, { method:'POST', body: JSON.stringify({ user_id:+$('#as-user').value }) });
      closeModal(); toast(`Ticket #${t.id} assigned ✓`, 'ok');
      await loadTickets(scopeCache==='all'?'all':'mine'); if (activeTab==='dashboard') loadDashboard();
    } catch (err) { toast(err.message, 'err'); }
  });
}

function confirmModal(title, msg, onYes) {
  openModal(`
    <div class="modal-head"><h3>${title}</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body">
      <div style="color:var(--muted);font-size:13px;line-height:1.5">${msg}</div>
      <div style="display:flex;gap:8px;margin-top:18px">
        <button class="btn-danger" id="confirm-yes" style="flex:1">Yes, proceed</button>
        <button class="btn-ghost" data-close style="flex:1">Cancel</button>
      </div>
    </div>`);
  $('#confirm-yes').addEventListener('click', () => { closeModal(); onYes(); });
}

/* ---------------- provisioning helpers ---------------- */
const PROV_ICON = { es:'ES', kibana:'KB', rabbitmq:'RMQ', glpi:'GLPI', misp:'MISP' };
function provisionChips(p) {
  p = p || {};
  const order = ['es','rabbitmq','glpi','misp'];
  return order.map(k => {
    const v = p[k]; if (!v) return `<span class="badge" title="not configured">${PROV_ICON[k]}·—</span>`;
    return `<span class="badge ${v.ok===true?'eligible':v.ok===false?'blocked':'medium'}" title="${(v.detail||'').replace(/"/g,'&quot;')}">${PROV_ICON[k]}${v.ok===true?'✓':v.ok===false?'✗':'…'}</span>`;
  }).join(' ') || '<span class="badge">—</span>';
}
function provisionSummary(res) {
  if (!res) return '';
  const keys = Object.keys(res); if (!keys.length) return '';
  const ok = keys.filter(k => res[k] && res[k].ok === true).length;
  const bad = keys.filter(k => res[k] && res[k].ok === false).map(k => {
    const d = (res[k].detail || '').slice(0, 70);
    return `<div style="font-size:11.5px;color:var(--crit)">· ${k}: ${d || 'failed'}</div>`;
  }).join('');
  return `<div style="font-size:12px;line-height:1.6;margin-top:10px;padding:10px;border-radius:10px;background:rgba(34,48,72,.5);border:1px solid rgba(255,255,255,.06)">
    <b>Provisioned</b> — ${ok}/${keys.length} platforms <span style="color:var(--ok)">✓</span>
    ${bad}
  </div>`;
}

/* ---------------- users ---------------- */
async function loadUsers() {
  $('#users-body').innerHTML = skel();
  try {
    const us = await api('/api/users');
    $('#users-body').innerHTML = `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>User</th><th>Role</th><th>Solved / Total</th><th>Rate</th><th>Open</th><th>Status</th><th>Provisioned</th><th></th></tr></thead><tbody>
      ${us.map(u => {
        const pct = u.resolution_rate*100;
        const self = u.id === ME.id;
        return `<tr><td><b>${u.username}</b><div class="sub">${u.full_name}</div></td>
          <td><span class="badge ${ROLE_TIER[u.role]||'medium'}">${u.role_label||u.role}</span></td>
          <td>${u.solved} / ${u.total_assigned}</td>
          <td style="min-width:140px"><div class="progress"><i style="width:${pct}%"></i></div><div class="progress-label">${pct.toFixed(0)}%</div></td>
          <td>${u.open}</td>
          <td>${u.active? (u.resolution_rate>0.5?'<span class="badge eligible">● eligible</span>':'<span class="badge blocked">○ waiting</span>') : '<span class="badge">disabled</span>'}${u.role!=='admin'?` <button class="small" data-toggle="${u.id}">${u.active?'disable':'enable'}</button>`:''}</td>
          <td>${provisionChips(u.provision)}</td>
          <td style="white-space:nowrap">
            <button class="small" data-uedit="${u.id}">✎ Edit</button>
            <button class="small" data-ureset="${u.id}">Reset pwd</button>
            ${!self?`<button class="small" style="color:var(--crit)" data-udel="${u.id}">Delete</button>`:''}
          </td></tr>`;
      }).join('')}
      </tbody></table></div>`;
    $$('#users-body button[data-toggle]').forEach(b => b.onclick = async () => { await api(`/api/users/${b.dataset.toggle}/toggle`, {method:'POST', body:'{}'}); toast('User state updated', 'ok'); loadUsers(); });
    $$('#users-body button[data-uedit]').forEach(b => b.onclick = () => editUserModal(us.find(u=>u.id===+b.dataset.uedit)));
    $$('#users-body button[data-ureset]').forEach(b => b.onclick = () => resetPwdModal(+b.dataset.ureset));
    $$('#users-body button[data-udel]').forEach(b => b.onclick = () => {
      const u = us.find(x=>x.id===+b.dataset.udel);
      confirmModal(`Delete user "${u.username}"?`, `Their ${u.total_assigned} ticket(s) will be released back to the open queue. This cannot be undone.`, async () => {
        try { await api(`/api/users/${u.id}`, { method:'DELETE' }); toast(`User ${u.username} deleted`, 'ok'); loadUsers(); }
        catch (e) { toast(e.message, 'err'); }
      });
    });
  } catch (e) { $('#users-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

function editUserModal(u) {
  openModal(`
    <div class="modal-head"><h3>Edit user — ${u.username}</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body"><form id="ue-form" class="form">
      <label>Full name <input id="ue-full" value="${(u.full_name||'').replace(/"/g,'&quot;')}"></label>
      <label>Role <select id="ue-role"></select></label>
      <label style="gap:8px">Additional privileges (grants)
        <div id="ue-grants" style="display:flex;flex-wrap:wrap;gap:6px;text-transform:none;letter-spacing:0"></div>
        <div style="font-size:11.5px;color:var(--muted);text-transform:none;letter-spacing:0">Base role capabilities are always active; grants add more on top.</div>
      </label>
      ${u.id===ME.id?'<div style="font-size:12px;color:var(--med)">You cannot change your own role.</div>':''}
      <div style="display:flex;gap:8px">
        <button type="submit" class="btn-primary" style="flex:1">Save</button>
        <button type="button" class="btn-ghost" data-close>Cancel</button>
      </div>
    </form></div>`);
  const allCaps = { 'dashboard.view':'View dashboard', 'tickets.view_all':'View all tickets', 'tickets.create':'Create tickets', 'tickets.edit':'Edit tickets', 'tickets.delete':'Delete tickets', 'tickets.assign':'Assign tickets', 'tickets.reopen':'Reopen tickets', 'tickets.import':'Sync scanner feed', 'users.manage':'Manage users & access', 'services.view':'Access platform services', 'attack.view':'MITRE ATT&CK', 'misp.view':'View threat intel', 'misp.manage':'Manage threat intel', 'glpi.view':'View GLPI tickets', 'glpi.manage':'Manage GLPI tickets', 'infra.view':'View infrastructure health', 'infra.manage':'Manage infrastructure' };
  const grants = u.grants || [];
  $('#ue-grants').innerHTML = Object.entries(allCaps).map(([cap,label]) => `
    <label class="grant-check" style="flex-direction:row;align-items:center;gap:6px;text-transform:none;letter-spacing:0">
      <input type="checkbox" data-cap="${cap}" ${grants.includes(cap)?'checked':''}> ${label}
    </label>`).join('');
  api('/api/roles').then(roles => {
    $('#ue-role').innerHTML = roles.map(r =>
      `<option value="${r.role}" ${r.role===u.role?'selected':''}>${r.label}</option>`).join('');
  }).catch(()=>{});
  $('#ue-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const body = { full_name: $('#ue-full').value.trim() };
      if (u.id !== ME.id) body.role = $('#ue-role').value;
      body.grants = $$('#ue-grants input[data-cap]:checked').map(i => i.dataset.cap);
      await api(`/api/users/${u.id}`, { method:'PUT', body: JSON.stringify(body) });
      closeModal(); toast(`User ${u.username} updated ✓`, 'ok'); loadUsers();
    } catch (err) { toast(err.message, 'err'); }
  });
}

function resetPwdModal(uid) {
  openModal(`
    <div class="modal-head"><h3>Reset password</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body"><form id="up-form" class="form">
      <label>New password <input id="up-pass" type="password" minlength="6" required placeholder="min 6 chars"></label>
      <div style="display:flex;gap:8px">
        <button type="submit" class="btn-primary" style="flex:1">Reset</button>
        <button type="button" class="btn-ghost" data-close>Cancel</button>
      </div>
    </form></div>`);
  $('#up-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      await api(`/api/users/${uid}/password`, { method:'POST', body: JSON.stringify({ password: $('#up-pass').value }) });
      closeModal(); toast('Password reset ✓', 'ok');
    } catch (err) { toast(err.message, 'err'); }
  });
}
$('#user-form').addEventListener('submit', async e => {
  e.preventDefault();
  const resultsEl = $('#provision-results');
  try {
    const res = await api('/api/users', { method:'POST', body: JSON.stringify({ username:$('#u-name').value.trim(), full_name:$('#u-full').value, password:$('#u-pass').value, role:$('#u-role').value }) });
    toast(`User created ✓ — account provisioned across the platform`, 'ok'); $('#user-form').reset();
    if (resultsEl) resultsEl.innerHTML = provisionSummary(res.provision);
    loadUsers();
  } catch (err) { toast(err.message, 'err'); }
});

/* ---------------- services ---------------- */
const SVC_META = {
  kibana:  { name:'Kibana', tag:'Dashboards & visualizations', ico:'📊', group:'observability' },
  es:      { name:'Elasticsearch', tag:'Search & index engine', ico:'🔎', group:'observability' },
  logstash:{ name:'Logstash', tag:'Ingestion pipeline', ico:'🛢', group:'observability' },
  glpi:    { name:'GLPI', tag:'ITSM · asset inventory', ico:'🗂', group:'it' },
  misp:    { name:'MISP', tag:'Threat intelligence', ico:'🧬', group:'intel' },
  rabbitmq:{ name:'RabbitMQ', tag:'Message broker / queueing', ico:'🐇', group:'integration' },
  risk_engine:{ name:'Risk Engine', tag:'Vulnerability scoring', ico:'⚖️', group:'integration' },
  portal:  { name:'VOC Portal', tag:'This console', ico:'🛡️', group:'core' },
};
const SVC_ORDER = ['elasticsearch','kibana','logstash','risk_engine','glpi','misp','rabbitmq','portal'];
let SERVICES = {};
let ACCESS = [];

async function loadServicesPage() {
  const grid = $('#services-grid');
  const sum = $('#svc-summary');
  if (!grid) return;
  grid.innerHTML = skel();
  try {
    SERVICES = await api('/api/services');
    renderServicesGrid();
  } catch (e) { grid.innerHTML = `<div class="empty">${e.message}</div>`; }
  try {
    ACCESS = await api('/api/services/access');
    renderServicesGrid();
  } catch (e) {}
  try {
    HEALTH = await api('/api/health');
    renderServicesGrid();
  } catch (e) {}
}

function svcStatus(key) {
  if (key === 'portal') return 'up';
  const map = { es:'elasticsearch', kibana:'kibana', logstash:'logstash', glpi:'glpi', misp:'misp', rabbitmq:'rabbitmq', risk_engine:'risk_engine' };
  const k = map[key] || key;
  const v = HEALTH[k];
  if (v === 'up' || v === 'green') return 'up';
  if (v === 'yellow' || (v||'').startsWith('http:')) return 'warn';
  return 'down';
}

function renderServicesGrid() {
  const grid = $('#services-grid'), sum = $('#svc-summary');
  if (!grid) return;
  if (!Object.keys(SERVICES).length && !Object.keys(HEALTH).length) return;
  const rows = Object.keys(SERVICES).map(k => {
    const acc = ACCESS.find(a => a.key === k);
    return { k, url: (acc && acc.sso && acc.url) || SERVICES[k], sso: !!(acc && acc.sso) };
  });
  if (!rows.length) rows.push({ k:'portal', url:'http://' + location.host, sso:false });
  const entries = rows.map(({k,url,sso}) => {
    const meta = SVC_META[k] || { name:k, tag:'', ico:'◆', group:'other' };
    const st = svcStatus(k);
    const stLabel = st==='up' ? 'online' : st==='warn' ? 'degraded' : 'offline';
    return `<div class="svc-card">
      <div class="svc-top">
        <div class="svc-ico">${meta.ico}</div>
        <span class="badge ${st==='up'?'pill-up':st==='warn'?'pill-warn':'pill-down'}">${stLabel}</span>
      </div>
      <div>
        <div class="svc-name">${meta.name}</div>
        <div class="svc-tag">${meta.tag}</div>
      </div>
      <div class="svc-meta">
        <div class="mono">${sso ? (url||'').replace(/\/\/.*@/,'//***@') : url}</div>
        <div>${st==='warn'?'Cluster degraded':st==='down'?'Unreachable':'Healthy'}</div>
      </div>
      <div class="svc-foot">
        <a class="btn-ghost" style="text-decoration:none;text-align:center;flex:1" href="${url}" target="_blank" rel="noopener">Open ↗${sso?' · SSO':''}</a>
      </div>
    </div>`;
  }).join('');
  grid.innerHTML = entries;
  if (sum) {
    const total = Object.keys(HEALTH).length;
    const up = Object.values(HEALTH).filter(v => v==='up'||v==='green').length;
    const warn = Object.values(HEALTH).filter(v => v==='yellow'||(v||'').startsWith('http:')).length;
    sum.innerHTML = total
      ? `<span class="stat-chip"><i class="dot up"></i> ${up} online</span>
         <span class="stat-chip"><i class="dot warn"></i> ${warn} degraded</span>
         <span class="stat-chip"><i class="dot down"></i> ${total-up-warn} offline</span>`
      : '';
  }
}

async function loadServices() {
  try {
    SERVICES = await api('/api/services');
    const map = { kibana:'Kibana · dashboards', glpi:'GLPI · ITSM', misp:'MISP · threat intel', es:'Elasticsearch · search', rabbitmq:'RabbitMQ · queues', portal:'VOC Portal' };
    $('#services-menu').innerHTML = Object.entries(SERVICES).map(([k,v]) => `<a href="${v}" target="_blank" rel="noopener">${map[k]||k}</a>`).join('');
  } catch (e) {}
}

/* ---------------- my account ---------------- */
async function loadAccount() {
  const prof = $('#account-profile'), priv = $('#account-privs'), acc = $('#account-access');
  prof.innerHTML = skel(); priv.innerHTML = skel(); if (acc) acc.innerHTML = skel();
  try {
    ME = await api('/api/me');
    $('#whoami').textContent = ME.username;
    $('#role-tag').textContent = roleLabel(ME.role);
    $('#avatar').textContent = (ME.username[0]||'?').toUpperCase();
    const created = (ME.created_at||'').replace('T',' ').slice(0,10);
    const grantCaps = ME.grants || [];
    prof.innerHTML = `
      <div style="display:flex;gap:16px;align-items:center;margin-bottom:18px">
        <div class="avatar" style="width:56px;height:56px;font-size:22px">${(ME.username[0]||'?').toUpperCase()}</div>
        <div>
          <div style="font-size:18px;font-weight:800">${ME.full_name || ME.username}</div>
          <div style="color:var(--muted);font-size:12.5px">@${ME.username} · member since ${created}</div>
          <div style="margin-top:6px"><span class="badge ${ROLE_TIER[ME.role]||'medium'}">${roleLabel(ME.role)}</span>
          ${grantCaps.length?` <span class="badge eligible">+${grantCaps.length} granted</span>`:''}</div>
        </div>
      </div>
      <form id="acc-name" class="form" style="margin-bottom:16px">
        <label>Display name <input id="acc-full" value="${(ME.full_name||'').replace(/"/g,'&quot;')}"></label>
        <button type="submit" class="btn-ghost" style="align-self:flex-start">Save name</button>
      </form>
      <form id="acc-pass" class="form">
        <label>Current password <input id="ap-cur" type="password" autocomplete="current-password" required></label>
        <label>New password <input id="ap-new" type="password" minlength="6" autocomplete="new-password" required placeholder="min 6 chars"></label>
        <label>Confirm new password <input id="ap-new2" type="password" minlength="6" autocomplete="new-password" required></label>
        <button type="submit" class="btn-primary" style="align-self:flex-start">Change password</button>
      </form>`;
    $('#acc-name').addEventListener('submit', async e => {
      e.preventDefault();
      try { await api('/api/me', { method:'PUT', body: JSON.stringify({ full_name: $('#acc-full').value.trim() }) }); toast('Profile updated ✓', 'ok'); loadAccount(); }
      catch (err) { toast(err.message, 'err'); }
    });
    $('#acc-pass').addEventListener('submit', async e => {
      e.preventDefault();
      if ($('#ap-new').value !== $('#ap-new2').value) { toast('New passwords do not match', 'err'); return; }
      try { await api('/api/me/password', { method:'POST', body: JSON.stringify({ current_password: $('#ap-cur').value, new_password: $('#ap-new').value }) }); toast('Password changed ✓', 'ok'); e.target.reset(); }
      catch (err) { toast(err.message, 'err'); }
    });
    priv.innerHTML = (ME.privileges||[]).map(p => `
      <div style="display:flex;gap:10px;align-items:flex-start;padding:10px 0;border-bottom:1px solid rgba(34,48,72,.6)">
        <span style="color:var(--ok);font-size:15px;line-height:1">✓</span>
        <div>
          <div style="font-size:13px;font-weight:600">${p.permission} ${(grantCaps.includes(p.cap)?'<span class="badge eligible" style="margin-left:6px">granted</span>':'')}</div>
          <div style="color:var(--muted);font-size:11.5px">${p.scope}</div>
        </div>
      </div>`).join('') || '<div class="empty">No privileges</div>';
    if (acc) {
      acc.innerHTML = (ME.access||[]).map(a => `
        <div class="svc-card" style="display:flex;flex-direction:column;gap:10px">
          <div class="svc-top">
            <div class="svc-ico">${({kibana:'📊',es:'🔎',rabbitmq:'🐇',glpi:'🗂',misp:'🧬'})[a.key]||'◆'}</div>
            <span class="badge ${a.sso?'eligible':'medium'}">${a.sso?'auto-login':'same password'}</span>
          </div>
          <div>
            <div class="svc-name">${a.name}</div>
            <div class="svc-tag">${a.tag}</div>
          </div>
          <div class="svc-meta"><div class="mono" style="font-size:10.5px">${(a.url||'').replace(/\/\/.*@/,'//***@')}</div></div>
          <a class="btn-ghost" style="text-decoration:none;text-align:center;flex:1" href="${a.url}" target="_blank" rel="noopener">Open →</a>
        </div>`).join('') || '<div class="empty">No platform access configured</div>';
    }
  } catch (e) { prof.innerHTML = `<div class="empty">${e.message}</div>`; priv.innerHTML=''; if (acc) acc.innerHTML=''; }
}

/* ---------------- MITRE ATT&CK ---------------- */
const TACTIC_LABEL = { 'initial-access':'Initial Access', 'execution':'Execution', 'persistence':'Persistence', 'defense-evasion':'Defense Evasion', 'credential-access':'Credential Access', 'discovery':'Discovery', 'lateral-movement':'Lateral Movement', 'collection':'Collection', 'command-and-control':'Command & Control', 'impact':'Impact' };
const TACTIC_COLOR = { 'initial-access':'#ff4d5e', 'execution':'#ff9f43', 'persistence':'#f5d34a', 'defense-evasion':'#b27bf5', 'credential-access':'#4f8cff', 'discovery':'#38bdf8', 'lateral-movement':'#f472b6', 'collection':'#34d399', 'command-and-control':'#a3e635', 'impact':'#ff6b6b' };

const TACTIC_RGB = { 'initial-access':[255,77,94], 'execution':[255,159,67], 'persistence':[245,211,74], 'defense-evasion':[178,123,245], 'credential-access':[79,140,255], 'discovery':[56,189,248], 'lateral-movement':[244,114,182], 'collection':[52,211,153], 'command-and-control':[163,230,53], 'impact':[255,107,107] };

function techHeat(tactic, count, max) {
  if (!count) return 'rgba(34,48,72,.55)';
  const t = count / Math.max(1, max);
  const c = TACTIC_RGB[tactic] || TACTIC_RGB['initial-access'];
  return `rgba(${c.join(',')},${0.15+0.7*t})`;
}

async function loadAttack() {
  const body = $('#attack-body'), leg = $('#attack-legend');
  body.innerHTML = skel();
  try {
    const data = await api('/api/attack');
    const tactics = data.tactics || {};
    const all = Object.values(tactics).flat();
    const max = Math.max(1, ...all.map(t => t.open_tickets));
    const order = Object.keys(TACTIC_LABEL);
    const keys = Object.keys(tactics).sort((a,b) => order.indexOf(a) - order.indexOf(b));
    leg.innerHTML = `<span class="m" style="display:flex;gap:12px;align-items:center">heat · open tickets
      <i style="display:inline-block;width:12px;height:12px;border-radius:3px;background:rgba(34,48,72,.55)"></i>0
      <i style="display:inline-block;width:12px;height:12px;border-radius:3px;background:rgba(255,77,94,.45)"></i>mid
      <i style="display:inline-block;width:12px;height:12px;border-radius:3px;background:rgba(255,77,94,1)"></i>${max}</span>`;
    body.innerHTML = keys.map(tac => `
      <div style="margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <i style="display:inline-block;width:10px;height:10px;border-radius:3px;background:${TACTIC_COLOR[tac]}"></i>
          <b style="font-size:12.5px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted)">${TACTIC_LABEL[tac]||tac}</b>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px">
          ${tactics[tac].map(t => `
            <button class="tech-cell" data-t="${t.id}" style="background:${techHeat(tac,t.open_tickets,max)}" ${t.open_tickets? '' : 'disabled'}>
              <div style="display:flex;justify-content:space-between;gap:6px">
                <b class="mono">${t.id}</b>
                <span style="font-weight:700">${t.open_tickets}</span>
              </div>
              <div style="font-size:11.5px;opacity:.9;margin-top:4px;text-align:left">${t.name}</div>
            </button>`).join('')}
        </div>
      </div>`).join('') || '<div class="empty">No techniques seeded</div>';
    $$('#attack-body .tech-cell[data-t]').forEach(c => c.addEventListener('click', () => attackTicketsModal(c.dataset.t, data.tickets[c.dataset.t] || [])));
  } catch (e) { body.innerHTML = `<div class="empty">${e.message}</div>`; }
}

function attackTicketsModal(tid, tickets) {
  openModal(`
    <div class="modal-head"><h3><span class="mono">${tid}</span> — open tickets</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body">
      ${tickets.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>#</th><th>Sev</th><th>Title</th><th>Host</th><th>Risk</th></tr></thead><tbody>
        ${tickets.map(t => `<tr data-id="${t.id}"><td><b>#${t.id}</b></td><td><span class="badge ${SEV[t.severity]}">${t.severity}</span></td>
          <td>${t.title}</td><td class="mono">${t.host||'—'}</td><td>${t.risk_score!=null?t.risk_score:'—'}</td></tr>`).join('')}
      </tbody></table></div>`
      : '<div class="empty">No open tickets mapped to this technique</div>'}
      <div style="display:flex;gap:8px;margin-top:16px"><button class="btn-ghost" id="modal-close" style="flex:1">Close</button></div>
    </div>`);
  $('#modal-close').addEventListener('click', closeModal);
  $$('#modal tbody tr').forEach(tr => tr.addEventListener('click', () => { closeModal(); ticketModal(+tr.dataset.id); }));
}

/* ---------------- vulnerabilities / attack graph / predictions ---------------- */
let vulnsPage = 1;
const vulnsState = { q:'', sev:'' };

async function loadVulns() {
  $('#vulns-body').innerHTML = skel();
  $('#vulns-graph').innerHTML = skel();
  $('#vulns-predictions').innerHTML = skel();
  loadVulnsPage();
  loadAttackGraph();
  loadPredictionsHistory();
}

async function loadVulnsPage() {
  $('#vulns-body').innerHTML = skel();
  try {
    const params = new URLSearchParams({ q: vulnsState.q, severity: vulnsState.sev, page: vulnsPage, page_size: 25 });
    const r = await api('/api/vulns?' + params.toString());
    $('#vulns-count').textContent = `${r.total} findings`;
    $('#vulns-page').textContent = `Page ${r.page}`;
    $('#vulns-prev').disabled = r.page <= 1;
    $('#vulns-next').disabled = r.page * r.page_size >= r.total;
    $('#vulns-body').innerHTML = r.rows.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Host</th><th>Sev</th><th>Risk</th><th>Port/Service</th><th>Last seen</th></tr></thead><tbody>
      ${r.rows.map(v => `<tr data-fid="${(v.finding_id||'').replace(/"/g,'&quot;')}"><td class="cve-cell"><b>${v.cve||'—'}</b></td><td class="mono">${v.host_ip||'—'}${v.hostname?`<div class="sub" style="color:var(--muted)">🖥 ${v.hostname}</div>`:''}</td>
        <td><span class="badge ${SEV[(v.severity||'').toLowerCase()]||'medium'}">${v.severity||'—'}</span>${v.confidence==='confirmed'?' <span class="badge critical" title="Confirmed by active NSE check">CONFIRMED</span>':' <span class="badge blocked" title="Version-based match">potential</span>'}</td>
        <td>${v.risk_score!=null?v.risk_score:'—'}</td><td>${v.port||''} ${v.service||''}</td>
        <td class="mono" style="font-size:11.5px">${(v.last_seen||v['@timestamp']||'').replace('T',' ').slice(0,16)}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No matching findings</div>';
    $$('#vulns-body tbody tr').forEach(tr => tr.addEventListener('click', () => vulnDetail(tr.dataset.fid)));
  } catch (e) { $('#vulns-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

/* Vulnerability detail modal (Feature 13): what/why/prioritization/action */
async function vulnDetail(fid) {
  if (!fid) return;
  openModal('<div class="modal-head"><h3>Vulnerability detail</h3><button class="close" data-close>✕</button></div><div id="vd-body">'+skel()+'</div>');
  try {
    const [v, hist] = await Promise.all([
      api('/api/vulns/detail?finding_id=' + encodeURIComponent(fid)),
      api('/api/vulns/detail/history?finding_id=' + encodeURIComponent(fid)).catch(() => [])
    ]);
    const ctx = v.asset_context || {};
    const bd = v.risk_breakdown || {};
    const why = (v.risk_factors || []);
    $('#vd-body').innerHTML = `
      <div style="margin-bottom:12px">
        <b style="font-size:16px">${v.cve || v.plugin_id || 'Finding'}</b>
        <span class="badge ${SEV[(v.severity||'').toLowerCase()]||'medium'}">${v.severity||''}</span>
        ${(v.in_kev?'<span class="badge kev">KEV · actively exploited</span>':'')}
        ${(v.exploit_available?'<span class="badge high">public exploit</span>':'')}
        ${(v.confidence==='confirmed'?'<span class="badge critical" title="Proved by an active NSE check">✓ CONFIRMED by scanner</span>':'<span class="badge blocked" title="Matched from product/version banner">potential (version match)</span>')}
        <span class="badge ${String(v.status)==='resolved'?'solved':'eligible'}">${v.status||''}${v.lifecycle_state&&v.lifecycle_state!=='detected'?' · '+v.lifecycle_state:''}</span>
        <div style="color:var(--muted);font-size:11.5px;margin-top:4px">
          finding <code>${fid}</code> · scan <code>${v.scan_id||'—'}</code> · scanner ${v.scanner||'nmap'}
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:12px;font-size:12.5px">
        <div><div class="m">Asset</div>${v.host_ip||'—'}${ctx.criticality?` · criticality ${ctx.criticality}/5`:''}${ctx.environment?` · ${ctx.environment}`:''}${ctx.internet_exposed?' · internet-exposed':''}<br><span class="m">Port:</span> ${v.port||'—'} (${v.service||'—'})<br><span class="m">Product:</span> ${v.product||'—'} ${v.version||''}</div>
        <div><div class="m">Scores</div>CVSS ${v.cvss??'—'} · EPSS ${v.epss_score??'—'} · Risk <b>${v.risk_score??'—'}/10</b><br>${Object.entries(bd).filter(([k])=>k.endsWith('_score')).map(([k,vv])=>`<span class="m">${k}:</span> ${vv}`).join(' · ')}</div>
      </div>
      ${why && why.length ? `<div style="margin-bottom:10px"><div class="m" style="margin-bottom:4px">Why this score?</div><ul style="margin:0;padding-left:18px;font-size:12px;color:var(--fg)">${why.map(x=>`<li>${x}</li>`).join('')}</ul></div>`:''}
      ${v.description?`<div style="margin-bottom:10px"><div class="m" style="margin-bottom:4px">Description</div><div style="white-space:normal;font-size:12.5px">${String(v.description).slice(0,600)}</div></div>`:''}
      ${v.evidence?`<div style="margin-bottom:10px"><div class="m" style="margin-bottom:4px">Scanner evidence</div><pre style="white-space:pre-wrap;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11px;color:var(--fg);max-height:220px;overflow:auto;margin:0">${String(v.evidence).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre></div>`:''}
      ${v.remediation && v.remediation.length?`<div style="margin-bottom:10px"><div class="m" style="margin-bottom:4px">Remediation</div><ol style="margin:0;padding-left:18px;font-size:12.5px">${v.remediation.map(r=>`<li>${r}</li>`).join('')}</ol></div>`:''}
      ${hist.length?`<div style="margin-bottom:6px"><div class="m" style="margin-bottom:4px">Timeline</div><table class="no-row-click"><tbody>${hist.slice(0,8).map(h=>`<tr class="no-click"><td class="mono" style="font-size:11px">${(h['@timestamp']||'').replace('T',' ').slice(0,16)}</td><td>${h.status||''} ${h.lifecycle_state&&h.lifecycle_state!=='detected'?'('+h.lifecycle_state+')':''}</td><td>risk ${h.risk_score??'—'}</td><td class="mono" style="font-size:10.5px">${h.scan_id||''}</td></tr>`).join('')}</tbody></table></div>`:''}`;
  } catch (e) { $('#vd-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

$('#vulns-q').addEventListener('input', e => { vulnsState.q = e.target.value; vulnsPage = 1; if (activeTab==='vulns') loadVulnsPage(); });
$$('#vulns-sev .pill').forEach(p => p.addEventListener('click', () => {
  $$('#vulns-sev .pill').forEach(x => x.classList.remove('active')); p.classList.add('active');
  vulnsState.sev = p.dataset.sev; vulnsPage = 1; loadVulnsPage();
}));
$('#vulns-prev').addEventListener('click', () => { if (vulnsPage>1) { vulnsPage--; loadVulnsPage(); } });
$('#vulns-next').addEventListener('click', () => { vulnsPage++; loadVulnsPage(); });

async function loadAttackGraph() {
  try {
    const nodes = await api('/api/vulns/attack-graph');
    $('#vulns-graph').innerHTML = nodes.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>Host</th><th>Critical</th><th>Risk</th><th>Blast radius</th></tr></thead><tbody>
      ${nodes.map(n => `<tr><td class="mono">${n.host}</td><td>${n.critical?'<span class="badge critical">CRIT</span>':'—'}</td>
        <td>${n.risk}</td><td><div class="bar" style="width:140px;display:inline-block;vertical-align:middle;margin-right:8px"><i style="width:${Math.min(100,n.blast*10)}%"></i></div>${n.blast}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No attack-graph data yet</div>';
  } catch (e) { $('#vulns-graph').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function loadPredictionsHistory() {
  try {
    const preds = await api('/api/vulns/predictions');
    $('#vulns-predictions').innerHTML = preds.length ? preds.map(p => `
      <div style="margin-bottom:14px">
        <div class="m" style="color:var(--muted);font-size:11.5px;margin-bottom:6px">${(p.date||'').slice(0,10)}</div>
        ${p.top10.slice(0,5).map((t,i) => `<div class="row" style="margin-bottom:4px"><span class="grow"><b>${i+1}.</b> <span class="cve-cell">${t.cve}</span> ${t.in_kev?'<span class="badge kev">KEV</span>':''}</span><span class="m">${(t.score*100).toFixed(0)}%</span></div>`).join('')}
      </div>`).join('') : '<div class="empty">No forecasts yet — next run Sunday 06:00</div>';
  } catch (e) { $('#vulns-predictions').innerHTML = `<div class="empty">${e.message}</div>`; }
}

/* ---------------- asset inventory (Feature 1) ---------------- */
const CRIT_LABEL = {1:'Low',2:'Moderate',3:'Important',4:'High',5:'Mission Critical'};
let assetsState = { q:'', page:1 };

async function loadAssets() {
  $('#assets-body').innerHTML = skel();
  try {
    const params = new URLSearchParams({ q: assetsState.q, page: assetsState.page, page_size: 25 });
    const r = await api('/api/assets?' + params.toString());
    $('#assets-count').textContent = `${r.total} assets`;
    $('#assets-page').textContent = `Page ${r.page}`;
    $('#assets-prev').disabled = r.page <= 1;
    $('#assets-next').disabled = r.page * r.page_size >= r.total;
    const editable = hasCap('assets.edit');
    $('#assets-body').innerHTML = r.rows.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>Host</th><th>Hostname</th><th>OS</th><th>Crit</th><th>Env</th><th>Owner</th><th>Ports</th><th>Status</th><th>Last seen</th><th></th></tr></thead><tbody>
      ${r.rows.map(a => `<tr>
        <td class="mono">${a.ip_address||'—'}</td><td>${a.hostname||'<span class="m">—</span>'}</td>
        <td style="font-size:11.5px">${(a.os||'—').slice(0,40)}</td>
        <td title="${CRIT_LABEL[a.criticality]||''}">${'★'.repeat(a.criticality||3)}${editable?' <button class="small" data-asset-edit="'+a.asset_id+'">edit</button>':''}</td>
        <td>${a.environment||'<span class="m">—</span>'}</td><td>${a.owner||'<span class="m">—</span>'}</td>
        <td>${a.open_ports??'—'}</td><td><span class="badge ${a.status==='active'?'eligible':'blocked'}">${a.status||''}</span></td>
        <td class="mono" style="font-size:11px">${(a.last_seen||'').replace('T',' ').slice(0,16)}</td>
        <td></td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No assets discovered yet — run a scan</div>';
    $$('[data-asset-edit]').forEach(b => b.onclick = e => { e.stopPropagation(); assetEditModal(b.dataset.assetEdit); });
  } catch (e) { $('#assets-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function assetEditModal(assetId) {
  try {
    const a = await api('/api/assets/' + assetId);
    const hist = (a.observations_history || []);
    openModal(`
      <div class="modal-head"><h3>Asset ${a.ip_address||assetId} ${a.hostname?'· '+a.hostname:''} ${a.device_changed?'<span class="badge critical" title="'+(a.device_change_reason||'')+'">⚠ DEVICE CHANGED</span>':''}</h3><button class="close" data-close>✕</button></div>
      ${hist.length?`<div style="padding:10px 16px 0">
        <div class="m" style="font-size:11.5px;margin-bottom:6px">Observation history</div>
        <table class="no-row-click" style="width:100%"><tbody>
          ${hist.map(h=>`<tr class="no-click"><td class="mono" style="font-size:10.5px">${(h.date||'').replace('T',' ').slice(0,16)}</td><td>${h.event==='device_changed'?'<span class="badge critical">SWAP</span>':'<span class="badge blocked">change</span>'}</td><td style="font-size:11px">${h.detail||''}</td></tr>`).join('')}
        </tbody></table></div>`:''}
      <div class="modal-body"><form id="asset-form" class="form">
        <label>Criticality <select id="ae-crit">${[1,2,3,4,5].map(c=>`<option value="${c}" ${+a.criticality===c?'selected':''}>${c} - ${CRIT_LABEL[c]}</option>`).join('')}</select></label>
        <label>Environment <select id="ae-env">${['','development','testing','staging','production'].map(e=>`<option value="${e}" ${(a.environment||'')===e?'selected':''}>${e||'unknown'}</option>`).join('')}</select></label>
        <label>Owner <input id="ae-owner" value="${a.owner||''}" placeholder="team / person"></label>
        <label>Business service <input id="ae-bsn" value="${a.business_service||''}" placeholder="what runs here"></label>
        <label>Network zone <input id="ae-zone" value="${a.network_zone||''}" placeholder="dmz / lan / vpn..."></label>
        <label class="row"><input type="checkbox" id="ae-exposed" ${a.internet_exposed?'checked':''} style="width:auto"> Internet-exposed</label>
        <button type="submit" class="btn-primary">Save</button>
      </form></div>`);
    $('#asset-form').onsubmit = async ev => {
      ev.preventDefault();
      try {
        await api('/api/assets/' + assetId, { method:'PATCH', body: JSON.stringify({
          criticality: +$('#ae-crit').value,
          environment: $('#ae-env').value || undefined,
          owner: $('#ae-owner').value,
          business_service: $('#ae-bsn').value,
          network_zone: $('#ae-zone').value,
          internet_exposed: $('#ae-exposed').checked }) });
        toast('Asset updated ✓', 'ok'); closeModal(); loadAssets();
      } catch (err) { toast(err.message, 'err'); }
    };
  } catch (e) { toast(e.message, 'err'); }
}
$('#assets-q').addEventListener('input', e => { assetsState.q = e.target.value; assetsState.page = 1; if (activeTab==='assets') loadAssets(); });
$('#assets-prev').addEventListener('click', () => { if (assetsState.page>1) { assetsState.page--; loadAssets(); } });
$('#assets-next').addEventListener('click', () => { assetsState.page++; loadAssets(); });

/* ---------------- audit trail (Feature 9) ---------------- */
async function loadAudit() {
  if (!hasCap('audit.view')) return;
  $('#audit-body').innerHTML = skel();
  try {
    const rows = await api('/api/audit?limit=300');
    $('#audit-body').innerHTML = rows.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>When</th><th>User</th><th>Action</th><th>Resource</th><th>Detail</th><th>IP</th><th>Result</th></tr></thead><tbody>
      ${rows.map(a => `<tr>
        <td class="mono" style="font-size:11px">${(a.at||'').replace('T',' ').slice(0,19)}</td>
        <td>${a.username||('#'+a.user_id)||'system'}</td>
        <td><code>${a.action}</code>${a.old_value!=null&&a.new_value!=null?`<div class="sub">${String(a.old_value).slice(0,30)} → ${String(a.new_value).slice(0,30)}</div>`:''}</td>
        <td>${a.resource||''}${a.resource_id?' #'+a.resource_id:''}</td>
        <td style="font-size:11.5px">${(a.detail||'').slice(0,80)}</td>
        <td class="mono">${a.ip||''}</td>
        <td><span class="badge ${a.result==='success'?'eligible':'critical'}">${a.result||''}</span></td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No audit events yet</div>';
  } catch (e) { $('#audit-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function refreshRoleOptions() {
  try {
    const rows = await api('/api/roles');
    const sel = $('#u-role');
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = rows.map(r => `<option value="${r.name}">${r.label}</option>`).join('');
    if (cur) sel.value = cur;
  } catch (e) { /* roles.manage required */ }
}

/* ---------------- Endpoint activity (FIM + processes) ---------------- */
let epState = { q: '', type: '', host: '', result: '', minutes: 1440, noise: 1, page: 1 };

async function loadEndpoints() {
  ['#ep-kpis','#ep-files','#ep-processes'].forEach(id => { const el=$(id); if(el) el.innerHTML=skel(); });
  try {
    const sum = await api('/api/endpoints/summary');
    $('#ep-kpis').innerHTML = [
      { l:'File changes · 24h', v:sum.file_changes_24h ?? 0, d:(sum.actions||[]).map(a=>a[0]).slice(0,3).join(', ')||'—', c:'high' },
      { l:'Processes · 24h', v:sum.processes_24h ?? 0, d:'executions observed', c:'fg' },
      { l:'Hosts monitored', v:(sum.hosts||[]).length, d:(sum.hosts||[]).join(', ')||'—', c:'low' },
    ].map(k => `<div class="kpi"><div class="l">${k.l}</div><div class="v" style="color:var(--${k.c})">${k.v}</div><div class="d">${k.d}</div></div>`).join('');
    await loadEndpointFiles();
    loadEndpointProcesses();
    loadFleetAgents();
    loadNetworkLive();
  } catch (e) {
    ['ep-kpis','ep-files','ep-processes'].forEach(id => { const el=$('#'+id); if(el) el.innerHTML=`<div class="empty">${e.message}</div>`; });
  }
}

async function loadEndpointFiles() {
  const params = new URLSearchParams({ q: epState.q, type: epState.type, host: epState.host,
                                       result: epState.result, minutes: epState.minutes,
                                       noise: epState.noise ? 1 : 0,
                                       page: epState.page, page_size: 40 });
  try {
    const r = await api('/api/endpoints/activity?' + params);
    $('#ep-page').textContent = `${r.total} events · page ${r.page}`;
    $('#ep-prev').disabled = r.page <= 1;
    $('#ep-next').disabled = r.page * r.page_size >= r.total;
    $('#ep-files').innerHTML = r.rows.length ? `<table class="no-row-click"><thead><tr><th>When</th><th>Host</th><th>Type</th><th>Detail</th><th>User / IP</th><th>Résultat</th></tr></thead><tbody>
      ${r.rows.map(f => {
        const isLogin = f.kind === 'login';
        const outcomeCls = f.outcome === 'failed' ? 'critical' : f.outcome === 'success' ? 'eligible' : 'blocked';
        return `<tr title="${f.sha256?('sha256: '+f.sha256):''}">
        <td class="mono" style="font-size:10.5px">${(f['@timestamp']||'').replace('T',' ').slice(0,19)}</td>
        <td><b>${f.host||'—'}</b></td>
        <td>${isLogin?'<span class="badge kev">LOGIN</span>':`<span class="badge ${(f.action||'')==='deleted'?'critical':(f.action||'')==='created'?'eligible':'high'}">${f.action||'file'}</span>`}</td>
        <td class="mono" style="font-size:11px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${String(f.detail||'').replace(/"/g,'&quot;')}">${f.detail||'—'}</td>
        <td style="font-size:11.5px">${f.user?`<b>${f.user}</b>`:''} ${f.ip?`<span class="mono" style="color:var(--muted)">${f.ip}</span>`:''}</td>
        <td>${f.outcome?`<span class="badge ${outcomeCls}">${f.outcome.toUpperCase()}</span>`:'<span class="m">—</span>'}</td></tr>`;
      }).join('')}
      </tbody></table>` : '<div class="empty">Aucun événement ne correspond aux filtres</div>';
  } catch (e) { $('#ep-files').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function loadEndpointProcesses() {
  try {
    const r = await api('/api/endpoints/processes?page_size=30');
    $('#ep-processes').innerHTML = r.rows.length ? `<table class="no-row-click"><tbody>
      ${r.rows.map(pr => `<tr title="${(pr.cmdline||'').replace(/"/g,'&quot;')}">
        <td class="mono" style="font-size:10.5px">${(pr['@timestamp']||'').replace('T',' ').slice(0,16)}</td>
        <td><b>${pr.name||'?'}</b><div class="sub mono" style="font-size:10px">${(pr.cmdline||'').slice(0,60)}</div></td>
        <td>${pr.user||''}</td></tr>`).join('')}
      </tbody></table>` : '<div class="empty">No process data</div>';
  } catch (e) { $('#ep-processes').innerHTML = `<div class="empty">${e.message}</div>`; }
}

$('#act-q').addEventListener('input', e => { epState.q = e.target.value; epState.page = 1;
  clearTimeout(window._epT); window._epT = setTimeout(() => { if (activeTab==='endpoints') loadEndpointFiles(); }, 350); });
$('#act-type').addEventListener('change', e => { epState.type = e.target.value; epState.page = 1; loadEndpointFiles(); });
$('#act-host').addEventListener('change', e => { epState.host = e.target.value; epState.page = 1; loadEndpointFiles(); });
$('#act-result').addEventListener('change', e => { epState.result = e.target.value; epState.page = 1; loadEndpointFiles(); });
$('#act-minutes').addEventListener('change', e => { epState.minutes = e.target.value; epState.page = 1; loadEndpointFiles(); });
$('#act-noise').addEventListener('change', e => { epState.noise = e.target.checked ? 1 : 0; epState.page = 1; loadEndpointFiles(); });
$('#ep-prev').addEventListener('click', () => { if (epState.page > 1) { epState.page--; loadEndpointFiles(); } });
$('#ep-next').addEventListener('click', () => { epState.page++; loadEndpointFiles(); });
$('#btn-fim-canary').addEventListener('click', async () => {
  try {
    const r = await api('/api/endpoints/test-fim', { method: 'POST', body: '{}' });
    toast(`Canary written to ${r.path} — it will appear below within ~10s`, 'info', 6000);
    setTimeout(loadEndpointFiles, 12000);
  } catch (e) { toast(e.message, 'err'); }
});
setInterval(() => { if (activeTab === 'endpoints') { loadEndpointFiles(); loadNetworkLive(); } }, 30000);

async function loadFleetAgents() {
  const el = $('#ep-fleet'); if (!el) return;
  try {
    const r = await api('/api/endpoints/fleet');
    $('#fleet-count').textContent = `${r.online}/${r.total} en ligne`;
    el.innerHTML = r.agents.length ? r.agents.map(a => `
      <div class="row">
        <span>${a.online ? '🟢' : '🔴'}</span>
        <span class="grow"><b>${a.name}</b><div class="sub mono" style="font-size:10px">${(a.ips||[]).join(', ')||'—'} · ${a.os||''}</div></span>
        <span class="m" style="font-size:10.5px">${a.checkin_minutes_ago!=null?`il y a ${a.checkin_minutes_ago}min`:'—'}</span>
      </div>`).join('') : '<div class="empty">Aucun agent enrôlé</div>';
  } catch (e) { el.innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function loadNetworkLive() {
  const el = $('#ep-network'); if (!el) return;
  try {
    const r = await api('/api/endpoints/network?minutes=30');
    el.innerHTML = r.machines.length ? r.machines.slice(0, 12).map(m => `
      <div class="row">
        <span class="badge ${m.known_asset?'eligible':'blocked'}">${m.known_asset?'asset':'inconnu'}</span>
        <span class="grow"><span class="mono">${m.ip}</span>${m.hostname?` · ${m.hostname}`:''}</span>
        <span class="m" style="font-size:10.5px">${m.flows} flux</span>
      </div>`).join('') : '<div class="empty">Aucun trafic inter-réseaux récent</div>';
  } catch (e) { el.innerHTML = `<div class="empty">${e.message}</div>`; }
}

/* ---------------- Host Intel (Ansible Deep Scan) ---------------- */
async function loadHostIntel() {
  $('#hi-list').innerHTML = skel(); $('#hi-detail').innerHTML='';
  try {
    const r = await api('/api/intel/hosts');
    $('#hi-list').innerHTML = r.hosts.length ? `<table class="no-row-click"><thead><tr><th>Machine</th><th>OS</th><th>Uptime</th><th>Paquets</th><th>Services</th><th>Users</th><th>Profil</th><th>Scanné</th><th></th></tr></thead><tbody>
      ${r.hosts.map(h => `<tr>
        <td><b>${h.host}</b><div class="sub mono">${h.ip||''}</div></td>
        <td style="font-size:11.5px">${h.os||''}<div class="sub" style="font-size:10.5px">${h.kernel||''}</div></td>
        <td>${h.uptime_days??'—'} j</td><td><b>${h.packages_count??'—'}</b></td><td>${h.services_count??'—'}</td><td>${h.users_count??'—'}</td>
        <td><span class="badge ${h.scan_profile==='max'?'critical':'high'}">${(h.scan_profile||'').toUpperCase()}</span></td>
        <td class="mono" style="font-size:10.5px">${(h.scanned_at||'').replace('T',' ').slice(0,16)}</td>
        <td><button class="small primary" data-hi="${h.host}">Détails</button></td></tr>`).join('')}
    </tbody></table>` : '<div class="empty">Aucun scan — lancez : systemctl start argus-deepscan.service</div>';
    $$('[data-hi]').forEach(b => b.onclick = () => hostIntelDetail(b.dataset.hi));
  } catch (e) { $('#hi-list').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function hostIntelDetail(host) {
  openModal(`<div class="modal-head"><h3>Intel · ${host}</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body" id="hi-body">${skel()}</div>`);
  try {
    const d = await api('/api/intel/host/' + encodeURIComponent(host));
    const pkgSearch = `
      <input id="hi-pkg-q" class="search" placeholder="Filtrer les paquets… (openssh, apache…)" style="margin:8px 0">
      <div id="hi-pkgs" style="max-height:220px;overflow:auto;display:flex;flex-wrap:wrap;gap:6px">
        ${(d.packages||[]).map(p=>{const [n,v]=p.split('|');return `<span class="badge blocked mono" style="font-size:10.5px" title="${v}">${n} <span style="color:var(--muted)">${v}</span></span>`}).join('')}
      </div>`;
    $('#hi-body').innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;font-size:12.5px">
        <div><span class="m">OS:</span> ${d.os||'—'}<br><span class="m">Kernel:</span> ${d.kernel||'—'}<br><span class="m">IP:</span> <span class="mono">${d.ip||'—'}</span></div>
        <div><span class="m">Uptime:</span> ${d.uptime_days??'—'} jours<br><span class="m">Scanné:</span> ${(d.scanned_at||'').replace('T',' ').slice(0,16)}<br><span class="m">Profil:</span> <span class="badge high">${(d.scan_profile||'deep').toUpperCase()}</span></div>
      </div>
      <details open style="margin-bottom:10px"><summary class="m">Ports en écoute (${(d.ports||[]).length})</summary>
        <table class="no-row-click" style="margin-top:6px"><tbody>
        ${(d.ports||[]).map(p=>`<tr class="no-click"><td class="mono"><b>${p.port}</b></td><td class="mono" style="font-size:11px">${p.local}</td><td>${p.process||''}</td></tr>`).join('') || '<tr><td colspan=3 class=empty>aucun</td></tr>'}
        </tbody></table></details>
      <details style="margin-bottom:10px"><summary class="m">Comptes utilisateurs (${(d.users||[]).length})</summary>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">${(d.users||[]).map(u=>`<span class="badge eligible mono" style="font-size:10.5px">${u.split(':')[0]}</span>`).join('')}</div></details>
      <details style="margin-bottom:10px"><summary class="m">Dernières connexions</summary>
        <pre style="white-space:pre-wrap;font-size:10.5px;background:var(--bg2);border-radius:8px;padding:10px;margin:6px 0 0;color:var(--fg)">${(d.recent_logins||[]).join('\n')}</pre></details>
      <details><summary class="m">Paquets installés (${d.packages_count})</summary>${pkgSearch}</details>`;
    $('#hi-pkg-q').addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      $$('#hi-pkgs .badge').forEach(el => el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none');
    });
  } catch (e) { $('#hi-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

/* ---------------- Tools Hub (unified console) ---------------- */
const HUB_STATUS_CLS = { up:'eligible', down:'critical', not_deployed:'blocked', covered:'eligible', remote:'high' };
async function loadToolsHub() {
  $('#hub-body').innerHTML = skel();
  try {
    const [hub, health] = await Promise.all([
      api('/api/tools'),
      api('/api/tools/health').catch(() => ({}))
    ]);
    const groups = {};
    hub.tools.forEach(t => { (groups[t.category] ||= []).push(t); });
    const dots = Object.entries(health).map(([k, v]) =>
      `<span class="dot ${v==='up'||v==='green'?'up':v==='yellow'?'warn':'down'}"><span>${k}</span></span>`).join('');
    $('#hub-body').innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <div class="card-head"><h3>Platform status</h3><div class="stat-row">${dots}</div></div>
      </div>
      ${Object.entries(groups).map(([cat, tools]) => `
        <div class="card" style="margin-bottom:14px">
          <div class="card-head"><h3>${cat}</h3></div>
          <div class="svc-grid">
            ${tools.map(t => {
              const cls = HUB_STATUS_CLS[t.status] || 'blocked';
              const body = t.url
                ? `<a class="small primary" href="${t.url}" target="_blank" rel="noopener" style="text-decoration:none">Open ${t.sso?'· SSO':''} ↗</a>` : '';
              const native = t.key === 'voc_dashboards'
                ? `<button class="small primary" onclick="switchTab('dashboards')">View</button>` : '';
              return `<div class="svc-card">
                <div class="row"><b>${t.name}</b><span class="badge ${cls}" title="${t.note||''}">${t.status}</span></div>
                <div class="sub" style="margin:6px 0 10px;color:var(--muted);font-size:11.5px;min-height:28px">${t.note||''}</div>
                <div style="display:flex;gap:8px;flex-wrap:wrap">${native}${body}</div>
              </div>`;
            }).join('')}
          </div>
        </div>`).join('')}`;
  } catch (e) { $('#hub-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

/* ---------------- Native Dashboards tab ---------------- */
async function loadDashboardsTab() {
  ['#nd-trend','#nd-confidence','#nd-confirmed','#nd-kibana'].forEach(id => { const el=$(id); if(el) el.innerHTML=skel(); });
  try {
    const [d, hub] = await Promise.all([api('/api/dashboard'), api('/api/tools').catch(() => ({tools: [], public_host: 'localhost'}))]);
    $('#nd-trend').innerHTML = (d.trend||[]).length ? stackedTrendChart(d.trend) : '<div class="empty">No data yet</div>';
    const cf = d.confidence || {};
    $('#nd-confidence').innerHTML = (cf.confirmed || cf.potential)
      ? donutChart([['confirmed', cf.confirmed||0], ['potential', cf.potential||0]])
      : '<div class="empty">No scan data yet</div>';
    const r = await api('/api/vulns?confidence=confirmed&page_size=8');
    $('#nd-confirmed').innerHTML = r.rows.length ? `<table class="no-row-click"><thead><tr><th>CVE</th><th>Host</th><th>Sev</th><th>Evidence</th></tr></thead><tbody>
      ${r.rows.map(v => `<tr><td class="cve-cell"><b>${v.cve}</b></td><td class="mono">${v.host_ip}${v.hostname?` <span class="m">(${v.hostname})</span>`:''}</td>
        <td><span class="badge ${(v.severity||'').toLowerCase()||'medium'}">${v.severity||''}</span></td>
        <td style="font-size:11px;color:var(--muted);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${(v.evidence||'').replace(/"/g,'&quot;')}">${(v.plugin_id||'NSE')}</td></tr>`).join('')}
      </tbody></table>` : '<div class="empty">No confirmed findings yet — NSE checks run with every scan</div>';
    if (hub.kibana_embed_url) {
      $('#nd-kibana').innerHTML = `<iframe src="${hub.kibana_embed_url}" style="width:100%;height:520px;border:1px solid var(--border);border-radius:10px;background:#fff"></iframe>`;
    } else {
      $('#nd-kibana').innerHTML = `<div class="empty" style="line-height:1.9">
        Full Kibana dashboards can be embedded here.<br>
        1. Open <a href="${hub.tools.find(t=>t.key==='kibana')?.url||'http://'+hub.public_host+':5601'}" target="_blank">Kibana</a><br>
        2. Open a dashboard → <b>Share → Embed code</b> → copy the iframe URL<br>
        3. Set <code>KIBANA_EMBED_URL=...</code> in <code>.env</code> and restart the portal<br>
        <a class="btn-primary small" style="display:inline-block;margin-top:8px;text-decoration:none" href="${hub.tools.find(t=>t.key==='kibana')?.url||'#'}" target="_blank">Open Kibana ↗</a></div>`;
    }
  } catch (e) { $('#nd-kibana').innerHTML = `<div class="empty">${e.message}</div>`; }
}
/* ---------------- Roles matrix (dynamic RBAC) ---------------- */
let CAPS_CATALOG = null;
async function capsCatalog() {
  if (!CAPS_CATALOG) CAPS_CATALOG = await api('/api/roles/catalog');
  return CAPS_CATALOG;
}
async function loadRoles() {
  if (!hasCap('roles.manage')) return;
  $('#roles-body').innerHTML = skel();
  try {
    const rows = await api('/api/roles');
    $('#roles-body').innerHTML = `<table class="no-row-click"><thead><tr><th>Rôle</th><th>Type</th><th>Utilisateurs</th><th>Permissions</th><th></th></tr></thead><tbody>
      ${rows.map(r => {
        const custom = !r.builtin;
        return `<tr>
          <td><b>${r.label}</b><div class="sub mono">${r.name}</div></td>
          <td>${r.builtin?'<span class="badge blocked">BUILTIN</span>':'<span class="badge eligible">CUSTOM</span>'}</td>
          <td>${r.users}</td>
          <td style="font-size:11px">${r.caps.length} permissions</td>
          <td style="white-space:nowrap">
            <button class="small primary" data-role-edit="${r.id}">${custom?'Modifier':'Voir'}</button>
            ${custom?`<button class="small" data-role-del="${r.id}">Supprimer</button>`:''}
          </td></tr>`;
      }).join('')}
    </tbody></table>`;
    $$('[data-role-edit]').forEach(b => b.onclick = () => roleMatrixModal(+b.dataset.roleEdit));
    $$('[data-role-del]').forEach(b => b.onclick = async () => {
      if (!confirm('Supprimer ce rôle ?')) return;
      try { await api('/api/roles/' + b.dataset.roleDel, {method:'DELETE'});
        toast('Rôle supprimé ✓','ok'); loadRoles();
      } catch(e){ toast(e.message,'err'); }
    });
  } catch (e) { $('#roles-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function roleMatrixModal(roleId) {
  const cat = await capsCatalog();
  let current = { name:'', label:'', caps:[], builtin:true };
  if (roleId) {
    const rows = await api('/api/roles');
    current = rows.find(r => r.id === roleId) || current;
  }
  const readonly = !!current.builtin;
  openModal(`
    <div class="modal-head"><h3>${roleId ? (readonly?'Rôle intégré : ':'Modifier : ') + current.label : 'Nouveau rôle'}</h3>
      <button class="close" data-close>✕</button></div>
    <div class="modal-body">
      ${readonly?'<div class="empty" style="margin-bottom:10px">Les rôles intégrés ne sont pas modifiables (protection anti-lockout). Clonez-les en rôle personnalisé si besoin.</div>':`
      <form id="role-form" class="form" style="flex-direction:row;gap:8px;margin-bottom:10px">
        ${roleId?'':`<input id="rl-name" placeholder="nom (ex: stagiaire)" required pattern="[a-z0-9][a-z0-9_-]{1,31}" style="flex:1">`}
        <input id="rl-label" placeholder="Libellé affiché" value="${current.label||''}" required style="flex:1">
      </form>`}
      <div id="matrix" style="max-height:340px;overflow:auto"></div>
      ${readonly?'':`<button class="btn-primary" id="rl-save" style="margin-top:12px;width:100%">${roleId?'Enregistrer':'Créer le rôle'}</button>`}
    </div>`);
  const matrix = $('#matrix');
  matrix.innerHTML = cat.groups.map(([group, caps]) => `
    <div style="margin-bottom:12px">
      <div class="m" style="font-size:11.5px;margin-bottom:4px;color:var(--muted)">${group}</div>
      ${caps.map(cap => {
        const meta = cat.meta[cap] || {};
        return `<label class="row" style="padding:4px 0;cursor:${readonly?'default':'pointer'}">
          <input type="checkbox" class="cap-cb" value="${cap}" ${current.caps.includes(cap)?'checked':''} ${readonly?'disabled':''} style="width:auto">
          <span class="grow" style="font-size:12.5px">${meta[0]||cap} <span class="m mono" style="font-size:10px">${cap}</span></span>
        </label>`;
      }).join('')}
    </div>`).join('');
  const saveBtn = $('#rl-save');
  if (saveBtn) saveBtn.onclick = async () => {
    const caps = $$('#matrix .cap-cb:checked').map(cb => cb.value);
    try {
      if (roleId) {
        await api('/api/roles/' + roleId, { method:'PUT',
          body: JSON.stringify({ label: $('#rl-label').value, caps }) });
        toast('Rôle mis à jour ✓','ok');
      } else {
        await api('/api/roles', { method:'POST',
          body: JSON.stringify({ name: $('#rl-name').value, label: $('#rl-label').value, caps }) });
        toast('Rôle créé ✓','ok');
      }
      closeModal(); loadRoles(); loadUsers && activeTab==='users' && loadUsers();
    } catch (e) { toast(e.message, 'err'); }
  };
}
$('#btn-new-role').addEventListener('click', () => roleMatrixModal(null));

/* ---------------- GLPI live panel (inside the ticket modal) ---------------- */
async function loadGlpiPanel(t) {
  const el = $('#modal-glpi');
  if (!el) return;
  const head = '<div class="card-head" style="margin-bottom:8px"><h3>GLPI ticket</h3></div>';
  el.innerHTML = head + skel();
  try {
    const look = await api(`/api/glpi/lookup?cve=${encodeURIComponent(t.cve)}&host=${encodeURIComponent(t.host)}`);
    if (!look.found) { el.innerHTML = head + '<div class="empty">No matching GLPI ticket found for this CVE/host</div>'; return; }
    const g = await api(`/api/glpi/tickets/${look.id}`);
    const canManage = hasCap('glpi.manage');
    el.innerHTML = `
      <div class="card-head" style="margin-bottom:8px"><h3>GLPI ticket #${g.id}</h3><span class="badge medium">${g.status_label}</span></div>
      <div style="font-size:13px;margin-bottom:10px">${g.name||''}</div>
      ${canManage ? `<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
        <select id="glpi-status-sel" style="background:var(--bg2);border:1px solid var(--border);color:var(--fg);border-radius:8px;padding:6px 10px;font-size:12.5px">
          ${Object.entries({1:'New',2:'Processing (assigned)',3:'Processing (planned)',4:'Pending',5:'Solved',6:'Closed'}).map(([k,v])=>`<option value="${k}" ${+k===g.status?'selected':''}>${v}</option>`).join('')}
        </select>
        <button class="small primary" id="glpi-status-btn">Update status</button>
      </div>` : ''}
      <div style="font-size:12px;color:var(--muted);margin-bottom:6px">Follow-ups</div>
      <div style="display:flex;flex-direction:column;gap:6px;max-height:160px;overflow-y:auto;margin-bottom:${canManage?'10px':'0'}">
        ${(g.followups||[]).map(f => `<div class="row" style="align-items:flex-start"><span class="grow" style="white-space:normal">${(f.content||'').replace(/<[^>]+>/g,' ').slice(0,240)}</span><span class="m" style="font-size:10.5px">${(f.date||'').replace('T',' ').slice(0,16)}</span></div>`).join('') || '<div class="empty">No follow-ups yet</div>'}
      </div>
      ${canManage ? `<form id="glpi-followup-form" class="form" style="flex-direction:row;gap:8px">
        <input id="glpi-followup-text" placeholder="Add a follow-up…" style="flex:1;padding:8px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;color:var(--fg);font-size:12.5px">
        <button type="submit" class="small primary">Add</button>
      </form>` : ''}`;
    if (canManage) {
      $('#glpi-status-btn').onclick = async () => {
        try { await api(`/api/glpi/tickets/${g.id}/status`, { method:'PUT', body: JSON.stringify({ status:+$('#glpi-status-sel').value }) }); toast('GLPI status updated ✓', 'ok'); loadGlpiPanel(t); }
        catch (e) { toast(e.message, 'err'); }
      };
      $('#glpi-followup-form').addEventListener('submit', async e => {
        e.preventDefault();
        const content = $('#glpi-followup-text').value.trim();
        if (!content) return;
        try { await api(`/api/glpi/tickets/${g.id}/followup`, { method:'POST', body: JSON.stringify({ content }) }); toast('Follow-up added ✓', 'ok'); loadGlpiPanel(t); }
        catch (e) { toast(e.message, 'err'); }
      });
    }
  } catch (e) { el.innerHTML = head + `<div class="empty">${e.message}</div>`; }
}

/* ---------------- threat intel (MISP) ---------------- */
let MISP_EVENTS = [];
async function loadThreatIntel(q) {
  $('#misp-body').innerHTML = skel();
  try {
    const params = new URLSearchParams({ q: q || '' });
    MISP_EVENTS = await api('/api/misp/events?' + params.toString());
    renderMispEvents();
  } catch (e) { $('#misp-body').innerHTML = `<div class="empty">${e.message}</div>`; }
}

function renderMispEvents() {
  const list = MISP_EVENTS || [];
  $('#misp-body').innerHTML = list.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>Event</th><th>Date</th><th>Published</th><th>Tags</th><th></th></tr></thead><tbody>
    ${list.map(row => {
      const ev = row.Event || row;
      const pub = ev.published == 1 || ev.published === true;
      const tags = (ev.Tag||[]).map(t=>t.name).slice(0,4).join(', ');
      return `<tr><td class="clickable" data-view="${ev.id}"><b>#${ev.id}</b> ${ev.info||''}</td><td class="mono" style="font-size:11.5px">${ev.date||''}</td>
        <td>${pub?'<span class="badge eligible">published</span>':'<span class="badge blocked">draft</span>'}</td>
        <td style="font-size:11.5px;color:var(--muted)">${tags}</td>
        <td style="white-space:nowrap">
          ${hasCap('misp.manage') && !pub ? `<button class="small primary" data-pub="${ev.id}">Publish</button>` : ''}
          ${hasCap('misp.manage') ? `<button class="small" style="color:var(--crit)" data-del="${ev.id}" data-info="${(ev.info||'').replace(/"/g,'&quot;')}">Delete</button>` : ''}
        </td></tr>`;
    }).join('')}
    </tbody></table></div>` : '<div class="empty">No matching MISP events</div>';
  $$('#misp-body td[data-view]').forEach(td => td.addEventListener('click', () => mispEventModal(td.dataset.view)));
  $$('#misp-body button[data-pub]').forEach(b => b.onclick = async e => {
    e.stopPropagation();
    try { await api(`/api/misp/events/${b.dataset.pub}/publish`, {method:'POST', body:'{}'}); toast('Event published ✓', 'ok'); loadThreatIntel($('#misp-q').value); }
    catch (err) { toast(err.message, 'err'); }
  });
  $$('#misp-body button[data-del]').forEach(b => b.onclick = e => {
    e.stopPropagation();
    confirmModal(`Delete MISP event #${b.dataset.del}?`, `"${b.dataset.info}" will be permanently removed from MISP. This cannot be undone.`, async () => {
      try { await api(`/api/misp/events/${b.dataset.del}`, {method:'DELETE'}); toast('Event deleted', 'ok'); loadThreatIntel($('#misp-q').value); }
      catch (err) { toast(err.message, 'err'); }
    });
  });
}

async function mispEventModal(id) {
  try {
    const ev = await api(`/api/misp/events/${id}`);
    const attrs = ev.Attribute || [];
    detailModal(`MISP event #${ev.id}`, `
      <div style="font-size:14px;font-weight:600;margin-bottom:10px">${ev.info||''}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        ${(ev.Tag||[]).map(t=>`<span class="badge medium">${t.name}</span>`).join('')}
      </div>
      <div class="table-wrap"><table class="no-row-click"><thead><tr><th>Type</th><th>Category</th><th>Value</th></tr></thead><tbody>
        ${attrs.map(a=>`<tr><td>${a.type}</td><td>${a.category}</td><td class="mono" style="font-size:12px;word-break:break-all">${a.value}</td></tr>`).join('') || '<tr><td colspan="3" class="empty">No attributes</td></tr>'}
      </tbody></table></div>`);
  } catch (e) { toast(e.message, 'err'); }
}

$('#misp-search-btn').addEventListener('click', () => loadThreatIntel($('#misp-q').value.trim()));
$('#misp-q').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); loadThreatIntel($('#misp-q').value.trim()); } });
$('#btn-misp-new').addEventListener('click', () => {
  openModal(`
    <div class="modal-head"><h3>New MISP event</h3><button class="close" data-close>✕</button></div>
    <div class="modal-body"><form id="misp-new-form" class="form">
      <label>Info / title <input id="mn-info" required placeholder="Suspicious activity on 192.168.1.18"></label>
      <label>Tags (comma-separated) <input id="mn-tags" placeholder="source:voc-portal, tlp:white"></label>
      <button type="submit" class="btn-primary">Create draft event</button>
    </form></div>`);
  $('#misp-new-form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const tags = $('#mn-tags').value.split(',').map(s=>s.trim()).filter(Boolean);
      await api('/api/misp/events', { method:'POST', body: JSON.stringify({ info: $('#mn-info').value.trim(), tags: tags.length?tags:undefined }) });
      closeModal(); toast('MISP event created (draft — publish when ready) ✓', 'ok');
      loadThreatIntel($('#misp-q').value);
    } catch (err) { toast(err.message, 'err'); }
  });
});

/* ---------------- infrastructure (RabbitMQ + Elasticsearch) ---------------- */
async function loadInfra() {
  $('#infra-queues').innerHTML = skel();
  $('#infra-es-health').innerHTML = skel();
  $('#infra-indices').innerHTML = skel();
  loadQueues(); loadEsHealth(); loadEsIndices();
}

async function loadQueues() {
  try {
    const qs = await api('/api/infra/queues');
    $('#infra-queues').innerHTML = qs.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>Queue</th><th>Ready</th><th>Unacked</th><th>Consumers</th><th>Rate/s</th><th></th></tr></thead><tbody>
      ${qs.map(q => `<tr><td class="mono">${q.name}</td><td>${q.messages_ready}</td><td>${q.messages_unacknowledged}</td>
        <td>${q.consumers}</td><td>${q.message_rate}</td>
        <td>${hasCap('infra.manage') ? `<button class="small" style="color:var(--crit)" data-purge="${q.name}">Purge</button>` : ''}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No queues</div>';
    $$('#infra-queues button[data-purge]').forEach(b => b.onclick = () => {
      confirmModal(`Purge queue "${b.dataset.purge}"?`, 'All messages currently in this queue will be permanently discarded. In-flight scans/tickets tied to those messages will not complete. This cannot be undone.', async () => {
        try { await api(`/api/infra/queues/${encodeURIComponent(b.dataset.purge)}/purge`, {method:'POST', body:'{}'}); toast(`Queue "${b.dataset.purge}" purged`, 'ok'); loadQueues(); }
        catch (e) { toast(e.message, 'err'); }
      });
    });
  } catch (e) { $('#infra-queues').innerHTML = `<div class="empty">${e.message}</div>`; }
}

async function loadEsHealth() {
  try {
    const h = await api('/api/infra/es/health');
    const st = h.status;
    $('#infra-es-health').innerHTML = `
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <span class="stat-chip"><i class="dot ${st==='green'?'up':st==='yellow'?'warn':'down'}"></i> ${st}</span>
        <span class="stat-chip">Nodes <b>${h.number_of_nodes}</b></span>
        <span class="stat-chip">Active shards <b>${h.active_shards}</b></span>
        <span class="stat-chip">Unassigned <b>${h.unassigned_shards}</b></span>
      </div>`;
  } catch (e) { $('#infra-es-health').innerHTML = `<div class="empty">${e.message}</div>`; }
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (n >= 1024 && i < u.length-1) { n/=1024; i++; }
  return n.toFixed(1) + ' ' + u[i];
}

async function loadEsIndices() {
  try {
    const idx = await api('/api/infra/es/indices');
    $('#infra-indices').innerHTML = idx.length ? `<div class="table-wrap"><table class="no-row-click"><thead><tr><th>Index</th><th>Health</th><th>Docs</th><th>Size</th><th></th></tr></thead><tbody>
      ${idx.map(i => `<tr><td class="mono">${i.index}</td><td><span class="badge ${i.health==='green'?'eligible':i.health==='yellow'?'medium':'critical'}">${i.health}</span></td>
        <td>${i.docs_count}</td><td>${fmtBytes(i.store_size)}</td>
        <td>${hasCap('infra.manage') && !i.index.startsWith('.') ? `<button class="small" style="color:var(--crit)" data-delidx="${i.index}">Delete</button>` : ''}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">No indices</div>';
    $$('#infra-indices button[data-delidx]').forEach(b => b.onclick = () => {
      confirmModal(`Delete index "${b.dataset.delidx}"?`, 'Every document in this index will be permanently destroyed, including any pipeline data it holds. This cannot be undone.', async () => {
        try { await api(`/api/infra/es/indices/${encodeURIComponent(b.dataset.delidx)}`, {method:'DELETE'}); toast(`Index "${b.dataset.delidx}" deleted`, 'ok'); loadEsIndices(); }
        catch (e) { toast(e.message, 'err'); }
      });
    });
  } catch (e) { $('#infra-indices').innerHTML = `<div class="empty">${e.message}</div>`; }
}

/* ---------------- init ---------------- */
(async () => {
  if (TOKEN) {
    try { ME = await api('/api/me'); enterApp(); return; } catch (e) {}
  }
  $('#login-view').classList.remove('hidden');
})();