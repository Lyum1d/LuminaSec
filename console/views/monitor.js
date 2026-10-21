/* 实时监控：跨项目看「现在有哪些运行、各自什么状态、谁在等我确认」。
 *
 * 入口列表来自 `GET /api/console/runs`（v112）。
 *
 * ⚠️ 这一页**只读列表，绝不新造确认/取消通道**：
 * 确认的双闸门（一次性 token + 绑定步骤 step_id + L3 的书面授权确认 auth_ack）是安全核心，
 * 见 `app/main.py` 里 `/api/sessions/{sid}/confirm` 的注释。控制台只做
 * 「换个界面调用同一个接口」—— 重写一遍就等于绕过它。所以这里的按钮全部透传既有端点：
 *   · 确认 / 拒绝 → POST /api/sessions/{sid}/confirm
 *   · 取消        → POST /api/sessions/{sid}/cancel
 *   · 详情（步骤表）→ GET /api/sessions/{sid}
 *
 * ⚠️ 「正在取消」读的是后端 `cancelling`（来自取消事件），**不是** state ——
 * `/cancel` 只置一个事件，state 要跑到下一个步骤边界才变。只看 state 会把"取消中"
 * 显示成正常的"执行中"，用户以为没生效而反复点。
 *
 * ⚠️ 不要引入 SSE 事件里的 `second` 字段当风险等级：它的含义是"第几轮"，
 * 与 `/api/sessions/{sid}` 里同名的 `second`（"是否需要双轮确认"）**同名不同义**，
 * 本项目曾有看板脚本因此把 L3 印成 L2。后端也刻意不返回它。
 */
import { api, esc, toast, setFileHint } from '/console-assets/core.js?v=112';

const REFRESH_MS = 5000;

let D = null;            // 最近一次 /runs
let SEL = '';            // 选中的 session_id
let DETAIL = null;       // 选中会话的 /api/sessions/{sid}
let ONLY_ACTIVE = true;
let AUTO = true;
let TIMER = null;

/* ---------------------------------------------------------------- 小工具 */
function fmtTs(sec) {
  if (!sec) return '—';
  const d = new Date(sec * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getMonth() + 1}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function statePill(x) {
  if (x.cancelling) return '<span class="pill warn">取消中</span>';
  const kind = { awaiting_confirm: 'warn', running: 'ok', idle: 'dim',
                 done: 'dim', error: 'bad', interrupted: 'bad' }[x.state] || 'dim';
  return `<span class="pill ${kind}">${esc(x.state_label || x.state)}</span>`;
}

function stopTimer() {
  if (TIMER) { clearInterval(TIMER); TIMER = null; }
}

/* 自动刷新：**每 tick 先确认这个视图还在页面上**。
   `goto()` 只换 `viewHost.innerHTML`，不会通知视图清理 —— 不检查的话，
   切走之后定时器还在跑，每 5 秒去写一个已经脱离文档的节点（白耗 + 潜在报错）。 */
function startTimer(host) {
  stopTimer();
  if (!AUTO) return;
  TIMER = setInterval(() => {
    if (!document.body.contains(host)) { stopTimer(); return; }
    // 有未提交的确认输入（勾了授权确认 / 填了参数）就跳过这一轮，
    // 否则刷新会把用户正在操作的表单抹掉。
    const ack = document.getElementById('moAck');
    const argsEl = document.getElementById('moArgs');
    if ((ack && ack.checked) || (argsEl && argsEl.value.trim())) {
      const hint = document.getElementById('moPause');
      if (hint) hint.textContent = '（已暂停刷新：有未提交的确认输入）';
      return;
    }
    load(host, { withDetail: true });
  }, REFRESH_MS);
}

/* ---------------------------------------------------------------- 渲染 */
function rowsHtml(items) {
  if (!items.length) return '<tr><td colspan="7" class="empty">没有符合条件的运行</td></tr>';
  return items.map((x) => `<tr data-sid="${esc(x.session_id)}"
      class="${SEL === x.session_id ? 'review' : ''}">
    <td>${statePill(x)}
      ${x.urgent && x.state === 'awaiting_confirm'
        ? '<div class="hint">等你确认</div>' : ''}
      ${x.urgent && x.state === 'interrupted' ? '<div class="hint">可续聊</div>' : ''}</td>
    <td>${esc(x.project_name || x.project_id || '—')}
      ${x.subtask ? '<span class="pill dim">子任务</span>' : ''}</td>
    <td>${esc(x.title || '（未命名）')}
      <div class="hint mono">${esc(x.session_id)} · ${esc(x.mode)}</div></td>
    <td class="mono">${esc(x.target || '—')}</td>
    <td class="mono">${x.steps.total}
      ${x.steps.error ? `<span class="pill bad">${x.steps.error} 失败</span>` : ''}
      ${x.steps.denied ? `<span class="pill dim">${x.steps.denied} 拒绝</span>` : ''}</td>
    <td class="hint mono">${esc(fmtTs(x.created_at))}
      ${x.live ? '' : '<div class="hint">仅在库</div>'}</td>
    <td class="row-actions">
      <button class="ghost sm" data-act="look" data-sid="${esc(x.session_id)}">查看</button>
      <button class="ghost sm" data-act="cancel" data-sid="${esc(x.session_id)}">取消</button>
    </td>
  </tr>`).join('');
}

function pendingHtml(x, d) {
  const p = x.pending || {};
  if (!x.awaiting_confirmation) return '';
  const lg = d && d.steps ? d.steps : [];
  const step = lg.find((s) => s.id === p.step_id) || {};
  return `<div class="sec-title">正在等人工确认</div>
    <div class="card">
      <div class="alert mid"><span class="ico">!</span><span>
        Agent 停在这一步等你决定。<b>不点它就不会继续</b>（超时后该步作废，
        <b>不会自动放行</b>）。
      </span></div>
      <div class="kv"><span>工具</span><span>${esc(p.tool_name || p.tool_alias)}</span></div>
      <div class="kv"><span>目标</span><span>${esc(p.target || '—')}</span></div>
      <div class="kv"><span>风险等级</span><span>
        <span class="pill ${p.risk_level === 'L3' ? 'bad' : 'warn'}">${esc(p.risk_level || '?')}</span>
        ${p.requires_double_confirm ? ' <span class="pill bad">需双轮确认</span>' : ''}</span></div>
      ${step.args ? `<div class="kv"><span>原参数</span>
        <span class="mono">${esc(step.args)}</span></div>` : ''}
      <label class="hint" style="display:block;margin-top:8px">
        改参数（留空 = 按原参数执行）
      </label>
      <input id="moArgs" placeholder="例如 -X GET --timeout 15">
      <label class="ack" style="margin-top:8px;display:flex">
        <input type="checkbox" id="moAck">
        <span>已获书面授权（<b>L3 必须勾选</b>；服务端强制校验，不勾会被 400 拒）</span>
      </label>
      <div class="toolbar" style="margin-top:10px">
        <button class="primary" id="moApprove">批准执行</button>
        <button class="danger" id="moReject">拒绝</button>
        <span class="grow"></span>
        <span class="hint" id="moPause"></span>
      </div>
    </div>`;
}

function detailHtml(x, d) {
  if (!SEL) return '<div class="hint">点上面任意一行的「查看」看步骤明细。</div>';
  if (!x) return '<div class="hint">这个会话已不在列表里（可能超出回看条数）。</div>';
  const steps = (d && d.steps) || [];
  return `
    <div class="sec-title">会话详情
      <span class="hint">${esc(x.session_id)}</span></div>
    <div class="card">
      <div class="kv"><span>状态</span><span>${statePill(x)}</span></div>
      <div class="kv"><span>项目 / 目标</span><span>${esc(x.project_name || '—')} · ${esc(x.target || '—')}</span></div>
      <div class="kv"><span>结论摘要</span><span class="hint">${esc(x.summary || '（无）')}</span></div>
      ${x.parent_id ? `<div class="kv"><span>父会话</span><span class="mono">${esc(x.parent_id)}</span></div>` : ''}
    </div>
    ${pendingHtml(x, d)}
    <div class="sec-title">步骤（最近 ${steps.length} 条）</div>
    <div class="table-wrap" style="max-height:40vh"><table>
      <thead><tr><th style="width:12%">状态</th><th style="width:16%">工具</th>
        <th style="width:10%">风险</th><th style="width:22%">目标</th>
        <th style="width:8%">耗时</th><th>输出（截断）</th></tr></thead>
      <tbody>${steps.slice().reverse().map((s) => `<tr>
        <td>${esc(s.status || '')}${s.attribution
          ? `<div class="hint">${esc(s.attribution)}</div>` : ''}</td>
        <td class="mono">${esc(s.tool_alias || s.tool_name || '')}</td>
        <td class="mono">${esc((s.risk || {}).level || '')}</td>
        <td class="mono">${esc(s.target || '')}</td>
        <td class="mono">${s.elapsed != null ? esc(String(Math.round(s.elapsed))) + 's' : '—'}</td>
        <td class="hint mono">${esc(String(s.output || '').slice(0, 160))}</td>
      </tr>`).join('') || '<tr><td colspan="6" class="empty">还没有步骤</td></tr>'}</tbody>
    </table></div>`;
}

function draw(host) {
  const c = D.counts || {};
  const w = D.window || {};
  const sel = (D.items || []).find((x) => x.session_id === SEL) || null;
  host.innerHTML = `
    <div class="toolbar">
      <label class="chk"><input type="checkbox" id="moActive"${ONLY_ACTIVE ? ' checked' : ''}>
        只看活跃</label>
      <label class="chk"><input type="checkbox" id="moAuto"${AUTO ? ' checked' : ''}>
        自动刷新（${REFRESH_MS / 1000}s）</label>
      <span class="grow"></span>
      <span class="hint">共 ${c.total || 0} 条 · 内存中 ${c.live || 0}
        · 待确认 <b>${c.awaiting || 0}</b> · 中断 ${c.interrupted || 0}
        · 取消中 ${c.cancelling || 0}</span>
      <button class="ghost sm" id="moReload">刷新</button>
    </div>

    ${(D.notes || []).map((n) =>
      `<div class="alert ${n.includes('等着你确认') ? 'mid' : 'low'}">`
      + `<span class="ico">${n.includes('等着你确认') ? '!' : 'i'}</span>`
      + `<span>${esc(n)}</span></div>`).join('')}

    <div class="table-wrap" style="max-height:44vh"><table>
      <thead><tr><th style="width:13%">状态</th><th style="width:14%">项目</th>
        <th style="width:22%">标题</th><th style="width:15%">目标</th>
        <th style="width:12%">步骤</th><th style="width:11%">创建</th><th>操作</th></tr></thead>
      <tbody>${rowsHtml(D.items || [])}</tbody>
    </table></div>

    ${detailHtml(sel, DETAIL)}`;

  document.getElementById('moActive').onchange = (e) => {
    ONLY_ACTIVE = e.target.checked; load(host);
  };
  document.getElementById('moAuto').onchange = (e) => {
    AUTO = e.target.checked; startTimer(host); draw(host);
  };
  document.getElementById('moReload').onclick = () => load(host);
  host.querySelectorAll('button[data-act=look]').forEach((b) => {
    b.onclick = () => { SEL = b.dataset.sid; loadDetail(host); };
  });
  host.querySelectorAll('button[data-act=cancel]').forEach((b) => {
    b.onclick = () => doCancel(host, b.dataset.sid);
  });
  const ap = document.getElementById('moApprove');
  if (ap) ap.onclick = () => doConfirm(host, sel, true);
  const rj = document.getElementById('moReject');
  if (rj) rj.onclick = () => doConfirm(host, sel, false);
}

/* ---------------------------------------------------------------- 数据 */
async function load(host, { withDetail = false } = {}) {
  const q = `/runs?active=${ONLY_ACTIVE ? 1 : 0}`;
  try {
    D = await api(q);
  } catch (e) {
    toast(e.message, 'err');
    return;
  }
  // 详情也要一起刷：只刷列表会让页面"半新半旧" —— 待确认卡片是新的（它读 /runs），
  // 而下面的步骤表还是旧的，看起来像数据对不上。
  if (withDetail && SEL) {
    try {
      DETAIL = await api(`/api/sessions/${encodeURIComponent(SEL)}`);
    } catch (e) { /* 详情取不到不阻断列表 */ }
  }
  setFileHint(`runs · ${D.counts.total} 条 · 待确认 ${D.counts.awaiting}`);
  draw(host);
}

async function loadDetail(host) {
  if (!SEL) return;
  try {
    DETAIL = await api(`/api/sessions/${encodeURIComponent(SEL)}`);
  } catch (e) {
    DETAIL = null;
    toast(`读取会话详情失败：${e.message}`, 'err');
  }
  draw(host);
}

async function doCancel(host, sid) {
  try {
    await api(`/api/sessions/${encodeURIComponent(sid)}/cancel`, { method: 'POST' });
    toast('已请求取消：当前步骤会跑完，随后收尾并沉淀半程成果。', 'ok');
  } catch (e) {
    // 409 = 该状态本来就无需取消（空闲/已结束）—— 把后端的原话转达，别自己编。
    toast(e.message, 'err');
  }
  await load(host);
  if (SEL === sid) await loadDetail(host);
}

async function doConfirm(host, x, approved) {
  if (!x || !x.pending) { toast('这一步没有待确认的动作（可能已被处理）。', 'err'); return; }
  const body = {
    approved,
    step_id: x.pending.step_id,        // 绑定步骤：不绑会被后端 400/409 挡下
    token: x.pending.token,            // 一次性令牌，原样回传
    auth_ack: approved && !!(document.getElementById('moAck') || {}).checked,
  };
  const args = ((document.getElementById('moArgs') || {}).value || '').trim();
  if (args) body.args = args;          // 留空表示"按原参数执行"（None）
  if (approved && x.pending.requires_double_confirm && !body.auth_ack) {
    toast('这一步是 L3：必须勾选「已获书面授权」才能批准（服务端强制）。', 'err');
    return;
  }
  try {
    await api(`/api/sessions/${encodeURIComponent(x.session_id)}/confirm`,
              { method: 'POST', body });
    toast(approved ? '已批准，Agent 会继续执行这一步。' : '已拒绝，Agent 会收到拒绝并调整方向。', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  }
  await load(host);
  await loadDetail(host);
}

export async function render(host) {
  stopTimer();
  host.innerHTML = '<div class="empty">正在读取运行列表…</div>';
  await load(host);
  startTimer(host);
}
