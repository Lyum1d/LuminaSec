/* 统计看板：步骤成功率 / 耗时 / 工具调用 / 目标流量 / 失败归因。
 *
 * 数据来自 `GET /api/console/stats`（**执行侧**聚合）。
 * 「成本侧」（token 用量与费用）在既有 `/api/usage/*` 里，本页刻意不重复 ——
 * 两边是按数据来源分工的两半，不是一回事。
 *
 * 图表一律**自绘 SVG**：不引第三方库、不引 CDN（本机有代理且可能离线，外联资源会直接坏掉）。
 * SVG 里用 `var(--...)` 取色，所以跟随控制台的主题切换，不需要两套配色。
 *
 * ⚠️ 这一页最容易犯的错是**给出一个好看但错的数字**。三处口径必须照搬后端：
 *   · 「成功率」分母只算 done + error（闸门拒绝的不算失败）；
 *   · 耗时分位数已剔除未记录耗时的步骤；
 *   · 空窗口要能解释"为什么没数据"（库里的数据可能早于窗口）。
 * 这些都来自 `notes` 字段，本页**原样显示**，不自己再算一遍。
 */
import { api, esc, toast, setFileHint } from '/console-assets/core.js?v=112';

const WINDOWS = [['7', '最近 7 天'], ['30', '最近 30 天'], ['90', '最近 90 天'],
                 ['365', '最近 365 天'], ['0', '全部历史']];

let WIN = '30';
let D = null;          // 最近一次 /stats 的返回

/* ---------------------------------------------------------------- 小工具 */
function short(s, n) {
  const t = String(s == null ? '' : s);
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

function fmtTs(sec) {
  if (!sec) return '—';
  const d = new Date(sec * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
       + `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1048576) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1073741824) return `${(v / 1048576).toFixed(1)} MB`;
  return `${(v / 1073741824).toFixed(2)} GB`;
}

/* 横向条形图（自绘 SVG）。
 *
 * rows: [{label, n, note}] —— 左标签、中间条、右数字。
 * 为什么不用 canvas 或引图表库：SVG 能吃 CSS 变量、跟随主题，且零依赖（见文件头）。 */
function bars(rows, { tone = 'var(--accent)', unit = '' } = {}) {
  const list = (rows || []).filter((r) => r && Number(r.n) > 0);
  if (!list.length) return '<div class="hint">这个窗口内没有数据。</div>';
  const max = Math.max(...list.map((r) => Number(r.n)));
  const W = 620, LABEL = 172, NUM = 104, ROW = 26, PAD = 4;
  const BAR = W - LABEL - NUM;
  const H = list.length * ROW + PAD * 2;
  const body = list.map((r, i) => {
    const y = PAD + i * ROW;
    const w = Math.max(2, Math.round((Number(r.n) / max) * BAR));
    const right = `${r.n}${unit}` + (r.note ? `  ${r.note}` : '');
    return `<g>
      <text x="0" y="${y + ROW / 2}" dominant-baseline="central" font-size="12"
        fill="var(--text-dim)">${esc(short(r.label, 22))}</text>
      <rect x="${LABEL}" y="${y + 6}" width="${BAR}" height="${ROW - 12}" rx="3"
        fill="var(--panel-2)"/>
      <rect x="${LABEL}" y="${y + 6}" width="${w}" height="${ROW - 12}" rx="3"
        fill="${tone}"/>
      <text x="${W}" y="${y + ROW / 2}" text-anchor="end" dominant-baseline="central"
        font-size="12" fill="var(--text)">${esc(right)}</text>
    </g>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img"
    style="display:block;max-width:${W}px">${body}</svg>`;
}

function kv(label, value) {
  return `<div class="kv"><span>${esc(label)}</span><span>${value}</span></div>`;
}

function card(title, inner) {
  return `<div class="card" style="margin-bottom:12px">
    <h3>${esc(title)}</h3>${inner}</div>`;
}

const STATUS_LABEL = {
  done: '成功 done', error: '失败 error',
  denied: '闸门拒绝 denied', running: '在途 running',
};

/* ---------------------------------------------------------------- 渲染 */
function draw(host) {
  const d = D;
  const st = d.steps || {};
  const el = st.elapsed || {};
  const tf = d.traffic || {};
  const tl = d.tools || {};
  const fnd = d.findings || {};
  const ev = tf.by_event_type || {};

  const rate = st.success_rate;
  const rateTxt = rate == null ? '—' : `${(rate * 100).toFixed(1)}%`;

  const rowsOf = (obj, wrap = (k) => k) =>
    Object.entries(obj || {}).map(([k, n]) => ({ label: wrap(k), n }));

  const statusRows = rowsOf(st.by_status, (k) => STATUS_LABEL[k] || k);
  const attrRows = (d.attribution || []).map((x) => ({ label: x.bucket, n: x.n }));
  const toolRows = (tl.top || []).map((t) => ({
    label: t.name && t.name !== t.alias ? `${t.alias}（${t.name}）` : t.alias,
    n: t.calls, note: t.fail ? `失败 ${t.fail}` : '',
  }));
  const elRows = [
    { label: 'p50（一半步骤快于此）', n: el.p50 || 0 },
    { label: 'p90', n: el.p90 || 0 },
    { label: 'p99', n: el.p99 || 0 },
    { label: 'max（最慢一次）', n: el.max || 0 },
  ];
  const neverTxt = (tl.never_used || []).join('、');
  const staleGate = (d.attribution || []).some((x) => x.bucket.includes('未标注'));

  host.innerHTML = `
    <div class="toolbar">
      <label class="hint">时间窗</label>
      <select id="ckWin" style="width:auto">
        ${WINDOWS.map(([v, t]) =>
          `<option value="${v}"${WIN === v ? ' selected' : ''}>${t}</option>`).join('')}
      </select>
      <span class="grow"></span>
      <span class="hint">${esc(d.window.label)} · 生成于 ${esc(fmtTs(d.generated_at))}
        · 缓存${d.cache.hit ? '命中' : '未命中'}（TTL ${d.cache.ttl}s）</span>
      <button class="ghost sm" id="ckRefresh">强制刷新</button>
    </div>

    ${(d.notes || []).map((n) =>
      `<div class="alert low"><span class="ico">i</span><span>${esc(n)}</span></div>`).join('')}

    <div class="cards">
      <div class="card"><h3>步骤成功率</h3>
        <div class="big">${esc(rateTxt)}</div>
        <div class="sub">${st.judged
          ? `有效判定 ${st.judged} 步（已排除闸门拒绝与在途）`
          : '窗口内还没有可判定的步骤'}</div></div>
      <div class="card"><h3>步骤总数</h3>
        <div class="big">${st.total || 0}</div>
        <div class="sub">闸门拒绝 ${st.denied_by_gate || 0} · 在途 ${st.running || 0}</div></div>
      <div class="card"><h3>目标请求（sent）</h3>
        <div class="big">${ev.sent || 0}</div>
        <div class="sub">settled ${ev.settled || 0} · rejected ${ev.rejected || 0}
          · 入站 ${esc(fmtBytes(tf.bytes_in))}</div></div>
      <div class="card"><h3>漏洞记录</h3>
        <div class="big">${Object.values(fnd.by_severity || {})
          .reduce((a, b) => a + b, 0)}</div>
        <div class="sub">${esc(Object.entries(fnd.by_severity || {})
          .map(([k, n]) => `${k} ${n}`).join(' · ') || '窗口内没有')}</div></div>
      <div class="card"><h3>用过的工具</h3>
        <div class="big">${tl.distinct || 0}</div>
        <div class="sub">可用 ${tl.usable || 0} 个 · <span title="${esc(neverTxt)}">从未调用 ${
          tl.never_used_total || 0} 个</span></div></div>
      <div class="card"><h3>数据跨度（全部历史）</h3>
        <div class="big" style="font-size:15px">
          ${esc(fmtTs(d.span && d.span.first_step_at).slice(0, 10))} →
          ${esc(fmtTs(d.span && d.span.last_step_at).slice(0, 10))}</div>
        <div class="sub">${(d.span || {}).projects || 0} 个项目 ·
          ${(d.span || {}).sessions || 0} 个会话（不受窗口限制）</div></div>
    </div>

    <div class="sec-title">步骤状态分布</div>
    ${card('按 status 分组', bars(statusRows, { tone: 'var(--ok)' }))}

    <div class="sec-title">失败归因分布（含被闸门拒绝）</div>
    ${card('原始取值已归一到有限几个可行动的桶',
      bars(attrRows, { tone: 'var(--danger)' })
      + `<div class="hint" style="margin-top:8px">
           「停手·授权边界 / 目标防护」是<b>必须停手</b>的类别，不是可重试的失败。
           「闸门拒绝·*」是三道闸门（并行子任务 / 任务级约束 / 风险确认）拦下的，属于设计生效。
           ${staleGate ? '带「未标注（旧数据）」的是本版之前写入的步骤 —— 那时还没记录是哪道闸门拦的。' : ''}
         </div>`)}

    <div class="sec-title">耗时分布</div>
    ${card(`分位数（已剔除 ${el.excluded || 0} 条没记录到耗时的步骤）`,
      bars(elRows, { tone: 'var(--accent)', unit: 's' })
      + `<div class="hint" style="margin-top:8px">
           有效样本 ${el.valid || 0} 条。${el.excluded
             ? `⚠️ 有 ${el.excluded} 条 <code>elapsed ≤ 0</code>（没记录到耗时，不是"瞬时完成"），
                已排除 —— 混进来的话 p50 会被拉到 0，而均值看着还正常。`
             : ''}
         </div>`)}

    <div class="sec-title">工具调用频次 TOP ${(tl.top || []).length}</div>
    ${card(`窗口内用过 ${tl.distinct || 0} 种工具`,
      bars(toolRows, { tone: 'var(--accent)' })
      + ((tl.never_used || []).length
        ? `<div class="hint" style="margin-top:8px">
             可用但从未被调用（共 ${tl.never_used_total} 个，列前 ${tl.never_used.length} 个）：
             <span class="mono">${esc(neverTxt)}</span><br>
             排障提示：若你以为某个工具在用却没出现，先确认它没被禁用、文件没缺
             （「工具与分级」页），以及是否压根没进模型清单（schema 有 40 条上限）。
           </div>` : ''))}

    <div class="sec-title">目标流量</div>
    ${card('事件类型', bars(rowsOf(ev), { tone: 'var(--accent)' }))}
    ${card('网络层错误类型', bars(rowsOf(tf.by_error_type), { tone: 'var(--danger)' }))}
    ${Object.keys(tf.by_status_code || {}).length
      ? card('响应状态码', bars(rowsOf(tf.by_status_code, (k) => `HTTP ${k}`),
                                { tone: 'var(--accent)' })) : ''}
    ${Object.keys((d.flow || {}).verdicts || {}).length
      ? card('流程绕过判定（flow_runs）', bars(rowsOf((d.flow || {}).verdicts),
                                              { tone: 'var(--warn)' })) : ''}
    ${Object.keys(fnd.by_severity || {}).length
      ? card('漏洞严重度', bars(rowsOf(fnd.by_severity), { tone: 'var(--warn)' })) : ''}

    <div class="sec-title">口径（这些决定数字怎么读）</div>
    <div class="card">
      ${kv('成功率分母', 'done + error（<b>不含</b>闸门拒绝与在途）')}
      ${kv('耗时统计', '只算 <code>elapsed &gt; 0</code> 的步骤')}
      ${kv('时间窗', '<code>days=0</code> = 全部历史；上限 365 天')}
      ${kv('缓存', `${d.cache.ttl} 秒内存缓存（同一时间窗共用）；「强制刷新」可跳过`)}
      ${kv('成本侧（token / 费用）', '不在这里 —— 见 <code>/api/usage/summary</code> 与既有用量界面')}
    </div>`;
}

/* ---------------------------------------------------------------- 交互 */
async function load(host, { refresh = false } = {}) {
  const q = `/stats?days=${encodeURIComponent(WIN)}` + (refresh ? '&refresh=1' : '');
  try {
    D = await api(q);
  } catch (e) {
    toast(e.message, 'err');
    return;
  }
  setFileHint(`stats · ${D.window.label} · 缓存${D.cache.hit ? '命中' : '未命中'}`);
  draw(host);
  const sel = document.getElementById('ckWin');
  if (sel) sel.onchange = (e) => { WIN = e.target.value; load(host); };
  const rb = document.getElementById('ckRefresh');
  if (rb) rb.onclick = () => load(host, { refresh: true });
}

export async function render(host) {
  host.innerHTML = '<div class="empty">正在汇总…</div>';
  await load(host);
}
