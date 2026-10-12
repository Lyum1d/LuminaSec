/* 工具与分级：查/改 197 个工具的分级、禁用、超时、caps、旗标白名单。
 *
 * 写入面是**两个文件、两种键口径**：
 *   · 分级（level/reason）→ data/risk_grades.json，键是**工具名**
 *   · 禁用/超时/caps/旗标 → data/tool_overrides.json，键是 **alias**
 * 所以后端会一起做乐观锁（两个文件哈希都核对）与失败回滚。
 */
import { api, esc, modal, toast, alertBox, reload, setFileHint }
  from '/console-assets/core.js?v=112';

let ALL = [];          // 全量工具
let META = {};         // files / levels / editable_fields
const FILTER = { q: '', level: '', only: '' };

const LEVEL_KIND = { L0: 'ok', L1: 'dim', L2: 'warn', L3: 'bad' };

function levelPill(t) {
  // ⚠️ 不可编排的工具**不参与分级**（registry 只在 `if scriptable` 时从
  // risk_grades 取 level），它显示的 L2 只是数据类默认值。在这里照常显示等级
  // 会让人以为「有 309 个 L2 工具需要审」—— 实际其中大部分根本没有分级这回事。
  // 所以非可编排的显示 `—`，把「等级对它们无意义」直接说出来。
  if (!t.scriptable) {
    return '<span class="pill dim" title="不可编排（图形界面/网页工具），不参与分级">—</span>';
  }
  return `<span class="pill ${LEVEL_KIND[t.level] || 'dim'}">${esc(t.level || '?')}</span>`;
}

function rows() {
  const q = FILTER.q.trim().toLowerCase();
  return ALL.filter((t) => {
    if (FILTER.level && t.level !== FILTER.level) return false;
    if (FILTER.only === 'disabled' && !t.disabled) return false;
    if (FILTER.only === 'interactive' && !t.interactive) return false;
    if (FILTER.only === 'nomodel' && t.in_model_list) return false;
    if (FILTER.only === 'noexec' && t.executable) return false;
    if (!q) return true;
    return (t.alias + ' ' + t.name + ' ' + t.category).toLowerCase().includes(q);
  });
}

function tableHtml(list) {
  const body = list.map((t) => `<tr data-alias="${esc(t.alias)}">
    <td class="mono">${esc(t.alias)}</td>
    <td>${esc(t.name)}</td>
    <td>${levelPill(t)}</td>
    <td>${t.scriptable ? '<span class="pill ok">可编排</span>'
        : '<span class="pill dim">仅启动</span>'}</td>
    <td>${t.disabled ? '<span class="pill bad">已禁用</span>' : ''}
        ${t.interactive ? '<span class="pill warn">交互式·已剔除</span>' : ''}
        ${!t.executable && t.scriptable ? '<span class="pill bad">文件缺失</span>' : ''}
        ${!t.in_model_list && !t.disabled && !t.interactive && t.scriptable
          ? '<span class="pill dim">不在清单</span>' : ''}</td>
    <td class="mono">${esc((t.caps || []).join(',') || '-')}</td>
    <td class="mono">${t.timeout || '-'}</td>
    <td class="row-actions">
      <button class="ghost sm" data-act="edit" data-alias="${esc(t.alias)}">编辑</button>
    </td>
  </tr>`).join('');
  return `<div class="table-wrap" style="max-height:62vh"><table>
    <thead><tr><th style="width:13%">alias</th><th style="width:18%">名称</th>
      <th style="width:7%">分级</th><th style="width:9%">可编排</th>
      <th style="width:26%">状态</th><th style="width:12%">caps</th>
      <th style="width:7%">超时</th><th>操作</th></tr></thead>
    <tbody>${body || '<tr><td colspan="8" class="empty">没有符合条件的工具</td></tr>'}</tbody>
  </table></div>`;
}

async function openEdit(alias) {
  const t = ALL.find((x) => x.alias === alias);
  if (!t) return;
  let detail = { caveat: '', description: '', risk_reason: '' };
  try { detail = await api('/tools/detail', { method: 'POST', body: { alias } }); }
  catch (e) { /* 详情取不到不阻断编辑 */ }

  const lvOpts = (META.levels || []).map((l) =>
    `<option value="${esc(l.level)}"${l.level === t.level ? ' selected' : ''}>`
    + `${esc(l.level)} · ${esc(l.name)}（${esc(l.policy)}）</option>`).join('');

  const ok = await modal({
    title: `编辑工具：${t.alias}（${t.name}）`,
    okText: '预览改动', okClass: 'primary', showOk: true,
    bodyHtml: `
      <div class="alert low"><span class="ico">i</span><span>
        分级写 <code>risk_grades.json</code>（按工具名）；其余写
        <code>tool_overrides.json</code>（按 alias）。提交后会自动重载 registry。</span></div>
      ${!t.scriptable ? alertBox('mid',
        '该工具不可编排（图形界面/网页工具），分级只对可编排工具生效 —— 改它不会有任何效果。')
        : ''}
      <div class="sec-title">分级</div>
      <label class="hint">风险等级</label>
      <select id="edLevel">${lvOpts}</select>
      <label class="hint" style="display:block;margin-top:8px">分级依据（必填，留痕）</label>
      <input id="edLevelReason" value="${esc(t.level_reason || '')}">

      <div class="sec-title">覆写</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <div><label class="hint">禁用</label>
          <select id="edDisabled">
            <option value="keep">（不改）</option>
            <option value="true"${t.disabled ? ' selected' : ''}>禁用</option>
            <option value="false"${t.has_override && !t.disabled ? ' selected' : ''}>启用</option>
          </select></div>
        <div><label class="hint">单工具超时(秒，0=用全局)</label>
          <input id="edTimeout" value="${esc(t.timeout || '')}" placeholder="留空=不改"></div>
      </div>
      <label class="hint" style="display:block;margin-top:8px">禁用理由（禁用时必填）</label>
      <input id="edReason" value="${esc(t.disabled_reason || '')}">
      <label class="hint" style="display:block;margin-top:8px">能力标签 caps（逗号分隔）</label>
      <input id="edCaps" value="${esc((t.caps || []).join(','))}" placeholder="bruteforce,scan">
      <label class="hint" style="display:block;margin-top:8px">target 形态</label>
      <select id="edTT">
        ${['', 'url', 'domain', 'host'].map((v) =>
          `<option value="${v}"${t.target_type === v ? ' selected' : ''}>${v || '（不声明）'}</option>`).join('')}
      </select>
      ${detail.description ? `<div class="sec-title">工具说明</div>
        <div class="hint">${esc(detail.description)}</div>` : ''}
      ${detail.caveat ? `<div class="sec-title">caveat（会写进给模型的说明）</div>
        <div class="mono hint" style="white-space:pre-wrap">${esc(detail.caveat)}</div>` : ''}`,
  });
  if (!ok) return;

  // ---- 组装请求：只为「真的改了」的字段赋值 ----
  const overrides = {};
  const dis = document.getElementById('edDisabled').value;
  if (dis !== 'keep') overrides.disabled = dis === 'true';
  const to = document.getElementById('edTimeout').value.trim();
  if (to !== '') overrides.timeout = Number(to);
  const rs = document.getElementById('edReason').value.trim();
  if (rs !== (t.disabled_reason || '')) overrides.reason = rs;
  const caps = document.getElementById('edCaps').value.split(',').map((x) => x.trim())
    .filter(Boolean);
  if (caps.join(',') !== (t.caps || []).join(',')) overrides.caps = caps;
  const tt = document.getElementById('edTT').value;
  if (tt !== (t.target_type || '')) overrides.target_type = tt;

  const grade = { level: document.getElementById('edLevel').value,
                  reason: document.getElementById('edLevelReason').value.trim() };

  const body = { alias };
  if (Object.keys(overrides).length) body.overrides = overrides;
  if (grade.level !== t.level || grade.reason !== (t.level_reason || '')) body.grade = grade;
  if (!body.overrides && !body.grade) { toast('没有任何改动。'); return; }

  let prev;
  try { prev = await api('/tools/preview', { method: 'POST', body }); }
  catch (e) { toast(e.message, 'err'); return; }

  const diffRows = prev.diff.map((d) => `<div class="row">`
    + `${esc(d.file)} · ${esc(d.key)}：${esc(String(d.before))} → `
    + `<b>${esc(String(d.after))}</b></div>`).join('')
    || '<div class="row same">（无字段变化）</div>';

  const go = await modal({
    title: '确认改动工具配置',
    okText: '确认提交', okClass: 'danger', requireAck: true,
    ackText: '我确认已核对上面每一项改动（分级会直接影响自动执行与确认次数）。',
    bodyHtml: `<div class="kv"><span>风险等级</span><span>`
      + `<span class="pill ${prev.level === 'high' ? 'bad' : 'warn'}">${esc(prev.level)}</span>`
      + `</span></div>`
      + `<div class="kv"><span>将写入</span><span class="mono">${esc((prev.files || []).join('、'))}</span></div>`
      + `<div class="sec-title">字段差异</div><div class="diff">${diffRows}</div>`,
  });
  if (!go) return;

  try {
    const r = await api('/tools/commit', {
      method: 'POST',
      body: { ...body, confirm_token: prev.confirm_token,
              expect_sha256: prev.expect_sha256 },
    });
    toast(`已写入 ${(r.written || []).join('、')}`
        + (r.reload && r.reload.actions ? '；' + r.reload.actions.join('；') : ''), 'ok');
    await reload();
  } catch (e) { toast(e.message, 'err'); }
}

function draw(host) {
  const list = rows();
  host.innerHTML = `
    <div class="toolbar">
      <input id="fltQ" placeholder="搜索 alias / 名称 / 分类" style="width:220px"
             value="${esc(FILTER.q)}">
      <select id="fltLevel" style="width:auto">
        <option value="">全部分级</option>
        ${(META.levels || []).map((l) => `<option value="${esc(l.level)}"${
          FILTER.level === l.level ? ' selected' : ''}>${esc(l.level)} · ${esc(l.name)}</option>`).join('')}
      </select>
      <select id="fltOnly" style="width:auto">
        ${[['', '全部'], ['disabled', '仅已禁用'], ['interactive', '仅交互式（已剔除）'],
           ['nomodel', '仅不在模型清单'], ['noexec', '仅文件缺失']]
          .map(([v, t]) => `<option value="${v}"${FILTER.only === v ? ' selected' : ''}>${t}</option>`).join('')}
      </select>
      <span class="grow"></span>
      <span class="hint">${list.length} / ${ALL.length} 个工具</span>
      <button class="ghost sm" id="btnReload">重新读取</button>
    </div>
    ${tableHtml(list)}
    <div class="sec-title">改完会怎样</div>
    <div class="hint">
      · <strong>分级</strong>决定自动执行与确认次数：L0/L1 自动、L2 需一次确认、L3 需双轮确认。<br>
      · <strong>禁用</strong>让工具不进模型清单（必须填理由）；<strong>caps</strong> 供任务级约束闸门用
      （任务书声明「不做字典爆破」时，带 <code>bruteforce</code> 的工具会被直接拒绝）。<br>
      · 提交后控制台会<strong>自动重载 registry 并回显结果</strong> —— 这一步是必要的：
      registry 有缓存，只写文件不重载就会出现「改了没生效」。
    </div>`;

  document.getElementById('fltQ').oninput = (e) => { FILTER.q = e.target.value; draw(host); };
  document.getElementById('fltLevel').onchange = (e) => { FILTER.level = e.target.value; draw(host); };
  document.getElementById('fltOnly').onchange = (e) => { FILTER.only = e.target.value; draw(host); };
  document.getElementById('btnReload').onclick = () => reload();
  host.querySelectorAll('button[data-act=edit]').forEach((b) => {
    b.onclick = () => openEdit(b.dataset.alias);
  });
}

export async function render(host) {
  const d = await api('/tools');
  ALL = d.items || [];
  META = d;
  setFileHint(`grades ${d.files.grades.sha256_short || '-'} / `
            + `overrides ${d.files.overrides.sha256_short || '-'}`);
  draw(host);
}
