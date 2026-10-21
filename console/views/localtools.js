/* 本地工具（v110）：用户指定本机的一个目录 → 程序自动识别里面的工具 → 并入工具箱。
 *
 * 为什么要有这一页：工具来源原先只有「某个第三方工具箱的 config/tools.json」，
 * 于是没装那个工具箱的人**一个外部工具都没有**，也没法用自己的工具。
 * 现在工具来源有三类：外部工具箱清单（可选）/ 内置能力（进程内）/ **本机自备工具（本页）**。
 *
 * 两个刻意的设计：
 *   1. **不手填工具清单** —— 只填目录，识别由程序做（扩展名 + 目录结构 + 跳过规则）。
 *      所以页面主体是"选目录 → 看识别结果 → 勾掉不要的 → 保存"。
 *   2. **风险分级/闸门不在这里改** —— 那是「工具与分级」页的事，
 *      `risk_grades.json`（按工具名）与 `tool_overrides.json`（按 alias）对自备工具同样生效。
 *      这正是"与外部工具同一套闸门"的落点：共用同一份配置，不是各来一套。
 */
import { api, esc, modal, toast, alertBox, reload, setFileHint }
  from '/console-assets/core.js?v=112';

let META = {};        // /localtools 的元信息（支持的扩展名、阈值…）
let ROOTS = [];       // 已添加的目录（服务端现状）
let DRAFT = null;     // 正在编辑的目录（草稿；识别结果挂在 DRAFT._scan）

/* 需要**内嵌 HTML**（加粗 / 代码样式）时的告警块。
 *
 * 为什么不用 `alertBox()`：它会对文本做 `esc()` —— 传 HTML 进去会被转义成
 * 字面量 `<b>`。项目既有页面的做法就是这种情况手写块（见 rules.js / scope.js），
 * 这里统一成一个 helper，免得每处都手抄一遍结构。
 * ⚠️ 所有插进来的数据都必须自己 `esc()`。 */
function note(level, html) {
  const ico = { high: '!', mid: '!', low: 'i' }[level] || 'i';
  return `<div class="alert ${level}"><span class="ico">${ico}</span>`
       + `<span>${html}</span></div>`;
}

/* ---------------------------------------------------------------- 列表页 */
function rootPill(r) {
  if (!r.exists) return '<span class="pill bad">目录不可用</span>';
  if (!r.enabled) return '<span class="pill dim">已停用</span>';
  const n = (r.stats || {}).included || 0;
  if (!n) return '<span class="pill warn">没识别到工具</span>';
  return `<span class="pill ok">${n} 个工具</span>`;
}

function rootsTable() {
  const body = ROOTS.map((r, i) => {
    const st = r.stats || {};
    const byType = Object.entries(st.by_type || {})
      .map(([k, v]) => `${esc(k)}×${v}`).join(' ');
    return `<tr data-i="${i}">
      <td class="mono">${esc(r.path)}</td>
      <td>${esc(r.label)}<div class="hint">${esc(r.category || '')}</div></td>
      <td>${rootPill(r)}${st.excluded ? `<div class="hint">已排除 ${st.excluded} 个</div>` : ''}
          <div class="hint mono">${byType}</div></td>
      <td>${r.truncated ? '<span class="pill warn">截断</span>' : ''}
          ${r.hint ? '<span class="pill dim" title="' + esc(r.hint) + '">有快捷方式</span>' : ''}
          ${r.problem ? `<div class="hint">${esc(r.problem)}</div>` : ''}</td>
      <td class="row-actions">
        <button class="ghost sm" data-act="edit" data-i="${i}">编辑</button>
        <button class="ghost sm" data-act="del" data-i="${i}">移除</button>
      </td>
    </tr>`;
  }).join('');
  return `<div class="table-wrap"><table>
    <thead><tr><th style="width:34%">目录</th><th style="width:14%">显示名</th>
      <th style="width:22%">识别结果</th><th style="width:16%">状态</th><th>操作</th></tr></thead>
    <tbody>${body || `<tr><td colspan="5" class="empty">还没有添加任何目录</td></tr>`}</tbody>
  </table></div>`;
}

/* ---------------------------------------------------------------- 编辑页 */
function draftForm() {
  const d = DRAFT;
  return `
    <div class="toolbar">
      <button class="ghost sm" id="ltBack">← 返回列表</button>
      <span class="grow"></span>
      <span class="hint">${d.path ? '正在编辑' : '新增一个工具目录'}</span>
    </div>

    ${note('low',
      '只填<b>目录</b>，工具由程序识别（按扩展名 + 目录结构）。识别只读文件系统，'
      + '<b>不会执行任何程序</b>。')}

    <div class="sec-title">1. 选目录</div>
    <label class="hint">目录（绝对路径）</label>
    <div style="display:flex;gap:8px">
      <input id="ltPath" value="${esc(d.path)}" placeholder="例如 E:\\我的工具"
             style="flex:1" ${d.path ? 'readonly' : ''}>
      <button class="ghost" id="ltBrowse" ${d.path ? 'disabled' : ''}>浏览…</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-top:10px">
      <div><label class="hint">显示名</label>
        <input id="ltLabel" value="${esc(d.label)}" placeholder="留空=取目录名"></div>
      <div><label class="hint">默认分类</label>
        <input id="ltCat" value="${esc(d.category)}" placeholder="留空=跟随显示名"></div>
      <div><label class="hint">.jar 的 java 版本</label>
        <select id="ltJava">
          ${['JAVA8', 'JAVA11'].map((v) =>
            `<option value="${v}"${d.java === v ? ' selected' : ''}>${v}</option>`).join('')}
        </select></div>
    </div>
    <div style="margin-top:10px">
      <label class="hint">备注（给自己看）</label>
      <input id="ltNote" value="${esc(d.note)}">
    </div>
    <div class="toolbar" style="margin-top:12px">
      <button class="primary" id="ltScan">识别这个目录</button>
      <span class="hint" id="ltScanMsg"></span>
    </div>

    <div id="ltResult"></div>

    <div class="sec-title">识别规则</div>
    <div class="hint">
      按扩展名识别：${Object.entries(META.ext_types || {})
        .map(([k, v]) => `<code>${esc(k)}</code>→${esc(v)}`).join('、')}
      （另有 <code>.url</code> 收作网页书签，不进 Agent 清单）。<br>
      跳过含 <code>帮助</code>/<code>说明</code>/<code>node_modules</code> 等目录，
      隐藏目录（以 <code>.</code> 开头）与软链/目录联接也不跟随；
      最多深入 ${META.max_depth} 层。<br>
      ⚠️ ${esc((META.shortcut_exts || []).join('、'))} 快捷方式**不纳入**（目标不在本目录内）——
      若那些才是你要的工具，请选它们目标所在的目录。
    </div>`;
}

function resultsTable(scan) {
  if (!scan.exists) {
    return note('mid', `目录不可用：${esc(scan.problem || '')}`);
  }
  const rows = (scan.tools || []).map((t, i) => `<tr data-i="${i}"
      class="${t.excluded ? 'same' : ''}">
    <td><input type="checkbox" data-act="inc" data-i="${i}"
        ${t.excluded ? '' : 'checked'}></td>
    <td class="mono">${esc(t.rel_path)}</td>
    <td>${esc(t.name)}</td>
    <td><input data-act="alias" data-i="${i}" value="${esc(t.alias || '')}"
        style="width:130px;${t.needs_alias ? 'border-color:var(--warn)' : ''}"
        class="mono" title="${t.needs_alias
          ? '自动推导不出有意义的名字（中文文件名推不出 ASCII 别名）—— 建议在这里起一个英文名'
          : ''}"></td>
    <td>${esc(t.type)}</td>
    <td class="hint">${esc(t.category)}</td>
    <td class="hint mono">${t.url ? esc(t.url) : (t.size ? Math.ceil(t.size / 1024) + 'K' : '')}</td>
  </tr>`).join('');
  const st = scan.stats || {};
  const needAlias = (scan.tools || []).filter((t) => t.needs_alias && !t.excluded).length;
  const warnAlias = needAlias
    ? note('mid', `有 <b>${needAlias}</b> 个工具的别名是自动兜底出来的占位名`
        + `（<code>tool</code>/<code>tool_2</code> 这种）。它对模型选工具<b>没有帮助</b> ——`
        + `模型只能靠描述去猜。建议在上表「别名」列里给它们起个英文名`
        + `（例如 <code>myscan</code>、<code>webdir_scan</code>）。`)
    : '';
  const warn = (st.included || 0) >= (META.warn_count || 60)
    ? note('mid', `识别到 ${st.included} 个工具 —— 数量偏多。它们会<b>全部</b>进入模型的`
        + `工具清单，可能拖慢本地小模型的决策。建议拆成几个目录，或勾掉不需要的。`)
    : '';
  return `
    ${note('low', `识别到 <b>${st.found || 0}</b> 个工具`
      + `（纳入 ${st.included || 0}、已排除 ${st.excluded || 0}）`
      + (scan.truncated
          ? '。<b>已达单目录上限被截断</b> —— 请缩小到具体子目录，'
            + '否则后面的工具不会被识别到' : ''))}
    ${scan.hint ? note('low', esc(scan.hint)) : ''}
    ${warnAlias}
    ${warn}
    <div class="table-wrap" style="max-height:44vh"><table>
      <thead><tr>
        <th style="width:44px"><input type="checkbox" id="ltAll" checked></th>
        <th style="width:30%">相对路径</th><th style="width:16%">名称</th>
        <th style="width:16%">别名（模型用它点名）</th>
        <th style="width:9%">类型</th><th style="width:14%">分类</th><th>备注</th>
      </tr></thead>
      <tbody>${rows || '<tr><td colspan="7" class="empty">这个目录里没识别到工具</td></tr>'}</tbody>
    </table></div>
    <div class="hint" style="margin-top:6px">
      别名只能是字母/数字/下划线、以字母或下划线开头（模型侧要求 ASCII）。
      留空即用自动推导的名字；自动名被别的工具占用时会加数字后缀，这里显示的就是<b>最终</b>名字。
    </div>`;
}

/* ---------------------------------------------------------------- 目录浏览 */
function renderBrowse(d) {
  if (d.is_root_list) {
    return `<div class="hint">先选一个盘符，再逐级进入工具目录。</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">
      ${(d.dirs || []).map((x) =>
        `<button class="ghost sm" data-dir="${esc(x.path)}">${esc(x.name)}</button>`).join('')}
      </div>`;
  }
  const here = d.here
    ? `<div class="hint">当前目录自己识别到 <b>${d.here.included}</b> 个工具。</div>` : '';
  return `<div class="kv"><span>当前</span><span>${esc(d.path)}</span></div>
    ${here}
    <div class="table-wrap" style="max-height:46vh"><table>
      <thead><tr><th>子目录</th><th style="width:80px">进入</th></tr></thead>
      <tbody>
        ${d.parent ? `<tr><td class="mono">..</td>
          <td><button class="ghost sm" data-dir="${esc(d.parent)}">上级</button></td></tr>` : ''}
        ${(d.dirs || []).map((x) => `<tr><td class="mono">${esc(x.name)}</td>
          <td><button class="ghost sm" data-dir="${esc(x.path)}">进入</button></td></tr>`).join('')}
      </tbody></table></div>`;
}

async function pickDir(start) {
  let chosen = '';
  const p = modal({
    title: '选择工具目录', okText: '就用这个目录', okClass: 'primary',
    bodyHtml: '<div id="brBody" class="hint">正在读取…</div>',
  });
  const host = document.getElementById('brBody');
  async function load(path) {
    try {
      const d = await api('/localtools/browse', { method: 'POST', body: { path } });
      chosen = d.path || '';
      host.innerHTML = renderBrowse(d);
      host.querySelectorAll('button[data-dir]').forEach((b) => {
        b.onclick = () => load(b.dataset.dir);
      });
    } catch (e) {
      host.innerHTML = alertBox('mid', esc(e.message));
    }
  }
  await load(start || '');
  const ok = await p;
  if (!ok) return '';
  if (!chosen) { toast('请先进入一个具体目录，再点「就用这个目录」。', 'err'); return ''; }
  return chosen;
}

/* ---------------------------------------------------------------- 交互 */
async function openEdit(i) {
  const r = i === null ? null : ROOTS[i];
  DRAFT = r
    ? { path: r.path, label: r.label, category: r.category, enabled: r.enabled,
        java: r.java || 'JAVA8', note: r.note || '',
        excluded: (r.tools || []).filter((t) => t.excluded).map((t) => t.rel_path),
        aliases: {}, overrides: {}, _scan: null }
    : { path: '', label: '', category: '', enabled: true, java: 'JAVA8', note: '',
        excluded: [], aliases: {}, overrides: {}, _scan: null };
  await reload();
  if (r) doScan();          // 编辑已有目录时先自动识别一次，省一次点击
}

function syncDraftFromForm() {
  const g = (id) => (document.getElementById(id) || {}).value;
  if (document.getElementById('ltPath')) {
    DRAFT.path = g('ltPath').trim();
    DRAFT.label = g('ltLabel').trim();
    DRAFT.category = g('ltCat').trim();
    DRAFT.java = g('ltJava');
    DRAFT.note = g('ltNote').trim();
  }
}

async function doScan() {
  syncDraftFromForm();
  const msg = document.getElementById('ltScanMsg');
  const box = document.getElementById('ltResult');
  if (!DRAFT.path) { toast('请先填目录或点「浏览…」选一个。', 'err'); return; }
  if (msg) msg.textContent = '识别中…';
  try {
    const scan = await api('/localtools/scan', {
      method: 'POST',
      body: { path: DRAFT.path, label: DRAFT.label, category: DRAFT.category,
              java: DRAFT.java, note: DRAFT.note,
              excluded: DRAFT.excluded, aliases: DRAFT.aliases },
    });
    DRAFT._scan = scan;
    if (msg) msg.textContent = '';
    box.innerHTML = resultsTable(scan);
    const all = document.getElementById('ltAll');
    if (all) all.onchange = () => {
      box.querySelectorAll('input[data-act=inc]').forEach((c) => { c.checked = all.checked; });
    };
    drawSaveBar(scan);
  } catch (e) {
    if (msg) msg.textContent = '';
    box.innerHTML = alertBox('mid', esc(e.message));
  }
}

function collectFromResults() {
  const box = document.getElementById('ltResult');
  const excluded = [];
  const aliases = {};
  box.querySelectorAll('tr[data-i]').forEach((tr) => {
    const i = Number(tr.dataset.i);
    const src = (DRAFT._scan.tools || [])[i];
    if (!src) return;
    const inc = tr.querySelector('input[data-act=inc]');
    const al = tr.querySelector('input[data-act=alias]');
    if (inc && !inc.checked) excluded.push(src.rel_path);
    const v = al ? al.value.trim() : '';
    if (v && v !== (src.alias_auto || '')) aliases[src.rel_path] = v;
  });
  return { excluded, aliases };
}

function drawSaveBar(scan) {
  const box = document.getElementById('ltResult');
  const bar = document.createElement('div');
  bar.className = 'toolbar';
  bar.style.marginTop = '12px';
  bar.innerHTML = `<button class="primary" id="ltSave">预览并保存</button>
    <span class="hint">保存后 registry 会自动重载，新工具立刻能在会话里被调用。</span>`;
  box.appendChild(bar);
  document.getElementById('ltSave').onclick = saveDraft;
}

async function currentRootsPayload(extra) {
  // 已保存的目录保持原样；本次编辑的目录用草稿（排掉同路径的旧条目）
  const out = [];
  for (const r of ROOTS) {
    if (r.path && DRAFT.path
        && r.path.toLowerCase() === DRAFT.path.toLowerCase()) {
      continue;                                   // 同路径的旧条目由草稿取代
    }
    out.push({
      path: r.path, label: r.label, category: r.category, enabled: r.enabled,
      java: r.java || 'JAVA8', note: r.note || '',
      excluded: (r.tools || []).filter((t) => t.excluded).map((t) => t.rel_path),
      aliases: {}, overrides: {},
    });
  }
  out.push(extra);
  return out;
}

async function saveDraft() {
  syncDraftFromForm();
  const got = collectFromResults();
  const mine = {
    path: DRAFT.path, label: DRAFT.label, category: DRAFT.category,
    enabled: DRAFT.enabled, java: DRAFT.java, note: DRAFT.note,
    excluded: got.excluded, aliases: got.aliases, overrides: DRAFT.overrides || {},
  };
  const roots = await currentRootsPayload(mine);

  let prev;
  try {
    prev = await api('/localtools/preview', { method: 'POST', body: { roots } });
  } catch (e) { toast(e.message, 'err'); return; }

  const diffRows = prev.diff.map((d) => `<div class="row">${esc(d.key)}：`
    + `${esc(String(d.before))} → <b>${esc(String(d.after))}</b></div>`).join('')
    || '<div class="row same">（无变化）</div>';
  const go = await modal({
    title: '确认保存本地工具目录',
    okText: '确认提交', okClass: 'danger', requireAck: true,
    ackText: '我确认上面列出的目录与纳入范围正确。',
    bodyHtml: `<div class="kv"><span>风险等级</span>
        <span><span class="pill ${prev.level === 'high' ? 'bad' : 'warn'}">${esc(prev.level)}</span></span></div>`
      + `<div class="kv"><span>将写入</span><span class="mono">data/local_tools.json</span></div>`
      + (prev.warnings || []).map((w) => note('mid', esc(w))).join('')
      + `<div class="sec-title">改动</div><div class="diff">${diffRows}</div>`,
  });
  if (!go) return;
  try {
    const r = await api('/localtools/commit', {
      method: 'POST',
      body: { roots, confirm_token: prev.confirm_token,
              expect_sha256: prev.expect_sha256 },
    });
    toast(`已保存。registry 现有 ${r.registry_total} 个工具，`
        + `其中自备 ${r.local_tools} 个。`, 'ok');
    DRAFT = null;
    await reload();
  } catch (e) { toast(e.message, 'err'); }
}

/* ---------------------------------------------------------------- 渲染 */
function draw(host) {
  if (DRAFT) {
    host.innerHTML = draftForm();
    document.getElementById('ltBack').onclick = () => { DRAFT = null; reload(); };
    document.getElementById('ltScan').onclick = doScan;
    const b = document.getElementById('ltBrowse');
    if (b) b.onclick = async () => {
      const p = await pickDir(DRAFT.path);
      if (p) { DRAFT.path = p; await reload(); doScan(); }
    };
    if (DRAFT._scan) {
      document.getElementById('ltResult').innerHTML = resultsTable(DRAFT._scan);
      drawSaveBar(DRAFT._scan);
    }
    return;
  }

  const c = META.counts || {};
  host.innerHTML = `
    ${note('low',
      '这里添加的是<b>你自己机器上</b>的工具目录（只存本机 <code>data/local_tools.json</code>，'
      + '不入库）。工具由程序自动识别，识别结果会与外部工具箱的工具一起出现在'
      + '「工具与分级」页里，共用同一套风险分级与闸门。')}
    <div class="cards">
      <div class="card"><h3>已添加目录</h3><div class="big">${c.roots || 0}</div>
        <div class="sub">每个目录独立启用/停用</div></div>
      <div class="card"><h3>自备工具</h3><div class="big">${c.local_tools || 0}</div>
        <div class="sub">来自本机目录，换了机器就没有</div></div>
      <div class="card"><h3>registry 工具总数</h3><div class="big">${c.registry_total || 0}</div>
        <div class="sub">外部工具箱 + 自备 + 内置能力</div></div>
      <div class="card"><h3>识别结果来自</h3><div class="big" style="font-size:15px">
        ${esc((META.file || {}).exists ? '已保存' : '尚未添加')}</div>
        <div class="sub mono">local_tools.json ${
          esc((META.file || {}).sha256_short || '-')}</div></div>
    </div>
    <div class="toolbar" style="margin-top:14px">
      <button class="primary" id="ltAdd">+ 添加工具目录</button>
      <span class="grow"></span>
      <span class="hint">${ROOTS.length} 个目录</span>
      <button class="ghost sm" id="ltReload">重新扫描</button>
    </div>
    ${rootsTable()}`;

  document.getElementById('ltAdd').onclick = () => openEdit(null);
  document.getElementById('ltReload').onclick = () => reload();
  host.querySelectorAll('button[data-act=edit]').forEach((b) => {
    b.onclick = () => openEdit(Number(b.dataset.i));
  });
  host.querySelectorAll('button[data-act=del]').forEach((b) => {
    b.onclick = () => removeRoot(Number(b.dataset.i));
  });
}

async function removeRoot(i) {
  const r = ROOTS[i];
  if (!r) return;
  const go = await modal({
    title: '移除这个工具目录？', okText: '确认移除', okClass: 'danger', requireAck: true,
    ackText: '我确认从工具箱里移除这个目录（目录本身不会被删除）。',
    bodyHtml: `<div class="kv"><span>目录</span><span>${esc(r.path)}</span></div>`
      + `<div class="kv"><span>当前识别到</span>
         <span>${(r.stats || {}).included || 0} 个工具</span></div>`
      + note('low', '只是从工具箱里摘掉登记，<b>磁盘上的文件不会动</b>。'
        + '想临时停用而不移除，用「编辑」里的启用开关即可。'),
  });
  if (!go) return;
  const roots = ROOTS.filter((_, k) => k !== i).map((x) => ({
    path: x.path, label: x.label, category: x.category, enabled: x.enabled,
    java: x.java || 'JAVA8', note: x.note || '',
    excluded: (x.tools || []).filter((t) => t.excluded).map((t) => t.rel_path),
    aliases: {}, overrides: {},
  }));
  try {
    const prev = await api('/localtools/preview', { method: 'POST', body: { roots } });
    await api('/localtools/commit', {
      method: 'POST',
      body: { roots, confirm_token: prev.confirm_token,
              expect_sha256: prev.expect_sha256 },
    });
    toast('已移除。', 'ok');
    await reload();
  } catch (e) { toast(e.message, 'err'); }
}

export async function render(host) {
  const d = await api('/localtools');
  META = d;
  ROOTS = d.roots || [];
  setFileHint(`local_tools.json ${(d.file || {}).sha256_short || '-'}`);
  draw(host);
}
