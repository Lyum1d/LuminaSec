/* 合规与模板：红线 Markdown / 调用模板 / 本机密钥（FOFA·CEye）。
 *
 * 三个子页各自独立读写：
 *   · 红线      data/rules/compliance-redlines.md（注入系统提示，**下一轮生效**）
 *   · 调用模板  data/invocation_templates.json（改后需重载 registry）
 *   · 密钥      config.yaml（被 app/fofa.py 用**自写的扁平解析器**读 ——
 *               只允许改值，键名与其它行原样保留，否则会出现「填了却没生效」）
 */
import { api, esc, modal, toast, alertBox, reload, setFileHint }
  from '/console-assets/core.js?v=112';

let TAB = 'rules';

/* ============================================================ 红线 */
async function drawRules(host) {
  const d = await api('/rules');
  setFileHint(`redlines.md ${d.file.sha256_short || '（不存在）'}`);
  const secs = (d.sections || []).map((s) =>
    `<div class="kv"><span>${esc(s.title)}</span>
      <span class="hint">${s.chars} 字符</span></div>`).join('');
  host.innerHTML = `
    <div class="toolbar">
      <button class="primary" id="btnSave">预览并提交</button>
      <button class="ghost" id="btnReload">放弃改动</button>
      <span class="grow"></span>
      <span class="hint">${esc(d.note)}</span>
    </div>
    <div class="sec-title">当前章节</div>
    <div class="card">${secs || '<div class="hint">未检测到二级标题。</div>'}</div>
    <div class="sec-title">正文（可直接编辑）</div>
    <textarea id="rulesText" class="mono" style="width:100%;height:44vh;line-height:1.5"
      >${esc(d.text)}</textarea>
    <div class="hint" style="margin-top:6px">
      红线注入系统提示，**下一轮对话生效**。清空会被拒绝 —— 那等于移除纪律约束。
    </div>`;
  host.querySelector('#btnReload').onclick = () => reload();
  host.querySelector('#btnSave').onclick = async () => {
    const text = host.querySelector('#rulesText').value;
    let prev;
    try { prev = await api('/rules/preview', { method: 'POST', body: { text } }); }
    catch (e) { toast(e.message, 'err'); return; }
    const go = await modal({
      title: '确认改动合规红线', okText: '确认提交', okClass: 'danger',
      requireAck: true, ackText: '我确认已通读改动（红线是纪律依据，改错会放松约束）。',
      bodyHtml: `<div class="kv"><span>行数</span><span>${prev.stats.before_lines} → `
        + `${prev.stats.after_lines}</span></div>`
        + `<div class="kv"><span>字符数</span><span>${prev.stats.before_chars} → `
        + `${prev.stats.after_chars}</span></div>`
        + '<div class="sec-title">diff（n=0）</div>'
        + `<pre class="mono" style="max-height:40vh;overflow:auto;font-size:12px">`
        + `${esc(prev.preview)}</pre>`,
    });
    if (!go) return;
    try {
      const r = await api('/rules/commit', {
        method: 'POST',
        body: { text, confirm_token: prev.confirm_token,
                expect_sha256: prev.expect_sha256 },
      });
      toast('已写入：' + (r.backup || '（无备份）')
          + (r.reload && r.reload.actions ? '；' + r.reload.actions.join('；') : ''), 'ok');
      await reload();
    } catch (e) { toast(e.message, 'err'); }
  };
}

/* ============================================================ 调用模板 */
let TPL = [];

async function drawTemplates(host) {
  const d = await api('/templates');
  TPL = (d.items || []).map((x) => ({ ...x }));
  setFileHint(`invocation_templates.json ${d.file.sha256_short || '-'}`);
  const rows = TPL.map((t, i) => `<tr>
    <td><input data-i="${i}" data-k="alias" value="${esc(t.alias || '')}"></td>
    <td><input data-i="${i}" data-k="cmd" class="mono" value="${esc(t.cmd || '')}"></td>
    <td><select data-i="${i}" data-k="target">${(d.targets || []).map((v) =>
      `<option value="${esc(v)}"${(t.target || 'raw') === v ? ' selected' : ''}>${esc(v)}</option>`).join('')}</select></td>
    <td><button class="ghost sm" data-del="${i}">删除</button></td>
  </tr>`).join('');
  // 加载期被丢弃的模板（例如手工改写导致缺 {exe}）必须显式提示 ——
  // 否则「模板被静默忽略、走默认拼接」这件事只留在服务端日志里，等于没发现。
  const probs = (d.problems || []).length
    ? alertBox('high', `有 ${d.problems.length} 条模板在加载时被丢弃（不会生效）：`
        + d.problems.map((p) => `${p.alias}（${p.why}）`).join('；')
        + ' —— 已退回默认拼接「{exe} {args} {target}」，用的是受信任的工具路径。')
    : '';
  host.innerHTML = `
    <div class="toolbar">
      <button class="primary" id="btnSave">预览并提交</button>
      <button class="ghost" id="btnAdd">新增一行</button>
      <span class="grow"></span>
      <span class="hint">共 ${TPL.length} 条</span>
    </div>
    ${probs}
    <div class="table-wrap"><table>
      <thead><tr><th style="width:20%">alias</th><th>命令模板</th>
        <th style="width:14%">target 形态</th><th style="width:70px">操作</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4" class="empty">暂无模板</td></tr>'}</tbody>
    </table></div>
    <div class="sec-title">字段含义</div>
    <div class="hint">${esc(d.note)}<br>${esc(d.target_form)}</div>`;

  host.querySelectorAll('input[data-i],select[data-i]').forEach((el) => {
    el.onchange = () => { TPL[Number(el.dataset.i)][el.dataset.k] = el.value; };
  });
  host.querySelectorAll('button[data-del]').forEach((b) => {
    b.onclick = () => { TPL.splice(Number(b.dataset.del), 1); drawTemplates(host); };
  });
  host.querySelector('#btnAdd').onclick = () => {
    TPL.push({ alias: '', cmd: '{exe} {args} {target}', target: 'raw' });
    drawTemplates(host);
  };
  host.querySelector('#btnSave').onclick = async () => {
    let prev;
    try { prev = await api('/templates/preview', { method: 'POST', body: { items: TPL } }); }
    catch (e) { toast(e.message, 'err'); return; }
    const list = (label, arr) => arr.length
      ? `<div class="kv"><span>${label}</span><span class="mono">${esc(arr.join('、'))}</span></div>` : '';
    const go = await modal({
      title: '确认改动调用模板', okText: '确认提交', okClass: 'danger',
      requireAck: true,
      ackText: '我确认命令模板正确（它决定工具实际怎么被调用）。',
      bodyHtml: list('新增', prev.added) + list('删除', prev.removed)
        + list('修改', prev.changed)
        || '<div class="hint">无改动</div>',
    });
    if (!go) return;
    try {
      const r = await api('/templates/commit', {
        method: 'POST',
        body: { items: TPL, confirm_token: prev.confirm_token,
                expect_sha256: prev.expect_sha256 },
      });
      toast('已写入：' + (r.backup || '（无备份）')
          + (r.reload && r.reload.actions ? '；' + r.reload.actions.join('；') : ''), 'ok');
      await reload();
    } catch (e) { toast(e.message, 'err'); }
  };
}

/* ============================================================ 密钥 */
async function drawSecrets(host) {
  const d = await api('/secrets');
  setFileHint(`config.yaml ${d.file.sha256_short || '（不存在）'}`);
  const rows = d.items.map((it) => `<div class="kv" style="align-items:center;gap:8px;padding:6px 0">
    <span style="min-width:150px"><span class="mono">${esc(it.key)}</span>
      ${it.is_secret ? ' <span class="pill warn">密钥</span>' : ''}</span>
    <span style="flex:1"><input data-k="${esc(it.key)}" type="${it.is_secret ? 'password' : 'text'}"
      placeholder="${it.has_value ? '' : '尚未填写'}"
      value="${it.is_secret ? '' : esc(it.masked)}"></span>
    <span style="min-width:200px;text-align:right" class="hint">
      ${it.has_value ? `已填：<span class="mono">${esc(it.masked)}</span>`
                     : '<span class="pill dim">未填</span>'}</span>
  </div>`).join('');
  host.innerHTML = `
    <div class="toolbar">
      <button class="primary" id="btnSave">保存</button>
      <span class="grow"></span>
      <span class="hint">只回显「是否已填」与打码值，**不下发明文**</span>
    </div>
    <div class="card">${rows}</div>
    <div class="sec-title">修改控制台口令（推荐走这里）</div>
    <div class="card" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="curPw" type="password" placeholder="当前口令" autocomplete="current-password"
             style="flex:1;min-width:160px">
      <input id="newPw2" type="password" placeholder="新口令（至少 8 位）" autocomplete="new-password"
             style="flex:1;min-width:160px">
      <input id="newPw3" type="password" placeholder="再次输入新口令" autocomplete="new-password"
             style="flex:1;min-width:160px">
      <button class="primary" id="btnChangePw">修改口令</button>
    </div>
    <div class="hint">新口令会<strong>写入本机 config.yaml（consolePassword）长期保存</strong>，
      重启服务不丢；修改时会校验当前口令并记入合规审计（值不入审计）。
      若口令来自环境变量 AGENT_CONSOLE_PASSWORD（优先级最高），请改环境变量 ——
      这里会明确提示，而不是改了不生效。</div>
    <div class="sec-title">注意</div>
    <div class="hint">${esc(d.note)}<br>
      保存是低危操作（不改结构、不改变防护强度），因此不要求二次确认；改动会记入合规审计
      （只记改了哪些键，<strong>不记值</strong>）。</div>`;
  host.querySelector('#btnChangePw').onclick = async () => {
    const body = {
      current_password: host.querySelector('#curPw').value,
      new_password: host.querySelector('#newPw2').value,
    };
    if (body.new_password !== host.querySelector('#newPw3').value) {
      toast('两次输入的新口令不一致。', 'err'); return;
    }
    try {
      const r = await api('/password/change', { method: 'POST', body });
      toast(r.note || '口令已修改并保存。', 'ok');
      ['#curPw', '#newPw2', '#newPw3'].forEach((s) => { host.querySelector(s).value = ''; });
      await reload();
    } catch (e) { toast(e.message, 'err'); }
  };
  host.querySelector('#btnSave').onclick = async () => {
    const values = {};
    host.querySelectorAll('input[data-k]').forEach((el) => {
      if (el.value !== '') values[el.dataset.k] = el.value;   // 留空 = 不改
    });
    if (!Object.keys(values).length) { toast('没有要保存的内容（留空表示不修改）。'); return; }
    try {
      const r = await api('/secrets/commit', { method: 'POST', body: { values } });
      toast('已保存：' + Object.keys(values).join('、'), 'ok');
      // v102：服务端可能带回「环境变量压着 consolePassword」之类的告警 ——
      // 必须弹出来，否则就是又一轮「明明保存了却不生效」。
      (r.warnings || []).forEach((w) => toast(w, 'err'));
      await reload();
    } catch (e) { toast(e.message, 'err'); }
  };
}

/* ============================================================ 入口 */
const TABS = [['rules', '合规红线'], ['templates', '调用模板'], ['secrets', '本机密钥']];

export async function render(host) {
  host.innerHTML = `<div class="toolbar" id="subTabs">${TABS.map(([k, t]) =>
    `<button class="ghost sm${k === TAB ? ' primary' : ''}" data-t="${k}">${t}</button>`).join('')}
    </div><div id="subHost"></div>`;
  host.querySelectorAll('#subTabs button').forEach((b) => {
    b.onclick = () => { TAB = b.dataset.t; render(host); };
  });
  const sub = host.querySelector('#subHost');
  sub.innerHTML = '<div class="empty">正在加载…</div>';
  try {
    if (TAB === 'rules') await drawRules(sub);
    else if (TAB === 'templates') await drawTemplates(sub);
    else await drawSecrets(sub);
  } catch (e) {
    sub.innerHTML = `<div class="alert high"><span class="ico">!</span>`
      + `<span>加载失败：${esc(e.message)}</span></div>`;
  }
}
