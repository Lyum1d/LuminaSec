/* 白盒侧：代码库登记/删除 + 知识库篇目增删改（v102 新增）
 *
 * ## 为什么这两件事放在控制台、而不是作战界面
 *   · **代码库入库 = 一条授权记录**（写 data/codebases.json，与授权靶标同级）：
 *     它决定白盒会话"可以审计哪些本机目录"。所以与 scope 页同一套规矩 ——
 *     预览 → 二次确认 → 留痕，不能点一下就写。
 *   · **知识库篇目是"给模型看的文档"**：写坏了模型会照着错的说明去调用工具，
 *     比没有文档更坏。所以写入前**强制**过仓库既有硬约定（≤8000 字符、姊妹篇互指、
 *     不含本机路径），写完再一键跑 test_068 验证索引/合计/交叉引用三项一致性。
 *
 * ## 与后端的分工
 *   本页只做「呈现 + 触发两段式」；所有校验与写入都在 app/console_api.py 的
 *   /whitebox、/kb/*、/codebases/* 里。前端**不**做放行判断 —— 绕过前端也写不进去。
 *
 * ## 样式
 *   只用 console.css 里既有的类（sec-title / card / kv / mono / diff / toolbar /
 *   grow / pill / alert / hint / empty），**不新增任何 CSS** —— 与既有各页保持一致。
 */
import { api, esc, modal, toast } from '/console-assets/core.js?v=112';

let TAB = 'codebases';
let OVERVIEW = null;

export async function render(host) {
  host.innerHTML = `
    <div class="toolbar">
      <button class="ghost sm${TAB === 'codebases' ? ' primary' : ''}" data-t="codebases">代码库</button>
      <button class="ghost sm${TAB === 'kb' ? ' primary' : ''}" data-t="kb">知识库</button>
      <span class="grow"></span>
      <button class="ghost sm" id="wbRefresh">刷新</button>
    </div>
    <div id="wbBody"><div class="empty">正在加载…</div></div>`;

  host.querySelectorAll('[data-t]').forEach(b => {
    b.onclick = () => { TAB = b.dataset.t; render(host); };
  });
  host.querySelector('#wbRefresh').onclick = () => render(host);

  const body = host.querySelector('#wbBody');
  try {
    OVERVIEW = await api('/whitebox');
    if (TAB === 'codebases') drawCodebases(body, host);
    else drawKb(body, host);
  } catch (e) {
    body.innerHTML = `<div class="alert high"><span class="ico">!</span>`
      + `<span>加载失败：${esc(e.message)}</span></div>`;
  }
}

/* ============================================================ 代码库 */

function drawCodebases(host, root) {
  const cbs = OVERVIEW.codebases || [];
  host.innerHTML = `
    <div class="alert low"><span class="ico">i</span><span>
      代码库登记 = 一条<strong>授权记录</strong>：白盒会话只能审计这里登记过的目录。
      删除只移除登记，<strong>不会动磁盘上的源码</strong>。</span></div>

    <div class="sec-title">已登记（${cbs.length}）</div>
    ${cbs.length ? `<div class="table-wrap"><table>
      <thead><tr><th>codebase_id</th><th>层级 / 来源</th><th>目录</th><th>备注</th><th></th></tr></thead>
      <tbody>${cbs.map(cb => `<tr>
        <td class="mono">${esc(cb.codebase_id)}</td>
        <td><span class="pill dim">${esc(cb.white_layer)}</span>
            <span class="pill dim">${esc(cb.source)}</span></td>
        <td class="mono hint">${esc(cb.root)}</td>
        <td class="hint">${esc(cb.note || '')}</td>
        <td class="row-actions">
          <button class="ghost sm" data-del="${esc(cb.codebase_id)}">删除</button></td>
      </tr>`).join('')}</tbody></table></div>`
      : '<div class="empty">还没有登记任何代码库</div>'}

    <div class="sec-title">登记新代码库</div>
    <div class="card">
      <div class="kv"><label>源码目录（绝对路径）</label>
        <input id="cbRoot" placeholder="E:\\repo\\target"></div>
      <div class="kv"><label>codebase_id（留空按目录名生成）</label>
        <input id="cbId" placeholder="my-target"></div>
      <div class="kv"><label>来源</label>
        <select id="cbSource">
          <option value="authorized">authorized（已获授权）</option>
          <option value="opensource">opensource（开源代码）</option>
        </select></div>
      <div class="kv"><label>白盒层级</label>
        <select id="cbLayer">
          <option value="full">full（完整源码）</option>
          <option value="partial">partial（部分源码）</option>
          <option value="gray">gray（灰盒：无源码但有符号/配置）</option>
        </select></div>
      <div class="kv"><label>备注 / 授权凭据摘要</label>
        <input id="cbNote" placeholder="如：客户名 + 授权邮件日期"></div>
      <div class="toolbar"><span class="grow"></span>
        <button class="primary" id="cbAdd">登记…</button></div>
    </div>`;

  host.querySelectorAll('[data-del]').forEach(b => {
    b.onclick = () => previewThenCommit('/codebases/preview', '/codebases/commit',
      { action: 'delete', codebase_id: b.dataset.del }, root);
  });
  host.querySelector('#cbAdd').onclick = () => {
    previewThenCommit('/codebases/preview', '/codebases/commit', {
      action: 'upsert',
      root: host.querySelector('#cbRoot').value.trim(),
      codebase_id: host.querySelector('#cbId').value.trim(),
      source: host.querySelector('#cbSource').value,
      white_layer: host.querySelector('#cbLayer').value,
      note: host.querySelector('#cbNote').value.trim(),
    }, root);
  };
}

/* ============================================================ 知识库 */

function drawKb(host, root) {
  const docs = OVERVIEW.kb || [];
  const errs = docs.filter(d => d.level === 'error');
  const warns = docs.filter(d => d.level === 'warn');
  const lvlIcon = (d) => (d.level === 'error' ? '🔴' : (d.level === 'warn' ? '🟡' : '🟢'));
  const lvlText = (d) => [...(d.issues || []), ...(d.warnings || [])].join('；');
  host.innerHTML = `
    <div class="alert ${errs.length ? 'high' : (warns.length ? 'mid' : 'low')}">
      <span class="ico">${errs.length ? '!' : 'i'}</span><span>
      共 <b>${docs.length}</b> 篇。<b>白盒篇目</b>（<code>whitebox-*.md</code>）
      上限 ${OVERVIEW.kb_max} 字符/篇（超了在审计循环里会被截断）；
      其它参考文档不限长度。
      ${errs.length ? `⚠️ <b>${errs.length}</b> 篇越界。` : ''}
      ${warns.length ? `🟡 <b>${warns.length}</b> 篇接近上限（该考虑拆篇了）。` : ''}
      ${(!errs.length && !warns.length) ? '全部通过硬约定。' : ''}
      新增/删除会自动同步 README 索引表与合计数字（否则 test_068 会报红）。</span>
      <span class="grow"></span>
      <button class="ghost sm" id="kbRegress">▶ 跑回归 test_068</button></div>
    <div id="kbRegressOut"></div>

    <div class="sec-title">篇目</div>
    <div class="table-wrap"><table>
      <thead><tr><th></th><th>篇目</th><th>字符</th><th>问题 / 提示</th><th></th></tr></thead>
      <tbody>${docs.map(d => `<tr>
        <td title="${esc(d.level || '')}">${lvlIcon(d)}</td>
        <td class="mono">${esc(d.name)}</td>
        <td class="${d.level === 'error' ? '' : 'hint'}">${d.chars}</td>
        <td class="hint">${esc(lvlText(d))}</td>
        <td class="row-actions">
          <button class="ghost sm" data-edit="${esc(d.name)}">编辑</button>
          <button class="ghost sm" data-kbdel="${esc(d.name)}">删除</button></td>
      </tr>`).join('')}</tbody></table></div>

    <div class="sec-title">编辑篇目</div>
    <div class="card">
      <div class="kv"><label>篇目名</label>
        <input id="kbName" placeholder="whitebox-xxx.md"></div>
      <div class="kv"><label>索引表说明（新增篇目时写进 README 的一行）</label>
        <input id="kbDesc" placeholder="一句话说明这篇讲什么"></div>
      <textarea id="kbText" class="mono" rows="16"
        placeholder="篇目全文（Markdown）…"></textarea>
      <div class="hint" id="kbCount">0 字符</div>
      <div class="toolbar"><span class="grow"></span>
        <button class="primary" id="kbSave">保存…</button></div>
    </div>`;

  const ta = host.querySelector('#kbText');
  const cnt = host.querySelector('#kbCount');
  const sync = () => {
    const n = ta.value.length;
    const max = OVERVIEW.kb_max || 8000;
    cnt.textContent = `${n} 字符` + (n > max ? `（超出上限 ${n - max}）` : `（上限 ${max}）`);
    cnt.className = n > max ? 'alert high' : 'hint';
  };
  ta.oninput = sync;

  host.querySelectorAll('[data-edit]').forEach(b => {
    b.onclick = async () => {
      try {
        const d = await api('/kb/read?name=' + encodeURIComponent(b.dataset.edit));
        host.querySelector('#kbName').value = d.name;
        host.querySelector('#kbText').value = d.text;
        sync();
        ta.scrollIntoView({ behavior: 'smooth', block: 'center' });
      } catch (e) { toast(e.message, 'err'); }
    };
  });
  host.querySelectorAll('[data-kbdel]').forEach(b => {
    b.onclick = () => previewThenCommit('/kb/preview', '/kb/commit',
      { name: b.dataset.kbdel, delete: true }, root);
  });
  host.querySelector('#kbSave').onclick = () => previewThenCommit('/kb/preview', '/kb/commit', {
    name: host.querySelector('#kbName').value.trim(),
    desc: host.querySelector('#kbDesc').value.trim(),
    text: ta.value,
  }, root);

  host.querySelector('#kbRegress').onclick = async () => {
    const out = host.querySelector('#kbRegressOut');
    out.innerHTML = '<div class="empty">正在运行 test_068 …</div>';
    try {
      const r = await api('/whitebox/regress', { method: 'POST', body: {} });
      // 正式版有意不含回归脚本（shipped:false）⇒ 这是「能力不在」不是「跑挂了」，
      // 用中性提示，别画成红色失败（否则使用者会以为 KB 被改坏了）。
      if (r.shipped === false) {
        out.innerHTML = `<div class="alert low"><span class="ico">i</span>`
          + `<span>正式版不含回归脚本</span></div>`
          + `<div class="diff"><pre>${esc(r.error || '')}</pre></div>`;
        return;
      }
      out.innerHTML = `<div class="alert ${r.ok ? 'low' : 'high'}"><span class="ico">`
        + `${r.ok ? '✓' : '!'}</span><span>${r.ok ? '回归通过' : '回归失败'}`
        + `${r.passed != null ? `（${r.passed} 通过 / ${r.failed} 失败）` : ''}</span></div>`
        + `<div class="diff"><pre>${esc(r.output || r.error || '')}</pre></div>`;
    } catch (e) {
      out.innerHTML = `<div class="alert high"><span class="ico">!</span>`
        + `<span>${esc(e.message)}</span></div>`;
    }
  };
}

/* ============================================================ 两段式：预览 → 二次确认 → 提交 */

async function previewThenCommit(previewPath, commitPath, body, root) {
  let prev;
  try {
    prev = await api(previewPath, { method: 'POST', body });
  } catch (e) {
    toast(e.message, 'err');
    return;
  }
  // 硬拒绝（未过仓库硬约定）：不弹确认框，直接把原因摆出来 —— 确认框只用于
  // "已通过校验、需要人再确认一次"的场景，把它用在"校验失败"上会误导。
  if (prev && prev.ok === false) {
    modal({
      title: '已拒绝（未通过硬约定）', okText: '知道了', okClass: 'primary',
      bodyHtml: `<div class="alert high"><span class="ico">!</span>`
        + `<span>${esc(prev.error || '校验未通过')}</span></div>`,
    }).then(() => {});
    return;
  }

  const high = prev.level === 'high';
  let html = '';
  if (prev.action === 'delete') {
    html = `<div class="alert high"><span class="ico">!</span><span>即将<b>删除</b>：`
      + `<code>${esc(body.name || body.codebase_id || '')}</code></span></div>`;
    if (prev.referenced_count) {
      html += `<div class="alert mid"><span class="ico">!</span><span>被 `
        + `${prev.referenced_count} 篇引用：${esc((prev.referenced_by || []).join('、'))}`
        + `<br>${esc(prev.note || '')}</span></div>`;
    } else if (prev.note) {
      html += `<div class="hint">${esc(prev.note)}</div>`;
    }
  } else if (prev.action === 'upsert' && prev.record) {
    html = `<div class="hint">将写入 <code>data/codebases.json</code>：</div>`
      + `<div class="diff"><pre>${esc(JSON.stringify(prev.record, null, 2))}</pre></div>`;
    if ((prev.warnings || []).length) {
      html += `<div class="alert mid"><span class="ico">!</span><span>`
        + `${prev.warnings.map(esc).join('<br>')}</span></div>`;
    }
  } else {
    const st = prev.stats || {};
    html = `<div class="hint">字符 ${st.before_chars ?? 0} → ${st.after_chars ?? 0}；`
      + `差异块 ${prev.hunks ?? 0}</div>`
      + (prev.compliance
          ? `<div class="alert ${(prev.compliance.warnings || []).length ? 'mid' : 'low'}">`
            + `<span class="ico">${(prev.compliance.warnings || []).length ? '!' : 'i'}</span>`
            + `<span>合规检查通过（${prev.compliance.chars} 字符）`
            + ((prev.compliance.warnings || []).length
                ? `<br>🟡 ${prev.compliance.warnings.map(esc).join('<br>🟡 ')}` : '')
            + `</span></div>`
          : '')
      + `<div class="diff"><pre>${esc(prev.preview || '（无差异预览）')}</pre></div>`;
  }

  const ok = await modal({
    title: prev.action === 'delete' ? '确认删除' : '确认写入',
    bodyHtml: html,
    okText: high ? '我确认，提交' : '提交',
    requireAck: true,
    ackText: high ? '我确认这是一次授权范围内的变更' : '我确认以上改动',
  });
  if (!ok) return;

  try {
    const r = await api(commitPath, {
      method: 'POST',
      body: { ...body, confirm_token: prev.confirm_token, expect_sha256: prev.expect_sha256 },
    });
    let extra = '';
    if (r.readme && r.readme.ok === false) {
      extra = `；⚠️ README 索引同步失败：${r.readme.reason || r.readme.error}`;
    } else if (r.readme && r.readme.ok) {
      extra = `；README 已同步（合计 ${r.readme.files} 篇）`;
    }
    toast('已提交并留痕' + extra + (r.backup ? '；备份 ' + r.backup : ''), 'ok');
    render(root);
  } catch (e) {
    toast(e.message, 'err');
  }
}
