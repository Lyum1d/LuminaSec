/* 授权白名单：结构化条目 CRUD + 逐行干跑 + 提交前 diff + 高危二次确认。
 *
 * 这一页是整个控制台的核心（用户点名的需求），也是最需要小心的一页：
 * 它改的是**授权红线**。所以：
 *   · 改动走两段式（preview 拿一次性票据 → commit 带票据），**服务端强制**；
 *   · commit 带 `expect_sha256`，文件被手工改过就 409，绝不盲目覆盖；
 *   · `include_subdomains` 在本版**只读**（闸门还没支持「不含子域」，见下）。
 */
import { api, esc, modal, toast, diffHtml, alertBox, reload, setFileHint, parseList }
  from '/console-assets/core.js?v=112';

let rows = [];          // 当前编辑中的结构化条目
let meta = {};          // 服务端返回的 data（含 file / consistent / note）

const FIELDS = [
  ['host', '主机 / 域名', 'text'],
  ['cid', '补天 cid', 'text'],
  ['owner', '授权主体', 'text'],
  ['authorized_at', '授权日期', 'text'],
  ['ports', '端口（逗号分隔，留空=不限）', 'text'],
  ['schemes', '协议（http,https，留空=不限）', 'text'],
  ['scope_note', '限制条件 / 备注', 'text'],
];

function toRows(targets) {
  return (targets || []).map((t) => ({
    host: String(t.host || ''),
    include_subdomains: t.include_subdomains !== false,
    ports: Array.isArray(t.ports) ? t.ports.join(',') : '',
    schemes: Array.isArray(t.schemes) ? t.schemes.join(',') : '',
    cid: String(t.cid || ''),
    owner: String(t.owner || ''),
    authorized_at: String(t.authorized_at || ''),
    scope_note: String(t.scope_note || ''),
    added_by: String(t.added_by || 'console'),
    needs_review: !!t.needs_review,
  }));
}

function toPayload() {
  return rows
    .filter((r) => String(r.host || '').trim())
    .map((r) => {
      // 端口/协议的解析走 lib.parseList（空 → null = 不限，与后端语义一致）。
      // 抽出去是因为这块错了会**静默**改变授权范围，必须有测试守住。
      const ports = parseList(r.ports, { numeric: true });
      const schemes = parseList(r.schemes);
      return {
        host: String(r.host).trim().toLowerCase(),
        include_subdomains: true,          // 见下方说明：本版写死，闸门尚无该开关
        ports,
        schemes,
        cid: String(r.cid || '').trim(),
        owner: String(r.owner || '').trim(),
        authorized_at: String(r.authorized_at || '').trim(),
        scope_note: String(r.scope_note || '').trim(),
        added_by: r.added_by || 'console',
        needs_review: !(String(r.cid || '').trim() && String(r.owner || '').trim()),
      };
    });
}

function renderTable() {
  if (!rows.length) {
    return '<div class="empty">尚无结构化条目。点「迁移预演」把现有 domains 与授权留痕反解为结构化条目。</div>';
  }
  const head = `<tr><th style="width:22%">主机</th><th style="width:11%">cid</th>
    <th style="width:16%">授权主体</th><th style="width:11%">授权日期</th>
    <th style="width:11%">端口</th><th style="width:11%">协议</th>
    <th>限制条件</th><th style="width:120px">操作</th></tr>`;
  const body = rows.map((r, i) => `
    <tr class="${r.needs_review ? 'review' : ''}">
      <td><input data-i="${i}" data-k="host" value="${esc(r.host)}" placeholder="a.example.test"></td>
      <td><input data-i="${i}" data-k="cid" value="${esc(r.cid)}" placeholder="待补"></td>
      <td><input data-i="${i}" data-k="owner" value="${esc(r.owner)}"></td>
      <td><input data-i="${i}" data-k="authorized_at" value="${esc(r.authorized_at)}" placeholder="YYYY-MM-DD"></td>
      <td><input data-i="${i}" data-k="ports" value="${esc(r.ports)}" placeholder="80,443"></td>
      <td><input data-i="${i}" data-k="schemes" value="${esc(r.schemes)}" placeholder="https"></td>
      <td><input data-i="${i}" data-k="scope_note" value="${esc(r.scope_note)}"></td>
      <td><div class="row-actions">
        <button class="ghost sm" data-act="verify" data-i="${i}">验证</button>
        <button class="ghost sm" data-act="del" data-i="${i}">删除</button>
      </div></td>
    </tr>`).join('');
  return `<div class="table-wrap"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
}

function bindTable(host) {
  host.querySelectorAll('input[data-i]').forEach((inp) => {
    inp.oninput = () => {
      const i = Number(inp.dataset.i);
      rows[i][inp.dataset.k] = inp.value;
    };
  });
  host.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      const i = Number(b.dataset.i);
      if (b.dataset.act === 'del') {
        rows.splice(i, 1);
        draw(host);
        return;
      }
      await verify(rows[i].host);
    };
  });
}

async function verify(h) {
  const host = String(h || '').trim();
  if (!host) { toast('请先填主机名', 'err'); return; }
  try {
    const d = await api('/scope/verify', { method: 'POST', body: { host } });
    await modal({
      title: `干跑结果：${host}`,
      okText: '知道了', okClass: 'primary', showOk: true,
      bodyHtml: `<div class="alert ${d.allowed ? 'low' : 'high'}">`
        + `<span class="ico">${d.allowed ? '✓' : '!'}</span>`
        + `<span>${d.allowed ? '会放行' : '会被拒绝'}：${esc(d.reason)}</span></div>`
        + '<div class="hint">干跑只做本地字符串匹配，<strong>不发任何目标流量</strong>。</div>',
    });
  } catch (e) { toast(e.message, 'err'); }
}

async function runPlan(host) {
  try {
    const d = await api('/scope/plan', { method: 'POST' });
    const rep = d.report || {};
    const reviewList = (rep.needs_review || []).slice(0, 30);
    const ok = await modal({
      title: '迁移预演（未写盘）',
      okText: '载入到表格', okClass: 'primary', requireAck: false,
      bodyHtml:
        `<div class="kv"><span>host 总数</span><span>${rep.hosts}</span></div>`
        + `<div class="kv"><span>反解出 cid</span><span>${rep.with_cid}</span></div>`
        + `<div class="kv"><span>反解出授权主体</span><span>${rep.with_owner}</span></div>`
        + `<div class="kv"><span>_说明 原文保留</span><span>${rep.note_preserved ? '是' : '否'}</span></div>`
        + `<div class="kv"><span>domains 已同步</span><span>${rep.domains_synced ? '是' : '否'}</span></div>`
        + (reviewList.length
            ? `<div class="sec-title">需人工复核（${reviewList.length} 条）</div>`
              + '<div class="hint">这些条目的 cid 或授权主体反解不出来 —— '
              + '**不猜**，留给人工补。绝不拿猜测值填授权信息。</div>'
              + `<div class="mono" style="margin-top:6px">${reviewList.map(esc).join('<br>')}</div>`
            : '<div class="hint">全部条目都反解出了 cid 与授权主体。</div>')
        + (d.problems && d.problems.length
            ? alertBox('high', '结构校验问题：' + d.problems.join('；')) : ''),
    });
    if (!ok) return;
    rows = toRows((d.preview || {}).targets);
    draw(host);
    toast(`已载入 ${rows.length} 条，确认后点「预览并提交」`, 'ok');
  } catch (e) { toast(e.message, 'err'); }
}

async function commit(host) {
  const payload = toPayload();
  if (!payload.length) { toast('白名单不能为空 —— 存盘后所有工具都会被拒绝执行', 'err'); return; }
  let prev;
  try {
    prev = await api('/scope/preview', { method: 'POST', body: { targets: payload } });
  } catch (e) { toast(e.message, 'err'); return; }

  const warnHtml = (prev.warnings || []).map((w) => alertBox('mid', w)).join('');
  const ok = await modal({
    title: '确认改动授权白名单',
    okText: '确认提交', okClass: 'danger',
    requireAck: true,
    ackText: '我确认以上目标均已获得书面授权，并已核对新增/移除的条目。',
    bodyHtml:
      `<div class="kv"><span>风险等级</span><span>`
      + `<span class="pill ${prev.level === 'high' ? 'bad' : 'dim'}">${esc(prev.level)}</span>`
      + `</span></div>`
      + warnHtml
      + '<div class="sec-title">改动差异</div>'
      + diffHtml(prev.added, prev.removed, prev.unchanged)
      + `<div class="hint" style="margin-top:8px">确认票据有效期 ${prev.confirm_ttl} 秒，`
      + '且只能在服务端使用一次。提交时会带上文件哈希做乐观锁 —— 若文件在此期间被手工改过会被拒绝。</div>',
  });
  if (!ok) return;

  try {
    const r = await api('/scope/commit', {
      method: 'POST',
      body: { confirm_token: prev.confirm_token, expect_sha256: prev.expect_sha256,
              targets: payload, note_append: '' },
    });
    toast('已写入并备份：' + (r.backup || '（无备份文件）'), 'ok');
    meta = r.data || meta;
    rows = toRows(meta.targets);
    draw(host);
  } catch (e) { toast(e.message, 'err'); }
}

function draw(host) {
  const consistent = meta.consistent !== false;
  const warn = (!consistent
      ? alertBox('mid', 'domains 与 targets 不一致（可能是手工编辑只改了一处）。'
                 + '提交一次即可让两者同步。') : '')
    + (rows.some((r) => r.needs_review)
        ? alertBox('mid', `有 ${rows.filter((r) => r.needs_review).length} 条缺少 cid 或授权主体，`
                   + '已用左侧黄条标出，等待人工补齐。') : '');

  host.innerHTML = `
    ${warn}
    <div class="toolbar">
      <button class="primary" id="btnCommit">预览并提交</button>
      <button class="ghost" id="btnPlan">迁移预演</button>
      <button class="ghost" id="btnAdd">新增一条</button>
      <button class="ghost" id="btnReload">重新读取</button>
      <span class="grow"></span>
      <span class="hint">${rows.length} 条 · 文件哈希 ${esc(meta.file && meta.file.sha256_short || '-')}</span>
    </div>
    ${renderTable()}
    <div class="sec-title">关于「是否含子域」</div>
    <div class="alert mid"><span class="ico">!</span>
      <span>当前授权闸门 <code>host_in_scope()</code> <strong>一律做子域匹配</strong>
      （写 <code>a.com</code> 即含其所有子域），产品层<strong>还没有</strong>「只授权主域、
      不含子域」这个开关。因此本版<strong>不提供</strong>该开关的编辑 ——
      给了就是假承诺：你以为排除了子域，工具照样能打。如需该语义，需先改闸门
      （属收紧方向，但要单独回归 + 缺省行为不变）。</span></div>
    <div class="sec-title">生效说明</div>
    <div class="hint">scope.json 每次调用现读，<strong>无需重载、立即生效</strong>。
      写入前会自动备份到 <code>data/console_backups/</code>，
      变更记入 <code>data/console_audit.jsonl</code>（两者均不入库）。</div>`;

  host.querySelector('#btnCommit').onclick = () => commit(host);
  host.querySelector('#btnPlan').onclick = () => runPlan(host);
  host.querySelector('#btnReload').onclick = () => reload();
  host.querySelector('#btnAdd').onclick = () => {
    rows.push({ host: '', include_subdomains: true, ports: '', schemes: '',
                cid: '', owner: '', authorized_at: '', scope_note: '',
                added_by: 'console', needs_review: true });
    draw(host);
  };
  bindTable(host);
}

export async function render(host) {
  const d = await api('/scope');
  meta = d.data || {};
  setFileHint(`scope.json ${meta.file && meta.file.sha256_short || '（不存在）'}`);
  rows = toRows(meta.targets);
  draw(host);
}
