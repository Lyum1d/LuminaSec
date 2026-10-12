/* 合规审计：配置变更日志 + 一键导出（默认脱敏）。
 *
 * P1 就把这一页做成可用的，因为它是「高危二次确认 + 全量留痕」这个承诺的**凭据**：
 * 承诺了留痕，就得有个地方能看见痕。
 */
import { api, esc, fmtTime, toast, setFileHint, alertBox }
  from '/console-assets/core.js?v=112';

const FACES = [['', '全部'], ['scope', '授权白名单'], ['tools', '工具与分级'],
               ['params', '运行参数'], ['rules', '合规与模板'], ['auth', '登录']];

function levelPill(l) {
  const k = l === 'high' ? 'bad' : l === 'mid' ? 'warn' : 'dim';
  return `<span class="pill ${k}">${esc(l || '-')}</span>`;
}

function brief(v) {
  if (v == null) return '';
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  return esc(s.length > 160 ? s.slice(0, 160) + '…' : s);
}

export async function render(host) {
  const face = new URL(location.href).searchParams.get('face') || '';
  const d = await api('/audit?limit=200' + (face ? '&face=' + encodeURIComponent(face) : ''));
  setFileHint(`console_audit.jsonl ${d.file.sha256_short || '（尚无记录）'}`);

  const opts = FACES.map(([v, t]) =>
    `<option value="${esc(v)}"${v === face ? ' selected' : ''}>${esc(t)}</option>`).join('');

  const rowsHtml = (d.items || []).map((r) => `
    <tr>
      <td class="mono">${esc(r.time || fmtTime(r.ts))}</td>
      <td>${esc(r.face)}</td>
      <td>${esc(r.action)}</td>
      <td>${levelPill(r.level)}</td>
      <td>${esc(r.actor || '')}</td>
      <td>${esc(r.note || '')}</td>
      <td class="mono">${brief(r.before)}</td>
      <td class="mono">${brief(r.after)}</td>
    </tr>`).join('');

  host.innerHTML = `
    <div class="toolbar">
      <select id="faceSel" style="width:auto;min-width:150px">${opts}</select>
      <button class="ghost sm" id="btnRefresh">刷新</button>
      <span class="grow"></span>
      <a class="ghost sm" href="/api/console/audit/export?mask=1" target="_blank"
         rel="noopener" style="text-decoration:none;padding:4px 9px;border:1px solid var(--border);border-radius:7px">
        导出 CSV（脱敏）</a>
      <button class="ghost sm" id="btnRaw">导出全量…</button>
    </div>
    ${d.items && d.items.length ? `
      <div class="table-wrap"><table>
        <thead><tr><th>时间</th><th>面</th><th>动作</th><th>等级</th>
          <th>操作者</th><th>说明</th><th>改动前</th><th>改动后</th></tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table></div>`
      : '<div class="empty">尚无配置变更记录。第一次通过控制台改配置后这里会出现记录。</div>'}
    <div class="sec-title">关于留痕范围</div>
    <div class="hint">
      记录内容：时间 / 面 / 动作 / 风险等级 / 说明 / 改动前值 / 改动后值。
      文件位于 <code>data/console_audit.jsonl</code>，<strong>已 gitignored</strong>
      —— 它会包含真实授权主机名，入库即等于公开泄露。
      因此导出<strong>默认脱敏</strong>（主机只留前后各 3 字符）；需要全量时请明确确认。
    </div>`;

  host.querySelector('#faceSel').onchange = (e) => {
    const u = new URL(location.href);
    if (e.target.value) u.searchParams.set('face', e.target.value);
    else u.searchParams.delete('face');
    location.href = u.toString();
  };
  host.querySelector('#btnRefresh').onclick = () => render(host);
  host.querySelector('#btnRaw').onclick = async () => {
    const ok = window.confirm(
      '全量导出会包含真实授权主机名。确认这是发给你自己（或不介意看到靶标的人）？\n\n'
      + '确定 = 全量导出；取消 = 保持脱敏。');
    if (!ok) { toast('已取消（未导出）。'); return; }
    window.open('/api/console/audit/export?mask=0', '_blank');
  };
}
