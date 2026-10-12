/* 运行参数与闸门：分组表单 + 不变量校验 + **热生效**。
 *
 * 热生效的依据：全项目 0 处 `from .config import X`、220 处 `config.X` 属性访问
 * （调用时读取），所以运行时 setattr 立即对所有调用点生效，不用重启。
 *
 * 校验走服务端：`param_spec.validate()` 会**临时把候选值应用到 config 上再跑
 * config.param_warnings()** —— 校验的就是「真正生效后会不会违反不变量」，
 * 而不是一条平行推断。前端不做第二套校验规则（避免两份规则漂移）。
 */
import { api, esc, modal, toast, alertBox, reload, setFileHint }
  from '/console-assets/core.js?v=112';

let DATA = null;
const DIRTY = {};        // key -> 新值
const RESET = new Set(); // 要复位（删掉覆盖）的 key

const SRC = { runtime: ['控制台覆盖', 'warn'], env: ['环境变量', 'dim'],
              default: ['默认值', 'ok'], unknown: ['来源未知', 'dim'] };

function fieldHtml(s) {
  const id = 'p_' + s.key;
  const cur = DIRTY[s.key] !== undefined ? DIRTY[s.key] : s.value;
  let input;
  if (s.type === 'bool') {
    input = `<select id="${id}" data-k="${esc(s.key)}">
      <option value="true"${cur === true ? ' selected' : ''}>开</option>
      <option value="false"${cur === false ? ' selected' : ''}>关</option></select>`;
  } else if (s.type === 'enum') {
    input = `<select id="${id}" data-k="${esc(s.key)}">${s.options.map((o) =>
      `<option value="${esc(o)}"${String(cur) === o ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  } else {
    input = `<input id="${id}" data-k="${esc(s.key)}" data-t="${esc(s.type)}"
      value="${esc(cur)}">`;
  }
  const [srcTxt, srcKind] = SRC[s.source] || SRC.unknown;
  const danger = s.danger ? ' <span class="pill bad">高危</span>' : '';
  return `<div class="kv" style="align-items:center;gap:8px;padding:6px 0">
    <span style="min-width:230px">
      <b style="font-weight:600">${esc(s.label)}</b>${danger}
      <span class="mono hint" style="display:block">${esc(s.key)}</span>
    </span>
    <span style="flex:1;min-width:120px">${input}</span>
    <span style="min-width:230px;text-align:right">
      <span class="pill ${srcKind}">${srcTxt}</span>
      <span class="hint" style="display:block">默认 <span class="mono">${esc(String(s.default))}</span>
        ${s.env ? `· <span class="mono">${esc(s.env)}</span>` : ''}</span>
    </span>
  </div>
  ${s.note ? `<div class="hint" style="margin:-2px 0 8px 0">${esc(s.note)}</div>` : ''}
  ${(s.type === 'int' || s.type === 'float')
      ? `<div class="hint" style="margin:-6px 0 8px 0">取值 ${s.min} ~ ${s.max}</div>` : ''}`;
}

function draw(host) {
  const groups = DATA.groups.map((g) => `
    <div class="sec-title">${esc(g.group)}</div>
    <div class="card">${g.items.map(fieldHtml).join('')}</div>`).join('');

  const ex = `<div class="sec-title">有意排除的参数（以及为什么）</div>
    <div class="card">${DATA.excluded.map((e) => `
      <div class="kv"><span class="mono">${esc(e.key)}</span>
        <span class="hint" style="text-align:right;max-width:70%">${esc(e.why)}</span></div>`).join('')}
    </div>`;

  const dirtyN = Object.keys(DIRTY).length + RESET.size;
  host.innerHTML = `
    ${DATA.warnings.length
        ? DATA.warnings.map((w) => alertBox('high', w)).join('')
        : '<div class="alert low"><span class="ico">i</span><span>当前参数无不变量告警。</span></div>'}
    <div class="toolbar">
      <button class="primary" id="btnSave"${dirtyN ? '' : ' disabled'}>预览并提交${dirtyN ? `（${dirtyN} 项）` : ''}</button>
      <button class="ghost" id="btnResetAll">清空全部运行时覆盖</button>
      <span class="grow"></span>
      <span class="hint">${esc(DATA.note)}</span>
    </div>
    ${groups}
    ${ex}
    <div class="sec-title">为什么改完不用重启</div>
    <div class="hint">
      全项目 <strong>0 处</strong> <code>from .config import X</code>、
      <strong>220 处</strong> <code>config.X</code> 属性访问（都在调用时读取），
      所以运行时改属性立即对所有调用点生效。<br>
      「复位」是<strong>删掉覆盖项</strong>而不是「填成默认值」—— 对「被环境变量设过」的参数
      这两者结果不同：删掉会回到环境变量，写成默认值则会覆盖环境变量。
    </div>`;

  host.querySelectorAll('[data-k]').forEach((el) => {
    el.onchange = () => {
      const k = el.dataset.k;
      const s = DATA.groups.flatMap((g) => g.items).find((x) => x.key === k);
      let v = el.value;
      if (s.type === 'bool') v = v === 'true';
      else if (s.type === 'int') v = parseInt(v, 10);
      else if (s.type === 'float') v = parseFloat(v);
      if (v === s.value) { delete DIRTY[k]; } else { DIRTY[k] = v; }
      RESET.delete(k);
      draw(host);
    };
  });
  const bSave = host.querySelector('#btnSave');
  if (bSave) bSave.onclick = () => save(host);
  host.querySelector('#btnResetAll').onclick = async () => {
    const ok = await modal({
      title: '清空全部运行时覆盖', okText: '确认清空', okClass: 'danger',
      requireAck: true, ackText: '我确认清空所有控制台写入的覆盖值。',
      bodyHtml: alertBox('mid',
        '会删除 data/runtime_overrides.json 里的全部覆盖项。'
        + '**需要重启服务才会真正回到环境变量/默认值**（本进程内的属性仍是覆盖后的值）。'),
    });
    if (!ok) return;
    try {
      const r = await api('/params/reset', { method: 'POST' });
      toast(r.note || '已清空', 'ok');
      await reload();
    } catch (e) { toast(e.message, 'err'); }
  };
}

async function save(host) {
  const body = { values: { ...DIRTY }, reset: [...RESET] };
  let prev;
  try { prev = await api('/params/preview', { method: 'POST', body }); }
  catch (e) { toast(e.message, 'err'); return; }

  const rows = prev.diff.map((d) => `<div class="row">
    <span class="mono">${esc(d.key)}</span>：${esc(String(d.before))} →
    <b>${esc(String(d.after))}</b>
    <span class="hint">（默认 ${esc(String(d.default))}）</span></div>`).join('');

  const go = await modal({
    title: '确认改运行参数',
    okText: '确认提交', okClass: 'danger',
    requireAck: prev.level === 'high',
    ackText: '我确认这些改动会立即改变 Agent 的行为（含防护强度）。',
    bodyHtml: `<div class="kv"><span>风险等级</span><span>`
      + `<span class="pill ${prev.level === 'high' ? 'bad' : 'warn'}">${esc(prev.level)}</span>`
      + `</span></div>`
      + `<div class="hint">${esc(DATA.note)}</div>`
      + '<div class="sec-title">改动</div><div class="diff">' + rows + '</div>'
      + (prev.warnings && prev.warnings.length
          ? '<div class="sec-title">提交后会出现的不变量告警</div>'
            + prev.warnings.map((w) => alertBox('high', w)).join('') : ''),
  });
  if (!go) return;
  try {
    const r = await api('/params/commit', {
      method: 'POST',
      body: { ...body, confirm_token: prev.confirm_token,
              expect_sha256: prev.expect_sha256 },
    });
    toast(`已生效：${(r.applied || []).length} 项即时应用到运行中的服务`, 'ok');
    for (const k of Object.keys(DIRTY)) delete DIRTY[k];
    RESET.clear();
    await reload();
  } catch (e) { toast(e.message, 'err'); }
}

export async function render(host) {
  DATA = await api('/params');
  setFileHint(`runtime_overrides.json ${DATA.file.sha256_short || '（尚无覆盖）'}`);
  draw(host);
}
