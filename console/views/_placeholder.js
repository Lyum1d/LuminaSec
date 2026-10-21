/* 占位视图工厂。
 *
 * P1 只交付「总览 + 授权白名单」两页完整，其余按用户决定留占位。
 * 占位页必须**说清楚三件事**，否则它就只是一个「坏了」的页面：
 *   1. 这一页将来做什么（以及对应哪些后端接口，接口没建就先写「待建」）；
 *   2. 为什么现在没有；
 *   3. 现在想改这些配置该怎么办（给出文件路径 —— 别让人以为功能坏了）。
 */
import { esc } from '/console-assets/core.js?v=112';

export function placeholder({ title, goal, items = [], apis = [], files = [] }) {
  return async function render(host) {
    const apiRows = apis.length
      ? apis.map(([m, p, s]) => {
          const tag = s === 'ready' ? '<span class="pill ok">已有</span>'
            : s === 'partial' ? '<span class="pill warn">部分</span>'
            : '<span class="pill dim">待建</span>';
          return `<div class="kv"><span class="mono">${esc(m)} ${esc(p)}</span>`
               + `<span>${tag}</span></div>`;
        }).join('')
      : '<div class="hint">（本页只读现有接口，无需新接口）</div>';

    host.innerHTML = `
      <div class="alert low"><span class="ico">i</span>
        <span>本页为 <strong>P1 占位</strong>：计划在 ${esc(title)} 里交付以下能力，
        当前尚未实现。现在如需修改，请直接编辑下列文件。</span></div>

      <div class="sec-title">这一页要做什么</div>
      <div class="card"><div>${esc(goal)}</div>
        ${items.length ? '<ul style="margin:10px 0 0 18px;padding:0">'
          + items.map((x) => `<li>${x}</li>`).join('') + '</ul>' : ''}
      </div>

      <div class="sec-title">需要的后端接口</div>
      <div class="card">${apiRows}</div>

      ${files.length ? `<div class="sec-title">当前请直接编辑</div>
      <div class="card">${files.map((f) => `<div class="kv"><span class="mono">${esc(f[0])}</span>`
        + `<span>${esc(f[1])}</span></div>`).join('')}</div>` : ''}`;
  };
}
