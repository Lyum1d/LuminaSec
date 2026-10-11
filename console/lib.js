/* 控制台的**纯函数**部分（不碰 DOM）。
 *
 * 为什么单独一个文件：把纯逻辑与 DOM 拆开，Node 才能直接 `import` 进来做行为测试。
 * 现有 `web/app.js` 是单文件 + 依赖 DOM，于是它的测试（test_appjs.js）只能靠
 * 手写假 DOM 桩去跑，脆弱且难维护。这里从源头避免那条路。
 *
 * 被 `core.js` 再导出，视图层仍从 core.js 取（视图不需要知道文件怎么切）。
 */

/** HTML 转义。所有插进 innerHTML 的动态内容都必须过它。 */
export function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** 秒级时间戳 → 本地时间字符串。 */
export function fmtTime(sec) {
  if (!sec) return '-';
  const d = new Date(sec * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
       + `${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 告警条 HTML。level: high | mid | low */
export function alertBox(level, text) {
  const ico = { high: '!', mid: '!', low: 'i' }[level] || 'i';
  return `<div class="alert ${esc(level)}"><span class="ico">${ico}</span>`
       + `<span>${esc(text)}</span></div>`;
}

/**
 * 白名单改动差异视图。
 *
 * 语义约定（提交前确认框就靠它）：
 *   · 被移除的条目用 `del` 类（红），新增的用 `add` 类（绿）——**不能反**，
 *     确认框里颜色反了会让人把「新增授权」看成「移除授权」，是授权语义错误；
 *   · 没有增删时**必须给出「无变化」提示**，而不是渲染一个空白区域
 *     （空白会被误读成「加载失败」）；
 *   · 所有主机名都要转义（它们来自用户输入）。
 */
export function diffHtml(added = [], removed = [], unchanged = 0) {
  const parts = [];
  removed.forEach((h) => parts.push(`<div class="row del">− ${esc(h)}</div>`));
  added.forEach((h) => parts.push(`<div class="row add">+ ${esc(h)}</div>`));
  if (!added.length && !removed.length) {
    parts.push('<div class="row same">（白名单条目无变化）</div>');
  }
  if (unchanged) parts.push(`<div class="row same">保留 ${unchanged} 条不变</div>`);
  return `<div class="diff">${parts.join('')}</div>`;
}

/**
 * 把「端口/协议」表单值解析成提交用的数组。空 → null（= 不限，与后端语义一致）。
 *
 * 为什么单独抽出来测：这块错了会**静默**改变授权范围 ——
 * 例如把空的 `ports` 提交成 `[]`（后端会拒）或 `[0]`（危险），
 * 又或者把用户写的 `80, 443` 解析成 `[NaN]`。
 */
export function parseList(raw, { numeric = false } = {}) {
  const items = String(raw == null ? '' : raw)
    .split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
  if (!items.length) return null;
  if (!numeric) return items;
  const nums = items.map((x) => Number(x)).filter((n) => Number.isFinite(n));
  return nums.length ? nums : null;
}
