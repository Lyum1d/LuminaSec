/* 配置控制台内核（v050）：登录闸门 / 视图路由 / 请求 / 弹窗 / 提示 / 小工具。
 *
 * 零构建、原生 ES module。改完刷新即生效，无 node 依赖。
 * 设计约束（与项目其它部分一致）：
 *   · 不引第三方库、不引 CDN —— 本机有代理且可能离线，外联资源会直接坏掉；
 *   · 图表用自绘 SVG（现有 graph.js 已是先例）。
 */

const API = '/api/console';

/* ============================================================ 请求 */
export async function api(path, { method = 'GET', body = null } = {}) {
  const opt = { method, headers: {}, credentials: 'same-origin' };
  if (body !== null) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(API + path, opt);
  } catch (e) {
    // 网络层失败：控制台自己的提示要「说出来」，否则界面静默空着
    // （与现有 web/ 的 test_appjs.js 所守的同一类行为）
    toast('后端未连接：' + e.message, 'err');
    throw e;
  }
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) {
    const detail = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
    const err = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    err.status = res.status;
    err.data = data;
    if (res.status === 401) { showLogin('登录已过期，请重新登录。'); }
    throw err;
  }
  return data;
}

/* ============================================================ 提示 */
export function toast(msg, kind = '') {
  const host = document.getElementById('toastHost');
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 3200);
}

/* ============================================================ 弹窗 */
let _modalResolve = null;

export function modal({ title, bodyHtml, okText = '确认提交', okClass = 'danger',
                       requireAck = false, ackText = '我确认以上改动', showOk = true }) {
  const mask = document.getElementById('modalMask');
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('modalBody').innerHTML = bodyHtml;
  const ok = document.getElementById('modalOk');
  const ackWrap = document.getElementById('modalAckWrap');
  const ack = document.getElementById('modalAck');
  ok.textContent = okText;
  ok.className = okClass;
  ok.hidden = !showOk;
  ackWrap.hidden = !requireAck;
  document.getElementById('modalAckText').textContent = ackText;
  ack.checked = false;
  const sync = () => { ok.disabled = requireAck && !ack.checked; };
  ack.onchange = sync;
  sync();
  mask.hidden = false;
  return new Promise((resolve) => { _modalResolve = resolve; });
}

function _closeModal(result) {
  document.getElementById('modalMask').hidden = true;
  const r = _modalResolve; _modalResolve = null;
  if (r) r(result);
}

export function bindModal() {
  document.getElementById('modalX').onclick = () => _closeModal(false);
  document.getElementById('modalCancel').onclick = () => _closeModal(false);
  document.getElementById('modalOk').onclick = () => _closeModal(true);
}

/* ============================================================ 小工具 */
/* 纯函数从 lib.js 再导出 —— 拆出去是为了让 Node 能直接 import 做行为测试
 * （DOM 相关的东西留在本文件，纯逻辑在 lib.js）。视图层仍从 core.js 取。 */
export { esc, fmtTime, alertBox, diffHtml, parseList } from '/console-assets/lib.js?v=052';

/* ============================================================ 登录 */
export function showLogin(msg) {
  document.getElementById('loginMask').hidden = false;
  document.getElementById('appRoot').hidden = true;
  document.getElementById('loginWrap').hidden = false;
  document.getElementById('setupWrap').hidden = true;
  if (msg) document.getElementById('loginMsg').textContent = msg;
}

/* 首次设置模式（口令尚未配置）：把登录表单换成设置表单。
 * v102 新增 —— 此前口令未配置时整个 console 403，只能去改环境变量/config.yaml
 * 再重启；而环境变量是「当前窗口有效」（set AGENT_CONSOLE_PASSWORD=...），
 * 于是每开一次服务就要重设一次口令。现在从登录页一次设置、写入 config.yaml。 */
export function showSetup(msg) {
  document.getElementById('loginMask').hidden = false;
  document.getElementById('appRoot').hidden = true;
  document.getElementById('loginWrap').hidden = true;
  document.getElementById('setupWrap').hidden = false;
  document.getElementById('loginMsg').textContent = msg || '';
}

function hideLogin() {
  document.getElementById('loginMask').hidden = true;
  document.getElementById('appRoot').hidden = false;
}

async function doLogin() {
  const pw = document.getElementById('pw').value;
  const msg = document.getElementById('loginMsg');
  msg.textContent = '';
  try {
    await api('/login', { method: 'POST', body: { password: pw } });
    document.getElementById('pw').value = '';
    await boot();
  } catch (e) {
    msg.textContent = e.message;
  }
}

async function doSetup() {
  const p1 = document.getElementById('newPw').value;
  const p2 = document.getElementById('newPw2').value;
  const msg = document.getElementById('loginMsg');
  msg.textContent = '';
  try {
    const r = await api('/password/setup', {
      method: 'POST', body: { password: p1, confirm: p2 },
    });
    document.getElementById('newPw').value = '';
    document.getElementById('newPw2').value = '';
    toast(r.note || '口令已设置并保存。', 'ok');
    await boot();
  } catch (e) {
    msg.textContent = e.message;
  }
}

/* ============================================================ 视图路由 */
const VIEWS = {
  overview: () => import('/console-assets/views/overview.js?v=103'),
  scope:    () => import('/console-assets/views/scope.js?v=052'),
  tools:    () => import('/console-assets/views/tools.js?v=052'),
  // v110：本机自备工具（加目录 → 自动识别 → 并入工具箱）。
  // 刻意**紧挨着「工具与分级」**：两者是同一件事的两半 ——
  // 这一页回答"有哪些工具"，那一页回答"每个工具怎么分级、怎么设闸门"，
  // 而两类工具（外部工具箱 / 自备）在这两页里是**同一套数据**。
  localtools: () => import('/console-assets/views/localtools.js?v=110'),
  params:   () => import('/console-assets/views/params.js?v=052'),
  rules:    () => import('/console-assets/views/rules.js?v=103'),
  // v102：白盒侧（代码库 + 知识库）。放在 scope 之后：两者都是"授权/范围"性质的写入口。
  whitebox: () => import('/console-assets/views/whitebox.js?v=102'),
  // v112：实时监控从占位页换成真页（运行列表 + 透传既有确认/取消）。URL 必须跟着抬。
  monitor:  () => import('/console-assets/views/monitor.js?v=112'),
  // v111：统计看板从占位页换成真看板（自绘 SVG）。URL 必须跟着抬，
  // 否则浏览器会继续用缓存的占位版。
  charts:   () => import('/console-assets/views/charts.js?v=111'),
  audit:    () => import('/console-assets/views/audit.js?v=052'),
};
const TITLES = {
  overview: '总览', scope: '授权白名单', tools: '工具与分级',
  localtools: '本地工具（自备目录）', params: '运行参数',
  rules: '合规与模板', whitebox: '白盒侧（代码库 / 知识库）',
  monitor: '实时监控', charts: '统计看板', audit: '合规审计',
};

let current = '';

export async function goto(view) {
  if (!VIEWS[view]) view = 'overview';
  current = view;
  document.querySelectorAll('#tabs .tab').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === view);
  });
  document.getElementById('viewTitle').textContent = TITLES[view] || view;
  const host = document.getElementById('viewHost');
  host.innerHTML = '<div class="empty">正在加载…</div>';
  try {
    const mod = await VIEWS[view]();
    host.innerHTML = '';
    await mod.render(host);
  } catch (e) {
    // 面板加载失败必须「说出来」。这条是刻意保留的行为：
    // 后端没有某个接口时（404）若只是静默空着，用户会以为功能坏了。
    host.innerHTML = `<div class="alert high"><span class="ico">!</span>`
      + `<span>该面板加载失败：${esc(e.message)}</span></div>`
      + `<div class="hint">若是 404，说明后端未注册该接口（可能版本不匹配）。</div>`;
  }
}

export function reload() { return goto(current); }

/* ============================================================ 启动 */
export async function boot() {
  let s;
  try {
    s = await api('/session');
  } catch (e) {
    showLogin('无法读取会话状态：' + e.message);
    return;
  }
  if (!s.password_configured) {
    // v102：不再只是「让人去改环境变量再重启」—— 直接给设置入口，
    // 写入 config.yaml 长期保存（环境变量仍是最高优先级，但不再是唯一途径）。
    showSetup('控制台口令尚未设置。在下面一次设置即可：口令会写入本机 config.yaml'
              + '（consolePassword）长期保存，重启服务不丢。');
    return;
  }
  if (!s.authenticated) {
    const src = s.password_source === 'env:AGENT_CONSOLE_PASSWORD'
      ? '提示：当前口令来自环境变量 AGENT_CONSOLE_PASSWORD（优先级最高）—— '
        + '在 config.yaml 里改 consolePassword 不会生效，要改请改环境变量。'
      : '提示：当前口令来自本机 config.yaml（consolePassword），重启不丢。';
    showLogin(src);
    return;
  }

  hideLogin();
  document.getElementById('whoami').textContent = '已登录 · 仅本机';
  await goto('overview');
}

export function setFileHint(text) {
  document.getElementById('fileHint').textContent = text || '';
}

function initGlobal() {
  bindModal();
  document.getElementById('loginBtn').onclick = doLogin;
  document.getElementById('pw').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('setupBtn').onclick = doSetup;
  for (const id of ['newPw', 'newPw2']) {
    document.getElementById(id).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doSetup();
    });
  }
  document.getElementById('logoutBtn').onclick = async () => {
    try { await api('/logout', { method: 'POST' }); } catch (e) { /* 忽略 */ }
    showLogin('已退出登录。');
  };
  document.getElementById('themeBtn').onclick = () => {
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('src_theme', next); } catch (e) { /* 忽略 */ }
  };
  document.getElementById('tabs').addEventListener('click', (e) => {
    const b = e.target.closest('.tab');
    if (b) goto(b.dataset.view);
  });
}

initGlobal();
boot();
