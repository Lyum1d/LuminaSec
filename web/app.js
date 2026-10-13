/* LuminaSec 控制台前端 — 对话式界面 */

/* ---------- v102：工作模式 ----------
 * 模式由起始选择界面（/）经 `/app?mode=` 带进来，落 localStorage 以便下次默认高亮。
 * 它决定两件事，**两端必须一致**：
 *   · 前端：左栏显示哪些标签页、工具列表按模式过滤（下方 renderTools）
 *   · 后端：模型可见的工具 schema 与系统提示片段（app/registry.py + app/agent.py）
 * 前端这里做过滤只是"界面上不给看"，真正的闸门在后端 —— 不要只改前端。
 */
const MODES = {
  blackbox: { name: '黑盒侧测试', icon: '🌐' },
  whitebox: { name: '白盒侧测试', icon: '📦' },
};
//: 白盒模式在界面上保留的工具前缀（与后端 registry._WHITEBOX_ALLOW 保持一致）
const WHITEBOX_TOOL_PREFIX = ['code_', 'kb_', 'note_'];

function readMode() {
  let m = '';
  try {
    m = new URLSearchParams(location.search).get('mode') || '';
    if (!m) m = localStorage.getItem('src_mode') || '';
  } catch (e) { /* 无 URL/localStorage 时退回默认 */ }
  return MODES[m] ? m : 'blackbox';
}

let state = {
  mode: readMode(),
  projects: [],
  currentProject: null,
  sessionId: null,
  threadFresh: true,   // 当前聊天区是否还是「没发过消息」的空线程（true=发送时复用 sessionId）
  tree: [],            // 当前项目的线索树
  eventSource: null,
  tools: [],
  steps: [],
  models: null,
  assistant: null,   // 当前 AI 气泡的 DOM 引用（streaming 时填充）
  branchParent: null, // 开分支弹窗的父会话 id
  confirmBusy: false, // 高危确认是否正在提交（挡连点，防「预支」掉下一次确认）
  pendingConfirm: null,   // 当前待确认步骤的 {token, stepId, needDouble}：服务端要求原样回传
};

/* ---------- v102 模式相关的界面适配 ---------- */

/** 该工具在当前模式下是否可见（与后端 registry._WHITEBOX_ALLOW 保持一致）。 */
function toolVisibleInMode(alias) {
  const a = String(alias || '');
  const isWhiteTool = WHITEBOX_TOOL_PREFIX.some(p => a.startsWith(p));
  if (state.mode === 'whitebox') return isWhiteTool;
  return !isWhiteTool;                 // 黑盒：隐藏白盒工具
}

/** 该项目在当前模式下是否可见（与后端 store projects.mode 一致）。
 * v102 追加：此前项目列表不按模式过滤 —— 选了白盒侧，黑盒项目（目标=企业名/域名）
 * 照样列出来，这正是「选了白盒还出现黑盒项目」的来源。
 * 历史项目 mode 可能为空：按黑盒处理（v102 之前建的项目都是黑盒口径；
 * 后端迁移时已按 target 形态做过一次性回填，这里是前端兜底）。 */
function projectVisibleInMode(p) {
  const m = String((p && p.mode) || 'blackbox');
  if (state.mode === 'whitebox') return m === 'whitebox';
  return m !== 'whitebox';
}

/** 把当前模式刷到界面上：徽标、白盒面板、工具列表、欢迎语。 */
function applyModeUI() {
  const m = MODES[state.mode] || MODES.blackbox;

  const badge = $('modeBadge');
  if (badge) {
    badge.textContent = `${m.icon} ${m.name}`;
    badge.title = '点击切换工作模式（回到起始选择界面）';
  }
  document.body.setAttribute('data-mode', state.mode);

  // 白盒专属标签页：只有白盒模式显示
  const codeTab = $('tabBtnCode');
  if (codeTab) codeTab.style.display = (state.mode === 'whitebox') ? '' : 'none';
  const codePane = $('tab-code');
  if (codePane && state.mode !== 'whitebox') codePane.style.display = 'none';

  // 项目标签页的文案：白盒下"目标"应当被理解为"代码库"
  const pTarget = $('pTarget');
  if (pTarget) {
    pTarget.placeholder = (state.mode === 'whitebox')
      ? '代码库：本机源码目录绝对路径，如 E:\\repo\\target'
      : '目标：企业名 / 域名';
  }
  const pName = $('pName');
  if (pName) {
    pName.placeholder = (state.mode === 'whitebox')
      ? '项目名称，如：审计-某开源组件'
      : '项目名称，如：补天-XX厂商';
  }

  // 欢迎语按模式给不同的下一步提示
  const w = $('welcome');
  if (w) {
    const h = w.querySelector('.w-title, h2, h3') || w;
    if (state.mode === 'whitebox') {
      h.innerHTML = '<b>📦 白盒侧测试</b><br><span style="font-weight:400">'
        + '先建项目 → 把源码目录入库（<code>code_ingest</code>）→ 建索引（<code>code_index</code>）'
        + '→ 查候选（<code>code_search</code>）→ 读上下文判可达性（<code>code_read</code>）。'
        + '<br>本模式只放代码审计工具，不会向任何外部目标发流量。</span>';
    } else {
      h.innerHTML = '<b>🌐 黑盒侧测试</b><br><span style="font-weight:400">'
        + '先建项目并填授权目标 → 描述本轮任务（侦察 / 验证 / 取证）。'
        + '<br>所有请求都会经过授权白名单闸门，范围外不发。</span>';
    }
  }

  renderTools();
  loadCodebases();
}

/** 切换模式：回到起始选择界面重新选（模式在进入工作区前定，避免"进去再回头改"）。 */
function switchMode() {
  location.href = '/';
}

/** 白盒面板：列出已入库代码库（只读；登记/删除在配置控制台）。 */
async function loadCodebases() {
  const host = $('codebaseList');
  if (!host || state.mode !== 'whitebox') return;
  host.innerHTML = '<div class="muted" style="padding:8px">加载中…</div>';
  try {
    const d = await api('/api/codebases');
    if (!d.ok) throw new Error(d.error || '读取失败');
    if (!d.codebases.length) {
      host.innerHTML = '<div class="muted" style="padding:8px">'
        + '还没有入库任何代码库。<br>在下方输入本机源码目录，让 Agent 执行 <code>code_ingest</code>。'
        + '<br><br>登记/删除也可在<a href="/console" target="_blank" rel="noopener">配置控制台</a>里做。</div>';
      return;
    }
    host.innerHTML = d.codebases.map(cb => `
      <div class="codebase-item" title="${esc(cb.root)}">
        <div class="cb-id">${esc(cb.codebase_id)}</div>
        <div class="cb-meta">${esc(cb.white_layer)} · ${esc(cb.source)}</div>
        <div class="cb-root muted">${esc(cb.root)}</div>
      </div>`).join('');
  } catch (e) {
    host.innerHTML = `<div class="muted" style="padding:8px">读取失败：${esc(e.message)}</div>`;
  }
}

/* ---------- 工具函数 ---------- */
const $ = (id) => document.getElementById(id);const esc = (s) => String(s).replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
}

function scrollToBottom() {
  const m = $('messages');
  m.scrollTop = m.scrollHeight;
}

function clearWelcome() {
  const w = $('welcome');
  if (w) w.remove();
}

/* 系统提示（非任务的日志，如「模型已切换」「项目已删除」） */
function log(text, cls = '') {
  clearWelcome();
  const box = $('messages');
  const line = document.createElement('div');
  line.className = 'sys-note ' + cls;
  line.textContent = text;
  box.appendChild(line);
  scrollToBottom();
}

/* 最小 markdown 渲染：代码块 / 行内代码 / 加粗 / 标题 / 列表 */
function md(text) {
  if (!text) return '';
  let s = esc(text);
  s = s.replace(/```[a-zA-Z]*\r?\n?([\s\S]*?)```/g, (_, code) =>
    `<pre class="code-block">${code.replace(/^\r?\n/, '').replace(/\r?\n$/, '')}</pre>`);
  s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  s = s.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
  s = s.replace(/^#{1,4}\s+(.+)$/gm, '<div class="md-h">$1</div>');
  s = s.replace(/^\s*[-*]\s+(.+)$/gm, '<div class="md-li">• $1</div>');
  s = s.replace(/\n/g, '<br>');
  return s;
}

/* ---------- 亮/暗主题 ---------- */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('themeToggle');
  if (btn) btn.textContent = theme === 'light' ? '☀️' : '🌙';
  try { localStorage.setItem('src_theme', theme); } catch (e) {}
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}

/* ---------- 消息气泡 ---------- */
function addUserMessage(text) {
  clearWelcome();
  const m = $('messages');
  const wrap = document.createElement('div');
  wrap.className = 'msg user';
  wrap.innerHTML = `<div class="avatar">🧑</div><div class="bubble">${esc(text)}</div>`;
  m.appendChild(wrap);
  scrollToBottom();
}

function createAssistant() {
  clearWelcome();
  const m = $('messages');
  const wrap = document.createElement('div');
  wrap.className = 'msg assistant';
  wrap.innerHTML = `
    <div class="avatar">🛡</div>
    <div class="bubble">
      <div class="bubble-meta">
        <span class="who">LuminaSec</span>
        <span class="meta-tags"></span>
      </div>
      <div class="bubble-steps"></div>
      <div class="bubble-body"></div>
      <div class="bubble-status"></div>
    </div>`;
  m.appendChild(wrap);
  state.assistant = {
    root: wrap,
    metaTags: wrap.querySelector('.meta-tags'),
    stepsEl: wrap.querySelector('.bubble-steps'),
    bodyEl: wrap.querySelector('.bubble-body'),
    statusEl: wrap.querySelector('.bubble-status'),
    outputEl: null,
  };
  scrollToBottom();
  return state.assistant;
}

function setAssistantMeta(tagText) {
  const a = state.assistant; if (!a) return;
  const tag = document.createElement('span');
  tag.className = 'tag';
  tag.textContent = tagText;
  a.metaTags.appendChild(tag);
}

function addTargetTag(target) {
  const a = state.assistant; if (!a) return;
  const tag = document.createElement('span');
  tag.className = 'tag target';
  tag.textContent = '目标：' + target;
  a.metaTags.appendChild(tag);
}

function setAssistantStatus(text) {
  const a = state.assistant; if (!a) return;
  a.statusEl.textContent = text;
  scrollToBottom();
}

function closeOutput() { if (state.assistant) state.assistant.outputEl = null; }

function appendReasoning(html) {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const div = document.createElement('div');
  div.className = 'reasoning';
  div.innerHTML = html;
  a.bodyEl.appendChild(div);
  scrollToBottom();
}

function appendCommand(cmd) {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const pre = document.createElement('pre');
  pre.className = 'code-block cmd';
  pre.textContent = '$ ' + cmd;
  a.bodyEl.appendChild(pre);
  scrollToBottom();
}

function appendOutput(text) {
  const a = state.assistant; if (!a) return;
  if (!a.outputEl) {
    const pre = document.createElement('pre');
    pre.className = 'code-block output';
    a.bodyEl.appendChild(pre);
    a.outputEl = pre;
  }
  a.outputEl.textContent += text + '\n';
  scrollToBottom();
}

function appendLine(text, cls = '') {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const div = document.createElement('div');
  div.className = 'line ' + cls;
  div.textContent = text;
  a.bodyEl.appendChild(div);
  scrollToBottom();
}

function appendAnswer(mdHtml) {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const div = document.createElement('div');
  div.className = 'answer-block';
  div.innerHTML = `<div class="answer-title">✔ 结论</div><div class="answer-body">${mdHtml}</div>`;
  a.bodyEl.appendChild(div);
  scrollToBottom();
}

function finalizeAssistant(stateName, stepCount) {
  const a = state.assistant; if (!a) return;
  a.statusEl.textContent = '';
  appendLine(`■ 结束（${stateName}），共 ${stepCount} 步`, 'muted');
  state.assistant = null;
}

/* ---------- 初始化 ---------- */
async function init() {
  // 同步主题按钮图标（主题本身已在 <head> 内联脚本里按 localStorage 设置，避免闪烁）
  const t = document.documentElement.getAttribute('data-theme') || 'dark';
  $('themeToggle').textContent = t === 'light' ? '☀️' : '🌙';

  // v102：先把模式刷到界面上（徽标/标签页/欢迎语/工具过滤）。
  // 放在最前面：即便后端还没就绪，用户也能立刻看到自己进的是哪个模式。
  applyModeUI();

  await loadModels();
  // 等后端就绪再继续（页面可能在服务启动完成前被打开）
  if (!(await waitForBackend())) return;
  try {
    const h = await api('/api/health');
    const dot = h.llm.ready ? '<span class="dot ok"></span>' : '<span class="dot bad"></span>';
    const cur = (state.models && state.models.items.find(m => m.name === h.current_backend)) || {};
    const label = cur.label || h.current_backend;
    $('status').innerHTML = `
      ${dot}<b>${esc(label)}</b> ${esc(h.current_model || cur.model || '')}（${h.llm.ready ? '就绪' : '未就绪'}）
      · <b>可编排</b> ${h.registry.scriptable}
      · <b>本地</b> ${h.registry.launchable}
      · <b>授权</b> ${h.enforce_scope ? ((h.scope_domains || []).length ? `${h.scope_domains.length} 个目标` : '未配置') : '已关闭'}`;
    // 授权边界异常必须显式可见：白名单为空时所有工具都会被拒（现象像"工具坏了"），
    // 而 ENFORCE_SCOPE=0 时工具会对任意目标执行。两种都不该靠使用者自己猜。
    if (h.scope_warning) log(`⚠ ${h.scope_warning}`, 'c-err');
  } catch (e) {
    $('status').innerHTML = `<span class="dot bad"></span>后端未连接：${esc(e.message)}`;
    return;
  }
  loadProjects().then(() => { autoSelectProject(); renderProjects(); updateProjectHeader(); loadFindings(); loadFacts(); loadIdentities(); loadRequests(); loadTree(); });
  loadTools();
  refreshUsageBadge();
}

/* 后端就绪探测：每 0.8s 重试一次，最多 40 次（约 30s），全部失败给出可操作提示 */
async function waitForBackend(tries = 40) {
  for (let i = 1; i <= tries; i++) {
    try {
      await api('/api/health');
      return true;
    } catch (e) {
      $('status').innerHTML = `<span class="dot bad"></span>正在连接后端…（${i}/${tries}）`;
      await new Promise(r => setTimeout(r, 800));
    }
  }
  $('status').innerHTML = '<span class="dot bad"></span>后端未连接：请确认服务已启动（python run.py），或刷新页面重试';
  return false;
}

/* ---------- 模型切换 ---------- */
async function loadModels() {
  try {
    const d = await api('/api/models');
    state.models = d;
    renderModelSelect();
  } catch (e) { /* 后端未连接时静默 */ }
}

function renderModelSelect() {
  const sel = $('modelSelect');
  const d = state.models;
  if (!sel || !d) return;
  sel.innerHTML = d.items.map(m => `
    <option value="${esc(m.name)}" ${m.name === d.current ? 'selected' : ''} ${m.available ? '' : 'disabled'}>
      ${esc(m.label)} · ${esc(m.model)}${m.available ? '' : '（未配置）'}
    </option>`).join('');
}

async function switchModel(name) {
  if (!name || (state.models && name === state.models.current)) return;
  try {
    const d = await api('/api/models', {
      method: 'POST',
      body: JSON.stringify({ backend: name }),
    });
    if (state.models) state.models.current = d.current;
    renderModelSelect();
    log(`模型已切换：${d.current}（${d.model}），下一个任务生效`, 'c-ok');
  } catch (e) {
    log(`模型切换失败：${e.message}`, 'c-err');
    loadModels();
  }
}

/* ---------- 项目 ---------- */
let editingProject = null;
let pendingDelete = null;

function persistCurrent() {
  try { localStorage.setItem('src_current_project', state.currentProject || ''); } catch (e) {}
}

function autoSelectProject() {
  if (!state.projects.length) { state.currentProject = null; persistCurrent(); return; }
  const ids = new Set(state.projects.map(p => p.id));
  let want = '';
  try { want = localStorage.getItem('src_current_project') || ''; } catch (e) {}
  state.currentProject = (want && ids.has(want)) ? want : state.projects[0].id;
  persistCurrent();
}

function updateProjectHeader() {
  const p = state.projects.find(x => x.id === state.currentProject);
  $('currentProjectName').textContent = p ? p.name : '未选择项目';
  $('currentProjectTarget').textContent = p ? (p.target || '') : '';
}

async function loadProjects() {
  // v102：按当前模式拉取（后端 ?mode= 过滤），回来再滤一层兜底 ——
  // 即便后端被回退成忽略 ?mode 的旧版本，另一侧的项目也不会摆上界面。
  const d = await api('/api/projects?mode=' + encodeURIComponent(state.mode));
  state.projects = (d.items || []).filter(projectVisibleInMode);
  renderProjects();
}

function renderProjects() {
  const el = $('projectList');
  if (!state.projects.length) {
    el.innerHTML = (state.mode === 'whitebox')
      ? '<div class="empty">还没有白盒项目，先建一个<br>（目标填本机源码目录绝对路径）</div>'
      : '<div class="empty">还没有项目，先建一个</div>';
    return;
  }
  el.innerHTML = state.projects.map(p => {
    const noTarget = (state.mode === 'whitebox') ? '无源码路径' : '无目标';
    if (editingProject === p.id) {
      return `<div class="list-item active">
        <div class="row" style="margin-bottom:4px;"><input id="editPName" value="${esc(p.name)}" placeholder="项目名称"></div>
        <div class="row"><input id="editPTarget" value="${esc(p.target || '')}"
          placeholder="${(state.mode === 'whitebox') ? '源码目录：本机绝对路径' : '目标：企业名 / 域名'}"></div>
        <div style="display:flex;gap:6px;">
          <button class="primary sm" onclick="submitEditProject('${p.id}')">保存</button>
          <button class="sm" onclick="cancelEditProject()">取消</button>
        </div>
      </div>`;
    }
    if (pendingDelete === p.id) {
      return `<div class="list-item active" style="border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.08);">
        <div class="name">删除「${esc(p.name)}」？</div>
        <div class="meta">漏洞记录、已证事实与会话将一并删除，不可恢复。</div>
        <div class="item-actions" style="display:flex;">
          <button class="danger" onclick="event.stopPropagation();removeProject('${p.id}')">确认删除</button>
          <button onclick="event.stopPropagation();pendingDelete=null;renderProjects()">取消</button>
        </div>
      </div>`;
    }
    return `<div class="list-item ${state.currentProject === p.id ? 'active' : ''}"
         onclick="selectProject('${p.id}')">
      <div class="name">${esc(p.name)}</div>
      <div class="meta">${esc(p.target || noTarget)} · 漏洞 ${p.finding_count}</div>
      <div class="item-actions">
        <button onclick="event.stopPropagation();startEditProject('${p.id}')">重命名</button>
        <button class="danger" onclick="event.stopPropagation();askDeleteProject('${p.id}')">删除</button>
      </div>
    </div>`;
  }).join('');
}

async function createProject() {
  const name = $('pName').value.trim();
  if (!name) return alert('请填写项目名称');
  const p = await api('/api/projects', {
    method: 'POST',
    // v102：把当前模式建到项目上 —— 否则白盒下建的项目无法归属白盒侧，
    // 列表过滤与会话模式闸门（后端 create_session 的错配检查）都无从生效。
    body: JSON.stringify({ name, target: $('pTarget').value.trim(), mode: state.mode }),
  });
  $('pName').value = ''; $('pTarget').value = '';
  state.currentProject = p.id;
  persistCurrent();
  await loadProjects();
  updateProjectHeader();
  loadFindings();
  loadFacts();
  loadIdentities();
  loadRequests();
  loadTree();
}

async function selectProject(pid) {
  state.currentProject = pid;
  persistCurrent();
  renderProjects();
  updateProjectHeader();
  loadFindings();
  loadFacts();
  loadIdentities();
  loadRequests();
  // 切项目 = 切对话树：清空当前线程，聊天区回到空态
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.sessionId = null;
  state.threadFresh = true;
  state.steps = [];
  state.assistant = null;
  $('confirmBox').innerHTML = '';
  $('messages').innerHTML = `
    <div class="welcome" id="welcome">
      <div class="welcome-logo">🛡</div>
      <div class="welcome-title">LuminaSec 渗透测试编排助手</div>
      <div class="welcome-sub">已切换项目。描述你的任务开始测试；发现可疑点可随时「＋ 分支」拆出新线索。</div>
    </div>`;
  loadTree();
}

function startEditProject(pid) {
  editingProject = pid;
  pendingDelete = null;
  renderProjects();
  const el = $('editPName');
  if (el) el.focus();
}

function cancelEditProject() {
  editingProject = null;
  renderProjects();
}

async function submitEditProject(pid) {
  const name = $('editPName').value.trim();
  if (!name) return alert('项目名称不能为空');
  await api(`/api/projects/${pid}`, {
    method: 'PUT',
    body: JSON.stringify({ name, target: $('editPTarget').value.trim() }),
  });
  editingProject = null;
  await loadProjects();
  updateProjectHeader();
  log('项目已保存修改', 'c-ok');
}

function askDeleteProject(pid) {
  pendingDelete = pid;
  editingProject = null;
  renderProjects();
}

async function removeProject(pid) {
  await api(`/api/projects/${pid}`, { method: 'DELETE' });
  pendingDelete = null;
  if (state.currentProject === pid) {
    state.currentProject = null;
    $('findingList').innerHTML = '<div class="empty">暂无记录</div>';
    $('factList').innerHTML = '<div class="empty">暂无已证事实</div>';
    $('factCount').textContent = '0';
  }
  await loadProjects();
  autoSelectProject();
  renderProjects();
  updateProjectHeader();
  log('项目已删除', 'c-ok');
  loadTree();
}

/* ---------- 工具箱 ---------- */
async function loadTools() {
  const d = await api('/api/tools?kind=all');
  state.tools = d.items;
  // v106：把「为什么工具这么少」记下来，渲染时摆在清单最上面。
  // 未配置工具箱时目录里只剩内置工具（httpreplay / py_exec / kb_* / code_* …），
  // 使用者看到的是「工具全空」，而原因原本只存在于后端 registry.errors 里 ——
  // 结果是只能翻日志或问人。这里把原因与配置方法直接显示出来。
  state.toolboxNotice = (d.errors && d.errors.length) ? String(d.errors[0]) : '';
  // v110：工具来源现在有三类（外部工具箱 / 本机自备 / 内置能力）。
  // 只显示"未配置工具箱"会让用户以为无路可走 —— 所以在提示下面补一句"下一步"。
  state.toolboxHint = d.local_hint || '';
  renderTools();
}

function renderTools() {
  const kw = $('toolSearch').value.trim().toLowerCase();
  const kind = $('toolKind').value;
  let items = state.tools.filter(t => {
    if (kind === 'web') return !!t.url;
    // v108：内置能力**不是**本地可启动的程序（它由 Agent 在任务执行时调用）。
    // 原先这里只判 exists && !url，而内置能力的 exists 为真 ⇒ 它们被摆进
    // "本地工具（点击启动）"，点一下就去 spawn 一个不存在的路径 → WinError 123。
    if (kind === 'launchable') return !!t.exists && !t.url && !t.builtin;
    if (kind === 'scriptable') return !!t.scriptable;
    return true;
  });
  // v102：按模式过滤。白盒只留代码审计/留痕工具，黑盒隐藏 code_*。
  // ⚠️ 这里只是"界面上不给看"；真闸门在后端 registry.mode_allows（模型拿不到 schema）。
  items = items.filter(t => toolVisibleInMode(t.alias));
  if (kw) items = items.filter(t =>
    t.name.toLowerCase().includes(kw) || t.alias.toLowerCase().includes(kw));

  const groups = {};
  items.forEach(t => (groups[t.category] = groups[t.category] || []).push(t));

  // 降级提示摆在最上面：让「工具少了」这件事自带解释，而不是让人以为程序坏了。
  const notice = state.toolboxNotice
    ? `<div class="tool-notice">⚠️ ${esc(state.toolboxNotice)}</div>`
      + (state.toolboxHint
          ? `<div class="tool-notice hint2">${esc(state.toolboxHint)}</div>` : '')
    : '';

  $('toolList').innerHTML = notice + (Object.entries(groups).map(([cat, list]) => `
    <div class="tool-group">${esc(cat)} (${list.length})</div>
    ${list.map(t => {
      // v108：内置能力没有可启动的程序 ⇒ **不给点击交互**，改挂「内置」徽标 + 说明。
      // 风险分级照旧显示（例如 Python代码执行 是 L3），只是不再假装它能"一键启动"。
      const risk = t.scriptable ? `<span class="badge ${t.risk_level}">${t.risk_level}</span>` : '';
      // v110：自备工具加「自备」徽标。它是**本机**的，换台机器就没有 ——
      // 与工具箱自带的一视同仁会让用户以为"程序把我的工具吃掉了"。
      const srcBadge = t.source === 'local'
        ? '<span class="badge local-src">自备</span>' : '';
      const badge = t.builtin
        ? `<span class="badge builtin">内置</span>${risk}`
        : t.url
          ? '<span class="badge">网页</span>'
          : t.disabled
            ? '<span class="badge off">已禁用</span>'
            : t.scriptable
              ? risk
              : '<span class="badge gui">GUI</span>';
      const click = t.builtin ? '' : (t.url ? `window.open('${t.url}')` : `launchTool('${t.alias}')`);
      const tip = t.builtin
        ? `${t.name}（内置能力）：由 Agent 在任务执行时调用，不需要工具箱，也不能单独启动`
        : (t.source === 'local'
            ? `${t.path || t.url}（来自你自备的目录：${t.root_label || '未命名'}）`
            : (t.path || t.url));
      return `<div class="tool${t.builtin ? ' tool-builtin' : ''}"${
        click ? ` onclick="${click}"` : ''} title="${esc(tip)}">
                <span class="tname">${esc(t.name)}</span>${srcBadge}${badge}
              </div>`;
    }).join('')}
  `).join('')) || (notice ? '' : '<div class="empty">无匹配工具</div>');
}

async function launchTool(alias) {
  try {
    const r = await api(`/api/tools/launch/${alias}`, { method: 'POST' });
    log(r.ok ? `已启动：${r.message}` : `启动失败：${r.message}`, r.ok ? 'c-ok' : 'c-err');
  } catch (e) {
    // L2/L3 工具需要显式确认：首次调用会被后端以 409 挡下，这里据此二次确认后重试。
    // 与「流程内工具执行」的风险闸门口径保持一致（此前启动图形界面工具完全不校验分级）。
    const msg = String(e.message || '');
    if (msg.includes('需要显式确认')) {
      if (!confirm(`${msg}\n\n确认启动该工具？`)) return;
      try {
        const r2 = await api(`/api/tools/launch/${alias}?confirm=true`, { method: 'POST' });
        log(r2.ok ? `已启动：${r2.message}` : `启动失败：${r2.message}`, r2.ok ? 'c-ok' : 'c-err');
      } catch (e2) {
        log(`启动失败：${e2.message}`, 'c-err');
      }
      return;
    }
    log(`启动失败：${msg}`, 'c-err');
  }
}

/* ---------- 任务执行 ---------- */
async function sendTask() {
  const msg = $('taskInput').value.trim();
  if (!msg) return;
  $('taskInput').value = '';
  $('sendBtn').disabled = true;
  $('confirmBox').innerHTML = '';
  state.steps = [];
  state.assistant = null;

  if (state.currentProject && !state.projects.some(p => p.id === state.currentProject)) {
    autoSelectProject();
    renderProjects();
    updateProjectHeader();
  }
  if (!state.currentProject) {
    if (state.projects.length) {
      autoSelectProject();
      renderProjects();
      updateProjectHeader();
    } else {
      log('还没有项目：请先在左侧「新建项目」并填写目标，Agent 才能识别扫描对象', 'c-warn');
      $('sendBtn').disabled = false;
      return;
    }
  }
  const proj = state.projects.find(p => p.id === state.currentProject);
  if (proj && !proj.target) {
    log(`项目「${proj.name}」未填写目标，模型可能无法识别扫描对象（可在项目上点「重命名」补填）`, 'c-warn');
  }

  // 先渲染用户气泡 + AI 气泡，再发起任务
  addUserMessage(msg);
  createAssistant();

  // 同一线索内连续发消息 = 续聊（上下文累积，便于对一个方向深挖）；
  // 新建对话或刚切换进来的已有线索，threadFresh 标记是否需要复用。
  let sid;
  if (state.sessionId && state.threadFresh) {
    sid = state.sessionId;
  } else {
    const s = await api('/api/sessions', {
      method: 'POST',
      // v102：把当前模式一并建到会话上。**只在新建时传** —— 续聊/切线索分支
      // 由后端从库里恢复原模式（store.create_branch 继承父会话），中途不会改口径。
      body: JSON.stringify({ project_id: state.currentProject || '', mode: state.mode }),
    });
    sid = s.session_id;
    state.threadFresh = false;
  }
  state.sessionId = sid;

  await api(`/api/sessions/${sid}/run`, {
    method: 'POST',
    body: JSON.stringify({ message: msg, project_id: state.currentProject || '' }),
  });

  connectStream(sid);
}

function connectStream(sid) {
  if (state.eventSource) state.eventSource.close();
  const es = new EventSource(`/api/sessions/${sid}/stream`);
  state.eventSource = es;

  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    handleEvent(ev);
  };
  es.onerror = () => {
    es.close();
    $('sendBtn').disabled = false;
  };
}

function handleEvent(ev) {
  switch (ev.type) {
    case 'session_start':
      setAssistantMeta(`会话 ${ev.session_id}`);
      break;
    case 'model':
      setAssistantMeta(`${ev.data.label} · ${ev.data.model}`);
      break;
    case 'target':
      addTargetTag(ev.data);
      break;
    case 'thinking':
      setAssistantStatus(ev.data);
      break;
    case 'reasoning':
      appendReasoning(md(ev.data));
      break;
    case 'command':
      appendCommand(ev.data);
      break;
    case 'output':
      appendOutput(ev.data);
      break;
    case 'exit':
      appendLine(`退出码 ${ev.code}`, ev.code === 0 ? 'muted' : 'err');
      break;
    case 'step_start':
    case 'step_done':
    case 'step_denied':
      upsertStep(ev.step);
      break;
    case 'error':
      appendLine(ev.data, 'err');
      break;
    case 'need_confirm':
      showConfirm(ev);
      break;
    case 'branch_proposal':
      showBranchCard(ev.data);
      break;
    case 'branch_update':
      log(`子线索「${ev.data.title}」有新结论：${ev.data.summary.slice(0, 80)}…（已可在报告/小地图查看）`, 'c-ok');
      loadTree();
      break;
    case 'answer':
      appendAnswer(md(ev.data));
      break;
    case 'done':
      finalizeAssistant(ev.state, state.steps.length);
      $('sendBtn').disabled = false;
      state.eventSource.close();
      state.threadFresh = false;
      if (state.currentProject) { loadFindings(); loadFacts(); loadTree(); }
      refreshUsageBadge();
      break;
  }
}

/* ---------- 执行计划 ---------- */
function upsertStep(step) {
  const i = state.steps.findIndex(s => s.id === step.id);
  if (i >= 0) state.steps[i] = step; else state.steps.push(step);
  renderSteps();
}

function renderSteps() {
  const a = state.assistant; if (!a) return;
  const el = a.stepsEl;
  if (!state.steps.length) { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = `<div class="steps-title">执行计划 · ${state.steps.length} 步</div>` +
    state.steps.map((s, i) => `
      <div class="step-chip">
        <span class="idx">${i + 1}</span>
        <span class="badge ${s.risk.level}">${s.risk.level}</span>
        <span class="t">${esc(s.tool_name)} → ${esc(s.target || '')}</span>
        <span class="st ${s.status}">${s.status}</span>
      </div>`).join('');
}

/* ---------- 高危确认 ---------- */
/* 参数改成可编辑：闸门原本只有「放行 / 拒绝」两个结果，但很多时候用户知道该怎么改
   （换参数位置、去掉危险开关、把范围缩小），却只能整个否掉、让模型再猜一轮。
   改完参数点放行即可；参数照样要过服务端的清洗管线与授权白名单校验，改参数不等于绕闸门。 */
function showConfirm(ev) {
  const s = ev.step;
  const needDouble = ev.risk.double_confirm;
  // 服务端在下发 need_confirm 时附带一次性令牌；提交确认必须原样回传，
  // 否则会被判为「上一轮遗留的确认」而拒绝（409）。needDouble 用于 L3 的二次确认。
  state.pendingConfirm = { token: ev.token || '', stepId: s.id, needDouble: !!needDouble };
  $('confirmBox').innerHTML = `
    <div class="confirm">
      <div class="title">⚠ 需要授权：${esc(s.tool_name)}（风险等级 ${ev.risk.level}）</div>
      <div class="desc">
        目标：<code>${esc(s.target || '(无)')}</code><br>
        判定依据：${esc(ev.risk.reason || ev.risk.name)}<br>
        <span class="muted">参数可以直接改——改完点「放行」就按你改的执行（仍会过一遍参数清洗与授权白名单）。</span>
      </div>
      <textarea id="cfmArgs" class="cfm-args" spellcheck="false" placeholder="（无参数）">${esc(s.args || '')}</textarea>
      <div class="actions">
        ${needDouble ? '<label><input type="checkbox" id="authChk"> 我确认已获得该目标的书面授权</label>' : ''}
        <button class="primary" onclick="doConfirm(true)">放行</button>
        <button class="danger" onclick="doConfirm(false)">拒绝</button>
      </div>
    </div>`;
}

async function doConfirm(approved) {
  const p = state.pendingConfirm || {};
  const chk = $('authChk');
  // 只有 L3（needDouble）才要求勾选书面授权；服务端同样会校验，这里只是提前拦一下
  if (approved && p.needDouble && chk && !chk.checked) {
    return alert('请先勾选授权确认');
  }
  // 防重复点击：连点会投递多条确认，多出来的那条会被**下一个**高危步骤直接消费掉，
  // 等于用户没看确认框就放行了。这里用一次性的在途标志把并发点击挡掉，
  // 后端也会以 409 兜底（队列非空即拒收），两侧都不依赖对方。
  if (state.confirmBusy) return;
  state.confirmBusy = true;
  const box = $('cfmArgs');
  const args = box ? box.value : '';
  $('confirmBox').innerHTML = '';
  appendLine(approved ? '→ 已放行' : '→ 已拒绝', approved ? '' : 'err');
  try {
    // 双闸门：必须带上一次性 token 与 step_id，后端据此拒绝陈旧/重放/伪造的确认
    // （详见 /confirm 接口注释）。
    await api(`/api/sessions/${state.sessionId}/confirm`, {
      method: 'POST',
      // 未放行时不回传参数；放行时原样回传（服务端只在「与模型给的不同」时才替换）
      body: JSON.stringify({
        approved,
        args: approved ? args : null,
        token: p.token || '',
        step_id: p.stepId || '',
        // L3 必须显式确认已获书面授权；非 L3 一律回 true（服务端不看该字段）
        auth_ack: approved ? !!(p.needDouble ? (chk && chk.checked) : true) : false,
      }),
    });
  } catch (e) {
    appendLine(`确认提交失败：${e.message}`, 'err');
  } finally {
    state.confirmBusy = false;
  }
}

/* ---------- 线索树（对话树小地图） ---------- */
const THREAD_STATUS_LABEL = { active: '进行中', done: '已完成', abandoned: '已放弃' };

async function loadTree() {
  if (!state.currentProject) { $('treeBar').style.display = 'none'; return; }
  try {
    const d = await api(`/api/projects/${state.currentProject}/tree`);
    state.tree = d.items;
    $('treeBar').style.display = 'flex';
    renderTree();
  } catch (e) { /* 树加载失败不打断聊天 */ }
}

function threadName(n) {
  return n.title || (n.task || '').slice(0, 18) || '未命名对话';
}

/* 树的父子关系：只保留「父节点确实在本树里」的边，其余当根节点。
   父线索被删掉、或线索被移到别的项目时，子线索的 parent_id 会指向树外；
   若照搬会导致整棵子线索在建树时凭空消失，所以这里统一收敛为根。 */
function treeEdges() {
  const ids = new Set(state.tree.map(n => n.id));
  const byParent = {};
  state.tree.forEach(n => {
    const pid = (n.parent_id && ids.has(n.parent_id)) ? n.parent_id : '';
    (byParent[pid] = byParent[pid] || []).push(n);
  });
  return byParent;
}

/* 前序遍历：给每个节点算出深度和第几号，同列的节点按前序号排序后父子连线不会交叉 */
function treeLayout() {
  const byParent = treeEdges();
  const depthOf = {}, orderOf = {};
  const seen = new Set();
  let seq = 0;
  const walk = (pid, d) => (byParent[pid] || []).forEach(n => {
    if (seen.has(n.id)) return;        // 数据成环时防死循环
    seen.add(n.id);
    depthOf[n.id] = d;
    orderOf[n.id] = seq++;
    walk(n.id, d + 1);
  });
  walk('', 0);
  // 兜底：成环等原因没被走到的节点，按根节点补上，不让它有洞
  state.tree.forEach(n => {
    if (!seen.has(n.id)) {
      seen.add(n.id);
      depthOf[n.id] = 0;
      orderOf[n.id] = seq++;
    }
  });
  const maxDepth = Math.max(0, ...Object.values(depthOf));
  const cols = Array.from({ length: maxDepth + 1 }, (_, d) =>
    state.tree.filter(n => depthOf[n.id] === d).sort((a, b) => orderOf[a.id] - orderOf[b.id]));
  return { cols, depthOf };
}

function renderTree() {
  const strip = $('treeStrip');
  if (!state.tree.length) {
    strip.innerHTML = '<div class="tree-empty">同一方向聊久了会遗忘细节——发现可疑点就「＋ 分支」拆出独立线索深挖</div>';
    return;
  }
  const { cols } = treeLayout();
  strip.innerHTML = cols.map(nodes => `<div class="tree-col">
      ${nodes.map(n => {
        const isCur = n.id === state.sessionId;
        const st = THREAD_STATUS_LABEL[n.status] || n.status;
        const kids = state.tree.filter(x => x.parent_id === n.id).length;
        return `<div class="tnode st-${esc(n.status)} ${isCur ? 'cur' : ''}" data-sid="${n.id}"
          onclick="openThread('${n.id}')" title="${esc(n.task || '')}">
          <button class="tn-del" onclick="event.stopPropagation();deleteThread('${n.id}', this)" title="彻底删除该分支">×</button>
          <div class="tn-name">${esc(threadName(n))}</div>
          <div class="tn-meta">${st} · ${n.step_count} 步${kids ? ` · ${kids} 子线索` : ''}</div>
          <div class="tn-acts">
            <button onclick="event.stopPropagation();openBranchModal('${n.id}')" title="在此线索下开新分支">＋</button>
            ${n.status !== 'done' ? `<button onclick="event.stopPropagation();setThreadStatus('${n.id}','done')" title="标记已完成">✓</button>` : ''}
            ${n.status !== 'abandoned' ? `<button onclick="event.stopPropagation();setThreadStatus('${n.id}','abandoned')" title="标记已放弃">−</button>` : ''}
            ${n.status !== 'active' ? `<button onclick="event.stopPropagation();setThreadStatus('${n.id}','active')" title="重新打开">↺</button>` : ''}
          </div>
        </div>`;
      }).join('')}
    </div>`).join('');
  strip.insertAdjacentHTML('afterbegin', '<svg class="tree-lines" id="treeLines"></svg>');
  drawTreeLines();
}

/* 父子连线：一条从父节点右沿出发、经竖直主干转到子节点左沿的肘形折线。
   为什么要用 SVG 而不是纯 CSS：节点宽度随标题变化、每列节点数也不同，
   纯 CSS 画不出「父节点到它每一个子节点」的准确走向；这里直接读渲染后的
   实际位置现算，任何节点数、任何标题长度都能画准。
   坐标统一换算到「内容坐标系」（= SVG 的坐标系）：
   getBoundingClientRect 给的是视口坐标，减去容器自身再加上滚动量即可，
   这样无论节点宽窄、容器怎么滚，线都贴在节点边缘。 */
function drawTreeLines() {
  const strip = $('treeStrip');
  const svg = $('treeLines');
  if (!strip || !svg) return;
  const w = strip.scrollWidth, h = strip.scrollHeight;
  // 线索树被隐藏（未选项目）时节点尺寸全是 0，此时按 0 算出来的路径是垃圾数据，直接跳过
  if (!w || !h) { svg.innerHTML = ''; return; }
  svg.setAttribute('width', w);
  svg.setAttribute('height', h);
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);

  // 高亮「当前线索」的祖先链，一眼看出自己在树的哪一支
  const parentOf = {};
  state.tree.forEach(n => { parentOf[n.id] = n.parent_id || ''; });
  const chain = new Set();
  for (let x = state.sessionId; x && !chain.has(x); x = parentOf[x]) chain.add(x);

  const sr = strip.getBoundingClientRect();
  const ox = strip.scrollLeft - sr.left;
  const oy = strip.scrollTop - sr.top;

  const paths = [];
  state.tree.forEach(n => {
    if (!n.parent_id) return;
    const p = strip.querySelector(`.tnode[data-sid="${n.parent_id}"]`);
    const c = strip.querySelector(`.tnode[data-sid="${n.id}"]`);
    if (!p || !c) return;              // 父节点不在本树里（已被提升/跨项目），无连线
    const pr = p.getBoundingClientRect();
    const cr = c.getBoundingClientRect();
    const x1 = pr.right + ox;
    const y1 = pr.top + oy + pr.height / 2;
    const x2 = cr.left + ox;
    const y2 = cr.top + oy + cr.height / 2;
    const mx = x2 - Math.max(6, (x2 - x1) / 2);          // 竖直主干落在两列之间
    let d;
    const r = Math.min(6, Math.abs(y2 - y1) / 2, Math.abs(mx - x1));
    if (Math.abs(y2 - y1) < 1 || r < 1) {
      d = `M ${x1} ${y1} H ${mx} V ${y2} H ${x2}`;
    } else {
      const dir = y2 > y1 ? 1 : -1;
      const my1 = y1 + dir * r, my2 = y2 - dir * r;
      d = `M ${x1} ${y1} H ${mx - r} Q ${mx} ${y1} ${mx} ${my1}`
        + ` V ${my2} Q ${mx} ${y2} ${mx + r} ${y2} H ${x2}`;
    }
    const on = (chain.has(n.id) && chain.has(n.parent_id)) ? ' hl' : '';
    paths.push(`<path class="tl${on}" d="${d}"/>`);
  });
  svg.innerHTML = paths.join('');
}

/* 窗口尺寸变化会改变节点宽度 → 连线跟着重算（防抖，避免拖拽窗口时狂重排） */
let _treeLineTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(_treeLineTimer);
  _treeLineTimer = setTimeout(drawTreeLines, 120);
});

/* 切换到某条线索：恢复持久化会话并回放历史 */
async function openThread(sid) {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  $('sendBtn').disabled = false;
  $('confirmBox').innerHTML = '';
  try {
    await api('/api/sessions', { method: 'POST', body: JSON.stringify({ sid }) });
  } catch (e) { return alert('切换失败：' + e.message); }
  state.sessionId = sid;
  state.threadFresh = false;
  const d = await api(`/api/sessions/${sid}`);
  const m = $('messages');
  m.innerHTML = '';
  state.steps = d.steps || [];
  state.assistant = null;

  const head = document.createElement('div');
  head.className = 'sys-note';
  head.textContent = `线索「${d.title || '未命名对话'}」 · ${state.steps.length} 条历史记录`;
  m.appendChild(head);

  (d.records || []).forEach(rec => {
    const el = document.createElement('div');
    el.className = 'sys-note thread-record';
    el.textContent = '📦 ' + rec;
    m.appendChild(el);
  });

  // 历史对话回放：有聊天记录时按原气泡样式还原（用户消息 / AI 说明 / 结论）
  const chat = d.chat || [];
  if (chat.length) {
    const chatHead = document.createElement('div');
    chatHead.className = 'sys-note';
    chatHead.textContent = '—— 历史对话 ——';
    m.appendChild(chatHead);
    chat.forEach(msg => {
      if (msg.role === 'user') {
        addUserMessage(msg.content);
      } else {
        if (!state.assistant) createAssistant();
        if (msg.kind === 'answer') appendAnswer(md(msg.content));
        else appendReasoning(md(msg.content));
      }
    });
    state.assistant = null;
  } else {
    // 旧会话无聊天记录：回退为步骤清单 + 结论摘要
    state.steps.forEach(s => {
      appendLine(`• ${s.tool_name || s.tool_alias} → ${s.target || '-'} [${s.status}]`, 'muted');
    });
    if (d.summary) appendAnswer(md(d.summary));
  }
  if (d.state === 'running' || d.state === 'awaiting_confirm') {
    connectStream(sid);
    log('该线索正在执行中，已接入实时输出…', 'c-warn');
  }
  // 断线/刷新后重连：need_confirm 事件已经过去，必须按后端回传的「正在等待确认的步骤」
  // 重绘确认框。否则用户会看到「执行中」却没有任何可点的按钮，只能干等到超时。
  if (d.pending_confirm && d.pending_confirm.step) {
    log('该线索有一步高危操作正在等待你的授权确认…', 'c-warn');
    // v022：state 接口现在回传 token/second——刷新后重绘的确认框可正常提交（P1-2）
    showConfirm({ step: d.pending_confirm.step, risk: d.pending_confirm.risk || {},
                  token: d.pending_confirm.token || '', second: d.pending_confirm.second });
  }
  renderTree();
  scrollToBottom();
}

/* 另起一条独立主对话 */
function newThread() {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.sessionId = null;
  state.threadFresh = true;
  state.steps = [];
  state.assistant = null;
  $('sendBtn').disabled = false;
  $('confirmBox').innerHTML = '';
  $('messages').innerHTML = `
    <div class="welcome" id="welcome">
      <div class="welcome-logo">🛡</div>
      <div class="welcome-title">新的对话</div>
      <div class="welcome-sub">描述你的任务开始。发送后它会作为一条主对话出现在上方线索树里。</div>
    </div>`;
  renderTree();
}

async function setThreadStatus(sid, status) {
  try {
    await api(`/api/sessions/${sid}/meta`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    });
    loadTree();
  } catch (e) { alert('状态更新失败：' + e.message); }
}

async function deleteThread(sid, btn) {
  if (!confirm('确定彻底删除该线索分支？\n其下的子分支、执行记录、对话历史将一并删除，不可恢复。')) return;
  if (btn) btn.disabled = true;
  try {
    await api(`/api/sessions/${sid}`, { method: 'DELETE' });
    if (state.sessionId === sid) { newThread(); }
    await loadTree();
  } catch (e) { alert('删除失败：' + e.message); }
  finally { if (btn) btn.disabled = false; }
}

/* 开分支弹窗：候选记录 = 该线索最近的执行步骤 */
async function openBranchModal(sid) {
  state.branchParent = sid || state.sessionId;
  if (!state.branchParent) {
    return log('还没有可分叉的对话：先发送一个任务，或在线索树里选中一条线索', 'c-warn');
  }
  $('bTitle').value = '';
  $('bNote').value = '';
  $('branchState').textContent = '';
  let steps = [];
  try {
    const d = await api(`/api/sessions/${state.branchParent}`);
    steps = d.steps || [];
  } catch (e) { /* 忽略，保留空候选 */ }
  const cands = steps.slice(-8).reverse();
  $('branchCandidates').innerHTML = cands.length
    ? cands.map((c, i) => `
      <label class="bc-cand">
        <input type="checkbox" value="${esc(c.id)}" ${i < 3 ? 'checked' : ''}>
        <span class="bc-cand-t">${esc(c.tool_name || c.tool_alias)} → ${esc(c.target || '-')}</span>
        <span class="bc-cand-o">${esc((c.output || '').replace(/\s+/g, ' ').slice(0, 70))}</span>
      </label>`).join('')
    : '<div class="empty">该线索还没有执行记录，将只带走补充说明</div>';
  $('branchModal').style.display = 'flex';
}

function closeBranchModal() {
  $('branchModal').style.display = 'none';
  state.branchParent = null;
}

async function confirmCreateBranch() {
  const title = $('bTitle').value.trim();
  if (!title) return alert('请填写线索名称');
  const ids = [...$('branchCandidates').querySelectorAll('input:checked')].map(x => x.value);
  try {
    const r = await api(`/api/sessions/${state.branchParent}/branch`, {
      method: 'POST',
      body: JSON.stringify({ title, record_ids: ids, extra_note: $('bNote').value.trim() }),
    });
    closeBranchModal();
    log(`已创建线索「${r.title}」，携带 ${r.records.length} 条记录`, 'c-ok');
    await loadTree();
    openThread(r.session_id);
  } catch (e) {
    $('branchState').textContent = '创建失败：' + e.message;
  }
}

/* AI 建议开线索的卡片（propose_branch 事件触发） */
function showBranchCard(data) {
  clearWelcome();
  const m = $('messages');
  const card = document.createElement('div');
  card.className = 'branch-card';
  card.innerHTML = `
    <div class="bc-title">🌱 建议开辟新线索：《${esc(data.title)}》</div>
    ${data.reason ? `<div class="bc-reason">${md(data.reason)}</div>` : ''}
    <div class="bc-tip">新线索会带上你勾选的记录独立深挖这个方向，当前对话不受影响：</div>
    <div class="bc-cands">
      ${(data.candidates || []).map(c => `
        <label class="bc-cand">
          <input type="checkbox" value="${esc(c.id)}" checked>
          <span class="bc-cand-t">${esc(c.tool_name || c.tool_alias)} → ${esc(c.target || '-')}</span>
          <span class="bc-cand-o">${esc((c.output || '').replace(/\s+/g, ' ').slice(0, 70))}</span>
        </label>`).join('') || '<div class="muted">（暂无可打包的执行记录，仅携带建议说明）</div>'}
    </div>
    <div class="bc-actions">
      <button class="primary sm bc-go">确认开辟并切换</button>
      <button class="sm bc-no">暂不需要</button>
    </div>`;
  m.appendChild(card);
  scrollToBottom();
  card.querySelector('.bc-go').onclick = async () => {
    const ids = [...card.querySelectorAll('input:checked')].map(x => x.value);
    try {
      const r = await api(`/api/sessions/${state.sessionId}/branch`, {
        method: 'POST',
        body: JSON.stringify({ title: data.title, record_ids: ids, extra_note: data.reason || '' }),
      });
      card.remove();
      log(`已创建线索「${r.title}」`, 'c-ok');
      await loadTree();
      openThread(r.session_id);
    } catch (e) {
      log('创建线索失败：' + e.message, 'c-err');
    }
  };
  card.querySelector('.bc-no').onclick = () => card.remove();
}

/* ---------- Token 用量统计 ---------- */
function fmtTok(n) {
  n = n || 0;
  if (n >= 10000) return (n / 10000).toFixed(1) + '万';
  return String(n);
}
function fmtCost(c) {
  return '≈ ¥' + (c || 0).toFixed(c > 0 && c < 1 ? 4 : 2);
}

/* 顶栏徽标：今日 token（任务完成后与打开弹窗时刷新） */
async function refreshUsageBadge() {
  try {
    const d = await api('/api/usage/summary');
    const b = $('usageBadge');
    if (b) b.textContent = d.today.calls ? `今日 ${fmtTok(d.today.tokens)} tok` : '';
  } catch (e) { /* 静默 */ }
}

function openUsage() {
  $('usageModal').style.display = 'flex';
  loadUsage();
  loadUsageList();
  loadPriceEditor();
}
function closeUsage() { $('usageModal').style.display = 'none'; }

async function loadUsage() {
  try {
    const [sum, daily, projects] = await Promise.all([
      api('/api/usage/summary'),
      api('/api/usage/daily?days=30'),
      api('/api/projects'),
    ]);
    // 汇总卡
    $('uTodayTok').textContent = fmtTok(sum.today.tokens) + ' tok';
    $('uTodayCost').textContent = fmtCost(sum.today.cost);
    $('uTodayCalls').textContent = `${sum.today.calls} 次调用 · 输入 ${fmtTok(sum.today.prompt)} / 输出 ${fmtTok(sum.today.completion)}`;
    $('uMonthTok').textContent = fmtTok(sum.month.tokens) + ' tok';
    $('uMonthCost').textContent = fmtCost(sum.month.cost);
    $('uMonthCalls').textContent = `${sum.month.calls} 次调用`;
    $('uTotalTok').textContent = fmtTok(sum.total.tokens) + ' tok';
    $('uTotalCost').textContent = fmtCost(sum.total.cost);
    $('uTotalCalls').textContent = `${sum.total.calls} 次调用`;
    // 占比
    renderUsageBars('uByModel', sum.by_model, sum.total.tokens);
    renderUsageBars('uByProject', sum.by_project, sum.total.tokens,
      Object.fromEntries(projects.items.map(p => [p.id, p.name])));
    // 筛选下拉
    const pSel = $('uFilterProject');
    const curP = pSel.value;
    pSel.innerHTML = '<option value="">全部项目</option>' + projects.items.map(p =>
      `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
    pSel.value = curP;
    const mSel = $('uFilterModel');
    const curM = mSel.value;
    mSel.innerHTML = '<option value="">全部模型</option>' + Object.keys(sum.by_model).map(k =>
      `<option value="${esc(k.split(':')[1] || k)}">${esc(k)}</option>`).join('');
    mSel.value = curM;
    // 趋势图
    renderDailyChart(daily.items);
    refreshUsageBadge();
  } catch (e) {
    log('用量加载失败：' + e.message, 'c-err');
  }
}

/* 横向占比条 */
function renderUsageBars(elId, map, total, nameMap) {
  const el = $(elId);
  const entries = Object.entries(map || {}).sort((a, b) => b[1].tokens - a[1].tokens);
  if (!entries.length) { el.innerHTML = '<div class="empty">暂无数据</div>'; return; }
  const maxTok = entries[0][1].tokens || 1;
  el.innerHTML = entries.map(([k, v]) => {
    const label = nameMap ? (nameMap[k] || (k ? k.slice(0, 8) : '未关联项目')) : k;
    const pct = total ? Math.round(v.tokens / total * 100) : 0;
    return `<div class="ubar" title="${esc(label)}：${v.tokens} tok / ${v.calls} 次 / ${fmtCost(v.cost)}">
      <div class="ubar-head"><span>${esc(label)}</span><span class="muted">${fmtTok(v.tokens)} · ${pct}% · ${fmtCost(v.cost)}</span></div>
      <div class="ubar-track"><div class="ubar-fill" style="width:${Math.max(3, Math.round(v.tokens / maxTok * 100))}%"></div></div>
    </div>`;
  }).join('');
}

/* SVG 按天柱状图（无外部依赖） */
function renderDailyChart(items) {
  const el = $('uDailyChart');
  if (!items || !items.some(d => d.tokens)) {
    el.innerHTML = '<div class="empty">暂无数据：跑一个任务后这里会出现按天趋势</div>';
    return;
  }
  const W = 860, H = 180, padL = 44, padB = 22, padT = 10;
  const maxTok = Math.max(...items.map(d => d.tokens), 1);
  const bw = (W - padL - 8) / items.length;
  const bars = items.map((d, i) => {
    const h = Math.round(d.tokens / maxTok * (H - padT - padB));
    const x = padL + i * bw + 1;
    const y = H - padB - h;
    const tip = `${d.day}｜${fmtTok(d.tokens)} tok · ${d.calls} 次 · ${fmtCost(d.cost)}`;
    return `<rect x="${x}" y="${y}" width="${Math.max(1, bw - 3)}" height="${h}" rx="2"
      class="uchart-bar"><title>${esc(tip)}</title></rect>
      ${i % Math.ceil(items.length / 10) === 0 ? `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle" class="uchart-x">${d.day}</text>` : ''}`;
  }).join('');
  const gridLines = [0.25, 0.5, 0.75, 1].map(f => {
    const y = H - padB - f * (H - padT - padB);
    return `<line x1="${padL}" y1="${y}" x2="${W - 8}" y2="${y}" class="uchart-grid"/>
      <text x="${padL - 5}" y="${y + 4}" text-anchor="end" class="uchart-y">${fmtTok(Math.round(maxTok * f))}</text>`;
  }).join('');
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" style="width:100%;">${gridLines}${bars}</svg>`;
}

async function loadUsageList() {
  const pid = $('uFilterProject').value;
  const model = $('uFilterModel').value;
  const days = $('uFilterDays').value;
  const qs = new URLSearchParams({ project_id: pid, model, days, limit: '300' });
  try {
    const d = await api('/api/usage/list?' + qs.toString());
    const projNames = {};
    try {
      const projects = await api('/api/projects');
      projects.items.forEach(p => projNames[p.id] = p.name);
    } catch (e) { /* 项目名映射失败就显示 id */ }
    const tb = $('uTable').querySelector('tbody');
    if (!d.items.length) {
      tb.innerHTML = '<tr><td colspan="6" class="empty">暂无记录</td></tr>';
      return;
    }
    tb.innerHTML = d.items.map(r => {
      const t = new Date(r.ts * 1000);
      const time = `${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')} ${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
      return `<tr>
        <td>${time}</td>
        <td>${esc(projNames[r.project_id] || (r.project_id ? r.project_id.slice(0, 8) : '未关联'))}</td>
        <td>${esc(r.provider_id)} / ${esc(r.model)}</td>
        <td>${r.prompt_tokens}</td>
        <td>${r.completion_tokens}</td>
        <td>${r.duration_ms ? (r.duration_ms / 1000).toFixed(1) + 's' : '-'}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    log('明细加载失败：' + e.message, 'c-err');
  }
}

/* ---------- 单价编辑 ---------- */
async function loadPriceEditor() {
  try {
    const d = await api('/api/usage/prices');
    renderPriceRows(d.items);
  } catch (e) { /* 静默 */ }
}

function renderPriceRows(prices) {
  const tb = $('uPriceTable').querySelector('tbody');
  const keys = Object.keys(prices || {}).sort();
  tb.innerHTML = keys.map(k => `
    <tr>
      <td><input class="up-key" value="${esc(k)}" style="width:100%;"></td>
      <td><input class="up-in" type="number" step="0.01" min="0" value="${prices[k].input}"></td>
      <td><input class="up-out" type="number" step="0.01" min="0" value="${prices[k].output}"></td>
      <td><button class="sm danger" onclick="this.closest('tr').remove()">删</button></td>
    </tr>`).join('') || '<tr><td colspan="4" class="empty">无单价条目，点「+ 新增单价」</td></tr>';
}

function addPriceRow(model = '', input = 0, output = 0) {
  const tb = $('uPriceTable').querySelector('tbody');
  if (tb.querySelector('.empty')) tb.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td><input class="up-key" value="${esc(model)}" placeholder="模型名，如 qwen3.7-plus" style="width:100%;"></td>
    <td><input class="up-in" type="number" step="0.01" min="0" value="${input}"></td>
    <td><input class="up-out" type="number" step="0.01" min="0" value="${output}"></td>
    <td><button class="sm danger" onclick="this.closest('tr').remove()">删</button></td>`;
  tb.appendChild(tr);
}

async function savePrices() {
  const prices = {};
  $('uPriceTable').querySelectorAll('tbody tr').forEach(tr => {
    const k = tr.querySelector('.up-key').value.trim();
    if (!k) return;
    prices[k] = {
      input: parseFloat(tr.querySelector('.up-in').value) || 0,
      output: parseFloat(tr.querySelector('.up-out').value) || 0,
    };
  });
  try {
    await api('/api/usage/prices', { method: 'POST', body: JSON.stringify({ prices }) });
    $('uPriceState').textContent = '单价已保存，费用估算立即按新价生效。';
    loadUsage();
  } catch (e) {
    $('uPriceState').textContent = '保存失败：' + e.message;
  }
}

async function resetPrices() {
  if (!confirm('恢复默认单价表（当前修改会被覆盖）？')) return;
  try {
    const d = await api('/api/usage/prices/reset', { method: 'POST' });
    renderPriceRows(d.items);
    $('uPriceState').textContent = '已恢复默认单价。';
    loadUsage();
  } catch (e) {
    $('uPriceState').textContent = '恢复失败：' + e.message;
  }
}

/* ---------- 清空 / 导出 ---------- */
function exportUsage() {
  window.open('/api/usage/export.csv', '_blank');
}

async function clearUsageAsk() {
  const choice = prompt(
    '清理用量记录：\n输入 0 = 清空全部\n输入 N（如 30）= 只删除 N 天前的旧记录\n输入其他或取消 = 放弃', '0');
  if (choice === null) return;
  const days = parseInt(choice, 10);
  if (isNaN(days) || days < 0) return;
  if (!confirm(days === 0 ? '确定清空全部用量记录？不可恢复。' : `确定删除 ${days} 天前的用量记录？`)) return;
  try {
    const r = await api('/api/usage/clear', { method: 'POST', body: JSON.stringify({ days }) });
    log(`已清理 ${r.deleted} 条用量记录`, 'c-ok');
    loadUsage();
    loadUsageList();
    refreshUsageBadge();
  } catch (e) {
    alert('清理失败：' + e.message);
  }
}

/* ---------- 右侧面板折叠 ---------- */
function toggleRight() {
  const p = $('rightPanel');
  const closed = p.classList.toggle('closed');
  document.querySelector('.app').classList.toggle('right-closed', closed);
  $('toggleRightBtn').textContent = closed ? '报告 ◂' : '报告 ▸';
}

/* ---------- 漏洞发现 ---------- */
function toggleFindingForm() {
  const el = $('findingForm');
  el.style.display = el.style.display === 'none' ? 'flex' : 'none';
}

async function loadFindings() {
  if (!state.currentProject) return;
  const d = await api(`/api/projects/${state.currentProject}`);
  const el = $('findingList');
  if (!d.findings.length) {
    el.innerHTML = '<div class="empty">暂无记录</div>';
    return;
  }
  el.innerHTML = d.findings.map(f => `
    <div class="finding">
      <div class="ftitle">${esc(f.title)} <span class="badge">${esc(f.severity)}</span>
        <span class="badge" style="${f.status === 'confirmed' ? '' : 'opacity:.6;'}">${esc(f.status || 'draft')}</span></div>
      <div class="fmeta">${esc(f.target || '无目标')}${f.vuln_type ? ' · ' + esc(f.vuln_type) : ''}</div>
      <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;">
        <button class="mini" onclick="reviewFinding('${f.id}')" title="五项复核清单：可重复/权限差异/复现链/无损害/影响可证明">复核</button>
        ${f.status !== 'confirmed' ? `<button class="mini" onclick="confirmFinding('${f.id}')">确认</button>` : ''}
        <button class="sm danger" onclick="delFinding('${f.id}')">删除</button>
      </div>
    </div>`).join('');
}

async function addFinding() {
  if (!state.currentProject) return alert('请先选择项目');
  const title = $('fTitle').value.trim();
  if (!title) return alert('请填写漏洞名称');
  await api(`/api/projects/${state.currentProject}/findings`, {
    method: 'POST',
    body: JSON.stringify({
      title,
      severity: $('fSev').value,
      target: $('fTarget').value.trim(),
      detail: $('fDetail').value.trim(),
      evidence: $('fEvidence').value.trim(),
    }),
  });
  ['fTitle', 'fTarget', 'fDetail', 'fEvidence'].forEach(id => $(id).value = '');
  toggleFindingForm();
  loadFindings();
  loadProjects();
}

async function delFinding(fid) {
  await api(`/api/projects/${state.currentProject}/findings/${fid}`, { method: 'DELETE' });
  loadFindings();
  loadProjects();
}

/* 五项复核清单（v017.4）：逐项 confirm 收集，PUT 落库。
   confirmed 硬闸门：五项不全时服务端拒绝确认（400）。 */
async function reviewFinding(fid) {
  if (!state.currentProject) return;
  const items = [
    ['c1_repeat', '① 至少重复两次且结果一致？'],
    ['c2_permission_delta', '② 权限/身份差异是否明确？'],
    ['c3_minimal_chain', '③ 最小 HTTP 请求/响应复现链是否完整？'],
    ['c4_readonly_or_safe', '④ 只读证明优先，写操作无真实损害？'],
    ['c5_impact_proven', '⑤ 对象/数据/状态影响可证明？'],
  ];
  const checks = {};
  for (const [k, q] of items) {
    checks[k] = confirm(q + '\n\n（取消 = 该项未达成）');
    if (!checks[k]) break;
  }
  if (Object.values(checks).some(v => !v)) {
    log('五项复核未全部达成——该漏洞只能保持候选状态，无法确认进报告', 'c-warn');
  }
  const note = prompt('复核备注（可空）：') || '';
  try {
    await api(`/api/projects/${state.currentProject}/findings/${fid}/checklist`, {
      method: 'PUT', body: JSON.stringify({ ...checks, note }),
    });
    log('复核清单已保存', 'c-ok');
  } catch (e) { log('复核清单保存失败：' + (e.message || e), 'c-err'); }
}

async function confirmFinding(fid) {
  if (!state.currentProject) return;
  if (!confirm('确认该漏洞进入正式报告（confirmed）？\n五项复核清单必须已全部达成，否则将被拒绝。')) return;
  try {
    await api(`/api/projects/${state.currentProject}/findings/${fid}/review`, {
      method: 'POST', body: JSON.stringify({ action: 'confirmed', approved: true }),
    });
    log('漏洞已确认，进入正式报告', 'c-ok');
    loadFindings();
  } catch (e) {
    log('确认被拒绝：' + (e.message || e) + '\n请先完成五项复核清单', 'c-err');
  }
}

/* ---------- 已证事实 ---------- */
function toggleFactForm() {
  const el = $('factForm');
  el.style.display = el.style.display === 'none' ? 'flex' : 'none';
}

async function loadFacts() {
  if (!state.currentProject) return;
  const d = await api(`/api/projects/${state.currentProject}`);
  renderFacts(d.facts || []);
}

function renderFacts(facts) {
  $('factCount').textContent = facts.length;
  const el = $('factList');
  if (!facts.length) {
    el.innerHTML = '<div class="empty">暂无已证事实</div>';
    return;
  }
  el.innerHTML = facts.map(f => `
    <div class="finding">
      <div class="ftitle">${esc(f.content)} <span class="badge ${f.source === 'agent' ? '' : 'off'}">${f.source === 'agent' ? 'Agent' : '人工'}</span></div>
      <div class="fmeta"><button class="sm danger" onclick="delFact('${f.id}')">删除</button></div>
    </div>`).join('');
}

async function addFact() {
  if (!state.currentProject) return alert('请先选择项目');
  const content = $('factContent').value.trim();
  if (!content) return alert('请填写事实内容');
  await api(`/api/projects/${state.currentProject}/facts`, {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
  $('factContent').value = '';
  toggleFactForm();
  loadFacts();
}

async function delFact(fid) {
  await api(`/api/projects/${state.currentProject}/facts/${fid}`, { method: 'DELETE' });
  loadFacts();
}

/* ---------- 报告 ---------- */
async function viewReport() {
  if (!state.currentProject) return alert('请先选择项目');
  const d = await api(`/api/projects/${state.currentProject}/report`);
  window.open('data:text/markdown;charset=utf-8,' + encodeURIComponent(d.markdown), '_blank');
}

async function exportReport() {
  if (!state.currentProject) return alert('请先选择项目');
  const d = await api(`/api/projects/${state.currentProject}/report/export`, { method: 'POST' });
  log(`报告已导出至 ${d.path}`, 'c-ok');
}

/* ---------- 设置 · 通用 LLM 供应商管理 ---------- */
let prov = { items: [], current: 'ollama', auto_route: true, auto_route_id: 'deepseek', presets: [] };
let editingProvider = null;

async function openSettings() {
  $('settingsModal').style.display = 'flex';
  editingProvider = null;
  $('providerForm').style.display = 'none';
  await loadPresets();
  await loadProviders();
}

function closeSettings() {
  $('settingsModal').style.display = 'none';
}

async function loadPresets() {
  if (prov.presets.length) return;
  try {
    const d = await api('/api/llm/presets');
    prov.presets = d.items;
    $('presetSelect').innerHTML = d.items.map(p =>
      `<option value="${esc(p.key)}">${esc(p.name)}${p.note ? ' — ' + esc(p.note) : ''}</option>`
    ).join('');
  } catch (e) { /* 静默 */ }
}

async function loadProviders() {
  try {
    const d = await api('/api/llm/providers');
    prov.items = d.items;
    prov.current = d.current;
    prov.auto_route = d.auto_route;
    prov.auto_route_id = d.auto_route_id;
    $('storeFileTip').textContent = d.store_file || '';
    renderProviders();
  } catch (e) {
    $('providerList').innerHTML = `<div class="empty">读取失败：${esc(e.message)}</div>`;
  }
}

function renderProviders() {
  const box = $('providerList');
  if (!prov.items.length) {
    box.innerHTML = '<div class="empty">还没有供应商，从上方模板添加一个</div>';
  } else {
    box.innerHTML = prov.items.map(p => {
      const tag = p.local
        ? '<span class="badge L0">本地</span>'
        : (p.type === 'anthropic' ? '<span class="badge gui">Anthropic</span>'
                                  : '<span class="badge L1">OpenAI</span>');
      const cur = p.id === prov.current ? '<span class="badge L1">使用中</span>' : '';
      const off = !p.enabled ? '<span class="badge off">已停用</span>' : '';
      const key = p.local ? '' : (p.has_key
        ? `<span class="badge">${esc(p.key_masked)}</span>`
        : '<span class="badge off">未填 Key</span>');
      const isCur = p.id === prov.current;
      return `<div class="prov-item ${isCur ? 'current' : ''}">
        <div class="pinfo">
          <div class="pname">${esc(p.name)}${tag}${cur}${off}</div>
          <div class="pmeta">${esc(p.model || '未填模型')} · ${esc(p.base_url || '未填端点')} ${key}</div>
        </div>
        <div class="pacts">
          <button class="sm" onclick="useProvider('${p.id}')" ${isCur ? 'disabled' : ''}>${isCur ? '使用中' : '启用'}</button>
          <button class="sm" onclick="testProvider('${p.id}')">测试</button>
          <button class="sm" onclick="openProviderForm('${p.id}')">编辑</button>
          ${p.builtin
            ? `<button class="sm" onclick="resetProvider('${p.id}')">恢复默认</button>`
            : `<button class="sm danger" onclick="deleteProvider('${p.id}')">删除</button>`}
        </div>
      </div>`;
    }).join('');
  }

  $('autoRouteChk').checked = !!prov.auto_route;
  $('autoRouteSel').innerHTML = prov.items.filter(p => !p.local).map(p =>
    `<option value="${esc(p.id)}" ${p.id === prov.auto_route_id ? 'selected' : ''}>${esc(p.name)}</option>`
  ).join('') || '<option value="">（无云端供应商）</option>';
}

function openProviderForm(id) {
  editingProvider = id;
  $('providerForm').style.display = 'block';
  $('pfModelPick').style.display = 'none';
  $('pfState').textContent = '';
  const p = id ? prov.items.find(x => x.id === id) : null;
  $('pfName').value = p ? p.name : '';
  $('pfType').value = p ? p.type : 'openai';
  $('pfBase').value = p ? p.base_url : '';
  $('pfKey').value = '';
  $('pfModel').value = p ? p.model : '';
  $('pfThinking').checked = p ? !!p.thinking : false;
  $('pfLocal').checked = p ? !!p.local : false;
  $('pfDisabled').checked = p ? !p.enabled : false;
  $('pfTimeout').value = p && p.timeout ? p.timeout : '';
  onProviderTypeChange();
  $('pfName').focus();
}

function closeProviderForm() {
  editingProvider = null;
  $('providerForm').style.display = 'none';
}

function onProviderTypeChange() {
  const isAnth = $('pfType').value === 'anthropic';
  $('pfBase').placeholder = isAnth
    ? 'Base URL，如 https://api.anthropic.com'
    : 'Base URL，如 https://api.deepseek.com/v1';
}

async function saveProviderForm() {
  const body = {
    id: editingProvider || '',
    name: $('pfName').value.trim(),
    type: $('pfType').value,
    base_url: $('pfBase').value.trim(),
    api_key: $('pfKey').value.trim(),
    model: $('pfModel').value.trim(),
    thinking: $('pfThinking').checked,
    local: $('pfLocal').checked,
    enabled: !$('pfDisabled').checked,
  };
  const t = parseInt($('pfTimeout').value, 10);
  if (t > 0) body.timeout = t;

  if (!body.name) return alert('请填写供应商名称');
  if (!body.base_url) return alert('请填写 Base URL');
  if (!body.model) return alert('请填写模型名');
  if (!body.local && !body.api_key && !editingProvider) return alert('云端供应商请填写 API Key');

  try {
    const r = await api('/api/llm/providers', { method: 'POST', body: JSON.stringify(body) });
    $('pfKey').value = '';
    editingProvider = r.provider.id;
    $('pfState').textContent = '已保存，可点列表里的「测试」验证连通性与工具调用能力。';
    await loadProviders();
    loadModels();
    log(`供应商「${r.provider.name}」已保存`, 'c-ok');
  } catch (e) {
    $('pfState').textContent = `保存失败：${e.message}`;
  }
}

async function addFromPreset() {
  const preset = prov.presets.find(p => p.key === $('presetSelect').value);
  if (!preset) return;
  const exist = prov.items.find(p => p.id === preset.key);
  if (exist) { openProviderForm(exist.id); return; }
  try {
    const r = await api('/api/llm/providers', {
      method: 'POST',
      body: JSON.stringify({
        name: preset.name, type: preset.type, base_url: preset.base_url,
        model: preset.model, local: !!preset.local, thinking: !!preset.thinking,
        api_key: '', enabled: true,
      }),
    });
    await loadProviders();
    loadModels();
    openProviderForm(r.provider.id);
    $('pfState').textContent = '模板已创建，填写 API Key 后「保存」→「测试」。';
  } catch (e) {
    alert('添加失败：' + e.message);
  }
}

async function useProvider(id) {
  try {
    await api(`/api/llm/providers/${id}/use`, { method: 'POST', body: JSON.stringify({ id }) });
    await loadProviders();
    loadModels();
    log(`决策供应商已切换：${id}`, 'c-ok');
  } catch (e) {
    alert('切换失败：' + e.message);
  }
}

async function saveAutoRoute() {
  const id = prov.current || 'ollama';
  try {
    await api(`/api/llm/providers/${id}/use`, {
      method: 'POST',
      body: JSON.stringify({
        id,
        auto_route: $('autoRouteChk').checked,
        auto_route_id: $('autoRouteSel').value,
      }),
    });
    prov.auto_route = $('autoRouteChk').checked;
    prov.auto_route_id = $('autoRouteSel').value;
    log(`自动路由${prov.auto_route ? '已开启 → ' + prov.auto_route_id : '已关闭'}`, 'c-ok');
  } catch (e) {
    alert('保存失败：' + e.message);
  }
}

async function testProvider(id) {
  const p = prov.items.find(x => x.id === id);
  log(`正在探测「${p ? p.name : id}」…`, 'c-mute');
  try {
    const r = await api(`/api/llm/providers/${id}/test`, { method: 'POST' });
    if (r.error) {
      log(`测试失败：${r.error}`, 'c-err');
      alert('连接失败：\n' + r.error);
      return;
    }
    log(`测试「${p ? p.name : id}」：对话 ${r.chat ? '✓' : '✗'} · 工具调用 ${r.tools ? '✓' : '✗'} · 可用模型 ${r.models.length} 个`, r.chat ? 'c-ok' : 'c-err');
    if (r.hint) log(`提示：${r.hint}`, 'c-warn');
    if (r.models.length) {
      const pick = $('pfModelPick');
      pick.innerHTML = `<option value="">— 选择模型（${r.models.length}）—</option>`
        + r.models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
      pick.style.display = 'block';
    }
  } catch (e) {
    log(`测试请求失败：${e.message}`, 'c-err');
  }
}

async function fetchProviderModels() {
  if (!editingProvider) return alert('请先「保存」该供应商，再拉取模型列表');
  try {
    const r = await api(`/api/llm/providers/${editingProvider}/models`);
    if (!r.ok || !r.models.length) {
      $('pfState').textContent = '未能拉取：' + (r.error || '该端点未开放 /models 接口，请手动填写模型名');
      return;
    }
    const pick = $('pfModelPick');
    pick.innerHTML = `<option value="">— 选择模型（${r.models.length}）—</option>`
      + r.models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
    pick.style.display = 'block';
    $('pfState').textContent = `已拉取 ${r.models.length} 个模型，选中后自动填入模型名。`;
  } catch (e) {
    $('pfState').textContent = '拉取失败：' + e.message;
  }
}

async function deleteProvider(id) {
  const p = prov.items.find(x => x.id === id);
  if (!confirm(`删除供应商「${p ? p.name : id}」？`)) return;
  try {
    await api(`/api/llm/providers/${id}`, { method: 'DELETE' });
    if (editingProvider === id) closeProviderForm();
    await loadProviders();
    loadModels();
    log(`已删除供应商：${id}`, 'c-ok');
  } catch (e) {
    alert('删除失败：' + e.message);
  }
}

async function resetProvider(id) {
  if (!confirm('恢复默认会清空已填的 Key 与端点，确认？')) return;
  await api(`/api/llm/providers/${id}/reset`, { method: 'POST' });
  await loadProviders();
  loadModels();
  log(`已恢复默认：${id}`, 'c-ok');
}

/* ---------- 标签切换 ---------- */
document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('tab-proj').style.display = t.dataset.tab === 'proj' ? 'flex' : 'none';
    $('tab-tools').style.display = t.dataset.tab === 'tools' ? 'flex' : 'none';
    // v102：白盒面板（非白盒模式下这个标签本身是隐藏的，这里再兜一层）
    const codePane = $('tab-code');
    if (codePane) {
      const show = t.dataset.tab === 'code' && state.mode === 'whitebox';
      codePane.style.display = show ? 'flex' : 'none';
      if (show) loadCodebases();
    }
  };
});

$('settingsModal').addEventListener('click', e => {
  if (e.target.id === 'settingsModal') closeSettings();
});

$('usageModal').addEventListener('click', e => {
  if (e.target.id === 'usageModal') closeUsage();
});

/* ---------- 线索图（攻击图 / 因果图） ----------
   渲染本身在 web/graph.js（零依赖 SVG 分层 DAG）；这里只做取数与事件接线。
   两个视图同源于 app/graph.py：
     · 攻击图 = 项目为根、线索为节点的对话树画布（与上方小地图同数据）
     · 因果图 = 证据 → 关键事实 → 漏洞 的推理链（必要/或然置信度传播）
   注意：新增的类名用 .gtab 而不是 .tab，避免被上面「标签切换」那段全局 .tab 绑定吃掉。 */
const graphState = { view: 'attack', mounted: false };
const GRAPH_EMPTY = {
  attack: '还没有线索节点：先在左侧选择项目并发送一个任务，线索会出现在这里',
  causal: '暂无因果节点：Agent 记录已证事实 / 发现漏洞后会自动生成，也可点「从数据派生」重建',
};

async function openGraph(view) {
  if (!state.currentProject) return log('先选择或创建一个项目', 'c-warn');
  $('graphModal').style.display = 'flex';
  const cvs = $('graphCanvas');
  cvs.innerHTML = '';
  graphState.mounted = false;
  GraphView.mount(cvs, {
    legendEl: $('graphLegend'),
    // 攻击图上点「线索」节点 → 关掉图画布并切到那条对话（最直觉的期望）
    onOpenThread: (sid) => { closeGraph(); openThread(sid); },
    onBranch: (sid) => { closeGraph(); openBranchModal(sid); },
    onSetStatus: (sid, action) => setGraphThreadStatus(sid, action),
    // 因果图上「以此线索开分支」：仍挂到当前线索下（因果节点不是会话）
    onBranchFromNode: () => { closeGraph(); openBranchModal(state.sessionId); },
  });
  graphState.mounted = true;
  await switchGraph(view || graphState.view || 'attack');
}

function closeGraph() { $('graphModal').style.display = 'none'; }

async function switchGraph(view) {
  graphState.view = view;
  $('gTabAttack').classList.toggle('active', view === 'attack');
  $('gTabCausal').classList.toggle('active', view === 'causal');
  // 因果图才需要「从数据派生」；攻击图直接读会话树，没有派生一说
  $('gDeriveBtn').style.display = view === 'causal' ? '' : 'none';
  if (!graphState.mounted) return;
  try {
    const d = await api(`/api/projects/${state.currentProject}/graph/${view}`);
    // currentId 用于高亮「当前线索 → 根」的活跃路径
    GraphView.render(d, {
      view,
      currentId: state.sessionId || '',
      emptyText: GRAPH_EMPTY[view] || '暂无节点',
    });
  } catch (e) {
    log('线索图加载失败：' + e.message, 'c-err');
  }
}

function graphFit() { GraphView.fit(); }

async function deriveCausal() {
  if (!state.currentProject) return;
  if (!confirm('将按现有「工具执行 / 已证事实 / 漏洞发现」重建整张因果图（原有因果节点与边会被覆盖）。继续？')) return;
  try {
    await api(`/api/projects/${state.currentProject}/graph/causal/derive`, { method: 'POST' });
    log('已从现有数据派生因果图', 'c-ok');
    await switchGraph('causal');
  } catch (e) { alert('派生失败：' + e.message); }
}

/* 图上的状态调整复用线索树同一套接口（PUT /api/sessions/{sid}/meta），动作名映射到后端状态值 */
async function setGraphThreadStatus(sid, action) {
  const map = { done: 'done', abandon: 'abandoned', active: 'active' };
  await setThreadStatus(sid, map[action] || action);
  if (graphState.mounted) await switchGraph(graphState.view);
}

$('graphModal').addEventListener('click', e => { if (e.target.id === 'graphModal') closeGraph(); });

/* ---------- 测试身份（v017.2）----------
   凭据 DPAPI 加密落盘；前端只提交明文一次（本地回环），之后只显示
   标签/角色/状态——服务端任何接口都不回显凭据。 */
function toggleIdentityForm() {
  const f = $('identityForm');
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function loadIdentities() {
  if (!state.currentProject) return;
  try {
    const d = await api(`/api/projects/${state.currentProject}/identities`);
    const items = d.items || [];
    biz.identities = items;   // 工作台下拉复用
    $('identityCount').textContent = items.length;
    const el = $('identityList');
    if (!items.length) { el.innerHTML = '<div class="empty">暂无测试身份</div>'; return; }
    el.innerHTML = items.map(i => `
      <div class="list-item">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;">
          <b>${esc(i.label)}</b>
          <span style="opacity:.65;font-size:11px;">${esc(i.role)}${i.tenant ? ' · ' + esc(i.tenant) : ''}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:2px;">
          <span class="badge" style="${i.status === 'active' ? '' : 'opacity:.55;'}">${esc(i.status)}</span>
          <span>
            <button class="mini" onclick="checkIdentity('${i.id}')" title="发一次只读请求验证凭据是否有效">检查</button>
            <button class="mini" onclick="delIdentity('${i.id}')">删除</button>
          </span>
        </div>
      </div>`).join('');
  } catch (e) { /* 项目未选等场景静默 */ }
}

async function addIdentity() {
  if (!state.currentProject) return log('先选择项目', 'c-warn');
  const parseJson = (id, name) => {
    const raw = ($(id).value || '').trim();
    if (!raw) return {};
    try { return JSON.parse(raw); }
    catch (e) { throw new Error(`${name} 不是合法 JSON`); }
  };
  let headers, cookies;
  try {
    headers = parseJson('identityHeaders', '请求头');
    cookies = parseJson('identityCookies', 'Cookie');
  } catch (e) { return log(e.message, 'c-err'); }
  try {
    await api(`/api/projects/${state.currentProject}/identities`, {
      method: 'POST',
      body: JSON.stringify({
        label: $('identityLabel').value.trim(),
        role: $('identityRole').value,
        tenant: $('identityTenant').value.trim(),
        headers, cookies,
        check_url: $('identityCheckUrl').value.trim(),
      }),
    });
    log('身份已登记（凭据已加密保存）', 'c-ok');
    $('identityLabel').value = ''; $('identityCheckUrl').value = '';
    $('identityHeaders').value = ''; $('identityCookies').value = '';
    toggleIdentityForm();
    loadIdentities();
  } catch (e) { log('登记失败：' + (e.message || e), 'c-err'); }
}

async function checkIdentity(iid) {
  if (!state.currentProject) return;
  log('正在检查身份有效性（只读请求）…', 'c-dim');
  try {
    const r = await api(`/api/projects/${state.currentProject}/identities/${iid}/check`, { method: 'POST' });
    log(`身份检查：${r.ok ? '有效' : '凭据已失效'}（HTTP ${r.status_code}，${r.latency}s）`, r.ok ? 'c-ok' : 'c-warn');
    loadIdentities();
  } catch (e) { log('检查失败：' + (e.message || e), 'c-err'); loadIdentities(); }
}

async function delIdentity(iid) {
  if (!state.currentProject) return;
  if (!confirm('删除该身份及其加密凭据？')) return;
  try {
    await api(`/api/projects/${state.currentProject}/identities/${iid}`, { method: 'DELETE' });
    loadIdentities();
  } catch (e) { log('删除失败：' + (e.message || e), 'c-err'); }
}

/* ---------- 请求库与身份差分（v017.1/.3）---------- */
async function loadRequests() {
  if (!state.currentProject) return;
  try {
    const d = await api(`/api/projects/${state.currentProject}/requests?scope_status=allowed&limit=50`);
    const items = d.items || [];
    $('reqLibCount').textContent = items.length;
    const el = $('reqLibList');
    if (!items.length) {
      el.innerHTML = '<div class="empty">暂无导入请求（Burp 右键 Save items 导出 XML，或浏览器导出 HAR）</div>';
      return;
    }
    el.innerHTML = items.map(r => `
      <div class="list-item">
        <div style="display:flex;justify-content:space-between;gap:6px;align-items:center;">
          <span style="font-weight:600;">${esc(r.method)}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.8;" title="${esc(r.url)}">${esc(r.url)}</span>
          <button class="mini" onclick="delRequest('${r.id}')">删</button>
        </div>
        ${r.object_candidates && r.object_candidates.length
          ? `<div style="font-size:11px;opacity:.7;margin-top:2px;">对象候选: ${r.object_candidates.map(c => esc(c.field) + '@' + esc(c.location)).join(', ')}</div>`
          : ''}
      </div>`).join('');
  } catch (e) { /* 静默 */ }
}

async function importRequests(input, cb) {
  const file = input.files && input.files[0];
  if (!file || !state.currentProject) return;
  const after = cb || loadRequests;
  const reader = new FileReader();
  reader.onload = async () => {
    const b64 = reader.result.split(',')[1];
    try {
      const pv = await api(`/api/projects/${state.currentProject}/imports/preview`, {
        method: 'POST', body: JSON.stringify({ filename: file.name, content_base64: b64 }),
      });
      const s = pv.stat;
      if (!confirm(`解析 ${s.total} 条：授权内 ${s.allowed}，越界 ${s.rejected}（不入库），重复 ${s.duplicates}。\n确认导入授权内的请求？`)) return;
      const cm = await api(`/api/projects/${state.currentProject}/imports/commit`, {
        method: 'POST', body: JSON.stringify({ filename: file.name, content_base64: b64 }),
      });
      log(`已导入 ${cm.inserted} 条请求到请求库`, 'c-ok');
      loadRequests();
      if (typeof after === 'function') after();
    } catch (e) { log('导入失败：' + (e.message || e), 'c-err'); }
    input.value = '';
  };
  reader.readAsDataURL(file);
}

async function delRequest(rid) {
  if (!state.currentProject) return;
  try {
    await api(`/api/projects/${state.currentProject}/requests/${rid}`, { method: 'DELETE' });
    loadRequests();
  } catch (e) { log('删除失败：' + (e.message || e), 'c-err'); }
}

/* 差分：prompt 依次取目标字段与值（最小交互；工作台面板在后续版本完善） */
async function runDiff(rid) {
  if (!state.currentProject) return;
  const ids = (await api(`/api/projects/${state.currentProject}/identities`)).items || [];
  if (!ids.length) return log('请先在「测试身份」登记基准身份（如 account_a）', 'c-warn');
  const idOpts = ids.map(i => `${i.id}=${i.label}(${i.role})`).join('\n');
  const baseline = prompt('选择基准身份（复制其一的 ID）:\n' + idOpts);
  if (!baseline) return;
  const field = prompt('对象字段名（如 userId / orderId）:');
  if (!field) return;
  const location = prompt('位置（query / path / body）:', 'query');
  if (!location) return;
  const value = prompt('目标对象值（从响应或页面中取得的他人对象 ID）:');
  if (!value) return;
  log('差分执行中（只读请求，可能需要数十秒）…', 'c-dim');
  try {
    const r = await api(`/api/projects/${state.currentProject}/diff-run`, {
      method: 'POST',
      body: JSON.stringify({ request_id: rid, baseline_identity_id: baseline.trim(),
                             target_field: field.trim(), target_location: location.trim(),
                             target_value: value.trim(), with_anonymous: true, repeat: 2 }),
    });
    const v = r.verdict || {};
    if (v.verdict === 'suspect_idor') {
      log(`⚠ 疑似越权：${v.reason}（已标记候选建议，请人工核对后登记漏洞）`, 'c-warn');
      if (r.finding_draft && confirm('已生成候选漏洞预填材料。\n\n' + r.finding_draft.title +
          '\n\n确认登记为候选漏洞（draft，需人工复核确认）？')) {
        const d = r.finding_draft;
        try {
          await api(`/api/projects/${state.currentProject}/findings`, {
            method: 'POST',
            body: JSON.stringify({ title: d.title, severity: d.severity, target: d.target,
                                   detail: d.detail, evidence: d.evidence,
                                   reproduction: d.reproduction, vuln_type: d.vuln_type,
                                   status: 'draft' }),
          });
          log('候选漏洞已登记（draft）——请在漏洞面板补全证据并完成五项复核', 'c-ok');
          loadFindings();
        } catch (e) { log('登记失败：' + (e.message || e), 'c-err'); }
      }
    } else if (v.verdict === 'access_denied') {
      log(`差分结论：${v.reason}`, 'c-ok');
    } else if (v.verdict === 'no_diff') {
      log(`差分结论：${v.reason}`, 'c-dim');
    } else {
      log(`差分结论：${v.reason || v.verdict}`, 'c-warn');
    }
    if (r.anonymous_note) log(`另：${r.anonymous_note}`, 'c-warn');
    const detail = (r.steps || []).map(s => `${s.tag}: ${s.status || s.error || ''}`).join(' | ');
    if (detail) log(`执行序列  ${detail}`, 'c-dim');
  } catch (e) { log('差分失败：' + (e.message || e), 'c-err'); }
}

/* ---------- 业务测试工作台（v017）---------- */
const biz = { selected: [], identities: [] };

async function openBiz() {
  if (!state.currentProject) return log('先选择项目', 'c-warn');
  $('bizModal').style.display = 'flex';
  biz.selected = [];
  await loadIdentities();
  await loadBizRequests();
}

function closeBiz() { $('bizModal').style.display = 'none'; }

async function loadBizRequests() {
  const el = $('bizReqList');
  el.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const d = await api(`/api/projects/${state.currentProject}/requests?scope_status=allowed&limit=100`);
    const items = d.items || [];
    if (!items.length) { el.innerHTML = '<div class="empty">请求库为空——先导入 Burp XML / HAR</div>'; return; }
    el.innerHTML = items.map(r => `
      <div class="list-item" style="margin-bottom:4px;">
        <label style="display:flex; gap:6px; align-items:start; cursor:pointer;">
          <input type="checkbox" class="biz-req-cb" data-rid="${r.id}" onchange="bizToggle('${r.id}', this.checked)">
          <span style="min-width:0;">
            <b>${esc(r.method)}</b>
            <span style="opacity:.8; font-size:11px; word-break:break-all;">${esc(r.url)}</span>
            ${r.object_candidates && r.object_candidates.length
              ? `<div style="font-size:11px; opacity:.65;">候选: ${r.object_candidates.map(c => esc(c.field) + '@' + esc(c.location)).join(', ')}</div>` : ''}
          </span>
        </label>
      </div>`).join('');
  } catch (e) { el.innerHTML = '<div class="empty">加载失败</div>'; }
  // 身份下拉
  const sel = $('bizIdentity');
  sel.innerHTML = '<option value="">— 选择基准身份 —</option>' +
    (biz.identities || []).map(i => `<option value="${esc(i.id)}">${esc(i.label)}（${esc(i.role)}）</option>`).join('');
}

function bizToggle(rid, checked) {
  if (checked) { if (!biz.selected.includes(rid)) biz.selected.push(rid); }
  else biz.selected = biz.selected.filter(x => x !== rid);
}

function renderBizResult(html) { $('bizResult').innerHTML = html; }

async function runDiffFromWorkbench() {
  if (!state.currentProject) return;
  const rid = biz.selected[0];
  if (!rid) return log('请先在左侧勾选一条请求作为差分对象', 'c-warn');
  const identity = $('bizIdentity').value;
  const field = $('bizField').value.trim();
  const value = $('bizValue').value.trim();
  if (!identity || !field || !value) return log('请完整填写基准身份、对象字段与目标值', 'c-warn');
  renderBizResult('<div class="empty">差分执行中…（只读请求，含重复验证）</div>');
  try {
    const r = await api(`/api/projects/${state.currentProject}/diff-run`, {
      method: 'POST',
      body: JSON.stringify({ request_id: rid, baseline_identity_id: identity,
                             target_field: field, target_location: $('bizLocation').value,
                             target_value: value, with_anonymous: $('bizAnon').checked,
                             repeat: 2 }),
    });
    renderDiffResult(r);
  } catch (e) { renderBizResult(`<div class="empty">差分失败：${esc(e.message || e)}</div>`); }
}

function renderDiffResult(r) {
  const v = r.verdict || {};
  const colors = { suspect_idor: '#d97706', suspect_unauthorized: '#d97706',
                   access_denied: '#16a34a', no_diff: '#6b7280',
                   flow_protected: '#16a34a', suspect_flow_bypass: '#d97706',
                   flow_invalid: '#6b7280', unstable: '#6b7280' };
  let html = `<div style="font-weight:700; color:${colors[v.verdict] || 'inherit'}; font-size:14px;">
    ${esc(v.verdict || '')}</div>
    <div style="margin:4px 0;">${esc(v.reason || '')}</div>`;
  if (r.anonymous_note) html += `<div style="color:#d97706; margin:4px 0;">⚠ ${esc(r.anonymous_note)}</div>`;
  html += `<div style="margin:6px 0;"><b>执行序列</b><br>` +
    (r.steps || []).map(s => `${esc(s.tag)}: ${esc(String(s.status || s.error || ''))} <span style="opacity:.7">${esc(s.url)}</span>`).join('<br>') + `</div>`;
  if (r.finding_draft) {
    html += `<button class="primary" onclick="registerDraftFinding()">登记为候选漏洞（draft）</button>
      <div style="font-size:11px; opacity:.7; margin-top:4px;">登记后仍需人工核对并完成五项复核清单才能确认。</div>`;
  }
  renderBizResult(html);
  window._lastDraft = r.finding_draft || null;
}

async function registerDraftFinding() {
  const d = window._lastDraft;
  if (!d) return;
  try {
    await api(`/api/projects/${state.currentProject}/findings`, {
      method: 'POST',
      body: JSON.stringify({ title: d.title, severity: d.severity, target: d.target,
                             detail: d.detail, evidence: d.evidence,
                             reproduction: d.reproduction, vuln_type: d.vuln_type,
                             status: 'draft' }),
    });
    log('候选漏洞已登记（draft）——请完成五项复核后确认', 'c-ok');
    loadFindings();
    renderBizResult('<div class="empty">已登记为候选漏洞（draft）。请在右侧漏洞面板完成五项复核清单后再确认。</div>');
  } catch (e) { log('登记失败：' + (e.message || e), 'c-err'); }
}

async function runFlowFromWorkbench() {
  if (!state.currentProject) return;
  if (biz.selected.length < 2) return log('流程检查需要勾选至少 2 条请求（按顺序，最后一条为目标步骤）', 'c-warn');
  const identity = $('bizIdentity').value;
  renderBizResult('<div class="empty">流程检查执行中…</div>');
  try {
    const r = await api(`/api/projects/${state.currentProject}/flow-run`, {
      method: 'POST',
      body: JSON.stringify({ request_ids: biz.selected.slice(), identity_id: identity }),
    });
    renderDiffResult(r);
  } catch (e) { renderBizResult(`<div class="empty">流程检查失败：${esc(e.message || e)}</div>`); }
}

$('bizModal').addEventListener('click', e => { if (e.target.id === 'bizModal') closeBiz(); });

/* ---------- 流量安全面板（v023.5）---------- */
const STATE_COLOR = {
  NORMAL: '#16a34a', CAUTION: '#d97706', COOLDOWN: '#d97706',
  BLOCKED: '#dc2626', PAUSED: '#dc2626', MANUAL_PROBE: '#2563eb',
  RECOVERED: '#2563eb',
};

async function openTraffic() {
  if (!state.currentProject) return log('先选择项目', 'c-warn');
  $('trafficModal').style.display = 'flex';
  loadTraffic();
}

function closeTraffic() { $('trafficModal').style.display = 'none'; }

async function loadTraffic() {
  if (!state.currentProject) return;
  const el = $('trafficList');
  el.innerHTML = '<div class="empty">加载中…</div>';
  try {
    const [st, rep, ev] = await Promise.all([
      api(`/api/projects/${state.currentProject}/traffic/status`),
      api(`/api/projects/${state.currentProject}/traffic/report`),
      api(`/api/projects/${state.currentProject}/traffic/events?limit=20`),
    ]);
    // 顶部摘要
    const bar = $('trafficStateBar');
    bar.innerHTML = `
      <span class="badge">测试时长 ${esc(rep.span_text || '-')}</span>
      <span class="badge">已发请求 ${rep.total_sent ?? 0}</span>
      <span class="badge">被拒 ${rep.total_rejected ?? 0}</span>
      <span class="badge">防护事件 ${rep.state_changes ?? 0}</span>
      <span class="badge">自动暂停 ${rep.auto_pauses ?? 0}</span>
      ${rep.avg_interval != null ? `<span class="badge">平均间隔 ${rep.avg_interval}s</span>` : ''}
      <span class="badge">测试模式 ${st.test_mode ? '开' : '关'}</span>`;
    // 目标列表
    const items = st.items || [];
    if (!items.length) {
      el.innerHTML = '<div class="empty">暂无目标流量记录（发送过请求后这里会出现）</div>';
    } else {
      el.innerHTML = items.map(t => `
        <div class="list-item" style="margin-bottom:4px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;">
            <b>${esc(t.root_domain)}</b>
            <span class="badge" style="color:${STATE_COLOR[t.state] || 'inherit'};">
              ${esc(t.state)}</span>
          </div>
          <div style="font-size:11px; opacity:.8; margin-top:2px;">
            IP ${esc(t.resolved_ip || '-')} · 预算 ${t.used}/${t.max_requests}（剩 ${t.remaining}）
            · 近 10 分钟 ${t.requests_last_600s} · 并发 ${t.inflight} · 排队 ${t.queued}
            ${t.last_error_label ? ' · 最后错误：' + esc(t.last_error_label) : ''}
          </div>
          ${t.reason ? `<div style="font-size:11px; color:#d97706; margin-top:2px;">${esc(t.reason)}</div>` : ''}
          <div style="margin-top:4px; display:flex; gap:6px; flex-wrap:wrap;">
            <button class="mini" onclick="trafficPause('${esc(t.root_domain)}')">暂停</button>
            <button class="mini" onclick="trafficProbe('${esc(t.root_domain)}')">单次恢复探测</button>
            <button class="mini" onclick="trafficConfirm('${esc(t.root_domain)}')">确认恢复</button>
            <button class="mini" onclick="trafficClearQueue('${esc(t.root_domain)}')">清空排队</button>
            <button class="mini" onclick="trafficClear('${esc(t.root_domain)}')">清除状态</button>
          </div>
        </div>`).join('');
    }
    // 事件
    $('trafficEvents').innerHTML = (ev.items || []).map(e => {
      const ts = new Date((e.created_at || 0) * 1000).toLocaleTimeString();
      return `<div>${ts} · ${esc(e.event_type)} · ${esc(e.root_domain || '')} `
        + `${e.status_code ? 'HTTP ' + e.status_code : ''} `
        + `${esc(e.error_type || '')} ${esc((e.redaction_summary || '').slice(0, 60))}</div>`;
    }).join('') || '<div class="empty">暂无事件</div>';
  } catch (e) { el.innerHTML = `<div class="empty">加载失败：${esc(e.message || e)}</div>`; }
}

async function trafficPause(root) {
  await api(`/api/projects/${state.currentProject}/traffic/pause`, {
    method: 'POST', body: JSON.stringify({ root_domain: root }),
  });
  log(`已暂停目标 ${root}`, 'c-warn'); loadTraffic();
}

async function trafficPauseAll() {
  if (!confirm('暂停本项目所有目标？（所有自动请求将停止，需人工恢复）')) return;
  const r = await api(`/api/projects/${state.currentProject}/traffic/pause-all`, { method: 'POST' });
  log(`已暂停 ${r.count} 个目标`, 'c-warn'); loadTraffic();
}

async function trafficProbe(root) {
  const url = prompt(`对 ${root} 发起【单次】低风险只读探测（URL 须在授权范围内）：`);
  if (!url) return;
  log('探测中…', 'c-dim');
  try {
    const r = await api(`/api/projects/${state.currentProject}/traffic/resume-probe`, {
      method: 'POST', body: JSON.stringify({ root_domain: root, probe_url: url }),
    });
    if (r.ok) log(`探测成功（HTTP ${r.status_code}）——目标可能已恢复，请点「确认恢复」后才会恢复自动请求`, 'c-ok');
    else log(`探测失败：${r.error || ('HTTP ' + (r.status_code || '?'))}——保持停止，不要连续探测`, 'c-warn');
    loadTraffic();
  } catch (e) { log('探测失败：' + (e.message || e), 'c-err'); }
}

async function trafficConfirm(root) {
  if (!confirm(`确认恢复 ${root} 的自动请求？（仅在你的探测成功后执行）`)) return;
  await api(`/api/projects/${state.currentProject}/traffic/confirm-resume`, {
    method: 'POST', body: JSON.stringify({ root_domain: root }),
  });
  log(`已恢复 ${root}`, 'c-ok'); loadTraffic();
}

async function trafficClearQueue(root) {
  const r = await api(`/api/projects/${state.currentProject}/traffic/clear-queue`, {
    method: 'POST', body: JSON.stringify({ root_domain: root }),
  });
  log(`已清空 ${root} 排队请求（当时排队 ${r.queued_at_clear} 个；已发出的无法撤回）`, 'c-warn');
  loadTraffic();
}

async function trafficClear(root) {
  if (!confirm(`强制清除 ${root} 的防护状态？\n仅在确认目标确实正常（例如刚才是误判）时使用。`)) return;
  await api(`/api/projects/${state.currentProject}/traffic/clear-state`, {
    method: 'POST', body: JSON.stringify({ root_domain: root }),
  });
  log(`已清除 ${root} 状态`, 'c-warn'); loadTraffic();
}

async function exportTrafficReport() {
  if (!state.currentProject) return;
  const r = await api(`/api/projects/${state.currentProject}/traffic/report`);
  const L = [];
  L.push(`# 流量审计报告\n`);
  L.push(`- 项目：${state.currentProject}`);
  L.push(`- 测试时长：${r.span_text}`);
  L.push(`- 实际发出请求：${r.total_sent}（被调度拒绝 ${r.total_rejected}）`);
  L.push(`- 平均间隔：${r.avg_interval ?? '-'}s（最短 ${r.min_interval ?? '-'}s）`);
  L.push(`- 防护事件：状态变更 ${r.state_changes}，自动暂停 ${r.auto_pauses}，人工探测 ${r.manual_probes}`);
  L.push(`\n## 按通道\n` + (r.by_tool || []).map(t => `- ${t.tool}: ${t.sent}`).join('\n'));
  L.push(`\n## 按目标\n` + (r.by_root || []).map(t => `- ${t.root_domain}: ${t.sent}`).join('\n'));
  L.push(`\n## 状态码分布\n` + (r.by_status || []).map(t => `- ${t.status_code}: ${t.n}`).join('\n'));
  if (r.errors && r.errors.length) {
    L.push(`\n## 网络层/请求错误\n` + r.errors.map(t =>
      `- ${t.error_type || '(未标注)'} ${t.os_error_code ? '(errno ' + t.os_error_code + ')' : ''}: ${t.n}`).join('\n'));
  }
  if (r.waf_events && r.waf_events.length) {
    L.push(`\n## 防护/暂停事件\n` + r.waf_events.map(e =>
      `- ${new Date(e.at * 1000).toLocaleString()} ${e.reason}`).join('\n'));
  }
  if (r.states && r.states.length) {
    L.push(`\n## 目标最终状态\n` + r.states.map(s =>
      `- ${s.root_domain} [${s.state}] ${(s.reason || '').slice(0, 60)} (IP ${s.resolved_ip || '-'})`).join('\n'));
  }
  const blob = new Blob([L.join('\n')], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `traffic_audit_${state.currentProject}_${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(a.href);
  log('流量审计报告已导出', 'c-ok');
}

$('trafficModal').addEventListener('click', e => { if (e.target.id === 'trafficModal') closeTraffic(); });

init();
