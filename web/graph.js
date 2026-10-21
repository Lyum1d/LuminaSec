/* 线索图画布 —— 零依赖 SVG 分层 DAG 渲染。
 *
 * 形态对齐 LuaN1aoAgent 的线索图：
 *   · dagre 式的自上而下分层布局（这里自己实现：拓扑定层 + 重心法减少交叉）
 *   · 圆角矩形节点 + 左上角类型色药丸 + 标题/副标题两行
 *   · 平滑曲线连线 + 实心三角箭头
 *   · 缩放平移、悬停邻居聚焦 + 提示气泡、点击出节点详情
 *   · 活跃路径高亮、图例
 * 差别：全部自己写，不引 d3/dagre，保持「纯本地静态、断网可用」；
 *      配色走 CSS 变量类名，自动适配本项目的亮/暗主题。
 */
const GraphView = (function () {
  const NS = 'http://www.w3.org/2000/svg';

  // 类型色（CSS 变量名定义在 style.css 里，亮/暗主题各一套）
  const TYPE_VAR = {
    Project: '--g-project', Thread: '--g-thread', Evidence: '--g-evidence',
    KeyFact: '--g-keyfact', Hypothesis: '--g-hypothesis',
    Vulnerability: '--g-vuln', PossibleVulnerability: '--g-vuln',
    ConfirmedVulnerability: '--g-confirmed', Exploit: '--g-exploit',
    Credential: '--g-credential', SystemProperty: '--g-credential',
    TargetArtifact: '--g-confirmed', Flag: '--g-confirmed',
  };
  const STATUS_TEXT = {
    in_progress: '进行中', running: '运行中', completed: '已完成',
    deprecated: '已放弃', blocked: '待确认', pending: '待执行',
    interrupted: '已中断', failed: '失败',
    PENDING: '待验证', SUPPORTED: '已支撑', CONFIRMED: '已确认',
    CONTRADICTED: '被反驳', FALSIFIED: '已证伪', RE_EVALUATION_PENDING: '待重估',
  };
  const LEGEND_ATTACK = [
    ['in_progress', '进行中'], ['running', '运行中'], ['completed', '已完成'],
    ['blocked', '待确认'], ['deprecated', '已放弃'],
  ];
  // 攻击图图例色（状态 → CSS 变量）
  const STATUS_VAR = {
    in_progress: '--g-thread', running: '--g-accent', completed: '--ok',
    blocked: '--g-keyfact', deprecated: '--g-link', failed: '--danger',
  };
  const LEGEND_CAUSAL = [
    ['Evidence', '证据'], ['KeyFact', '关键事实'], ['Hypothesis', '假设'],
    ['Vulnerability', '疑似漏洞'], ['ConfirmedVulnerability', '确认漏洞'],
    ['Exploit', '利用'],
  ];

  const GAP_X = 34;      // 同层节点水平间距
  const GAP_Y = 86;      // 层间垂直间距
  const PAD = 26;        // 画布内边距
  // 允许调用方注入的回调（mount 或 render 时均可传入）
  const HOOK_KEYS = ['onOpenThread', 'onBranch', 'onSetStatus', 'onBranchFromNode'];

  let host = null, svg = null, vp = null, lLink = null, lLabel = null, lNode = null;
  let tipEl = null, panelEl = null, legendEl = null, emptyEl = null;
  let hooks = { onOpenThread: null, onBranch: null, onSetStatus: null, onBranchFromNode: null };
  let S = {
    view: 'attack', nodes: [], edges: [], currentId: '', selId: '',
    scale: 1, tx: 0, ty: 0, pos: new Map(), kids: new Map(), pars: new Map(),
    drag: null,
  };

  /* ---------- 小工具 ---------- */
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const cls = (s) => String(s || '').replace(/[^A-Za-z0-9_-]/g, '_');
  const color = (t) => `var(${TYPE_VAR[t] || '--g-link'})`;
  const statusText = (s) => STATUS_TEXT[s] || s || '';

  function el(tag, attrs) {
    const n = document.createElementNS(NS, tag);
    for (const k in (attrs || {})) n.setAttribute(k, attrs[k]);
    return n;
  }

  /* ---------- 尺寸 ---------- */
  function sizeOf(n) {
    const t = (n && n.node_type) || '';
    if (t === 'Project') return { w: 210, h: 66 };
    if (t === 'Thread') return { w: 178, h: 62 };
    if (t === 'ConfirmedVulnerability') return { w: 176, h: 60 };
    if (t === 'Vulnerability') return { w: 164, h: 58 };
    if (t === 'KeyFact' || t === 'Evidence') return { w: 152, h: 56 };
    return { w: 152, h: 56 };
  }

  /* ---------- 布局：拓扑定层 + 重心法排序 ---------- */
  function computeLayout(nodes, edges) {
    const byId = new Map(nodes.map(n => [n.id, n]));
    const kids = new Map(), pars = new Map();
    nodes.forEach(n => { kids.set(n.id, []); pars.set(n.id, []); });
    edges.forEach(e => {
      if (!byId.has(e.source_id) || !byId.has(e.target_id)) return;
      if (e.source_id === e.target_id) return;
      kids.get(e.source_id).push(e.target_id);
      pars.get(e.target_id).push(e.source_id);
    });

    // Kahn 拓扑序；成环的节点按原顺序兜底（线索图正常不会有环）
    const indeg = new Map(nodes.map(n => [n.id, pars.get(n.id).length]));
    const queue = nodes.filter(n => indeg.get(n.id) === 0).map(n => n.id);
    const order = [], seen = new Set();
    while (queue.length) {
      const id = queue.shift();
      if (seen.has(id)) continue;
      seen.add(id); order.push(id);
      kids.get(id).forEach(k => {
        indeg.set(k, indeg.get(k) - 1);
        if (indeg.get(k) === 0) queue.push(k);
      });
    }
    nodes.forEach(n => { if (!seen.has(n.id)) order.push(n.id); });

    // rank = 所有前驱 rank 的最大值 + 1（多父节点取最深，保证边都向下）
    const rank = new Map();
    order.forEach(id => {
      let r = 0;
      pars.get(id).forEach(p => { if (rank.has(p)) r = Math.max(r, rank.get(p) + 1); });
      rank.set(id, r);
    });

    // 孤立节点（既无进边也无出边）单独落到底部一行。
    // 否则它们的 rank 是 0，会跑到最上层和「证据 / 起点」挤在一起，看着像同类。
    let maxRank = 0;
    rank.forEach(r => { if (r > maxRank) maxRank = r; });
    nodes.forEach(n => {
      const noIn = (pars.get(n.id) || []).length === 0;
      const noOut = (kids.get(n.id) || []).length === 0;
      if (noIn && noOut) rank.set(n.id, maxRank + 1);
    });

    const layers = [];
    nodes.forEach(n => {
      const r = rank.get(n.id) || 0;
      (layers[r] = layers[r] || []).push(n.id);
    });
    const rows = layers.filter(Boolean);

    // 重心法迭代：先自下而上按父节点位置排，再自上而下按子节点位置排
    const seq = new Map();
    rows.forEach(layer => layer.forEach((id, i) => seq.set(id, i)));
    const barySort = (layer, relMap) => {
      const items = layer.map((id, i) => {
        const rels = (relMap.get(id) || []).map(x => seq.get(x)).filter(v => v !== undefined);
        return { id, i, b: rels.length ? rels.reduce((a, c) => a + c, 0) / rels.length : i };
      });
      items.sort((a, b) => (a.b - b.b) || (a.i - b.i));
      items.forEach((it, i) => seq.set(it.id, i));
      return items.map(it => it.id);
    };
    for (let it = 0; it < 4; it++) {
      for (let li = 1; li < rows.length; li++) rows[li] = barySort(rows[li], pars);
      for (let li = rows.length - 2; li >= 0; li--) rows[li] = barySort(rows[li], kids);
    }

    // ---- 坐标分配 ----
    // 先按层均匀铺开，再迭代「向相邻层重心靠拢 + 同层防重叠右推」。
    // 只做层内居中是不够的：那样子节点不会落在父节点下方，图会歪（实测偏移上百像素）。
    const widthOf = (layer) => layer.reduce((a, id) => a + sizeOf(byId.get(id)).w, 0)
      + GAP_X * Math.max(0, layer.length - 1);
    const maxW = Math.max(1, ...rows.map(widthOf));

    const xs = new Map();
    rows.forEach(layer => {
      let x = (maxW - widthOf(layer)) / 2;
      layer.forEach(id => {
        const s = sizeOf(byId.get(id));
        xs.set(id, x + s.w / 2);
        x += s.w + GAP_X;
      });
    });

    const wantX = (id, relMap) => {
      const rels = (relMap.get(id) || []).filter(r => xs.has(r));
      if (!rels.length) return null;
      return rels.reduce((a, r) => a + xs.get(r), 0) / rels.length;
    };

    for (let it = 0; it < 8; it++) {
      const down = it % 2 === 0;                       // 下推：对齐父节点；上推：对齐子节点
      const idxs = rows.map((_, i) => i);
      if (!down) idxs.reverse();
      idxs.forEach(li => {
        const rel = down ? pars : kids;
        const layer = rows[li];
        const want = new Map(layer.map(id => [id, wantX(id, rel) ?? xs.get(id)]));
        const sorted = layer.slice().sort((a, b) => want.get(a) - want.get(b));
        let prev = -Infinity;
        sorted.forEach((id, i) => {
          const s = sizeOf(byId.get(id));
          let cx = want.get(id);
          if (i > 0) cx = Math.max(cx, prev + GAP_X + s.w / 2);
          xs.set(id, cx);
          prev = cx + s.w / 2;
        });
        // 压紧后整体平移，让本层中心落在期望位置的均值上
        const targetMean = sorted.reduce((a, id) => a + want.get(id), 0) / sorted.length;
        const center = sorted.reduce((a, id) => a + xs.get(id), 0) / sorted.length;
        const shift = targetMean - center;
        sorted.forEach(id => xs.set(id, xs.get(id) + shift));
        rows[li] = sorted;
      });
    }

    const pos = new Map();
    let y = 0;
    rows.forEach(layer => {
      const h = Math.max(20, ...layer.map(id => sizeOf(byId.get(id)).h));
      layer.forEach(id => {
        const s = sizeOf(byId.get(id));
        pos.set(id, { x: xs.get(id), y: y + h / 2, w: s.w, h: s.h });
      });
      y += h + GAP_Y;
    });

    S.pos = pos; S.kids = kids; S.pars = pars;
    let x0 = Infinity, x1 = -Infinity;
    pos.forEach(p => {
      x0 = Math.min(x0, p.x - p.w / 2);
      x1 = Math.max(x1, p.x + p.w / 2);
    });
    const box = { x0: x0 - PAD, y0: -PAD,
                  x1: x1 + PAD, y1: Math.max(60, y - GAP_Y) + PAD };
    return { pos, box };
  }

  /* ---------- 文字截断（用真实渲染宽度，避免中英混排估算失真） ---------- */
  function fitText(node, maxWidth) {
    // 2026-09-18 修复文字溢出：三层保险。
    // 根因：首次测量时中文/主题字体尚未就绪，getComputedTextLength() 用
    // fallback 字体测出偏窄宽度 → 误判「不超限」不截断，字体就绪后实际
    // 渲染变宽溢出节点卡片。因此：
    //   ① 原文存 dataset.fullText——重截时从原文开始（截断是破坏性的，
    //      直接在已截文本上再截会越截越短）；
    //   ② maxWidth 存 dataset.maxw——fonts.ready 后可批量重截（refitTexts）；
    //   ③ 测量异常（元素未布局）直接放弃本次截断，交给 refitTexts 兜底。
    node.dataset.maxw = String(maxWidth);
    const original = node.dataset.fullText ?? node.textContent;
    node.dataset.fullText = original;
    node.textContent = original;
    let len;
    try {
      len = node.getComputedTextLength();
    } catch (e) {
      return;
    }
    if (!len || len <= maxWidth) return;
    let s = original;
    while (s.length > 1 && node.getComputedTextLength() > maxWidth) {
      s = s.slice(0, -1);
      node.textContent = s + '…';
    }
  }

  function refitTexts() {
    if (!lNode) return;
    lNode.querySelectorAll('text[data-maxw]').forEach(t => {
      fitText(t, parseFloat(t.dataset.maxw) || 0);
    });
  }
  // 字体异步就绪后统一重截一次（首绘测宽失真的兜底）
  if (typeof document !== 'undefined' && document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => refitTexts());
  }

  /* ---------- 绘制 ---------- */
  function pathOf(e) {
    const a = S.pos.get(e.source_id), b = S.pos.get(e.target_id);
    if (!a || !b) return '';
    const y1 = a.y + a.h / 2, y2 = b.y - b.h / 2;
    const dy = Math.max(22, (y2 - y1) * 0.42);
    return `M ${a.x} ${y1} C ${a.x} ${y1 + dy}, ${b.x} ${y2 - dy}, ${b.x} ${y2}`;
  }

  function activePathIds() {
    // 攻击图上高亮「根 → 当前线索」的路径
    if (S.view !== 'attack' || !S.currentId || !S.pos.has(S.currentId)) return new Set();
    const out = new Set();
    let cur = S.currentId, guard = 0;
    while (cur && guard++ < 64) {
      out.add(cur);
      const pars = S.pars.get(cur) || [];
      cur = pars.length ? pars[0] : '';
    }
    return out;
  }

  function draw() {
    if (!svg) return;
    lLink.textContent = ''; lLabel.textContent = ''; lNode.textContent = '';
    const activeIds = activePathIds();
    const activeEdges = new Set();
    activeIds.forEach(id => {
      (S.pars.get(id) || []).forEach(p => { if (activeIds.has(p)) activeEdges.add(p + '>' + id); });
    });

    // ---- 边 ----
    S.edges.forEach(e => {
      const d = pathOf(e);
      if (!d) return;
      const active = activeEdges.has(e.source_id + '>' + e.target_id);
      lLink.appendChild(el('path', {
        d, class: `glink st-${cls(e.label)}${active ? ' active' : ''}`,
        'marker-end': 'url(#g-arrow)', 'data-s': e.source_id, 'data-t': e.target_id,
      }));
      // 因果图把边语义（支撑/反驳/揭示）标出来，攻击图全是「分支」就不标了
      if (S.view === 'causal' && e.label && e.label !== 'BRANCH') {
        const a = S.pos.get(e.source_id), b = S.pos.get(e.target_id);
        const t = el('text', {
          class: `glabel lg-${cls(e.label)}`,
          x: (a.x + b.x) / 2 + 8, y: (a.y + a.h / 2 + b.y - b.h / 2) / 2 + 3,
        });
        t.textContent = e.label_text || e.label;
        lLabel.appendChild(t);
      }
    });

    // ---- 节点 ----
    S.nodes.forEach(n => {
      const p = S.pos.get(n.id);
      if (!p) return;
      const isCur = n.id === S.currentId;
      const isSel = n.id === S.selId;
      const onPath = activeIds.has(n.id);
      const g = el('g', {
        class: `gnode t-${cls(n.node_type)} s-${cls(n.status)}`
          + (isCur ? ' cur' : '') + (isSel ? ' sel' : '') + (onPath ? ' onpath' : ''),
        transform: `translate(${p.x},${p.y})`,
      });
      g.dataset.id = n.id;
      g.appendChild(el('rect', {
        x: -p.w / 2, y: -p.h / 2, width: p.w, height: p.h, rx: 9, ry: 9,
        class: 'gn-box',
      }));

      // 左上角类型药丸
      const pill = (n.type_label || n.node_type || '节点');
      const pillW = Math.min(p.w - 18, 26 + pill.length * 11);
      g.appendChild(el('rect', {
        x: -p.w / 2 + 9, y: -p.h / 2 + 6, width: pillW, height: 15, rx: 7.5,
        class: 'gn-pill', style: `fill:${color(n.node_type)}`,
      }));
      const pt = el('text', {
        x: -p.w / 2 + 9 + pillW / 2, y: -p.h / 2 + 17, class: 'gn-pilltext',
      });
      pt.textContent = pill;
      g.appendChild(pt);

      const title = el('text', { x: -p.w / 2 + 10, y: p.h / 2 - 19, class: 'gn-title' });
      title.textContent = n.title || n.id;
      g.appendChild(title);
      fitText(title, p.w - 20);

      const sub = el('text', { x: -p.w / 2 + 10, y: p.h / 2 - 7, class: 'gn-sub' });
      sub.textContent = subtitleOf(n);
      g.appendChild(sub);
      fitText(sub, p.w - 20);

      lNode.appendChild(g);
    });

    applyTransform();
    renderLegend();
    bindNodeEvents();
    // 字体就绪时序兜底：下一帧重截一次（首绘测量可能用了 fallback 字体宽度）
    requestAnimationFrame(refitTexts);
  }

  function subtitleOf(n) {
    if (S.view === 'attack') {
      const st = statusText(n.status);
      if (n.node_type === 'Project') return n.description || '项目根';
      const steps = (n.data && n.data.step_count) || 0;
      return `${st} · ${steps} 步`;
    }
    const bits = [statusText(n.status)];
    if (typeof n.confidence === 'number') bits.push(`置信 ${Math.round(n.confidence * 100)}%`);
    if (n.severity) bits.push(n.severity);
    return bits.join(' · ');
  }

  function applyTransform() {
    if (vp) vp.setAttribute('transform', `translate(${S.tx},${S.ty}) scale(${S.scale})`);
  }

  /* ---------- 交互 ---------- */
  function neighbours(id) {
    const out = new Set([id]);
    (S.kids.get(id) || []).forEach(k => out.add(k));
    (S.pars.get(id) || []).forEach(p => out.add(p));
    return out;
  }

  function focusNeighbours(id) {
    if (!id) return;
    const keep = neighbours(id);
    lNode.querySelectorAll('.gnode').forEach(g => {
      g.classList.toggle('dimmed', !keep.has(g.dataset.id));
    });
    const strong = new Set();
    keep.forEach(k => keep.forEach(j => { if (k !== j) strong.add(k + '>' + j); strong.add(j + '>' + k); }));
    lLink.querySelectorAll('.glink').forEach(p => {
      p.classList.toggle('dimmed', !strong.has(p.dataset.s + '>' + p.dataset.t));
    });
  }

  function clearFocus() {
    lNode.querySelectorAll('.gnode.dimmed').forEach(g => g.classList.remove('dimmed'));
    lLink.querySelectorAll('.glink.dimmed').forEach(p => p.classList.remove('dimmed'));
  }

  function showTip(n, ev) {
    if (!tipEl || !n) return;
    const desc = n.description || (n.data && (n.data.output_head || n.data.summary)) || '';
    tipEl.innerHTML = `<div class="gt-title">${escapeHtml(n.title || n.id)}</div>`
      + `<div class="gt-meta">${escapeHtml(n.type_label || n.node_type)}`
      + `${n.confidence != null ? ' · 置信 ' + Math.round(n.confidence * 100) + '%' : ''}</div>`
      + (desc ? `<div class="gt-desc">${escapeHtml(desc.slice(0, 220))}</div>` : '');
    tipEl.style.display = 'block';
    moveTip(ev);
  }

  function moveTip(ev) {
    if (!tipEl || tipEl.style.display === 'none') return;
    const box = host.getBoundingClientRect();
    const x = clamp(ev.clientX - box.left + 14, 4, box.width - 300);
    const y = clamp(ev.clientY - box.top + 14, 4, box.height - 90);
    tipEl.style.left = x + 'px';
    tipEl.style.top = y + 'px';
  }

  function hideTip() { if (tipEl) tipEl.style.display = 'none'; }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function bindNodeEvents() {
    lNode.querySelectorAll('.gnode').forEach(g => {
      const id = g.dataset.id;
      const node = S.nodes.find(n => n.id === id);
      g.addEventListener('mouseenter', ev => { focusNeighbours(id); showTip(node, ev); });
      g.addEventListener('mousemove', moveTip);
      g.addEventListener('mouseleave', () => { clearFocus(); hideTip(); });
      // 攻击图上单击「线索」节点直接切到那条对话——这是最直觉的期望，也是切换线索的主入口。
      // （曾经改成"只弹详情面板"，用户就以为回不去旧对话了。）面板照样弹，两者不冲突。
      g.addEventListener('click', ev => {
        ev.stopPropagation();
        select(id);
        if (S.view === 'attack' && node && node.node_type === 'Thread'
            && hooks.onOpenThread && id !== S.currentId) {
          hooks.onOpenThread(id);
        }
      });
      g.addEventListener('dblclick', ev => {
        ev.stopPropagation();
        if (S.view === 'attack' && node && node.node_type === 'Thread' && hooks.onOpenThread) {
          hooks.onOpenThread(id);
        }
      });
    });
  }

  function select(id) {
    S.selId = id;
    lNode.querySelectorAll('.gnode').forEach(g =>
      g.classList.toggle('sel', g.dataset.id === id));
    renderPanel();
  }

  /* ---------- 节点详情面板 ---------- */
  function renderPanel() {
    if (!panelEl) return;
    const n = S.nodes.find(x => x.id === S.selId);
    if (!n) { panelEl.style.display = 'none'; panelEl.innerHTML = ''; return; }
    const rows = [];
    rows.push(`<div class="gp-head"><span class="gp-type" style="color:${color(n.node_type)}">`
      + `${escapeHtml(n.type_label || n.node_type)}</span>`
      + `<button class="gp-x" title="关闭">✕</button></div>`);
    rows.push(`<div class="gp-title">${escapeHtml(n.title || n.id)}</div>`);
    const meta = [];
    // 置信度只属于因果图：攻击图的「线索」节点谈置信度没有意义（一律 100%，纯噪声）
    const causal = S.view === 'causal';
    if (n.status) meta.push(statusText(n.status));
    if (causal && n.confidence != null) meta.push(`置信 ${Math.round(n.confidence * 100)}%`);
    if (!causal && n.data && n.data.step_count != null) meta.push(`${n.data.step_count} 步`);
    if (n.severity) meta.push(n.severity);
    if (meta.length) rows.push(`<div class="gp-meta">${escapeHtml(meta.join(' · '))}</div>`);
    if (causal && n.confidence != null) {
      rows.push(`<div class="gp-bar"><i style="width:${Math.round(n.confidence * 100)}%"></i></div>`);
    }
    if (n.description) rows.push(`<div class="gp-desc">${escapeHtml(n.description)}</div>`);
    const extra = n.data && (n.data.output_head || n.data.evidence || n.data.summary);
    if (extra) rows.push(`<pre class="gp-pre">${escapeHtml(String(extra).slice(0, 700))}</pre>`);

    const acts = [];
    if (!causal && n.node_type === 'Thread' && hooks.onOpenThread) {
      acts.push(`<button class="primary mini" data-a="open">打开这条线索</button>`);
      if (hooks.onBranch) acts.push(`<button class="mini" data-a="branch">＋ 分支</button>`);
      if (hooks.onSetStatus) {
        if (n.status !== 'completed') acts.push(`<button class="mini" data-a="done">✓ 标记完成</button>`);
        if (n.status !== 'deprecated') acts.push(`<button class="mini" data-a="abandon">✕ 标记放弃</button>`);
        if (n.status !== 'in_progress') acts.push(`<button class="mini" data-a="active">↺ 重新打开</button>`);
      }
    } else if (causal && hooks.onBranchFromNode) {
      acts.push(`<button class="primary mini" data-a="dig">以此线索开分支</button>`);
      acts.push(`<button class="mini" data-a="copy">复制内容</button>`);
    }
    if (acts.length) rows.push(`<div class="gp-acts">${acts.join('')}</div>`);

    panelEl.innerHTML = rows.join('');
    panelEl.style.display = 'block';
    const closeBtn = panelEl.querySelector('.gp-x');
    if (closeBtn) closeBtn.onclick = (e) => {
      e.stopPropagation();
      S.selId = ''; renderPanel();
      lNode.querySelectorAll('.gnode.sel').forEach(g => g.classList.remove('sel'));
    };
    panelEl.querySelectorAll('.gp-acts button').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const a = btn.dataset.a;
        if (a === 'open' && hooks.onOpenThread) hooks.onOpenThread(n.id);
        else if (a === 'branch' && hooks.onBranch) hooks.onBranch(n.id);
        else if (a === 'done' && hooks.onSetStatus) hooks.onSetStatus(n.id, 'done');
        else if (a === 'abandon' && hooks.onSetStatus) hooks.onSetStatus(n.id, 'abandoned');
        else if (a === 'active' && hooks.onSetStatus) hooks.onSetStatus(n.id, 'active');
        else if (a === 'dig' && hooks.onBranchFromNode) hooks.onBranchFromNode(n);
        else if (a === 'copy') {
          const text = `${n.title || ''}\n${n.description || ''}`.trim();
          if (navigator.clipboard) navigator.clipboard.writeText(text);
        }
      };
    });
  }

  /* ---------- 图例 ---------- */
  function renderLegend() {
    if (!legendEl) return;
    const items = S.view === 'causal'
      ? LEGEND_CAUSAL.filter(([k]) => S.nodes.some(n => n.node_type === k))
        .map(([k, t]) => [color(k), t])
      : LEGEND_ATTACK.map(([k, t]) => [`var(${STATUS_VAR[k] || '--g-link'})`, t]);
    legendEl.innerHTML = items.map(([c, t]) =>
      `<span class="gl-item"><i style="background:${c}"></i>${escapeHtml(t)}</span>`).join('');
  }

  /* ---------- 视图控制 ---------- */
  function fit() {
    if (!host || !S.pos.size) return;
    const box = host.getBoundingClientRect();
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    S.pos.forEach(p => {
      x0 = Math.min(x0, p.x - p.w / 2); x1 = Math.max(x1, p.x + p.w / 2);
      y0 = Math.min(y0, p.y - p.h / 2); y1 = Math.max(y1, p.y + p.h / 2);
    });
    const w = Math.max(1, x1 - x0), h = Math.max(1, y1 - y0);
    const availW = Math.max(120, box.width - PAD * 2);
    const availH = Math.max(90, box.height - PAD * 2);
    S.scale = clamp(Math.min(availW / w, availH / h, 1.15), 0.1, 4);
    S.tx = (box.width - w * S.scale) / 2 - x0 * S.scale;
    S.ty = (box.height - h * S.scale) / 2 - y0 * S.scale;
    applyTransform();
  }

  function zoomBy(f, cx, cy) {
    if (!host) return;
    const box = host.getBoundingClientRect();
    const mx = cx == null ? box.width / 2 : cx;
    const my = cy == null ? box.height / 2 : cy;
    const ns = clamp(S.scale * f, 0.1, 4);
    S.tx = mx - (mx - S.tx) * (ns / S.scale);
    S.ty = my - (my - S.ty) * (ns / S.scale);
    S.scale = ns;
    applyTransform();
  }

  function bindCanvasEvents() {
    svg.addEventListener('wheel', ev => {
      ev.preventDefault();
      const box = host.getBoundingClientRect();
      zoomBy(ev.deltaY < 0 ? 1.12 : 1 / 1.12, ev.clientX - box.left, ev.clientY - box.top);
    }, { passive: false });

    svg.addEventListener('mousedown', ev => {
      if (ev.button !== 0) return;
      S.drag = { x: ev.clientX, y: ev.clientY, tx: S.tx, ty: S.ty, moved: false };
      svg.classList.add('grabbing');
    });
    window.addEventListener('mousemove', ev => {
      if (!S.drag) return;
      const dx = ev.clientX - S.drag.x, dy = ev.clientY - S.drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) S.drag.moved = true;
      S.tx = S.drag.tx + dx; S.ty = S.drag.ty + dy;
      applyTransform();
    });
    window.addEventListener('mouseup', () => {
      if (!S.drag) return;
      const moved = S.drag.moved;
      S.drag = null;
      svg.classList.remove('grabbing');
      if (!moved) { S.selId = ''; renderPanel(); }   // 点空白处取消选中
    });
    svg.addEventListener('dblclick', ev => {
      if (ev.target.closest && ev.target.closest('.gnode')) return;
      fit();
    });
  }

  /* ---------- 对外接口 ---------- */
  function mount(hostEl, options) {
    host = hostEl;
    hooks = Object.assign(hooks, options || {});
    host.innerHTML = '';
    svg = el('svg', { class: 'gsvg' });
    const defs = el('defs');
    const marker = el('marker', {
      id: 'g-arrow', viewBox: '0 0 10 10', refX: '9', refY: '5',
      markerWidth: '6', markerHeight: '6', orient: 'auto-start-reverse',
    });
    marker.appendChild(el('path', { d: 'M 0 0 L 10 5 L 0 10 z', class: 'g-arrow-head' }));
    defs.appendChild(marker);
    svg.appendChild(defs);
    vp = el('g'); lLink = el('g'); lLabel = el('g'); lNode = el('g');
    vp.appendChild(lLink); vp.appendChild(lLabel); vp.appendChild(lNode);
    svg.appendChild(vp);
    host.appendChild(svg);

    emptyEl = document.createElement('div');
    emptyEl.className = 'graph-empty';
    host.appendChild(emptyEl);

    tipEl = document.createElement('div');
    tipEl.className = 'graph-tip';
    tipEl.style.display = 'none';
    host.appendChild(tipEl);

    panelEl = document.createElement('div');
    panelEl.className = 'graph-panel';
    panelEl.style.display = 'none';
    host.appendChild(panelEl);

    legendEl = options && options.legendEl ? options.legendEl : null;
    bindCanvasEvents();
    return GraphView;
  }

  function render(data, opts) {
    opts = opts || {};
    // 回调允许在 render 时传入（也可在 mount 时一次性给）。只认函数，避免把普通字段误当回调。
    for (const k of HOOK_KEYS) {
      if (typeof opts[k] === 'function') hooks[k] = opts[k];
    }
    S.view = opts.view || S.view;
    S.currentId = opts.currentId || '';
    S.nodes = (data && data.nodes) || [];
    S.edges = (data && data.edges) || [];
    if (S.selId && !S.nodes.some(n => n.id === S.selId)) { S.selId = ''; renderPanel(); }
    if (!svg) return;

    if (!S.nodes.length) {
      lLink.textContent = ''; lLabel.textContent = ''; lNode.textContent = '';
      if (emptyEl) {
        emptyEl.style.display = 'block';
        emptyEl.textContent = opts.emptyText || '暂无节点';
      }
      if (legendEl) legendEl.innerHTML = '';
      if (panelEl) { panelEl.style.display = 'none'; panelEl.innerHTML = ''; }
      return;
    }
    if (emptyEl) emptyEl.style.display = 'none';

    computeLayout(S.nodes, S.edges);
    draw();
    if (!opts.keepViewport) fit();
    // 首次渲染时容器可能还没拿到尺寸，下一帧再适配一次
    if (!opts.keepViewport) requestAnimationFrame(() => { if (S.scale === 1) fit(); });
    return GraphView;
  }

  return {
    mount, render, fit, zoomBy,
    reset: fit,
    setView: (v) => { S.view = v; },
    getView: () => S.view,
    select: (id) => select(id),
    closePanel: () => { S.selId = ''; renderPanel(); },
  };
})();
