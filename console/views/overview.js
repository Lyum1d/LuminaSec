/* 总览：配置体检。**只读**。
 *
 * 这一页的价值不是「显示数据」，而是**一眼看出哪条防线没配上** ——
 * 下面每一项单看都不报错，组合起来才危险。所以警告区放在最上面，异常项红框置顶。
 */
import { api, esc, alertBox, setFileHint } from '/console-assets/core.js?v=112';

function kv(k, v, mono = true) {
  return `<div class="kv"><span>${esc(k)}</span>`
       + `<span class="${mono ? 'mono' : ''}">${esc(v)}</span></div>`;
}

function pill(text, kind) { return `<span class="pill ${kind}">${esc(text)}</span>`; }

export async function render(host) {
  const d = await api('/overview');
  setFileHint(`scope.json ${d.scope.file.sha256_short || '（不存在）'}`);

  const warns = (d.warnings || []).map((w) => alertBox(w.level, w.text)).join('');

  // ---- 白名单 ----
  const scopeCard = `
    <div class="card">
      <h3>授权白名单</h3>
      <div class="big">${d.scope.count} <span class="hint">条主机</span></div>
      <div class="sub">结构化条目 ${d.scope.structured} 条</div>
      <div class="kv"><span>强制校验</span><span>${d.scope.enforce
        ? pill('已开启', 'ok') : pill('已关闭', 'bad')}</span></div>
      <div class="kv"><span>待人工复核</span><span>${d.scope.needs_review
        ? pill(d.scope.needs_review + ' 条', 'warn') : pill('无', 'ok')}</span></div>
      ${kv('文件哈希', d.scope.file.sha256_short || '-')}
    </div>`;

  // ---- 工具 ----
  const levels = Object.entries(d.tool_levels || {})
    .sort().map(([k, v]) => kv(k, v)).join('');
  const toolCard = `
    <div class="card">
      <h3>工具登记</h3>
      <div class="big">${d.tools.scriptable} <span class="hint">可编排 / ${d.tools.total} 总数</span></div>
      <div class="sub">实际可用 ${d.tools.launchable} · 缺文件 ${d.tools.missing}
        · 交互式剔除 ${d.tools.interactive}</div>
      ${levels}
    </div>`;

  // ---- 供应商 ----
  const provRows = (d.providers || []).map((p) => {
    const st = !p.enabled ? pill('停用', 'dim')
      : (p.local || p.has_key) ? pill('可用', 'ok') : pill('缺 Key', 'bad');
    return `<div class="kv"><span>${esc(p.name || p.id)}${p.current ? ' · 当前' : ''}</span>`
         + `<span>${st}</span></div>`;
  }).join('') || '<div class="hint">未读取到供应商。</div>';
  // v102：口令来源必须显示出来 —— 「改了 config.yaml 却不生效」的根因
  // 往往是环境变量压着旧值；不说清楚就只能靠猜（表现为「口令设置了不保存」）。
  const pwSrcMap = {
    'env:AGENT_CONSOLE_PASSWORD': '环境变量 AGENT_CONSOLE_PASSWORD（优先）',
    'config.yaml': 'config.yaml（consolePassword）',
  };
  const pwSrc = pwSrcMap[d.console.password_source] || '未设置';
  const provCard = `<div class="card"><h3>决策模型</h3>${provRows}
    <div class="sub" style="margin-top:6px">口令已配：${d.console.password_configured ? '是' : '否'}
      · 来源：${esc(pwSrc)}</div></div>`;

  // ---- 依赖服务 ----
  const mcpOk = d.mcp && d.mcp.available;
  const mcpCard = `
    <div class="card">
      <h3>外部工具服务</h3>
      <div class="kv"><span>Burp MCP</span><span>${mcpOk
        ? pill('可用', 'ok') : pill('不可用', d.mcp && d.mcp.enabled ? 'warn' : 'dim')}</span></div>
      <div class="sub">${esc((d.mcp && d.mcp.note) || '').slice(0, 120)}</div>
      <div class="kv"><span>FOFA 测绘</span><span>${d.fofa.configured
        ? pill('已配置', 'ok') : pill('未配置', 'warn')}</span></div>
      <div class="sub">未配置时该工具仍会出现在模型清单里（P2 待修）。</div>
    </div>`;

  // ---- 超时口径 ----
  const ch = (d.timeouts && d.timeouts.channels) || {};
  const toCard = `
    <div class="card">
      <h3>超时口径</h3>
      ${kv('外部工具总时长', (ch.external_tool && ch.external_tool.total_cap) + 's')}
      ${kv('外部工具空闲', (ch.external_tool && ch.external_tool.idle_cap) + 's')}
      ${kv('py_exec', (ch.py_exec && ch.py_exec.total_cap) + 's')}
      <div class="kv"><span>不变量 idle&lt;total</span><span>${d.timeouts.idle_below_total
        ? pill('成立', 'ok') : pill('违反', 'bad')}</span></div>
    </div>`;

  // ---- 编排 ----
  const o = d.orchestration || {};
  const orchCard = `
    <div class="card">
      <h3>编排与闸门</h3>
      ${kv('执行模式', o.execution_mode)}
      ${kv('单轮最大步数', o.max_steps)}
      ${kv('token 预算', (o.run_token_budget || 0).toLocaleString())}
      <div class="kv"><span>py_exec 能力分档</span><span>${o.py_exec_grade_enabled
        ? pill('开', 'ok') : pill('关', 'warn')}</span></div>
      <div class="kv"><span>任务级约束闸门</span><span>${o.task_constraints_enabled
        ? pill('开', 'ok') : pill('关', 'warn')}</span></div>
    </div>`;

  host.innerHTML = `
    ${warns || '<div class="alert low"><span class="ico">i</span>'
      + '<span>未发现配置告警。</span></div>'}
    <div class="cards">
      ${scopeCard}${toolCard}${provCard}${mcpCard}${toCard}${orchCard}
    </div>
    <div class="sec-title">本页只读</div>
    <div class="hint">总览页不提供任何写入。要改配置请到左侧对应页签；
      所有写入都会记入「合规审计」。</div>`;
}
