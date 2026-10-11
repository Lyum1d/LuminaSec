/* 实时运行监控（P1 占位，P3 实现）。 */
import { placeholder } from '/console-assets/views/_placeholder.js?v=052';

export const render = placeholder({
  title: '实时监控',
  goal: '在控制台里看会话进度：步骤流、SSE 事件、确认框、取消与续跑。',
  items: [
    '会列表 → 选中看步骤表与事件日志',
    '确认框<strong>透传</strong>现有 <code>/api/sessions/{sid}/confirm</code>',
    '取消 / 续跑复用现有接口',
  ],
  apis: [['GET', '/api/projects', 'ready'], ['GET', '/api/sessions/{sid}', 'ready'],
         ['GET', '/api/sessions/{sid}/stream', 'ready'],
         ['POST', '/api/sessions/{sid}/confirm', 'ready'],
         ['POST', '/api/sessions/{sid}/cancel', 'ready'], ['GET', '/api/console/runs', 'todo']],
});

// 刻意**不新造确认通道**：确认双闸门（token + step_id + auth_ack）是安全核心，
// 控制台只做「换个界面调用同一个接口」。重写一遍就等于绕过它。
