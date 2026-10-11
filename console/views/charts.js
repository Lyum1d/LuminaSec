/* 统计看板（P1 占位，P3 实现）。 */
import { placeholder } from '/console-assets/views/_placeholder.js?v=052';

export const render = placeholder({
  title: '统计看板',
  goal: '把用量、流量、步骤成功率、耗时分布、工具调用频次画出来。',
  items: [
    'token 用量与费用趋势（按日）',
    '目标请求数、步骤成功率、耗时分布',
    '工具调用 TOP N 与失败归因分布',
    '图表<strong>自绘 SVG</strong>，不引第三方库、不引 CDN（本机有代理且可能离线）',
  ],
  apis: [['GET', '/api/usage/summary', 'ready'], ['GET', '/api/usage/daily', 'ready'],
         ['GET', '/api/usage/list', 'ready'], ['GET', '/api/console/stats', 'todo']],
});

// 现有 /api/usage/* 已有数据，但界面很弱（只有一个弹窗），本页是把它做成常驻看板。
