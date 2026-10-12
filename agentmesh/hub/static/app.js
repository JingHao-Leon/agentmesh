/* AgentMesh 看板前端
   零依赖、零构建、单文件逻辑 —— 演示/内网环境不该因为拉不到 npm 包就看不到看板。
   数据来源:WebSocket 实时事件 + 3 秒一次快照兜底。 */

const $  = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

const state = {
  snapshot: null,
  events: [],        // 最近 500 条
  eventFilter: '',
  drawerTask: null,
  ws: null,
  wsBackoff: 800,
  lastHead: -1,
};

const COLUMNS = [
  { key: 'ready',   title: '待认领',   hint: '任何匹配能力的 Agent 都能领' },
  { key: 'handoff', title: '交接中',   hint: '已指名,等对方来领' },
  { key: 'claimed', title: '执行中',   hint: '持有租约,正在做' },
  { key: 'done',    title: '已完成',   hint: '产出已归档' },
];

const STATUS_TEXT = { idle: '空闲', busy: '执行中', offline: '离线', disabled: '已禁用' };

// ============================================================
// 启动
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  $('hubAddr').textContent = location.origin;
  $('btnVerify').addEventListener('click', runVerify);
  $('btnCloseVerify').addEventListener('click', () => { $('verifyPanel').hidden = true; });
  $('btnCloseDrawer').addEventListener('click', closeDrawer);
  $('drawerMask').addEventListener('click', closeDrawer);
  $('eventFilter').addEventListener('change', (e) => {
    state.eventFilter = e.target.value;
    renderEvents();
  });
  $('btnNewTask').addEventListener('click', openTaskModal);
  $('submitTask').addEventListener('click', submitTask);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeDrawer(); $('taskModal').close(); }
  });

  refresh();
  loadInitialEvents();
  connect();
  setInterval(refresh, 3000);   // 兜底轮询:即便 WS 断了,数据也不会僵住
});

// ============================================================
// WebSocket
// ============================================================
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws = ws;

  ws.onopen = () => {
    setWsState('on', '实时连接');
    state.wsBackoff = 800;
    // 断线期间可能漏了事件,主动补齐再进实时流
    ws.send(JSON.stringify({ type: 'sync', after_seq: state.lastHead }));
  };

  ws.onmessage = (m) => {
    let msg;
    try { msg = JSON.parse(m.data); } catch { return; }
    if (msg.type === 'hello') {
      state.lastHead = msg.head_seq;
    } else if (msg.type === 'sync_done') {
      (msg.events || []).forEach(pushEvent);
      state.lastHead = msg.head_seq;
      scheduleRender();
    } else if (msg.type === 'event') {
      pushEvent(msg.event);
      scheduleRender();
    } else if (msg.type === 'tick') {
      scheduleRender();
    } else if (msg.type === 'notice') {
      toast(msg.text || '', 'warn');
    }
  };

  ws.onclose = () => {
    setWsState('off', '连接断开,重连中…');
    setTimeout(connect, state.wsBackoff);
    state.wsBackoff = Math.min(state.wsBackoff * 1.7, 10000);
  };
  ws.onerror = () => { try { ws.close(); } catch {} };
}

function setWsState(kind, text) {
  const box = $('wsBox');
  box.className = 'ws ' + kind;
  $('wsText').textContent = text;
}

let renderTimer = null;
function scheduleRender() {
  if (renderTimer) return;
  // 合并高频事件到一帧里渲染,避免事件多时页面卡顿
  renderTimer = setTimeout(() => { renderTimer = null; render(); }, 260);
}

function pushEvent(ev) {
  if (ev && ev.seq <= state.lastHead && state.events.length) {
    // 补齐模式下重复推送会跳过;实时模式下 lastHead 还没更新,所以能进来
    if (state.events.some((e) => e.seq === ev.seq)) return;
  }
  state.events.push(ev);
  if (state.events.length > 500) state.events.splice(0, state.events.length - 500);
  state.lastHead = Math.max(state.lastHead, ev.seq || -1);
}

// ============================================================
// 数据
// ============================================================
async function refresh() {
  try {
    const r = await fetch('/api/state');
    if (!r.ok) return;
    state.snapshot = await r.json();
    $('hubFp').textContent = state.snapshot.hub_fingerprint || '—';
    render();
  } catch (e) { /* 网络抖动,下一轮再试 */ }
}

// 首屏补历史事件。只靠 WebSocket 的话,页面打开前发生的那些事就永远看不到了。
async function loadInitialEvents() {
  try {
    const r = await fetch('/api/events?after_seq=-1&limit=2000');
    if (!r.ok) return;
    const d = await r.json();
    const all = d.events || [];
    const tail = all.slice(-400);           // 只留最近 400 条,够看又不拖慢渲染
    state.events = tail;
    state.lastHead = d.head;
    renderEvents();
  } catch (e) { /* 忽略 */ }
}

// ============================================================
// 渲染
// ============================================================
function render() {
  const s = state.snapshot;
  if (!s) return;
  renderStats(s);
  renderAgents(s);
  renderBoard(s);
  renderEvents();
}

function renderStats(s) {
  const t = s.stats.tasks || {};
  const items = [
    { k: '在线 Agent', v: `${s.stats.agents_online}/${s.stats.agents_total}`, s: '持有私钥的独立进程', cls: 'ok' },
    { k: '执行中',     v: t.claimed || 0, s: '正在持有租约', cls: 'acc' },
    { k: '待认领',     v: t.ready || 0, s: '等合适的人来领', cls: 'warn' },
    { k: '已完成',     v: t.done || 0, s: '产出已归档', cls: 'ok' },
    { k: '事件总数',   v: s.stats.events || 0, s: '全部经签名入链', cls: 'acc' },
  ];
  const box = $('stats');
  box.textContent = '';
  items.forEach((it) => {
    const d = el('div', 'stat ' + (it.cls || ''));
    d.appendChild(el('div', 'k', it.k));
    d.appendChild(el('div', 'v', String(it.v)));
    d.appendChild(el('div', 's', it.s));
    box.appendChild(d);
  });
  $('chainSeq').textContent = '#' + s.head_seq;
  $('chainHash').textContent = (s.head_hash || '').slice(0, 16);
}

function renderAgents(s) {
  const box = $('agents');
  box.textContent = '';
  if (!s.agents.length) {
    box.appendChild(el('div', 'hint', '还没有 Agent 注册。命令见 README:python -m agentmesh.agent --id xxx'));
  }
  s.agents.forEach((a) => {
    const c = el('div', 'agent ' + a.status);
    c.appendChild(a.status === 'busy' ? el('div', 'lease-bar') : document.createComment(''));

    const top = el('div', 'agent-top');
    const left = el('div');
    left.appendChild(el('div', 'agent-name', a.display_name));
    left.appendChild(el('div', 'agent-id', a.agent_id));
    if (a.role) left.appendChild(el('div', 'agent-role', a.role));
    top.appendChild(left);
    top.appendChild(el('span', 'badge ' + a.status, STATUS_TEXT[a.status] || a.status));
    c.appendChild(top);

    const caps = el('div', 'caps');
    (a.capabilities || []).forEach((x) => caps.appendChild(el('span', 'cap', x)));
    c.appendChild(caps);

    if (a.current_task) {
      const t = el('div', 'agent-task');
      t.textContent = '▶ ' + (a.current_task_title || a.current_task);
      c.appendChild(t);
    }

    const foot = el('div', 'agent-foot');
    foot.appendChild(kvLine('心跳', a.heartbeat_age + 's 前'));
    foot.appendChild(kvLine('完成', a.tasks_done));
    foot.appendChild(kvLine('交出', a.handoffs_given));
    foot.appendChild(kvLine('接手', a.handoffs_recv));
    foot.appendChild(kvLine('指纹', a.key_fingerprint));
    c.appendChild(foot);

    c.addEventListener('click', () => a.current_task && openDrawer(a.current_task));
    box.appendChild(c);
  });
  $('agentHint').textContent = `${s.stats.agents_online} 在线 / ${s.stats.agents_total} 注册`;
}

function kvLine(k, v) {
  const n = el('span');
  n.appendChild(el('b', null, k + ' '));
  n.appendChild(document.createTextNode(String(v)));
  return n;
}

function bucketOf(t) {
  if (t.state === 'done' || t.state === 'failed' || t.state === 'cancelled') return 'done';
  if (t.state === 'claimed') return 'claimed';
  if (t.handoff_open) return 'handoff';
  return 'ready';
}

function renderBoard(s) {
  const board = $('board');
  board.textContent = '';
  const buckets = { ready: [], handoff: [], claimed: [], done: [] };
  s.tasks.forEach((t) => buckets[bucketOf(t)].push(t));
  // 已完成按最近完成排前面:看板要看"刚发生了什么",不是翻旧账
  buckets.done.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));

  const LIMIT = 14;
  COLUMNS.forEach((col) => {
    const c = el('div', 'col');
    const h = el('div', 'col-head');
    h.appendChild(el('span', null, col.title));
    h.appendChild(el('span', 'n', String(buckets[col.key].length)));
    h.title = col.hint;
    c.appendChild(h);

    const items = buckets[col.key];
    if (!items.length) {
      c.appendChild(el('div', 'hint', col.key === 'ready' ? '队列为空' : '—'));
    }
    items.slice(0, LIMIT).forEach((t) => c.appendChild(taskCard(t)));
    if (items.length > LIMIT) {
      c.appendChild(el('div', 'col-more', `另有 ${items.length - LIMIT} 条`));
    }
    board.appendChild(c);
  });
}

function taskCard(t) {
  const card = el('div', 'task');
  card.appendChild(el('div', 'task-title', t.title));

  const meta = el('div', 'task-meta');
  const pr = el('span', 'prio p' + t.priority, 'P' + t.priority);
  meta.appendChild(pr);
  if (t.required_capability) {
    const origin = (t.context || {})._origin_capability;
    // 交接会把能力推进到下一步,所以可能和原始需求能力不同。
    // 显示成 analyze→review,读起来就是"这活走过哪些工序",而不是"标错了"。
    const label = origin && origin !== t.required_capability
      ? `${origin}→${t.required_capability}` : t.required_capability;
    const cap = el('span', 'cap', label);
    if (origin && origin !== t.required_capability) {
      cap.title = `原始需求能力:${origin};已随交接推进到 ${t.required_capability}`;
    }
    meta.appendChild(cap);
  }
  if (t.owner) meta.appendChild(el('span', 'task-owner', '👤 ' + t.owner));
  if (t.failure_count) meta.appendChild(el('span', null, `失败${t.failure_count}`));
  card.appendChild(meta);

  if (t.handoff_open && t.preferred_agent) {
    card.appendChild(el('div', 'handoff-flag', `🤝 指名给 ${t.preferred_agent},等待其领取`));
  }

  if (t.state === 'claimed' && t.lease_remaining !== null && t.lease_remaining !== undefined) {
    const pct = Math.max(0, Math.min(100, (t.lease_remaining / 30) * 100));
    const bar = el('div', 'lease-bar' + (t.lease_remaining < 8 ? ' low' : ''));
    const fill = el('i');
    fill.style.width = pct + '%';
    bar.appendChild(fill);
    card.appendChild(bar);
    const lv = el('div', 'task-meta');
    lv.appendChild(el('span', null, `租约剩余 ${Math.max(0, t.lease_remaining).toFixed(0)}s`));
    card.appendChild(lv);
  }

  card.addEventListener('click', () => openDrawer(t.task_id));
  return card;
}

function evTypeClass(type) {
  const k = type.replace('task.', '');
  return 't-' + k;
}

function renderEvents() {
  const box = $('events');
  box.textContent = '';
  const f = state.eventFilter;
  const list = state.events.filter((e) => {
    if (!f) return true;
    const k = (e.type || '').replace('task.', '');
    return k === f;
  }).slice(-160).reverse();

  if (!list.length) {
    box.appendChild(el('div', 'hint', '暂无事件'));
    return;
  }
  list.forEach((e) => {
    const row = el('div', 'ev');
    row.appendChild(el('div', 'ev-seq', '#' + e.seq));

    const main = el('div', 'ev-main');
    const r1 = el('div', 'ev-row');
    r1.appendChild(el('span', 'ev-type ' + evTypeClass(e.type), e.type));
    r1.appendChild(el('span', 'ev-actor', shortActor(e.actor)));
    const p = e.payload || {};
    const srv = e.server || {};
    const text = p.summary || p.message || p.reason || p.title || srv.reason || srv.note || '';
    if (text) r1.appendChild(el('span', 'ev-text', text.slice(0, 110)));
    main.appendChild(r1);

    const foot = el('div', 'ev-row');
    foot.appendChild(el('span', 'ev-hash', '#' + (e.hash || '').slice(0, 10)));
    if (e.attest_sig) foot.appendChild(el('span', 'ev-hash', '✓已签名'));
    if (e.task_id) {
      const link = el('span', 'ev-hash', e.task_id.slice(0, 14));
      link.style.cursor = 'pointer';
      link.style.color = 'var(--accent)';
      link.addEventListener('click', (ev) => { ev.stopPropagation(); openDrawer(e.task_id); });
      foot.appendChild(link);
    }
    main.appendChild(foot);

    row.appendChild(main);
    row.addEventListener('click', () => e.task_id && openDrawer(e.task_id));
    box.appendChild(row);
  });
}

function shortActor(a) {
  return (a || '').replace('agent:', '');
}

// ============================================================
// 任务详情抽屉
// ============================================================
async function openDrawer(taskId) {
  state.drawerTask = taskId;
  $('drawer').hidden = false;
  $('drawerMask').hidden = false;
  $('drawerTitle').textContent = '加载中…';
  $('drawerBody').textContent = '';
  try {
    const r = await fetch(`/api/tasks/${taskId}/timeline`);
    const d = await r.json();
    $('drawerTitle').textContent = d.task.title;
    $('drawerId').textContent = d.task.task_id;
    renderDrawer(d);
  } catch (e) {
    $('drawerTitle').textContent = '加载失败';
  }
}

function closeDrawer() {
  $('drawer').hidden = true;
  $('drawerMask').hidden = true;
  state.drawerTask = null;
}

function renderDrawer(d) {
  const t = d.task;
  const body = $('drawerBody');
  body.textContent = '';

  const dl = el('dl', 'kv');
  const add = (k, v) => { dl.appendChild(el('dt', null, k)); dl.appendChild(el('dd', null, String(v))); };
  add('状态', t.state);
  add('能力', t.required_capability || '任意');
  add('优先级', t.priority);
  add('创建者', (t.created_by || '').replace('agent:', ''));
  add('当前持有', t.owner || '—');
  add('尝试次数', t.attempt);
  if (t.failure_count) add('失败次数', t.failure_count);
  body.appendChild(dl);

  if (t.description) {
    body.appendChild(el('h4', null, '任务描述'));
    body.appendChild(el('div', 'result-box', t.description));
  }

  const h = el('h4', null, '交接与处理时间线');
  h.style.cssText = 'margin:16px 0 9px;font-size:12.5px';
  body.appendChild(h);

  const tl = el('div', 'timeline');
  d.events.forEach((e) => {
    const k = (e.type || '').replace('task.', '');
    const item = el('div', 'tl-item ' + k);
    const head = el('div', 'tl-head');
    head.appendChild(el('span', 'ev-type ' + evTypeClass(e.type), e.type));
    head.appendChild(el('span', 'ev-actor', shortActor(e.actor)));
    item.appendChild(head);

    const p = e.payload || {};
    const srv = e.server || {};
    const line = p.summary || p.message || p.reason ||
      (e.type === 'task.handed_off' ? `${srv.from} → ${srv.to}:${srv.reason}` : '') ||
      (e.type === 'task.created' ? srv.title : '');
    if (line) item.appendChild(el('div', 'tl-text', String(line).slice(0, 240)));
    item.appendChild(el('div', 'ev-hash', `seq#${e.seq} · hash ${(e.hash || '').slice(0, 14)}${e.attest_sig ? ' · 已签名' : ''}`));
    tl.appendChild(item);
  });
  body.appendChild(tl);

  if (t.result) {
    const rh = el('h4', null, '最终产出');
    rh.style.cssText = 'margin:16px 0 9px;font-size:12.5px';
    body.appendChild(rh);
    body.appendChild(el('div', 'result-box', t.result));
  }
}

// ============================================================
// 校验
// ============================================================
async function runVerify() {
  $('btnVerify').textContent = '校验中…';
  try {
    const r = await fetch('/api/verify');
    const d = await r.json();
    renderVerify(d);
    $('verifyPanel').hidden = false;
    toast(d.ok ? `链校验通过:${d.total} 条事件全部有效` : `发现 ${d.problems.length} 处异常`, d.ok ? 'ok' : 'bad');
  } catch (e) {
    toast('校验请求失败', 'bad');
  } finally {
    $('btnVerify').textContent = '校验整条链';
  }
}

function renderVerify(d) {
  const box = $('verifyBody');
  box.textContent = '';

  const line = el('div', 'vline');
  line.appendChild(el('span', 'vbadge ' + (d.ok ? 'ok' : 'bad'), d.ok ? '✅ 全部通过' : '❌ 发现异常'));
  line.appendChild(el('span', null,
    d.ok
      ? `链未被改序或删改;${d.verified}/${d.total} 条事件的哈希链与内容签名均有效。`
      : `共 ${d.problems.length} 处异常,首次出现在 seq=${d.broken_at_seq}。`));
  box.appendChild(line);

  const grid = el('div', 'vgrid');
  const cell = (k, v) => {
    const c = el('div', 'vcell');
    c.appendChild(el('div', 'k', k));
    c.appendChild(el('div', 'v', String(v)));
    return c;
  };
  grid.appendChild(cell('校验事件数', d.total));
  grid.appendChild(cell('通过', d.verified));
  grid.appendChild(cell('链头 seq', d.head_seq));
  grid.appendChild(cell('链头 hash', (d.head_hash || '').slice(0, 16)));
  box.appendChild(grid);

  (d.problems || []).forEach((p) => {
    box.appendChild(el('div', 'vprob', `seq ${p.seq} · [${p.kind}] ${p.detail}`));
  });

  box.appendChild(el('p', 'hint',
    '这一页的结论是中心自己算的。想独立验证,用命令 '
    + 'python -m agentmesh.tools.verify —— 它只读数据库文件和公钥,不连中心。'));
}

// ============================================================
// 新建任务
// ============================================================
function openTaskModal() {
  const sel = $('capSelect');
  if (!sel.options.length) {
    const caps = new Set();
    (state.snapshot?.agents || []).forEach((a) => (a.capabilities || []).forEach((c) => caps.add(c)));
    sel.appendChild(new Option('(任意能力)', ''));
    [...caps].sort().forEach((c) => sel.appendChild(new Option(c, c)));
  }
  $('taskModal').showModal();
}

async function submitTask(ev) {
  ev.preventDefault();
  const f = $('taskModal').querySelector('form');
  const title = f.title.value.trim();
  if (!title) return;
  const body = {
    title,
    description: f.description.value.trim(),
    required_capability: f.required_capability.value,
    priority: Number(f.priority.value) || 5,
  };
  try {
    const r = await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(await r.text());
    $('taskModal').close();
    f.reset();
    toast('任务已入池,谁有能力谁领', 'ok');
    refresh();
  } catch (e) {
    toast('创建失败:' + e.message, 'bad');
  }
}

// ============================================================
// 提示
// ============================================================
function toast(text, kind) {
  document.querySelectorAll('.toast').forEach((t) => t.remove());
  const n = el('div', 'toast ' + (kind || ''), text);
  document.body.appendChild(n);
  setTimeout(() => n.remove(), 4200);
}