(() => {
  'use strict';

  const mappingsPage = document.getElementById('mappingsPage');
  const connectionRows = document.getElementById('connectionRows');
  const connectionPanel = connectionRows?.closest('section.panel');
  if (!mappingsPage || !connectionPanel || document.getElementById('tokenUsagePanel')) return;

  const panel = document.createElement('section');
  panel.id = 'tokenUsagePanel';
  panel.className = 'panel';
  panel.innerHTML = `
    <div class="head">
      <h2>用户 Token 用量</h2>
      <span id="tokenUsageUpdated" class="quiet">从启用统计功能后开始累计</span>
    </div>
    <div class="body">
      <div class="notice">
        <strong>这里显示模型在响应中报告的真实 usage，不会读取或保存对话正文。</strong><br>
        过去只有流量字节，无法准确换算为 Token，因此不会伪造历史数字。通过 HTTP/HTTPS 域名入口访问且上游返回 usage 的请求可以精确统计；TCP/UDP 透明转发无法识别模型响应，会显示“未统计”。
      </div>
      <div class="token-leaderboard-head"><h3>Token 使用排行榜</h3><span class="quiet">显示全部用户 · 有真实 usage 的按总 Token 排名</span></div>
      <div id="tokenLeaderboard" class="token-leaderboard"><div class="quiet">等待足够的 usage 数据</div></div>
      <div class="topology-summary">
        <div class="topology-stat"><span>已统计输入</span><strong id="tokenInputTotal">0</strong></div>
        <div class="topology-stat"><span>已统计输出</span><strong id="tokenOutputTotal">0</strong></div>
        <div class="topology-stat"><span>已统计总量</span><strong id="tokenGrandTotal">0</strong></div>
        <div class="topology-stat"><span>Usage 报告数</span><strong id="tokenReportTotal">0</strong></div>
      </div>
      <div class="table-wrap" style="margin-top:14px">
        <table class="peer-table">
          <thead><tr><th>排名</th><th>用户</th><th>设备 IP</th><th>输入 Token</th><th>输出 Token</th><th>总 Token</th><th>缓存 Token</th><th>推理 Token</th><th>已统计请求</th><th>最近活动</th><th>统计状态</th></tr></thead>
          <tbody id="tokenUsageRows"><tr><td colspan="11">等待新的 usage 数据</td></tr></tbody>
        </table>
      </div>
    </div>`;
  connectionPanel.insertAdjacentElement('afterend', panel);

  if (!document.getElementById('tokenUsageStyles')) {
    const style = document.createElement('style');
    style.id = 'tokenUsageStyles';
    style.textContent = `.token-leaderboard-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:16px 0 9px}.token-leaderboard-head h3{font-size:13px;margin:0}.token-leaderboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:14px}.token-rank-card{position:relative;min-width:0;padding:14px 14px 13px 48px;border:1px solid var(--line);border-radius:8px;background:#fafbfb}.token-rank-card.untracked{background:#f7f8f9;color:var(--muted)}.token-rank-card.rank-1{border-color:#c9a646;background:#fffaf0}.token-rank-card.rank-2{border-color:#9aa7b2;background:#f8fafb}.token-rank-card.rank-3{border-color:#b68561;background:#fff8f3}.token-rank-number{position:absolute;left:13px;top:14px;display:grid;place-items:center;width:25px;height:25px;border-radius:50%;background:#26323a;color:#fff;font-weight:750}.token-rank-card.untracked .token-rank-number{background:#a5adb3}.token-rank-card.rank-1 .token-rank-number{background:#aa7a00}.token-rank-card.rank-2 .token-rank-number{background:#73818c}.token-rank-card.rank-3 .token-rank-number{background:#98623f}.token-rank-user{font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.token-rank-total{display:block;margin-top:5px;font-size:19px;color:var(--accent)}.token-rank-card.untracked .token-rank-total{color:var(--muted);font-size:15px}.token-rank-meta{margin-top:4px;color:var(--muted);font-size:11px}@media(max-width:760px){.token-leaderboard{grid-template-columns:1fr}.token-leaderboard-head{align-items:flex-start;flex-direction:column}}`;
    document.head.appendChild(style);
  }

  const ui = {
    rows: document.getElementById('tokenUsageRows'),
    leaderboard: document.getElementById('tokenLeaderboard'),
    updated: document.getElementById('tokenUsageUpdated'),
    input: document.getElementById('tokenInputTotal'),
    output: document.getElementById('tokenOutputTotal'),
    total: document.getElementById('tokenGrandTotal'),
    reports: document.getElementById('tokenReportTotal'),
  };

  function tokenNumber(value) {
    return Math.max(0, Number(value || 0));
  }

  function formatTokens(value) {
    return tokenNumber(value).toLocaleString(document.documentElement.lang || 'zh-CN');
  }

  function aggregateUsage(connections) {
    const users = new Map();
    for (const connection of connections || []) {
      const key = `${connection.userName || ''}|${connection.address || ''}`;
      let usage = users.get(key);
      if (!usage) {
        usage = {
          userName: connection.userName || '—', address: connection.address || '—', protocols: new Set(),
          input: 0, output: 0, total: 0, cached: 0, reasoning: 0, reports: 0, lastSeen: connection.lastSeen,
        };
        users.set(key, usage);
      }
      usage.protocols.add(String(connection.protocol || '').toLowerCase());
      usage.input += tokenNumber(connection.inputTokens);
      usage.output += tokenNumber(connection.outputTokens);
      usage.total += tokenNumber(connection.totalTokens);
      usage.cached += tokenNumber(connection.cachedTokens);
      usage.reasoning += tokenNumber(connection.reasoningTokens);
      usage.reports += tokenNumber(connection.tokenUsageReports);
      if (new Date(connection.lastSeen || 0) > new Date(usage.lastSeen || 0)) usage.lastSeen = connection.lastSeen;
    }
    return [...users.values()].sort((left, right) => right.total - left.total || left.userName.localeCompare(right.userName));
  }

  function usageStatus(usage) {
    if (usage.reports > 0) return '<span class="online">精确 · 上游 usage</span>';
    if (usage.protocols.has('http')) return '<span class="quiet">等待上游 usage</span>';
    return '<span class="offline">未统计 · 透明 TCP/UDP</span>';
  }

  function renderLeaderboard(users) {
    const allRanked = users.filter(user => user.reports > 0);
    if (!users.length) {
      ui.leaderboard.innerHTML = '<div class="quiet">暂无用户连接记录</div>';
      return new Map();
    }
    const positions = new Map();
    allRanked.forEach((user, index) => positions.set(`${user.userName}|${user.address}`, index + 1));
    ui.leaderboard.innerHTML = users.map(user => {
      const position = positions.get(`${user.userName}|${user.address}`) || 0;
      const rankClass = position > 0 && position <= 3 ? `rank-${position}` : (position ? '' : 'untracked');
      const total = position ? `${formatTokens(user.total)} Token` : '未统计';
      const meta = position
        ? `输入 ${formatTokens(user.input)} · 输出 ${formatTokens(user.output)} · ${formatTokens(user.reports)} 次请求`
        : '没有真实 usage · 不参与排名';
      return `<div class="token-rank-card ${rankClass}">
      <span class="token-rank-number">${position || '—'}</span>
      <div class="token-rank-user">${esc(user.userName)} <span class="quiet">${esc(user.address)}</span></div>
      <strong class="token-rank-total">${total}</strong>
      <div class="token-rank-meta">${meta}</div>
    </div>`;
    }).join('');
    return positions;
  }

  async function refreshTokenUsage() {
    try {
      const response = await api('/api/mappings');
      const users = aggregateUsage(response.connections || []);
      const totals = users.reduce((sum, user) => ({
        input: sum.input + user.input,
        output: sum.output + user.output,
        total: sum.total + user.total,
        reports: sum.reports + user.reports,
      }), {input: 0, output: 0, total: 0, reports: 0});
      ui.input.textContent = formatTokens(totals.input);
      ui.output.textContent = formatTokens(totals.output);
      ui.total.textContent = formatTokens(totals.total);
      ui.reports.textContent = formatTokens(totals.reports);
      const positions = renderLeaderboard(users);
      ui.rows.innerHTML = users.map(user => `<tr>
        <td>${positions.get(`${user.userName}|${user.address}`) || '—'}</td><td>${esc(user.userName)}</td><td><code>${esc(user.address)}</code></td>
        <td>${formatTokens(user.input)}</td><td>${formatTokens(user.output)}</td><td><strong>${formatTokens(user.total)}</strong></td>
        <td>${formatTokens(user.cached)}</td><td>${formatTokens(user.reasoning)}</td><td>${formatTokens(user.reports)}</td>
        <td>${when(user.lastSeen)}</td><td>${usageStatus(user)}</td>
      </tr>`).join('') || '<tr><td colspan="11">暂无用户连接记录</td></tr>';
      ui.updated.textContent = `更新于 ${new Date().toLocaleTimeString()} · 仅累计已报告 usage 的请求`;
    } catch (error) {
      ui.rows.innerHTML = `<tr><td colspan="10">${esc(error.message)}</td></tr>`;
      ui.updated.textContent = 'Token 用量读取失败';
    }
  }

  window.refreshTokenUsage = refreshTokenUsage;
  const previousShowPage = window.showPage;
  window.showPage = function(name) {
    previousShowPage(name);
    if (name === 'mappings') refreshTokenUsage();
  };
  document.addEventListener('meshlan:languagechange', () => {
    if (typeof currentPage !== 'undefined' && currentPage === 'mappings') refreshTokenUsage();
  });
  setInterval(() => {
    if (!document.hidden && typeof currentPage !== 'undefined' && currentPage === 'mappings') refreshTokenUsage();
  }, 10000);
})();
