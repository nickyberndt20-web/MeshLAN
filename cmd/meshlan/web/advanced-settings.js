(() => {
  'use strict';

  const settingsPage = document.getElementById('settingsPage');
  const routingStatus = document.getElementById('interfaceRoutingStatus');
  const routingPanel = routingStatus?.closest('section.panel');
  if (!settingsPage || !routingPanel || document.getElementById('advancedSettingsPanel')) return;

  const panel = document.createElement('section');
  panel.id = 'advancedSettingsPanel';
  panel.className = 'panel';
  panel.innerHTML = `
    <div class="head">
      <div>
        <h2>高级设置</h2>
        <span class="quiet">多网卡、代理与特殊网络环境</span>
      </div>
      <button id="advancedSettingsToggle" type="button" aria-expanded="false" onclick="toggleAdvancedSettings()">展开高级设置</button>
    </div>
    <div id="advancedSettingsContent" class="body hidden">
      <div class="notice">
        <strong>大多数用户不需要修改这里，保持“自动 / 自动”即可。</strong><br>
        此功能适用于同时连接 Wi-Fi、网线或随身 Wi-Fi，并希望 MeshLAN 与普通上网流量使用不同物理网卡的电脑。它不是按用户、服务或端口分流。
      </div>
      <div class="grid">
        <div class="panel" style="margin:0">
          <div class="head"><h2>P2P 出口网卡</h2></div>
          <div class="body">控制 MeshLAN/Nebula 的 Lighthouse、Peer 公网端点、NAT 打洞和 P2P 诊断从哪块物理网卡出站。软件会为这些目标维护专用路由，不会接管普通互联网流量。</div>
        </div>
        <div class="panel" style="margin:0">
          <div class="head"><h2>业务优先网卡</h2></div>
          <div class="body">调整 Windows 普通流量的默认网卡优先级，可能影响浏览器、API、Codex 和其他应用，不仅影响 MeshLAN 映射服务。代理或 TUN 已接管的流量仍按代理自身规则运行。</div>
        </div>
      </div>
      <div class="notice" style="margin-top:14px">
        访问映射服务时，对方到你电脑的连接走 MeshLAN；该本地服务随后访问互联网时，继续遵循 Windows 默认路由和自己的代理设置。错误选择可能造成普通上网异常，指定网卡不可用时软件会尝试回退到其他物理网卡。
      </div>
      <div id="advancedRoutingMount"></div>
    </div>`;

  settingsPage.appendChild(panel);
  const mount = panel.querySelector('#advancedRoutingMount');
  const routingTitle = routingPanel.querySelector('.head h2');
  const routingHint = routingPanel.querySelector('.head .quiet');
  if (routingTitle) routingTitle.textContent = '多网卡流量分流';
  if (routingHint) routingHint.textContent = '修改后 Nebula 会短暂重启，现有连接将自动恢复';
  routingPanel.style.marginTop = '14px';
  routingPanel.style.marginBottom = '0';
  mount.appendChild(routingPanel);

  const actions = routingPanel.querySelector('.actions');
  if (actions && !document.getElementById('resetInterfaceRoutingButton')) {
    const reset = document.createElement('button');
    reset.id = 'resetInterfaceRoutingButton';
    reset.type = 'button';
    reset.textContent = '恢复自动选择';
    reset.onclick = () => window.resetInterfaceRouting();
    actions.appendChild(reset);
  }

  window.toggleAdvancedSettings = force => {
    const content = document.getElementById('advancedSettingsContent');
    const button = document.getElementById('advancedSettingsToggle');
    if (!content || !button) return;
    const open = typeof force === 'boolean' ? force : content.classList.contains('hidden');
    content.classList.toggle('hidden', !open);
    button.setAttribute('aria-expanded', String(open));
    button.textContent = open ? '收起高级设置' : '展开高级设置';
  };

  window.resetInterfaceRouting = async () => {
    const confirmed = await showConfirm({
      title: '恢复自动选择',
      message: 'P2P 出口和业务出口都会恢复为自动选择。Nebula 会短暂重启，普通网络将恢复由 Windows 自行选择。',
      confirmText: '恢复并重启',
    });
    if (!confirmed) return;
    const button = document.getElementById('resetInterfaceRoutingButton');
    setButtonLoading(button, '正在恢复...');
    try {
      const result = await api('/api/settings/interfaces', {
        method: 'POST',
        body: JSON.stringify({p2p: 'auto', business: 'auto'}),
      });
      ui.p2pInterface.value = result.p2p;
      ui.businessInterface.value = result.business;
      ui.interfaceRoutingStatus.textContent = '已恢复：P2P=auto，业务=auto';
      showToast('流量分流已恢复自动选择', 'success');
      setTimeout(refresh, 1800);
    } catch (error) {
      showToast('恢复失败：' + error.message, 'error');
    } finally {
      unsetButtonLoading(button);
    }
  };
})();
