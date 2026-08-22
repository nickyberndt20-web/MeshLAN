(() => {
  'use strict';

  const STORAGE_KEY = 'meshlan.interfaceLanguage';
  const SUPPORTED = new Set(['zh-CN', 'zh-TW', 'en', 'ja']);
  const LANGUAGE_NAMES = {
    'zh-CN': '简体中文',
    'zh-TW': '繁體中文',
    en: 'English',
    ja: '日本語',
  };

  // Source text is Simplified Chinese. Longer phrases are intentionally kept
  // alongside common terms so dynamically rendered status text is translated too.
  const rows = [
    ['界面语言', '介面語言', 'Interface language', '表示言語'],
    ['立即生效并保存在本机', '立即生效並儲存在本機', 'Applied immediately and saved on this device', 'すぐに適用し、この端末に保存します'],
    ['显示语言', '顯示語言', 'Display language', '表示言語'],
    ['设备接入', '裝置接入', 'Device setup', 'デバイス接続'],
    ['在线设备', '線上裝置', 'Online devices', 'オンライン端末'],
    ['发现节点', '探索節點', 'Discovery nodes', '探索ノード'],
    ['链路质量', '鏈路品質', 'Link quality', 'リンク品質'],
    ['网络拓扑', '網路拓撲', 'Network topology', 'ネットワークトポロジー'],
    ['P2P 诊断', 'P2P 診斷', 'P2P diagnostics', 'P2P 診断'],
    ['历史与回放', '歷史與回放', 'History and replay', '履歴とリプレイ'],
    ['服务映射', '服務映射', 'Service mapping', 'サービスマッピング'],
    ['全网共享服务', '全網共享服務', 'Shared services', '共有サービス'],
    ['文件直传', '檔案直傳', 'Direct file transfer', 'ファイル直接転送'],
    ['消息列表', '訊息清單', 'Messages', 'メッセージ'],
    ['消息', '訊息', 'Messages', 'メッセージ'],
    ['AI控制', 'AI控制', 'AI assistant', 'AI アシスタント'],
    ['MeshLAN AI控制', 'MeshLAN AI控制', 'MeshLAN AI assistant', 'MeshLAN AI アシスタント'],
    ['AI助手', 'AI助手', 'AI assistant', 'AI アシスタント'],
    ['MeshLAN AI助手', 'MeshLAN AI助手', 'MeshLAN AI assistant', 'MeshLAN AI アシスタント'],
    ['＋ 新建对话', '＋ 新增對話', '＋ New conversation', '＋ 新しい会話'],
    ['新建对话', '新增對話', 'New conversation', '新しい会話'],
    ['新对话', '新對話', 'New conversation', '新しい会話'],
    ['正在连接 AI 服务', '正在連線 AI 服務', 'Connecting to AI service', 'AI サービスに接続中'],
    ['本地历史 · 端到端加密', '本機歷史 · 端對端加密', 'Local history · end-to-end encrypted', 'ローカル履歴 · エンドツーエンド暗号化'],
    ['重命名', '重新命名', 'Rename', '名前を変更'],
    ['直接说出你想做什么，或描述遇到的问题…', '直接說出你想做什麼，或描述遇到的問題…', 'Tell the assistant what you want to do or describe the problem…', '実行したいこと、または発生している問題を入力…'],
    ['发送', '傳送', 'Send', '送信'],
    ['Enter 发送 · Shift + Enter 换行', 'Enter 傳送 · Shift + Enter 換行', 'Enter to send · Shift + Enter for a new line', 'Enter で送信 · Shift + Enter で改行'],
    ['修改操作仍需你确认', '修改操作仍需你確認', 'Changes still require your confirmation', '変更操作には引き続き確認が必要です'],
    ['可以连续对话，也可以让助手分析网络、创建映射或处理故障。', '可以連續對話，也可以讓助手分析網路、建立映射或處理故障。', 'Continue the conversation or ask the assistant to analyze the network, create mappings, or troubleshoot problems.', '会話を続けたり、ネットワーク分析、マッピング作成、障害対応を依頼できます。'],
    ['涉及修改时，会先展示操作计划并等待你的明确授权。', '涉及修改時，會先顯示操作計畫並等待你的明確授權。', 'Before making changes, it shows an action plan and waits for your explicit approval.', '変更が必要な場合は操作計画を表示し、明示的な承認を待ちます。'],
    ['AI服务在线', 'AI服務線上', 'AI service online', 'AI サービスはオンラインです'],
    ['AI服务未启用', 'AI服務未啟用', 'AI service disabled', 'AI サービスは無効です'],
    ['AI服务连接失败', 'AI服務連線失敗', 'AI service connection failed', 'AI サービスへの接続に失敗'],
    ['端到端加密', '端對端加密', 'end-to-end encrypted', 'エンドツーエンド暗号化'],
    ['本地历史', '本機歷史', 'local history', 'ローカル履歴'],
    ['等待加密密钥', '等待加密金鑰', 'waiting for encryption key', '暗号鍵を待機中'],
    ['会话读取失败', '對話讀取失敗', 'Failed to load conversations', '会話の読み込みに失敗'],
    ['暂无历史会话', '暫無歷史對話', 'No conversation history', '会話履歴はありません'],
    ['请等待当前回复完成', '請等待目前回覆完成', 'Wait for the current reply to finish', '現在の応答が完了するまでお待ちください'],
    ['条消息 · 仅保存在本机', '則訊息 · 僅儲存在本機', 'messages · stored only on this device', '件のメッセージ · この端末のみに保存'],
    ['请求错误', '請求錯誤', 'Request error', 'リクエストエラー'],
    ['执行记录', '執行記錄', 'Execution record', '実行記録'],
    ['你', '你', 'You', 'あなた'],
    ['高风险', '高風險', 'High risk', '高リスク'],
    ['中风险', '中風險', 'Medium risk', '中リスク'],
    ['低风险', '低風險', 'Low risk', '低リスク'],
    ['操作计划', '操作計畫', 'Action plan', '操作計画'],
    ['可撤销', '可撤銷', 'Reversible', '取り消し可能'],
    ['可能不可撤销', '可能不可撤銷', 'May be irreversible', '取り消せない可能性があります'],
    ['确认并执行', '確認並執行', 'Confirm and execute', '確認して実行'],
    ['上报未解决问题', '回報未解決問題', 'Report unresolved issue', '未解決の問題を報告'],
    ['实时工作过程', '即時工作過程', 'Live work progress', 'リアルタイム処理状況'],
    ['正在处理', '正在處理', 'Processing', '処理中'],
    ['处理中', '處理中', 'Processing', '処理中'],
    ['处理完成', '處理完成', 'Completed', '処理完了'],
    ['处理失败', '處理失敗', 'Failed', '処理失敗'],
    ['AI请求失败', 'AI請求失敗', 'AI request failed', 'AI リクエスト失敗'],
    ['AI回复完成', 'AI回覆完成', 'AI reply complete', 'AI の応答が完了しました'],
    ['确认高风险操作', '確認高風險操作', 'Confirm high-risk actions', '高リスク操作を確認'],
    ['确认执行操作计划', '確認執行操作計畫', 'Confirm action plan', '操作計画を確認'],
    ['确认并执行全部操作', '確認並執行全部操作', 'Confirm and execute all actions', '確認してすべて実行'],
    ['正在执行并复核...', '正在執行並複核...', 'Executing and verifying...', '実行して検証中...'],
    ['执行失败', '執行失敗', 'Execution failed', '実行失敗'],
    ['上报加密问题报告', '回報加密問題報告', 'Submit encrypted issue report', '暗号化された問題レポートを送信'],
    ['同意上报', '同意回報', 'Agree and submit', '同意して送信'],
    ['正在上报...', '正在回報...', 'Submitting...', '送信中...'],
    ['上报失败', '回報失敗', 'Submission failed', '送信失敗'],
    ['重命名会话', '重新命名對話', 'Rename conversation', '会話名を変更'],
    ['会话名称', '對話名稱', 'Conversation name', '会話名'],
    ['会话已重命名', '對話已重新命名', 'Conversation renamed', '会話名を変更しました'],
    ['删除会话', '刪除對話', 'Delete conversation', '会話を削除'],
    ['本地会话已删除', '本機對話已刪除', 'Local conversation deleted', 'ローカル会話を削除しました'],
    ['模型正在处理', '模型正在處理', 'Model is processing', 'モデルが処理中'],
    ['连接保持正常', '連線保持正常', 'connection is healthy', '接続は正常です'],
    ['保存本地上下文', '儲存本機上下文', 'Save local context', 'ローカルコンテキストを保存'],
    ['用户消息已写入当前设备的本地历史库。', '使用者訊息已寫入目前裝置的本機歷史庫。', 'The user message was saved to local history on this device.', 'ユーザーメッセージをこの端末のローカル履歴に保存しました。'],
    ['设置', '設定', 'Settings', '設定'],
    ['Nebula 自动配对', 'Nebula 自動配對', 'Nebula automatic enrollment', 'Nebula 自動登録'],
    ['正在读取版本...', '正在讀取版本...', 'Reading version...', 'バージョンを読み込み中...'],
    ['正在连接本机服务', '正在連線本機服務', 'Connecting to local service', 'ローカルサービスに接続中'],
    ['实时同步', '即時同步', 'Live sync', 'リアルタイム同期'],
    ['同步失败 · 点击重试', '同步失敗 · 點擊重試', 'Sync failed · click to retry', '同期失敗 · クリックして再試行'],
    ['页面数据已刷新', '頁面資料已重新整理', 'Page data refreshed', 'ページを更新しました'],
    ['刷新中...', '重新整理中...', 'Refreshing...', '更新中...'],
    ['刷新失败', '重新整理失敗', 'Refresh failed', '更新失敗'],
    ['刷新', '重新整理', 'Refresh', '更新'],
    ['默认强制 P2P，并只走物理网卡。', '預設強制 P2P，且僅走實體網卡。', 'P2P is enforced by default and uses only physical adapters.', '既定で P2P を強制し、物理アダプターのみを使用します。'],
    ['设备名称', '裝置名稱', 'Device name', '端末名'],
    ['服务器地址', '伺服器位址', 'Server address', 'サーバーアドレス'],
    ['配对哈希', '配對雜湊', 'Enrollment hash', '登録ハッシュ'],
    ['哈希', '雜湊', 'hash', 'ハッシュ'],
    ['验证、领证并启动', '驗證、領證並啟動', 'Verify, enroll, and start', '検証・登録して起動'],
    ['已完成配对', '已完成配對', 'Enrollment complete', '登録済み'],
    ['后续启动不需要配对哈希', '後續啟動不需要配對雜湊', 'The enrollment hash is no longer required', '次回以降、登録ハッシュは不要です'],
    ['重新配对或更换网络', '重新配對或更換網路', 'Re-enroll or change network', '再登録またはネットワーク変更'],
    ['设备状态', '裝置狀態', 'Device status', '端末状態'],
    ['Nebula 地址', 'Nebula 位址', 'Nebula address', 'Nebula アドレス'],
    ['当前路径', '目前路徑', 'Current path', '現在の経路'],
    ['打洞端口', '打洞連接埠', 'Punching port', 'ホールパンチポート'],
    ['路由器映射', '路由器映射', 'Router mapping', 'ルーターマッピング'],
    ['TUN 直连锁', 'TUN 直連鎖', 'TUN direct-path lock', 'TUN 直結ロック'],
    ['物理出口', '實體出口', 'Physical egress', '物理出口'],
    ['直连优化', '直連最佳化', 'Direct-path optimization', '直接接続の最適化'],
    ['启动服务', '啟動服務', 'Start service', 'サービスを起動'],
    ['停止服务', '停止服務', 'Stop service', 'サービスを停止'],
    ['安装物理直连锁并重启', '安裝實體直連鎖並重新啟動', 'Install direct-path lock and restart', '直結ロックを導入して再起動'],
    ['强制 P2P 诊断', '強制 P2P 診斷', 'Force P2P diagnostics', 'P2P 強制診断'],
    ['恢复 Relay 兜底', '恢復 Relay 備援', 'Restore Relay fallback', 'Relay フォールバックを復元'],
    ['服务已启动', '服務已啟動', 'Service started', 'サービスを起動しました'],
    ['服务已停止', '服務已停止', 'Service stopped', 'サービスを停止しました'],
    ['正在启动...', '正在啟動...', 'Starting...', '起動中...'],
    ['正在停止...', '正在停止...', 'Stopping...', '停止中...'],
    ['Lighthouse 发现节点', 'Lighthouse 探索節點', 'Lighthouse discovery nodes', 'Lighthouse 探索ノード'],
    ['已配置节点', '已設定節點', 'Configured nodes', '設定済みノード'],
    ['当前可达', '目前可達', 'Currently reachable', '現在到達可能'],
    ['主节点', '主節點', 'Primary node', 'プライマリノード'],
    ['最近同步', '最近同步', 'Last sync', '最終同期'],
    ['立即同步', '立即同步', 'Sync now', '今すぐ同期'],
    ['节点明细', '節點明細', 'Node details', 'ノード詳細'],
    ['节点', '節點', 'Node', 'ノード'],
    ['角色', '角色', 'Role', 'ロール'],
    ['虚拟 IP', '虛擬 IP', 'Virtual IP', '仮想 IP'],
    ['公网端点', '公網端點', 'Public endpoint', '公開エンドポイント'],
    ['实时网络拓扑', '即時網路拓撲', 'Live network topology', 'リアルタイムトポロジー'],
    ['等待首个快照', '等待第一個快照', 'Waiting for the first snapshot', '最初のスナップショットを待機中'],
    ['本机模式', '本機模式', 'Local mode', 'ローカルモード'],
    ['Peer 可达', 'Peer 可達', 'Reachable peers', '到達可能 Peer'],
    ['端口映射服务', '連接埠映射服務', 'Mapped services', 'マッピングサービス'],
    ['实时传输', '即時傳輸', 'Live transfer', 'リアルタイム転送'],
    ['P2P / 业务出口', 'P2P / 業務出口', 'P2P / application egress', 'P2P / アプリ出口'],
    ['放大', '放大', 'Zoom in', '拡大'],
    ['缩小', '縮小', 'Zoom out', '縮小'],
    ['复位', '重設', 'Reset', 'リセット'],
    ['适应画布', '適應畫布', 'Fit canvas', '全体表示'],
    ['滚轮缩放 · 按住空白区域拖动画布 · 点击节点查看详情', '滾輪縮放 · 按住空白區域拖動畫布 · 點擊節點查看詳情', 'Wheel to zoom · drag empty space · click a node for details', 'ホイールで拡大縮小 · 空白をドラッグ · ノードをクリックして詳細表示'],
    ['P2P 直连', 'P2P 直連', 'P2P direct', 'P2P 直接接続'],
    ['Relay 中继', 'Relay 中繼', 'Relay', 'Relay 中継'],
    ['隧道不可达', '隧道不可達', 'Tunnel unreachable', 'トンネル到達不能'],
    ['实时发送', '即時傳送', 'Live sent', 'リアルタイム送信'],
    ['实时接收', '即時接收', 'Live received', 'リアルタイム受信'],
    ['选中节点详情', '所選節點詳情', 'Selected node details', '選択ノードの詳細'],
    ['出口与安全策略', '出口與安全策略', 'Egress and security policy', '出口とセキュリティポリシー'],
    ['实时数据传输', '即時資料傳輸', 'Live data transfer', 'リアルタイムデータ転送'],
    ['点击设备或服务节点查看', '點擊裝置或服務節點查看', 'Click a device or service node', '端末またはサービスノードをクリック'],
    ['设备链路明细', '裝置鏈路明細', 'Device link details', '端末リンク詳細'],
    ['端口映射服务明细', '連接埠映射服務明細', 'Mapped service details', 'マッピングサービス詳細'],
    ['真实 UDP 出口诊断，不修改网络。', '真實 UDP 出口診斷，不修改網路。', 'Real UDP egress diagnostics without changing the network.', 'ネットワークを変更せずに実際の UDP 出口を診断します。'],
    ['P2P 打洞向导', 'P2P 打洞精靈', 'P2P hole-punching wizard', 'P2P ホールパンチウィザード'],
    ['通常需要 5-15 秒', '通常需要 5-15 秒', 'Usually takes 5–15 seconds', '通常 5～15 秒かかります'],
    ['开始完整检测', '開始完整檢測', 'Run full diagnostics', '完全診断を開始'],
    ['导出脱敏故障报告', '匯出去識別故障報告', 'Export redacted diagnostic report', 'マスク済み診断レポートを出力'],
    ['尚未运行', '尚未執行', 'Not run yet', '未実行'],
    ['出口与现有路径', '出口與現有路徑', 'Egress and current paths', '出口と現在の経路'],
    ['物理网卡', '實體網卡', 'Physical adapter', '物理アダプター'],
    ['TUN/代理网卡', 'TUN/代理網卡', 'TUN/proxy adapter', 'TUN／プロキシアダプター'],
    ['当前 P2P / Relay', '目前 P2P / Relay', 'Current P2P / Relay', '現在の P2P / Relay'],
    ['STUN 探测明细', 'STUN 探測明細', 'STUN probe details', 'STUN プローブ詳細'],
    ['地址族', '位址族', 'Address family', 'アドレスファミリー'],
    ['服务器', '伺服器', 'Server', 'サーバー'],
    ['目标', '目標', 'Target', 'ターゲット'],
    ['公网映射', '公網映射', 'Public mapping', '公開マッピング'],
    ['错误', '錯誤', 'Error', 'エラー'],
    ['针对性建议', '針對性建議', 'Recommendations', '推奨事項'],
    ['先运行完整检测', '先執行完整檢測', 'Run full diagnostics first', '最初に完全診断を実行してください'],
    ['历史与拓扑回放', '歷史與拓撲回放', 'History and topology replay', '履歴とトポロジーリプレイ'],
    ['SQLite 本地保留 30 天', 'SQLite 本機保留 30 天', 'Stored locally in SQLite for 30 days', 'SQLite にローカルで 30 日保存'],
    ['刷新历史', '重新整理歷史', 'Refresh history', '履歴を更新'],
    ['时间范围', '時間範圍', 'Time range', '期間'],
    ['拓扑时间回放', '拓撲時間回放', 'Topology timeline replay', 'トポロジー時間リプレイ'],
    ['暂无历史快照', '暫無歷史快照', 'No history snapshots', '履歴スナップショットはありません'],
    ['新增服务映射', '新增服務映射', 'Create service mapping', 'サービスマッピングを作成'],
    ['每个服务前缀在本设备下必须唯一', '每個服務前綴在本裝置下必須唯一', 'Each service prefix must be unique on this device', 'サービスプレフィックスは端末内で一意にしてください'],
    ['服务名称', '服務名稱', 'Service name', 'サービス名'],
    ['服务域名前缀', '服務網域前綴', 'Service DNS prefix', 'サービス DNS プレフィックス'],
    ['协议', '協定', 'Protocol', 'プロトコル'],
    ['域名访问方式', '網域存取方式', 'Domain access mode', 'ドメインアクセス方式'],
    ['普通域名，需要端口', '一般網域，需要連接埠', 'Standard domain, port required', '通常ドメイン（ポート必須）'],
    ['HTTP域名网关，无需端口', 'HTTP網域閘道，無需連接埠', 'HTTP domain gateway, no port required', 'HTTP ドメインゲートウェイ（ポート不要）'],
    ['本地地址', '本機位址', 'Local host', 'ローカルホスト'],
    ['本地端口', '本機連接埠', 'Local port', 'ローカルポート'],
    ['局域网端口（可选）', '區域網路連接埠（選填）', 'Mesh port (optional)', 'Mesh ポート（任意）'],
    ['留空自动分配 20000-29999', '留空自動分配 20000-29999', 'Leave blank to assign 20000–29999', '空欄で 20000～29999 を自動割当'],
    ['访问模式', '存取模式', 'Access mode', 'アクセスモード'],
    ['无需批准，直接连接', '無需批准，直接連線', 'No approval, connect directly', '承認不要、直接接続'],
    ['需要创建者手动批准', '需要建立者手動批准', 'Owner approval required', '作成者の承認が必要'],
    ['创建映射', '建立映射', 'Create mapping', 'マッピングを作成'],
    ['域名会按个人前缀实时生成', '網域會按個人前綴即時產生', 'The domain is generated from your prefix in real time', '個人プレフィックスからドメインをリアルタイム生成'],
    ['我的映射', '我的映射', 'My mappings', '自分のマッピング'],
    ['连接用户', '連線使用者', 'Connected users', '接続ユーザー'],
    ['用户访问控制', '使用者存取控制', 'User access control', 'ユーザーアクセス制御'],
    ['所有用户可见，只读目录', '所有使用者可見，唯讀目錄', 'Visible to all members, read-only directory', '全メンバーが閲覧可能な読み取り専用一覧'],
    ['用户', '使用者', 'User', 'ユーザー'],
    ['访问地址', '存取位址', 'Access address', 'アクセス先'],
    ['我的权限', '我的權限', 'My permission', '自分の権限'],
    ['最后检查', '最後檢查', 'Last check', '最終確認'],
    ['文件内容只在设备之间通过 Nebula 加密隧道直传。', '檔案內容僅在裝置之間透過 Nebula 加密隧道直傳。', 'File contents are transferred directly through the Nebula encrypted tunnel.', 'ファイル本体は Nebula 暗号化トンネルで端末間を直接転送します。'],
    ['创建临时分享', '建立臨時分享', 'Create temporary share', '一時共有を作成'],
    ['选择文件', '選擇檔案', 'Choose file', 'ファイルを選択'],
    ['接收设备', '接收裝置', 'Recipient device', '受信端末'],
    ['所有在线设备', '所有線上裝置', 'All online devices', 'すべてのオンライン端末'],
    ['有效期', '有效期限', 'Expires', '有効期限'],
    ['最多接收次数', '最多接收次數', 'Maximum downloads', '最大受信回数'],
    ['创建并发布', '建立並發布', 'Create and publish', '作成して公開'],
    ['我创建的分享', '我建立的分享', 'My shares', '自分の共有'],
    ['收到的文件', '收到的檔案', 'Received files', '受信ファイル'],
    ['接收文件', '接收檔案', 'Receive file', 'ファイルを受信'],
    ['撤销', '撤銷', 'Revoke', '取り消す'],
    ['发送者', '傳送者', 'Sender', '送信者'],
    ['剩余次数', '剩餘次數', 'Remaining downloads', '残り回数'],
    ['访问申请与审批结果', '存取申請與審批結果', 'Access requests and decisions', 'アクセス申請と承認結果'],
    ['申请用户/创建者', '申請使用者/建立者', 'Requester / owner', '申請者／作成者'],
    ['我的个人域名前缀', '我的個人網域前綴', 'My personal domain prefix', '個人ドメインプレフィックス'],
    ['个人前缀', '個人前綴', 'Personal prefix', '個人プレフィックス'],
    ['最终域名', '最終網域', 'Final domain', '最終ドメイン'],
    ['保存并实时同步', '儲存並即時同步', 'Save and sync', '保存して同期'],
    ['MeshDNS 状态', 'MeshDNS 狀態', 'MeshDNS status', 'MeshDNS 状態'],
    ['功能状态', '功能狀態', 'Feature status', '機能状態'],
    ['已应用记录', '已套用記錄', 'Applied records', '適用済みレコード'],
    ['最后同步', '最後同步', 'Last sync', '最終同期'],
    ['启用 MeshDNS', '啟用 MeshDNS', 'Enable MeshDNS', 'MeshDNS を有効化'],
    ['实时名称目录', '即時名稱目錄', 'Live name directory', 'リアルタイム名前一覧'],
    ['MeshDNS 名称', 'MeshDNS 名稱', 'MeshDNS name', 'MeshDNS 名'],
    ['归属设备', '所屬裝置', 'Owner device', '所有端末'],
    ['服务入口', '服務入口', 'Service endpoint', 'サービス入口'],
    ['Peer 数据协议', 'Peer 資料協定', 'Peer network protocol', 'Peer 通信プロトコル'],
    ['三个模式只能启用一个', '三個模式只能啟用一個', 'Only one mode can be active', '同時に選べるモードは一つです'],
    ['仅 IPv4', '僅 IPv4', 'IPv4 only', 'IPv4 のみ'],
    ['仅 IPv6', '僅 IPv6', 'IPv6 only', 'IPv6 のみ'],
    ['智能双栈与网络场景', '智慧雙棧與網路場景', 'Smart dual stack and network profiles', 'スマートデュアルスタックとネットワークプロファイル'],
    ['仅在 IPv4 + IPv6 模式下可用', '僅在 IPv4 + IPv6 模式下可用', 'Available only in IPv4 + IPv6 mode', 'IPv4 + IPv6 モードでのみ利用可能'],
    ['智能双栈竞速', '智慧雙棧競速', 'Smart dual-stack racing', 'スマートデュアルスタック競合'],
    ['网络场景切换', '網路場景切換', 'Network profile switching', 'ネットワークプロファイル切替'],
    ['当前场景', '目前場景', 'Current profile', '現在のプロファイル'],
    ['当前胜出路径', '目前勝出路徑', 'Current winning path', '現在の優先経路'],
    ['最近竞速', '最近競速', 'Last race', '最終競合'],
    ['流量分流', '流量分流', 'Traffic routing', 'トラフィック経路'],
    ['P2P出口网卡', 'P2P出口網卡', 'P2P egress adapter', 'P2P 出口アダプター'],
    ['业务优先网卡', '業務優先網卡', 'Application-preferred adapter', 'アプリ優先アダプター'],
    ['应用分流并重启', '套用分流並重新啟動', 'Apply routing and restart', '経路を適用して再起動'],
    ['身份与证书安全', '身分與憑證安全', 'Identity and certificate security', 'ID と証明書のセキュリティ'],
    ['证书状态', '憑證狀態', 'Certificate status', '証明書状態'],
    ['证书指纹', '憑證指紋', 'Certificate fingerprint', '証明書フィンガープリント'],
    ['吊销列表', '撤銷清單', 'Revocation list', '失効リスト'],
    ['安全修复身份', '安全修復身分', 'Secure identity repair', '安全な ID 修復'],
    ['安全更新与回滚', '安全更新與回復', 'Secure updates and rollback', '安全な更新とロールバック'],
    ['当前版本', '目前版本', 'Current version', '現在のバージョン'],
    ['服务器版本', '伺服器版本', 'Server version', 'サーバーバージョン'],
    ['更新验证', '更新驗證', 'Update verification', '更新の検証'],
    ['自动更新', '自動更新', 'Automatic updates', '自動更新'],
    ['每 6 小时检查并静默安装', '每 6 小時檢查並靜默安裝', 'Check every 6 hours and install silently', '6 時間ごとに確認して自動インストール'],
    ['检查更新', '檢查更新', 'Check for updates', '更新を確認'],
    ['安装并自动重启', '安裝並自動重新啟動', 'Install and restart', 'インストールして再起動'],
    ['回滚上一版本', '回復上一版本', 'Roll back previous version', '前のバージョンへ戻す'],
    ['代理兼容', '代理相容', 'Proxy compatibility', 'プロキシ互換性'],
    ['无需修改 Clash 规则', '無需修改 Clash 規則', 'No Clash rule changes required', 'Clash ルールの変更不要'],
    ['HTTPS 根证书', 'HTTPS 根憑證', 'HTTPS root certificate', 'HTTPS ルート証明書'],
    ['安装证书', '安裝憑證', 'Install certificate', '証明書をインストール'],
    ['卸载证书', '解除安裝憑證', 'Uninstall certificate', '証明書を削除'],
    ['取消', '取消', 'Cancel', 'キャンセル'],
    ['确认', '確認', 'Confirm', '確認'],
    ['我知道了', '我知道了', 'Got it', '了解'],
    ['关闭', '關閉', 'Close', '閉じる'],
    ['删除', '刪除', 'Delete', '削除'],
    ['暂停', '暫停', 'Pause', '一時停止'],
    ['重新启动', '重新啟動', 'Restart', '再起動'],
    ['允许', '允許', 'Allow', '許可'],
    ['拒绝', '拒絕', 'Reject', '拒否'],
    ['复制', '複製', 'Copy', 'コピー'],
    ['详情', '詳情', 'Details', '詳細'],
    ['操作', '操作', 'Actions', '操作'],
    ['设备', '裝置', 'Device', '端末'],
    ['服务', '服務', 'Service', 'サービス'],
    ['状态', '狀態', 'Status', '状態'],
    ['类型', '類型', 'Type', '種類'],
    ['地址', '位址', 'Address', 'アドレス'],
    ['路径', '路徑', 'Path', '経路'],
    ['延迟', '延遲', 'Latency', '遅延'],
    ['抖动', '抖動', 'Jitter', 'ジッター'],
    ['丢包', '封包遺失', 'Packet loss', 'パケットロス'],
    ['版本', '版本', 'Version', 'バージョン'],
    ['结果', '結果', 'Result', '結果'],
    ['时间', '時間', 'Time', '時刻'],
    ['大小', '大小', 'Size', 'サイズ'],
    ['健康', '健康', 'Health', 'ヘルス'],
    ['在线', '線上', 'Online', 'オンライン'],
    ['离线', '離線', 'Offline', 'オフライン'],
    ['运行中', '執行中', 'Running', '実行中'],
    ['已停止', '已停止', 'Stopped', '停止'],
    ['已暂停', '已暫停', 'Paused', '一時停止中'],
    ['可达', '可達', 'Reachable', '到達可能'],
    ['不可达', '不可達', 'Unreachable', '到達不能'],
    ['直连', '直連', 'Direct', '直接接続'],
    ['中继', '中繼', 'Relay', '中継'],
    ['异常', '異常', 'Unhealthy', '異常'],
    ['正常', '正常', 'Healthy', '正常'],
    ['等待检测', '等待檢測', 'Waiting for check', '確認待ち'],
    ['等待检查', '等待檢查', 'Waiting for check', '確認待ち'],
    ['等待同步', '等待同步', 'Waiting for sync', '同期待ち'],
    ['等待识别', '等待識別', 'Waiting for detection', '検出待ち'],
    ['等待建链', '等待建鏈', 'Waiting for link', 'リンク待ち'],
    ['等待刷新', '等待重新整理', 'Waiting for refresh', '更新待ち'],
    ['正在加载...', '正在載入...', 'Loading...', '読み込み中...'],
    ['正在安装...', '正在安裝...', 'Installing...', 'インストール中...'],
    ['正在同步...', '正在同步...', 'Syncing...', '同期中...'],
    ['正在切换...', '正在切換...', 'Switching...', '切替中...'],
    ['正在应用...', '正在套用...', 'Applying...', '適用中...'],
    ['正在检查...', '正在檢查...', 'Checking...', '確認中...'],
    ['已启用', '已啟用', 'Enabled', '有効'],
    ['已关闭', '已關閉', 'Disabled', '無効'],
    ['已安装', '已安裝', 'Installed', 'インストール済み'],
    ['未安装', '未安裝', 'Not installed', '未インストール'],
    ['尚未安装', '尚未安裝', 'Not installed', '未インストール'],
    ['已允许', '已允許', 'Allowed', '許可済み'],
    ['已拒绝', '已拒絕', 'Rejected', '拒否済み'],
    ['已是最新', '已是最新', 'Up to date', '最新版'],
    ['可更新', '可更新', 'Update available', '更新あり'],
    ['暂无记录', '暫無記錄', 'No records', '記録なし'],
    ['暂无消息', '暫無訊息', 'No messages', 'メッセージなし'],
    ['暂无分享', '暫無分享', 'No shares', '共有なし'],
    ['暂无连接记录', '暫無連線記錄', 'No connection records', '接続履歴なし'],
    ['暂无其他用户', '暫無其他使用者', 'No other users', '他のユーザーはいません'],
    ['暂无可接收文件', '暫無可接收檔案', 'No files available', '受信可能なファイルなし'],
    ['暂无已配对设备', '暫無已配對裝置', 'No enrolled devices', '登録済み端末なし'],
    ['尚未触发', '尚未觸發', 'Not triggered', '未実行'],
    ['尚未应用', '尚未套用', 'Not applied', '未適用'],
    ['尚未发布更新', '尚未發布更新', 'No update published', '更新は公開されていません'],
    ['未就绪', '未就緒', 'Not ready', '未準備'],
    ['不可用', '不可用', 'Unavailable', '利用不可'],
    ['检测失败', '檢測失敗', 'Check failed', '確認失敗'],
    ['设置失败', '設定失敗', 'Setting failed', '設定失敗'],
    ['创建失败', '建立失敗', 'Creation failed', '作成失敗'],
    ['修改失败', '修改失敗', 'Update failed', '変更失敗'],
    ['安装失败', '安裝失敗', 'Installation failed', 'インストール失敗'],
    ['更新于', '更新於', 'Updated at', '更新時刻'],
    ['本机', '本機', 'This device', 'この端末'],
    ['当前', '目前', 'Current', '現在'],
    ['小时', '小時', 'hours', '時間'],
    ['天', '天', 'days', '日'],
  ];

  const index = Object.create(null);
  const targetIndex = { 'zh-TW': 1, en: 2, ja: 3 };
  for (const row of rows) index[row[0]] = row;
  const sortedRows = [...rows].sort((a, b) => b[0].length - a[0].length);

  // Fallback conversion covers uncommon Simplified-Chinese status strings.
  const traditionalCharacters = {
    '网':'網','络':'絡','设':'設','备':'備','务':'務','实':'實','时':'時','历':'歷','发':'發','现':'現','节':'節','点':'點','链':'鏈','质':'質','诊':'診','断':'斷','录':'錄','区':'區','个':'個','户':'戶','员':'員','权':'權','开':'開','关':'關','闭':'閉','启':'啟','动':'動','暂':'暫','删':'刪','显':'顯','储':'儲','当':'當','态':'態','应':'應','该':'該','执':'執','间':'間','过':'過','载':'載','输':'輸','传':'傳','证':'證','书':'書','签':'簽','验':'驗','码':'碼','钥':'鑰','获':'獲','择':'擇','优':'優','径':'徑','标':'標','识':'識','败':'敗','误':'誤','试':'試','检':'檢','测':'測','丢':'丟','报':'報','导':'導','统':'統','计':'計','图':'圖','缩':'縮','复':'複','详':'詳','览':'覽','创':'創','称':'稱','议':'議','访':'訪','问':'問','达':'達','线':'線','离':'離','绑':'綁','写':'寫','读':'讀','换':'換','连':'連','归':'歸','属':'屬','剩':'剩','数':'數','见':'見','仅':'僅','单':'單','双':'雙','栈':'棧','场':'場','别':'別','争':'爭','纹':'紋','销':'銷','滚':'滾','静':'靜','护':'護','从':'從','与':'與','为':'為','将':'將','这':'這','后':'後','无':'無','还':'還','会':'會','对':'對','请':'請','经':'經','给':'給','临':'臨','终':'終','组':'組','额':'額','满':'滿','边':'邊','际':'際','简':'簡','体':'體','语':'語','制':'製','号':'號','项':'項','并':'並','虽':'雖','确':'確','认':'認','异':'異','维':'維','级':'級','拥':'擁','页':'頁','顶':'頂','选':'選','击':'擊','错':'錯','构':'構','块':'塊','术':'術','据':'據','隐':'隱','扫':'掃','规':'規','则':'則','扩':'擴','压':'壓','严':'嚴','损':'損','综':'綜','拟':'擬','机':'機','软':'軟','弹':'彈','窗':'窗','转':'轉','稳':'穩','布':'布','内':'內','旧':'舊','广':'廣','东':'東','门':'門','层':'層','缀':'綴','冲':'衝','险':'險','杂':'雜','总':'總','阅':'閱','纲':'綱','毕':'畢','独':'獨','释':'釋','围':'圍','来':'來','处':'處','续':'續','绝':'絕','够':'夠','汇':'匯','举':'舉','领':'領'
  };

  let language = 'zh-CN';
  let applying = false;
  const textState = new WeakMap();
  const attributeState = new WeakMap();

  function readStoredLanguage() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (SUPPORTED.has(stored)) return stored;
    } catch (_) {}
    const browser = String(navigator.language || '').toLowerCase();
    if (browser.startsWith('zh-tw') || browser.startsWith('zh-hk') || browser.startsWith('zh-mo')) return 'zh-TW';
    if (browser.startsWith('ja')) return 'ja';
    if (browser.startsWith('en')) return 'en';
    return 'zh-CN';
  }

  function convertTraditional(value) {
    return [...value].map(character => traditionalCharacters[character] || character).join('');
  }

  function translateText(value, requestedLanguage = language) {
    if (!value || requestedLanguage === 'zh-CN') return value;
    const match = value.match(/^(\s*)([\s\S]*?)(\s*)$/);
    const leading = match ? match[1] : '';
    const source = match ? match[2] : value;
    const trailing = match ? match[3] : '';
    if (!source) return value;
    const direct = index[source];
    if (direct) return leading + direct[targetIndex[requestedLanguage]] + trailing;
    let translated = source;
    for (const row of sortedRows) {
      if (!translated.includes(row[0])) continue;
      translated = translated.split(row[0]).join(row[targetIndex[requestedLanguage]]);
    }
    if (requestedLanguage === 'zh-TW') translated = convertTraditional(translated);
    return leading + translated + trailing;
  }

  function ignored(node) {
    const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    return !element || !!element.closest('script,style,[data-i18n-ignore]');
  }

  function translateTextNode(node) {
    if (ignored(node) || !node.nodeValue || !node.nodeValue.trim()) return;
    const current = node.nodeValue;
    let state = textState.get(node);
    if (!state || current !== state.rendered) state = { source: current, rendered: current };
    const rendered = translateText(state.source);
    state.rendered = rendered;
    textState.set(node, state);
    if (current !== rendered) node.nodeValue = rendered;
  }

  function translateAttributes(element) {
    if (ignored(element)) return;
    let states = attributeState.get(element);
    if (!states) {
      states = Object.create(null);
      attributeState.set(element, states);
    }
    for (const name of ['placeholder', 'title', 'aria-label']) {
      if (!element.hasAttribute(name)) continue;
      const current = element.getAttribute(name) || '';
      let state = states[name];
      if (!state || current !== state.rendered) state = { source: current, rendered: current };
      const rendered = translateText(state.source);
      state.rendered = rendered;
      states[name] = state;
      if (current !== rendered) element.setAttribute(name, rendered);
    }
  }

  function translateTree(root = document.body) {
    if (!root) return;
    applying = true;
    try {
      if (root.nodeType === Node.TEXT_NODE) {
        translateTextNode(root);
        return;
      }
      if (root.nodeType !== Node.ELEMENT_NODE) return;
      translateAttributes(root);
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        if (node.nodeType === Node.TEXT_NODE) translateTextNode(node);
        else translateAttributes(node);
      }
    } finally {
      applying = false;
    }
  }

  function updateLanguageControls() {
    const selector = document.getElementById('languageSelect');
    if (selector) selector.value = language;
    const status = document.getElementById('languageStatus');
    if (status) {
      status.setAttribute('data-i18n-ignore', '');
      const labels = {
        'zh-CN': '当前：简体中文',
        'zh-TW': '目前：繁體中文',
        en: 'Current: English',
        ja: '現在：日本語',
      };
      if (status.textContent !== labels[language]) status.textContent = labels[language];
    }
  }

  function applyLanguage(nextLanguage, persist = true, feedback = true) {
    language = SUPPORTED.has(nextLanguage) ? nextLanguage : 'zh-CN';
    document.documentElement.lang = language;
    if (persist) {
      try { localStorage.setItem(STORAGE_KEY, language); } catch (_) {}
    }
    translateTree(document.body);
    updateLanguageControls();
    document.dispatchEvent(new CustomEvent('meshlan:languagechange', { detail: { language } }));
    if (feedback && typeof window.showToast === 'function') {
      const messages = {
        'zh-CN': '界面语言已切换为简体中文',
        'zh-TW': '介面語言已切換為繁體中文',
        en: 'Interface language changed to English',
        ja: '表示言語を日本語に切り替えました',
      };
      window.showToast(messages[language], 'success', 1800);
    }
  }

  window.setInterfaceLanguage = nextLanguage => applyLanguage(nextLanguage, true, true);
  window.meshLANI18n = {
    get language() { return language; },
    translate: (value, requestedLanguage) => translateText(value, requestedLanguage || language),
    apply: applyLanguage,
    supported: [...SUPPORTED],
    names: { ...LANGUAGE_NAMES },
  };

  language = readStoredLanguage();
  applyLanguage(language, false, false);

  const observer = new MutationObserver(mutations => {
    if (applying) return;
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') translateTextNode(mutation.target);
      if (mutation.type === 'attributes') translateAttributes(mutation.target);
      for (const node of mutation.addedNodes || []) translateTree(node);
    }
    updateLanguageControls();
  });
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ['placeholder', 'title', 'aria-label'],
  });
})();
