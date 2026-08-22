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
    ['Relay默认关闭；Route Guard将 Nebula的 Lighthouse与 Peer公网端点绕过全局代理和 TUN。localhost服务访问 GPT等外部业务仍按本机代理设置运行。', 'Relay預設關閉；Route Guard會讓 Nebula 的 Lighthouse與 Peer公網端點繞過全域代理和 TUN。localhost服務存取 GPT等外部業務仍依本機代理設定執行。', 'Relay is disabled by default. Route Guard sends Nebula Lighthouse and peer public endpoints around global proxies and TUN adapters. External traffic from localhost services still follows local proxy settings.', 'Relay は既定で無効です。Route Guard は Nebula の Lighthouse と Peer 公開エンドポイントをグローバルプロキシ／TUN から除外します。localhost サービスの外部通信は端末のプロキシ設定に従います。'],
    ['本机证书、私钥和 Lighthouse配置已经保存。以后双击软件即可管理服务，不需要再次填写哈希。', '本機憑證、私鑰和 Lighthouse設定已儲存。之後雙擊軟體即可管理服務，不需要再次填寫雜湊。', 'The local certificate, private key, and Lighthouse configuration are saved. Open the app to manage services without entering the enrollment hash again.', '証明書、秘密鍵、Lighthouse 設定は保存済みです。次回から登録ハッシュを再入力せずに管理できます。'],
    ['路由器不支持或未开启 UPnP', '路由器不支援或未開啟 UPnP', 'The router does not support UPnP or UPnP is disabled', 'ルーターが UPnP に対応していないか、無効になっています'],
    ['已绕过 TUN · 保护', '已繞過 TUN · 保護', 'TUN bypass active · protecting', 'TUN バイパス有効 · 保護中'],
    ['个公网端点', '個公網端點', 'public endpoints', '個の公開エンドポイント'],
    ['已应用 · 业务代理保持不变', '已套用 · 業務代理保持不變', 'Applied · application proxy unchanged', '適用済み · アプリのプロキシは変更なし'],
    ['诊断输出', '診斷輸出', 'Diagnostic output', '診断出力'],
    ['禁用 Peer IPv6；Lighthouse和 P2P只使用 IPv4。', '停用 Peer IPv6；Lighthouse和 P2P僅使用 IPv4。', 'Disable peer IPv6; Lighthouse and P2P use IPv4 only.', 'Peer IPv6 を無効化し、Lighthouse と P2P は IPv4 のみを使用します。'],
    ['禁用 Peer IPv4；保留 Lighthouse必要的 IPv4发现通道。', '停用 Peer IPv4；保留 Lighthouse必要的 IPv4探索通道。', 'Disable peer IPv4 while retaining the IPv4 discovery channel required by Lighthouse.', 'Peer IPv4 を無効化し、Lighthouse に必要な IPv4 探索チャネルだけを残します。'],
    ['同时启用，Nebula自动选择更快的直连地址。', '同時啟用，Nebula自動選擇更快的直連位址。', 'Enable both; Nebula automatically selects the faster direct endpoint.', '両方を有効にし、Nebula がより速い直接接続先を自動選択します。'],
    ['当前模式：', '目前模式：', 'Current mode: ', '現在のモード：'],
    ['双栈', '雙棧', 'dual stack', 'デュアルスタック'],
    ['在质量恶化时重新进行 IPv4/IPv6 竞速', '在品質惡化時重新進行 IPv4/IPv6 競速', 'Race IPv4 and IPv6 again when quality degrades', '品質低下時に IPv4／IPv6 の競合を再実行'],
    ['按当前物理网络自动恢复 P2P 与业务出口', '依目前實體網路自動恢復 P2P 與業務出口', 'Restore P2P and application egress for the current physical network', '現在の物理ネットワークに合わせて P2P／アプリ出口を復元'],
    ['状态：', '狀態：', 'Status: ', '状態：'],
    ['稳定监测', '穩定監測', 'stable monitoring', '安定監視'],
    ['竞速版本：', '競速版本：', 'Race version: ', '競合バージョン：'],
    ['评分变化，已切换优先中继节点', '評分變化，已切換優先中繼節點', 'score changed; preferred relay node switched', 'スコア変化により優先 Relay ノードを切り替えました'],
    ['分 ·', '分 ·', ' points ·', ' 点 ·'],
    ['场景', '場景', 'Profile', 'プロファイル'],
    ['P2P出口', 'P2P出口', 'P2P egress', 'P2P 出口'],
    ['业务出口', '業務出口', 'Application egress', 'アプリ出口'],
    ['最近识别', '最近識別', 'Last detected', '最終検出'],
    ['网络', '網路', 'network', 'ネットワーク'],
    ['网卡不可用时自动回退其他物理网卡', '網卡不可用時自動回退其他實體網卡', 'Automatically fall back to another physical adapter when the selected adapter is unavailable', '選択したアダプターが利用できない場合は別の物理アダプターへ自動フォールバック'],
    ['auto 或 WLAN', 'auto 或 WLAN', 'auto or WLAN', 'auto または WLAN'],
    ['auto 或 以太网 13', 'auto 或乙太網路 13', 'auto or Ethernet 13', 'auto またはイーサネット 13'],
    ['偏好', '偏好', 'preferred', '優先'],
    ['业务偏好', '業務偏好', 'application preference', 'アプリ優先'],
    ['签名吊销列表 · 原子身份修复', '簽章撤銷清單 · 原子身分修復', 'Signed revocation list · atomic identity repair', '署名付き失効リスト · アトミック ID 修復'],
    ['有效，证书与私钥匹配', '有效，憑證與私鑰相符', 'Valid; certificate and private key match', '有効：証明書と秘密鍵が一致'],
    ['本机已应用', '本機已套用', 'applied locally', 'ローカル適用済み'],
    ['设备令牌', '裝置權杖', 'Device token', '端末トークン'],
    ['DPAPI认证密文', 'DPAPI驗證密文', 'DPAPI-protected credential', 'DPAPI で保護された認証情報'],
    ['秘密目录ACL', '秘密目錄ACL', 'Secret directory ACL', '機密ディレクトリ ACL'],
    ['仅当前用户与SYSTEM', '僅目前使用者與SYSTEM', 'Current user and SYSTEM only', '現在のユーザーと SYSTEM のみ'],
    ['身份私钥备份', '身分私鑰備份', 'Identity private-key backup', 'ID 秘密鍵バックアップ'],
    ['DPAPI备份可恢复', 'DPAPI備份可恢復', 'Recoverable DPAPI backup', '復元可能な DPAPI バックアップ'],
    ['“安全修复身份”会在本机生成全新私钥，服务端暂存新证书；校验通过后才提交切换并吊销旧证书。设备名、虚拟 IP、服务映射和设置保持不变。', '「安全修復身分」會在本機產生全新私鑰，服務端暫存新憑證；驗證通過後才切換並撤銷舊憑證。裝置名稱、虛擬 IP、服務映射和設定保持不變。', 'Secure identity repair generates a new private key locally and stages a new certificate on the server. It switches and revokes the old certificate only after verification. Device name, virtual IP, mappings, and settings stay unchanged.', '安全な ID 修復は端末で新しい秘密鍵を生成し、サーバーに新証明書を一時保存します。検証後に切り替えて旧証明書を失効させます。端末名、仮想 IP、マッピング、設定は変わりません。'],
    ['当前 Windows 用户证书库', '目前 Windows 使用者憑證庫', 'Current Windows user certificate store', '現在の Windows ユーザー証明書ストア'],
    ['已安装并受当前用户信任', '已安裝並受目前使用者信任', 'Installed and trusted by the current user', 'インストール済みで現在のユーザーが信頼'],
    ['安装位置', '安裝位置', 'Install location', 'インストール先'],
    ['当前 Windows 用户 · 受信任的根证书颁发机构', '目前 Windows 使用者 · 受信任的根憑證授權單位', 'Current Windows user · Trusted Root Certification Authorities', '現在の Windows ユーザー · 信頼されたルート証明機関'],
    ['HTTPS 网关', 'HTTPS 閘道', 'HTTPS gateway', 'HTTPS ゲートウェイ'],
    ['安装后请完全关闭并重新打开浏览器，并使用服务的', '安裝後請完全關閉並重新開啟瀏覽器，並使用服務的', 'After installation, fully close and reopen the browser, then use the service domain', 'インストール後にブラウザーを完全終了して再起動し、サービスのドメインを使用してください'],
    ['域名访问；使用 IP、错误域名或旧浏览器会话仍会显示不安全。', '網域存取；使用 IP、錯誤網域或舊瀏覽器工作階段仍會顯示不安全。', 'Using an IP address, the wrong domain, or an old browser session will still appear insecure.', 'IP、誤ったドメイン、古いブラウザーセッションでは引き続き安全でないと表示されます。'],
    ['重新安装证书', '重新安裝憑證', 'Reinstall certificate', '証明書を再インストール'],
    ['自动直连', '自動直連', 'Automatic direct access', '自動直接接続'],
    ['让 .mesh 域名和 10.77.0.0/24 绕过 Windows 系统代理', '讓 .mesh 網域和 10.77.0.0/24 繞過 Windows 系統代理', 'Bypass the Windows system proxy for .mesh domains and 10.77.0.0/24', '.mesh ドメインと 10.77.0.0/24 を Windows システムプロキシから除外'],
    ['系统代理绕过', '系統代理繞過', 'System proxy bypass', 'システムプロキシ除外'],
    ['已直连', '已直連', 'direct', '直接接続'],
    ['已写入', '已寫入', 'configured', '設定済み'],
    ['应用后请重启浏览器和API工具。纯TUN模式若强制接管所有进程流量，第三方代理仍可能拥有最终控制权。', '套用後請重新啟動瀏覽器和API工具。純TUN模式若強制接管所有處理程序流量，第三方代理仍可能擁有最終控制權。', 'Restart browsers and API tools after applying. A third-party proxy may still have final control when pure TUN mode forcibly captures all process traffic.', '適用後にブラウザーと API ツールを再起動してください。純 TUN モードが全プロセス通信を強制取得する場合、第三者プロキシが最終制御権を持つことがあります。'],
    ['Ed25519清单签名 · SHA-256 · 可选 Authenticode', 'Ed25519清單簽章 · SHA-256 · 可選 Authenticode', 'Ed25519 manifest signature · SHA-256 · optional Authenticode', 'Ed25519 マニフェスト署名 · SHA-256 · 任意の Authenticode'],
    ['Ed25519签名有效', 'Ed25519簽章有效', 'Valid Ed25519 signature', 'Ed25519 署名は有効'],
    ['应用签名通道', '應用程式簽章通道', 'application signing channel', 'アプリ署名チャネル'],
    ['只共享本机回环服务，域名与列表实时同步。', '僅分享本機回環服務，網域與清單即時同步。', 'Only local loopback services are shared; domains and directories sync in real time.', 'ローカルのループバックサービスだけを共有し、ドメインと一覧をリアルタイム同期します。'],
    ['普通TCP/UDP保留“域名 + 端口”；Web服务通过自动 HTTPS 网关使用', '一般TCP/UDP保留「網域 + 連接埠」；Web服務透過自動 HTTPS 閘道使用', 'Standard TCP/UDP uses “domain + port”; web services use the automatic HTTPS gateway at', '通常の TCP/UDP は「ドメイン + ポート」を使用し、Web サービスは自動 HTTPS ゲートウェイで次を使用します'],
    ['，无需端口。客户端每15秒检查目标健康。', '，無需連接埠。用戶端每15秒檢查目標健康。', ', without a port. The client checks target health every 15 seconds.', '（ポート不要）。クライアントは 15 秒ごとに対象のヘルスを確認します。'],
    ['本地目标', '本機目標', 'Local target', 'ローカル対象'],
    ['原始地址', '原始位址', 'Original address', '元のアドレス'],
    ['映射入口', '映射入口', 'Mapped endpoint', 'マッピング入口'],
    ['映射状态', '映射狀態', 'Mapping status', 'マッピング状態'],
    ['运行', '執行', 'Running', '実行'],
    ['创建者', '建立者', 'Owner', '作成者'],
    ['连接数', '連線數', 'Connections', '接続数'],
    ['实时进入', '即時進入', 'Live inbound', 'リアルタイム受信'],
    ['实时返回', '即時返回', 'Live outbound', 'リアルタイム返信'],
    ['直接端口与HTTP域名访问统一统计，不记录内容', '直接連接埠與HTTP網域存取統一統計，不記錄內容', 'Direct-port and HTTP-domain access share statistics; payload contents are not recorded', '直接ポートと HTTP ドメインアクセスを統合集計し、内容は記録しません'],
    ['端口与域名入口共享同一审批策略', '連接埠與網域入口共用同一審批策略', 'Port and domain endpoints share the same approval policy', 'ポートとドメイン入口は同じ承認ポリシーを使用'],
    ['权限状态', '權限狀態', 'Permission status', '権限状態'],
    ['服务器只同步分享元数据，不保存文件内容。分享过期或下载次数用完后，本机自动删除内容。', '伺服器僅同步分享中繼資料，不儲存檔案內容。分享過期或下載次數用完後，本機自動刪除內容。', 'The server syncs share metadata only and never stores file contents. Local contents are deleted when the share expires or reaches its download limit.', 'サーバーは共有メタデータだけを同期し、ファイル本体は保存しません。有効期限または受信上限に達すると端末から自動削除します。'],
    ['等待文件服务', '等待檔案服務', 'Waiting for file service', 'ファイルサービス待ち'],
    ['等待其他设备发布', '等待其他裝置發布', 'Waiting for another device to publish', '他の端末からの公開を待機中'],
    ['可查看接收确认并随时撤销', '可查看接收確認並隨時撤銷', 'View receipt confirmations and revoke at any time', '受信確認を表示し、いつでも取り消せます'],
    ['次数', '次數', 'Count', '回数'],
    ['最近接收确认', '最近接收確認', 'Latest receipt', '最新の受信確認'],
    ['服务端校验全网唯一，其他用户不能修改', '服務端驗證全網唯一，其他使用者不能修改', 'The server enforces global uniqueness; other users cannot modify it', 'サーバーが全体での一意性を検証し、他のユーザーは変更できません'],
    ['SYSTEM Route Guard仅维护自己的hosts托管区块', 'SYSTEM Route Guard僅維護自己的hosts託管區塊', 'SYSTEM Route Guard manages only its own hosts block', 'SYSTEM Route Guard は専用 hosts ブロックのみを管理'],
    ['新建、删除、暂停和改名前缀后自动更新', '新增、刪除、暫停和重新命名前綴後自動更新', 'Updates automatically after create, delete, pause, or prefix rename', '作成、削除、一時停止、プレフィックス変更後に自動更新'],
    ['持久连接记录', '持久連線記錄', 'Persistent connection records', '永続接続記録'],
    ['客户端重启后仍保留，不记录报文内容', '用戶端重新啟動後仍保留，不記錄封包內容', 'Retained after client restart; payload contents are not recorded', 'クライアント再起動後も保持し、ペイロード内容は記録しません'],
    ['流量变化与链路数量', '流量變化與鏈路數量', 'Traffic changes and link count', '通信量の変化とリンク数'],
    ['覆盖时长', '涵蓋時長', 'Coverage', '対象期間'],
    ['独立采样时刻', '獨立取樣時刻', 'Independent samples', '独立サンプル時刻'],
    ['窗口新增流量', '視窗新增流量', 'Traffic added in window', '期間内の追加通信量'],
    ['累计流量', '累計流量', 'Cumulative traffic', '累積通信量'],
    ['接收 + 发送', '接收 + 傳送', 'Received + sent', '受信 + 送信'],
    ['平均延迟', '平均延遲', 'Average latency', '平均遅延'],
    ['连续在线', '連續線上', 'Continuous uptime', '連続オンライン'],
    ['连接状态', '連線狀態', 'Connection status', '接続状態'],
    ['最近切换', '最近切換', 'Last switch', '最終切替'],
    ['切换原因', '切換原因', 'Switch reason', '切替理由'],
    ['路径稳定率', '路徑穩定率', 'Path stability', '経路安定率'],
    ['P2P 样本占可达样本', 'P2P 取樣占可達取樣', 'P2P share of reachable samples', '到達可能サンプルに占める P2P'],
    ['拓扑快照', '拓撲快照', 'Topology snapshots', 'トポロジースナップショット'],
    ['全部设备样本', '全部裝置取樣', 'All device samples', 'すべての端末サンプル'],
    ['全部事件', '全部事件', 'All events', 'すべてのイベント'],
    ['事件类型', '事件類型', 'Event type', 'イベント種別'],
    ['上线、服务启停、路径变化与安全操作', '上線、服務啟停、路徑變化與安全操作', 'Online status, service start/stop, path changes, and security actions', 'オンライン状態、サービス起動／停止、経路変更、セキュリティ操作'],
    ['数据路径', '資料路徑', 'Data path', 'データ経路'],
    ['路径来自本机 Nebula 事件日志', '路徑來自本機 Nebula 事件日誌', 'Paths come from the local Nebula event log', '経路はローカル Nebula イベントログから取得'],
    ['路径切换', '路徑切換', 'Path switches', '経路切替'],
    ['首次', '首次', 'First seen', '初回'],
    ['最近', '最近', 'Latest', '最新'],
    ['心跳', '心跳', 'Heartbeat', 'ハートビート'],
    ['活动连接', '活動連線', 'Active connections', 'アクティブ接続'],
    ['最近活动', '最近活動', 'Last activity', '最終アクティビティ'],
    ['流量', '流量', 'Traffic', '通信量'],
    ['提示', '提示', 'Hint', 'ヒント'],
    ['搜索', '搜尋', 'Search', '検索'],
    ['显示更多', '顯示更多', 'Show more', 'さらに表示'],
    ['重新读取', '重新讀取', 'Reload', '再読み込み'],
    ['正在采集链路样本...', '正在收集鏈路取樣...', 'Collecting link samples...', 'リンクサンプルを収集中...'],
    ['实时采样准备中', '即時取樣準備中', 'Preparing live samples', 'リアルタイムサンプルを準備中'],
    ['等待读取数据库', '等待讀取資料庫', 'Waiting for database', 'データベース待ち'],
    ['等待读取', '等待讀取', 'Waiting to load', '読み込み待ち'],
    ['等待真实流量样本', '等待真實流量取樣', 'Waiting for real traffic samples', '実トラフィックサンプル待ち'],
    ['等待主服务端同步', '等待主服務端同步', 'Waiting for main server sync', 'メインサーバー同期待ち'],
    ['等待状态', '等待狀態', 'Waiting for status', '状態待ち'],
    ['正在加载拓扑...', '正在載入拓撲...', 'Loading topology...', 'トポロジーを読み込み中...'],
    ['正在加载服务拓扑...', '正在載入服務拓撲...', 'Loading service topology...', 'サービストポロジーを読み込み中...'],
    ['正在检测节点...', '正在檢測節點...', 'Checking nodes...', 'ノードを確認中...'],
    ['暂无事件', '暫無事件', 'No events', 'イベントなし'],
    ['暂无探测', '暫無探測', 'No probes', 'プローブなし'],
    ['无真实字节增量时不播放传输动画', '無真實位元組增量時不播放傳輸動畫', 'Transfer animation plays only when real byte counts increase', '実バイト数が増加した場合のみ転送アニメーションを表示'],
    ['底层协议', '底層協定', 'Underlay protocol', '下位プロトコル'],
    ['隧道', '隧道', 'Tunnel', 'トンネル'],
    ['质量', '品質', 'Quality', '品質'],
    ['虚拟IP', '虛擬IP', 'Virtual IP', '仮想 IP'],
    ['双栈竞速', '雙棧競速', 'Dual-stack race', 'デュアルスタック競合'],
    ['NAT诊断', 'NAT診斷', 'NAT diagnostics', 'NAT 診断'],
    ['P2P / Relay / 断线', 'P2P / Relay / 斷線', 'P2P / Relay / disconnected', 'P2P / Relay / 切断'],
    ['加入网络', '加入網路', 'Joined network', 'ネットワーク参加'],
    ['状态事件', '狀態事件', 'Status event', '状態イベント'],
    ['当前用户', '目前使用者', 'current user', '現在のユーザー'],
    ['已应用', '已套用', 'Applied', '適用済み'],
    ['最近 6 小时', '最近 6 小時', 'Last 6 hours', '過去 6 時間'],
    ['最近 24 小时', '最近 24 小時', 'Last 24 hours', '過去 24 時間'],
    ['最近 7 天', '最近 7 天', 'Last 7 days', '過去 7 日'],
    ['最近 30 天', '最近 30 天', 'Last 30 days', '過去 30 日'],
    ['条', '則', 'items', '件'],
    ['个实时样本', '個即時取樣', 'live samples', 'リアルタイムサンプル'],
    ['路径变化实时记录', '路徑變化即時記錄', 'path changes recorded in real time', '経路変更をリアルタイム記録'],
    ['测试套接字绑定 P2P 物理网卡并指定接口，分别检测 IPv4 NAT 映射、IPv6 UDP、TUN干扰、UPnP和已有 Nebula 直连证据。最终仍以双方真实握手为准。', '測試通訊端綁定 P2P 實體網卡並指定介面，分別檢測 IPv4 NAT 映射、IPv6 UDP、TUN干擾、UPnP和既有 Nebula 直連證據。最終仍以雙方真實握手為準。', 'The test socket binds to the P2P physical adapter and selected interface, then checks IPv4 NAT mapping, IPv6 UDP, TUN interference, UPnP, and existing Nebula direct-path evidence. The real peer handshake remains authoritative.', 'テストソケットを P2P 物理アダプターと指定インターフェースにバインドし、IPv4 NAT マッピング、IPv6 UDP、TUN 干渉、UPnP、既存の Nebula 直接接続証拠を確認します。最終判断は実際の Peer ハンドシェイクに基づきます。'],
    ['客户端同时向所有可用节点注册，自动故障切换', '用戶端同時向所有可用節點註冊，自動容錯移轉', 'The client registers with every available node and fails over automatically', '利用可能な全ノードへ同時登録し、自動フェイルオーバーします'],
    ['普通入口：service.你的前缀.mesh:分配端口', '一般入口：service.你的前綴.mesh:分配連接埠', 'Standard endpoint: service.your-prefix.mesh:assigned-port', '通常入口：service.あなたのプレフィックス.mesh:割当ポート'],
    ['所选时间范围', '所選時間範圍', 'Selected time range', '選択期間'],
    ['同一测试端口访问不同目标，用于判断映射是否稳定', '同一測試連接埠存取不同目標，用於判斷映射是否穩定', 'Use the same test port with different targets to determine mapping stability', '同じテストポートから複数の対象へ接続し、マッピングの安定性を判定'],
    ['文件', '檔案', 'File', 'ファイル'],
    ['正在读取自动网络状态...', '正在讀取自動網路狀態...', 'Reading automatic network status...', '自動ネットワーク状態を読み込み中...'],
    ['只能管理本机创建的映射 ·', '只能管理本機建立的映射 ·', 'Only mappings created on this device can be managed ·', 'この端末で作成したマッピングのみ管理可能 ·'],
    ['最后心跳', '最後心跳', 'Last heartbeat', '最終ハートビート'],
    ['设备私钥只在本机生成', '裝置私鑰僅在本機產生', 'Device private keys are generated only on this device', '端末秘密鍵はこの端末でのみ生成'],
    ['HTTP网关等待检测', 'HTTP閘道等待檢測', 'HTTP gateway waiting for check', 'HTTP ゲートウェイ確認待ち'],
    ['Lighthouse 公网 IP 或域名', 'Lighthouse 公網 IP 或網域', 'Lighthouse public IP or domain', 'Lighthouse 公開 IP またはドメイン'],
    ['MeshDNS域名', 'MeshDNS網域', 'MeshDNS domain', 'MeshDNS ドメイン'],
    ['P2P：', 'P2P：', 'P2P: ', 'P2P：'],
    ['业务偏好：', '業務偏好：', 'application preference: ', 'アプリ優先：'],
    ['以太网', '乙太網路', 'Ethernet', 'イーサネット'],
    ['已启用', '已啟用', 'Enabled', '有効'],
    ['服务端显示的配对哈希', '服務端顯示的配對雜湊', 'Enrollment hash shown by the server', 'サーバーに表示された登録ハッシュ'],
    ['台', '台', 'devices', '台'],
    ['检测于', '檢測於', 'Checked at', '確認時刻'],
    ['首选', '首選', 'Preferred', '優先'],
    ['子节点', '子節點', 'Child node', '子ノード'],
    ['复制端点', '複製端點', 'Copy endpoint', 'エンドポイントをコピー'],
    ['已更新', '已更新', 'Updated', '更新済み'],
    ['个流量点', '個流量點', 'traffic points', 'トラフィック点'],
    ['实时 ·', '即時 ·', 'Live ·', 'リアルタイム ·'],
    ['实时更新', '即時更新', 'Live update', 'リアルタイム更新'],
    ['链路数量', '鏈路數量', 'Link count', 'リンク数'],
    ['紫 P2P / 橙 Relay', '紫 P2P / 橙 Relay', 'purple P2P / orange Relay', '紫 P2P／橙 Relay'],
    ['吞吐峰值', '吞吐峰值', 'Peak throughput', '最大スループット'],
    ['当前接收', '目前接收', 'current received', '現在の受信'],
    ['当前发送', '目前傳送', 'current sent', '現在の送信'],
    ['断开', '斷開', 'Disconnected', '切断'],
    ['变化', '變化', 'Changes', '変化'],
    ['显示', '顯示', 'Showing', '表示'],
    ['已确认支持 P2P 直连', '已確認支援 P2P 直連', 'P2P direct support confirmed', 'P2P 直接接続対応を確認'],
    ['NAT打洞成功，从 Relay 切换为 P2P直连', 'NAT打洞成功，從 Relay 切換為 P2P直連', 'NAT hole punching succeeded; switched from Relay to P2P direct', 'NAT ホールパンチ成功：Relay から P2P 直接接続へ切替'],
    ['应用 P2P=', '套用 P2P=', 'Applied P2P=', 'P2P を適用='],
    ['，业务=', '，業務=', ', application=', '、アプリ='],
    ['IPv4 为端点相关 NAT，稳定 P2P 困难', 'IPv4 為端點相關 NAT，穩定 P2P 困難', 'IPv4 uses endpoint-dependent NAT; stable P2P is difficult', 'IPv4 はエンドポイント依存 NAT のため、安定した P2P が困難'],
    ['Peer探测连续失败，当前隧道不可达', 'Peer探測連續失敗，目前隧道不可達', 'Peer probes repeatedly failed; the current tunnel is unreachable', 'Peer プローブが連続失敗し、現在のトンネルは到達不能'],
    ['Peer恢复可达，重新建立IPV4 RELAY路径', 'Peer恢復可達，重新建立IPV4 RELAY路徑', 'Peer became reachable; rebuilt the IPv4 Relay path', 'Peer が復旧し、IPv4 Relay 経路を再構築'],
    ['Peer恢复可达，重新建立IPV6 P2P路径', 'Peer恢復可達，重新建立IPV6 P2P路徑', 'Peer became reachable; rebuilt the IPv6 P2P path', 'Peer が復旧し、IPv6 P2P 経路を再構築'],
    ['控制心跳超时，设备按离线处理', '控制心跳逾時，裝置按離線處理', 'Control heartbeat timed out; device marked offline', '制御ハートビートがタイムアウトし、端末をオフラインとして処理'],
    ['共享服务', '共享服務', 'Shared service', '共有サービス'],
    ['普通入口：', '一般入口：', 'Standard endpoint: ', '通常入口：'],
    ['分配端口', '分配連接埠', 'assigned-port', '割当ポート'],
    ['创建分享后自动启动', '建立分享後自動啟動', 'Starts automatically after creating a share', '共有作成後に自動起動'],
    ['*.mesh 与 10.77.* 已直连', '*.mesh 與 10.77.* 已直連', '*.mesh and 10.77.* are direct', '*.mesh と 10.77.* は直接接続'],
    ['.mesh 与 10.77.0.0/24 已写入', '.mesh 與 10.77.0.0/24 已寫入', '.mesh and 10.77.0.0/24 are configured', '.mesh と 10.77.0.0/24 は設定済み'],
    ['采样于', '取樣於', 'Sampled at', 'サンプル時刻'],
    ['每台设备', '每台裝置', 'per device', '端末ごと'],
    ['个样本', '個取樣', 'samples', 'サンプル'],
    ['胜出', '勝出', 'won', '優先'],
    ['首次检测到IPV6 P2P路径', '首次檢測到IPV6 P2P路徑', 'First detected an IPv6 P2P path', 'IPv6 P2P 経路を初めて検出'],
    ['首次检测到IPV4 P2P路径', '首次檢測到IPV4 P2P路徑', 'First detected an IPv4 P2P path', 'IPv4 P2P 経路を初めて検出'],
    ['稳定', '穩定', 'Stable', '安定'],
    ['已应用 P2P=', '已套用 P2P=', 'Applied P2P=', 'P2P 適用='],
    ['小时', '小時', 'h', '時間'],
    ['分', '分', 'm', '分'],
    ['真实字节增量', '真實位元組增量', 'real byte delta', '実バイト増分'],
    ['网络策略', '網路策略', 'Network policy', 'ネットワークポリシー'],
    ['实时吞吐', '即時吞吐', 'Live throughput', 'リアルタイムスループット'],
    ['网络出口', '網路出口', 'Network egress', 'ネットワーク出口'],
    ['全图', '全圖', 'Full graph', '全体表示'],
    ['缩放', '縮放', 'Zoom', 'ズーム'],
    ['本机核心', '本機核心', 'Local core', 'ローカルコア'],
    ['设备链路', '裝置鏈路', 'Device links', '端末リンク'],
    ['发现', '探索', 'Discovery', '探索'],
    ['业务默认', '業務預設', 'Application default', 'アプリ既定'],
    ['控制', '控制', 'Control', '制御'],
    ['出口', '出口', 'Egress', '出口'],
    ['网关', '閘道', 'Gateway', 'ゲートウェイ'],
    ['本机：', '本機：', 'Local device: ', 'この端末：'],
    ['监听：', '監聽：', 'Listening: ', '待受：'],
    ['数据协议：', '資料協定：', 'Data protocol: ', 'データプロトコル：'],
    ['P2P 策略：', 'P2P 策略：', 'P2P policy: ', 'P2P ポリシー：'],
    ['服务：', '服務：', 'Services: ', 'サービス：'],
    ['累计接收：', '累計接收：', 'Total received: ', '累計受信：'],
    ['累计发送：', '累計傳送：', 'Total sent: ', '累計送信：'],
    ['IPv6 默认路由：已压制，Peer /128 保留', 'IPv6 預設路由：已抑制，保留 Peer /128', 'IPv6 default route: suppressed; peer /128 routes retained', 'IPv6 デフォルトルート：抑制済み、Peer /128 を維持'],
    ['未检测到', '未檢測到', 'Not detected', '未検出'],
    ['安全策略：', '安全策略：', 'Security policy: ', 'セキュリティポリシー：'],
    ['兜底', '備援', 'fallback', 'フォールバック'],
    ['采样间隔：', '取樣間隔：', 'Sample interval: ', 'サンプル間隔：'],
    ['秒', '秒', 's', '秒'],
    ['当前采样周期没有检测到新的字节增量，动画暂停。', '目前取樣週期未檢測到新的位元組增量，動畫暫停。', 'No new byte delta was detected in the current sample; animation is paused.', '現在のサンプルで新しいバイト増分が検出されなかったため、アニメーションを一時停止します。'],
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
    ['高级设置', '進階設定', 'Advanced settings', '詳細設定'],
    ['多网卡、代理与特殊网络环境', '多網卡、代理與特殊網路環境', 'Multiple adapters, proxies, and special network environments', '複数アダプター、プロキシ、特殊なネットワーク環境'],
    ['展开高级设置', '展開進階設定', 'Expand advanced settings', '詳細設定を開く'],
    ['收起高级设置', '收合進階設定', 'Collapse advanced settings', '詳細設定を閉じる'],
    ['大多数用户不需要修改这里，保持“自动 / 自动”即可。', '大多數使用者不需要修改這裡，保持「自動 / 自動」即可。', 'Most users do not need to change these settings. Keep “Auto / Auto”.', 'ほとんどのユーザーは変更不要です。「自動／自動」のまま使用してください。'],
    ['此功能适用于同时连接 Wi-Fi、网线或随身 Wi-Fi，并希望 MeshLAN 与普通上网流量使用不同物理网卡的电脑。它不是按用户、服务或端口分流。', '此功能適用於同時連線 Wi-Fi、網路線或隨身 Wi-Fi，並希望 MeshLAN 與一般上網流量使用不同實體網卡的電腦。它不是依使用者、服務或連接埠分流。', 'Use this only when the computer has Wi-Fi, Ethernet, or a mobile hotspot at the same time and MeshLAN should use a different physical adapter from ordinary Internet traffic. It does not split traffic by user, service, or port.', 'Wi-Fi、イーサネット、モバイル Wi-Fi を同時に接続し、MeshLAN と通常のインターネット通信で別の物理アダプターを使いたい場合に使用します。ユーザー、サービス、ポート単位の分流ではありません。'],
    ['P2P 出口网卡', 'P2P 出口網卡', 'P2P egress adapter', 'P2P 出口アダプター'],
    ['控制 MeshLAN/Nebula 的 Lighthouse、Peer 公网端点、NAT 打洞和 P2P 诊断从哪块物理网卡出站。软件会为这些目标维护专用路由，不会接管普通互联网流量。', '控制 MeshLAN/Nebula 的 Lighthouse、Peer 公網端點、NAT 打洞和 P2P 診斷從哪塊實體網卡出站。軟體會為這些目標維護專用路由，不會接管一般網際網路流量。', 'Selects the physical adapter used by MeshLAN/Nebula for Lighthouse, peer public endpoints, NAT hole punching, and P2P diagnostics. Dedicated routes are maintained for those targets without taking over ordinary Internet traffic.', 'MeshLAN/Nebula の Lighthouse、Peer 公開エンドポイント、NAT ホールパンチ、P2P 診断に使う物理アダプターを選びます。対象専用ルートを維持し、通常のインターネット通信は引き継ぎません。'],
    ['调整 Windows 普通流量的默认网卡优先级，可能影响浏览器、API、Codex 和其他应用，不仅影响 MeshLAN 映射服务。代理或 TUN 已接管的流量仍按代理自身规则运行。', '調整 Windows 一般流量的預設網卡優先順序，可能影響瀏覽器、API、Codex 和其他應用程式，不僅影響 MeshLAN 映射服務。代理或 TUN 已接管的流量仍依代理自身規則執行。', 'Changes the Windows default-adapter priority for ordinary traffic. This can affect browsers, APIs, Codex, and other applications—not only MeshLAN mapped services. Traffic already captured by a proxy or TUN still follows that proxy’s rules.', 'Windows の通常通信で使う既定アダプターの優先度を変更します。MeshLAN のマッピングサービスだけでなく、ブラウザー、API、Codex、その他のアプリにも影響します。プロキシや TUN が取得済みの通信は、そのルールに従います。'],
    ['访问映射服务时，对方到你电脑的连接走 MeshLAN；该本地服务随后访问互联网时，继续遵循 Windows 默认路由和自己的代理设置。错误选择可能造成普通上网异常，指定网卡不可用时软件会尝试回退到其他物理网卡。', '存取映射服務時，對方到你電腦的連線走 MeshLAN；該本機服務隨後存取網際網路時，繼續遵循 Windows 預設路由和自己的代理設定。錯誤選擇可能造成一般上網異常，指定網卡不可用時軟體會嘗試回退到其他實體網卡。', 'When someone opens a mapped service, the incoming connection uses MeshLAN. If that local service then accesses the Internet, it still follows the Windows default route and its own proxy settings. A wrong selection can disrupt ordinary Internet access; if the chosen adapter is unavailable, MeshLAN attempts to fall back to another physical adapter.', 'マッピングサービスへの受信接続は MeshLAN を通ります。そのローカルサービスがインターネットへ接続する場合は、Windows の既定ルートと独自のプロキシ設定に従います。誤った選択は通常の通信障害につながる可能性があり、指定アダプターが利用できない場合は別の物理アダプターへフォールバックします。'],
    ['多网卡流量分流', '多網卡流量分流', 'Multi-adapter traffic routing', '複数アダプターのトラフィック経路'],
    ['修改后 Nebula 会短暂重启，现有连接将自动恢复', '修改後 Nebula 會短暫重新啟動，現有連線將自動恢復', 'Nebula briefly restarts after changes; existing connections recover automatically', '変更後に Nebula が短時間再起動し、既存の接続は自動復旧します'],
    ['恢复自动选择', '恢復自動選擇', 'Restore automatic selection', '自動選択に戻す'],
    ['P2P 出口和业务出口都会恢复为自动选择。Nebula 会短暂重启，普通网络将恢复由 Windows 自行选择。', 'P2P 出口和業務出口都會恢復為自動選擇。Nebula 會短暫重新啟動，一般網路將恢復由 Windows 自行選擇。', 'Both P2P and application egress return to automatic selection. Nebula briefly restarts, and Windows resumes choosing the ordinary network path.', 'P2P 出口とアプリ出口を自動選択へ戻します。Nebula が短時間再起動し、通常のネットワーク経路は Windows の自動選択に戻ります。'],
    ['恢复并重启', '恢復並重新啟動', 'Restore and restart', '復元して再起動'],
    ['正在恢复...', '正在恢復...', 'Restoring...', '復元中...'],
    ['已恢复：P2P=auto，业务=auto', '已恢復：P2P=auto，業務=auto', 'Restored: P2P=auto, application=auto', '復元済み：P2P=auto、アプリ=auto'],
    ['流量分流已恢复自动选择', '流量分流已恢復自動選擇', 'Traffic routing restored to automatic selection', 'トラフィック経路を自動選択に戻しました'],
    ['恢复失败：', '恢復失敗：', 'Restore failed: ', '復元失敗：'],
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
