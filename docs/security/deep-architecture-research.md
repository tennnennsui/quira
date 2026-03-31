# Deep Architecture Research: macOS 深層メカニズムからの新規セキュリティ構造

> Status: Research Proposal (未実装 — Founder承認後に検証フェーズへ移行)
> Date: 2026-07
> Scope: architecture.md (12マッピング) + radical-architecture.md (8パラダイム) + novel-research.md (10概念) のいずれにも含まれない構造
> Depends: [threat-model.md](threat-model.md) — 本文書の全概念は形式的脅威モデル G=(V,E,Σ,Φ,Τ) の上に構築される

---

## 0. 調査方針と既存カバレッジ分析

### 既にカバー済みの macOS 概念（除外対象）

| macOS メカニズム | Quira マッピング先 | 文書 |
|----------------|-------------------|------|
| Gatekeeper | Context Gatekeeper (L0-L4) | architecture.md |
| XProtect | Context XProtect (CED) | architecture.md |
| SIP | Context Integrity Protection (CIP) | architecture.md |
| App Sandbox | Context Sandbox | architecture.md |
| TCC | Context TCC | architecture.md |
| Keychain | Context Keychain | architecture.md |
| FileVault / Data Vault | Context Vault (SQLCipher AES-256) | architecture.md |
| Secure Enclave | Hardware-Backed Context Security | architecture.md |
| Code Signing | Context Code Signing | architecture.md |
| Privacy Labels | Context Privacy Labels | architecture.md |
| Lockdown Mode | Context Lockdown Mode | architecture.md |
| Rapid Security Response | Rapid Context Response | architecture.md |

### 本研究で分析する未マッピング macOS 深層メカニズム

| macOS メカニズム | 本文書での提案 | 新規性の根拠 |
|----------------|---------------|-------------|
| **Data Protection Classes (A-D)** | Knowledge Protection Classes (KPC) | 状態ベース暗号化。Context Vault は at-rest 暗号化のみ |
| **Endpoint Security Framework** | Context Security Event Bus (CSEB) | プログラマブルなリアルタイムイベント監視。XProtect はシグネチャベース |
| **iCloud Private Relay (MASQUE/ODoH)** | Knowledge Query Relay (KQR) | アイデンティティ/コンテンツの構造的分離。Cloud AI 時の通信アーキテクチャ |
| **XPC Services** | Privilege-Separated Context Services (PSCS) | 権限分離マイクロサービス。現行アーキテクチャに欠落 |
| **Sealed System Volume (SSV)** | Sealed Knowledge Volume (SKV) | グラフ状態の暗号学的コミットメント。CIP は改竄検知のみ |
| **Sandbox Profile Language (sbpl)** | Declarative Security Policy Language (DSPL) | 宣言的ポリシー合成。TCC は個別許可モデルのみ |
| **AMFI** | Context Trust Arbiter (CTA) | 一元化された信頼判定デーモン。現行は各レイヤーが独立判断 |
| **Security State Transitions** | Adaptive Security Posture (ASP) | 連続的信頼度変動。Lockdown Mode は二値切替のみ |

---

## 1. Knowledge Protection Classes (KPC)

### 1.1 macOS のインスピレーション元: Data Protection Classes

iOS/macOS はファイルごとに 4 つの保護クラスを適用する:

| クラス | iOS 動作 | 鍵の可用性 |
|-------|---------|-----------|
| **Class A** (NSFileProtectionComplete) | デバイスロック時にクラス鍵を即座に破棄。ロック解除で再導出 | ロック解除時のみ |
| **Class B** (NSFileProtectionCompleteUnlessOpen) | ECDH (Curve25519) で per-file 鍵をラップ。ファイルハンドルが開いていれば書込可能 | ファイルオープン中 or ロック解除時 |
| **Class C** (NSFileProtectionCompleteUntilFirstUserAuthentication) | 初回認証後は鍵が残存。再起動でのみ破棄。サードパーティアプリのデフォルト | 初回認証後〜シャットダウン |
| **Class D** (NSFileProtectionNone) | UID のみで導出。リモートワイプを可能にする | 常時 |

鍵階層: per-file key → class key → hardware key (UID) → Secure Enclave

**Quira の Context Vault との差分:**
Context Vault は SQLCipher による AES-256-XTS の全体暗号化を行う。これは Class C に相当する（一度認証すればセッション中は全データがアクセス可能）。Class A/B に相当する**状態依存の段階的保護**が存在しない。

### 1.2 提案: Knowledge Protection Classes (KPC)

知識グラフ $G$ のデータを認証状態に応じて 4 段階の保護クラスに分類する。

#### 形式的定義

保護クラス関数 $\kappa: V \cup E \to \{A, B, C, D\}$ を定義し、各ノード/エッジにクラスを割当てる。

認証状態空間 $\mathcal{S}_\text{auth}$:

$$\mathcal{S}_\text{auth} = \{\text{locked}, \text{session\_start}, \text{space\_active}, \text{foreground}\}$$

各クラスの鍵可用性関数 $\text{Available}(\kappa, s)$:

| クラス | 適用対象 | 鍵導出条件 | 鍵破棄条件 | macOS 対応 |
|-------|---------|-----------|-----------|-----------|
| **KPC-A** (Active Research) | アクティブ Space のグラフデータ全体 | Space をフォアグラウンドに表示 + 生体/パスワード認証 | Space がバックグラウンドになった時点で即座に鍵破棄 | Class A |
| **KPC-B** (Session Data) | 現セッション中に参照された Space のデータ | セッション内で一度認証済み | ブラウザ終了時に鍵破棄 | Class C |
| **KPC-C** (Index Only) | FTS5 インデックス + グラフトポロジーのサブセット | 初回認証（マスターパスワード or 生体） | OS シャットダウン時に破棄 | Class C (制限版) |
| **KPC-D** (Structural) | ノード数、Space 名、最終更新日時 | 認証不要（UID 由来の鍵で暗号化） | なし（リモートワイプでのみ全消去） | Class D |

#### 暗号学的メカニズム

```
鍵階層:

Master Key (K_m)
├── derived via Argon2id from passphrase + hardware UID
│
├── KPC-D Key (K_d) = HKDF(K_m, "kpc-d", salt_d)
│   └── 常時利用可能。リモートワイプ = K_m の破棄
│
├── KPC-C Key (K_c) = HKDF(K_m, "kpc-c", salt_c)
│   └── 初回認証で K_m から導出。メモリ保持。シャットダウンで消去
│
├── KPC-B Key (K_b) = HKDF(K_c, "kpc-b", salt_b + session_id)
│   └── セッション固有。ブラウザ終了で消去
│
└── KPC-A Key (K_a) = HKDF(K_b, "kpc-a", salt_a + space_id)
    └── Space がフォアグラウンドの間のみ存在。バックグラウンド化で即座に消去
```

#### 脅威モデルとの対応

| 敵対者 | 攻撃 | KPC による防御 |
|--------|------|-------------|
| $\mathcal{A}_4$ (OS) | メモリダンプ | KPC-A: アクティブ Space のデータのみ復号状態 → 被害がその Space に限定 |
| $\mathcal{A}_4$ | コールドブート攻撃 | KPC-B: セッション鍵は揮発性メモリのみ → 電源断で全鍵消失 |
| $\mathcal{A}_4$ | ディスク窃取 (電源OFF) | KPC-C/D: Master Key なしでは全クラス復号不可 |
| $\mathcal{A}_3$ (拡張) | グラフ全体読取 | KPC-A: 非アクティブ Space のデータは復号鍵自体が存在しない |

#### 攻撃面マッピング

- **S7 (Disk→Memory)**: KPC-A/B によりメモリ上の復号データを最小化
- **S10 (User→Graph)**: KPC-D によりロック画面でも Space 一覧は表示可能

### 1.3 先行技術分析

| 先行技術 | 関係性 | KPC の差分 |
|---------|--------|-----------|
| iOS Data Protection API | 直接のインスピレーション | ファイルではなくグラフノード/エッジ単位。Space がファイルに相当 |
| SQLCipher | 現行 Context Vault の実装 | DB 全体を 1 鍵で暗号化。KPC は複数鍵で部分暗号化 |
| Android FBE (File-Based Encryption) | CE/DE 2 層 | Credential Encrypted / Device Encrypted の 2 層。KPC は 4 層 |
| VeraCrypt Hidden Volume | 否認可能暗号化 | 異なる目的。KPC は否認ではなく段階的アクセス制御 |

**新規性評価: ★★★★☆**

iOS Data Protection Classes の直接的な翻訳ではあるが、以下の点が新しい:
- ファイルではなくグラフノード/エッジへの適用はブラウザに前例なし
- Space = 保護境界という抽象化は Knowledge Graph Browser 固有
- 4 層の鍵階層を SQLite 上で実現する暗号設計は未踏

**制約: SQLCipher は DB 全体を 1 鍵で暗号化するため、KPC の 4 層鍵を直接適用できない。** Space ごとに別 DB ファイルを使用するか、同一 DB 内でテーブル/ページ単位の暗号化を実装する必要がある。

---

## 2. Context Security Event Bus (CSEB)

### 2.1 macOS のインスピレーション元: Endpoint Security Framework

macOS Endpoint Security Framework は C API 経由で以下を提供する:

- **AUTH イベント** (ブロッキング): プロセス実行、ファイルオープン、mmap を事前にブロック/許可
- **NOTIFY イベント** (非ブロッキング): フォーク、シグナル、マウント等を事後通知
- TCC 固有構造: `es_event_tcc_modify_t`, `es_tcc_authorization_reason_t`
- コード署名検証カテゴリ: app_store, developer_id, development, platform, etc.
- System Extension として配信。`com.apple.developer.endpoint-security.client` エンタイトルメント必要

**Quira の Context XProtect との差分:**
Context XProtect (CED) はパターンベースのエクスフィルトレーション検出。これはシグネチャマッチングに相当する。Endpoint Security Framework のようなプログラマブルな汎用イベント監視機構が存在しない。

### 2.2 提案: Context Security Event Bus (CSEB)

知識グラフの全操作がセキュリティイベントとして発火し、ルールエンジンがリアルタイムで処理する。

#### 形式的定義

イベント空間 $\mathcal{E}$:

$$\mathcal{E} = \{e = (\tau, \text{type}, \text{subject}, \text{object}, \text{action}, \text{metadata})\}$$

イベントタイプの分類:

| 大分類 | イベントタイプ | AUTH/NOTIFY | 例 |
|--------|------------|------------|-----|
| **Graph.Read** | node.read, edge.read, query.execute | NOTIFY | 拡張がノード内容を読取 |
| **Graph.Write** | node.create, node.update, edge.create | AUTH | AI がエンティティを追加 |
| **Graph.Delete** | node.delete, edge.delete, space.purge | AUTH | ユーザーが Space を削除 |
| **Graph.Export** | export.json, export.markdown, clipboard.copy | AUTH | データのブラウザ外への持出し |
| **AI.Pipeline** | ai.extract, ai.embed, ai.summarize, ai.query | AUTH | AI パイプラインの各段階 |
| **Extension.API** | ext.graph.read, ext.graph.write, ext.network.send | AUTH | 拡張の API 呼出し |
| **Auth.State** | auth.lock, auth.unlock, auth.timeout | NOTIFY | 認証状態の変化 |
| **TCC.Modify** | tcc.grant, tcc.revoke, tcc.escalate | AUTH | 権限の変更 |

#### ルールエンジン

ルール $r = (\text{match}, \text{condition}, \text{action})$:

```
rule: block_bulk_export
  match: Graph.Export
  condition: |
    event.metadata.node_count > 100
    AND event.subject.type == "extension"
    AND NOT event.subject.has_capability("bulk_export")
  action: DENY
  notify: user
  log: security_audit

rule: rate_limit_ext_reads
  match: Extension.API where action == "graph.read"
  condition: |
    count(events, window=60s, subject=event.subject) > 50
  action: THROTTLE(delay=1000ms)
  notify: none
  log: security_audit

rule: ai_output_entropy_check
  match: AI.Pipeline where action == "ai.extract"
  condition: |
    shannon_entropy(event.metadata.output) > threshold(event.metadata.input_domain)
  action: QUARANTINE
  notify: user
  log: security_audit
```

#### アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                    CSEB Architecture                         │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Renderer │  │ AI Pipe  │  │Extension │  │  Export  │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│       ▼              ▼              ▼              ▼         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Event Bus (lock-free ring buffer)        │   │
│  └─────────────────────────┬────────────────────────────┘   │
│                            │                                 │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Rule Engine                              │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │ Built-in │  │ Community│  │  User    │           │   │
│  │  │  Rules   │  │  Rules   │  │  Rules   │           │   │
│  │  └──────────┘  └──────────┘  └──────────┘           │   │
│  └──────────────────────────────────────────────────────┘   │
│       │              │              │                        │
│       ▼              ▼              ▼                        │
│  ┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ ALLOW  │  │  DENY    │  │THROTTLE  │  │QUARANTINE│     │
│  └────────┘  └──────────┘  └──────────┘  └──────────┘     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Audit Log (append-only)                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

#### 脅威モデルとの対応

| 敵対者 | 攻撃 | CSEB による防御 |
|--------|------|---------------|
| $\mathcal{A}_3$ (拡張) | A3.1 一括グラフ窃取 | AUTH ルールで node_count > N をブロック |
| $\mathcal{A}_3$ | A3.2 漸増的窃取 | rate_limit ルールでウィンドウ内読取回数を制限 |
| $\mathcal{A}_3$ | A3.3 ストレージ蓄積→送信 | ext.storage.write と ext.network.send の相関ルール |
| $\mathcal{A}_2$ (Web) | A2.1 プロンプトインジェクション | AI.Pipeline AUTH でエントロピー閾値チェック |
| $\mathcal{A}_2$ | A2.3 埋め込み空間操作 | ai.embed の出力分布チェック |

#### 攻撃面マッピング

- **S2 (Renderer→AI)**: AI.Pipeline イベントでコンテンツ消毒前後を監視
- **S3 (AI→Graph)**: Graph.Write AUTH で全 AI 出力をゲーティング
- **S4 (Extension→Graph)**: Extension.API AUTH で全拡張 API 呼出しを監視
- **S5 (Graph→Export)**: Graph.Export AUTH でエクスポートデータを検査

### 2.3 先行技術分析

| 先行技術 | 関係性 | CSEB の差分 |
|---------|--------|-----------|
| macOS Endpoint Security | 直接のインスピレーション | OS イベントではなくグラフ操作イベント |
| Linux eBPF/Audit | カーネルレベルイベント監視 | ブラウザ内部のアプリケーションレベル |
| Chrome Extension API permissions | 静的な権限モデル | CSEB は動的。ルールはコンテキスト依存（時間・頻度・相関） |
| Windows ETW (Event Tracing) | OS レベルイベントトレーシング | パフォーマンス監視ではなくセキュリティ判断 |
| SIEM (Splunk, Elastic) | セキュリティイベント分析 | リアルタイムAUTHゲーティング。SIEMは事後分析 |
| Falco (Kubernetes) | ランタイムセキュリティ | コンテナレベル。CSEB はグラフ操作レベル |

**新規性評価: ★★★★★**

ブラウザ内部にプログラマブルなセキュリティイベントバスを実装し、AUTH/NOTIFY の二重モードで全グラフ操作をリアルタイムゲーティングするシステムは前例がない。最も近いのは macOS Endpoint Security だが、あれは OS レベルであり、知識グラフ操作への適用は完全に新しい。

---

## 3. Knowledge Query Relay (KQR)

### 3.1 macOS のインスピレーション元: iCloud Private Relay

iCloud Private Relay のアーキテクチャ:

1. **Ingress Relay (Apple)**: ユーザーの IP を見れるが、DNS クエリは暗号化されているため接続先を見れない
2. **Egress Relay (Cloudflare/Fastly)**: 接続先を見れるが、ユーザーの IP を見れない。一時的 IP を割当て
3. プロトコル: MASQUE (IETF 標準化)、Oblivious DNS over HTTPS (ODoH)
4. RSA Blind Signatures でトークン認証（Apple は誰がどのトークンを使ったか追跡不可）

**Quira の Cloud AI アーキテクチャへの影響:**
Phase 2+ で Cloud AI（大規模モデル推論のオフロード）を導入する場合、ユーザーの知識クエリがクラウドプロバイダに送信される。これは致命的なプライバシーリスク: クエリ内容 = 研究内容 = 認知プロファイル。

### 3.2 提案: Knowledge Query Relay (KQR)

Cloud AI クエリにおけるアイデンティティとクエリ内容の構造的分離。

#### 形式的定義

3 つのエンティティを定義:

$$\text{User} \xrightarrow{\text{encrypted}} \text{Relay}_1 \xrightarrow{\text{re-encrypted}} \text{Relay}_2 \xrightarrow{\text{plaintext query}} \text{AI Compute}$$

| エンティティ | 知っている情報 | 知らない情報 |
|------------|-------------|-------------|
| $\text{Relay}_1$ (Quira 運営) | ユーザー ID、サブスクリプション状態、リクエスト頻度 | クエリ内容、AI 応答内容 |
| $\text{Relay}_2$ (独立第三者) | クエリ内容（平文）、AI 応答内容 | ユーザー ID、IP アドレス |
| AI Compute | クエリ内容 | ユーザー ID（$\text{Relay}_2$ 経由のため） |

#### プロトコル設計

```
1. ユーザー → Relay₁:
   - TLS 接続（Relay₁ はユーザー IP を見る）
   - ペイロード: E(Relay₂_pubkey, query) + blind_signature_token
   - Relay₁ は query を復号できない（Relay₂ の鍵で暗号化）

2. Relay₁ → Relay₂:
   - 新規 TLS 接続（Relay₂ は Relay₁ の IP を見るが、ユーザー IP は見ない）
   - ペイロード: E(Relay₂_pubkey, query) そのまま転送
   - Relay₁ は一時 ID を割当て（ユーザーとの対応は保持しない）

3. Relay₂ → AI Compute:
   - query を復号
   - AI 推論を実行
   - 応答を E(session_key, response) で暗号化

4. 逆経路で応答をユーザーに返却:
   - Relay₂ → Relay₁: 暗号化応答
   - Relay₁ → User: 暗号化応答（Relay₁ は内容を見れない）
   - User: session_key で復号
```

#### 認証: RSA Blind Signatures

ユーザーが Relay₁ にリクエストする際の認証を Blind Signature で行い、Relay₁ がトークンとユーザーの対応を追跡できなくする:

$$
\begin{aligned}
\text{User}: & \quad m = \text{token\_request} \\
& \quad m' = m \cdot r^e \mod n \quad (\text{blinding}) \\
\text{Relay}_1: & \quad s' = (m')^d \mod n \quad (\text{signing}) \\
\text{User}: & \quad s = s' \cdot r^{-1} \mod n \quad (\text{unblinding}) \\
& \quad \text{verify}: s^e = m \mod n
\end{aligned}
$$

Relay₁ は有効なサブスクリプションを持つユーザーにトークンを発行するが、どのトークンがどのクエリに使われたかを知ることができない。

#### 脅威モデルとの対応

| 敵対者 | 攻撃 | KQR による防御 |
|--------|------|-------------|
| $\mathcal{A}_1$ (NW) | クエリ内容の傍受 | E2E 暗号化。Relay₁ への TLS + Relay₂ の公開鍵暗号化 |
| $\mathcal{A}_5$ (ベンダー) | ユーザーのクエリパターン追跡 | Blind Signature でトークンとユーザーの対応を切断 |
| Cloud Provider | クエリ内容からのプロファイリング | Relay₂ がユーザー ID を隠蔽。IP は Relay₂ のもの |

#### 攻撃面マッピング

- **S6 (Graph→NLQuery)**: クエリがクラウドに出る場合の経路を保護
- threat-model.md の $P_1$ (URL 秘匿) + $P_3$ (AI 推論タイミング秘匿) に貢献

### 3.3 先行技術分析

| 先行技術 | 関係性 | KQR の差分 |
|---------|--------|-----------|
| iCloud Private Relay | 直接のインスピレーション | Web 閲覧ではなく AI クエリ |
| Tor Onion Routing | 多段プロキシ | 3+ ホップの匿名性 vs 2 ホップのパフォーマンス |
| Apple Private Cloud Compute (PCC) | AI 推論のプライバシー | PCC は単一プロバイダ内。KQR は 2 者分離 |
| Oblivious HTTP (OHTTP, RFC 9458) | プロトコル仕様 | KQR の実装基盤として利用可能 |
| Privacy Pass (RFC 9578) | 匿名認証 | Blind Signature トークンの標準化仕様 |

**新規性評価: ★★★☆☆**

構成要素（OHTTP, Privacy Pass, dual-relay）は全て既存。新規なのは「知識グラフクエリ」への特化応用と、AI 推論を組み込んだ end-to-end プロトコル設計。iCloud Private Relay の Architecture Decision を AI クエリに適用する設計判断自体は明確だが、技術的新規性は限定的。

**実用的価値: ★★★★★** — Cloud AI 導入時に必須のインフラ。

---

## 4. Privilege-Separated Context Services (PSCS)

### 4.1 macOS のインスピレーション元: XPC Services

macOS XPC (Cross-Process Communication) の特徴:

- 各サービスは独立プロセスとして動作
- サービスごとに最小限のエンタイトルメント
- typed IPC (NSXPCConnection): インターフェイスプロトコルで型安全な通信
- 独立ライフサイクル: クラッシュが親に波及しない。launchd が自動再起動
- サンドボックスプロファイルがサービスごとに異なる

**Quira の現状:**
architecture.md は 12 のセキュリティメカニズムを定義するが、それらがどのプロセスで動作するかの分離モデルが明示されていない。Gecko の Fission がレンダラープロセスを分離するが、AI パイプライン・グラフエンジン・権限マネージャーのプロセス分離は未設計。

### 4.2 提案: Privilege-Separated Context Services (PSCS)

セキュリティクリティカルなコンポーネントを XPC スタイルのマイクロサービスに分解する。

#### サービス分解

```
┌──────────────────────────────────────────────────────────────────┐
│                      Browser Main Process                        │
│  ┌─────────────┐                                                 │
│  │  UI Shell   │ — タブバー、Space 切替、検索 UI                  │
│  └──────┬──────┘                                                 │
│         │ typed IPC                                               │
├─────────┼────────────────────────────────────────────────────────┤
│         │                                                        │
│  ┌──────▼──────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Graph       │  │ AI Pipeline │  │ Permission  │             │
│  │ Engine      │  │ Service     │  │ Manager     │             │
│  │             │  │             │  │             │             │
│  │ Caps:       │  │ Caps:       │  │ Caps:       │             │
│  │ - DB r/w    │  │ - Model r/o │  │ - TCC DB    │             │
│  │ - FTS5      │  │ - GPU/CPU   │  │ - Policy    │             │
│  │ - KPC keys  │  │ - Temp mem  │  │ - Audit log │             │
│  │             │  │ - No DB     │  │ - No graph  │             │
│  │             │  │ - No net    │  │ - No net    │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                      │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐             │
│  │ Export      │  │ Extension   │  │ Update      │             │
│  │ Service     │  │ Host        │  │ Service     │             │
│  │             │  │             │  │             │             │
│  │ Caps:       │  │ Caps:       │  │ Caps:       │             │
│  │ - Graph r/o │  │ - Ext r/w   │  │ - Net r/o   │             │
│  │ - File w/o  │  │ - Graph via │  │ - Code sign │             │
│  │ - Clipboard │  │   Graph Eng │  │ - Binaries  │             │
│  │ - No net    │  │ - Net (ext) │  │ - No graph  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└──────────────────────────────────────────────────────────────────┘
```

#### 権限マトリクス

| サービス | Graph DB | AI Model | Network | File System | GPU | TCC DB |
|---------|---------|---------|---------|------------|-----|--------|
| Graph Engine | R/W | - | - | - | - | R |
| AI Pipeline | - | R | - | - | R/W | - |
| Permission Manager | - | - | - | - | - | R/W |
| Export Service | R (via Graph Engine) | - | - | W (export) | - | R |
| Extension Host | via Graph Engine IPC | - | R/W (ext) | R/W (ext) | - | R |
| Update Service | - | - | R | W (binaries) | - | - |

#### 型安全 IPC プロトコル

Rust の trait でサービスインターフェイスを定義:

```rust
// Graph Engine Service Interface
trait GraphService {
    fn read_nodes(&self, query: GraphQuery, cap: Capability) -> Result<Vec<Node>, SecurityError>;
    fn write_node(&self, mutation: NodeMutation, cap: Capability) -> Result<NodeId, SecurityError>;
    fn query_fts(&self, text: &str, cap: Capability) -> Result<Vec<SearchResult>, SecurityError>;
}

// AI Pipeline Service Interface
trait AIPipelineService {
    fn extract_entities(&self, content: SanitizedContent) -> Result<Vec<Entity>, PipelineError>;
    fn generate_embedding(&self, text: &str) -> Result<Embedding384, PipelineError>;
    fn summarize(&self, content: SanitizedContent) -> Result<Summary, PipelineError>;
}
```

**制約: AI Pipeline は Graph DB に直接アクセスできない。** Graph Engine を経由しなければならない。これにより A2.1 (プロンプトインジェクション) が AI Pipeline を突破しても、直接 DB 書込みは不可能。

#### 脅威モデルとの対応

| 攻撃 | PSCS による防御 |
|------|---------------|
| AI Pipeline 侵害 → Graph 全体アクセス | AI Pipeline は DB アクセス権を持たない。Graph Engine IPC 経由のみ |
| Extension Host 侵害 → 鍵窃取 | KPC 鍵は Graph Engine プロセスのみが保持 |
| Permission Manager 侵害 → 権限昇格 | 権限変更は CSEB AUTH イベントで二重検証 |
| サービスクラッシュ → 全体停止 | 各サービスは独立プロセス。自動再起動 |

### 4.3 先行技術分析

| 先行技術 | 関係性 | PSCS の差分 |
|---------|--------|-----------|
| macOS XPC | 直接のインスピレーション | OS サービスではなくブラウザ内部コンポーネント |
| Chromium multi-process | プロセス分離 | Chromium はレンダラー/ブラウザ/GPU/Network プロセス。PSCS は Graph/AI/Permission を分離 |
| Fission (Firefox) | Site Isolation | Fission はレンダラーの分離。PSCS はバックエンドの分離 |
| Fuchsia Zircon | Handle-based capability IPC | 類似思想だが OS レベル。PSCS はブラウザ内 |
| qmail (D. J. Bernstein) | 権限分離メール配送 | 先駆的な権限分離設計。同じ哲学をブラウザに適用 |

**新規性評価: ★★★☆☆**

権限分離マイクロサービスの概念は成熟している（XPC, Fuchsia, qmail, Subprojects/privilege separation in OpenSSH）。新規なのは「Knowledge Graph Browser のバックエンド」という特定ドメインへの分解設計と、Graph Engine / AI Pipeline / Permission Manager という分離境界の定義。

**実装的価値: ★★★★★** — セキュリティアーキテクチャの基盤。他の全概念（KPC, CSEB, CTA 等）が正しく機能するための前提。

---

## 5. Sealed Knowledge Volume (SKV)

### 5.1 macOS のインスピレーション元: Sealed System Volume (SSV)

macOS Big Sur 以降、システムパーティションは Sealed System Volume として保護される:

- 全ファイルの SHA-256 ハッシュをリーフとする Merkle Tree を構築
- ブート時に Root Hash を Secure Enclave に保管された値と比較
- 任意のファイルの改竄は Root Hash の不一致として検出
- 読み取り専用マウント + Merkle 検証 = 暗号学的に改竄不可能

**Quira の CIP (Context Integrity Protection) との差分:**
CIP は Merkle Tree でグラフの整合性を保護する。しかし CIP の目的は「改竄検知」であり、SKV が提供する以下の機能は含まれていない:
- 特定時点のグラフ状態の暗号学的コミットメント（タイムスタンプ証明）
- 第三者に対する知識状態の検証可能な証明
- 選択的開示（グラフの一部のみを証明として提示）

### 5.2 提案: Sealed Knowledge Volume (SKV)

知識グラフの状態を暗号学的にコミットし、時点証明・選択的開示・非改竄証明を可能にする。

#### 形式的定義

時刻 $t$ におけるグラフ $G_t$ のシール:

$$\text{Seal}(G_t) = (R_t, \sigma_t, \text{ts}_t)$$

| 記号 | 定義 |
|------|------|
| $R_t$ | Merkle Root Hash: $R_t = \text{MerkleRoot}(\{H(v_i) \mid v_i \in V_t\} \cup \{H(e_j) \mid e_j \in E_t\})$ |
| $\sigma_t$ | Root Hash への署名: $\sigma_t = \text{Sign}(K_\text{user}, R_t \| \text{ts}_t)$ |
| $\text{ts}_t$ | タイムスタンプ（任意: 外部 TSA で RFC 3161 タイムスタンプ付与） |

#### ユースケース

**UC1: 研究優先性の証明**

「この知識ノードは時刻 $t$ に存在していた」を第三者に証明:

$$\text{Prove}(v_i, t) = (\text{MerklePath}(v_i, R_t), R_t, \sigma_t, \text{ts}_t)$$

検証:
1. $\text{MerklePath}(v_i, R_t)$ を再計算し $R_t$ と一致するか確認
2. $\sigma_t$ を公開鍵で検証
3. $\text{ts}_t$ の TSA 署名を検証

**UC2: 知識非保有の証明 (Proof of Absence)**

「時刻 $t$ にこのトピックのノードは存在しなかった」を証明:

Sparse Merkle Tree (SMT) を使用:

$$\text{ProveAbsence}(\text{topic}, t) = (\text{NonMembershipProof}(\text{topic}, \text{SMT}_t), R_t, \sigma_t)$$

利用場面: 法的紛争で「この情報にアクセスしていなかった」ことを証明。

**UC3: 増分シール (Incremental Sealing)**

全ノードを毎回ハッシュするのはコストが高い。増分更新:

$$R_{t+1} = \text{MerkleUpdate}(R_t, \Delta_t)$$

$\Delta_t$: 時刻 $t$ 以降に変更されたノード/エッジの集合。

#### 脅威モデルとの対応

| 敵対者 | 攻撃 | SKV による防御 |
|--------|------|-------------|
| $\mathcal{A}_4$ (OS) | Graph DB の改竄 | Seal されたグラフは Root Hash で検知可能 |
| $\mathcal{A}_5$ (ベンダー) | 過去データの遡及変更 | TSA タイムスタンプで改竄不可 |
| 第三者 | 研究成果の盗用主張 | UC1 で研究優先性を暗号学的に証明 |
| 法執行 | 情報アクセスの虚偽主張 | UC2 で非保有を証明 |

### 5.3 先行技術分析

| 先行技術 | 関係性 | SKV の差分 |
|---------|--------|-----------|
| macOS SSV | 直接のインスピレーション | システムファイルではなく知識グラフ。増分シール |
| Git (content-addressable) | ファイルの Merkle DAG | Git はバージョン管理。SKV はセキュリティ証明 |
| Bitcoin/Ethereum Merkle | トランザクション検証 | ブロックチェーンは分散合意。SKV はローカルファースト |
| CIP (Quira) | グラフの Merkle Tree | CIP は改竄検知のみ。SKV は時点証明 + 選択的開示 + 非保有証明 |
| RFC 3161 TSA | タイムスタンプ | SKV の構成要素として利用 |
| Certificate Transparency (CT) | 追記型ログ | CT は証明書。SKV は知識グラフ状態 |
| Verifiable Data Structures (VDS) | Google Trillian | 類似技術。SKV は Knowledge Graph に特化 |

**新規性評価: ★★★★☆**

Merkle Tree + TSA + 選択的開示の構成要素は全て既存。新規なのは:
- 知識グラフへの適用（ノード/エッジの Merkle Tree 構築方法）
- Proof of Absence の知識グラフ応用（特定トピックの非保有証明）
- 増分シールのグラフ特化アルゴリズム
- CIP との統合設計

---

## 6. Declarative Security Policy Language (DSPL)

### 6.1 macOS のインスピレーション元: Sandbox Profile Language + Launch Constraints

macOS の 2 つの宣言的セキュリティ機構:

**1. Sandbox Profile Language (sbpl):**
```scheme
(version 1)
(deny default)
(allow file-read* (subpath "/usr/lib"))
(allow network-outbound (remote tcp "example.com:443"))
(deny file-write* (subpath "/System"))
```

**2. Launch Constraints (macOS 13+):**
- self constraint: 自身のコード署名要件
- parent constraint: 起動元プロセスの要件
- responsible constraint: 責任プロセスの要件
- library constraint: ロード可能なライブラリの要件

**Quira の Context TCC との差分:**
Context TCC は個別のリソースごとに allow/deny のバイナリ判定を行う。ポリシーの合成（ユーザーポリシー + 組織ポリシー + デフォルト）、条件付きアクセス（「ネットワーク接続中のみ」等）、ポリシーの形式的検証が存在しない。

### 6.2 提案: Declarative Security Policy Language (DSPL)

知識グラフのアクセス制御を宣言的・合成可能な言語で記述する。

#### 文法 (EBNF 簡略版)

```ebnf
policy      = "policy" IDENT "{" rule+ "}"
rule        = effect subject action resource condition? ";"
effect      = "allow" | "deny" | "audit"
subject     = "extension" "(" IDENT ")" | "ai_pipeline" | "user" | "any"
action      = "read" | "write" | "delete" | "export" | "query" | "embed"
resource    = "nodes" filter? | "edges" filter? | "space" "(" IDENT ")" | "graph"
filter      = "where" predicate
predicate   = field_ref comparator value ("and" predicate)?
condition   = "when" context_predicate
context_pred= "network" "==" ("online"|"offline")
            | "auth_state" ">=" ("locked"|"session"|"space"|"foreground")
            | "time_since_auth" "<" DURATION
            | "kpc_class" "in" "{" class_list "}"
```

#### ポリシー例

```
// デフォルトポリシー（Quira が同梱）
policy quira_default {
  deny any export graph;                         // グラフ全体のエクスポートをデフォルト禁止
  allow user export nodes where count <= 100;    // ユーザーは100ノードまでエクスポート可能
  deny extension(any) read nodes where space.is_sensitive == true;
  allow ai_pipeline write nodes when auth_state >= space;
  audit any read nodes where tag contains "medical";
}

// ユーザーカスタムポリシー
policy user_custom {
  deny extension("social-share") read nodes where tag contains "medical"
    and read nodes where tag contains "financial";
  allow extension("research-helper") read nodes where space == "work";
  deny any export nodes when network == "online" and kpc_class in {A, B};
}

// 組織ポリシー（企業配布）
policy org_acme {
  deny any export graph;
  deny any write nodes when time_since_auth > 30m;
  audit any read nodes where tag contains "confidential";
}
```

#### ポリシー合成

複数ポリシーの合成規則:

$$\text{Decision}(s, a, r, c) = \text{Compose}(P_\text{org}, P_\text{user}, P_\text{default})$$

合成戦略:

1. **deny-override**: いずれかのポリシーが deny なら deny（最も保守的）
2. **最高権限優先**: org > user > default の順で最初に明示的判定を返したものを採用
3. **明示 deny > 明示 allow > デフォルト deny** (closed-world assumption)

#### 形式的検証

ポリシーの矛盾・不完全性を静的に検出:

| 検査 | 意味 | 形式化 |
|------|------|--------|
| 矛盾検出 | 同一 (s,a,r,c) に allow と deny が同時定義 | $\exists x: P_1(x) = \text{allow} \land P_2(x) = \text{deny}$ |
| 冗長検出 | あるルールが別ルールに完全に包含される | $\forall x: R_1(x) \Rightarrow R_2(x)$ |
| 網羅性検証 | 全ての (s,a,r) 組合わせに判定が存在する | $\forall (s,a,r): \exists P: P(s,a,r) \neq \bot$ |
| 情報漏洩検出 | allow の組合わせで意図しないデータフローが発生 | IFC ラベル格子との整合性チェック |

### 6.3 先行技術分析

| 先行技術 | 関係性 | DSPL の差分 |
|---------|--------|-----------|
| macOS sbpl | 直接のインスピレーション | ファイル/ネットワークではなくグラフ操作 |
| XACML (OASIS) | 標準的アクセス制御ポリシー言語 | XML ベースの汎用仕様。DSPL はグラフ操作に特化 |
| OPA / Rego | 汎用ポリシーエンジン | Rego は Datalog ベース。DSPL はドメイン特化で学習コスト低 |
| Cedar (AWS) | 型安全ポリシー言語 | 最も近い先行技術。DSPL は知識グラフ固有の述語を持つ |
| SELinux / AppArmor | MAC (Mandatory Access Control) | OS レベル。DSPL はアプリケーションレベル |
| CSS (analogy) | 宣言的スタイリング | カスケード合成の思想が類似 |

**新規性評価: ★★☆☆☆**

Cedar (AWS, 2023) がほぼ同じ問題空間を解決している。ドメイン特化の述語（`kpc_class`, `space.is_sensitive`, `tag contains "medical"`）は新しいが、言語自体の設計パターンは既存。

**検討:** Cedar を直接採用し、Quira 固有の Entity/Action/Resource 定義のみをカスタマイズする方が実装コスト・信頼性ともに優れる可能性が高い。

---

## 7. Context Trust Arbiter (CTA)

> **アーキテクチャ関係:** CTA は radical-architecture.md **Paradigm 1 (Capability-Based Security)** の信頼判定インフラ。Paradigm 1 がケーパビリティの発行・委譲・失効の原理を定義し、CTA はその判定を一元化する Single Point of Decision として機能する。AMFI が macOS で果たす役割を、Quira のコンテキストグラフ上で再現する。

### 7.1 macOS のインスピレーション元: AMFI (Apple Mobile File Integrity)

AMFI はユーザースペースデーモンとして動作し、以下の信頼判定を一元化する:

- コード署名ポリシーの判定（開発者署名、App Store、Notarization）
- エンタイトルメントの検証
- Launch Constraints の評価
- ライブラリ検証の判定
- カーネルの `mac_vnode_check_signature` への応答

AMFIは信頼判定の「Single Point of Decision」であり、個々のサブシステムが独自に信頼判定を行わない。

**Quira の現状:**
各セキュリティメカニズム（Gatekeeper, TCC, CIP, Sandbox 等）が独立に判定を行う。これには以下のリスクがある:
- 判定基準の不整合（TCC は allow だが Sandbox が deny するケース）
- TOCTOU (Time-of-check to time-of-use) 問題
- 監査の困難さ（判定ログが分散）

### 7.2 提案: Context Trust Arbiter (CTA)

全セキュリティ判定を一元化するデーモン。

#### アーキテクチャ

```
┌─────────────────────────────────────────────────────────┐
│  Requesting Component (Graph Engine / AI Pipeline / ...) │
│      "Can extension X read space Y's medical nodes?"     │
└────────────────────────────┬────────────────────────────┘
                             │ Trust Query
                             ▼
┌─────────────────────────────────────────────────────────┐
│                Context Trust Arbiter (CTA)               │
│                                                          │
│  1. Extension Identity Verification                      │
│     └→ Code Signing + Integrity Check                    │
│                                                          │
│  2. Capability Evaluation                                │
│     └→ Extension capabilities vs. requested action       │
│                                                          │
│  3. TCC Permission Check                                 │
│     └→ User consent for this resource                    │
│                                                          │
│  4. DSPL Policy Evaluation                               │
│     └→ Composed policy (org > user > default)            │
│                                                          │
│  5. KPC State Check                                      │
│     └→ Target data's protection class + current state    │
│                                                          │
│  6. CSEB Context Check                                   │
│     └→ Recent event patterns (rate limit, anomaly)       │
│                                                          │
│  Result: ALLOW / DENY / PROMPT_USER                      │
│  + Audit Record → append-only log                        │
└─────────────────────────────────────────────────────────┘
```

#### 判定ロジックの形式化

信頼判定関数 $\text{Decide}: Q \to \{\text{allow}, \text{deny}, \text{prompt}\}$:

$$\text{Decide}(q) = \begin{cases}
\text{deny} & \text{if } \neg \text{VerifyIdentity}(q.\text{subject}) \\
\text{deny} & \text{if } \neg \text{HasCapability}(q.\text{subject}, q.\text{action}) \\
\text{deny} & \text{if } \neg \text{TCCApproved}(q.\text{subject}, q.\text{resource}) \\
\text{deny} & \text{if } \text{DSPL}(q) = \text{deny} \\
\text{deny} & \text{if } \text{KPCState}(q.\text{resource}) > q.\text{auth\_level} \\
\text{deny} & \text{if } \text{CSEBAnomaly}(q.\text{subject}) \\
\text{prompt} & \text{if any check returns "needs\_consent"} \\
\text{allow} & \text{otherwise}
\end{cases}$$

チェックは短絡評価（最初の deny で即座に返却、ALLOW は全チェック通過が必要）。

#### 他の提案との統合

CTA は本文書の他の全提案の「統合ハブ」として機能する:

| 提案 | CTA での検証項目 |
|------|----------------|
| KPC (§1) | ステップ 5: リクエストされたデータの保護クラスに対し、現在の認証状態が十分か |
| CSEB (§2) | ステップ 6: 直近のイベントパターンに異常がないか |
| PSCS (§4) | CTA 自体が独立プロセスとして動作 |
| SKV (§5) | CTA が Seal 操作への署名権限を一元管理 |
| DSPL (§6) | ステップ 4: 合成ポリシーの評価 |
| ASP (§8) | CTA の判定閾値を ASP が動的に調整 |

### 7.3 先行技術分析

| 先行技術 | 関係性 | CTA の差分 |
|---------|--------|-----------|
| AMFI | 直接のインスピレーション | OS のコード署名ではなくブラウザのグラフアクセス |
| PDP (XACML Policy Decision Point) | アクセス制御の一元化 | 概念的に同一パターン。CTA は PDP + 追加コンテキスト（KPC, CSEB） |
| OPA Decision Engine | 一元的ポリシー判定 | CSEB イベントコンテキストの統合が独自 |

**新規性評価: ★★★☆☆**

Policy Decision Point の一元化は XACML で標準化済み。CTA が新しいのは、KPC (状態ベース暗号化) + CSEB (リアルタイムイベント) + DSPL (宣言的ポリシー) という Knowledge Graph Browser 固有の判定要素の統合。パターンとしてはよく知られているが、統合対象のドメイン特殊性に価値がある。

---

## 8. Adaptive Security Posture (ASP)

### 8.1 macOS のインスピレーション元: セキュリティ状態遷移

macOS のセキュリティ状態は段階的だが、ほぼ離散的:
- 通常モード → Lockdown Mode（バイナリ切替）
- FileVault 有効/無効
- SIP 有効/無効
- セキュリティレベル: Full Security / Reduced Security / Permissive Security（Apple Silicon Mac）

これらは手動切替であり、環境に応じた自動適応は行わない。

**Quira の Context Lockdown Mode との差分:**
Context Lockdown Mode は「通常モード」と「ロックダウンモード」の二値切替。中間状態が存在しない。例えば「公衆 WiFi では AI クラウド推論を無効化するが、インデックス検索は許可」のような段階的な適応ができない。

### 8.2 提案: Adaptive Security Posture (ASP)

環境シグナルに基づいてセキュリティレベルを連続的に調整するシステム。

#### 形式的定義

セキュリティポスチャ $\pi \in [0.0, 1.0]$:

$$\pi(t) = f(\text{signals}(t))$$

| $\pi$ 範囲 | セキュリティレベル | 動作の変化 |
|-----------|----------------|----------|
| $[0.0, 0.2]$ | Lockdown | Context Lockdown Mode 相当。AI 無効、エクスポート禁止、拡張無効 |
| $(0.2, 0.4]$ | High Alert | Cloud AI 禁止、ローカル AI のみ、エクスポートにユーザー確認 |
| $(0.4, 0.6]$ | Elevated | 拡張のグラフアクセスにレート制限強化、KPC-A を自動適用 |
| $(0.6, 0.8]$ | Normal | デフォルト設定 |
| $(0.8, 1.0]$ | Relaxed | ユーザー承認済み環境。パフォーマンス優先のキャッシュ緩和 |

#### 環境シグナル

| シグナル | 重み | 取得方法 | 影響方向 |
|---------|------|---------|---------|
| ネットワーク種別 | 高 | OS API | 公衆WiFi → $\pi \downarrow$、自宅LAN → $\pi \uparrow$ |
| 認証経過時間 | 中 | 内部タイマー | 長時間 → $\pi \downarrow$ |
| 外部デバイス接続 | 中 | OS API | 不明 USB → $\pi \downarrow$ |
| 更新状態 | 中 | Update Service | 未更新期間長 → $\pi \downarrow$ |
| 異常イベント (CSEB) | 高 | CSEB 統計 | 異常検知 → $\pi \downarrow$ |
| 拡張のインストール状態 | 低 | Extension Host | 未検証拡張あり → $\pi \downarrow$ |
| OS セキュリティ状態 | 低 | OS API (可能な場合) | FDE 無効 → $\pi \downarrow$ |

#### ポスチャ計算

重み付きシグモイド集約:

$$\pi(t) = \sigma\left(\sum_i w_i \cdot s_i(t) + b\right)$$

$\sigma$: シグモイド関数。$w_i$: シグナル重み。$s_i(t) \in [-1, 1]$: 正規化シグナル値。$b$: バイアス（ユーザー設定のベースライン）。

#### CTA への統合

ASP は CTA の判定閾値を動的に調整する:

```
CTA.Decide(q):
  ...
  // ASP によるコンテキスト調整
  if asp.posture < 0.4:
    if q.action == "export" or q.action == "cloud_ai":
      return DENY  // High Alert 以下ではエクスポートと Cloud AI を禁止
  if asp.posture < 0.6:
    if q.subject.type == "extension":
      rate_limit = default_rate_limit * (asp.posture / 0.6)  // レートリミット強化
  ...
```

#### 脅威モデルとの対応

| 敵対者 | シナリオ | ASP による防御 |
|--------|---------|-------------|
| $\mathcal{A}_1$ (NW) | 公衆WiFiでの傍受 | ネットワーク種別シグナルで $\pi \downarrow$ → Cloud AI 禁止 |
| $\mathcal{A}_2$ (Web) | 集中的プロンプトインジェクション | CSEB 異常シグナルで $\pi \downarrow$ → AI パイプライン制限強化 |
| $\mathcal{A}_4$ (OS) | デバイス窃取後の攻撃 | 認証経過時間シグナルで $\pi \downarrow$ → KPC-A 自動適用 |
| $\mathcal{A}_3$ (拡張) | 環境脆弱性を利用した攻撃 | 複合シグナルで拡張のアクセスを自動制限 |

### 8.3 先行技術分析

| 先行技術 | 関係性 | ASP の差分 |
|---------|--------|-----------|
| macOS Lockdown Mode | 部分的インスピレーション | バイナリ切替 → 連続スペクトラム |
| Android Work Profile | 環境ベース分離 | 個人/仕事で切替。ASP はリアルタイム連続調整 |
| RAdAC (NIST) | リスク適応型アクセス制御 | ASP の直接的先行概念。RAdAC はポリシー指向、ASP は環境シグナル集約 |
| Zero Trust Architecture | 環境に基づく信頼判定 | ZTA の "never trust, always verify" を定量化 |
| novel-research.md STS (§2) | 意味論的信頼スコア | STS はノード/エッジの信頼度。ASP はシステム全体のセキュリティ状態 |

**新規性評価: ★★★☆☆**

RAdAC (Risk-Adaptable Access Control, NIST SP 800-162 に関連) が最も近い先行技術。ASP が追加するのは:
- CSEB との統合（リアルタイムイベントパターンによるポスチャ調整）
- KPC との連動（ポスチャに応じた保護クラスの自動引き上げ）
- Knowledge Graph Browser 固有のシグナル定義

---

## 9. 提案の優先順位と実装計画

### 9.1 優先順位マトリクス

| 提案 | 新規性 | 実装価値 | 他提案への依存 | 被依存 | 推奨フェーズ |
|------|--------|---------|-------------|--------|-----------|
| **PSCS (§4)** | ★★★ | ★★★★★ | なし | KPC, CSEB, CTA, DSPL | **Phase 1** |
| **CSEB (§2)** | ★★★★★ | ★★★★★ | PSCS | CTA, ASP | **Phase 1** |
| **KPC (§1)** | ★★★★ | ★★★★ | PSCS | CTA, ASP | **Phase 2** |
| **CTA (§7)** | ★★★ | ★★★★ | PSCS, CSEB, KPC | ASP | **Phase 2** |
| **SKV (§5)** | ★★★★ | ★★★ | PSCS | なし | **Phase 2** |
| **ASP (§8)** | ★★★ | ★★★★ | CTA, CSEB | なし | **Phase 3** |
| **DSPL (§6)** | ★★ | ★★★ | CTA | なし | **Phase 3** |
| **KQR (§3)** | ★★★ | ★★★★★ | なし | なし | **Phase 4** (Cloud AI 導入時) |

### 9.2 依存関係グラフ

```
Phase 1:  PSCS ─────┬──→ CSEB
                     │
Phase 2:  KPC ◄──────┤
          SKV        ├──→ CTA
                     │
Phase 3:  ASP ◄──────┤
          DSPL ◄─────┘

Phase 4:  KQR (独立、Cloud AI 導入時)
```

### 9.3 新規性サマリ

| 概念 | 学術的新規性 | 実装/応用新規性 | ブラウザでの前例 | 総合評価 |
|------|------------|-------------|---------------|---------|
| **CSEB** | 高 | 高 | なし | 最も新規性が高い |
| **KPC** | 中（iOS DPの翻訳） | 高 | なし | 応用新規性が高い |
| **SKV** | 中（Merkle+TSA） | 高 | なし | ユースケース新規 |
| **ASP** | 低（RAdAC） | 中 | なし | 統合設計に価値 |
| **PSCS** | 低（XPC翻訳） | 高 | Chrom/Firefoxは別の分離 | 基盤として必須 |
| **CTA** | 低（PDP） | 中 | なし | 統合ハブとして必須 |
| **DSPL** | 低（Cedar/XACML） | 低 | なし | Cedar採用を推奨 |
| **KQR** | 低（Private Relay翻訳） | 中 | なし | Cloud AI時に必須 |

---

## 10. threat-model.md との対応マップ

本文書の 8 提案が threat-model.md の各要素をどうカバーするかの完全マッピング:

### 10.1 敵対者クラスへの対応

| 提案 | $\mathcal{A}_1$ (NW) | $\mathcal{A}_2$ (Web) | $\mathcal{A}_3$ (Ext) | $\mathcal{A}_4$ (OS) | $\mathcal{A}_5$ (Vendor) |
|------|------|------|------|------|------|
| KPC  | - | - | 高 | **極高** | - |
| CSEB | - | 高 | **極高** | - | - |
| KQR  | **極高** | - | - | - | 高 |
| PSCS | - | 高 | 高 | 中 | - |
| SKV  | - | - | - | 高 | **高** |
| DSPL | - | 中 | 高 | - | - |
| CTA  | - | 中 | 高 | 中 | - |
| ASP  | 高 | 中 | 高 | 高 | - |

### 10.2 攻撃面への対応

| 提案 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 |
|------|----|----|----|----|----|----|----|----|----|----|
| KPC  | - | - | - | - | - | - | ++ | + | - | + |
| CSEB | - | ++ | ++ | ++ | ++ | + | - | - | - | - |
| KQR  | - | - | - | - | - | ++ | - | - | - | - |
| PSCS | - | ++ | ++ | ++ | + | + | + | - | - | - |
| SKV  | - | - | - | - | + | - | + | - | + | - |
| DSPL | - | - | - | ++ | ++ | + | - | - | - | - |
| CTA  | - | + | + | ++ | ++ | + | - | - | - | + |
| ASP  | + | + | + | + | + | + | + | - | - | + |

`++`: 主要防御、`+`: 補助防御、`-`: 対象外

### 10.3 未カバー攻撃面

**S8 (Memory→DMA)** は本文書の全提案でカバーされない。これは hardware-level の防御（TME/SME, IOMMU）が必要であり、architecture.md の Phase 3 で対処予定。

**S9 (Update→Code)** は SKV が部分的にカバーするが、主要防御は既存の Context Code Signing + Reproducible Build に委ねる。
