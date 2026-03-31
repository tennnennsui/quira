# Quira Browser — Formal Threat Model

> Version: 1.0 | Date: 2026-03 | Status: Research Draft
> Scope: Knowledge Graph Browser の形式的セキュリティ分析基盤

---

## 0. 本ドキュメントの位置づけ

セキュリティ研究を学術的に成立させるために、全防御メカニズムの前提となる**形式的脅威モデル**を定義する。個々のパラダイム（radical-architecture.md）や新規概念（novel-research.md）は、本モデルの上に構築される。

参照関係:
```
threat-model.md （本文書 — 基盤）
  ├── architecture.md （macOS 着想の防御マッピング）
  ├── radical-architecture.md （8パラダイム — 防御メカニズム設計）
  ├── research.md （SOTA 調査 + Context Security 定義）
  └── novel-research.md （新規研究概念 — 再評価済み）
```

---

## 1. 資産定義 (Asset Definition)

### 1.1 知識グラフの形式的定義

Quira の知識グラフ $G$ を以下で定義する:

$$G = (V, E, \Sigma, \Phi, \Tau)$$

| 記号 | 定義 |
|------|------|
| $V = \{v_1, v_2, \ldots, v_n\}$ | ノード集合。各 $v_i$ は 1 ページ訪問に対応 |
| $E \subseteq V \times V \times L_E$ | ラベル付き有向エッジ集合。$L_E = \{\text{navigation}, \text{ai\_inferred}, \text{user\_created}\}$ |
| $\Sigma: V \to \mathcal{S}$ | 各ノードの構造化属性への写像 |
| $\Phi: V \to \mathbb{R}^{384}$ | 各ノードの埋め込みベクトルへの写像 |
| $\Tau: V \to \mathcal{T}$ | 各ノードの時間メタデータへの写像 |

ノード属性空間 $\mathcal{S}$:

$$\mathcal{S} = \{(\text{title}, \text{url}, \text{summary}, \text{entities}, \text{tags}, \text{notes}, \text{space\_id})\}$$

時間属性空間 $\mathcal{T}$:

$$\mathcal{T} = \{(\text{visit\_timestamps}[], \text{dwell\_time}, \text{visit\_count}, \text{first\_visited}, \text{last\_visited})\}$$

### 1.2 資産の機密度階層

**構成的機密性原理 (Compositional Sensitivity Principle)**:

個々のデータポイントの機密度 $s(x)$ と、それらの集合体の機密度 $S(X)$ の関係:

$$S(X) \gg \sum_{x \in X} s(x)$$

単一ページ訪問は低機密だが、グラフ全体は極めて高機密。機密度は加算的ではなく超加算的 (super-additive) である。

| 資産 | 記号 | 機微度 | 理由 |
|------|------|--------|------|
| 個別ノード内容 | $v_i.\text{summary}$ | 低 | 公開Webコンテンツの要約 |
| エンティティ集合 | $\bigcup_i v_i.\text{entities}$ | 中 | 関心分野の部分的プロファイル |
| エッジ集合 (navigation) | $E_\text{nav} \subset E$ | 高 | 思考の流れ = 研究経路の完全記録 |
| 埋め込みベクトル | $\Phi(V)$ | 高 | コンテンツのinversion攻撃が可能 |
| 時間メタデータ | $\Tau(V)$ | 高 | 行動パターンの完全タイムライン |
| グラフトポロジー | $(V, E)$ の構造 | 極高 | 個人を一意に識別可能（認知フィンガープリント） |
| グラフ全体 | $G$ | 極高 | 上記全てを含む個人知識の完全表現 |

### 1.3 派生資産

グラフ $G$ から暗黙的に導出される資産:

| 派生資産 | 導出方法 | 機微度 |
|---------|---------|--------|
| 認知プロファイル | トピック頻度分布 + 時間パターン + 遷移確率 | 極高 |
| 研究動態 | $E_\text{nav}$ の時系列解析 | 高 |
| 関心分野ベクトル | $\Phi(V)$ のクラスタ重心集合 | 高 |
| 社会グラフ断片 | 人物エンティティの共起分析 | 中〜高 |
| 職業・専門性推定 | トピック分布 + 深度分析 | 高 |

---

## 2. 敵対者モデル (Adversary Model)

### 2.1 敵対者の形式的定義

敵対者 $\mathcal{A}$ を三つ組で定義する:

$$\mathcal{A} = (\mathcal{C}, \mathcal{G}, \mathcal{K})$$

| 記号 | 定義 |
|------|------|
| $\mathcal{C}$ | 能力集合 (Capability Set) — 敵対者が実行可能な操作 |
| $\mathcal{G}$ | 目標 (Goal) — 達成しようとするセキュリティ違反 |
| $\mathcal{K}$ | 事前知識 (Prior Knowledge) — 攻撃前に保有する情報 |

### 2.2 敵対者クラス (Adversary Classes)

5段階の敵対者クラスを定義する。上位は下位の能力を包含する。

#### Class 1: ネットワーク観察者 (Network Observer)

$$\mathcal{A}_1 = (\mathcal{C}_1, \mathcal{G}_1, \mathcal{K}_1)$$

| 項目 | 定義 |
|------|------|
| $\mathcal{C}_1$ | ネットワークトラフィックの受動的観察。DNS クエリ、TLS SNI、パケットサイズ/タイミングを観測可能。ペイロードは TLS により暗号化済み |
| $\mathcal{G}_1$ | ユーザーの閲覧対象の推定、行動パターンの時間的プロファイリング |
| $\mathcal{K}_1$ | ユーザーの IP アドレス、ISP 情報、DNS リゾルバ設定 |
| 例 | ISP、公衆WiFi運営者、国家レベルネットワーク監視 |

**$\mathcal{A}_1$ から保護すべき性質:**
- $P_1$: 訪問先 URL の秘匿（ECH/ESNI 依存）
- $P_2$: Context Graph の操作タイミングの秘匿（バッチ処理による）
- $P_3$: AI推論のタイミングから閲覧内容を推定されない

#### Class 2: 悪意ある Web コンテンツ (Malicious Web Content)

$$\mathcal{A}_2 = (\mathcal{C}_2, \mathcal{G}_2, \mathcal{K}_2)$$

| 項目 | 定義 |
|------|------|
| $\mathcal{C}_2$ | 任意の HTML/CSS/JS をレンダラプロセス内で実行。不可視テキスト、メタデータ操作、CSS トリック、Unicode 操作が可能。ただし Gecko サンドボックスの外には直接アクセス不可 |
| $\mathcal{G}_2$ | AI パイプラインへのプロンプトインジェクション、エンティティポイズニング、埋め込み空間操作、認知フィンガープリント採取 |
| $\mathcal{K}_2$ | Quira の公開されたアーキテクチャ設計（本リポジトリ）、AI モデルの仕様（公開モデル使用時） |
| 例 | フィッシングサイト、広告ネットワーク、国家レベル情報操作 |

**$\mathcal{A}_2$ 固有の攻撃ベクトル:**

| ID | 攻撃 | 形式的定義 |
|----|------|----------|
| A2.1 | プロンプトインジェクション | 入力 $x$ に命令 $i$ を埋め込み、AI出力 $f(x) \neq f(x \setminus i)$ を引き起こす |
| A2.2 | エンティティポイズニング | 偽エンティティ $e^* \notin \text{visible}(x)$ を抽出させ、$v_i.\text{entities}$ を汚染 |
| A2.3 | 埋め込み空間操作 | ページ内容を操作し $\Phi(v_\text{malicious}) \approx \Phi(v_\text{target})$ を達成、類似度検索結果を汚染 |
| A2.4 | 認知フィンガープリント採取 | JS API（タイミング、インタラクション）を通じてユーザーの認知パターンを推定 |
| A2.5 | クラスタ重心シフト | $N$ ページにわたるコンテンツ操作で、特定クラスタの重心 $\mu_c$ を $\mu_c + \delta$ へシフト |

#### Class 3: 悪意ある拡張機能 (Malicious Extension)

$$\mathcal{A}_3 = (\mathcal{C}_3, \mathcal{G}_3, \mathcal{K}_3)$$

| 項目 | 定義 |
|------|------|
| $\mathcal{C}_3$ | WebExtensions API の範囲内で動作。宣言した権限（tabs, storage, webRequest 等）を保有。更新時にコードを変更可能。ネットワーク送信可能 |
| $\mathcal{G}_3$ | Context Graph の窃取（部分的または全体）、データ外部送信、グラフ操作、サイレントプロファイリング |
| $\mathcal{K}_3$ | Context Graph API の仕様、ユーザーが付与した権限の範囲、拡張のローカルストレージへのアクセス |
| 例 | サプライチェーン攻撃で改竄された正規拡張、最初から悪意を持つ拡張、買収後に悪意コードを注入された拡張 |

**$\mathcal{A}_3$ 固有の攻撃パターン:**

| ID | 攻撃 | 検出困難性 |
|----|------|----------|
| A3.1 | 一括グラフ読取 + ネットワーク送信 | 低（量的異常） |
| A3.2 | 徐々に読取頻度を上昇（boiling frog） | 中（長期トレンド分析が必要） |
| A3.3 | グラフデータをローカルストレージに蓄積し定期送信 | 中（ストレージ-ネットワーク相関分析が必要） |
| A3.4 | Read-then-Send: グラフ読取直後にネットワーク送信 | 低（時間相関検出） |
| A3.5 | 正規 API でメタデータのみ収集（ノード数、トピック分布） | 高（メタデータ自体が有用な情報） |

#### Class 4: OS 権限を持つ攻撃者 (OS-Level Adversary)

$$\mathcal{A}_4 = (\mathcal{C}_4, \mathcal{G}_4, \mathcal{K}_4)$$

| 項目 | 定義 |
|------|------|
| $\mathcal{C}_4$ | ファイルシステムへの読取アクセス（SQLite DB直接読取）、プロセスメモリダンプ、DMA攻撃（物理アクセス時）、コールドブート攻撃 |
| $\mathcal{G}_4$ | 暗号化されたグラフDBの復号、メモリ上の復号済みデータの窃取、暗号鍵の取得 |
| $\mathcal{K}_4$ | ファイルシステム構造、SQLite DB のスキーマ（OSS公開）、暗号化方式 |
| 例 | マルウェア、ルートキット、物理的デバイス窃取、フォレンジック調査者 |

**$\mathcal{A}_4$ に対する防御要件:**
- ディスク上のDBは常に暗号化
- メモリ上の復号データは最小限（アクティブタブのみ）
- 鍵はプラットフォームキーチェーン / TEE に保管
- Dead Man's Switch: 無認証状態が継続すれば鍵を自動消去

#### Class 5: ブラウザベンダー自身 (Browser Vendor)

$$\mathcal{A}_5 = (\mathcal{C}_5, \mathcal{G}_5, \mathcal{K}_5)$$

| 項目 | 定義 |
|------|------|
| $\mathcal{C}_5$ | コードの変更、テレメトリの追加、更新の配布、サーバーサイドの変更。OSS であるため全コードは公開監査可能 |
| $\mathcal{G}_5$ | ユーザーデータの収集、プロファイリング、第三者への販売（意図的 or 法的強制） |
| $\mathcal{K}_5$ | 全ソースコード、全アーキテクチャ |
| 例 | 経営陣の変更、買収、法執行機関からの要請 |

**$\mathcal{A}_5$ に対する構造的防御:**
- ローカルファースト: デフォルトでデータがデバイスから出ない
- OSS: コード変更は公開 Git 履歴で追跡可能
- 再現可能ビルド: バイナリとソースの対応を第三者検証可能
- テレメトリはオプトイン + 差分プライバシー（公開 $\varepsilon$ 値）

---

## 3. セキュリティ特性の形式的定義

### 3.1 機密性 (Confidentiality)

**定義 (Graph Confidentiality):**

敵対者 $\mathcal{A}$ がグラフ $G$ へのアクセスを試みた場合、$\mathcal{A}$ の能力 $\mathcal{C}$ で許可された操作を超えるノード・エッジ・属性を取得できない。

$$\forall \mathcal{A}, \forall q \in \text{Queries}(\mathcal{A}): \text{result}(q, G) \subseteq \text{Authorized}(\mathcal{A}, G)$$

IFC ラベル $\ell$ を持つデータ $d$ について:

$$\text{flow}(d, \text{destination}) \Rightarrow \ell(d) \sqsubseteq \text{clearance}(\text{destination})$$

$\sqsubseteq$ はラベル格子上の順序関係。高機密データは低クリアランスの宛先に流れない。

### 3.2 完全性 (Integrity)

**定義 (Graph Integrity):**

外部入力（Web コンテンツ、拡張、ネットワーク）は、検証レイヤーを経由せずにグラフを変更できない。

$$\forall \text{mutation} \in \text{Mutations}(G): \text{mutation} = \text{Validate}(\text{raw\_mutation})$$

検証関数 $\text{Validate}$ は以下を保証する:
1. エンティティは可視テキストから導出されている
2. 要約はスキーマに適合し、異常エントロピーを持たない
3. 埋め込みはドメインの統計分布内にある

### 3.3 推論耐性 (Inference Resistance)

**定義:**

敵対者 $\mathcal{A}$ が部分情報 $G' \subset G$ にアクセスした場合、$G \setminus G'$（未アクセス部分）についての推論利得が有界である。

差分プライバシーの枠組みで:

$$\Pr[\mathcal{M}(G) \in S] \leq e^\varepsilon \cdot \Pr[\mathcal{M}(G') \in S] + \delta$$

ここで $\mathcal{M}$ は出力メカニズム（エクスポート、分析、共有）、$\varepsilon$ はプライバシー予算、$\delta$ は失敗確率。

具体的に保護すべき推論:

| 推論 | 保護メカニズム | 目標 |
|------|-------------|------|
| メタデータからの認知プロファイル再構成 | 時間ジッタリング + バッチ処理 | 識別率 $< 1/k$（$k$-匿名性） |
| 埋め込みベクトルからのテキスト復元 | ノイズ注入 $\Phi'(v) = \Phi(v) + \mathcal{N}(0, \sigma^2 I)$ | 復元 BLEU $< 0.1$ |
| グラフトポロジーからの個人識別 | ファントムノード注入 | 構造的 $k$-匿名性 $\geq 50$ |
| エクスポートデータからの非公開ノード推定 | エッジ差分プライバシー | $\varepsilon \leq 1.0$ |

### 3.4 可用性 (Availability)

**定義:**

セキュリティメカニズムは通常の利用を妨げない。

$$\text{latency}(\text{secured\_operation}) \leq \alpha \cdot \text{latency}(\text{unsecured\_operation})$$

目標: $\alpha \leq 1.05$（セキュリティオーバーヘッド5%以下）。ただし:
- 暗号化 DB アクセス: $\alpha \leq 1.10$
- IFC ラベルチェック: $\alpha \leq 1.02$
- 行動ベースライン比較: 非同期（$\alpha = 1.00$）

### 3.5 検証可能性 (Verifiability)

**定義:**

AI パイプラインの全出力に対し、ユーザーまたは外部監査者が以下を検証可能:

$$\text{Verify}(\text{output}, \text{provenance\_record}) \to \{\text{valid}, \text{invalid}\}$$

provenance record の構成:

$$\text{prov}(o) = (\text{H}(input), \text{H}(model), \text{H}(system\_prompt), \text{H}(o), t, \text{params})$$

$\text{H}$: SHA-256。$t$: タイムスタンプ。$\text{params}$: 推論パラメータ。

---

## 4. 攻撃面分析 (Attack Surface Analysis)

### 4.1 攻撃面の分類

```
┌──────────────────────────────────────────────────────────────────┐
│                     QUIRA 攻撃面マップ                           │
├────────────────────┬─────────────────────────────────────────────┤
│ 攻撃面             │ 信頼境界                                    │
├────────────────────┼─────────────────────────────────────────────┤
│ S1: Web → Renderer │ Gecko Fission プロセス境界                  │
│ S2: Renderer → AI  │ IPC + コンテンツ消毒パイプライン            │
│ S3: AI → Graph     │ 出力スキーマ検証 + IFCラベル付与            │
│ S4: Extension → Graph │ Capability Gateway + Context TCC         │
│ S5: Graph → Export │ 差分プライバシー + プライバシーレビュー      │
│ S6: Graph → NLQuery│ サマリーのみ使用 + プロンプト分離           │
│ S7: Disk → Memory  │ SQLCipher + プラットフォームキーチェーン    │
│ S8: Memory → DMA   │ TME/SME + IOMMU                            │
│ S9: Update → Code  │ コード署名 + 再現可能ビルド                 │
│ S10: User → Graph  │ 認証 + Dead Man's Switch                    │
└────────────────────┴─────────────────────────────────────────────┘
```

### 4.2 攻撃面ごとのリスク評価

| 攻撃面 | 対応敵対者 | 発生確率 | 影響度 | リスク | 既存防御 | 追加研究 |
|--------|----------|---------|--------|--------|---------|---------|
| S2: Renderer→AI | $\mathcal{A}_2$ | 高 | 高 | **Critical** | コンテンツ消毒 | Inverse Sandboxing (出力制限) |
| S4: Extension→Graph | $\mathcal{A}_3$ | 高 | 極高 | **Critical** | Capability + TCC | AI 行動監視 |
| S6: Graph→NLQuery | $\mathcal{A}_2$ | 中 | 高 | **High** | サマリーのみ使用 | クエリ結果のprovenance強化 |
| S5: Graph→Export | $\mathcal{A}_1$ | 中 | 高 | **High** | — | 認知FP耐性 + トポロジー難読化 |
| S7: Disk→Memory | $\mathcal{A}_4$ | 中 | 極高 | **High** | SQLCipher | 閾値暗号 + TEE |
| S3: AI→Graph | $\mathcal{A}_2$ | 中 | 中 | **Medium** | スキーマ検証 | エントロピー制限 |
| S8: Memory→DMA | $\mathcal{A}_4$ | 低 | 極高 | **Medium** | — | TME/SME (Phase 3) |
| S1: Web→Renderer | $\mathcal{A}_2$ | 高 | 中 | **Medium** | Gecko Fission | （Gecko upstream 依存） |
| S9: Update→Code | $\mathcal{A}_5$ | 低 | 極高 | **Medium** | OSS | 再現可能ビルド |
| S10: User→Graph | $\mathcal{A}_4$ | 低 | 高 | **Low** | パスワード | Dead Man's Switch |

---

## 5. 定量的プライバシー分析フレームワーク

### 5.1 認知フィンガープリントのエントロピー分析

知識グラフ $G$ の認知フィンガープリント $F(G)$ を以下の特徴ベクトルで定義:

$$F(G) = (f_\text{topic}, f_\text{transition}, f_\text{depth}, f_\text{temporal}, f_\text{query})$$

| 特徴 | 定義 | 推定エントロピー |
|------|------|---------------|
| $f_\text{topic}$ | トピック頻度分布 $P(t)$ over $T$ topics | $H(f_\text{topic}) = -\sum_t P(t) \log_2 P(t)$ |
| $f_\text{transition}$ | トピック遷移確率行列 $M_{ij} = P(t_j \mid t_i)$ | $H(f_\text{transition}) = -\sum_{i,j} P(t_i) M_{ij} \log_2 M_{ij}$ |
| $f_\text{depth}$ | トピック別ノード数分布 | $H(f_\text{depth})$ |
| $f_\text{temporal}$ | 24h 活動分布 | $H(f_\text{temporal}) \leq \log_2 24 \approx 4.6$ bits |
| $f_\text{query}$ | クエリ語彙のn-gram分布 | $H(f_\text{query})$ |

**識別力の推定:**

$N$ 人のユーザー集団に対し、フィンガープリント $F$ でユーザーを一意識別できる確率:

$$P(\text{unique} \mid F) = 1 - \left(1 - \frac{1}{N}\right)^{2^{H(F)}}$$

30トピック、100日分のデータで $H(F) \geq 40$ bits と推定される場合、$N = 10^9$ （全世界ユーザー）でも $P(\text{unique}) \approx 1.0$。

**防御目標:** ノイズ注入後の実効エントロピーを $H(F') \leq \log_2(k)$ に制限し、$k$-匿名性を達成する。$k = 1000$ なら $H(F') \leq 10$ bits。

### 5.2 埋め込みベクトルの復元リスク

384次元埋め込み $\Phi(v) \in \mathbb{R}^{384}$ からの元テキスト復元を分析する。

**先行研究に基づくリスク:**
- Vec2Text (Morris et al., 2023): GTR-base 埋め込みから BLEU 0.97 の復元を達成
- 短いテキスト（< 32 tokens）は長いテキストより復元が容易

**Quira における条件:**
- 格納されるのはページ全体ではなく AI 要約（2-3文、~50 tokens）
- 埋め込みモデルは公開（攻撃者が同一モデルでinversion attack可能）

**防御メカニズムの定量的評価:**

ノイズ注入 $\Phi'(v) = \Phi(v) + \eta$, $\eta \sim \mathcal{N}(0, \sigma^2 I_{384})$ に対し:

| $\sigma$ | 類似度検索精度 (Recall@10) | 復元 BLEU | 有用性-プライバシー |
|----------|--------------------------|-----------|-----------------|
| 0.00 | 1.00 | ~0.5-0.9 (推定) | 有用だが危険 |
| 0.01 | ~0.95 | ~0.3-0.5 (推定) | バランス |
| 0.05 | ~0.80 | ~0.1-0.2 (推定) | 安全だが精度低下 |
| 0.10 | ~0.60 | ~0.05 (推定) | 安全 |

**検証課題:** 上記は推定値。実測が必要。検証手順:
1. 公開テキストデータセットで embedding → inversion の BLEU を実測
2. ノイズ $\sigma$ の関数として recall@10 と BLEU を同時計測
3. Pareto front を描き、最適 $\sigma$ を決定

### 5.3 グラフトポロジーの匿名性分析

グラフ構造から個人を識別する攻撃のモデル化:

**攻撃:** 敵対者が観測するグラフ構造 $\tilde{G} = (|V|, \text{degree\_dist}, \text{clustering\_coeff}, \text{diameter}, ...)$ から、ターゲットユーザーとの照合を試みる。

**$k$-構造匿名性 ($k$-Structural Anonymity):**

ファントムノード注入後のグラフ $G_\text{combined}$ について、任意のサブグラフクエリ $q$ に対し、$q$ にマッチするサブグラフが $k$ 個以上存在する:

$$\forall q: |\{g \subseteq G_\text{combined} \mid g \cong q\}| \geq k$$

**コスト:** ファントムノード数 $|V_\text{phantom}|$ は $|V_\text{real}|$ に依存。目標 $k$ に対して:

$$|V_\text{phantom}| = O(k \cdot \sqrt{|V_\text{real}|})$$

（推定。実測による校正が必要）

---

## 6. 攻撃と防御の対応マップ

全攻撃を敵対者クラス・攻撃面・防御パラダイムに体系的に対応付ける。

| ID | 攻撃 | 敵対者 | 攻撃面 | 一次防御 | 二次防御 | 研究概念 |
|----|------|--------|--------|---------|---------|---------|
| A2.1 | プロンプトインジェクション | $\mathcal{A}_2$ | S2 | コンテンツ消毒 + 特権フレーミング | 出力スキーマ検証 | Inverse Sandboxing (エントロピー制限) |
| A2.2 | エンティティポイズニング | $\mathcal{A}_2$ | S3 | 可視テキスト相関チェック | IFC ラベル整合性 | — |
| A2.3 | 埋め込み空間操作 | $\mathcal{A}_2$ | S3 | マハラノビス距離外れ値検出 | ドメイン別分布 | クラスタ重心安定性監視 |
| A2.4 | 認知FP採取 | $\mathcal{A}_2$ | S1 | Farbling + タイミング正規化 | — | Cognitive FP Resistance |
| A2.5 | クラスタ重心シフト | $\mathcal{A}_2$ | S3 | ドメイン別レート制限 | 長期ドリフト検出 | — |
| A3.1 | 一括グラフ窃取 | $\mathcal{A}_3$ | S4 | Capability + MaxNodes | AI行動監視 | — |
| A3.2 | 漸増的窃取 | $\mathcal{A}_3$ | S4 | 長期トレンド分析 | 絶対閾値 | Context Capability Morphing |
| A3.3 | ストレージ蓄積→送信 | $\mathcal{A}_3$ | S4 | ストレージ-NW相関分析 | IFCラベル流出検出 | — |
| A3.4 | Read-then-Send | $\mathcal{A}_3$ | S4 | 5秒ウィンドウ相関検出 | — | — |
| A3.5 | メタデータのみ収集 | $\mathcal{A}_3$ | S4 | Capability粒度制限 | — | Semantic Topology Security |
| A4.1 | ディスクDB直接読取 | $\mathcal{A}_4$ | S7 | SQLCipher | 閾値暗号 | — |
| A4.2 | メモリダンプ | $\mathcal{A}_4$ | S8 | アクティブタブのみ復号 | TME/SME | Ephemeral Computation Zones |
| A4.3 | コールドブート | $\mathcal{A}_4$ | S8 | TME | DRAM暗号化 | — |
| A5.1 | テレメトリ挿入 | $\mathcal{A}_5$ | S9 | OSS監査 | 再現可能ビルド | VLAT (AI透過性ログ) |
| EXP.1 | エクスポートからの再識別 | $\mathcal{A}_1$ | S5 | — | — | ファントムナレッジ + 差分プライバシー |
| EMB.1 | 埋め込みからのテキスト復元 | $\mathcal{A}_4$ | S7 | 個別暗号化 | ノイズ注入 | 有用性-プライバシーPareto最適化 |

---

## 7. 安全性の定義と証明可能性

### 7.1 計算量的安全性 (Computational Security)

以下の性質は計算量的仮定に基づく:

| 性質 | 仮定 | 帰着先 |
|------|------|--------|
| Capability トークンの偽造不可能性 | HMAC-SHA256 の PRF 性質 | PRF 仮定 |
| 前方秘匿性 | X25519 の CDH 困難性 | DDH 仮定 |
| 閾値暗号の安全性 | Shamir の情報理論的安全性 | $t-1$ 個のシェアからは情報ゼロ |
| 検証可能削除 | Merkle 木の衝突耐性 | SHA-256 衝突耐性 |

### 7.2 形式検証の対象 (Formal Verification Scope)

以下を形式検証の候補とする（TLA+ / Coq）:

| 対象 | 検証する性質 | 難度 | 優先度 |
|------|------------|------|--------|
| Capability 発行/減衰/失効 | 増幅不可能性、失効の完全性 | 中 | P0 |
| IFC ラベル伝播 | ラベル単調性、flows-to 関係の健全性 | 中 | P0 |
| Context Graph IPC プロトコル | レンダラ→グラフ間の不正操作不可能性 | 高 | P1 |
| Dead Man's Switch 状態遷移 | 全状態からの鍵消去到達可能性 | 低 | P2 |

### 7.3 情報理論的安全性

| 性質 | 実現可能性 | 備考 |
|------|----------|------|
| 差分プライバシー（エクスポート） | $(\varepsilon, \delta)$-DP で保証可能 | $\varepsilon$ は公開パラメータ |
| 閾値暗号（$t$-of-$n$）| 情報理論的に安全 | $t-1$ シェアから情報量ゼロ |
| 認知FP耐性 | $k$-匿名性で近似保証 | 情報理論的保証は困難 |

---

## 8. 未解決の研究課題

### 8.1 定量的検証が必要な仮説

| ID | 仮説 | 検証方法 | 優先度 |
|----|------|---------|--------|
| H1 | 認知フィンガープリントは $N > 10^6$ でも個人を一意識別する | 合成データでの de-anonymization シミュレーション | 高 |
| H2 | 埋め込みノイズ $\sigma = 0.01$ で recall@10 $\geq 0.90$ を維持 | 実データでの precision-recall 測定 | 高 |
| H3 | AI出力のエントロピー制限でステガノグラフィックチャネル容量を $< 1$ bit/inference に抑制可能 | 情報理論的解析 + 実測 | 中 |
| H4 | Capability チェックのオーバーヘッドは $< 1\text{ms}$/query | ベンチマーク | 中 |
| H5 | 行動ベースライン異常検出の偽陽性率 $< 1\%$（14日学習後） | ユーザースタディ or シミュレーション | 中 |
| H6 | ファントムノード注入で $k = 50$ の構造匿名性を達成する際のストレージオーバーヘッド $< 2x$ | グラフ理論的解析 + シミュレーション | 低 |

### 8.2 既存研究で未到達の問題

1. **Knowledge Graph に対する embedding inversion attack の定量的リスク**: Vec2Text は汎用テキスト埋め込みを対象。知識グラフの要約埋め込み（短文、限定ドメイン）に対する inversion 精度は未測定。

2. **認知フィンガープリントの識別力**: keystroke dynamics、mouse movement biometrics は研究済みだが、知識獲得パターンの識別力は未研究。

3. **AI出力のステガノグラフィック容量**: テキスト生成モデルの出力をステガノグラフィックチャネルとして使うことは研究されているが（Ziegler et al., 2019）、ブラウザの要約パイプラインに対する出力エントロピー制限の効果は未検証。

4. **グラフトポロジーベースのアクセス制御の形式化**: RAdAC（Risk-Adaptive Access Control）はリスクスコアベースの動的制御として先行するが、データ構造のトポロジーメトリクスをリスク入力に使う定式化は未踏。

---

## Appendix A: 記法一覧

| 記号 | 意味 |
|------|------|
| $G = (V, E, \Sigma, \Phi, \Tau)$ | 知識グラフ |
| $\mathcal{A} = (\mathcal{C}, \mathcal{G}, \mathcal{K})$ | 敵対者モデル |
| $\mathcal{A}_1 \ldots \mathcal{A}_5$ | 敵対者クラス 1-5 |
| $\ell(d)$ | データ $d$ の IFC ラベル |
| $\Phi(v)$ | ノード $v$ の埋め込みベクトル |
| $H(\cdot)$ | SHA-256 ハッシュ or エントロピー（文脈で判別） |
| $\varepsilon, \delta$ | 差分プライバシーパラメータ |
| $k$ | $k$-匿名性のパラメータ |
| $\sigma$ | ノイズ注入の標準偏差 |
| $\alpha$ | セキュリティオーバーヘッドの許容倍率 |

## Appendix B: 先行技術との関係

| 先行技術 | Quira における位置づけ |
|---------|---------------------|
| NIST RAdAC | Semantic Topology Security の先行。STS は RAdAC のグラフトポロジー拡張 |
| XACML / ABAC | Context Capability Morphing の先行。CCM は自己評価型ケーパビリティとして差別化 |
| Apple PCC | VLAT の着想元。PCC はクラウド、VLAT はローカル |
| OWASP LLM Top 10 | AI脅威モデルの枠組み。Quira固有の脅威（グラフポイズニング等）を追加 |
| Dolev-Yao モデル | $\mathcal{A}_1$ のネットワーク脅威モデルの形式的基盤 |
| Bell-LaPadula モデル | IFC の機密性部分の理論的基盤（"no read up, no write down"） |
| Vec2Text (Morris et al.) | 埋め込みinversion攻撃の先行研究。Quira防御の定量評価基準 |
| SLSA Framework | N5 (VSCA) の基盤。SLSA L3準拠 + Sigstore でサプライチェーン信頼性を保証 |
| TLA+ (Lamport) | N6 (FSIE) の基盤。AWS S3/DynamoDB で実績。CGAG 状態機械の形式検証に適用 |
| Google Crypto-Shredding | N1 (CGS) の着想元。Googleはデータセンター規模、CGSはノード粒度 + embedding |
| Narayanan & Shmatikov (2008) | スタイロメトリ研究。N7 (CQN) が防御するクエリ言語指紋攻撃の理論的基盤 |
| zCDP (Bun & Dwork, 2016) | N8 (DPBC) の合成定理。Sequential Composition より tight な予算追跡 |

## Appendix C: 新規攻撃ベクトル (hardening / frontier)

> hardening-research.md および frontier-security-research.md で新たに定義された攻撃ベクトル。

| ベクトル | 敵対者 | 説明 | 防御 |
|---------|--------|------|------|
| A4.4 Embedding Inversion via Disk Theft | $\mathcal{A}_4$ | ディスク窃取による埋め込みベクトルからの元テキスト復元 | N1 (CGS) + E1 |
| A4.5 Spectre-BHB on LLM Inference | $\mathcal{A}_4$ | LLM推論中のキャッシュタイミング攻撃 | N3 (SEF) |
| A5.3 Binary Supply Chain Tampering | $\mathcal{A}_5$ | ビルドパイプライン汚染によるバイナリ改竄 | N5 (VSCA) |
| A5.4 Query Stylometry Identification | $\mathcal{A}_5$ | NLクエリの言語パターンによるユーザー特定 | N7 (CQN) + E5 |
| A-cross Audit Log Tampering | 全クラス | CSEBイベントバッファの改竄による証拠隠滅 | N2 (FIL) + E3 |
| A-cross Graph Structure Re-identification | $\mathcal{A}_1$, $\mathcal{A}_3$ | エクスポートされたグラフ構造による再識別 | N4 (GEAP) |
| A-cross DP Budget Exhaustion | $\mathcal{A}_1$, $\mathcal{A}_5$ | DP予算の意図的枯渇による保護劣化 | N8 (DPBC) |
| A-cross Security Invariant Violation | 全クラス | 実装バグによるセキュリティ不変条件の破壊 | N6 (FSIE) |
