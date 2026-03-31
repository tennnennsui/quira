# Novel Security Research: Beyond Existing Paradigms

> Status: Research Proposal (未実装 — Founder承認後に検証フェーズへ移行)
> Date: 2026-07 | Reassessed: 2026-07
> Scope: Quira Browser — 既存8パラダイム + security-research.md の先にある「誰もやっていない」領域
> Depends: [threat-model.md](threat-model.md) — 本文書の全概念は形式的脅威モデルの上に構築される

---

## 0. 調査方法と新規性の判定基準

### 調査した先行技術

| カテゴリ | 対象 |
|---------|------|
| **Quira既存設計** | radical-security-architecture.md (8パラダイム)、security-architecture.md (macOSマッピング12項目)、security-research.md (ZT拡張、TEE、DP、HE、PQC、DID、SMPC、形式検証、AI脅威モデル、CSF 6層) |
| **Apple/macOS** | KIP、APRR、SCIP、PAC (salt詳細)、PPL、SPTM/TXM、Launch Environment Constraints (self/parent/responsible/spawn/library)、Secure Enclave、Private Cloud Compute (5要件 + RSA Blind Signatures + OHTTP + target diffusion + append-only transparency log) |
| **Google/Chrome** | Site Isolation、V8 Sandbox (sandbox_ptr_t / external_ptr_t / pointer table indirection)、MiraclePtr/BackupRefPtr (UaF quarantine + poisoning)、Intel CET (Shadow Stack + IBT) |
| **GrapheneOS** | hardened_malloc、MTE (ARMv9)、exec spawning、BTI/PAC、Network/Sensors permission toggles、Storage/Contact Scopes、auto reboot (18h)、duress PIN、memory clearing on lock、dynamic code loading blocked、USB-C control、Vanadium hardening |
| **Fuchsia/Zircon** | Handle-based capability model、Rights per handle、Channels (message passing)、Job/Process/Thread hierarchy、VMOs、VMARs |
| **Cambridge CHERI** | Hardware capability pointers、memory safety (spatial/temporal/referential)、compartmentalization (co-processes + compartmentalized shared libraries)、CHERI-WebKit JSC port、CHERI-seL4、formal verification |
| **seL4** | 形式検証マイクロカーネル (Isabelle/HOL)、capability-based |
| **その他** | Brave (Shields/Farbling/Cookiecrumbler)、Tor (onion routing/uniform fingerprint)、QUARK browser (Coq形式検証)、Capsicum (FreeBSD capabilities)、Qubes OS (Xen compartmentalization) |

### 新規性の判定基準

1. **既存システムに実装が存在しない** — OS、ブラウザ、学術プロトタイプ問わず
2. **既存概念の単純な「ブラウザ版」ではない** — macOSのTCC→Context TCCのような直訳は除外（既にsecurity-architecture.mdに記載済み）
3. **組み合わせ自体が新しい** — 既存技術A + Bの組み合わせでも、その合成が未踏なら候補とする
4. **Knowledge Graph Browser固有** — 汎用ブラウザでは意味をなさず、知識グラフブラウザだからこそ成立する概念を優先

---

## 1. Cognitive Fingerprint Resistance (認知フィンガープリント耐性)

### 新規性: ★★★★★ (完全に新しい脅威モデル)

#### 概要

現行のフィンガープリント対策はすべて**技術的フィンガープリント**（Canvas、WebGL、フォント、AudioContext）を対象とする。Quiraは知識グラフを持つため、全く別次元のフィンガープリントベクトルが生まれる: **認知フィンガープリント**。

#### 脅威モデル

ユーザーの「知的活動パターン」は個人を一意に特定できる:

| パターン | 識別力 | 例 |
|---------|--------|----|
| **トピック遷移パターン** | 極高 | 量子力学 → 哲学 → 料理 という遷移順序は個人固有 |
| **研究深度分布** | 高 | あるトピックに15ページ費やし別のトピックは2ページで終わる |
| **時間帯別活動** | 高 | 深夜2時にセキュリティ論文を読む習慣 |
| **クエリ構文パターン** | 中 | NLクエリの語彙選択・構文は個人のidiolectを反映 |
| **知識獲得速度** | 中 | 新トピックへの展開速度は認知スタイルの指標 |

**先行事例の確認:**
- Brave Farbling: 技術的フィンガープリントのみ対処
- Tor uniform fingerprint: ブラウザ外見の均一化のみ
- GrapheneOS exec spawning: プロセスアドレス空間のランダム化
- 学術論文: keystroke dynamics / mouse movement biometrics は研究されているが、**知識獲得パターンによる個人識別**は未研究

→ 先行事例なし。Quira固有の新脅威。

#### 提案する防御メカニズム

```
┌─────────────────────────────────────────────────┐
│         Cognitive Fingerprint Resistance        │
├─────────────────────────────────────────────────┤
│                                                 │
│  1. Temporal Jittering                          │
│     ノード作成タイムスタンプに ±δ のノイズ注入     │
│     δ = calibrated_noise(privacy_budget)        │
│                                                 │
│  2. Phantom Research Trails                     │
│     バックグラウンドで無害なダミー知識経路を生成    │
│     実際の研究パターンにノイズを混入               │
│                                                 │
│  3. Batch Processing Obfuscation                │
│     AI処理をリアルタイムではなくバッチ実行          │
│     個々のページ訪問とAI処理の時間相関を除去        │
│                                                 │
│  4. Query Pattern Normalization                 │
│     NLクエリをcanonical形に正規化してから処理      │
│     ユーザー固有の語彙選択を消去                   │
│                                                 │
│  5. Export Sanitization                         │
│     共有・エクスポート時に認知パターンを除去       │
│     タイムスタンプ・訪問順序・深度情報を匿名化      │
│                                                 │
└─────────────────────────────────────────────────┘
```

#### macOSからのインスピレーション

Apple PCC の non-targetability: 「特定の個人を狙った攻撃を構造的に不可能にする」。これを認知レベルに拡張 — 認知パターンから特定の個人を狙い撃ちすることを構造的に不可能にする。

#### 検証方法

1. 合成データセットで認知フィンガープリントの識別力を定量測定
2. de-anonymization attack をシミュレートし、ノイズ注入前後の識別率を比較
3. 有用性とプライバシーのトレードオフ曲線を導出

#### リスク

- ノイズ注入により知識グラフの時間的正確性が低下
- ダミートレイル生成のリソースコスト
- 効果が測定困難（攻撃自体が仮説段階）

---

## 2. Semantic Topology Security (意味トポロジーセキュリティ)

> **アーキテクチャ関係:** STS は IFC（情報フロー制御）とは**独立した概念**。IFC がラベルベースのデータフロー制約を提供するのに対し、STS はグラフトポロジーメトリクス（次数中心性、クラスター密度等）をセキュリティポリシーの動的入力として使う。両者は直交し、STS の橋渡しノード検出が IFC ラベル自動付与のトリガーになるという**補完関係**にある。

### 新規性: ★★★★☆ (RAdAC のグラフトポロジー拡張 — 再評価済み)

> **再評価ノート:** 当初 ★★★★★ としたが、NIST/DoD の RAdAC (Risk-Adaptive Access Control) がリアルタイムリスクスコアに基づく動的アクセス制御として先行する。STS の真の新規性は「グラフトポロジーメトリクスをリスク入力に使う」点に限定される。

#### 概要

既存のアクセス制御は**静的な境界**に基づく（プロセス分離、サンドボックス、ケーパビリティ）。Semantic Topology Securityは、知識グラフの**動的なトポロジー構造自体**をセキュリティポリシーの入力として使う。

#### 原理

知識グラフのトポロジー特性がセキュリティポリシーを動的に決定する:

| トポロジー特性 | セキュリティ効果 |
|-------------|-------------|
| **ノードの次数中心性 (Degree Centrality)** | 中心性が高い（多くのノードと接続）→ 機微度が高い → アクセスに追加認証を要求 |
| **クラスター密度** | 密結合クラスター → 一括で保護対象 → クラスター単位の暗号化 |
| **橋渡しノード (Bridge Nodes)** | 異なるクラスター間を接続 → 情報流出リスクが高い → IFC（情報フロー制御）ラベルを自動付与 |
| **孤立ノード** | 接続が少ない → 低機微 → 軽量な保護で十分 |
| **新規エッジ** | 新たに形成された接続 → 潜在的なクロスドメイン情報流出 → 一時的な監査強化 |

#### 先行事例の確認

- RBAC / ABAC / PBAC: 属性ベースだがトポロジーベースではない
- Graph-based access control (GBAC): 主体・客体の関係グラフに基づくが、知識グラフそのものの構造変化を動的にポリシー化する研究はない
- Zircon capabilities: ハンドル+権限の静的モデル
- CHERI: ハードウェアレベルのメモリケーパビリティ
- Quiraのパラダイム2 (IFC): ラベルベースの静的フロー制御であり、トポロジー変化に反応しない
- **NIST/DoD RAdAC (Risk-Adaptive Access Control)**: リアルタイムリスクスコアに基づく動的アクセス制御。STS の先行概念

→ ~~知識グラフのトポロジー変化がセキュリティポリシーを動的に駆動する設計は先行事例なし。~~ RAdAC が動的リスクベースの制御として先行。STS の差別化はグラフトポロジーメトリクス（次数中心性、クラスター密度）をリスクスコアの入力源として使う点。

#### 具体例

```rust
// トポロジー解析によるセキュリティポリシー自動生成（概念コード）

struct TopologySecurityAnalyzer {
    centrality_threshold: f64,     // 中心性しきい値
    cluster_density_threshold: f64, // クラスター密度しきい値
}

enum AutoPolicy {
    RequireReauth,           // 高中心性ノードへのアクセス時
    ClusterEncryption(Key),  // 密結合クラスターの一括暗号化
    IFCLabel(Label),         // 橋渡しノードへの情報フロー制御
    AuditEnhanced,           // 新規エッジ形成時の一時監査
    StandardAccess,          // 低リスクノード
}

// グラフ変異ごとにトポロジーを再計算し、ポリシーを動的更新
fn on_graph_mutation(graph: &KnowledgeGraph, mutation: &Mutation) -> Vec<PolicyUpdate> {
    let affected_nodes = graph.neighbors(mutation.target_node);
    let new_centrality = graph.degree_centrality(mutation.target_node);
    
    // 中心性が閾値を超えたら自動的にセキュリティ昇格
    if new_centrality > self.centrality_threshold {
        return vec![PolicyUpdate::Escalate(mutation.target_node, AutoPolicy::RequireReauth)];
    }
    // ...
}
```

#### 検証方法

1. 既存知識グラフデータセットでトポロジー分析 → ポリシー生成のシミュレーション
2. 攻撃シナリオ: 特定ノードを狙った情報収集 vs トポロジーベースの動的防御
3. パフォーマンスオーバーヘッド測定（グラフ変異ごとの中心性再計算コスト）

#### リスク

- トポロジー計算コスト（大規模グラフでは O(V+E) が頻繁に走る）
- ポリシーの予測不可能性（ユーザーから見て「なぜ急に認証が必要になったか」が直感的でない場合がある）
- 偽陽性: 無害なトポロジー変化がセキュリティ昇格を誤発動

---

## 3. Verifiable Local AI Transparency (検証可能なローカルAI透過性)

### 新規性: ★★★★☆ (Apple PCC のローカル逆転適用 — 組み合わせが新しい)

#### 概要

Apple PCC は**クラウド側**のAI処理に検証可能な透過性を実現した。Quiraは**ローカル側**のAI処理に同じ原理を適用し、ユーザーがAIの挙動を数学的に検証できるようにする。

#### PCC との違い

| 特性 | Apple PCC | Quira VLAT |
|------|----------|-----------|
| **計算場所** | リモートサーバー | ローカルデバイス |
| **脅威モデル** | Appleサーバーオペレーターの不正 | ローカルマルウェア / 改竄モデル / prompt injection |
| **透過性ログ** | 中央集権 append-only log | ローカル append-only log (ユーザーのみがアクセス) |
| **検証者** | セキュリティ研究者 | ユーザー自身 + オプトインの外部監査 |
| **ステートレス性** | 毎リクエスト完全消去 | 選択的保存（出力のみ永続、中間状態は消去） |

#### アーキテクチャ

```
┌────────────────────────────────────────────────────────────────┐
│                    Verifiable Local AI Transparency              │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Pre-Inference Verification                                      │
│  ├── Model hash verification (SHA-256 of .gguf)                  │
│  ├── Model signature check (Ed25519, Quira signing key)          │
│  └── Model allowlist enforcement (only known-good models run)    │
│                                                                  │
│  During Inference                                                │
│  ├── Input content hash recorded                                 │
│  ├── System prompt hash recorded (immutable)                     │
│  ├── Inference executed in Ephemeral Computation Zone (§7)       │
│  └── All intermediate states (KV cache, attention) ephemeral     │
│                                                                  │
│  Post-Inference Verification                                     │
│  ├── Output hash computed                                        │
│  ├── Provenance record: {input_hash, model_hash, system_prompt   │
│  │   _hash, output_hash, timestamp, inference_params}            │
│  ├── Record signed with device-local key                         │
│  └── Appended to local transparency log (append-only)            │
│                                                                  │
│  User Audit Interface (quira://ai/audit)                         │
│  ├── Browse all AI operations with provenance chains             │
│  ├── Verify: "this summary was produced by this model from       │
│  │   this input"                                                 │
│  ├── Detect anomalies: unexpected model hash changes             │
│  └── Export audit log for external review                        │
│                                                                  │
└────────────────────────────────────────────────────────────────┘
```

#### 先行事例の確認

- Apple PCC: クラウドAI透過性 (ローカルにはない)
- Chrome AI features: 透過性メカニズムなし
- Brave AI: 透過性メカニズムなし
- 学術: ML model provenance (ModelCards等) は静的ドキュメントであり、推論ごとの暗号学的検証チェーンではない

→ ローカルAI推論に対する暗号学的provenance chainは先行事例なし。

#### 検証方法

1. provenance記録のオーバーヘッド測定 (SHA-256ハッシュ計算コスト vs 推論コスト)
2. 改竄モデル検出のE2Eテスト
3. ユーザビリティ評価: audit UIの理解しやすさ

---

## 4. Context Capability Morphing (コンテキストケーパビリティ変形)

> **アーキテクチャ関係:** CCM は radical-architecture.md **Paradigm 4 (Temporal Security)** の具体化手段。Paradigm 4 が時間軸での権限変化を**原理**として定義し、CCM は context_vector に基づく連続変形を**メカニズム**として実装する。

### 新規性: ★★★☆☆ (XACML PDP の分散化 — 再評価済み)

> **再評価ノート:** 当初 ★★★★☆ としたが、XACML の PDP (Policy Decision Point) が機能的に等価な集中型ポリシー評価を既に実現している。CCM の真の新規性は「中央 PDP を排し、ケーパビリティ自体に自己評価型モディファイアを埋め込む」分散設計に限定される。

#### 概要

既存のケーパビリティ（Zircon Handles、CHERI、QuiraのParadigm 1）は**発行時に権限が固定**される。Context Capability Morphingは、ケーパビリティ自体が多次元のコンテキストに応じて**連続的に変形**する。

#### 静的ケーパビリティとの違い

```
静的 (既存):
  Capability { rights: READ | WRITE }  ← 失効か有効かの二値

動的（提案）:
  MorphingCapability {
      base_rights: READ | WRITE,
      context_modifiers: [
          TimeDecay { half_life: 24h },           // 時間経過で権限減衰
          DevicePosture { require: secure_boot },   // デバイス状態で権限変動
          BehavioralBaseline { anomaly_threshold: 0.7 }, // 行動異常で権限制限
          NetworkContext { trusted_networks: [...] }, // ネットワーク環境で変動
          GraphSensitivity { auto_from_topology: true }, // §2のSTS連動
      ],
      effective_rights: fn(context) -> Rights,  // リアルタイム計算
  }
```

#### 先行事例の確認

- ABAC (Attribute-Based Access Control): 属性に基づくポリシー評価は既存。しかしABACはポリシー側を変更する。本提案はケーパビリティ自体が変形する点が異なる
- Quira Paradigm 4 (Temporal Security): 時間減衰は既存。本提案はそれを多次元に一般化
- macOS Launch Environment Constraints: 静的な起動制約（コード署名に埋め込み）。動的ではない
- OAuth scopes / JWT claims: 静的な権限付与
- **XACML PDP (Policy Decision Point)**: 属性ベースの動的ポリシー評価エンジン。CCM の先行概念

→ ~~ケーパビリティ自体が多次元コンテキストで連続変形する設計は先行事例なし。~~ XACML PDP が属性ベースの動的ポリシー評価として先行。CCM の差別化は中央 PDP を排し、ケーパビリティ自体に評価ロジックを埋め込む分散アーキテクチャ。

#### 検証方法

1. contextモディファイアの組み合わせ爆発に対するパフォーマンス測定
2. シナリオテスト: デバイス状態変化 → 権限自動変動 → 正当なアクセスが阻害されないか
3. ユーザー体験: 「なぜ急に権限が変わったか」のexplanability UI

---

## 5. Knowledge Entanglement Protocol (知識エンタングルメントプロトコル)

### 新規性: ★★★☆☆ (Merkle DAG 変種 — 再評価済み)

> **再評価ノート:** 当初 ★★★★☆ としたが、以下の問題を特定。(1) 循環グラフでの「DAG-ordered resolution」は未定義。知識グラフは DAG ではなく一般有向グラフであり、循環依存のハッシュ計算が自己参照になる。(2) 実質的に 1-hop Merkle DAG のバリアントであり、双方向ハッシュの理論的新規性は限定的。(3) 更新コスト O(degree) が高次数ノードで性能問題を起こす。

#### 概要

量子もつれ（entanglement）に着想を得た概念: 知識グラフ内で関連するノード同士が暗号学的に**相互依存**し、片方の改竄が他方の検証で即座に検出される。

#### Merkle Treeとの違い

| 特性 | Merkle Tree | Knowledge Entanglement |
|------|------------|----------------------|
| **構造** | 木（一方向: 葉→根） | グラフ（双方向: 隣接ノード間） |
| **検証方向** | 根のハッシュで全体を検証 | 任意のノードから隣接を検証可能 |
| **更新コスト** | O(log n) — パス上のハッシュ更新 | O(degree) — 隣接ノードのハッシュ更新 |
| **部分検証** | パス単位 | 局所近傍単位 |
| **循環グラフ対応** | 不可 | 対応（ハッシュ計算にDAG-ordered resolution使用） |

#### プロトコル概要

```
各ノードのentangled_hash:
  H(node) = SHA-256(
    node.content_hash ||
    node.metadata_hash ||
    SORT(neighbor_content_hashes) ||  // 隣接ノードの内容に依存
    node.timestamp
  )

ノードAが変更された場合:
  1. A.content_hash を再計算
  2. A.entangled_hash を再計算
  3. Aの全隣接ノード B1, B2, ... のentangled_hashを再計算
  4. B1, B2, ... の隣接にも伝播 (configurable depth, デフォルト1)

整合性検証:
  verify(node) → 隣接ノードのentangled_hashを再計算し、stored hashと比較
  不一致 → 改竄検出 → アラート + ノード隔離

攻撃シナリオ:
  攻撃者がノードAの内容を改竄 → Aのentangled_hash不一致
  → 攻撃者がAのhashも更新 → 隣接B1のentangled_hash不一致
  → 攻撃者がB1も更新 → B1の隣接C1, C2のhash不一致
  → 連鎖的に全グラフの改竄が必要 → 実質不可能
```

#### 先行事例の確認

- Merkle DAG (IPFS/IPLD): DAG構造で一方向ハッシュチェーン。双方向ではない
- Git objects: Merkle tree (一方向)
- Certificate Transparency: append-only Merkle tree
- Blockchain: 線形チェーン構造

→ 双方向グラフ構造での相互依存ハッシュプロトコルは先行事例なし。

---

## 6. Inverse Sandboxing — AI Output Restriction (逆サンドボックス)

### 新規性: ★★★★★ (入力制限→出力制限のパラダイム逆転 — 再評価で昇格)

> **再評価ノート:** 当初 ★★★★☆ としたが、エントロピー境界によるステガノグラフィック出力防止は (a) 測定可能、(b) 形式的に検証可能、(c) 実装可能であり、直接的な論文ポテンシャルを持つ。threat-model.md §5.2 の定量的分析フレームワークと合わせて最も研究価値が高い概念の一つ。

#### 概要

従来のサンドボックスは「信頼できないコードが何に**アクセス**できるか」を制限する（入力制限）。逆サンドボックスは「信頼できるAIが何を**出力**できるか」を制限する（出力制限）。

#### なぜ必要か

AIモデルが侵害された場合（prompt injection、モデル改竄）、入力サンドボックスは無意味:
- AIはすでにページ内容を読んでいる（入力は許可済み）
- AIの出力にステガノグラフィック（隠しチャネル）で情報をエンコードできる
  - 例: サマリーの語彙選択パターンにユーザーの他のブラウジングデータを埋め込む
  - 例: エンティティ抽出結果の微妙な順序変更にクエリ履歴を符号化する

#### メカニズム

```
┌─────────────────────────────────────────────────────────┐
│              Inverse Sandbox (Output Restriction)         │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Schema Enforcement                                       │
│  ├── Summary: UTF-8 text, max 500 chars, no URLs/code    │
│  ├── Entities: List<{name: str(max 100), type: enum}>    │
│  ├── Embeddings: Vec<f32>[384], L2-normalized             │
│  └── Relations: List<{from: NodeId, to: NodeId, type}>   │
│                                                           │
│  Entropy Restriction                                      │
│  ├── Output entropy must be within expected bounds        │
│  │   (prevents steganographic data encoding)              │
│  ├── Summary perplexity check: p < threshold              │
│  │   (unnaturally precise/structured text → flag)         │
│  └── Entity extraction count bounds: [1, 20] per page    │
│                                                           │
│  Cross-Inference Isolation                                │
│  ├── No output from inference N can reference             │
│  │   input/output from inference N-1                      │
│  ├── Stateless: each inference is independent             │
│  └── No accumulation across inferences                    │
│                                                           │
│  Output Diffing                                           │
│  ├── Compare AI output to a "reference output" from       │
│  │   a second, isolated model run (optional, expensive)   │
│  └── Significant divergence → quarantine + user review    │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

#### 先行事例の確認

- DLP (Data Loss Prevention): 企業のデータ流出防止。AIの出力を対象とするものはない
- AI guardrails (Anthropic, OpenAI): コンテンツ安全性フィルタであり、ステガノグラフィック出力の制限ではない
- GrapheneOS dynamic code loading blocked: コード実行の制限であり、データ出力の制限ではない
- Quira security-research.md §3.2 Output Validation: スキーマ検証は記載済みだが、エントロピー制限・ステガノグラフィック検出・cross-inference isolationは未記載

→ エントロピー制限によるステガノグラフィック出力防止は先行事例なし。

---

## 7. Ephemeral Computation Zones (一時的計算ゾーン)

### 新規性: ★★★☆☆ (既存技術の再パッケージング — 再評価済み)

> **再評価ノート:** 当初 ★★★★☆ としたが、4-6GB ワーキングセット全体の暗号化は AI 推論の性能を大幅に低下させる。`zero-on-free` + `explicit_bzero` + `madvise(MADV_DONTNEED)` の組み合わせで同等のセキュリティ効果をより低コストで達成可能。暗号学的消去は鍵管理の複雑さに対してマージナルな追加防御にとどまる。

#### 概要

AI推論の**中間状態**（attention weights、KVキャッシュ、隠れ層の活性化値）は、元のテキストの再構成に利用できる研究が存在する。Ephemeral Computation Zonesは、推論の中間状態を暗号学的に消去し、最終出力のみを保存する。

#### メカニズム

```
推論フロー:

1. Ephemeral Zone 確立
   - ランダム鍵 K_eph を生成 (Secure Enclave / ソフトウェアRNG)
   - AI推論の全メモリ割り当てを K_eph で暗号化されたリージョンに実施

2. 推論実行
   - Tokenization → Embedding → Transformer layers → Output generation
   - すべての中間テンソルは暗号化リージョン内

3. 出力抽出
   - 最終出力のみ（サマリーテキスト、エンティティリスト、埋め込みベクトル）を
     暗号化リージョンの外にコピー

4. Ephemeral Zone 消去
   - K_eph を破棄 → 中間状態は復号不可能に
   - メモリリージョンをゼロクリア（GrapheneOS zero-on-freeと同原理）
   - Apple PCC のように「鍵を消すことでデータを消す」暗号学的消去

結果:
   - 最終出力のみが残る
   - メモリフォレンジクスでも中間状態の復元不可
   - KVキャッシュ、attention map、hidden statesからの原文復元攻撃を防止
```

#### 先行事例の確認

- Apple PCC: サーバー全体のステートレス化（リブート時に全消去）。選択的ではない
- GrapheneOS auto-reboot: デバイス全体の再起動。推論単位の消去ではない
- GrapheneOS zero-on-free: メモリ解放時のゼロクリア。暗号学的消去ではない
- TEE (SGX/TrustZone): 保護はするが「使用後の消去」を強制するメカニズムではない

→ AI推論単位の、選択的な暗号学的中間状態消去は先行事例なし。

---

## 8. Privilege Ring Browser Architecture (特権リングブラウザアーキテクチャ)

### 新規性: ★★★☆☆ (SPTM/TXMのソフトウェア適用 — 概念は既存だが適用は新規)

#### 概要

macOSのSPTM/TXMは**カーネルより高い特権レベル**で動作するモニターを導入した。Quiraはブラウザ内部に同様の**多層特権アーキテクチャ**を構築する。

#### 現行のブラウザアーキテクチャとの比較

```
現行 (Chrome/Firefox):
  [Browser Process] ←→ [Renderer Process] ← プロセス分離（2層のみ）

提案 (Quira):
  Ring 0: Graph Integrity Monitor (GIM)
  ├── 知識グラフの全変更を検証する最高権限プロセス
  ├── 他の全コンポーネントより高い特権で動作
  ├── GIM自身は変更不可（read-only code, integrity-checked on startup）
  └── macOS SPTM に相当: カーネル（=メインブラウザプロセス）すら信頼しない

  Ring 1: Context Graph Engine
  ├── グラフの読み書き（GIMの検証を経由）
  ├── SQLite暗号化アクセス
  └── macOS TXM に相当: コード実行ポリシーを管理

  Ring 2: AI Processing Pipeline
  ├── グラフ読み取り権限のみ（書き込みはRing 1経由でGIM検証）
  ├── Ephemeral Computation Zone (§7) 内で動作
  └── ページ内容を処理するが直接グラフに書き込めない

  Ring 3: Extension Runtime
  ├── ケーパビリティゲート経由でのみグラフにアクセス
  ├── Morphing Capabilities (§4) で動的に権限変動
  └── Zero Trust Gateway (security-research.md §2.1) を通過

  Ring 4: Content Renderer (Gecko forks)
  ├── グラフへの直接アクセス不可
  ├── メッセージパッシングのみ
  └── Fission プロセス分離（既存）
```

#### 先行事例の確認

- x86 Ring 0-3: ハードウェアの特権レベル。ソフトウェアブラウザに適用した例はない
- SPTM/TXM: Appleシリコン専用。ブラウザには未適用
- Chrome Site Isolation: 均等なプロセス分離（特権階層ではない）
- V8 Sandbox: JavaScriptヒープの隔離であり、多層特権ではない

→ ブラウザコンポーネント間の多層特権リングアーキテクチャは先行事例なし。

---

## 9. Federated Knowledge Attestation (連合知識証明)

### 新規性: ★★☆☆☆ (技術的に非実用 — 再評価済み)

> **再評価ノート:** 当初 ★★★☆☆ としたが、zkML (EZKL, Giza) は ~100K パラメータモデルに限定される。7B モデルの ZK 証明は計算量的に 2026 年時点で非実行可能。Phase 1 の「Ed25519 + model hash」は実質的に既存のコード署名と同等であり、新規性は低い。ZK 部分は技術成熟を待つしかない。

#### 概要

ユーザー間で知識を共有する際、「この要約は本物のQuira AIモデルが本物のWebコンテンツから生成した」ことを、元のコンテンツやグラフ全体を開示せずに証明する。

#### プロトコル

```
Prover (知識共有者):
  1. 共有するノードのprovenance record (§3) を取得
  2. ZK proof を生成:
     - "このサマリーは、ハッシュ H_model のモデルが、
       ハッシュ H_input の入力から生成した" ことを証明
     - H_input の中身（=元のページ内容）は開示しない
     - model の重みも開示しない（ハッシュのみ）
  3. 証明を共有ノードに添付

Verifier (知識受領者):
  1. ZK proof を検証
  2. H_model が Quira公式モデルハッシュリストに含まれるか確認
  3. 検証成功 → 信頼できる知識として受理
  4. 検証失敗 → "unverified" とマーク

攻撃耐性:
  - 捏造された要約: provenance proofが生成不可能
  - 改竄されたモデル: H_model が公式リストにない → 検出
  - プライバシー: 元Webページの内容は一切開示されない
```

#### 先行事例の確認

- Apple PCC transparency log: 中央集権的な検証（P2Pではない）
- Web of Trust (PGP): 人間のID証明であり、AI出力の証明ではない
- Verifiable Credentials (W3C): 人間の属性証明であり、AI計算の証明ではない
- zkML (Zero-Knowledge Machine Learning): 研究段階。ML推論のZK証明は理論的に可能だが、実用的な実装は2026年時点で存在しない

→ 知識グラフノードのAI生成provenance に対するZK証明は先行事例なし（zkMLの実用応用第一号になり得る）。

#### リスク

- ZK proof生成のコンピュータコストが極めて高い（LLM推論のZK proofは現行技術では非実用的）
- 段階的アプローチが必要: Phase 1ではデジタル署名 (Ed25519) + model hash、Phase 3でZKに移行

---

## 10. Graph Topology Obfuscation via Phantom Knowledge (ファントムナレッジによるグラフトポロジー難読化)

### 新規性: ★★★☆☆ (ORAM概念のグラフ構造適用)

#### 概要

知識グラフの「形状」自体が個人を識別するメタデータとなる（§1の認知フィンガープリントの構造版）。Phantom Knowledge は、本物のグラフにダミーのノードとエッジを混入し、外部から観測しても本物のトポロジーを特定できなくする。

#### メカニズム

```
Graph Obfuscation Layer:
  1. 実グラフ G_real に対し、ダミーグラフ G_phantom を生成
     - G_phantom のトポロジー特性（次数分布、クラスタリング係数）は
       G_real と統計的に類似
     - ダミーノードの内容は合成テキスト（LLM生成）
     
  2. 結合グラフ G_combined = G_real ∪ G_phantom
     - ユーザーのクエリは G_real のみを検索
     - 外部から観測可能なメタデータ（ノード数、エッジ数、更新頻度）は
       G_combined を反映

  3. エクスポート・共有時:
     - G_real の一部のみエクスポート
     - ファントムノードは自動除外
     - しかし外部観測者にはどれがファントムか識別不可能

  4. 差分プライバシーとの統合:
     - ε-differential privacy でグラフ構造にノイズ追加
     - ファントムノードが構造ノイズの物理的実装として機能
```

#### 先行事例の確認

- ORAM (Oblivious RAM): メモリアクセスパターンの隠蔽。グラフ構造の隠蔽ではない
- Differential Privacy on Graphs: ノイズをエッジ/ノードに追加。しかし「ダミーノードを実体として維持する」アプローチは未踏
- Tor padding: トラフィック量の均一化。知識グラフのトポロジー均一化ではない
- k-anonymity for graphs: 部分グラフの匿名化。ファントムノード注入とは異なるアプローチ

→ ダミー知識ノードの体系的注入によるトポロジー難読化は先行事例なし。

---

## 新規性サマリー

| # | 概念 | 新規性 | 再評価 | macOS着想 | 実装難度 | Quira固有性 |
|---|------|--------|--------|----------|---------|------------|
| 1 | Cognitive Fingerprint Resistance | ★★★★★ | — | PCC non-targetability | 中 | ★★★★★ |
| 2 | Semantic Topology Security | ~~★★★★★~~ | ★★★★☆ | RAdAC拡張 | 高 | ★★★★★ |
| 3 | Verifiable Local AI Transparency | ★★★★☆ | — | PCC transparency log | 低 | ★★★★☆ |
| 4 | Context Capability Morphing | ~~★★★★☆~~ | ★★★☆☆ | XACML PDP分散化 | 中 | ★★★☆☆ |
| 5 | Knowledge Entanglement Protocol | ~~★★★★☆~~ | ★★★☆☆ | - (Merkle DAG変種) | 中 | ★★★★☆ |
| 6 | Inverse Sandboxing | ~~★★★★☆~~ | **★★★★★** | App Sandbox逆転 | 中 | ★★★★☆ |
| 7 | Ephemeral Computation Zones | ~~★★★★☆~~ | ★★★☆☆ | PCC stateless + SE | 高 | ★★★★☆ |
| 8 | Privilege Ring Architecture | ★★★☆☆ | — | SPTM/TXM | 高 | ★★★☆☆ |
| 9 | Federated Knowledge Attestation | ~~★★★☆☆~~ | ★★☆☆☆ | PCC attestation | 極高 | ★★★★☆ |
| 10 | Phantom Knowledge Obfuscation | ★★★☆☆ | — | - (ORAM着想) | 中 | ★★★★★ |

---

## 推奨する研究優先順位（再評価後）

> 再評価に基づく優先順位。形式的脅威モデル (threat-model.md) の完成が全ての前提条件。

### Tier 1: 最も研究価値が高い（論文化ポテンシャル）

1. **Cognitive Fingerprint Resistance (§1)** ★★★★★ — 新脅威クラスの定義 = 最大の研究インパクト。threat-model.md §5.1 のエントロピー分析と直結
2. **Inverse Sandboxing (§6)** ★★★★★ — 測定可能・検証可能・実装可能。エントロピー制限による情報理論的チャネル容量制限
3. **Verifiable Local AI Transparency (§3)** ★★★★☆ — 実装コスト最小。Phase R1 で即時着手可能

### Tier 2: 先行研究を正しく位置づけた上で差別化

4. **Semantic Topology Security (§2)** ★★★★☆ — RAdAC を正しく引用した上で、グラフトポロジーメトリクスの新規入力源としての差別化
5. **Phantom Knowledge Obfuscation (§10)** ★★★☆☆ — ダミーノードの品質問題が未解決だが、threat-model.md §5.3 の構造匿名性分析と連携

### Tier 3: 限定的な新規性（実装の工夫で差別化）

6. **Context Capability Morphing (§4)** ★★★☆☆ — XACML PDP の分散化として位置づけ
7. **Knowledge Entanglement (§5)** ★★★☆☆ — 循環グラフ問題の解決が先決
8. **Privilege Ring Architecture (§8)** ★★★☆☆ — 概念は既存、適用が新規

### Tier 4: 技術的制約により棚上げ

9. **Ephemeral Computation Zones (§7)** ★★★☆☆ — `zero-on-free` + `explicit_bzero` で十分。暗号学的消去はコスト過大
10. **Federated Knowledge Attestation (§9)** ★★☆☆☆ — zkML の成熟待ち。Phase 1 は既存コード署名と同等

---

## 既存パラダイムとの関係

| 新規概念 | 拡張する既存パラダイム | 関係 |
|---------|-------------------|------|
| Cognitive Fingerprint Resistance | Paradigm 4 (Temporal) | 時間的プライバシーを認知レベルに拡張 |
| Semantic Topology Security | Paradigm 2 (IFC) | 静的ラベル → 動的トポロジーベースのフロー制御 |
| Verifiable Local AI Transparency | Paradigm 5 (Adversarial ML) | AI整合性の検証可能性を追加 |
| Context Capability Morphing | Paradigm 1 (Capability) + 4 (Temporal) | 静的ケーパビリティを多次元文脈で動的化 |
| Knowledge Entanglement | Paradigm 6 (Crypto) | 暗号学的手法をグラフ整合性に適用 |
| Inverse Sandboxing | Paradigm 5 (Adversarial ML) | 入力防御 → 出力制限のパラダイムシフト |
| Ephemeral Computation Zones | Paradigm 7 (HW-SW Co-Design) | ハードウェアキー管理による一時的計算保護 |
| Privilege Ring Architecture | Paradigm 7 (HW-SW Co-Design) | SPTM/TXMモデルのソフトウェア実装 |
| Federated Knowledge Attestation | Paradigm 6 (Crypto) | ZK proofs のP2P知識共有への応用 |
| Phantom Knowledge | Paradigm 8 (Living Security) | 適応的プライバシー保護の具体的メカニズム |

---

## 次のステップ

Founder承認後:
1. **threat-model.md の検証実験**: §5 の仮説 H1-H6 を優先度順に実測
2. **§6 Inverse Sandboxing のプロトタイプ**: エントロピー制限パイプラインの PoC 実装
3. **§1 Cognitive Fingerprint**: 合成データセットでの de-anonymization シミュレーション
4. **§3 VLAT**: provenance record の実装（低コスト、即時着手可能）
5. 各概念の学術論文ドラフト準備（§1, §6 が最も論文化の価値がある）
