# Quira Browser — Security Hardening Research

> Version: 1.0 | Date: 2026-03 | Author: CEO Division (Opus)
> Status: Research Draft | Scope: Enhancements to existing security concepts
> Depends: threat-model.md, deep-architecture-research.md, emergent-interaction-research.md, radical-architecture.md

---

## 概要

既存26概念の防御カバレッジを精査した結果、6件の構造的弱点を特定し、それぞれに対する強化策を設計した。本文書は既存概念の**拡張**であり、新規概念（frontier-security-research.md）とは独立して適用可能。

### 動機

| 敵対者クラス | Phase 1 カバレッジ | 判定 |
|------------|------------------|------|
| $\mathcal{A}_1$ — ネットワーク観察者 | 40% | 危険 |
| $\mathcal{A}_2$ — 悪意あるWebコンテンツ | 80% | 良好 |
| $\mathcal{A}_3$ — 悪意ある拡張機能 | 75% | 良好 |
| $\mathcal{A}_4$ — OS レベル攻撃者 | 60% | 要注意 |
| $\mathcal{A}_5$ — ブラウザベンダー | 30% | 致命的 |

| セキュリティプロパティ | Phase 1 達成度 | 判定 |
|---------------------|--------------|------|
| S1 グラフ機密性 | 85% | 十分 |
| S2 グラフ完全性 | 80% | 十分 |
| S3 削除完全性 | 60% | 不足 |
| S4 フロー分離 | 50% | 不足 |
| S5 時間的整合性 | 40% | 危険 |

---

## E1. Embedding Residue Tracking (IRD + RSIP 拡張)

### 対象弱点

$\Phi: V \to \mathbb{R}^{384}$ で生成される埋め込みベクトルは、推論残留物の中で最も回復困難な形態である。IRDの現在の dependency_map は直接・伝播・統計的残留物を追跡するが、**埋め込みベクトルからの逆変換攻撃**（embedding inversion attack）を明示的にモデル化していない。

### 脅威モデル

埋め込みベクトル $\phi_i = \Phi(v_i)$ から元テキスト $v_i.\text{summary}$ を復元する攻撃:

$$\hat{t} = \arg\max_{t \in \mathcal{T}} P(t | \phi_i; \theta_{\text{inv}})$$

2024年以降、Sentence-BERT/E5系モデルに対する inversion attack の成功率は BLEU 0.5+ に達している（Morris et al., 2023; Li et al., 2024）。

### 強化設計

IRD の残留物分類に **R5: Embedding Residue** カテゴリを追加:

```
enum ResidueType {
    Direct,          // R1: 直接残留物
    Propagated,      // R2: 伝播残留物
    Embedded,        // R3: 埋め込み残留物（既存）
    Statistical,     // R4: 統計的残留物
    EmbeddingVector, // R5: 埋め込みベクトル残留物 ← NEW
}
```

R5 固有の追跡フィールド:

| フィールド | 型 | 説明 |
|-----------|------|------|
| `inversion_hazard_score` | `f64` | ベクトルからの逆変換リスク (0.0–1.0) |
| `dependent_indices` | `Vec<IndexId>` | このベクトルを含むFTS5/ANN インデックス |
| `key_derivation_path` | `KeyPath` | CGS (N1) と統合時の暗号鍵パス |

RSIP 実行時の追加ステップ:

1. R5 残留物が検出されたノードの $\phi_i$ を特定
2. 関連するANNインデックスからベクトルを除去
3. FTS5インデックスの再構築（ベクトルなしで）
4. 除去後に $\hat{t} = \text{inv}(\phi_i)$ のBLEUスコアが閾値以下であることを検証

### 対象敵対者

- $\mathcal{A}_3$ (拡張機能がembedding APIにアクセス)
- $\mathcal{A}_4$ (ディスク上のインデックスファイルを窃取)

### 実装フェーズ: Phase 1–2

---

## E2. Inference Provenance Chain (TCV 拡張)

### 対象弱点

TCV はナビゲーションエッジ $E_\text{nav}$ の因果連鎖をハッシュチェーンで記録するが、AI推論エッジ $E_\text{ai\_inferred}$ の因果入力を追跡していない。推論エッジ「A は B に関連する」がどのノード群の分析結果から導出されたかが不明。

### 問題の形式化

AI推論エッジ $e_\text{ai} = (v_i, v_j, \text{ai\_inferred})$ に対し、その因果入力集合:

$$\text{CausalInputs}(e_\text{ai}) = \{v_{k_1}, v_{k_2}, \ldots, v_{k_m}\}$$

が定義されていない。これは以下の問題を引き起こす:

1. **削除の不完全性**: $v_{k_1}$ を削除しても $e_\text{ai}$ が残存し、$v_{k_1}$ の存在が推論可能
2. **監査の不能**: 推論結果の根拠を事後検証できない
3. **RSIP の盲点**: 因果入力が不明な推論エッジはパージ対象から漏れる

### 強化設計

TCV ハッシュチェーンエントリに `causal_inputs` フィールドを追加:

```rust
struct TcvEntry {
    node_id: NodeId,
    edge_type: EdgeType,
    timestamp: u64,
    prev_hash: Hash,
    content_hash: Hash,
    // NEW: AI推論エッジの因果入力
    causal_inputs: Option<Vec<CausalInput>>,
}

struct CausalInput {
    source_node_id: NodeId,
    contribution_weight: f64,  // 0.0–1.0
    input_snapshot_hash: Hash, // 入力時点のノードハッシュ
}
```

因果入力の記録タイミング:

1. AIパイプラインが推論エッジを生成する時点で、使用した全ノードIDと寄与度を記録
2. `contribution_weight` は attention score または feature importance から導出
3. `input_snapshot_hash` はクエリ時点のノード内容ハッシュ（後から改変されても因果は保持）

### IRD + RSIP との統合

- IRD: `causal_inputs` を辿ることで推論残留物の完全なグラフが構築可能
- RSIP: ノード削除時に `causal_inputs` に含まれる全推論エッジを自動でパージ候補に

### 対象敵対者

- 全クラス（因果追跡は防御基盤の完全性に関わる）

### 実装フェーズ: Phase 2

---

## E3. Immutable Audit Commitment (CSEB 拡張)

### 対象弱点

CSEBはリアルタイムのイベント監視・ルーティング基盤として設計されているが、イベントの**不変記録**を保証していない。攻撃者がCSEBのイベントバッファを改竄した場合、侵害の証拠が消失する。

### 強化設計

CSEBにappend-only監査コミットメント層を追加:

```
CSEB Event → Audit Buffer (append-only, mmap)
                  │
                  ├─ 1時間ごと → Merkle Root 算出
                  │                    │
                  │                    └─ SKV にクロスコミット
                  │
                  └─ リアルタイム → 既存CSEBルーティング（変更なし）
```

監査イベントスキーマ（**プライバシー保護型**）:

```rust
struct AuditEvent {
    timestamp: u64,
    source: EventSource,       // CSEB rule ID
    action: AuditAction,       // Read/Write/Delete/Deny/Alert
    affected_count: u32,       // ノード数（IDは記録しない）
    decision: SecurityDecision, // Allow/Deny/Escalate
    posture_level: u8,         // ASP posture at the time
    // 注意: node_id, content, user入力は一切記録しない
}
```

**設計原則**: フォレンジック有用性とプライバシーのバランス。「何が起きたか」のパターン（アクション種別、頻度、判定結果）は記録するが、「何に対して」の具体的コンテンツは記録しない。

Merkle Root のSKV統合:

$$\text{MerkleRoot}(h) = H(H(\text{event}_1 \| \text{event}_2) \| H(\text{event}_3 \| \text{event}_4) \| \ldots)$$

SKV の封印済みボリュームに定期的にルートハッシュをコミットすることで、監査ログの遡及的改竄が検出可能になる。

### N2 (Forensic Integrity Layer) との関係

E3はCSEBの拡張として監査コミットメントを追加する。N2 (FIL) はこれを専用レイヤーとして独立させ、SIEM統合やインシデントレスポンス自動化まで含む。E3はN2の**前提条件**であり、Phase 1で実装すべき最小限の監査基盤。

### 対象敵対者

- $\mathcal{A}_2$, $\mathcal{A}_3$, $\mathcal{A}_4$, $\mathcal{A}_5$

### 実装フェーズ: Phase 1–2

---

## E4. Social Recovery Layer (KPC 拡張)

### 対象弱点

KPCの暗号化はマスターパスフレーズに完全依存する。パスフレーズの紛失 = 全データの永久喪失。正当なユーザーによる災害復旧手段が存在しない。

### 強化設計

Shamir Secret Sharing (SSS) による鍵回復:

$$\text{master\_key} = \text{SSS.reconstruct}(s_1, s_2, s_3) \quad \text{where } (t, n) = (3, 5)$$

5つのシェアを生成し、任意の3つから復元可能:

| シェア | 保管先 | リスク |
|-------|--------|-------|
| $s_1$ | ユーザーのモバイルデバイス | 紛失・盗難 |
| $s_2$ | BIP39 シードフレーズ（紙に書いて保管） | 物理的破壊 |
| $s_3$ | 信頼できる連絡先 A のデバイス | 連絡先の裏切り |
| $s_4$ | 信頼できる連絡先 B のデバイス | 連絡先の裏切り |
| $s_5$ | オプション: 暗号化済みクラウドバックアップ | ベンダーリスク |

**任意の3つ**で復元可能なため、2つまでのシェアが失われても安全。

セキュリティ制約:

- SSS シェアの生成・再構築はすべてローカルデバイスで実行
- シェアは暗号化されておらず、**組み合わせ**でのみ意味を持つ
- シェアの更新: 定期的に新しいシェアセットを生成し、古いシェアを無効化
- シェア保管先のメタデータ（「誰に渡したか」）はローカルにのみ保存

### オプトイン設計

Social Recovery は**オプトイン**。デフォルトではマスターパスフレーズのみ。ユーザーが明示的に有効化した場合のみシェアを生成する。

### 対象敵対者

- 災害復旧（敵対者ではなく可用性リスク）
- $\mathcal{A}_5$ に対する間接的防御（ベンダーがロックアウトしてもシェアから復元可能）

### 実装フェーズ: Phase 2–3

---

## E5. Query Canonicalization Shield (KQR 拡張)

### 対象弱点

KQR はゼロトラスト設計でクラウドAIへのクエリを中継するが、NLクエリの**言語的指紋**（語彙選択、構文パターン、略語使用頻度）からユーザーの認知スタイルが特定可能。これは $\mathcal{A}_1$ (ネットワーク観察者) と $\mathcal{A}_5$ (ベンダー) に対する実質的な情報漏洩。

### 攻撃モデル

クエリ列 $Q = \{q_1, q_2, \ldots, q_n\}$ の言語特徴ベクトル:

$$\text{LingFP}(Q) = (\text{vocab\_dist}, \text{syntax\_tree\_depth}, \text{abbrev\_rate}, \text{query\_length\_dist}, \text{topic\_transition\_pattern})$$

$\text{LingFP}$ はユーザーを高精度で識別可能（Narayanan & Shmatikov, 2008 のスタイロメトリ研究参照）。

### 強化設計

KQR に送信前のクエリ正規化パイプライン:

```
ユーザーのNLクエリ
    │
    ├── 1. 同義語統合: 「調べる」「検索する」「探す」→ 正規形 "search"
    ├── 2. 語順正規化: 節の順序を文法を保持しつつ標準形に
    ├── 3. フィラー除去: 口語表現、冗長修飾語の除去
    ├── 4. 構造化: [Topic] [Relation] [Constraint] 形式に再構成
    └── 5. ランダム摂動: ダミー修飾語の確率的挿入
    │
    → 正規化済みクエリ → KQR Relay → Cloud AI
```

**重要**: 正規化はKQRがクラウドに送信する前にローカルで実行。ユーザーが入力したオリジナルのクエリは Context Graph に保存され、正規化版のみがネットワークに送出される。

### N7 (Cognitive Query Normalization) との関係

E5はKQRの拡張として最小限のクエリ正規化を実装する。N7 (CQN) はこれを独立した認知指紋防御システムとして拡張し、適応的正規化、ドメイン別辞書、ML ベースのスタイル中和を含む。E5はN7の**ステッピングストーン**。

### 対象敵対者

- $\mathcal{A}_1$, $\mathcal{A}_5$

### 実装フェーズ: Phase 2

---

## E6. Cascade Failure Fallback (ASP 拡張)

### 対象弱点

CSEB + CTA が同時に侵害された場合、ASPはトリガーソースを失い、アクセス制御が事実上停止する。現在の設計には**独立したフォールバック機構**がない。

### 攻撃シナリオ

```
1. 攻撃者が CSEB のイベントバッファを汚染（偽イベント注入）
2. CTA が汚染されたイベントに基づき誤った信頼判定を実行
3. ASP が CTA の判定に基づき posture を "Normal" に維持
4. 攻撃者は "Normal" posture の緩い制御下で自由にグラフにアクセス
```

### 強化設計

CSEBとCTAから**独立した**ハードウェアウォッチドッグを追加:

```rust
struct CascadeWatchdog {
    // CSEB/CTAとは独立したメモリ空間で動作
    last_cseb_heartbeat: Instant,
    last_cta_heartbeat: Instant,
    heartbeat_timeout: Duration, // default: 5秒
    lockdown_policy: LockdownPolicy,
}

struct LockdownPolicy {
    // ハードコードされた最小権限ポリシー
    allow_read: bool,       // false — グラフ読取を拒否
    allow_write: bool,      // false — グラフ書込を拒否
    allow_network: bool,    // false — ネットワークアクセスを拒否
    allow_ai_inference: bool, // false — AI推論を停止
    ui_alert: bool,         // true — ユーザーに視覚的警告を表示
}
```

動作フロー:

1. CSEB と CTA は各々 5秒ごとに watchdog にハートビートを送信
2. いずれかのハートビートが途絶した場合: **Warning** — ユーザーに通知、posture を Elevated に強制
3. **両方**のハートビートが途絶した場合: **Lockdown** — ハードコードされた LockdownPolicy を即座に適用
4. Lockdown からの復帰には CSEB + CTA の再起動と watchdog への再認証が必要

### 核心原則

Lockdown Policy は**コンパイル時に埋め込む**。ランタイムで変更不可能にすることで、攻撃者がフォールバックポリシーを改竄するリスクを排除する。

### 対象敵対者

- $\mathcal{A}_3$ (拡張機能によるCSEB/CTA妨害)
- $\mathcal{A}_4$ (メモリ攻撃によるCSEB/CTA破壊)

### 実装フェーズ: Phase 2

---

## Summary

| ID | 名称 | 対象概念 | 深刻度 | Phase |
|----|------|---------|--------|-------|
| E1 | Embedding Residue Tracking | IRD + RSIP | CRITICAL | 1–2 |
| E2 | Inference Provenance Chain | TCV | HIGH | 2 |
| E3 | Immutable Audit Commitment | CSEB | CRITICAL | 1–2 |
| E4 | Social Recovery Layer | KPC | HIGH | 2–3 |
| E5 | Query Canonicalization Shield | KQR | HIGH | 2 |
| E6 | Cascade Failure Fallback | ASP | HIGH | 2 |

### 依存関係

```
E1 (Embedding Residue) ──→ N1 (CGS) で暗号的破砕と統合
E2 (Inference Provenance) ──→ IRD + RSIP で因果追跡を完成
E3 (Audit Commitment) ──→ N2 (FIL) のフォレンジック層の前提
E5 (Query Canonicalization) ──→ N7 (CQN) の認知指紋防御の前提
E6 (Cascade Fallback) ──→ ASP + CSEB + CTA の耐障害性を保証
E4 (Social Recovery) ──→ 独立（KPC のオプトイン拡張）
```
