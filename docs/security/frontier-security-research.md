# Quira Browser — Frontier Security Research

> Version: 1.0 | Date: 2026-03 | Author: CEO Division (Opus)
> Status: Research Draft | Scope: Novel security structures not present in existing architecture
> Depends: threat-model.md, hardening-research.md, integration-matrix.md

---

## 概要

Quiraの既存26概念 + 6件の強化策（hardening-research.md）を精査した結果、現在のセキュリティアーキテクチャが**カバーしていない8つの防御領域**を特定した。本文書はこれらの空白を埋める新規セキュリティ構造を定義する。

### 既存アーキテクチャの空白

| # | 空白領域 | 影響 | 本文書の対応 |
|---|---------|------|------------|
| G1 | 暗号的削除の不在 | GDPR Art.17 技術的不適合 | N1: CGS |
| G2 | フォレンジック層の不在 | 侵害後の被害範囲特定不能 | N2: FIL |
| G3 | マイクロアーキテクチャ側チャネル | LLM推論中のキャッシュ攻撃 | N3: SEF |
| G4 | エクスポート時の構造的再識別 | グラフ構造がユーザー指紋に | N4: GEAP |
| G5 | サプライチェーン検証の不在 | SolarWinds型攻撃への脆弱性 | N5: VSCA |
| G6 | 形式的検証の不在 | 実装バグがセキュリティ不変条件を破壊 | N6: FSIE |
| G7 | クエリの認知指紋 | NLクエリからユーザー特定可能 | N7: CQN |
| G8 | DP予算管理の不在 | ε値・累積予算・枯渇時挙動が未定義 | N8: DPBC |

---

## N1. Cryptographic Graph Shredding (CGS)

### 暗号的グラフ破砕

### 問題定義

GDPR Article 17 / CCPA の削除要求に対し、SQLiteからのDELETEでは技術的に不十分:

| 残存リスク | 説明 |
|-----------|------|
| WALログ | SQLite Write-Ahead Log にDELETE前のデータが残存 |
| FTS5インデックス | 全文検索インデックスに逆索引エントリが残留 |
| Embedding残滓 | ANNインデックスにベクトルが物理的に残存 |
| ファイルシステム | unlink後もディスクセクタに未上書きデータが残存 |

### 形式的モデル

各ノード $v_i$ に対して個別の暗号鍵を導出:

$$k_i = \text{HKDF}(\text{master\_key}, v_i.\text{id} \| \text{epoch})$$

ノードデータは $k_i$ で暗号化して保存:

$$\text{ct}_i = \text{AES\text{-}256\text{-}GCM}(k_i, v_i.\text{data})$$

**削除 = 鍵の破棄**:

$$\text{Delete}(v_i) \triangleq \text{SecureZeroMemory}(k_i) \wedge \text{KeyLedger.remove}(v_i.\text{id})$$

データそのものを消す必要がない。鍵を暗号的に破壊するだけで、残存する暗号文は復号不可能になる。

### 鍵台帳 (Key Ledger)

```rust
struct KeyLedger {
    entries: BTreeMap<NodeId, KeyEntry>,
    master_key: MasterKey,  // KPC のマスターキーと統合
}

struct KeyEntry {
    derived_key_hash: Hash,  // k_i のハッシュ（検証用、鍵そのものは保持しない）
    derivation_epoch: u64,
    protection_class: KpcClass, // KPC と統合
    created_at: u64,
    // 鍵そのものはメモリ上にのみ存在し、使用時にHKDFで再導出
}
```

### 削除の暗号的証明

$$\text{Proof}(\text{Delete}(v_i)) = \text{VerifyDecryptFails}(\text{ct}_i, k'_i) \quad \forall k'_i \in \text{KeySpace}$$

実用的には: 削除後に $k_i$ で復号を試行 → 失敗を記録 = 削除完全性の暗号的証拠。CAVの Proof of Forgetting と統合。

### E1 (Embedding Residue Tracking) との統合

CGSの鍵導出パスをE1の `key_derivation_path` フィールドと共有。ノード削除時:

1. CGS: $k_i$ を破棄 → 暗号文が復号不可能に
2. E1: embedding インデックスから $\phi_i$ を除去
3. CAV: 両方の削除完全性を検証

### 新規性評価: ★★★★☆

Crypto-shredding自体はGoogle/AWSで使用されているが、パーソナルナレッジグラフのノード粒度 + embedding + 推論残滓まで含む包括的破砕は世界初。

### 対象敵対者: $\mathcal{A}_4$, $\mathcal{A}_5$ | Phase: 1–2

---

## N2. Forensic Integrity Layer (FIL)

### フォレンジック完全性レイヤー

### 問題定義

現在の7層セキュリティモデル (L1–L7) に**事後分析レイヤー**がない。侵害が発生した場合に「何が、いつ、どの範囲で流出したか」を立証する手段が存在しない。CSEBはリアルタイム監視基盤だがフォレンジック用途ではなく、E3 (Immutable Audit Commitment) はCSEBの拡張に過ぎない。

FIL は E3 の上に構築される**専用フォレンジックレイヤー** (L8) として、OSの7層モデルを拡張する。

### アーキテクチャ

```
L1–L7: 既存セキュリティ層
    │
    └──→ CSEB Events ──→ E3 Audit Buffer (append-only)
                              │
                              ├──→ FIL Analyzer ──→ Incident Classification
                              │         │
                              │         ├── Pattern Detection (頻度異常、時間帯異常)
                              │         ├── Blast Radius Estimation (SBRC統合)
                              │         └── Evidence Preservation
                              │
                              └──→ FIL Export ──→ SIEM (CEF/JSON)
                                                    └── Incident Response Automation
```

### プライバシー保護型フォレンジック

FILの核心原則: **行動パターンは記録するが、知識内容は記録しない**。

| 記録する | 記録しない |
|---------|----------|
| イベント種別 (Read/Write/Delete/Deny) | node_id |
| 影響ノード数 (集計値) | ノードの内容・タイトル |
| CSEB ルール ID | ユーザーのクエリテキスト |
| 判定結果 (Allow/Deny/Escalate) | エンティティ名 |
| 時刻・頻度パターン | 埋め込みベクトル |
| ASP posture レベル | URL |

### インシデント分類

```rust
enum IncidentSeverity {
    /// 通常の偏差 — ログ記録のみ
    Info,
    /// 単一ルール違反 — ASP への通知
    Warning,
    /// 複数ルール違反またはパターン異常 — ユーザーに通知
    Alert,
    /// CSEB/CTA 障害または大量データアクセス — Lockdown 推奨
    Critical,
}
```

### SIEM統合

外部SIEM連携はオプトイン。エクスポート形式:

- **CEF** (Common Event Format): ArcSight, Splunk, QRadar 互換
- **JSON**: カスタム統合用

```json
{
  "version": "1.0",
  "timestamp": "2026-03-30T10:15:30Z",
  "severity": "Alert",
  "source": "cseb_rule_42",
  "action": "Deny",
  "affected_count": 15,
  "posture": 3,
  "pattern": "burst_read_anomaly"
}
```

### 新規性評価: ★★★★★

プライバシー保護型フォレンジック（ノード内容を記録せず行動パターンのみ記録）はパーソナルブラウザにおいて世界初。

### 対象敵対者: $\mathcal{A}_2$, $\mathcal{A}_3$, $\mathcal{A}_4$, $\mathcal{A}_5$ | Phase: 2

---

## N3. Speculative Execution Firewall (SEF)

### 投機実行ファイアウォール

### 問題定義

Spectre系攻撃はGecko FissionのSite Isolationでは完全に緩和されない。Quira固有のリスク: 同一プロセス内でLLM推論とContext Graph読み取りが共存する場合、キャッシュタイミング攻撃でembeddingベクトルが漏洩し得る。

| 攻撃ベクトル | 説明 | Fissionでの緩和 |
|------------|------|---------------|
| Spectre v1 (BCB) | 境界チェック回避 | Site Isolation で部分的 |
| Spectre v2 (BTI) | 分岐ターゲット注入 | retpoline で部分的 |
| Spectre-BHB | 分岐履歴バッファ汚染 | 未緩和 |
| MDS/TAA | マイクロアーキテクチャデータサンプリング | マイクロコード依存 |

### 防御設計

4層の緩和策:

#### Layer 1: ビルド時緩和

- **retpoline**: 全間接分岐を retpoline に変換 (`-mretpoline`)
- **SLH**: Speculative Load Hardening — 投機的ロードにマスクを適用 (`-mspeculative-load-hardening`)
- **LVI**: Load Value Injection 緩和 (`-mlvi-hardening`)

#### Layer 2: 推論パイプライン分離

```rust
fn secure_inference(query: &NormalizedQuery, graph: &ContextGraph) -> InferenceResult {
    // Step 1: キャッシュフラッシュ（L1/L2）
    arch::flush_l1_cache();
    
    // Step 2: メモリバリア
    core::sync::atomic::fence(Ordering::SeqCst);
    
    // Step 3: グラフデータをコピー（COW）
    let isolated_data = graph.snapshot_cow(query.required_nodes());
    
    // Step 4: 分離されたデータで推論実行
    let result = ai_pipeline::infer(query, &isolated_data);
    
    // Step 5: 推論完了後にキャッシュフラッシュ
    arch::flush_l1_cache();
    
    result
}
```

#### Layer 3: High Security モード

ASP posture が Elevated 以上の場合:
- 推論中の拡張機能サスペンド
- タイマー分解能の制限 (`performance.now()` → 100μs精度)
- SharedArrayBuffer の無効化

#### Layer 4: ランタイム検出

```rust
struct SpectreDetector {
    cache_timing_baseline: Duration,
    detection_threshold: f64,  // 標準偏差の倍数
}

impl SpectreDetector {
    fn detect_anomaly(&self, observed: Duration) -> bool {
        let z_score = (observed - self.cache_timing_baseline) / self.std_dev;
        z_score > self.detection_threshold
    }
}
```

### 新規性評価: ★★★☆☆

retpoline/SLHは既存だが、「ブラウザ内蔵LLM推論へのSpectre緩和」という組み合わせ適用は新規。

### 対象敵対者: $\mathcal{A}_4$ | Phase: 2–3

---

## N4. Graph Export Anonymization Protocol (GEAP)

### グラフエクスポート匿名化プロトコル

### 問題定義

ユーザーがリサーチセッションをエクスポート/共有する際、グラフ構造自体がフィンガープリントとして機能する:

| 構造的特徴 | 識別力 | 説明 |
|-----------|-------|------|
| 次数分布 | 高 | ユーザーの閲覧パターンの特徴 |
| クラスタリング係数 | 高 | トピック間の回遊パターン |
| スペクトル特性 | 極高 | 隣接行列の固有値分布は個人固有 |
| 中心性分布 | 中 | 重要ノードの分布パターン |

Narayanan & Shmatikov (2009) の研究により、匿名化されたソーシャルグラフでもグラフ構造だけで33%のユーザーを再識別可能であることが示されている。パーソナルナレッジグラフはさらに特異性が高い。

### 匿名化パイプライン

エクスポート時に自動適用される4段階の構造的摂動:

#### Stage 1: Edge Differential Privacy

$$\Pr[\mathcal{M}(G) \in S] \leq e^\varepsilon \cdot \Pr[\mathcal{M}(G') \in S]$$

ε-DP でエッジをフリップ（追加/削除）。コミュニティ構造は保持しつつ、個別エッジの存在を確率的保証の下に隠蔽。

デフォルト $\varepsilon = 1.0$（中程度のプライバシー保証）。ユーザー設定可能。

#### Stage 2: 次数キャッピング

表示上の最大次数を制限:

```rust
fn cap_degree(graph: &ExportGraph, max_degree: usize) -> ExportGraph {
    // 各ノードの次数が max_degree を超える場合、
    // ランダムに選択したエッジを除去
    // 除去候補の選択は一様ランダム（バイアスなし）
}
```

#### Stage 3: ダミーサブグラフ注入

PKO (Phantom Knowledge Obfuscation) のダミーノード生成を活用:

- 元グラフのトポロジー統計量（次数分布、クラスタリング係数）を保持するダミーサブグラフを生成
- ダミーノードにはプラウシブルな（もっともらしいが架空の）メタデータを付与
- ダミー比率: 元ノード数の 10–20%（設定可能）

#### Stage 4: 時間順序シャッフル

ノード作成タイムスタンプをランダム化:

$$\tau'_i = \tau_i + \text{Lap}(\lambda) \quad \text{where } \lambda = \frac{\Delta \tau}{\varepsilon_\tau}$$

ラプラスノイズを加算し、時間的な行動パターンの推定を防止。

### AGTR との統合

AGTR の Topological Invariant Monitor がエクスポート前にグラフの識別可能性スコアを算出。スコアが閾値を超える場合、GEAPの摂動強度を自動調整。

### 新規性評価: ★★★★☆

グラフDP自体は学術的に存在するが、パーソナルナレッジグラフに特化したエクスポート匿名化プロトコルは初。

### 対象敵対者: $\mathcal{A}_1$, $\mathcal{A}_3$ | Phase: 2–3

---

## N5. Verifiable Supply Chain Attestation (VSCA)

### 検証可能サプライチェーン証明

### 問題定義

Quiraはllama.cpp、ONNX Runtime、SQLite、OpenSSL等の外部ライブラリを組み込む。これらの完全性が検証されていない場合、SolarWinds型の攻撃で全ユーザーが危殆化する。$\mathcal{A}_5$ (ベンダー自身への不信) に対する防御でもある。

### SLSA Level 3 準拠

[SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) の Level 3 要件:

| 要件 | 実装 |
|------|------|
| Source: バージョン管理 | Git + signed commits |
| Build: ビルド自動化 | GitHub Actions / CI |
| Build: ビルド環境の隔離 | Ephemeral containers |
| Provenance: 来歴の自動生成 | SLSA provenance v1.0 |
| Provenance: 来歴の不偽造性 | Sigstore keyless signing |

### SBOM (Software Bill of Materials)

全依存関係をSPDX/CycloneDX形式で公開:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "llama.cpp",
      "version": "b4567",
      "hashes": [{"alg": "SHA-256", "content": "abc123..."}],
      "purl": "pkg:github/ggerganov/llama.cpp@b4567"
    },
    {
      "type": "library",
      "name": "sqlite",
      "version": "3.45.0",
      "hashes": [{"alg": "SHA-256", "content": "def456..."}]
    }
  ]
}
```

### Sigstore 署名

各リリースに keyless 署名を付与:

1. CI/CDパイプラインがバイナリを生成
2. Sigstore Cosign で keyless 署名（OIDC identity = GitHub Actions ワークフロー）
3. 署名と来歴を Rekor (Certificate Transparency Log) に登録
4. ユーザーは `cosign verify` で検証可能

### 再現ビルド

同一コミットから任意の第三者がバイト同一のバイナリを生成可能:

```bash
# 第三者による検証
git checkout v1.0.0
docker run --rm quira/reproducible-build:v1.0.0 ./build.sh
sha256sum build/quira-v1.0.0 # → CI が公開したハッシュと一致
```

### LLMランタイム検証

llama.cpp / ONNX Runtime の追加検証:

- バージョン固定 (`Cargo.lock` / `package-lock.json` 相当)
- ビルド時にソースコードハッシュを検証
- 実行時にロードされたバイナリのハッシュを検証

### 新規性評価: ★★★☆☆

SLSA/Sigstore自体は既存だが、ブラウザ内蔵LLMランタイムまでカバーするSBOMは初。

### 対象敵対者: $\mathcal{A}_5$ | Phase: 1–2

---

## N6. Formal Security Invariant Engine (FSIE)

### 形式的セキュリティ不変条件エンジン

### 問題定義

Capability-Based Security (CBS) のトークン判定、IFCのラベル伝播、CTAの信頼判定 — これらはすべてコードベースのバグで破壊され得る。テストでは網羅できない状態空間のエッジケースが存在する。

形式的検証により、**特定のセキュリティ不変条件が数学的に成立すること**を証明する。

### TLA+ 仕様

Context Graph Access Gateway (CGAG) の状態機械をTLA+で定義:

```tla
---- MODULE CGAG ----
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Nodes, Extensions, CapabilityTokens

VARIABLES
    graph,        \* Context Graph の状態
    tokens,       \* 発行済みトークンの集合
    requests,     \* 保留中のリクエストキュー
    posture       \* ASP posture レベル

TypeInvariant ==
    /\ graph \in [Nodes -> SUBSET Nodes]
    /\ tokens \subseteq CapabilityTokens
    /\ posture \in 0..4

\* === セキュリティ不変条件 ===

\* INV-1: 失効済みトークンでの読取は常にDENY
RevokedTokenDeny ==
    \A t \in tokens :
        t.revoked => ~(\E r \in requests : r.token = t /\ r.result = "Allow")

\* INV-2: Lockdown中はすべてのアクセスがDENY
LockdownDeny ==
    posture = 4 => \A r \in requests : r.result = "Deny"

\* INV-3: 拡張機能は自身のスコープ外のノードにアクセス不可
ScopeIsolation ==
    \A ext \in Extensions, r \in requests :
        r.source = ext /\ r.result = "Allow"
        => r.target \in ext.scope

\* INV-4: KPC-Sealed ノードは SKV 以外からアクセス不可
SealedAccess ==
    \A r \in requests :
        graph[r.target].class = "Sealed"
        => r.source = "SKV" \/ r.result = "Deny"
====
```

### プロパティベーステスト

TLA+ spec と Rust 実装の一致を継続検証:

```rust
#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn revoked_token_always_denied(
            token in arb_token(),
            request in arb_request()
        ) {
            let mut gateway = CgagGateway::new();
            gateway.issue_token(token.clone());
            gateway.revoke_token(&token.id);
            
            let result = gateway.evaluate(request.with_token(&token));
            prop_assert_eq!(result, Decision::Deny);
        }
    }
}
```

### CI統合

PR毎にTLC model checker を実行:

```yaml
# .github/workflows/formal-verify.yml
- name: TLC Model Check
  run: |
    java -jar tla2tools.jar -config CGAG.cfg CGAG.tla
    # 10K+ 状態を探索し、全不変条件が保持されることを検証
```

### 新規性評価: ★★★★☆

AWSはTLA+をSDN/S3に使用しているが、ブラウザのcapabilityモデルへのTLA+適用は初。

### 対象敵対者: 全クラス（実装バグ防止） | Phase: 1

---

## N7. Cognitive Query Normalization (CQN)

### 認知クエリ正規化

### 問題定義

NLクエリの言語パターン（語彙選択、構文、略語使用頻度）でユーザーの認知スタイルが特定可能。Narayanan & Shmatikov (2008) のスタイロメトリ研究は、数千語のテキストから著者を95%以上の精度で特定可能であることを示している。

KQRの転送経路保護だけでは不十分 — クエリ**内容**の言語的指紋が残る。E5 (Query Canonicalization Shield) はKQRの最小拡張だが、CQNはこれを独立した防御システムに昇格させる。

### 攻撃モデル

クエリ列 $Q = \{q_1, q_2, \ldots, q_n\}$ に対する言語指紋攻撃:

$$\text{Author}(Q) = \arg\max_{u \in \mathcal{U}} P(Q | \text{LingModel}(u))$$

特徴量:

| 特徴 | 例 | 識別力 |
|------|---|-------|
| 語彙分布 | 「調べる」vs「検索する」vs「ググる」 | 高 |
| 構文木深度 | 複文の多用 vs 単文のみ | 中 |
| 略語使用率 | 「AI」vs「人工知能」 | 中 |
| クエリ長分布 | 平均語数、分散 | 高 |
| トピック遷移パターン | 連続クエリのコサイン類似度分布 | 極高 |

### 正規化パイプライン

E5の4段階パイプラインを以下の高度な処理で拡張:

#### Stage 1: ドメイン適応型同義語辞書

```rust
struct DomainSynonymDict {
    general: HashMap<String, String>,      // 一般: 「調べる」→「検索」
    tech: HashMap<String, String>,         // 技術: 「バグ」→「defect」
    medical: HashMap<String, String>,      // 医療: 「風邪」→「感冒」
    // ドメイン検出はローカルLLMで自動実行
}
```

#### Stage 2: ML ベースのスタイル中和

ローカルLLMを使用してクエリを「スタイル中立形」に変換:

```
入力: "ちょっとこのAIの仕組みが知りたいんだけど、特にtransformerのattentionの部分"
正規化: "transformer attention mechanism explanation"
```

**重要**: この変換はローカルで実行される。クラウドに送信されるのは正規化後のクエリのみ。

#### Stage 3: 確率的クエリバッチング

個々のクエリではなく、複数クエリをバッチにまとめて送信:

- 時間ウィンドウ (10秒) 内のクエリをバッチ化
- バッチ内のクエリ順序をランダム化
- ダミークエリを確率的に挿入 (20%の確率)

#### Stage 4: トピック遷移の平滑化

連続クエリ間のコサイン類似度が急激に変化する場合（トピックジャンプ）、中間的なブリッジクエリを挿入して遷移を平滑化。

### E5 との関係

E5はKQRの拡張として最小限の正規化を実装。CQNはE5の上に構築される独立システムで、ML正規化、バッチング、トピック平滑化を追加。E5が前提条件。

### 新規性評価: ★★★★★

クエリの言語的指紋を体系的に消去するアプローチは、どのブラウザ・検索エンジンにも存在しない。

### 対象敵対者: $\mathcal{A}_1$, $\mathcal{A}_5$ | Phase: 2

---

## N8. Differential Privacy Budget Controller (DPBC)

### 差分プライバシー予算管理器

### 問題定義

既存の概念（AGTR, CSELP）は「DPノイズを注入する」と記述しているが、以下が未定義:

- ε値の選択根拠
- 累積予算の追跡方法
- 予算枯渇時の挙動
- 合成定理 (composition theorem) の適用

DPの保証は**累積的に劣化する**。個々のクエリが ε-DP を満たしていても、$k$ 回のクエリ後の合計保証は Sequential Composition により $k \cdot \varepsilon$-DP にしかならない。予算管理なしのDP適用は「DPをしている」という虚偽の安全感を与えるだけ。

### 予算モデル

$$\varepsilon_{\text{total}} = \sum_{i=1}^{k} \varepsilon_i \leq \varepsilon_{\text{budget}}$$

| パラメータ | デフォルト値 | 根拠 |
|-----------|------------|------|
| $\varepsilon_{\text{budget}}$ | 1.0 / 月 | US Census (10.0), Apple (2-8), Google RAPPOR (ln(3)≈1.1) の中央値 |
| $\delta$ | $10^{-5}$ | $\delta < 1/n$ の慣例（n = ノード数） |
| リセット周期 | 月次 | 予算は毎月1日にリセット |

### 合成定理の選択

| 定理 | 保証 | 使用場面 |
|------|------|---------|
| Basic Composition | $k\varepsilon$ | 少数クエリ |
| Advanced Composition | $\sqrt{2k \ln(1/\delta')}\varepsilon + k\varepsilon(e^\varepsilon - 1)$ | 多数クエリ |
| Rényi DP (zCDP) | $\rho_{\text{total}} = \sum \rho_i$ | 最も tight な保証 |

DPBC はデフォルトで **zCDP** (zero-Concentrated DP) を採用:

$$\rho_i = \frac{\varepsilon_i^2}{2}$$

zCDP から $(\varepsilon, \delta)$-DP への変換:

$$\varepsilon = \rho + 2\sqrt{\rho \ln(1/\delta)}$$

### アーキテクチャ

```rust
struct DpBudgetController {
    monthly_budget: f64,        // ε_budget (default: 1.0)
    consumed: f64,              // Σε_i
    delta: f64,                 // δ (default: 1e-5)
    ledger: Vec<DpExpenditure>, // 消費記録
    composition: CompositionTheorem, // Basic / Advanced / zCDP
}

struct DpExpenditure {
    timestamp: u64,
    component: DpComponent,    // AGTR / CSELP / GEAP / etc.
    epsilon: f64,
    description: String,       // "AGTR edge flip (export)"
}

enum BudgetDecision {
    Allow { remaining: f64 },
    Throttle { remaining: f64, reduced_epsilon: f64 },
    Deny { next_reset: u64 },
}
```

### 予算枯渇時の挙動

```
consumed < 70% → Allow (通常動作)
70% ≤ consumed < 90% → Throttle (ε値を自動縮小、ユーザーに通知)
90% ≤ consumed < 100% → Warning (オプトイン確認、ε値をさらに縮小)
consumed ≥ 100% → Deny (データ収集・分析を停止、翌月までブロック)
```

### UI統合

`quira://settings/privacy/budget` でリアルタイム予算ゲージ:

```
プライバシー予算 (3月)
████████░░ 78% 使用済み  残り: ε = 0.22

内訳:
  AGTR (エクスポート匿名化)  ε = 0.35
  CSELP (セッション分析)     ε = 0.28
  GEAP (グラフ匿名化)       ε = 0.15

[予算をリセット] [詳細設定]
```

### Local DP の原則

ノイズ注入はすべて**デバイス上**で実行:

- Quira サーバーを信頼する必要がない (trustless)
- クラウドに送信されるデータはすでにDPノイズが適用済み
- ε予算はデバイス上でのみ追跡（サーバーはε値を知らない）

### 新規性評価: ★★★★☆

DPの学術理論は成熟しているが、ブラウザにプライバシー予算UIを統合し、複数コンポーネント横断でzCDP予算を管理するプロダクトは皆無。

### 対象敵対者: $\mathcal{A}_1$, $\mathcal{A}_5$ | Phase: 2

---

## Summary & Priority Map

### 全N概念の一覧

| ID | 略記 | 正式名称 | ★ | Phase | 主要敵対者 |
|----|------|---------|---|-------|----------|
| N1 | **CGS** | Cryptographic Graph Shredding | ★4 | 1–2 | $\mathcal{A}_4$, $\mathcal{A}_5$ |
| N2 | **FIL** | Forensic Integrity Layer | ★5 | 2 | $\mathcal{A}_2$–$\mathcal{A}_5$ |
| N3 | **SEF** | Speculative Execution Firewall | ★3 | 2–3 | $\mathcal{A}_4$ |
| N4 | **GEAP** | Graph Export Anonymization Protocol | ★4 | 2–3 | $\mathcal{A}_1$, $\mathcal{A}_3$ |
| N5 | **VSCA** | Verifiable Supply Chain Attestation | ★3 | 1–2 | $\mathcal{A}_5$ |
| N6 | **FSIE** | Formal Security Invariant Engine | ★4 | 1 | 全クラス |
| N7 | **CQN** | Cognitive Query Normalization | ★5 | 2 | $\mathcal{A}_1$, $\mathcal{A}_5$ |
| N8 | **DPBC** | Differential Privacy Budget Controller | ★4 | 2 | $\mathcal{A}_1$, $\mathcal{A}_5$ |

### 依存関係グラフ

```
E3 (Audit Commitment)
  └──→ N2 (FIL) — E3の上に専用フォレンジック層を構築

E1 (Embedding Residue) + N1 (CGS)
  └──→ CAV — 暗号的削除 + embedding除去 + 忘却証明の完全パイプライン

E5 (Query Canonicalization)
  └──→ N7 (CQN) — 基本正規化の上にML正規化を構築

N8 (DPBC)
  └──→ N4 (GEAP), AGTR, CSELP — 全DP消費コンポーネントの予算を管理

N6 (FSIE)
  └──→ CBS, IFC, CTA — 不変条件の形式的検証

N5 (VSCA)
  └──→ 独立（ビルドパイプラインに統合）

N3 (SEF)
  └──→ 独立（ビルド + ランタイムに統合）
```

### 脅威カバレッジの改善見込み

| 敵対者 | 現状 | +E1–E6 | +N1–N8 | 改善幅 |
|--------|------|--------|--------|--------|
| $\mathcal{A}_1$ | 40% | 50% | 70% | +30% |
| $\mathcal{A}_2$ | 80% | 85% | 90% | +10% |
| $\mathcal{A}_3$ | 75% | 80% | 90% | +15% |
| $\mathcal{A}_4$ | 60% | 70% | 85% | +25% |
| $\mathcal{A}_5$ | 30% | 40% | 65% | +35% |

| プロパティ | 現状 | +E1–E6 | +N1–N8 | 改善幅 |
|-----------|------|--------|--------|--------|
| S3 削除完全性 | 60% | 75% | 95% | +35% |
| S4 フロー分離 | 50% | 55% | 70% | +20% |
| S5 時間的整合性 | 40% | 55% | 65% | +25% |

### 新規攻撃ベクトル

N1–N8 が新たに防御する攻撃ベクトル:

| ベクトル | 敵対者 | 防御 |
|---------|--------|------|
| A4.4 Embedding Inversion via Disk Theft | $\mathcal{A}_4$ | N1 (CGS) |
| A4.5 Spectre-BHB on LLM Inference | $\mathcal{A}_4$ | N3 (SEF) |
| A5.3 Binary Supply Chain Tampering | $\mathcal{A}_5$ | N5 (VSCA) |
| A5.4 Query Stylometry Identification | $\mathcal{A}_5$ | N7 (CQN) |
| A-cross Audit Log Tampering | 全クラス | N2 (FIL) |
| A-cross Graph Structure Re-identification | $\mathcal{A}_1$, $\mathcal{A}_3$ | N4 (GEAP) |
| A-cross DP Budget Exhaustion | $\mathcal{A}_1$, $\mathcal{A}_5$ | N8 (DPBC) |
| A-cross Security Invariant Violation | 全クラス | N6 (FSIE) |
