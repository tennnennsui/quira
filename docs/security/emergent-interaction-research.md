# Quira Browser — Emergent Interaction Security Research

> Version: 1.0 | Date: 2026-07-12 | Author: CEO Division (Opus)
> Status: Research Complete | Scope: Novel security structures arising from cognition-AI-graph interactions
> Depends: threat-model.md, novel-research.md, deep-architecture-research.md, radical-architecture.md, research.md

---

## Coverage Gap Analysis

既存の6文書は以下の領域を網羅している:
- **architecture.md**: macOS セキュリティ機構の Context Graph への写像（12機構）
- **radical-architecture.md**: ブラウザセキュリティの既存パラダイム拡張（8パラダイム）
- **novel-research.md**: AI + ブラウザの融合から生じる新概念（10概念）
- **deep-architecture-research.md**: macOS 深層機構の詳細翻訳（8構造）
- **research.md**: 標準化されたセキュリティフレームワーク（6層 + TEE/DP/HE 等）
- **threat-model.md**: 形式的脅威モデル（$G=(V,E,\Sigma,\Phi,\Tau)$, $\mathcal{A}_1$-$\mathcal{A}_5$）

**未探索の空白地帯:** ユーザーの認知パターン、AIの推論プロセス、グラフ構造の動的変化——この三者の**相互作用**から創発するセキュリティ課題。個別の防御（コンテンツフィルタリング、IFC、サンドボックス）では捕捉できない、知識のライフサイクル全体を貫く構造的脅威がここにある。

本文書はこの空白を8つの新構造で埋める。

---

## Table of Contents

1. [Knowledge Supply Chain Integrity (KSCI)](#1-knowledge-supply-chain-integrity-ksci)
2. [Inference Residue Defense (IRD)](#2-inference-residue-defense-ird)
3. [Semantic Blast Radius Containment (SBRC)](#3-semantic-blast-radius-containment-sbrc)
4. [Adversarial Graph Topology Resistance (AGTR)](#4-adversarial-graph-topology-resistance-agtr)
5. [Temporal Causality Verification (TCV)](#5-temporal-causality-verification-tcv)
6. [Cross-Session Entropy Leakage Prevention (CSELP)](#6-cross-session-entropy-leakage-prevention-cselp)
7. [Retroactive Sanitization with Inference Purging (RSIP)](#7-retroactive-sanitization-with-inference-purging-rsip)
8. [Contextual Amnesia Verification (CAV)](#8-contextual-amnesia-verification-cav)
9. [Summary & Priority Map](#9-summary--priority-map)

---

## 1. Knowledge Supply Chain Integrity (KSCI)

### 既存概念との差異

| 既存概念 | 保護対象 | KSCI が異なる点 |
|---------|---------|---------------|
| Context Gatekeeper | コードの実行可否 | KSCI は**知識そのもの**の信頼性を検証する |
| XProtect / CED | 既知の悪意あるシグネチャ | KSCI は未知の「真実だが戦略的に配置された」コンテンツを検出する |
| Adversarial ML Defense | AI モデルの保護 | KSCI はモデルではなく**入力の知識サプライチェーン**を検証する |
| Content IFC | データの流れの方向制御 | KSCI は流入する**知識の出自と整合性**を評価する |

### 問題定義

ソフトウェアサプライチェーン攻撃（SolarWinds, Log4Shell）は「正規の配布経路を通じて悪意あるコードを注入する」脅威である。KSCI はこの概念を**知識ドメイン**に拡張する: 攻撃者が**正規の Web コンテンツとして戦略的に配置した情報**が、ユーザーの Knowledge Graph を汚染する脅威を扱う。

これはフィッシング（偽サイトへの誘導）とは本質的に異なる。KSCI が対象とするのは**真正なドメイン上の、表面的には正当なコンテンツ**であり、その目的がグラフ構造の操作にある場合である。

### 形式的モデル

知識サプライチェーンを有向グラフとして定義する:

$$\text{KSC} = (S, T, \pi, \iota)$$

- $S = \{s_1, ..., s_n\}$: 情報源の集合（Web ページ、API、ドキュメント）
- $T$: 信頼スコア関数 $T: S \to [0, 1]$
- $\pi: S \to \mathcal{P}(S)$: 出自追跡関数（情報源 $s$ が参照/引用する他の情報源の集合）
- $\iota: S \to \{0, 1\}$: 整合性検証関数

知識ノード $v_i$ がグラフ $G$ に追加される際の信頼スコア:

$$T_{\text{composite}}(v_i) = \alpha \cdot T_{\text{source}}(s) + \beta \cdot T_{\text{corroboration}}(v_i) + \gamma \cdot T_{\text{temporal}}(v_i)$$

ここで:
- $T_{\text{source}}(s)$: 情報源自体の信頼度（ドメイン評判、HTTPS 証明書、コンテンツ安定性）
- $T_{\text{corroboration}}(v_i)$: 他の独立した情報源による裏付けの度合い
- $T_{\text{temporal}}(v_i)$: コンテンツの時間的安定性（最近急に変更されていないか）
- $\alpha + \beta + \gamma = 1$

**サプライチェーンポイズニング検出条件:**

情報源 $s$ が以下の条件を満たす場合、ポイズニングの可能性を警告する:

$$\text{Poison}(s) \Leftrightarrow T_{\text{temporal}}(s) < \tau_t \land \Delta_{\text{semantic}}(s, s_{-1}) > \tau_s \land \text{TargetAffinity}(s, G) > \tau_a$$

- $\tau_t$: 時間的安定性の閾値（最近のコンテンツ変更）
- $\tau_s$: 意味的変化の閾値（以前のバージョンとの乖離）
- $\tau_a$: ユーザーのグラフとの親和度（ユーザーの既存知識構造への適合度が不自然に高い）

3条件の論理積が重要である。コンテンツが変更されたこと**だけ**では攻撃ではない。変更が**意味的に大きく**、かつ**特定ユーザーのグラフを標的としている**場合に限り脅威となる。

### 攻撃シナリオ

**シナリオ 1: 段階的グラフポイズニング**
1. 攻撃者は Stack Overflow の回答を複数投稿し、評判を獲得する
2. 高評判を得た後、回答を微妙に編集して**ユーザーが研究中のトピック**に関する誤情報を含める
3. ユーザーの AI パイプラインがこの改竄された回答を取り込み、Knowledge Graph に「信頼できる情報源からの知識」として追加する
4. 誤情報が他のノードとの関連性を獲得し、後続の推論に影響を与える

**シナリオ 2: 知識クラスタ標的操作**
1. 攻撃者はユーザーの公開情報（ブログ、SNS）から関心領域を推定する
2. そのトピックに関する**表面的には正当だが微妙に方向付けされた**コンテンツを複数サイトに配置する
3. ユーザーが自然な検索行動でこれらのページを閲覧すると、特定の結論に向けたナッジがグラフに蓄積される

### 防御アーキテクチャ

```
Web Content ──→ [Provenance Tracker] ──→ [Corroboration Engine] ──→ Graph
                      │                         │
                      ▼                         ▼
               Source History DB          Cross-Reference Index
               (domain reputation,        (同一主張の独立情報源数、
                content stability,         情報源間の独立性検証)
                edit timestamps)
```

**Provenance Tracker**: 情報源のメタデータを記録する。ドメインの Whois 履歴、コンテンツの Wayback Machine スナップショットとの差分、TLS 証明書の有効期間などを自動収集する。これは Web コンテンツを「サプライチェーンのアーティファクト」として扱う発想である。

**Corroboration Engine**: 同一の主張（エンティティ + 関係）が独立した情報源からも確認できるかを検証する。1つの情報源のみに依存するノードには低信頼スコアを付与し、UI 上で視覚的に区別する。

### 先行技術との関係

- **ソフトウェア SBOM**: 知識グラフの "KBOM"（Knowledge Bill of Materials）として各ノードの出自を追跡する発想
- **Wikipedia の信頼性評価**: 複数の独立した情報源による裏付け要求は百科事典の検証可能性原則に通じる
- **SSL Certificate Transparency**: 知識ノードの出自をログに記録し、後から改竄を検出可能にする

### 独創性評価: ★★★★★

知識そのものをサプライチェーン攻撃の対象として形式化した研究は、2026年7月時点で存在しない。偽情報検出 (misinformation detection) とは異なり、KSCI は「真実だが戦略的に配置された情報」をも検出対象とする点で根本的に新しい。SolarWinds 型攻撃モデルの知識ドメインへの翻訳は学術的にも未踏の領域である。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_2$（悪意ある Web コンテンツ）— ただし従来の $\mathcal{A}_2$ が想定する「不可視テキスト」「プロンプトインジェクション」ではなく、**可視コンテンツ自体が兵器化される**新しい攻撃ベクトル
- 攻撃面: S2（Renderer → AI）および S3（AI → Graph）
- 既存防御の限界: コンテンツ消毒は悪意ある HTML/JS を除去するが、**意味的に真正だがグラフを標的とするコンテンツ**には無力

---

## 2. Inference Residue Defense (IRD)

### 問題定義

ユーザーが Knowledge Graph からノードを削除した場合、そのノードのデータはディスクから消去される。しかし、AI が**削除されたノードに基づいて生成した推論**は、他のノードの属性やエンティティ関係として残存する可能性がある。これを**推論残渣** (Inference Residue) と定義する。

### 既存概念との差異

| 既存概念 | 対応する問題 | IRD が異なる点 |
|---------|------------|---------------|
| Sealed Knowledge Volume (SKV) | データの暗号化・完全性保護 | IRD は暗号化ではなく**推論チェーンの追跡と消去**を扱う |
| Differential Privacy | 統計的出力からの個人情報推定防止 | IRD は**すでに生成された推論の遡及的消去**を扱う |
| Ephemeral Computation Zones | 処理中のデータの一時性 | IRD は処理**後**に残る推論の残渣を扱う |
| Phantom Knowledge Obfuscation | ダミーノードによる統計的保護 | IRD は**実在した知識の削除後に残る推論の痕跡**を扱う |

### 形式的定義

ノード $v_i$ の推論残渣を以下のように定義する:

$$\text{IR}(v_i) = \{(v_j, a_k) \mid v_j \in V \setminus \{v_i\}, a_k \in \text{attrs}(v_j), \text{dep}(a_k, v_i) > 0\}$$

ここで $\text{dep}(a_k, v_i) \in [0, 1]$ は属性 $a_k$ が $v_i$ に依存する度合いである。

**推論依存度の計算:**

AI パイプラインが $v_i$ を処理した際の出力を $O_i$ とする。$O_i$ が他のノード $v_j$ の属性に影響を与えた場合:

$$\text{dep}(a_k, v_i) = \frac{|\text{attention}(a_k, v_i)|}{|\text{attention}(a_k, \cdot)|}$$

ここで $\text{attention}(a_k, v_i)$ は属性 $a_k$ の生成時に $v_i$ に割り当てられたアテンション重みの総和であり、$\text{attention}(a_k, \cdot)$ は全入力に対するアテンション重みの総和である。

**推論残渣が問題となる条件:**

ノード $v_i$ が削除された後、推論残渣 $\text{IR}(v_i)$ が以下を満たす場合にプライバシー侵害が発生する:

$$\exists \text{Reconstruct}: \text{IR}(v_i) \to \hat{v}_i \text{ s.t. } \text{sim}(\hat{v}_i, v_i) > \tau_r$$

すなわち、残渣から元のノードの内容を閾値 $\tau_r$ 以上の精度で再構成できる場合である。

### 推論残渣の分類

| 種類 | 定義 | 例 | 検出難易度 |
|------|------|-----|----------|
| 直接残渣 | $v_i$ から直接生成されたエッジ・属性 | 「$v_i$ に関連」というタグ | 低（参照が明示的） |
| 伝播残渣 | $v_i$ が他ノードの推論に間接的に影響した部分 | $v_i$ を含むクラスタの重心シフト | 中 |
| 埋め込み残渣 | $v_i$ の埋め込みが他ノードの類似度計算に影響した部分 | 類似度ランキングの変化 | 高 |
| 統計的残渣 | $v_i$ がクラスタ統計やトピック分布に与えた影響 | トピック分布の歪み | 極高 |

### 防御アーキテクチャ

```
Delete Request(v_i)
       │
       ▼
  [Dependency Graph Traversal]  ← 推論依存グラフを逆方向に走査
       │
       ├──→ Direct Residue: 即時削除
       │
       ├──→ Propagation Residue: 再計算キューに投入
       │         │
       │         ▼
       │    [Re-inference Engine]  ← v_i を除外して再推論
       │         │
       │         ▼
       │    影響を受けた属性を更新 or 削除
       │
       ├──→ Embedding Residue: 影響を受けた類似度インデックスを再構築
       │
       └──→ Statistical Residue: トピック統計を v_i 除外で再集計
```

**Inference Dependency Graph (IDG):** AI パイプラインが推論を行うたびに、入力ノードと出力（生成された属性、エッジ、埋め込み更新）の依存関係を記録する有向非巡回グラフ。これは「推論の出自台帳」として機能する。

$$\text{IDG} = (V_{\text{infer}}, E_{\text{dep}})$$

- $V_{\text{infer}}$: すべての推論操作の記録
- $E_{\text{dep}}$: 推論操作間の依存エッジ（ノード $v_i$ の情報が推論 $f_j$ の入力として使われた場合 $(v_i, f_j) \in E_{\text{dep}}$）

### コスト分析

| 操作 | 追加コスト | 正当性 |
|------|----------|--------|
| IDG の記録 | 推論時に依存関係をログ: ~2% オーバーヘッド | ストレージは推論回数に比例するが、各エントリは小さい（ノードID + 操作ID） |
| 直接残渣の削除 | ディスク I/O: 即時 | 参照の明示的な削除は高速 |
| 再推論 | GPU/CPU 時間: $v_i$ の影響範囲に比例 | バッチ処理で非同期実行可能 |
| 埋め込み再構築 | 影響を受けたインデックスの部分再構築 | 全再構築は不要、差分更新で対応 |

### 攻撃シナリオ

**シナリオ: 医療情報の「幽霊」**
1. ユーザーが HIV 治療に関するページを閲覧し、Knowledge Graph にノードが追加される
2. AI が推論を行い、関連する健康トピックとのエッジを生成する
3. ユーザーが当該ノードを削除する
4. しかし、AI が生成した「健康に関心がある」「免疫系に関連する研究をしている」というメタデータが他ノードの属性として残存する
5. 攻撃者（$\mathcal{A}_3$: 悪意ある拡張機能）がこの残渣からユーザーの医療関心を推定する

### 先行技術との関係

- **Machine Unlearning**: モデルから特定データの影響を除去する研究（Bourtoule et al., 2021 "SISA Training"）。IRD はモデルではなく**グラフの推論出力**からの影響除去
- **GDPR 忘れられる権利**: データ削除要求への法的対応。IRD は技術的にこれを実現するメカニズム
- **Cascade Delete (RDBMS)**: 外部キー制約に基づくカスケード削除。IRD は**推論依存関係**に基づくカスケード（確率的依存であり、決定的な外部キーではない点が異なる）

### 独創性評価: ★★★★★

AI パイプラインが生成する推論残渣を形式的に定義し、その追跡と消去のアーキテクチャを提案した研究は存在しない。Machine Unlearning は**モデル重み**からの情報除去であり、**知識グラフの推論出力**からの除去とは問題の構造が異なる。IRD は知識グラフブラウザ固有の、完全に新規の安全性概念である。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_3$（拡張機能）、$\mathcal{A}_4$（OS レベル）
- 攻撃面: S4（Extension → Graph）、S5（Graph → Export）
- 関連するセキュリティ特性: 推論耐性（§3.3）の拡張——$v_i$ 削除後も推論耐性が保持されることを要求する

---

## 3. Semantic Blast Radius Containment (SBRC)

### 問題定義

従来のセキュリティ侵害評価は定量的指標に依存する: 漏洩したレコード数、影響を受けたユーザー数、露出したバイト数。しかし、Knowledge Graph においてこの評価は根本的に不十分である。

**核心的な観察:** 100個の料理レシピノードの漏洩と、100個の精神疾患治療ノードの漏洩は、ノード数は同じだが**意味的被害**は桁違いに異なる。

SBRC は侵害の影響を**意味的単位**で測定し、封じ込め境界を意味空間で定義する。

### 既存概念との差異

| 既存概念 | 測定対象 | SBRC が異なる点 |
|---------|---------|---------------|
| IFC ラベル | データの機密性カテゴリ | SBRC は**侵害後の被害量**を意味的に定量化する |
| Context Sandbox | 構造的な分離境界 | SBRC は**意味的な封じ込め境界**を定義する |
| Knowledge Protection Classes (KPC) | 暗号化レベルの分類 | SBRC は暗号化ではなく**漏洩時の影響評価**に焦点を当てる |
| Differential Privacy ($\varepsilon$) | 統計的なプライバシー損失 | SBRC は統計的ではなく**意味的なプライバシー損失**を測定する |

### 形式的定義

ノード集合 $V' \subseteq V$ の漏洩時の意味的被害を定義する:

$$\text{SBR}(V') = \sum_{v \in V'} w(v) \cdot \text{sensitivity}(v) \cdot \text{linkability}(v)$$

各項の定義:

**感度関数** $\text{sensitivity}: V \to \mathbb{R}_{\geq 0}$

$$\text{sensitivity}(v) = \max_{c \in \text{categories}(v)} \text{base\_sensitivity}(c) \cdot (1 + \text{specificity}(v))$$

- $\text{base\_sensitivity}(c)$: カテゴリ $c$ の基本感度（医療=1.0, 金融=0.9, 個人関係=0.8, 仕事=0.3, 一般知識=0.1）
- $\text{specificity}(v)$: ノードの具体性（「糖尿病」は「健康」より具体的で、より多くの情報を含む）

**連結可能性関数** $\text{linkability}: V \to \mathbb{R}_{\geq 0}$

$$\text{linkability}(v) = \log_2(|\{e \in E \mid v \in e\}| + 1) \cdot \text{cross\_category\_factor}(v)$$

- エッジ数が多いノードは他の情報との結合により被害が増大する
- $\text{cross\_category\_factor}(v)$: $v$ が異なる感度カテゴリのノードとエッジを持つ場合に増加する係数。カテゴリ横断的なノードは、1つの漏洩が複数領域の情報を暴露するため

**重み関数** $w: V \to \mathbb{R}_{\geq 0}$

$$w(v) = 1 + \text{uniqueness}(v)$$

- $\text{uniqueness}(v)$: そのノードの情報がユーザー固有である度合い（「Python の文法」は一般知識で uniqueness ≈ 0、「患者Xの投薬記録」は uniqueness ≈ 1）

### 意味的封じ込めゾーン

SBRC は意味空間を封じ込めゾーンに分割する:

$$Z = \{Z_1, Z_2, ..., Z_m\}$$

各ゾーン $Z_k$ は以下を満たす:
1. **内部結合性**: ゾーン内のノードは意味的に関連する
2. **境界分離**: ゾーン間のエッジは最小限に制限される
3. **被害上限**: 1つのゾーンが完全に漏洩しても、$\text{SBR}(Z_k) \leq B_k$（ゾーンごとのバジェット $B_k$）

**ゾーン境界の定義:**

$$\text{boundary}(Z_k, Z_l) = \{(v_i, v_j) \in E \mid v_i \in Z_k, v_j \in Z_l\}$$

ゾーン間エッジは意味的抽象化を適用する: エッジのラベルをより一般的なカテゴリに昇格させることで、1つのゾーンの漏洩が他のゾーンの具体的内容を暴露しないようにする。

例: 医療ゾーンと仕事ゾーンの間のエッジ「糖尿病の研究で論文を書いた」は、ゾーン境界では「健康に関連する仕事をしている」に抽象化される。

### 防御アーキテクチャ

```
Knowledge Graph
       │
       ▼
  [Semantic Zone Analyzer]
       │
       ├──→ Zone 1 (Medical): sensitivity_budget = 50
       │       ├── Sub-zone 1a (Diagnoses): budget = 30
       │       └── Sub-zone 1b (Research): budget = 20
       │
       ├──→ Zone 2 (Financial): sensitivity_budget = 40
       │
       ├──→ Zone 3 (Work): sensitivity_budget = 20
       │
       └──→ Zone 4 (General): sensitivity_budget = 5
              │
              ▼
       [Cross-Zone Edge Abstractor]
              │
              ▼
       Abstracted inter-zone edges only
```

**Semantic Damage Index (SDI):** 侵害が検出された際に、漏洩したノードの SDI をリアルタイムで計算し、ユーザーに「100ノードが漏洩」ではなく「医療情報の高感度ノード3個とその周辺の一般情報12個が漏洩、推定プライバシー被害: 高」と報告する。

### 攻撃シナリオ

**シナリオ: ゾーン横断推論攻撃**
1. 攻撃者（$\mathcal{A}_3$: 拡張機能）が低感度の「仕事」ゾーンへのアクセス権を持つ
2. 仕事ゾーンのノードから「医療ゾーンの存在」と「そのゾーンとの接続パターン」を推論する
3. ゾーン境界の抽象化が不十分な場合、仕事ゾーンのデータだけから医療ゾーンの概要を再構成できる

**防御:** Cross-Zone Edge Abstractor がゾーン境界のエッジを十分に抽象化し、低感度ゾーンから高感度ゾーンの具体的内容への推論を遮断する。

### 独創性評価: ★★★★☆

侵害被害を意味的次元で定量化する試みは、データ分類フレームワーク（NIST SP 800-60）に遠い先行技術がある。しかし、知識グラフ上の意味的封じ込めゾーンと SDI による被害の定量化は新規である。ゾーン間エッジの意味的抽象化もブラウザセキュリティの文脈では未提案。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_3$（拡張機能）、$\mathcal{A}_4$（OS レベル）
- 攻撃面: S4（Extension → Graph）、S5（Graph → Export）、S7（Disk → Memory）
- 関連するセキュリティ特性: 機密性（§3.1）の拡張——$\text{Authorized}(\mathcal{A}, G)$ を意味的ゾーン単位で定義し直す

---

## 4. Adversarial Graph Topology Resistance (AGTR)

### 問題定義

既存の攻撃モデル（$\mathcal{A}_2$ の A2.1–A2.5）は**個別のノード**への攻撃を扱う: プロンプトインジェクション、エンティティポイズニング、埋め込み空間操作、認知フィンガープリント採取、クラスタ重心シフト。

AGTR は**グラフのトポロジー（構造）自体**が攻撃対象となる新しい脅威クラスを定義する。攻撃者は個々のノードの内容ではなく、ノード間の**接続パターン**を操作することで、ユーザーの知識構造を識別・追跡・操作する。

### 既存概念との差異

| 既存概念 | 防御対象 | AGTR が異なる点 |
|---------|---------|---------------|
| Cognitive Fingerprint Resistance | 認知パターンからの個人識別 | AGTR は**グラフの構造的特徴**からの識別を防ぐ |
| Semantic Topology Security | トポロジーの安全性一般 | AGTR は**意図的なトポロジー操作**という攻撃ベクトルに焦点を当てる |
| Phantom Knowledge Obfuscation | ダミーノードによる統計的保護 | AGTR はダミーノードではなく**構造的不変量の保護**を扱う |
| $k$-構造匿名性（threat-model.md §5.3） | 構造的な匿名性定義 | AGTR はこれを拡張し、**能動的なトポロジー操作攻撃**への防御を提供する |

### 形式的定義

グラフトポロジー攻撃を以下のように形式化する:

**定義 (Topology Injection Attack):**

攻撃者 $\mathcal{A}$ が Web 上に $k$ 個のページ $P = \{p_1, ..., p_k\}$ を配置し、ユーザーがこれらを閲覧した場合にグラフ $G$ に特定の部分構造 $H$ が形成されることを意図する攻撃:

$$\text{TopoInject}(\mathcal{A}, P, G) \Leftrightarrow G \oplus \text{Extract}(P) \supseteq H$$

ここで $\text{Extract}(P)$ は AI パイプラインがページ群 $P$ から抽出するノードとエッジ、$\oplus$ はグラフの合成演算。

**構造的一意性の測定:**

グラフ $G$ の構造的フィンガープリント $\mathcal{F}_{\text{topo}}(G)$ を次元数が高い特徴空間で定義する:

$$\mathcal{F}_{\text{topo}}(G) = (\text{degree\_seq}(G), \text{clustering}(G), \text{motif\_freq}(G), \text{spectral}(G))$$

- $\text{degree\_seq}(G)$: 次数列（ノードごとのエッジ数の分布）
- $\text{clustering}(G)$: クラスタリング係数のヒストグラム
- $\text{motif\_freq}(G)$: サブグラフモチーフ（三角形、星型、パス等）の頻度
- $\text{spectral}(G)$: ラプラシアン行列の固有値スペクトル

**攻撃の成功条件:**

$$\text{TopoID}(\mathcal{F}_{\text{topo}}(G), \text{Database}) < \tau_{\text{id}}$$

すなわち、トポロジー特徴だけで $N$ 人のユーザーの中からターゲットを $\tau_{\text{id}}$ 未満の候補数に絞り込めた場合、攻撃が成功である。

### 攻撃シナリオ

**シナリオ 1: Structural Watermarking**
1. 攻撃者が特定ユーザーをターゲットとする
2. ユーザーの SNS 活動から関心トピックを推定する
3. そのトピックに関する $k$ 個のページを作成し、ページ間に**特定のリンク構造**を埋め込む
4. ユーザーがこれらのページを閲覧すると、Knowledge Graph に**識別可能な部分グラフ**（ウォーターマーク）が形成される
5. 後日、攻撃者がグラフの部分情報（エクスポートやメタデータ）を入手した場合、ウォーターマークの存在からユーザーを識別する

**シナリオ 2: Bridge Node Injection**
1. 攻撃者がユーザーの Knowledge Graph 内の分離されたクラスタ間に**橋渡しノード**を注入する
2. これにより、AI の推論が本来独立すべきクラスタ間で情報を伝播させる
3. 結果として、異なる感度カテゴリ間の情報漏洩が発生する

### 防御メカニズム

**Topological Invariant Monitor (TIM):**

グラフの構造的不変量を継続的に監視し、急激な構造変化を検出する:

$$\Delta_{\text{topo}}(G_t, G_{t-1}) = \|\mathcal{F}_{\text{topo}}(G_t) - \mathcal{F}_{\text{topo}}(G_{t-1})\|_2$$

$\Delta_{\text{topo}}$ が閾値を超えた場合:
1. 最近追加されたノード群を特定する
2. それらが形成する部分構造 $H$ を分析する
3. $H$ が既知のウォーターマークパターンに一致するか検査する
4. 異常が確認された場合、ユーザーに通知し、問題のノード群の隔離を提案する

**Structural Noise Injection:**

グラフのエクスポート時に構造的ノイズを注入する（threat-model.md §5.3 の $k$-構造匿名性を発展させる）:

1. 少数のダミーエッジを追加する（モチーフ頻度を撹乱）
2. 既存エッジの一部をランダムに省略する（次数列を撹乱）
3. ダミーノード間にデコイ部分構造を形成する（スペクトル特性を撹乱）

これにより、$\mathcal{F}_{\text{topo}}(G_{\text{export}}) \neq \mathcal{F}_{\text{topo}}(G_{\text{real}})$ を保証する。

### 独創性評価: ★★★★☆

グラフ de-anonymization（Narayanan & Shmatikov, 2009）の研究は存在するが、**ブラウザの知識グラフに対する能動的なトポロジー注入攻撃**とその防御は未研究である。特に、Web コンテンツを通じてユーザーのグラフ構造にウォーターマークを植え付けるという攻撃モデルは新規。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_2$（悪意ある Web コンテンツ）— A2.5（クラスタ重心シフト）の構造的拡張
- 攻撃面: S2（Renderer → AI）、S3（AI → Graph）
- 新たに定義すべき攻撃ベクトル: A2.6 Structural Watermarking、A2.7 Bridge Node Injection

---

## 5. Temporal Causality Verification (TCV)

### 問題定義

Knowledge Graph 内の知識には**取得の時間順序**がある。ユーザーはまず A を学び、次に B を学び、A と B の関連から C を推論した——このような因果的時系列は、知識の信頼性評価と不正検出に不可欠である。

既存の Temporal Security（radical-architecture.md Paradigm 4）はタイムスタンプの改竄防止と時間ベースのアクセス制御を扱うが、**知識取得の因果順序の検証可能性**は扱わない。TCV はこの空白を埋める。

### 既存概念との差異

| 既存概念 | 対応する問題 | TCV が異なる点 |
|---------|------------|---------------|
| Temporal Security | 時間ベースのアクセス制御・タイムスタンプ保護 | TCV は**因果関係の検証可能性**を保証する |
| Context Code Signing | ノードの出自の真正性 | TCV はノード**間の因果順序**の真正性を保証する |
| Provenance Record (threat-model.md §3.5) | AI 出力の入力・モデル・パラメータの記録 | TCV は**知識取得プロセス全体の因果チェーン**を記録する |

### 形式的定義

**因果順序グラフ** $\text{COG} = (V, E_c, \prec)$:
- $V$: Knowledge Graph のノード集合
- $E_c \subseteq V \times V$: 因果エッジ（$v_i$ の取得が $v_j$ の取得に因果的に先行する場合 $(v_i, v_j) \in E_c$）
- $\prec$: $E_c$ から誘導される半順序関係

**因果関係の定義:**

$v_i \prec v_j$ が成立する条件:
1. **時間的先行**: $\text{timestamp}(v_i) < \text{timestamp}(v_j)$
2. **情報的依存**: $v_j$ の取得コンテキストが $v_i$ の情報に依存する（例: $v_i$ のページ内リンクから $v_j$ に到達した）
3. **推論的依存**: AI が $v_i$ の情報を用いて $v_j$ に関する推論を生成した

**因果一貫性条件:**

$$\forall (v_i, v_j) \in E_c: \text{timestamp}(v_i) < \text{timestamp}(v_j) \land \text{context}(v_j) \cap \text{output}(v_i) \neq \emptyset$$

### 検証可能な因果チェーン

**Hash Chain Construction:**

各ノード $v_i$ の追加時にハッシュチェーンを構成する:

$$h_i = H(h_{i-1} \| \text{content}(v_i) \| \text{timestamp}(v_i) \| \text{causal\_refs}(v_i))$$

- $h_0$: 初期シード（ユーザーの master secret から派生）
- $\text{causal\_refs}(v_i)$: $v_i$ が因果的に依存するノードのハッシュ集合

このハッシュチェーンにより、以下が保証される:
1. **順序不改竄**: チェーンの途中にノードを挿入すると、以降の全ハッシュが無効化される
2. **因果参照の検証**: 因果依存が主張するノードが実際にチェーンの先に存在することを検証できる
3. **削除の検出**: ノードを削除するとチェーンが断絶し、検出可能

### 攻撃シナリオ

**シナリオ: 因果順序の偽造**
1. 攻撃者が時刻 $t_1$ に政治的に偏ったコンテンツ $v_1$ を閲覧させる
2. 時刻 $t_2 > t_1$ に「客観的な」コンテンツ $v_2$ を閲覧させる
3. しかし実際には $v_2$ は $v_1$ の主張を補強するように設計されている
4. TCV なしでは、$v_2$ は独立した情報源に見える。
5. TCV があれば、$v_1 \to v_2$ の因果チェーン（ユーザーが $v_1$ のリンクから $v_2$ に到達した事実）が記録されており、情報源の独立性が疑われる

**シナリオ: 知識のバックデーティング**
1. 悪意ある拡張機能がグラフ DB を直接操作し、ノードのタイムスタンプを改竄する
2. 「以前から知っていた知識」として偽の因果チェーンを構築する
3. TCV のハッシュチェーンが改竄を検出し、不整合を報告する

### 独創性評価: ★★★★☆

ブロックチェーンの因果順序保証やバージョン管理システムの DAG構造と概念的に関連するが、**知識グラフのノード取得に因果検証を適用する**のは新しい。特に、Web 閲覧行動の因果構造（あるページのリンクから次のページへ）を暗号学的に検証可能にする点が独自。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_2$（Web コンテンツ）、$\mathcal{A}_3$（拡張機能）、$\mathcal{A}_4$（OS レベル）
- 攻撃面: S3（AI → Graph）、S4（Extension → Graph）、S10（User → Graph）
- 関連するセキュリティ特性: 完全性（§3.2）と検証可能性（§3.5）の交差領域

---

## 6. Cross-Session Entropy Leakage Prevention (CSELP)

### 問題定義

完全なセッション分離（タブ間の分離、プロセス分離）を実現しても、セッション**間**のメタデータ相関が情報漏洩を引き起こす。これは Quira において特に深刻である。なぜなら、Knowledge Graph は**セッション横断的な永続構造**であり、各セッションの活動がグラフの成長パターンとして蓄積されるからである。

### 既存概念との差異

| 既存概念 | 防御対象 | CSELP が異なる点 |
|---------|---------|---------------|
| Cognitive Fingerprint Resistance | CSS/JS API 経由のフィンガープリント採取 | CSELP は**グラフの時系列成長パターン**からのフィンガープリント採取を防ぐ |
| Temporal Security | 時間ベースのアクセス制御 | CSELP はセッション間の**メタデータ相関**を遮断する |
| Phantom Knowledge Obfuscation | ダミーノードによる統計的保護 | CSELP は情報理論的にクロスセッション漏洩量を定量化し制限する |

### 形式的定義

セッション $\sigma_t$ のメタデータを以下のベクトルで表現する:

$$M(\sigma_t) = (\Delta|V|, \Delta|E|, \text{topic\_dist}_t, \text{query\_pattern}_t, \text{session\_duration}_t)$$

- $\Delta|V|$: セッション中のノード追加数
- $\Delta|E|$: セッション中のエッジ追加数
- $\text{topic\_dist}_t$: セッション中にアクセスされたトピックの分布
- $\text{query\_pattern}_t$: NL クエリのパターン
- $\text{session\_duration}_t$: セッション時間

**クロスセッション情報量:**

2つのセッション間で漏洩する情報量を相互情報量で定量化する:

$$I(M(\sigma_t); M(\sigma_{t-1})) = \sum_{m_t, m_{t-1}} P(m_t, m_{t-1}) \log_2 \frac{P(m_t, m_{t-1})}{P(m_t) P(m_{t-1})}$$

**防御目標:** $I(M(\sigma_t); M(\sigma_{t-1})) \leq \varepsilon_{\text{session}}$ を保証する。すなわち、あるセッションのメタデータを観測しても、前後のセッションについて得られる情報量が $\varepsilon_{\text{session}}$ ビット以下であること。

### メタデータ相関攻撃の実例

**攻撃ベクトル 1: Graph Growth Fingerprinting**
- セッション $\sigma_1$: ノード +50、エッジ +120、トピック: {ML, Python}
- セッション $\sigma_2$: ノード +3、エッジ +5、トピック: {cooking}
- セッション $\sigma_3$: ノード +80、エッジ +200、トピック: {ML, PyTorch}

この成長パターンは「ML エンジニアが趣味で料理をする人」というプロファイルを形成する。各セッション単独では無害だが、系列として観測すると識別可能になる。

**攻撃ベクトル 2: Query Pattern Correlation**
- 拡張機能が各セッションの NL クエリのタイミングと頻度のみを観測する
- クエリ間隔の分布は「認知リズム」を反映し、指紋として機能する
- Komogorova et al. (2023) の研究で、キーストロークタイミングの分布は99.5%の精度でユーザーを識別できることが示されている

### 防御アーキテクチャ

**Session Metadata Decorrelator (SMD):**

```
Session σ_t → [Metadata Observer] → M(σ_t) → [Decorrelation Engine] → M'(σ_t)
                                                       │
                                                       ▼
                                                 Correlate with M'(σ_{t-1})
                                                       │
                                                       ▼
                                                 I(M'; M'_{t-1}) ≤ ε ?
                                                       │
                                           ┌───────────┤
                                           │           │
                                          Yes         No → Inject noise
```

**具体的なデコリレーション技術:**

1. **Graph Growth Batching**: ノード追加をバッチ化し、固定間隔（例: 1時間ごと）でのみ実行する。セッション間のグラフ成長パターンを時間的に均一化する。
2. **Topic Distribution Smoothing**: 各セッションのトピック分布に Laplace ノイズを加算し、偏りを平滑化する。
3. **Query Timing Jitter**: NL クエリの発行タイミングにランダムな遅延を追加し、認知リズムのフィンガープリントを破壊する。
4. **Phantom Session Injection**: 実際のセッションの間にダミーセッション（バックグラウンドでのダミーグラフ操作）を挿入し、セッション系列の相関を低減する。

### 独創性評価: ★★★★☆

Tor Browser の「全ウィンドウ同一サイズ」やキーストロークタイミング攻撃の研究は存在するが、**知識グラフの時系列成長パターン**をフィンガープリントとして定義し、情報理論的にクロスセッション漏洩を定量化する研究は存在しない。CSELP は知識グラフブラウザ特有の、新しい匿名性問題の定式化である。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_1$（ネットワーク観察者）、$\mathcal{A}_3$（拡張機能 — A3.5 メタデータ収集）
- 攻撃面: S4（Extension → Graph）、S5（Graph → Export）
- 認知フィンガープリントのエントロピー分析（threat-model.md §5.1）の**時間次元への拡張**

---

## 7. Retroactive Sanitization with Inference Purging (RSIP)

### 問題定義

ユーザーがセキュリティポリシーを変更した場合（例: 「医療情報の感度レベルを上げる」「特定のトピックを完全にプライベートにする」）、その新しいポリシーは**将来のデータ**だけでなく**過去に収集・処理済みのデータ**にも適用されるべきである。

これは法的要求（GDPR の忘れられる権利、CCPA の消費者データ削除権）とも整合するが、技術的には極めて困難な問題である。なぜなら:

1. データはすでに AI パイプラインで処理されている
2. 推論結果が他のノードに伝播している（IRD の問題）
3. 埋め込みベクトルに情報がエンコードされている
4. クラスタ統計やトピックモデルに影響を与えている

### 既存概念との差異

| 既存概念 | 対応する問題 | RSIP が異なる点 |
|---------|------------|---------------|
| Inference Residue Defense (IRD) | 単一ノード削除後の残渣 | RSIP は**ポリシー変更の遡及適用**であり、削除でなく再分類・再制限が含まれる |
| IFC Label Update | ラベルの変更 | RSIP はラベル変更だけでなく、過去の推論結果への**遡及的な影響伝播**を扱う |
| Temporal Security | 時間ベースのアクセス制御変更 | RSIP は過去のデータ・推論に対する**遡及的なポリシー適用**を保証する |

### 形式的定義

時刻 $t_0$ にポリシー $\Pi_{\text{old}}$ から $\Pi_{\text{new}}$ に変更されたとする。

**遡及適用の完全性条件:**

$$\forall v \in V, \forall t < t_0: \text{enforce}(\Pi_{\text{new}}, v, t) = \text{enforce}(\Pi_{\text{new}}, v, t_0)$$

すなわち、$t_0$ 以前に追加されたノードも、$t_0$ 以降に追加されたノードと同じポリシーが適用される。

**推論パージの定義:**

ポリシー $\Pi_{\text{new}}$ のもとで制限されるデータ集合を $R \subseteq V$ とする。RSIP は以下を保証する:

$$\forall v \in V \setminus R, \forall a \in \text{attrs}(v): \text{dep}(a, R) = 0 \lor \text{re\_inferred}(a, V \setminus R)$$

- $R$ に含まれないノードの属性は、$R$ への依存がゼロか、$R$ を除外して再推論済みである

### 遡及適用パイプライン

```
Policy Change: Π_old → Π_new
       │
       ▼
  [Affected Node Identifier]
       │ R = {v ∈ V | Π_new restricts v more than Π_old}
       ▼
  [Direct Action]
       │ R のノードに新ポリシーを適用
       │  (ラベル変更、アクセス制限、暗号化レベル変更)
       ▼
  [Inference Dependency Walk]  ← IRD の IDG を使用
       │ R に依存する推論を全走査
       ▼
  [Re-inference Queue]
       │ R に依存する属性・エッジを再計算
       │  (R を入力から除外して再推論)
       ▼
  [Embedding Reindex]
       │ R のノードの埋め込みを更新 or 削除
       │ 影響を受けた類似度インデックスを再構築
       ▼
  [Statistics Recompute]
       │ トピック分布、クラスタ集計を R 除外で再計算
       ▼
  [Verification]
       │ ∀v ∉ R: dep(attrs(v), R) = 0 を検証
       ▼
  Complete: Policy retroactively applied
```

### コスト分析と最適化

完全な遡及適用は計算コストが高い。最適化戦略:

| 戦略 | 効果 | トレードオフ |
|------|------|------------|
| Lazy Re-inference | 影響を受けた属性にフラグを立て、次回アクセス時に再計算 | アクセスまで古い値が残る |
| Impact Threshold | $\text{dep}(a, R) < \tau_{\text{min}}$ なら再計算しない | 微小な残渣が残る |
| Batch Processing | 夜間バッチで一括再計算 | ポリシー適用に遅延が生じる |
| Progressive Purge | 高依存度から順に再計算し、閾値未満で打ち切り | 計算量を制御可能 |

**推奨:** Progressive Purge をデフォルトとし、ユーザーが「完全消去」を選択した場合のみ全走査を実行する。

### 攻撃シナリオ

**シナリオ: ポリシー変更の不完全適用を利用した推論**
1. ユーザーが「金融情報」の感度レベルを「最高」に変更する
2. RSIP が不完全な場合、過去の金融ノードに基づく推論（「投資に関心がある」「住宅ローンを検討中」）が他ノードの属性として残存する
3. 拡張機能がこの残存推論から、新ポリシーで保護されるべき金融情報を間接的に推定する

### 独創性評価: ★★★★★

GDPR のデータ消去要求への技術的対応は研究されているが、**知識グラフにおける推論チェーンを含めた遡及的ポリシー適用**は未研究である。IRD と組み合わせることで、「削除」だけでなく「再分類」「再制限」も推論残渣を考慮して実行する点が完全に新規。

### 脅威モデルへのマッピング

- 敵対者: 全クラス（ポリシー変更は全攻撃面に影響する）
- 攻撃面: 全面（ポリシーはグラフ全体に適用される）
- 関連するセキュリティ特性: 推論耐性（§3.3）の時間的拡張

---

## 8. Contextual Amnesia Verification (CAV)

### 問題定義

ユーザーが「このデータを忘れろ」と指示した場合、システムは本当にそれを忘れたのか? 従来のデータ削除は「削除を実行した」ことを確認するが、「復元不可能な状態になった」ことを**証明**しない。

CAV はデータの完全な忘却を**暗号学的に検証可能**にするメカニズムである。

### 既存概念との差異

| 既存概念 | 保証する内容 | CAV が異なる点 |
|---------|------------|---------------|
| Sealed Knowledge Volume (SKV) | データの完全性と暗号化 | CAV は**削除の完全性**を暗号学的に証明する |
| Dead Man's Switch | 無認証時の鍵自動消去 | CAV は個別のデータ忘却を検証可能にする（全消去ではなく選択的忘却） |
| GDPR 削除権 | 法的な削除義務 | CAV はその技術的実装と**検証可能性**を提供する |

### 形式的定義

**Proof of Forgetting (PoF):**

データ $d$ の忘却証明 $\text{PoF}(d)$ は以下を満たすトリプル $(\text{commit}_d, \text{delete\_proof}, \text{absence\_proof})$:

1. **Commitment Phase**: データ存在時に Merkle コミットメントを記録する
   $$\text{commit}_d = \text{MerkleRoot}(G) \text{ where } d \in \text{leaves}(G)$$

2. **Deletion Phase**: 削除後に新しい Merkle Root を計算する
   $$\text{delete\_proof} = \text{MerklePath}(\text{MerkleRoot}(G'), d) = \bot$$
   
   すなわち、$d$ に対する Merkle パスが存在しないことの証明。

3. **Absence Verification**: $G'$ 内で $d$ と情報的に同等なデータが存在しないことの検証
   $$\text{absence\_proof}: \forall v \in G', \text{sim}(\Phi(v), \Phi(d)) < \tau_{\text{forget}}$$

### Subsystem-wise Forgetting

知識グラフブラウザでは、同一データが複数のサブシステムに存在する:

| サブシステム | データ形式 | 忘却方法 | 検証方法 |
|------------|----------|---------|---------|
| Graph DB (SQLite) | ノード + エッジ | DELETE + VACUUM | Merkle Proof of Absence |
| Embedding Index | ベクトル | インデックス再構築 | $\max_{v} \text{sim}(\Phi(v), \Phi(d)) < \tau$ |
| Inference Cache | 推論結果 | IDG-based purge (IRD) | IDG 依存エッジの不在証明 |
| AI Model (fine-tuning した場合) | 重み更新 | Machine Unlearning | 統計的検証（model inversion test） |
| Log / Audit Trail | テキスト記録 | ログエントリ消去 | ログの Merkle Chain 再構築検証 |
| Export History | エクスポート記録 | 記録消去 | — (外部に送出済みのデータは回収不能) |

### Composite Proof of Forgetting

全サブシステムの忘却証明を合成する:

$$\text{PoF}_{\text{composite}}(d) = \bigwedge_{s \in \text{Subsystems}} \text{PoF}_s(d)$$

合成証明が有効であるためには、**すべてのサブシステム**で忘却が完了している必要がある。1つでも失敗した場合、合成証明は無効であり、ユーザーに「以下のサブシステムでデータの残存が検出されました」と報告する。

### 技術的課題

**課題 1: 埋め込み空間での忘却検証**

埋め込みベクトルは連続値であり、離散的なデータ削除とは異なる。「$d$ の埋め込みに最も近いベクトルが閾値以上離れている」ことを効率的に検証するには、近似最近傍検索の保証付きバリアントが必要。

**課題 2: 推論残渣の完全検出**

IRD で議論した統計的残渣は、その性質上完全な検出が不可能な場合がある。CAV は「合理的な範囲での忘却」を保証し、理論的な完全忘却との差を明示する:

$$\text{PoF}_{\text{practical}}(d) = \text{PoF}_{\text{structural}}(d) \land (\text{residual\_risk}(d) < \tau_{\text{accept}})$$

**課題 3: ログのジレンマ**

監査ログにはデータアクセスの記録が含まれるが、ログ自体がデータの存在を証明する。忘却の完全性のためにはログも消去すべきだが、消去するとセキュリティ監査能力が失われる。

**解決策:** ログエントリを**暗号化してから記録**し、忘却時にはログの暗号鍵を消去する。これにより、ログエントリは存在するが復号不能となり、構造的完全性（改竄検出）は保持しつつ内容の忘却を実現する。

### 攻撃シナリオ

**シナリオ: 不完全忘却の悪用**
1. ユーザーが機密ノードの削除を要求する
2. Graph DB からは削除されるが、埋め込みインデックスには残存する
3. 攻撃者（$\mathcal{A}_4$: OS レベル）がベクトル DB を直接読み取り、削除されたはずのコンテンツに近似するベクトルを発見する
4. Vec2Text 型の inversion attack で元の内容を推定する

**CAV による防御:** 忘却操作後に $\text{PoF}_{\text{composite}}$ が自動検証され、全サブシステムでの消去完了を確認するまでユーザーに「忘却完了」を報告しない。

### 独創性評価: ★★★★★

「忘れられる権利」の技術的実装は活発に研究されているが、**知識グラフの全サブシステムにまたがる合成忘却証明**の概念は新規である。特に、埋め込み空間での不在証明と推論依存グラフの消去検証を組み合わせる CAV のフレームワークは、2026年時点で学術文献に存在しない。

### 脅威モデルへのマッピング

- 敵対者: $\mathcal{A}_4$（OS レベル — 削除されたはずのデータの復元）、$\mathcal{A}_5$（ベンダー — ログからのデータ復元）
- 攻撃面: S7（Disk → Memory）、S10（User → Graph）
- 関連するセキュリティ特性: 機密性（§3.1）と検証可能性（§3.5）の交差

---

## 9. Summary & Priority Map

### 新構造一覧

| # | 構造 | 略称 | 独創性 | 実装緊急度 | 依存する既存概念 |
|---|------|------|--------|----------|---------------|
| 1 | Knowledge Supply Chain Integrity | KSCI | ★★★★★ | Phase 2 | Context Gatekeeper, XProtect |
| 2 | Inference Residue Defense | IRD | ★★★★★ | Phase 2 | IDG (新規), Provenance Record |
| 3 | Semantic Blast Radius Containment | SBRC | ★★★★☆ | Phase 2 | IFC Labels, KPC |
| 4 | Adversarial Graph Topology Resistance | AGTR | ★★★★☆ | Phase 3 | $k$-構造匿名性, Phantom Obfuscation |
| 5 | Temporal Causality Verification | TCV | ★★★★☆ | Phase 2 | Temporal Security, Code Signing |
| 6 | Cross-Session Entropy Leakage Prevention | CSELP | ★★★★☆ | Phase 3 | Cognitive FP Resistance |
| 7 | Retroactive Sanitization with Inference Purging | RSIP | ★★★★★ | Phase 2 | IRD, IFC, DSPL |
| 8 | Contextual Amnesia Verification | CAV | ★★★★★ | Phase 3 | SKV, IRD, Merkle Commitments |

### 相互依存関係

```
KSCI ─────────────────────────── (独立)
  │
  └──→ AGTR (供給チェーンの汚染がトポロジー攻撃を含む)

IRD ──────→ RSIP (遡及適用は推論パージに依存)
  │            │
  │            └──→ CAV (忘却証明は推論パージの完了を前提とする)
  │
  └──→ CAV (忘却証明は推論残渣の検出に依存)

SBRC ─────────────────────────── (独立だが IFC と相補的)

TCV ──────→ KSCI (因果検証は供給チェーン信頼性を強化)

CSELP ────────────────────────── (独立)
```

### 推奨実装順序

**Phase 2 (即時):**
1. **IRD** — 推論依存グラフ (IDG) の記録開始。これは RSIP と CAV の前提条件
2. **TCV** — ハッシュチェーンの構築。早期に開始するほどチェーンが長くなり検証能力が向上
3. **KSCI** — Provenance Tracker の基本実装。初期は出自記録のみで、Corroboration Engine は Phase 3
4. **SBRC** — Semantic Zone Analyzer の設計。IFC ラベルの拡張として実装可能

**Phase 3 (成熟期):**
5. **RSIP** — IRD の IDG が十分なデータを蓄積した後に実装
6. **CAV** — 全サブシステムの忘却インターフェースが整備された後に実装
7. **AGTR** — Topological Invariant Monitor の導入。十分なユーザーベースでの検証が必要
8. **CSELP** — Session Metadata Decorrelator の実装。Phantom Session Injection は計算コストが高いため最後

### 脅威モデルへの貢献

本文書の8構造は、threat-model.md の既存の攻撃ベクトル分類に以下の拡張を提案する:

| 新規攻撃ベクトル | 敵対者 | 既存の最近接 | 本文書の対応構造 |
|---------------|--------|------------|---------------|
| A2.6 Structural Watermarking | $\mathcal{A}_2$ | A2.5 (クラスタ重心シフト) | AGTR |
| A2.7 Bridge Node Injection | $\mathcal{A}_2$ | A2.2 (エンティティポイズニング) | AGTR |
| A2.8 Knowledge Supply Chain Poisoning | $\mathcal{A}_2$ | A2.2 (エンティティポイズニング) | KSCI |
| A3.6 Inference Residue Exploitation | $\mathcal{A}_3$ | A3.5 (メタデータ収集) | IRD |
| A3.7 Cross-Session Metadata Correlation | $\mathcal{A}_3$ | A3.5 (メタデータ収集) | CSELP |
| A4.3 Post-Deletion Data Recovery | $\mathcal{A}_4$ | — (新規) | CAV |
| A-cross Retroactive Policy Evasion | 全クラス | — (新規) | RSIP |

---

## Appendix: 既存文書との非重複性検証

以下の表は、本文書の各構造が既存の40+概念のいずれとも重複しないことを明示的に検証する。

| 本文書の構造 | 最も近い既存概念 | 重複しない理由 |
|------------|---------------|-------------|
| KSCI | Context Gatekeeper / XProtect | 既存: 悪意あるコード/シグネチャ検出。KSCI: **意味的に真正だが戦略的なコンテンツ**の検出 |
| IRD | Machine Unlearning / Ephemeral Zones | 既存: モデル重み/処理中データ。IRD: **推論出力として他ノードに伝播した情報**の追跡・消去 |
| SBRC | IFC / KPC / Differential Privacy | 既存: アクセス制御/暗号化/統計的保護。SBRC: **侵害後の意味的被害の定量化と封じ込め** |
| AGTR | $k$-構造匿名性 / Phantom Obfuscation | 既存: 受動的な匿名化。AGTR: **能動的なトポロジー操作攻撃**への防御 |
| TCV | Temporal Security / Provenance Record | 既存: タイムスタンプ保護/AI出力の記録。TCV: **知識取得の因果順序**の暗号検証 |
| CSELP | Cognitive FP Resistance | 既存: 単一セッションのフィンガープリント。CSELP: **セッション系列の成長パターン**からの識別防止 |
| RSIP | IFC Label Update / IRD | 既存: データフロー制御/単一ノード削除。RSIP: **ポリシー変更の遡及的適用と推論パージ** |
| CAV | SKV / Dead Man's Switch | 既存: データの暗号化/全消去。CAV: **選択的忘却の暗号学的証明** |
