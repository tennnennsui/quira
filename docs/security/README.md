# Quira Security Documentation

## 読み順

```
1. threat-model.md                    ← 全ての基盤。資産定義、敵対者モデル、セキュリティ特性
2. architecture.md                    ← macOS 12層分析 → Quira防御マッピング
3. research.md                        ← ブラウザ SOTA、新興技術、AI脅威モデル、CSF 6層
4. radical-architecture.md            ← 8パラダイム設計（Capability, IFC, Adversarial ML, Temporal, Forward Secrecy, AI Immune, Living Security, TEE）
5. novel-research.md                  ← 10個の新規研究概念（再評価済み）
6. deep-architecture-research.md      ← macOS深層メカニズムからの8新規構造（KPC, CSEB, KQR, PSCS, SKV, DSPL, CTA, ASP）
7. emergent-interaction-research.md   ← 認知・AI・グラフの相互作用から創発する8新規構造（KSCI, IRD, SBRC, AGTR, TCV, CSELP, RSIP, CAV）
8. hardening-research.md              ← 既存概念の強化策6件（E1–E6: Embedding Residue, Inference Provenance, Audit Commitment, Social Recovery, Query Canonicalization, Cascade Fallback）
9. frontier-security-research.md      ← 新規セキュリティ構造8件（N1–N8: CGS, FIL, SEF, GEAP, VSCA, FSIE, CQN, DPBC）
```

## 依存関係

```
threat-model.md
  │
  ├── architecture.md
  │     └── DESIGN.md §9 Context Security
  │
  ├── research.md
  │     └── radical-architecture.md (8パラダイムの防御設計)
  │
  ├── novel-research.md (threat-model.md の上に構築される新規概念)
  │
  ├── deep-architecture-research.md
  │     ├── architecture.md (12マッピングとの差分分析に依存)
  │     ├── novel-research.md (STS等との重複回避に参照)
  │     └── radical-architecture.md (8パラダイムとの統合)
  │
  ├── emergent-interaction-research.md
  │     ├── threat-model.md (形式的定義・敵対者モデルの拡張)
  │     ├── novel-research.md (既存概念との非重複検証)
  │     ├── deep-architecture-research.md (SKV, DSPL等との差異分析)
  │     └── radical-architecture.md (IFC, Temporal Security等の拡張)
  │
  ├── hardening-research.md
  │     ├── deep-architecture-research.md (IRD, TCV, CSEB, KPC, KQR, ASP の拡張)
  │     └── emergent-interaction-research.md (RSIP との統合)
  │
  └── frontier-security-research.md
        ├── hardening-research.md (E1→N1, E3→N2, E5→N7 の前提関係)
        ├── integration-matrix.md (フェーズ配分)
        └── threat-model.md (新規攻撃ベクトル A4.4–A5.4)
```

## ファイル概要

| ファイル | 行数 | 内容 |
|---------|------|------|
| [threat-model.md](threat-model.md) | ~400 | 形式的脅威モデル: $G=(V,E,\Sigma,\Phi,\Tau)$、敵対者 $\mathcal{A}_1$-$\mathcal{A}_5$、安全性定義、定量的プライバシー分析 |
| [architecture.md](architecture.md) | ~750 | macOS セキュリティ 12層の深層分析とブラウザへの適用 |
| [research.md](research.md) | ~700 | ブラウザセキュリティ SOTA + AI 脅威モデル + Context Security Framework |
| [radical-architecture.md](radical-architecture.md) | ~1080 | 8パラダイムの防御メカニズム設計（Rust コード付き） |
| [novel-research.md](novel-research.md) | ~700 | 10個の新規研究概念（再評価済み、優先順位付き） |
| [deep-architecture-research.md](deep-architecture-research.md) | ~750 | macOS 未マッピング深層メカニズム8件の分析と新規構造提案（KPC, CSEB, KQR, PSCS, SKV, DSPL, CTA, ASP） |
| [emergent-interaction-research.md](emergent-interaction-research.md) | ~680 | 認知・AI・グラフの相互作用から創発する8新規構造（KSCI, IRD, SBRC, AGTR, TCV, CSELP, RSIP, CAV） |
| [hardening-research.md](hardening-research.md) | ~280 | 既存概念の強化策6件（E1: Embedding Residue, E2: Inference Provenance, E3: Audit Commitment, E4: Social Recovery, E5: Query Canonicalization, E6: Cascade Fallback） |
| [frontier-security-research.md](frontier-security-research.md) | ~500 | 新規セキュリティ構造8件（N1: CGS, N2: FIL, N3: SEF, N4: GEAP, N5: VSCA, N6: FSIE, N7: CQN, N8: DPBC） |

## 全セキュリティ概念の統合新規性マトリクス

> 3研究文書（novel / deep / emergent）の26概念を新規性評価順にソート。正規の敵対者モデル・安全性定義は [threat-model.md](threat-model.md) を参照。

| ★ | 略記 | 正式名称 | ソース | 備考 |
|---|------|---------|--------|------|
| ★5 | **CFR** | Cognitive Fingerprint Resistance | novel §1 | 認知パターンの耐指紋化 |
| ★5 | **IS** | Inverse Sandboxing (AI Output Restriction) | novel §6 | AI出力制限の逆サンドボックス |
| ★5 | **CSEB** | Context Security Event Bus | deep §2 | macOS ESF → Context Graph イベント基盤 |
| ★5 | **KSCI** | Knowledge Supply Chain Integrity | emergent §1 | 知識サプライチェーン完全性 |
| ★5 | **IRD** | Inference Residue Defense | emergent §2 | 推論残留物防御 |
| ★5 | **RSIP** | Retroactive Sanitization with Inference Purging | emergent §7 | 遡及的推論パージ |
| ★5 | **CAV** | Contextual Amnesia Verification | emergent §8 | 文脈的忘却の検証可能性 |
| ★4 | **STS** | Semantic Topology Security | novel §2 | 意味トポロジーの構造的防御 |
| ★4 | **VLAT** | Verifiable Local AI Transparency | novel §3 | ローカルAIの検証可能透過性 |
| ★4 | **KPC** | Knowledge Protection Classes | deep §1 | macOS Data Vault → 知識保護クラス分類 |
| ★4 | **SKV** | Sealed Knowledge Volume | deep §5 | macOS SIP → 封印された知識ボリューム |
| ★4 | **SBRC** | Semantic Blast Radius Containment | emergent §3 | 意味的爆発半径の封じ込め |
| ★4 | **AGTR** | Adversarial Graph Topology Resistance | emergent §4 | 敵対的グラフトポロジー耐性 |
| ★4 | **TCV** | Temporal Causality Verification | emergent §5 | 時間的因果関係の検証 |
| ★4 | **CSELP** | Cross-Session Entropy Leakage Prevention | emergent §6 | セッション間エントロピー漏洩防止 |
| ★3 | **CCM** | Context Capability Morphing | novel §4 | コンテキスト依存の能力変形 |
| ★3 | **KEP** | Knowledge Entanglement Protocol | novel §5 | 知識量子もつれプロトコル |
| ★3 | **ECZ** | Ephemeral Computation Zones | novel §7 | 一時的計算ゾーン |
| ★3 | **PRBA** | Privilege Ring Browser Architecture | novel §8 | ブラウザ特権リング構造 |
| ★3 | **PKO** | Phantom Knowledge Obfuscation | novel §10 | ファントム知識によるグラフ難読化 |
| ★3 | **KQR** | Knowledge Query Relay | deep §3 | macOS XPC → 知識クエリ中継 |
| ★3 | **PSCS** | Privilege-Separated Context Services | deep §4 | 特権分離コンテキストサービス |
| ★3 | **CTA** | Context Trust Arbiter | deep §7 | 信頼性裁定メカニズム |
| ★3 | **ASP** | Adaptive Security Posture | deep §8 | 適応的セキュリティ姿勢 |
| ★2 | **FKA** | Federated Knowledge Attestation | novel §9 | 連合知識証明（zkML未成熟） |
| ★2 | **DSPL** | Declarative Security Policy Language | deep §6 | 宣言的セキュリティポリシー言語 |

**分布:** ★5: 7個 | ★4: 8個 | ★3: 9個 | ★2: 2個 — 計26概念

### 強化策 (hardening-research.md)

> 既存26概念の弱点を補強する6件の拡張。新規概念ではなく、既存概念の防御カバレッジを強化する。

| ID | 名称 | 対象概念 | 深刻度 | Phase |
|----|------|---------|--------|-------|
| E1 | Embedding Residue Tracking | IRD + RSIP | CRITICAL | 1–2 |
| E2 | Inference Provenance Chain | TCV | HIGH | 2 |
| E3 | Immutable Audit Commitment | CSEB | CRITICAL | 1–2 |
| E4 | Social Recovery Layer | KPC | HIGH | 2–3 |
| E5 | Query Canonicalization Shield | KQR | HIGH | 2 |
| E6 | Cascade Failure Fallback | ASP | HIGH | 2 |

### 新規構造 (frontier-security-research.md)

> 既存アーキテクチャがカバーしていない8つの防御領域を埋める新規構造。

| ★ | 略記 | 正式名称 | Phase | 主要敵対者 |
|---|------|---------|-------|----------|
| ★5 | **CQN** | Cognitive Query Normalization | 2 | $\mathcal{A}_1$, $\mathcal{A}_5$ |
| ★5 | **FIL** | Forensic Integrity Layer | 2 | $\mathcal{A}_2$–$\mathcal{A}_5$ |
| ★4 | **CGS** | Cryptographic Graph Shredding | 1–2 | $\mathcal{A}_4$, $\mathcal{A}_5$ |
| ★4 | **GEAP** | Graph Export Anonymization Protocol | 2–3 | $\mathcal{A}_1$, $\mathcal{A}_3$ |
| ★4 | **FSIE** | Formal Security Invariant Engine | 1 | 全クラス |
| ★4 | **DPBC** | Differential Privacy Budget Controller | 2 | $\mathcal{A}_1$, $\mathcal{A}_5$ |
| ★3 | **VSCA** | Verifiable Supply Chain Attestation | 1–2 | $\mathcal{A}_5$ |
| ★3 | **SEF** | Speculative Execution Firewall | 2–3 | $\mathcal{A}_4$ |

**全体分布（強化 + 新規含む）:** 既存26概念 + 強化6件 + 新規8件 = **計40セキュリティ要素**
