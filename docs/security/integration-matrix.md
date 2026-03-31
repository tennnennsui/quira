# Quira Security Integration Matrix

> Version: 1.1 | Date: 2026-03-30 | Author: CEO Division (Opus)
> Depends: [threat-model.md](threat-model.md), [README.md](README.md) (統合新規性マトリクス), [hardening-research.md](hardening-research.md), [frontier-security-research.md](frontier-security-research.md)

---

## 概要

8パラダイム (radical-architecture.md) + 26新規概念 (novel/deep/emergent) + 6強化策 (hardening) + 8新規構造 (frontier) の統合関係マトリクス。
概念間の依存・補完・相互作用を定義し、実装優先順位とフェーズ分配の根拠を示す。

---

## 1. Tier S — セキュリティランタイム統合

### CSEB + CTA + ASP = Unified Security Runtime

| 概念 | 役割 | 依存 |
|------|------|------|
| **CSEB** (Context Security Event Bus) | イベント伝播基盤 — 全セキュリティイベントの観測・ルーティング | radical §8 (Hardware), architecture.md ESF 分析 |
| **CTA** (Context Trust Arbiter) | 信頼性判定 — 6種のチェック (Signature, Reputation, Temporal, Behavioral, Contextual, Cross-reference) | CSEB (イベント入力), radical §1 (Capability tokens) |
| **ASP** (Adaptive Security Posture) | 動的防御レベル調整 — 5段階 (Normal → Maximum) | CSEB + CTA (トリガーソース), radical §8 (Living Security) |

**統合効果:** CSEB がイベントを検知 → CTA が信頼性を裁定 → ASP がポスチャーを調整。この3者はセキュリティランタイムの核を形成する。

**実装フェーズ:** Phase 1 (MVP) — 三者とも初期実装が必要。

### PSCS + Capability = Process Isolation + Token Control

| 概念 | 役割 | 依存 |
|------|------|------|
| **PSCS** (Privilege-Separated Context Services) | プロセス分離 — Graph/Embedding/Query/AI サービスの特権分離 | radical §1 (Capability), architecture.md App Sandbox |
| **Capability** (radical §1) | トークンベースアクセス制御 | (独立 — 基盤パラダイム) |

**統合効果:** Capability トークンが PSCS の各サービスへのアクセスを制御。PSCS が分離を、Capability が認可を提供。

**実装フェーズ:** Phase 2 (Pro)

---

## 2. Tier A — 高優先統合パターン

### IRD + RSIP + CAV = Forgetting Rights Engine

| 概念 | 役割 |
|------|------|
| **IRD** (Inference Residue Defense) | 推論残留物の検出と追跡 (直接/伝播/埋め込み/統計的残留物) |
| **RSIP** (Retroactive Sanitization with Inference Purging) | 遡及的削除 — IRD が検出した残留物の安全な除去 |
| **CAV** (Contextual Amnesia Verification) | 忘却の検証 — RSIP 後に残留物が完全除去されたことの暗号学的証明 |

**統合効果:** IRD → RSIP → CAV のパイプラインが「忘れられる権利」を技術的に実現。GDPR/個人情報保護法対応の差別化要素。

**実装フェーズ:** IRD: Phase 2, RSIP: Phase 4, CAV: Phase 4

### KPC + SKV + TCV = Temporal Integrity Chain

| 概念 | 役割 |
|------|------|
| **KPC** (Knowledge Protection Classes) | ノード分類 (Open/Internal/Sensitive/Sealed) — 保護レベルの静的割当 |
| **SKV** (Sealed Knowledge Volume) | KPC-Sealed クラスの暗号的封印 — SIP 相当のイミュータビリティ保証 |
| **TCV** (Temporal Causality Verification) | ハッシュチェーンによる知識の時間的整合性検証 |

**統合効果:** KPC が分類 → SKV が封印 → TCV が時間的一貫性を保証。知識の来歴完全性チェーン。

**実装フェーズ:** KPC: Phase 1, SKV: Phase 2, TCV: Phase 1

### KSCI + AI Immune + CSEB = Supply Chain Defense

| 概念 | 役割 |
|------|------|
| **KSCI** (Knowledge Supply Chain Integrity) | ソースから最終ノードまでの知識サプライチェーン信頼性 |
| **AI Immune** (radical §3) | AI パイプラインの行動異常検知 |
| **CSEB** | セキュリティイベントの伝播基盤 |

**統合効果:** KSCI がサプライチェーンを監視 → 異常を CSEB 経由で AI Immune System に通知 → 汚染されたノードを隔離。

**実装フェーズ:** KSCI: Phase 1, AI Immune: Phase 1, CSEB: Phase 1

---

## 3. Tier B — 中優先統合パターン

### SBRC + IFC + Space-Scoped = Semantic Isolation

| 概念 | 役割 |
|------|------|
| **SBRC** (Semantic Blast Radius Containment) | 侵害時の意味的影響範囲評価と封じ込め |
| **IFC** (radical §2) | 情報フローのラベルベース追跡 |
| **Space-Scoped Security** | Context Space 単位のセキュリティ境界 |

**関係:** SBRC は Space-Scoped Security の上位概念。Space は管理境界、SBRC は意味的爆発半径。IFC ラベルが SBRC の影響範囲計算に使用される。

**実装フェーズ:** SBRC: Phase 2, IFC: Phase 2, Space: Phase 2

### CSELP + AGTR = Anti-Fingerprinting

| 概念 | 役割 |
|------|------|
| **CSELP** (Cross-Session Entropy Leakage Prevention) | セッション間の情報漏洩防止 |
| **AGTR** (Adversarial Graph Topology Resistance) | グラフ構造からの個人識別防止 |

**統合効果:** AGTR がトポロジー攻撃を防御、CSELP がセッション間の統計的漏洩を防止。CFR (Cognitive Fingerprint Resistance) の実装基盤。

**実装フェーズ:** CSELP: Phase 3, AGTR: Phase 3

### KQR + IRD = Cloud AI Zero-Residue

| 概念 | 役割 |
|------|------|
| **KQR** (Knowledge Query Relay) | クラウド AI へのクエリ中継 — ゼロトラスト設計 |
| **IRD** (Inference Residue Defense) | クラウド側の推論残留物追跡 |

**統合効果:** KQR が最小限のコンテキストのみをクラウドに送信、IRD がクラウド応答から生じる残留物を追跡・制御。

**実装フェーズ:** KQR: Phase 3, IRD: Phase 2

---

## 4. Tier C — 将来統合パターン

### CFR + CSELP + AGTR = Cognitive Pattern Protection

完全な認知指紋防御。Phase 3-4 で段階的に統合。

### Inverse Sandboxing + PSCS + Adversarial ML = AI Output Control

AI 出力の逆サンドボックス + プロセス特権分離 + 敵対的 ML 防御。Phase 2-3。

---

## 5. 概念依存グラフ

```
                    threat-model.md
                         │
          ┌──────────────┼──────────────┐
          │              │              │
     Capability      IFC          AI Immune
     (radical §1)   (radical §2)  (radical §3)
          │              │              │
    ┌─────┼─────┐   ┌───┼───┐     ┌───┼───┐
    │     │     │   │   │   │     │   │   │
  PSCS  CTA  KPC  SBRC STS CSELP KSCI AGTR IRD
    │     │     │    │           │         │
    │  ┌──┘     │    │           │    ┌────┘
    │  │    SKV─┘    │           │    │
    │  ASP   │       │        CSEB────┤
    │        TCV     │              RSIP
    │                │                │
    └──── KQR ───────┘              CAV
```

---

## 6. フェーズ別実装リスト

| Phase | 概念 | 統合パターン |
|-------|------|------------|
| **1 (MVP)** | CSEB, CTA, KPC, TCV, KSCI, AI Immune, Capability, **E1**, **E3**, **N5 (VSCA)**, **N6 (FSIE)** | Tier S ランタイム + 基本サプライチェーン + 形式検証 + 監査基盤 |
| **2 (Pro)** | ASP, PSCS, SKV, IRD, SBRC, IFC, Space, IS, ECZ, **E2**, **E5**, **E6**, **N1 (CGS)**, **N2 (FIL)**, **N7 (CQN)**, **N8 (DPBC)** | Tier A 部分 + Tier B Semantic Isolation + 暗号削除 + フォレンジック + DP予算 |
| **3 (Enterprise)** | KQR, CSELP, AGTR, VLAT, PRBA, CFR, **E4**, **N3 (SEF)**, **N4 (GEAP)** | Tier B Anti-Fingerprinting + Cloud Zero-Residue + エクスポート匿名化 |
| **4 (Standard)** | RSIP, CAV, HE, FKA, DSPL | Tier A Forgetting Rights + 将来技術 |

---

## 7. 強化策の統合パターン (hardening-research.md)

### E1 + IRD + CGS = Cryptographic Deletion Pipeline

| 概念 | 役割 |
|------|------|
| **E1** (Embedding Residue Tracking) | R5残留物の検出・追跡・ハザードスコア算出 |
| **IRD** (Inference Residue Defense) | 全残留物タイプの依存グラフ構築 |
| **N1 CGS** (Cryptographic Graph Shredding) | ノード鍵破棄による暗号的削除 |

**統合効果:** E1がembedding残滓を検出 → IRDが依存グラフを構築 → CGSが鍵破棄で暗号的に不可逆削除。GDPR Art.17 の技術的充足。

### E3 + FIL = Forensic Chain

| 概念 | 役割 |
|------|------|
| **E3** (Immutable Audit Commitment) | CSEBイベントのappend-only記録 + Merkleルート |
| **N2 FIL** (Forensic Integrity Layer) | 専用フォレンジック分析 + SIEM統合 |

**統合効果:** E3が監査基盤を提供 → FILがその上にインシデント分類・証拠保全・外部統合を構築。

### E5 + CQN = Cognitive Fingerprint Defense

| 概念 | 役割 |
|------|------|
| **E5** (Query Canonicalization Shield) | KQR内の基本正規化パイプライン |
| **N7 CQN** (Cognitive Query Normalization) | ML正規化 + バッチング + トピック平滑化 |

**統合効果:** E5が基本的な言語正規化を提供 → CQNが高度なML正規化で認知指紋を体系的に消去。

---

## 8. 新規構造の統合パターン (frontier-security-research.md)

### N6 (FSIE) + CBS + IFC + CTA = Verified Security Core

TLA+仕様により CBS/IFC/CTA のセキュリティ不変条件を形式的に検証。プロパティベーステストで実装との一致を継続保証。Phase 1 必須。

### N8 (DPBC) + AGTR + CSELP + GEAP = DP-Managed Privacy

全DP消費コンポーネントの予算をDPBCが一元管理。zCDP合成定理で累積劣化を追跡し、予算枯渇時は自動停止。

### N5 (VSCA) + ビルドパイプライン = Supply Chain Trust

SLSA L3 + Sigstore署名 + SBOM公開。LLMランタイム（llama.cpp/ONNX）のハッシュ検証を含む。
