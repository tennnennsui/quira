export const languages = {
  en: { label: 'English', flag: '🇺🇸' },
  ja: { label: '日本語', flag: '🇯🇵' },
} as const;

export type Lang = keyof typeof languages;
export const defaultLang: Lang = 'en';

export function getLangFromPath(path: string): Lang {
  if (path.includes('/ja/')) return 'ja';
  if (path.includes('/en/')) return 'en';
  return defaultLang;
}

export function getBasePath(lang: Lang): string {
  return `/docs/${lang}`;
}

export function switchLangPath(currentPath: string, targetLang: Lang): string {
  const currentLang = getLangFromPath(currentPath);
  const currentBase = `/docs/${currentLang}/`;
  const targetBase = `/docs/${targetLang}/`;
  if (currentPath.includes(currentBase)) {
    return currentPath.replace(currentBase, targetBase);
  }
  return `${targetBase}`;
}

export const ui = {
  en: {
    navGuide: 'Guide',
    navApi: 'API Reference',
    navArch: 'Architecture',
    navContrib: 'Contributing',
    breadcrumbRoot: 'Docs',
    feedbackQuestion: 'Was this page helpful?',
    feedbackYes: 'Yes',
    feedbackNo: 'No',
    feedbackThanks: 'Thanks for your feedback!',
    feedbackImprove: "Thanks! We'll improve this page.",
    searchPlaceholder: 'Search documentation...',
    searchHint: 'Try "Context Graph", "installation", or "API"',
    searchEmpty: 'Start typing to search the documentation...',
    searchNoResults: 'No results found for',
    onThisPage: 'On this page',
    sidebarSearch: 'Search...',
    sidebarRepo: 'Repository',
    sidebarQuickStart: 'Quick Start',
    guideSections: ['Getting Started', 'Welcome', 'Core Concepts', 'Features'],
    apiSection: 'API Reference',
    archSection: 'Architecture',
    contribSection: 'Contributing',
    navSecurity: 'Security',
    securitySection: 'Security & Privacy',
  },
  ja: {
    navGuide: 'ガイド',
    navApi: 'API リファレンス',
    navArch: 'アーキテクチャ',
    navContrib: 'コントリビュート',
    breadcrumbRoot: 'ドキュメント',
    feedbackQuestion: 'このページは役に立ちましたか？',
    feedbackYes: 'はい',
    feedbackNo: 'いいえ',
    feedbackThanks: 'フィードバックありがとうございます！',
    feedbackImprove: 'ありがとうございます！改善に努めます。',
    searchPlaceholder: 'ドキュメントを検索...',
    searchHint: '"Context Graph"、"インストール"、"API" で検索',
    searchEmpty: '検索ワードを入力してください...',
    searchNoResults: '見つかりませんでした：',
    onThisPage: 'このページの内容',
    sidebarSearch: '検索...',
    sidebarRepo: 'リポジトリ',
    sidebarQuickStart: 'クイックスタート',
    guideSections: ['はじめに', 'ようこそ', 'コアコンセプト', '機能'],
    apiSection: 'API リファレンス',
    archSection: 'アーキテクチャ',
    contribSection: 'コントリビュート',
    navSecurity: 'セキュリティ',
    securitySection: 'セキュリティ & プライバシー',
  },
} as const;

export function t(lang: Lang) {
  return ui[lang];
}

export function getSidebarSections(lang: Lang) {
  const base = getBasePath(lang);
  if (lang === 'ja') {
    return [
      {
        title: 'はじめに',
        defaultOpen: true,
        items: [
          { href: `${base}/`, label: 'ようこそ' },
          { href: `${base}/getting-started/what-is-quira/`, label: 'Quira とは？' },
          { href: `${base}/getting-started/quick-start/`, label: 'クイックスタート' },
          { href: `${base}/getting-started/installation/`, label: 'インストール' },
        ],
      },
      {
        title: 'コアコンセプト',
        defaultOpen: true,
        items: [
          { href: `${base}/core-concepts/context-graph/`, label: 'Context Graph' },
          { href: `${base}/core-concepts/context-spaces/`, label: 'Context Spaces' },
          { href: `${base}/core-concepts/local-ai/`, label: 'Local AI' },
          { href: `${base}/core-concepts/research-replay/`, label: 'Research Replay' },
        ],
      },
      {
        title: '機能',
        defaultOpen: true,
        items: [
          { href: `${base}/features/nl-query/`, label: '自然言語クエリ' },
          { href: `${base}/features/ai-privacy/`, label: 'AI プライバシーレベル' },
          { href: `${base}/features/graph-visualization/`, label: 'グラフビジュアライゼーション' },
          { href: `${base}/features/export-import/`, label: 'エクスポート & インポート' },
        ],
      },
      {
        title: 'アーキテクチャ',
        defaultOpen: false,
        items: [
          { href: `${base}/architecture/technical-overview/`, label: '技術概要' },
          { href: `${base}/architecture/gecko-engine/`, label: 'Gecko Engine' },
          { href: `${base}/architecture/storage/`, label: 'ストレージ (SQLite)' },
          { href: `${base}/architecture/llm-integration/`, label: 'LLM Integration' },
        ],
      },
      {
        title: 'コントリビュート',
        defaultOpen: false,
        items: [
          { href: `${base}/contributing/dev-setup/`, label: '開発環境セットアップ' },
          { href: `${base}/contributing/code-style/`, label: 'コードスタイル' },
          { href: `${base}/contributing/pull-requests/`, label: 'プルリクエスト' },
          { href: `${base}/contributing/rfc-process/`, label: 'RFC プロセス' },
        ],
      },
      {
        title: 'セキュリティ & プライバシー',
        defaultOpen: false,
        items: [
          { href: `${base}/security/overview/`, label: 'セキュリティ概要' },
          { href: `${base}/security/threat-model/`, label: '脅威モデル' },
          { href: `${base}/security/network-firewall/`, label: 'ネットワークファイアウォール' },
          { href: `${base}/security/privacy-architecture/`, label: 'プライバシーアーキテクチャ' },
          { href: `${base}/security/content-filtering/`, label: 'コンテンツフィルタリング' },
          { href: `${base}/security/threat-protection/`, label: '脅威対策' },
          { href: `${base}/security/permission-system/`, label: 'パーミッションシステム' },
          { href: `${base}/security/advanced-architecture/`, label: '先進アーキテクチャ' },
          { href: `${base}/security/emergent-security/`, label: '創発的セキュリティ' },
        ],
      },
      {
        title: 'ユースケース',
        defaultOpen: false,
        items: [
          { href: `${base}/use-cases/developers/`, label: '開発者向け' },
          { href: `${base}/use-cases/researchers/`, label: '研究者向け' },
          { href: `${base}/use-cases/writers/`, label: 'ライター向け' },
        ],
      },
      {
        title: 'リソース',
        defaultOpen: false,
        items: [
          { href: `${base}/troubleshooting/`, label: 'トラブルシューティング' },
          { href: `${base}/release-notes/`, label: 'リリースノート' },
        ],
      },
      {
        title: 'API リファレンス',
        defaultOpen: false,
        items: [
          { href: `${base}/api/plugin-api/`, label: 'Plugin API' },
          { href: `${base}/api/webextension-api/`, label: 'WebExtension API' },
          { href: `${base}/api/graph-query-api/`, label: 'Graph Query API' },
        ],
      },
    ];
  }
  return [
    {
      title: 'Getting Started',
      defaultOpen: true,
      items: [
        { href: `${base}/`, label: 'Welcome' },
        { href: `${base}/getting-started/what-is-quira/`, label: 'What is Quira?' },
        { href: `${base}/getting-started/quick-start/`, label: 'Quick Start' },
        { href: `${base}/getting-started/installation/`, label: 'Installation' },
      ],
    },
    {
      title: 'Core Concepts',
      defaultOpen: true,
      items: [
        { href: `${base}/core-concepts/context-graph/`, label: 'Context Graph' },
        { href: `${base}/core-concepts/context-spaces/`, label: 'Context Spaces' },
        { href: `${base}/core-concepts/local-ai/`, label: 'Local AI' },
        { href: `${base}/core-concepts/research-replay/`, label: 'Research Replay' },
      ],
    },
    {
      title: 'Features',
      defaultOpen: true,
      items: [
        { href: `${base}/features/nl-query/`, label: 'Natural Language Query' },
        { href: `${base}/features/ai-privacy/`, label: 'AI Privacy Levels' },
        { href: `${base}/features/graph-visualization/`, label: 'Graph Visualization' },
        { href: `${base}/features/export-import/`, label: 'Export & Import' },
      ],
    },
    {
      title: 'Architecture',
      defaultOpen: false,
      items: [
        { href: `${base}/architecture/technical-overview/`, label: 'Technical Overview' },
        { href: `${base}/architecture/gecko-engine/`, label: 'Gecko Engine' },
        { href: `${base}/architecture/storage/`, label: 'Storage (SQLite)' },
        { href: `${base}/architecture/llm-integration/`, label: 'LLM Integration' },
      ],
    },
    {
      title: 'Contributing',
      defaultOpen: false,
      items: [
        { href: `${base}/contributing/dev-setup/`, label: 'Development Setup' },
        { href: `${base}/contributing/code-style/`, label: 'Code Style' },
        { href: `${base}/contributing/pull-requests/`, label: 'Pull Requests' },
        { href: `${base}/contributing/rfc-process/`, label: 'RFC Process' },
      ],
    },
    {
      title: 'Security & Privacy',
      defaultOpen: false,
      items: [
        { href: `${base}/security/overview/`, label: 'Security Overview' },
        { href: `${base}/security/threat-model/`, label: 'Threat Model' },
        { href: `${base}/security/network-firewall/`, label: 'Network Firewall' },
        { href: `${base}/security/privacy-architecture/`, label: 'Privacy Architecture' },
        { href: `${base}/security/content-filtering/`, label: 'Content Filtering' },
        { href: `${base}/security/threat-protection/`, label: 'Threat Protection' },
        { href: `${base}/security/permission-system/`, label: 'Permission System' },
        { href: `${base}/security/advanced-architecture/`, label: 'Advanced Architecture' },
        { href: `${base}/security/emergent-security/`, label: 'Emergent Security' },
      ],
    },
    {
      title: 'Use Cases',
      defaultOpen: false,
      items: [
        { href: `${base}/use-cases/developers/`, label: 'For Developers' },
        { href: `${base}/use-cases/researchers/`, label: 'For Researchers' },
        { href: `${base}/use-cases/writers/`, label: 'For Writers' },
      ],
    },
    {
      title: 'Resources',
      defaultOpen: false,
      items: [
        { href: `${base}/troubleshooting/`, label: 'Troubleshooting' },
        { href: `${base}/release-notes/`, label: 'Release Notes' },
      ],
    },
    {
      title: 'API Reference',
      defaultOpen: false,
      items: [
        { href: `${base}/api/plugin-api/`, label: 'Plugin API' },
        { href: `${base}/api/webextension-api/`, label: 'WebExtension API' },
        { href: `${base}/api/graph-query-api/`, label: 'Graph Query API' },
      ],
    },
  ];
}
