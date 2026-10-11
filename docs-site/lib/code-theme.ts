import type { ThemeRegistration } from 'shiki';

// Code tokens from the CKB KeyWay design system. Code blocks stay dark in both
// themes so code reads the same on every KeyWay site.
export const keywayCodeTheme: ThemeRegistration = {
  name: 'ckb-keyway',
  type: 'dark',
  colors: {
    'editor.background': '#111B35',
    'editor.foreground': '#F3F1E6',
  },
  tokenColors: [
    { settings: { foreground: '#F3F1E6' } },
    { scope: ['comment', 'punctuation.definition.comment'], settings: { foreground: '#A9B0C6', fontStyle: 'italic' } },
    {
      scope: ['keyword', 'storage', 'storage.type', 'storage.modifier', 'keyword.control', 'keyword.operator.new', 'variable.language'],
      settings: { foreground: '#8DA2FF' },
    },
    {
      scope: ['string', 'constant.numeric', 'constant.language', 'constant.character', 'string.template'],
      settings: { foreground: '#F2C14E' },
    },
    {
      scope: ['entity.name.tag', 'support.class.component', 'entity.name.type', 'entity.name.class', 'support.type'],
      settings: { foreground: '#FF9C88' },
    },
    { scope: ['entity.other.attribute-name', 'meta.object-literal.key'], settings: { foreground: '#F3F1E6' } },
  ],
};
