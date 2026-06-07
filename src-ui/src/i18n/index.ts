import { createI18n } from 'vue-i18n'
import en from './locales/en.json'
import zh from './locales/zh.json'
import zhTW from './locales/zh-TW.json'
import ja from './locales/ja.json'
import ko from './locales/ko.json'

export const SUPPORTED_LOCALES = ['en', 'zh', 'zh-TW', 'ja', 'ko'] as const
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number]

export const i18n = createI18n({
  legacy: false, // For Vue 3 Composition API
  locale: 'en',  // Default, will be updated by settings
  fallbackLocale: 'en',
  messages: {
    en,
    zh,
    'zh-TW': zhTW,
    ja,
    ko
  }
})
