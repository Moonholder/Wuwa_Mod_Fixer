import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { i18n } from '../i18n'

marked.setOptions({
  breaks: true,
  gfm: true,
})

const customRenderer = new marked.Renderer()

customRenderer.code = function({ text, lang }) {
  const displayLang = (lang || 'ini').toUpperCase()
  const safeCode = escapeHtml(text)
  const encodedCode = encodeURIComponent(text)
  const copyLabel = (i18n.global.t('console.copy') as string) || '复制'
  return `<div class="code-card my-2.5 rounded-lg overflow-hidden border border-zinc-200/90 dark:border-zinc-700/60 shadow-sm"><div class="code-card-header flex justify-between items-center px-3.5 py-1.5 bg-zinc-100/90 dark:bg-[#161922] border-b border-zinc-200/80 dark:border-zinc-700/60 text-[11px] font-mono select-none"><div class="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-400 font-semibold"><span class="w-2 h-2 rounded-full bg-sky-500 dark:bg-sky-400 inline-block shadow-[0_0_6px_rgba(56,189,248,0.5)]"></span><span>${displayLang}</span></div><button type="button" class="copy-code-btn inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] text-zinc-600 dark:text-zinc-300 hover:text-sky-600 dark:hover:text-sky-400 bg-white/80 dark:bg-white/[0.06] hover:bg-zinc-200/70 dark:hover:bg-white/10 border border-zinc-200 dark:border-zinc-700/50 transition-all cursor-pointer select-none active:scale-95" data-code="${encodedCode}"><svg class="w-3.5 h-3.5 copy-icon pointer-events-none text-current" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg><span class="copy-text pointer-events-none font-sans font-medium text-[11px]">${copyLabel}</span></button></div><pre class="!m-0 !p-3.5 !rounded-none !border-none !bg-[#0b0c11]"><code class="text-[12px] font-mono leading-relaxed text-emerald-400 select-text">${safeCode}</code></pre></div>`
}

marked.use({ renderer: customRenderer })

export function renderMarkdown(content: string): string {
  if (!content) return ''
  const rawHtml = marked.parse(content) as string
  return DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'p', 'b', 'i', 'strong', 'em', 'strike',
      'code', 'hr', 'br', 'ul', 'ol', 'li',
      'blockquote', 'pre', 'a', 'span', 'div',
      'button', 'svg', 'path'
    ],
    ALLOWED_ATTR: [
      'href', 'target', 'rel', 'class', 'style',
      'type', 'data-code', 'fill', 'stroke', 'viewBox',
      'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'd'
    ],
  })
}

// Simple HTML escape to prevent XSS
function escapeHtml(unsafe: string) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Precompile regex patterns for performance
const REGEX_HASH = /\b([0-9a-fA-F]{8,16})\b/g;
const REGEX_PATH = /(C:|D:|E:|F:|\/)?([\w\-\.\s\\]+\\[\w\-\.\s\\]+\.\w{3,4})/g;

function preformatLog(msg: string): string {
  let safeMsg = escapeHtml(msg);
  
  // Colorize log level prefixes with modern glowing high-quality badges
  safeMsg = safeMsg.replace(/^\[INFO\]\s*/, '<span class="inline-flex bg-sky-500/10 text-sky-400 font-bold px-1.5 py-0.5 rounded text-[10px] border border-sky-500/20 mr-1.5 select-none tracking-wide">INFO</span>');
  safeMsg = safeMsg.replace(/^\[WARN\]\s*/, '<span class="inline-flex bg-amber-500/10 text-amber-400 font-bold px-1.5 py-0.5 rounded text-[10px] border border-amber-500/20 mr-1.5 select-none tracking-wide">WARN</span>');
  safeMsg = safeMsg.replace(/^\[ERROR\]\s*/, '<span class="inline-flex bg-rose-500/10 text-rose-400 font-bold px-1.5 py-0.5 rounded text-[10px] border border-rose-500/20 mr-1.5 select-none tracking-wide">ERROR</span>');
  safeMsg = safeMsg.replace(/^\[OK\]\s*/, '<span class="inline-flex bg-emerald-500/10 text-emerald-400 font-bold px-1.5 py-0.5 rounded text-[10px] border border-emerald-500/20 mr-1.5 select-none tracking-wide">SUCCESS</span>');
  safeMsg = safeMsg.replace(/^\[DEBUG\]\s*/, '<span class="inline-flex bg-zinc-500/10 text-zinc-400 font-bold px-1.5 py-0.5 rounded text-[10px] border border-zinc-500/20 mr-1.5 select-none tracking-wide">DEBUG</span>');
  
  safeMsg = safeMsg.replace(REGEX_HASH, '<span class="text-sky-300 font-bold">$1</span>');
  safeMsg = safeMsg.replace(REGEX_PATH, '<span class="text-zinc-400 underline decoration-zinc-600 underline-offset-2 break-all">$&</span>');

  // Support inline markdown for single-line logs: `code` and **bold**
  safeMsg = safeMsg.replace(/`([^`]+)`/g, '<code class="bg-zinc-200/60 dark:bg-zinc-800 text-sky-600 dark:text-sky-300 px-1 py-0.5 rounded text-[11px] font-mono border border-zinc-300/50 dark:border-zinc-700/60">$1</code>');
  safeMsg = safeMsg.replace(/\*\*([^*]+)\*\*/g, '<strong class="font-bold text-zinc-900 dark:text-zinc-100">$1</strong>');

  return safeMsg;
}

let globalLogId = 0; // Global incremental ID for Vue list :key binding

export interface LogEntry {
  id: number
  level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG'
  messageHtml: string // 预渲染好的 HTML
  ts: number
  isMarkdown?: boolean
  rawText?: string
}

// ── rAF batching: buffer logs and flush at most once per animation frame ──
// This prevents Vue reactivity rebuilds from blocking the render loop.
let pendingLogs: LogEntry[] = [];
let rafId: number | null = null;

const MAX_LOGS = 500;

function scheduleFlush(store: ReturnType<typeof useFixStore>) {
  if (rafId !== null) return; // already scheduled
  rafId = requestAnimationFrame(() => {
    if (pendingLogs.length === 0) {
      rafId = null;
      return;
    }
    let merged = [...store.logs, ...pendingLogs];
    if (merged.length > MAX_LOGS) merged = merged.slice(merged.length - MAX_LOGS);
    store.logs = merged;
    pendingLogs = [];
    rafId = null;
  });
}

export interface PipelineEvent {
  event:
    | 'start'
    | 'stage'
    | 'file_start'
    | 'file_step'
    | 'file_success'
    | 'file_skipped'
    | 'file_error'
    | 'progress'
    | 'log'
    | 'task_cancelled'
    | 'finish'
  path?: string
  current?: number
  total?: number
  percent?: number
  mode?: string
  stage?: string
  description?: string
  character?: string
  reason?: string
  reason_key?: string
  error?: string
  error_key?: string
  message_key?: string
  message?: string
  summary?: {
    total_files: number
    success_count: number
    skipped_count: number
    failure_count: number
    elapsed_ms: number
  }
}

export const useFixStore = defineStore('fix', {
  state: () => ({
    isProcessing: false,
    isCancelling: false,
    logs: [] as readonly LogEntry[],
    progress: { current: 0, total: 0 },
    currentFile: '',
    activeStage: '',
    summary: null as PipelineEvent['summary'] | null,
    autoScroll: true,
  }),

  getters: {
    progressPct: (s) => s.progress.total ? Math.round((s.progress.current / s.progress.total) * 100) : 0,
    running: (s) => s.isProcessing,
  },

  actions: {
    pushLog(level: string, message: string) {
      // Object.freeze prevents Vue reactivity overhead
      const entry = Object.freeze({
        id: globalLogId++,
        level: level as LogEntry['level'],
        messageHtml: preformatLog(message),
        ts: Date.now(),
        rawText: message,
      });
      
      const newLogs = [...this.logs, entry];
      if (newLogs.length > MAX_LOGS) newLogs.splice(0, newLogs.length - MAX_LOGS);
      this.logs = newLogs; 
    },

    pushMarkdownLog(content: string, level = 'INFO') {
      const entry = Object.freeze({
        id: globalLogId++,
        level: level as LogEntry['level'],
        messageHtml: renderMarkdown(content),
        ts: Date.now(),
        isMarkdown: true,
        rawText: content,
      });

      const newLogs = [...this.logs, entry];
      if (newLogs.length > MAX_LOGS) newLogs.splice(0, newLogs.length - MAX_LOGS);
      this.logs = newLogs;
    },

    clearLogs() {
      this.logs = [];
    },

    async startFix(options: any) {
      if (!options.path) return;
      this.isProcessing = true;
      this.isCancelling = false;
      this.logs = [];
      this.progress = { current: 0, total: 0 };
      this.currentFile = '';
      this.activeStage = '';
      this.summary = null;

      // Reset rAF batch state
      pendingLogs = [];
      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }

      let unlisteners: UnlistenFn[] = [];

      // Listen to unified structured pipeline event stream
      unlisteners.push(await listen<PipelineEvent>('fix:pipeline_event', (e) => {
        const ev = e.payload;
        if (ev.event === 'file_start' && ev.path) {
          this.currentFile = ev.path;
        } else if (ev.event === 'stage' && ev.description) {
          this.activeStage = ev.description;
        } else if (ev.event === 'finish' && ev.summary) {
          this.summary = ev.summary;
        }
      }));

      // rAF-batched log listener: incoming logs buffer into pendingLogs,
      // flushed to Vue state at most once per animation frame (~16ms).
      // Combined with backend's 50ms batch interval, this ensures smooth 60fps.
      unlisteners.push(await listen<{ level: string; message: string }[]>('fix:logs', (e) => {
        const now = Date.now();
        for (const log of e.payload) {
          pendingLogs.push(Object.freeze({
            id: globalLogId++,
            level: log.level as LogEntry['level'],
            messageHtml: preformatLog(log.message),
            ts: now,
            rawText: log.message,
          }));
        }
        scheduleFlush(this);
      }));

      unlisteners.push(await listen<{ current: number; total: number }>('fix:progress', (e) => {
        this.progress = e.payload;
      }));

      return new Promise<void>(async (resolve) => {
        unlisteners.push(await listen('fix:done', () => {
          // Flush any remaining buffered logs immediately
          if (pendingLogs.length > 0) {
            let merged = [...this.logs, ...pendingLogs];
            if (merged.length > MAX_LOGS) merged = merged.slice(merged.length - MAX_LOGS);
            this.logs = merged;
            pendingLogs = [];
          }
          if (rafId !== null) {
            cancelAnimationFrame(rafId);
            rafId = null;
          }

          this.isProcessing = false;
          this.isCancelling = false;
          if (this.summary) {
            this.pushLog(
              'INFO',
              `✓ ${i18n.global.t('console.fix_done')} [${this.summary.success_count} OK, ${this.summary.skipped_count} Skip, ${this.summary.failure_count} Fail, ${this.summary.elapsed_ms}ms]`
            );
          } else {
            this.pushLog('INFO', `✓ ${i18n.global.t('console.fix_done')}`);
          }
          unlisteners.forEach(unlisten => unlisten());
          resolve();
        }));

        try {
          await invoke('start_fix', options);
        } catch (e) {
          this.isProcessing = false;
          this.isCancelling = false;
          const errMsg = typeof e === 'object' && e !== null && 'message' in e 
            ? `[${(e as any).kind || 'Error'}] ${(e as any).message}` 
            : String(e);
          this.pushLog('ERROR', errMsg);
          unlisteners.forEach(unlisten => unlisten());
          resolve();
        }
      });
    },

    async cancelFix() {
      if (!this.isProcessing || this.isCancelling) return;
      this.isCancelling = true;
      this.pushLog('WARN', i18n.global.t('console.cancelling') as string);
      await invoke('cancel_fix');
    }
  },
})