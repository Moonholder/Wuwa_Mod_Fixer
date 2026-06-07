import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { i18n } from '../i18n'

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
  
  safeMsg = safeMsg.replace(REGEX_HASH, '<span class="text-sky-300 font-bold">$1</span>');
  safeMsg = safeMsg.replace(REGEX_PATH, '<span class="text-zinc-400 underline decoration-zinc-600 underline-offset-2 break-all">$&</span>');
  return safeMsg;
}

let globalLogId = 0; // Global incremental ID for Vue list :key binding

export interface LogEntry {
  id: number
  level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG'
  messageHtml: string // 预渲染好的 HTML
  ts: number
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

export const useFixStore = defineStore('fix', {
  state: () => ({
    isProcessing: false,
    isCancelling: false,
    logs: [] as readonly LogEntry[],
    progress: { current: 0, total: 0 },
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
        ts: Date.now()
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

      // Reset rAF batch state
      pendingLogs = [];
      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }

      let unlisteners: UnlistenFn[] = [];

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
            ts: now
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
          this.pushLog('INFO', `✓ ${i18n.global.t('console.fix_done')}`);
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