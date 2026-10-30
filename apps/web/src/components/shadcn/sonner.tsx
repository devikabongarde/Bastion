import * as React from 'react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export interface ToastMessage {
  id: string;
  title: string;
  description?: string;
  type?: 'success' | 'error' | 'info';
}

interface ToastContextType {
  toast: (options: Omit<ToastMessage, 'id'>) => void;
}

const ToastContext = React.createContext<ToastContextType>({
  toast: () => {},
});

export function useToast() {
  return React.useContext(ToastContext);
}

export function Toaster({ children }: { children?: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<ToastMessage[]>([]);

  const toast = React.useCallback(
    ({ title, description, type = 'info' }: Omit<ToastMessage, 'id'>) => {
      const id = Math.random().toString(36).substring(2, 9);
      setToasts((prev) => [...prev, { id, title, description, type }]);

      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4000);
    },
    []
  );

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              'pointer-events-auto flex items-start gap-3 rounded-2xl border bg-[var(--surface)] p-4 shadow-xl transition-all animate-in slide-in-from-bottom-2 dark:bg-[#1A2420]',
              t.type === 'success' && 'border-emerald-500/20 text-emerald-950',
              t.type === 'error' && 'border-[#F26B21]/20 text-orange-950 dark:text-orange-100',
              t.type === 'info' && 'border-[var(--line-strong)] text-[var(--heading)]'
            )}
          >
            {t.type === 'success' && <CheckCircle2 className="h-5 w-5 text-[var(--accent-text)] shrink-0 mt-0.5" />}
            {t.type === 'error' && <AlertCircle className="h-5 w-5 text-[var(--status-fail)] shrink-0 mt-0.5" />}
            {t.type === 'info' && <Info className="h-5 w-5 text-[var(--heading-soft)] shrink-0 mt-0.5" />}
            <div className="flex-1">
              <h5 className="font-semibold text-sm">{t.title}</h5>
              {t.description && <p className="text-xs text-[var(--body)] mt-0.5">{t.description}</p>}
            </div>
            <button
              type="button"
              onClick={() => removeToast(t.id)}
              className="text-[var(--heading-soft)] hover:text-[var(--heading)] p-0.5"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

