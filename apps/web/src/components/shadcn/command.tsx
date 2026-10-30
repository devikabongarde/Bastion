import * as React from 'react';
import { Search } from 'lucide-react';

interface CommandDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

export function CommandDialog({ open, onOpenChange, children }: CommandDialogProps) {
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open) {
        onOpenChange(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onOpenChange]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 p-4 sm:p-6 animate-in fade-in duration-150">
      <div
        className="fixed inset-0 bg-[#0B2B26]/40 backdrop-blur-sm"
        onClick={() => onOpenChange(false)}
        aria-hidden="true"
      />
      <div className="relative z-50 w-full max-w-xl overflow-hidden rounded-[24px] border border-[var(--line-strong)] bg-[var(--surface)] shadow-2xl dark:bg-[#1A2420] dark:border-white/10">
        {children}
      </div>
    </div>
  );
}

export function CommandInput({
  value,
  onValueChange,
  placeholder = 'Type a command or search assets, policies, findings...',
}: {
  value: string;
  onValueChange: (val: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="flex items-center border-b border-[var(--line)] px-4 py-3 dark:border-white/10">
      <Search className="mr-3 h-5 w-5 text-[var(--heading-soft)] shrink-0" />
      <input
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        placeholder={placeholder}
        autoFocus
        className="flex h-9 w-full rounded-md bg-transparent text-sm text-[var(--heading)] outline-none placeholder:text-[var(--heading-soft)] dark:placeholder:text-emerald-500/50"
      />
      <kbd className="pointer-events-none hidden h-5 select-none items-center gap-1 rounded bg-[var(--surface)] px-1.5 font-mono text-[10px] font-medium text-[var(--heading-soft)] sm:flex dark:bg-white/10">
        ESC
      </kbd>
    </div>
  );
}

export function CommandList({ children }: { children: React.ReactNode }) {
  return <div className="max-h-[340px] overflow-y-auto p-2 space-y-1">{children}</div>;
}

export function CommandGroup({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <div className="py-1">
      <div className="px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-[var(--heading-soft)]">
        {heading}
      </div>
      <div>{children}</div>
    </div>
  );
}

export function CommandItem({
  children,
  onSelect,
  shortcut,
}: {
  children: React.ReactNode;
  onSelect: () => void;
  shortcut?: string;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className="flex w-full items-center justify-between rounded-xl px-3 py-2 text-sm text-[var(--heading)] transition-colors hover:bg-[var(--mint-tint)] hover:text-[var(--heading)] focus:bg-[var(--mint-tint)] focus:outline-none dark:hover:bg-white/10"
    >
      <div className="flex items-center gap-2.5 truncate">{children}</div>
      {shortcut && (
        <span className="font-mono text-[11px] text-[var(--heading-soft)]">{shortcut}</span>
      )}
    </button>
  );
}
