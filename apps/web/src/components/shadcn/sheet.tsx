import * as React from 'react';
import { X } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export interface SheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
  side?: 'right' | 'left' | 'bottom';
  className?: string;
}

export function Sheet({ open, onOpenChange, children, side = 'right', className }: SheetProps) {
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open) {
        onOpenChange(false);
      }
    };
    if (open) {
      document.body.style.overflow = 'hidden';
      window.addEventListener('keydown', handleKeyDown);
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [open, onOpenChange]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex overflow-hidden">
      <div
        className="fixed inset-0 bg-[#0B2B26]/40 backdrop-blur-sm transition-opacity animate-in fade-in duration-300"
        onClick={() => onOpenChange(false)}
        aria-hidden="true"
      />
      <div
        className={cn(
          'fixed z-50 flex h-full flex-col bg-[var(--surface)] shadow-2xl transition-all duration-300 dark:bg-[#151E1A] dark:border-white/10',
          side === 'right' && 'inset-y-0 right-0 w-full sm:max-w-2xl border-l border-[var(--line)] animate-in slide-in-from-right',
          side === 'left' && 'inset-y-0 left-0 w-full sm:max-w-2xl border-r border-[var(--line)] animate-in slide-in-from-left',
          side === 'bottom' && 'inset-x-0 bottom-0 h-[85vh] rounded-t-[32px] border-t border-[var(--line)] animate-in slide-in-from-bottom',
          className
        )}
      >
        <button
          type="button"
          onClick={() => onOpenChange(false)}
          className="absolute right-5 top-5 z-10 rounded-full p-2 text-[var(--heading-soft)] hover:bg-[var(--mint-tint)] hover:text-[var(--heading)] focus:outline-none focus:ring-2 focus:ring-[#00D4A0] dark:hover:bg-white/10"
          aria-label="Close drawer"
        >
          <X className="h-5 w-5" />
        </button>
        {children}
      </div>
    </div>
  );
}

export function SheetHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex flex-col space-y-1.5 p-6 sm:p-8 border-b border-[var(--line)] dark:border-white/10 text-left', className)}
      {...props}
    />
  );
}

export function SheetTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h2
      className={cn('text-xl font-bold tracking-tight text-[var(--heading)]', className)}
      {...props}
    />
  );
}

export function SheetDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p
      className={cn('text-sm text-[var(--heading-soft)]', className)}
      {...props}
    />
  );
}

export function SheetContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex-1 overflow-y-auto p-6 sm:p-8 space-y-6', className)} {...props} />;
}

export function SheetFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex items-center justify-end space-x-3 p-6 border-t border-[var(--line)] dark:border-white/10 bg-[var(--surface)] dark:bg-black/20', className)}
      {...props}
    />
  );
}

