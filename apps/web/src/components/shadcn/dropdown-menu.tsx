import * as React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

interface DropdownMenuContextType {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const DropdownMenuContext = React.createContext<DropdownMenuContextType>({
  open: false,
  setOpen: () => {},
});

export function DropdownMenu({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [open]);

  return (
    <DropdownMenuContext.Provider value={{ open, setOpen }}>
      <div ref={ref} className="relative inline-block text-left">
        {children}
      </div>
    </DropdownMenuContext.Provider>
  );
}

export function DropdownMenuTrigger({ children, asChild }: { children: React.ReactNode; asChild?: boolean }) {
  const { open, setOpen } = React.useContext(DropdownMenuContext);
  
  if (asChild && React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<any>, {
      onClick: (e: React.MouseEvent) => {
        (children.props as any).onClick?.(e);
        setOpen(!open);
      },
      'aria-expanded': open,
    });
  }

  return (
    <button
      type="button"
      onClick={() => setOpen(!open)}
      aria-expanded={open}
      className="inline-flex items-center justify-center rounded-full"
    >
      {children}
    </button>
  );
}

export function DropdownMenuContent({
  className,
  align = 'end',
  children,
}: {
  className?: string;
  align?: 'left' | 'end' | 'center';
  children: React.ReactNode;
}) {
  const { open } = React.useContext(DropdownMenuContext);
  if (!open) return null;

  return (
    <div
      className={cn(
        'absolute z-50 mt-2 min-w-[12rem] overflow-hidden rounded-2xl border border-[var(--line)] bg-[var(--surface)] p-1.5 shadow-xl animate-in fade-in zoom-in-95 duration-150 dark:bg-[#1A2420] dark:border-white/10',
        align === 'end' && 'right-0 origin-top-right',
        align === 'left' && 'left-0 origin-top-left',
        align === 'center' && 'left-1/2 -translate-x-1/2',
        className
      )}
    >
      {children}
    </div>
  );
}

export function DropdownMenuItem({
  className,
  children,
  onClick,
  disabled,
}: {
  className?: string;
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  const { setOpen } = React.useContext(DropdownMenuContext);

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => {
        if (!disabled) {
          onClick?.();
          setOpen(false);
        }
      }}
      className={cn(
        'flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm text-[var(--heading)] transition-colors hover:bg-[var(--mint-tint)] hover:text-[var(--heading)] disabled:opacity-50 disabled:pointer-events-none dark:hover:bg-white/10 text-left',
        className
      )}
    >
      {children}
    </button>
  );
}

export function DropdownMenuSeparator() {
  return <div className="my-1 h-px bg-[var(--line)] dark:bg-white/10" />;
}

