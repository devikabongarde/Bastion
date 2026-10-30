import * as React from 'react';
import { ChevronDown } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

interface AccordionContextType {
  openItems: string[];
  toggleItem: (value: string) => void;
}

const AccordionContext = React.createContext<AccordionContextType>({
  openItems: [],
  toggleItem: () => {},
});

export function Accordion({
  type = 'single',
  defaultValue,
  children,
  className,
}: {
  type?: 'single' | 'multiple';
  defaultValue?: string | string[];
  children: React.ReactNode;
  className?: string;
}) {
  const [openItems, setOpenItems] = React.useState<string[]>(
    Array.isArray(defaultValue) ? defaultValue : defaultValue ? [defaultValue] : []
  );

  const toggleItem = (val: string) => {
    if (type === 'single') {
      setOpenItems((prev) => (prev.includes(val) ? [] : [val]));
    } else {
      setOpenItems((prev) =>
        prev.includes(val) ? prev.filter((i) => i !== val) : [...prev, val]
      );
    }
  };

  return (
    <AccordionContext.Provider value={{ openItems, toggleItem }}>
      <div className={cn('divide-y divide-[var(--line)] dark:divide-white/10', className)}>
        {children}
      </div>
    </AccordionContext.Provider>
  );
}

export function AccordionItem({
  value,
  children,
  className,
}: {
  value: string;
  children: React.ReactNode;
  className?: string;
}) {
  return <div data-value={value} className={cn('py-2', className)}>{children}</div>;
}

export function AccordionTrigger({
  value,
  children,
  className,
}: {
  value: string;
  children: React.ReactNode;
  className?: string;
}) {
  const { openItems, toggleItem } = React.useContext(AccordionContext);
  const isOpen = openItems.includes(value);

  return (
    <button
      type="button"
      onClick={() => toggleItem(value)}
      aria-expanded={isOpen}
      className={cn(
        'flex w-full items-center justify-between py-3 text-left font-semibold text-[var(--heading)] transition-all hover:text-[var(--accent-text)]',
        className
      )}
    >
      <span>{children}</span>
      <ChevronDown
        className={cn(
          'h-4 w-4 shrink-0 text-[var(--heading-soft)] transition-transform duration-200',
          isOpen && 'rotate-180 text-[var(--accent-text)]'
        )}
      />
    </button>
  );
}

export function AccordionContent({
  value,
  children,
  className,
}: {
  value: string;
  children: React.ReactNode;
  className?: string;
}) {
  const { openItems } = React.useContext(AccordionContext);
  const isOpen = openItems.includes(value);

  if (!isOpen) return null;

  return (
    <div className={cn('pb-4 pt-1 text-sm text-[var(--body)] animate-in fade-in duration-200', className)}>
      {children}
    </div>
  );
}
