import * as React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export function Tooltip({
  content,
  children,
  side = 'top',
}: {
  content: React.ReactNode;
  children: React.ReactNode;
  side?: 'top' | 'bottom' | 'left' | 'right';
}) {
  const [visible, setVisible] = React.useState(false);

  return (
    <div
      className="relative inline-flex"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
      onFocus={() => setVisible(true)}
      onBlur={() => setVisible(false)}
    >
      {children}
      {visible && (
        <div
          role="tooltip"
          className={cn(
            'absolute z-50 whitespace-nowrap rounded-lg bg-[#0B2B26] px-2.5 py-1 text-xs font-medium text-white shadow-md pointer-events-none animate-in fade-in zoom-in-95 duration-150',
            side === 'top' && 'bottom-full left-1/2 -translate-x-1/2 mb-1.5',
            side === 'bottom' && 'top-full left-1/2 -translate-x-1/2 mt-1.5',
            side === 'left' && 'right-full top-1/2 -translate-y-1/2 mr-1.5',
            side === 'right' && 'left-full top-1/2 -translate-y-1/2 ml-1.5'
          )}
        >
          {content}
        </div>
      )}
    </div>
  );
}

