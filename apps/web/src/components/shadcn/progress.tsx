import * as React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  max?: number;
  indicatorClassName?: string;
}

export function Progress({
  value = 0,
  max = 100,
  className,
  indicatorClassName,
  ...props
}: ProgressProps) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));

  return (
    <div
      role="progressbar"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={max}
      className={cn(
        'relative h-2 w-full overflow-hidden rounded-full bg-[var(--mint-tint)] dark:bg-white/10',
        className
      )}
      {...props}
    >
      <div
        className={cn(
          'h-full bg-[#00D4A0] transition-all duration-500 ease-out rounded-full',
          indicatorClassName
        )}
        style={{ width: `${percentage}%` }}
      />
    </div>
  );
}

