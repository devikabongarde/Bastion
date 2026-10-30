import * as React from 'react';
import { ChevronRight } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export function Breadcrumb({ className, children, ...props }: React.HTMLAttributes<HTMLElement>) {
  return (
    <nav aria-label="breadcrumb" className={cn('flex items-center text-sm', className)} {...props}>
      <ol className="flex items-center gap-1.5">{children}</ol>
    </nav>
  );
}

export function BreadcrumbItem({ className, ...props }: React.HTMLAttributes<HTMLLIElement>) {
  return <li className={cn('inline-flex items-center gap-1.5', className)} {...props} />;
}

export function BreadcrumbLink({
  className,
  asChild,
  children,
  ...props
}: React.AnchorHTMLAttributes<HTMLAnchorElement> & { asChild?: boolean }) {
  return (
    <a
      className={cn(
        'text-[var(--heading-soft)] transition-colors hover:text-[var(--heading)]',
        className
      )}
      {...props}
    >
      {children}
    </a>
  );
}

export function BreadcrumbPage({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      role="link"
      aria-disabled="true"
      aria-current="page"
      className={cn('font-semibold text-[var(--heading)]', className)}
      {...props}
    />
  );
}

export function BreadcrumbSeparator({
  children,
  className,
  ...props
}: React.HTMLAttributes<HTMLLIElement>) {
  return (
    <li
      role="presentation"
      aria-hidden="true"
      className={cn('text-[var(--heading-soft)] [&>svg]:size-3.5', className)}
      {...props}
    >
      {children ?? <ChevronRight className="h-3.5 w-3.5" />}
    </li>
  );
}

