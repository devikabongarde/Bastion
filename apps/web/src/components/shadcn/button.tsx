import React from "react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: any[]) {
  return twMerge(clsx(inputs));
}

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "forest" | "outline" | "ghost" | "link";
  size?: "sm" | "md" | "lg";
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className = "", variant = "primary", size = "md", children, ...props }, ref) => {
    const variantClass =
      variant === "primary"
        ? "bastion-btn-primary"
        : variant === "forest"
        ? "bastion-btn-forest"
        : variant === "outline"
        ? "bastion-btn-outline"
        : variant === "ghost"
        ? "bastion-btn-ghost"
        : "text-[var(--accent-text)] underline-offset-4 hover:underline p-0";

    const sizeClass = size === "sm" ? "bastion-btn-sm" : size === "lg" ? "bastion-btn-lg" : "";

    return (
      <button
        ref={ref}
        className={cn("bastion-btn", variantClass, sizeClass, className)}
        {...props}
      >
        {children}
      </button>
    );
  }
);
Button.displayName = "Button";
