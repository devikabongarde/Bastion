import { Check, X, HelpCircle, AlertTriangle, UserCheck, Minus } from "lucide-react";

export type BastionStatus =
  | "PASS"
  | "FAIL"
  | "UNKNOWN"
  | "ERROR"
  | "MANUAL_REQUIRED"
  | "NOT_APPLICABLE"
  | "RESOLVED"
  | "RISK_ACCEPTED";

export interface StatusBadgeProps {
  status: BastionStatus | string;
  count?: number;
  className?: string;
  size?: "sm" | "md";
}

export function StatusBadge({ status, count, className = "", size = "md" }: StatusBadgeProps) {
  const normalized = status.toUpperCase().replace(/\s+/g, "_");
  const countSuffix = typeof count === "number" ? ` (${count})` : "";

  switch (normalized) {
    case "PASS":
    case "RESOLVED":
      return (
        <span className={`bastion-status-badge pass ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <Check aria-hidden="true" />
          <span>PASS{countSuffix}</span>
        </span>
      );

    case "FAIL":
      return (
        <span className={`bastion-status-badge fail ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <X aria-hidden="true" />
          <span>FAIL{countSuffix}</span>
        </span>
      );

    case "UNKNOWN":
      return (
        <span className={`bastion-status-badge unknown ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <HelpCircle aria-hidden="true" />
          <span>UNKNOWN{countSuffix}</span>
        </span>
      );

    case "ERROR":
      return (
        <span className={`bastion-status-badge error ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <AlertTriangle aria-hidden="true" />
          <span>ERROR{countSuffix}</span>
        </span>
      );

    case "MANUAL_REQUIRED":
    case "MANUAL":
      return (
        <span className={`bastion-status-badge manual ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <UserCheck aria-hidden="true" />
          <span>MANUAL{countSuffix}</span>
        </span>
      );

    case "NOT_APPLICABLE":
    case "NA":
      return (
        <span className={`bastion-status-badge na ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <Minus aria-hidden="true" />
          <span>N/A{countSuffix}</span>
        </span>
      );

    case "RISK_ACCEPTED":
      return (
        <span className={`bastion-status-badge unknown ${size === "sm" ? "text-[10px] py-0.5 px-2" : ""} ${className}`}>
          <HelpCircle aria-hidden="true" />
          <span>EXEMPT{countSuffix}</span>
        </span>
      );

    default:
      return (
        <span className={`bastion-status-badge na ${className}`}>
          <Minus aria-hidden="true" />
          <span>{status}{countSuffix}</span>
        </span>
      );
  }
}
