import { useId } from "react";

interface LogoProps {
  size?: number;
  showWordmark?: boolean;
  inverted?: boolean;
  className?: string;
}

/**
 * Bastion mark: two offset blocks. Ink is the evidence collected, mint is the
 * policy it is checked against, and the deep overlap is the verified result.
 */
export function LogoMark({ size = 28, inverted = false }: { size?: number; inverted?: boolean }) {
  const clip = `${useId().replace(/:/g, "")}-ink`;
  const ink = inverted ? "#FFFFFF" : "var(--logo-ink, #0B2B26)";
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true" style={{ flexShrink: 0 }}>
      <defs>
        <clipPath id={clip}>
          <rect x="2" y="2" width="19" height="19" rx="5.5" />
        </clipPath>
      </defs>
      <rect x="2" y="2" width="19" height="19" rx="5.5" fill={ink} />
      <rect x="11" y="11" width="19" height="19" rx="5.5" fill="#00D4A0" />
      <rect x="11" y="11" width="19" height="19" rx="5.5" fill={inverted ? "#7CF7D4" : "#00866A"} clipPath={`url(#${clip})`} />
    </svg>
  );
}

export function Logo({ size = 28, showWordmark = true, inverted = false, className = "" }: LogoProps) {
  return (
    <span className={`inline-flex items-center ${className}`} style={{ gap: size * 0.36 }}>
      <LogoMark size={size} inverted={inverted} />
      {showWordmark && (
        <span
          style={{
            fontFamily: "Inter, system-ui, sans-serif",
            fontWeight: 700,
            fontSize: size * 0.72,
            letterSpacing: "-0.04em",
            lineHeight: 1,
            color: inverted ? "#FFFFFF" : "var(--logo-ink, #0B2B26)",
          }}
        >
          bastion
        </span>
      )}
    </span>
  );
}
