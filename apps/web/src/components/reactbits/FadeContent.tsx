import React, { useEffect, useRef } from "react";
import gsap from "gsap";

export function FadeContent({
  children,
  blur = false,
  duration = 0.8,
  delay = 0,
  className = "",
}: {
  children: React.ReactNode;
  blur?: boolean;
  duration?: number;
  delay?: number;
  className?: string;
}) {
  const elRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!elRef.current) return;
    const isReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (isReduced) {
      gsap.to(elRef.current, { opacity: 1, duration: 0.3 });
      return;
    }

    gsap.fromTo(
      elRef.current,
      {
        opacity: 0,
        y: 25,
        filter: blur ? "blur(8px)" : "blur(0px)",
      },
      {
        opacity: 1,
        y: 0,
        filter: "blur(0px)",
        duration,
        delay,
        ease: "power3.out",
      }
    );
  }, [blur, duration, delay]);

  return (
    <div ref={elRef} className={className}>
      {children}
    </div>
  );
}

