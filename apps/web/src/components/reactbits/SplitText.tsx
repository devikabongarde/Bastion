import { useEffect, useRef } from "react";
import gsap from "gsap";

interface SplitTextProps {
  text: string;
  className?: string;
  delay?: number;
}

export function SplitText({ text, className = "", delay = 0 }: SplitTextProps) {
  const containerRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const chars = containerRef.current.querySelectorAll(".split-char");
    gsap.fromTo(
      chars,
      { opacity: 0, y: 15 },
      {
        opacity: 1,
        y: 0,
        duration: 0.6,
        stagger: 0.03,
        delay,
        ease: "power3.out",
      }
    );
  }, [text, delay]);

  const words = text.split(" ");

  return (
    <span ref={containerRef} className={`inline-block ${className}`} aria-label={text}>
      {words.map((word, wIdx) => (
        <span key={wIdx} className="inline-block whitespace-nowrap mr-[0.25em]">
          {word.split("").map((char, cIdx) => (
            <span key={cIdx} className="split-char inline-block">
              {char}
            </span>
          ))}
        </span>
      ))}
    </span>
  );
}
