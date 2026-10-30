export function ShinyText({ text, className = "" }: { text: string; className?: string }) {
  return <span className={`shiny-text ${className}`}>{text}</span>;
}
