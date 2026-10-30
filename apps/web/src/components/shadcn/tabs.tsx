import React, { createContext, useContext } from "react";

interface TabsContextType {
  value: string;
  onValueChange: (val: string) => void;
  variant?: "default" | "dark";
}

const TabsContext = createContext<TabsContextType>({
  value: "",
  onValueChange: () => {},
});

export function Tabs({
  value,
  onValueChange,
  variant = "default",
  className = "",
  children,
}: {
  value: string;
  onValueChange: (val: string) => void;
  variant?: "default" | "dark";
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <TabsContext.Provider value={{ value, onValueChange, variant }}>
      <div className={className}>{children}</div>
    </TabsContext.Provider>
  );
}

export function TabsList({ className = "", children }: { className?: string; children: React.ReactNode }) {
  return <div className={`bastion-tabs ${className}`}>{children}</div>;
}

export function TabsTrigger({
  value,
  className = "",
  children,
}: {
  value: string;
  className?: string;
  children: React.ReactNode;
}) {
  const ctx = useContext(TabsContext);
  const isActive = ctx.value === value;
  const activeClass = isActive
    ? ctx.variant === "dark"
      ? "active-dark"
      : "active"
    : "";

  return (
    <button
      type="button"
      className={`bastion-tab-item ${activeClass} ${className}`}
      onClick={() => ctx.onValueChange(value)}
    >
      {children}
    </button>
  );
}

export function TabsContent({
  value,
  className = "",
  children,
}: {
  value: string;
  className?: string;
  children: React.ReactNode;
}) {
  const ctx = useContext(TabsContext);
  if (ctx.value !== value) return null;
  return <div className={className}>{children}</div>;
}

