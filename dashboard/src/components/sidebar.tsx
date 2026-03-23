"use client";

import React, { useState, useCallback, createContext, useContext } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from "@/components/ui/tooltip";
import {
  LayoutDashboard,
  Radio,
  Bell,
  Search,
  FileSearch,
  Globe,
  Bot,
  Brain,
  Shield,
  FileText,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
  Crosshair,
} from "lucide-react";

/* ── Sidebar context ── */
interface SidebarContextValue {
  expanded: boolean;
  toggle: () => void;
}
const SidebarContext = createContext<SidebarContextValue>({
  expanded: false,
  toggle: () => {},
});
export const useSidebar = () => useContext(SidebarContext);

/* ── Navigation config ── */
interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "OPERATIONS",
    items: [
      { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
      { label: "Live Feed", href: "/live-feed", icon: Radio },
      { label: "Alerts", href: "/alerts", icon: Bell },
    ],
  },
  {
    title: "INTELLIGENCE",
    items: [
      { label: "Investigations", href: "/investigations", icon: FileSearch },
      { label: "Search", href: "/search", icon: Search },
      { label: "Threat Intel", href: "/threat-intel", icon: Globe },
    ],
  },
  {
    title: "AI SYSTEMS",
    items: [
      { label: "AI Agents", href: "/ai-agents", icon: Bot },
      { label: "Explainability", href: "/explainability", icon: Brain },
    ],
  },
  {
    title: "EVIDENCE",
    items: [
      { label: "Chain of Custody", href: "/evidence", icon: Shield },
      { label: "Reports", href: "/reports", icon: FileText },
    ],
  },
  {
    title: "PLATFORM",
    items: [
      { label: "System Health", href: "/system", icon: Activity },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
];

/* ── Sidebar component ── */
export function Sidebar() {
  const [expanded, setExpanded] = useState(false);
  const toggle = useCallback(() => setExpanded((e) => !e), []);
  const pathname = usePathname();

  return (
    <SidebarContext.Provider value={{ expanded, toggle }}>
      <TooltipProvider delayDuration={0}>
        <aside
          className={cn(
            "clif-sidebar flex flex-col border-r border-border bg-card/50 transition-all duration-200",
            expanded ? "w-[240px]" : "w-[56px]"
          )}
        >
          {/* Logo */}
          <div className="flex h-12 items-center justify-center border-b border-border px-2">
            {expanded ? (
              <div className="flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-primary" />
                <span className="text-sm font-bold tracking-wider text-foreground">
                  CLIF<span className="text-primary"> NEXUS</span>
                </span>
              </div>
            ) : (
              <Crosshair className="h-5 w-5 text-primary" />
            )}
          </div>

          {/* Navigation */}
          <nav className="flex-1 space-y-1 overflow-y-auto px-2 py-3">
            {NAV_SECTIONS.map((section) => (
              <div key={section.title} className="mb-3">
                {expanded && (
                  <div className="mb-1.5 px-2 text-2xs font-semibold uppercase tracking-widest text-muted-foreground/60">
                    {section.title}
                  </div>
                )}
                <div className="space-y-0.5">
                  {section.items.map((item) => {
                    const isActive =
                      pathname === item.href ||
                      (item.href !== "/dashboard" &&
                        pathname.startsWith(item.href));
                    const Icon = item.icon;

                    const link = (
                      <Link
                        key={item.href}
                        href={item.href}
                        className={cn(
                          "group flex items-center gap-3 rounded-md px-2 py-1.5 text-sm transition-all duration-150",
                          isActive
                            ? "bg-primary/10 text-primary font-medium"
                            : "text-muted-foreground hover:bg-muted hover:text-foreground",
                          !expanded && "justify-center"
                        )}
                      >
                        <Icon
                          className={cn(
                            "h-4 w-4 shrink-0 transition-colors",
                            isActive
                              ? "text-primary"
                              : "text-muted-foreground group-hover:text-foreground"
                          )}
                        />
                        {expanded && (
                          <span className="truncate">{item.label}</span>
                        )}
                        {expanded && item.badge && (
                          <span className="ml-auto rounded-full bg-destructive/10 px-1.5 py-0.5 text-2xs font-medium text-destructive">
                            {item.badge}
                          </span>
                        )}
                      </Link>
                    );

                    if (!expanded) {
                      return (
                        <Tooltip key={item.href}>
                          <TooltipTrigger asChild>{link}</TooltipTrigger>
                          <TooltipContent side="right" className="text-xs">
                            {item.label}
                          </TooltipContent>
                        </Tooltip>
                      );
                    }

                    return link;
                  })}
                </div>
              </div>
            ))}
          </nav>

          {/* Collapse toggle */}
          <button
            onClick={toggle}
            className="flex h-10 items-center justify-center border-t border-border text-muted-foreground transition-colors hover:text-foreground"
          >
            {expanded ? (
              <ChevronLeft className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>
        </aside>
      </TooltipProvider>
    </SidebarContext.Provider>
  );
}
