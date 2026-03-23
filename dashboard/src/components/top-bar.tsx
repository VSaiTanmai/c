"use client";

import React, { useState } from "react";
import { useTheme } from "next-themes";
import { usePathname } from "next/navigation";
import {
  Search,
  Bell,
  Sun,
  Moon,
  User,
  Command,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from "@/components/ui/tooltip";

const PAGE_TITLES: Record<string, string> = {
  "/dashboard": "CLIF Dashboard",
  "/live-feed": "Live Event Feed",
  "/alerts": "Alert Management",
  "/investigations": "Investigations",
  "/search": "Event Search",
  "/threat-intel": "Threat Intelligence",
  "/ai-agents": "AI Systems",
  "/explainability": "Explainability & XAI",
  "/chat": "CLIF AI Chat",
  "/evidence": "Chain of Custody",
  "/reports": "Reports",
  "/system": "System Health",
  "/settings": "Settings",
  "/attack-graph": "Attack Graph",
};

export function TopBar() {
  const { theme, setTheme } = useTheme();
  const pathname = usePathname();
  const [searchOpen, setSearchOpen] = useState(false);

  const pageTitle =
    Object.entries(PAGE_TITLES).find(([path]) =>
      pathname.startsWith(path)
    )?.[1] ?? "CLIF NEXUS";

  return (
    <TooltipProvider delayDuration={0}>
      <header className="clif-topbar flex items-center justify-between border-b border-border bg-card/80 px-4 backdrop-blur-sm">
        {/* Left: page title */}
        <div className="flex items-center gap-3">
          <h1 className="text-sm font-semibold text-foreground">{pageTitle}</h1>
          <div className="hidden items-center gap-1 rounded border border-border px-1.5 py-0.5 text-2xs text-muted-foreground sm:flex">
            <div className="status-dot status-dot-online h-1.5 w-1.5" />
            <span>LIVE</span>
          </div>
        </div>

        {/* Right: actions */}
        <div className="flex items-center gap-1">
          {/* Search */}
          {searchOpen ? (
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search events, investigations..."
                className="h-7 w-64 pl-8 text-xs"
                autoFocus
                onBlur={() => setSearchOpen(false)}
                onKeyDown={(e) => e.key === "Escape" && setSearchOpen(false)}
              />
              <kbd className="absolute right-2 top-1/2 -translate-y-1/2 rounded border border-border bg-muted px-1 text-2xs text-muted-foreground">
                ESC
              </kbd>
            </div>
          ) : (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => setSearchOpen(true)}
                >
                  <Search className="h-3.5 w-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                <div className="flex items-center gap-1">
                  Search <kbd className="rounded border px-1 text-2xs"><Command className="inline h-2.5 w-2.5" />K</kbd>
                </div>
              </TooltipContent>
            </Tooltip>
          )}

          {/* Notifications */}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon-sm" className="relative">
                <Bell className="h-3.5 w-3.5" />
                <span className="absolute -right-0.5 -top-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-destructive text-2xs text-white">
                  3
                </span>
              </Button>
            </TooltipTrigger>
            <TooltipContent>Notifications</TooltipContent>
          </Tooltip>

          {/* Theme toggle */}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              >
                <Sun className="h-3.5 w-3.5 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
                <Moon className="absolute h-3.5 w-3.5 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Toggle theme</TooltipContent>
          </Tooltip>

          {/* User avatar */}
          <Button variant="ghost" size="icon-sm" className="ml-1">
            <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-primary">
              <User className="h-3.5 w-3.5" />
            </div>
          </Button>
        </div>
      </header>
    </TooltipProvider>
  );
}
