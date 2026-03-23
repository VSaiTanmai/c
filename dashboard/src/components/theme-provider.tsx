"use client";

import * as React from "react";
import { ThemeProvider as NextThemesProvider, type ThemeProviderProps } from "next-themes";
import { Toaster } from "sonner";

export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>;
}

export function DynamicToaster() {
  return (
    <Toaster
      position="bottom-right"
      toastOptions={{
        classNames: {
          toast: "bg-card border-border text-foreground",
          title: "text-foreground",
          description: "text-muted-foreground",
        },
      }}
      richColors
      closeButton
    />
  );
}

export { useTheme } from "next-themes";
