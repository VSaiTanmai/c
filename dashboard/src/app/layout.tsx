import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider, DynamicToaster } from "@/components/theme-provider";
import { Sidebar } from "@/components/sidebar";
import { TopBar } from "@/components/top-bar";
import { ErrorBoundary } from "@/components/error-boundary";
import { ChatWidget } from "@/components/chat-widget";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "CLIF NEXUS — Security Operations",
  description: "Enterprise AI-powered Security Operations Center",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} font-sans`}>
        <ThemeProvider
          attribute="class"
          defaultTheme="light"
          enableSystem={false}
          disableTransitionOnChange
        >
          <div className="clif-shell" id="clif-shell">
            <TopBar />
            <Sidebar />
            <main className="clif-main overflow-y-auto">
              <ErrorBoundary>
                <div className="page-enter p-4 lg:p-6">{children}</div>
              </ErrorBoundary>
            </main>
          </div>
          <ChatWidget />
          <DynamicToaster />
        </ThemeProvider>
      </body>
    </html>
  );
}
