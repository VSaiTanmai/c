"use client";

import { useState, useRef, useEffect, useCallback, FormEvent } from "react";
import Link from "next/link";
import {
  Send,
  Bot,
  User,
  Loader2,
  Copy,
  RotateCcw,
  Trash2,
  Sparkles,
  AlertTriangle,
  Search,
  Shield,
  Crosshair,
  Brain,
  MessageSquare,
  Plus,
  ChevronRight,
  ShieldCheck,
  Clock,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: Date;
  metadata?: {
    model?: string;
    tokensUsed?: number;
    sources?: string[];
    confidence?: number;
  };
}

const QUICK_PROMPTS = [
  { label: "Summarize alerts", icon: AlertTriangle, prompt: "Summarize the current critical and high severity alerts" },
  { label: "Top threats", icon: Shield, prompt: "What are the top active threats in the last 24 hours?" },
  { label: "Investigate IOC", icon: Search, prompt: "Investigate this IOC and check for related activity" },
  { label: "MITRE mapping", icon: Crosshair, prompt: "Map recent attacks to MITRE ATT&CK techniques" },
  { label: "Pipeline status", icon: Brain, prompt: "What is the current status of the AI pipeline (Triage → Hunter → Verifier)?" },
  { label: "Evidence integrity", icon: ShieldCheck, prompt: "Check the integrity of recent evidence batches and HMAC chains" },
];

interface Conversation {
  id: string;
  title: string;
  messageCount: number;
  lastActivity: Date;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "system",
      content:
        "CLIF AI Assistant initialized. I can help you investigate security events, analyze threats, search the knowledge base, and provide recommendations based on your SOC data.\n\nI have access to your 3-agent AI pipeline (Triage → Hunter → Verifier), ClickHouse event store, and LanceDB vector search.",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showSidebar, setShowSidebar] = useState(true);
  const [conversations, setConversations] = useState<Conversation[]>([
    { id: "current", title: "Current Session", messageCount: 1, lastActivity: new Date() },
  ]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = useCallback(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  const handleSubmit = async (e?: FormEvent) => {
    e?.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || isLoading) return;

    const userMsg: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: trimmed,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const res = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: trimmed }),
      });

      if (!res.ok) throw new Error(`Chat API error: ${res.status}`);

      const data = await res.json();

      const assistantMsg: ChatMessage = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: data.response || data.message || "I couldn't process that request.",
        timestamp: new Date(),
        metadata: {
          model: data.model,
          tokensUsed: data.tokensUsed,
          sources: data.sources,
          confidence: data.confidence,
        },
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content:
            "I encountered an error processing your request. The AI backend may be unavailable. Please try again.",
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleQuickPrompt = (prompt: string) => {
    setInput(prompt);
    setTimeout(() => {
      const syntheticEvent = { preventDefault: () => {} } as FormEvent;
      setInput(prompt);
      handleSubmit(syntheticEvent);
    }, 50);
  };

  const handleCopy = (content: string) => {
    navigator.clipboard.writeText(content);
  };

  const clearChat = () => {
    setMessages([
      {
        id: "welcome",
        role: "system",
        content: "Chat cleared. How can I help you?",
        timestamp: new Date(),
      },
    ]);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div className="flex h-[calc(100vh-52px)]">
      {/* Sidebar — Conversation History */}
      {showSidebar && (
        <div className="w-56 shrink-0 border-r border-border bg-card/50 flex flex-col">
          <div className="p-3 border-b border-border">
            <Button variant="outline" size="sm" className="w-full text-xs" onClick={clearChat}>
              <Plus className="mr-1 h-3 w-3" /> New Chat
            </Button>
          </div>
          <ScrollArea className="flex-1 p-2">
            <div className="space-y-1">
              {conversations.map((c) => (
                <button
                  key={c.id}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-muted/20 transition-colors bg-primary/5"
                >
                  <MessageSquare className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="text-xs text-foreground truncate flex-1">{c.title}</span>
                </button>
              ))}
            </div>
          </ScrollArea>
          <div className="p-3 border-t border-border space-y-1.5">
            <p className="text-2xs font-medium text-muted-foreground uppercase tracking-wider">Quick Links</p>
            <Link href="/ai-agents" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <Brain className="h-3 w-3" /> AI Agents
            </Link>
            <Link href="/investigations" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <Shield className="h-3 w-3" /> Investigations
            </Link>
            <Link href="/search" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <Search className="h-3 w-3" /> Search
            </Link>
          </div>
        </div>
      )}

      {/* Main Chat Area */}
      <div className="flex flex-1 flex-col">
      {/* Quick prompts */}
      {messages.length <= 1 && (
        <div className="grid grid-cols-2 gap-2 p-4 md:grid-cols-3">
          {QUICK_PROMPTS.map((qp) => (
            <button
              key={qp.label}
              onClick={() => handleQuickPrompt(qp.prompt)}
              className="group flex items-center gap-2 rounded-lg border border-border bg-card p-3 text-left text-sm transition-colors hover:border-primary hover:bg-primary/5"
            >
              <qp.icon className="h-4 w-4 text-muted-foreground group-hover:text-primary" />
              <span className="text-xs font-medium text-muted-foreground group-hover:text-foreground">
                {qp.label}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-hidden">
        <ScrollArea className="h-full" ref={scrollRef}>
          <div className="mx-auto max-w-3xl space-y-4 p-4">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={cn("flex gap-3", msg.role === "user" && "justify-end")}
              >
                {msg.role !== "user" && (
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10">
                    {msg.role === "system" ? (
                      <Sparkles className="h-3.5 w-3.5 text-primary" />
                    ) : (
                      <Bot className="h-3.5 w-3.5 text-primary" />
                    )}
                  </div>
                )}

                <div
                  className={cn(
                    "max-w-[80%] rounded-lg p-3",
                    msg.role === "user"
                      ? "bg-primary text-primary-foreground"
                      : msg.role === "system"
                        ? "bg-muted/30 border border-border"
                        : "bg-card border border-border"
                  )}
                >
                  <p className="text-sm whitespace-pre-wrap">{msg.content}</p>

                  {msg.metadata && (
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {msg.metadata.confidence != null && (
                        <Badge variant="outline" className="text-2xs">
                          {(msg.metadata.confidence * 100).toFixed(0)}% confidence
                        </Badge>
                      )}
                      {msg.metadata.model && (
                        <Badge variant="ghost" className="text-2xs">
                          {msg.metadata.model}
                        </Badge>
                      )}
                      {msg.metadata.tokensUsed && (
                        <Badge variant="ghost" className="text-2xs">
                          {msg.metadata.tokensUsed} tokens
                        </Badge>
                      )}
                      {msg.metadata.sources?.map((s) => (
                        <Badge key={s} variant="cyan" className="text-2xs">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  )}

                  <div className="mt-1.5 flex items-center justify-between">
                    <span className="text-2xs text-muted-foreground opacity-60">
                      {msg.timestamp.toLocaleTimeString()}
                    </span>
                    {msg.role === "assistant" && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        onClick={() => handleCopy(msg.content)}
                        className="opacity-0 group-hover:opacity-100"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>

                {msg.role === "user" && (
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted">
                    <User className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                )}
              </div>
            ))}

            {isLoading && (
              <div className="flex gap-3">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10">
                  <Bot className="h-3.5 w-3.5 text-primary" />
                </div>
                <div className="rounded-lg border border-border bg-card p-3">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              </div>
            )}
          </div>
        </ScrollArea>
      </div>

      {/* Input bar */}
      <div className="border-t border-border bg-card/50 p-4">
        <form
          onSubmit={handleSubmit}
          className="mx-auto flex max-w-3xl items-end gap-2"
        >
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={clearChat}
            title="Clear chat"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>

          <div className="relative flex-1">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask CLIF AI about security events, threats, investigations..."
              className="w-full resize-none rounded-lg border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              rows={1}
              style={{ minHeight: 40, maxHeight: 120 }}
              disabled={isLoading}
            />
          </div>

          <Button
            type="submit"
            size="icon"
            disabled={!input.trim() || isLoading}
            className="shrink-0"
          >
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </Button>
        </form>
      </div>
      </div>
    </div>
  );
}
