"use client";

import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AlertTriangle } from "lucide-react";

interface ConfirmationDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  /** If set, user must type this exact string to confirm (GitHub-style) */
  confirmText?: string;
  /** Label for the confirmation button */
  confirmLabel?: string;
  /** Whether the action is destructive (red styling) */
  destructive?: boolean;
  /** Called when the user confirms */
  onConfirm: () => void;
  /** Loading state for the confirm button */
  loading?: boolean;
}

export function ConfirmationDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmText,
  confirmLabel = "Confirm",
  destructive = false,
  onConfirm,
  loading = false,
}: ConfirmationDialogProps) {
  const [input, setInput] = React.useState("");
  const canConfirm = confirmText ? input === confirmText : true;

  // Reset input when dialog opens/closes
  React.useEffect(() => {
    if (!open) setInput("");
  }, [open]);

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <DialogPrimitive.Content
          className={cn(
            "fixed left-[50%] top-[50%] z-50 w-full max-w-md translate-x-[-50%] translate-y-[-50%]",
            "rounded-lg border bg-card p-6 shadow-xl",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
            "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
            "data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%]",
            "data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%]",
            "duration-200",
          )}
          onOpenAutoFocus={(e) => {
            // Prevent auto-focusing the close button; focus the input if present
            if (confirmText) e.preventDefault();
          }}
        >
          <div className="flex items-start gap-4">
            <div
              className={cn(
                "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-full",
                destructive ? "bg-destructive/10" : "bg-amber-500/10",
              )}
            >
              <AlertTriangle
                className={cn(
                  "h-5 w-5",
                  destructive ? "text-destructive" : "text-amber-400",
                )}
              />
            </div>
            <div className="flex-1 space-y-2">
              <DialogPrimitive.Title className="text-base font-semibold">
                {title}
              </DialogPrimitive.Title>
              <DialogPrimitive.Description className="text-sm text-muted-foreground leading-relaxed">
                {description}
              </DialogPrimitive.Description>
              {confirmText && (
                <div className="pt-2">
                  <p className="mb-2 text-xs text-muted-foreground">
                    Type{" "}
                    <span className="font-mono font-semibold text-foreground">
                      {confirmText}
                    </span>{" "}
                    to confirm:
                  </p>
                  <Input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={confirmText}
                    className="h-9 font-mono text-sm"
                    autoFocus
                  />
                </div>
              )}
            </div>
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <DialogPrimitive.Close asChild>
              <Button variant="outline" size="sm" disabled={loading}>
                Cancel
              </Button>
            </DialogPrimitive.Close>
            <Button
              variant={destructive ? "destructive" : "default"}
              size="sm"
              disabled={!canConfirm || loading}
              onClick={() => {
                onConfirm();
                onOpenChange(false);
              }}
            >
              {loading ? "Processing…" : confirmLabel}
            </Button>
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
