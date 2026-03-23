import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default:   "bg-primary/10 text-primary border-primary/20",
        secondary: "bg-secondary text-secondary-foreground border-transparent",
        outline:   "bg-transparent text-foreground border-border",
        critical:  "sev-critical border",
        high:      "sev-high border",
        medium:    "sev-medium border",
        low:       "sev-low border",
        info:      "sev-info border",
        success:   "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
        warning:   "bg-amber-500/10 text-amber-400 border-amber-500/20",
        destructive: "bg-destructive/10 text-destructive border-destructive/20",
        cyan:      "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
        purple:    "bg-violet-500/10 text-violet-400 border-violet-500/20",
        ghost:     "bg-transparent text-muted-foreground border-transparent hover:bg-muted",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
