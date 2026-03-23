"use client";

import { useEffect, useCallback, useRef } from "react";

export interface Shortcut {
  /** Unique key identifier */
  id: string;
  /** Key combo, e.g. "g d" (vim-style sequence), "ctrl+k", "?" */
  keys: string;
  /** Human-readable label */
  label: string;
  /** Category for grouping */
  category: string;
  /** Action to perform */
  action: () => void;
}

/** Parse key combo into parts: modifiers + key sequence */
function parseCombo(keys: string) {
  const parts = keys.toLowerCase().split("+").map((s) => s.trim());
  const modifiers = {
    ctrl: parts.includes("ctrl") || parts.includes("meta"),
    shift: parts.includes("shift"),
    alt: parts.includes("alt"),
  };
  const keyParts = parts.filter(
    (p) => !["ctrl", "meta", "shift", "alt"].includes(p),
  );
  return { modifiers, keyParts };
}

function modifiersMatch(
  e: KeyboardEvent,
  mods: { ctrl: boolean; shift: boolean; alt: boolean },
) {
  return (
    (e.ctrlKey || e.metaKey) === mods.ctrl &&
    e.shiftKey === mods.shift &&
    e.altKey === mods.alt
  );
}

/**
 * Global keyboard shortcut manager.
 *
 * Supports:
 * - Single keys: "?"
 * - Modifier combos: "ctrl+k"
 * - Vim-style sequences: "g d" (press g then d within 800ms)
 *
 * Ignores shortcuts when focus is inside input/textarea/select.
 */
export function useKeyboardShortcuts(shortcuts: Shortcut[]) {
  const sequenceRef = useRef<string[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handler = useCallback(
    (e: KeyboardEvent) => {
      // Don't fire shortcuts when typing in inputs
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
      if (
        tag === "input" ||
        tag === "textarea" ||
        tag === "select" ||
        (e.target as HTMLElement)?.isContentEditable
      ) {
        return;
      }

      for (const shortcut of shortcuts) {
        const { modifiers, keyParts } = parseCombo(shortcut.keys);

        // Single key with modifiers (e.g., "ctrl+k")
        if (keyParts.length === 1 && (modifiers.ctrl || modifiers.shift || modifiers.alt)) {
          if (e.key.toLowerCase() === keyParts[0] && modifiersMatch(e, modifiers)) {
            e.preventDefault();
            shortcut.action();
            return;
          }
          continue;
        }

        // Vim-style sequence (e.g., "g d") or single non-modifier key (e.g., "?")
        if (keyParts.length === 1 && !shortcut.keys.includes(" ")) {
          // Simple single key
          if (
            e.key === keyParts[0] &&
            !e.ctrlKey &&
            !e.metaKey &&
            !e.altKey
          ) {
            // Allow shift for ? etc
            e.preventDefault();
            shortcut.action();
            return;
          }
          continue;
        }

        // Multi-key sequence (space-separated, e.g., "g d")
        const seqParts = shortcut.keys.toLowerCase().split(" ");
        if (seqParts.length > 1) {
          // Check if the current key continues the sequence
          sequenceRef.current.push(e.key.toLowerCase());
          // Reset timer
          if (timerRef.current) clearTimeout(timerRef.current);
          timerRef.current = setTimeout(() => {
            sequenceRef.current = [];
          }, 800);

          const seq = sequenceRef.current;
          if (seq.length === seqParts.length) {
            const match = seqParts.every((k, i) => seq[i] === k);
            if (match) {
              e.preventDefault();
              sequenceRef.current = [];
              if (timerRef.current) clearTimeout(timerRef.current);
              shortcut.action();
              return;
            }
          }
        }
      }
    },
    [shortcuts],
  );

  useEffect(() => {
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [handler]);
}
