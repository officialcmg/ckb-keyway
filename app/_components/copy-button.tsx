"use client";

import { useState, type ReactNode } from "react";
import { CheckIcon, CopyIcon } from "./icons";

/** Copies a value to the clipboard and briefly shows a check mark. */
export function CopyButton({ value, label, className = "icon-button", icon }: { value: string; label: string; className?: string; icon?: ReactNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={className}
      aria-label={copied ? "Copied" : label}
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <CheckIcon size={16} /> : icon ?? <CopyIcon />}
    </button>
  );
}
