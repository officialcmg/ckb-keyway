import type { SVGProps } from "react";

const MARK_PATH = "M14 6H34A8 8 0 0 1 42 14V15L37.5 19.5L42 24V25L38.5 28.5L42 32V34A8 8 0 0 1 34 42H14A8 8 0 0 1 6 34V14A8 8 0 0 1 14 6Z";

/** The key-cut cell mark, always a single colour. */
export function LogoMark({ size = 26, color = "var(--logo)", label }: { size?: number; color?: string; label?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" {...(label ? { role: "img", "aria-label": label } : { "aria-hidden": true })}>
      <path fill={color} d={MARK_PATH} />
    </svg>
  );
}

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function stroke({ size = 16, strokeWidth = 2, ...props }: IconProps) {
  return { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true, ...props };
}

export const CopyIcon = (props: IconProps) => <svg {...stroke(props)}><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>;
export const CheckIcon = (props: IconProps) => <svg {...stroke({ strokeWidth: 2.5, ...props })}><path d="M5 12l5 5L20 7" /></svg>;
export const SpinnerIcon = (props: IconProps) => <svg {...stroke({ strokeWidth: 2.5, ...props })}><path className="spin" d="M12 3a9 9 0 1 1-9 9" /></svg>;
export const AlertIcon = (props: IconProps) => <svg {...stroke(props)}><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16.5v.5" /></svg>;
export const ChevronRight = (props: IconProps) => <svg {...stroke(props)}><path d="M9 6l6 6-6 6" /></svg>;
export const ChevronDown = (props: IconProps) => <svg {...stroke(props)}><path d="M6 9l6 6 6-6" /></svg>;
export const ExternalIcon = (props: IconProps) => <svg {...stroke(props)}><path d="M7 17L17 7M9 7h8v8" /></svg>;
export const CloseIcon = (props: IconProps) => <svg {...stroke(props)}><path d="M6 6l12 12M18 6L6 18" /></svg>;
export const PlusIcon = (props: IconProps) => <svg {...stroke({ strokeWidth: 2.5, ...props })}><path d="M12 5v14M5 12h14" /></svg>;
export const MenuIcon = (props: IconProps) => <svg {...stroke(props)}><path d="M4 7h16M4 12h16M4 17h16" /></svg>;
